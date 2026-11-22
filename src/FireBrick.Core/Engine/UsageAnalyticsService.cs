using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Privacy-first, anonymous usage analytics client backed by a simple counter API
/// (POST {BaseUrl}/{key}/up). Sends only aggregate counters — zero PII, machine IDs,
/// IP addresses, or executable paths — and guards all calls with a short timeout
/// and an exponential-backoff circuit breaker when the counter API is unreachable.
/// </summary>
public sealed class UsageAnalyticsService : IDisposable
{
    public const string DefaultBaseUrl = "https://app.piyushagade.xyz/counter/firebrick";

    private const int CircuitFailureThreshold = 2;
    private static readonly TimeSpan[] BackoffSchedule =
    [
        TimeSpan.FromMinutes(15),
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(6)
    ];

    private readonly string _baseUrl;
    private readonly string _statePath;
    private readonly string _crashLogPath;
    private readonly Func<bool> _isEnabled;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly SemaphoreSlim _concurrencyGate = new(2, 2);
    private readonly object _lock = new();
    private readonly AnalyticsLocalState _state;

    private int _consecutiveFailures;
    private int _circuitOpenCount;
    private DateTimeOffset _circuitOpenUntilUtc = DateTimeOffset.MinValue;
    private bool _disposed;

    public bool IsCircuitOpen
    {
        get
        {
            lock (_lock)
            {
                return _utcNow() < _circuitOpenUntilUtc;
            }
        }
    }

    public int ConsecutiveFailures
    {
        get
        {
            lock (_lock)
            {
                return _consecutiveFailures;
            }
        }
    }

    public UsageAnalyticsService(
        Func<bool> isEnabled,
        string? baseUrl = null,
        string? statePath = null,
        string? crashLogPath = null,
        HttpMessageHandler? httpHandler = null,
        Func<DateTimeOffset>? utcNow = null,
        TimeSpan? timeout = null)
    {
        _isEnabled = isEnabled ?? throw new ArgumentNullException(nameof(isEnabled));
        _baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/');
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);

        var defaultDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FireBrick");
        _statePath = statePath ?? Path.Combine(defaultDir, "analytics_state.json");
        _crashLogPath = crashLogPath ?? Path.Combine(defaultDir, "crash.log");

        _http = httpHandler != null
            ? new HttpClient(httpHandler, disposeHandler: false)
            : new HttpClient();
        _ownsHttpClient = true;
        _http.Timeout = timeout ?? TimeSpan.FromSeconds(4);

        var version = GetAppVersion();
        _http.DefaultRequestHeaders.UserAgent.Clear();
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("FireBrick", version));

        _state = LoadState();
    }

    /// <summary>
    /// Increments a single anonymous counter key. Returns true if the counter API
    /// responded with a 2xx status, or false if disabled, guarded by the circuit breaker,
    /// or failed. Never throws.
    /// </summary>
    public async Task<bool> IncrementAsync(string key, CancellationToken ct = default)
    {
        if (_disposed || string.IsNullOrWhiteSpace(key))
            return false;

        if (!SafeIsEnabled())
            return false;

        var sanitized = SanitizeKey(key);
        if (sanitized.Length == 0)
            return false;

        lock (_lock)
        {
            if (_utcNow() < _circuitOpenUntilUtc)
                return false;
        }

        bool acquired = false;
        try
        {
            acquired = await _concurrencyGate.WaitAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            if (!acquired)
                return false;

            // Re-check circuit after waiting on the concurrency gate
            lock (_lock)
            {
                if (_utcNow() < _circuitOpenUntilUtc)
                    return false;
            }

            var url = $"{_baseUrl}/{Uri.EscapeDataString(sanitized)}/up";
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(string.Empty)
            };
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            if (resp.IsSuccessStatusCode)
            {
                RecordSuccess();
                return true;
            }

            RecordFailure();
            return false;
        }
        catch
        {
            RecordFailure();
            return false;
        }
        finally
        {
            if (acquired)
            {
                try { _concurrencyGate.Release(); } catch { }
            }
        }
    }

    /// <summary>
    /// Fire-and-forget helper for UI/background callers.
    /// </summary>
    public void Track(string key)
    {
        if (_disposed || !SafeIsEnabled()) return;
        _ = Task.Run(() => IncrementAsync(key));
    }

    /// <summary>
    /// Tracks app launch, first-run install, crash log growth diagnostics,
    /// and today's daily active usage ping.
    /// </summary>
    public async Task TrackAppLaunchAsync(
        FirewallProfileMode profileMode,
        bool isServiceConnected,
        string? appVersion = null,
        CancellationToken ct = default)
    {
        if (_disposed || !SafeIsEnabled())
            return;

        await IncrementAsync("app-launches", ct).ConfigureAwait(false);

        bool shouldSendFirstRun;
        lock (_lock)
        {
            shouldSendFirstRun = !_state.HasSentFirstRun;
        }

        if (shouldSendFirstRun)
        {
            if (await IncrementAsync("first-run", ct).ConfigureAwait(false))
            {
                lock (_lock)
                {
                    _state.HasSentFirstRun = true;
                    SaveStateNoThrow();
                }
            }
        }

        await CheckAndTrackCrashLogAsync(ct).ConfigureAwait(false);
        await TrackDailyActiveIfNeededAsync(profileMode, isServiceConnected, appVersion, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends the daily active usage (DAU) counters at most once per UTC calendar day.
    /// Safe to call periodically (e.g. hourly) for long-running tray sessions.
    /// </summary>
    public async Task TrackDailyActiveIfNeededAsync(
        FirewallProfileMode profileMode,
        bool isServiceConnected,
        string? appVersion = null,
        CancellationToken ct = default)
    {
        if (_disposed || !SafeIsEnabled())
            return;

        var todayUtc = _utcNow().UtcDateTime.ToString("yyyy-MM-dd");
        lock (_lock)
        {
            if (string.Equals(_state.LastDailyPingUtcDate, todayUtc, StringComparison.Ordinal))
                return;
        }

        // Only mark today as reported if the primary DAU ping actually succeeded
        if (!await IncrementAsync($"dau-{todayUtc}", ct).ConfigureAwait(false))
            return;

        lock (_lock)
        {
            _state.LastDailyPingUtcDate = todayUtc;
            SaveStateNoThrow();
        }

        await IncrementAsync("dau-total", ct).ConfigureAwait(false);

        var versionTag = SanitizeVersion(appVersion ?? GetAppVersion());
        if (versionTag.Length > 0)
            await IncrementAsync($"version-{versionTag}", ct).ConfigureAwait(false);

        var profileTag = profileMode switch
        {
            FirewallProfileMode.HighFiltering => "profile-high",
            FirewallProfileMode.MediumFiltering => "profile-medium",
            FirewallProfileMode.LowFiltering => "profile-low",
            FirewallProfileMode.NoFiltering => "profile-none",
            _ => "profile-unknown"
        };
        await IncrementAsync(profileTag, ct).ConfigureAwait(false);

        if (isServiceConnected)
            await IncrementAsync("service-connected", ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Tracks a blocked connection interception (all-time + daily bucket).
    /// </summary>
    public void TrackInterception()
    {
        if (_disposed || !SafeIsEnabled())
            return;

        var todayUtc = _utcNow().UtcDateTime.ToString("yyyy-MM-dd");
        _ = Task.Run(async () =>
        {
            await IncrementAsync("interceptions-total").ConfigureAwait(false);
            await IncrementAsync($"interceptions-{todayUtc}").ConfigureAwait(false);
        });
    }

    /// <summary>
    /// Tracks a user's decision in the Connection Alert prompt.
    /// </summary>
    public void TrackAlertDecision(RuleAction action, bool isTemporary)
    {
        if (_disposed || !SafeIsEnabled())
            return;

        var key = action == RuleAction.Block
            ? "alert-block"
            : (isTemporary ? "alert-temp-allow" : "alert-allow");
        Track(key);
    }

    public void TrackPresetApplied() => Track("preset-applied");

    private async Task CheckAndTrackCrashLogAsync(CancellationToken ct)
    {
        long currentBytes = 0;
        try
        {
            if (File.Exists(_crashLogPath))
                currentBytes = new FileInfo(_crashLogPath).Length;
        }
        catch
        {
            return;
        }

        bool grew;
        lock (_lock)
        {
            if (currentBytes < _state.LastKnownCrashLogBytes)
            {
                // Log was cleared or rotated
                _state.LastKnownCrashLogBytes = currentBytes;
                SaveStateNoThrow();
                return;
            }
            grew = currentBytes > _state.LastKnownCrashLogBytes;
        }

        if (!grew)
            return;

        if (await IncrementAsync("crash-count", ct).ConfigureAwait(false))
        {
            lock (_lock)
            {
                _state.LastKnownCrashLogBytes = currentBytes;
                SaveStateNoThrow();
            }
        }
    }

    private void RecordSuccess()
    {
        lock (_lock)
        {
            _consecutiveFailures = 0;
            _circuitOpenCount = 0;
            _circuitOpenUntilUtc = DateTimeOffset.MinValue;
        }
    }

    private void RecordFailure()
    {
        lock (_lock)
        {
            _consecutiveFailures++;
            if (_consecutiveFailures >= CircuitFailureThreshold)
            {
                var tierIndex = Math.Min(_circuitOpenCount, BackoffSchedule.Length - 1);
                _circuitOpenUntilUtc = _utcNow().Add(BackoffSchedule[tierIndex]);
                _circuitOpenCount++;
            }
        }
    }

    private bool SafeIsEnabled()
    {
        try { return _isEnabled(); }
        catch { return false; }
    }

    private static string GetAppVersion()
    {
        try
        {
            var raw = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? "1.0.0";
            var plusIndex = raw.IndexOf('+');
            return plusIndex > 0 ? raw[..plusIndex] : raw;
        }
        catch
        {
            return "1.0.0";
        }
    }

    private static string SanitizeVersion(string version)
    {
        var plusIndex = version.IndexOf('+');
        if (plusIndex > 0) version = version[..plusIndex];
        return SanitizeKey(version.Replace('.', '_'));
    }

    private static string SanitizeKey(string raw)
    {
        Span<char> buffer = stackalloc char[Math.Min(raw.Length, 64)];
        int len = 0;
        foreach (var ch in raw)
        {
            if (len >= buffer.Length) break;
            if (char.IsLetterOrDigit(ch) || ch is '-' or '_')
            {
                buffer[len++] = char.ToLowerInvariant(ch);
            }
        }
        return new string(buffer[..len]);
    }

    private AnalyticsLocalState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                var json = File.ReadAllText(_statePath);
                return JsonSerializer.Deserialize<AnalyticsLocalState>(json) ?? new AnalyticsLocalState();
            }
        }
        catch { }

        return new AnalyticsLocalState();
    }

    private void SaveStateNoThrow()
    {
        try
        {
            var dir = Path.GetDirectoryName(_statePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(_state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_statePath, json);
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsHttpClient) _http.Dispose();
        _concurrencyGate.Dispose();
    }

    private sealed class AnalyticsLocalState
    {
        public bool HasSentFirstRun { get; set; }
        public string LastDailyPingUtcDate { get; set; } = string.Empty;
        public long LastKnownCrashLogBytes { get; set; }
    }
}
