using System.Text.Json;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Unified coordinator for FireBrick's optional bandwidth limiting engines:
/// - Disabled (100% driverless, default)
/// - Windows QoS (driverless, upload-only via NetQos)
/// - WinDivert Add-on (upload &amp; download per-app packet pacing)
/// </summary>
public sealed class BandwidthLimiterManager : IDisposable
{
    private readonly string _configPath;
    private readonly object _lock = new();
    private readonly WindowsQosBandwidthEngine _qosEngine = new();
    private readonly WinDivertBandwidthEngine _winDivertEngine = new();
    private readonly LiveConnectionsMonitor? _liveConnections;
    private BandwidthLimiterConfigDto _config = new();
    private string? _lastError;

    public BandwidthLimiterManager(LiveConnectionsMonitor? liveConnections = null, string? configPath = null)
    {
        _liveConnections = liveConnections;
        if (!string.IsNullOrWhiteSpace(configPath))
        {
            _configPath = configPath;
        }
        else
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireBrick");
            Directory.CreateDirectory(dir);
            _configPath = Path.Combine(dir, "bandwidth_config.json");
        }

        Load();
    }

    public BandwidthLimiterStatusDto GetStatus()
    {
        lock (_lock)
        {
            var activeCount = _config.Rules.Count(r => r.Enabled && (r.DownloadLimitKBps > 0 || r.UploadLimitKBps > 0));
            bool installed = WinDivertAddonManager.IsInstalled();
            bool driverLoaded = WinDivertAddonManager.IsDriverLoaded();
            bool isActive = _config.Mode switch
            {
                BandwidthLimiterMode.WindowsQos => _qosEngine.IsApplied,
                BandwidthLimiterMode.WinDivert => _winDivertEngine.IsRunning,
                _ => false
            };

            string msg = _config.Mode switch
            {
                BandwidthLimiterMode.Disabled => "Bandwidth limiter is disabled (driverless).",
                BandwidthLimiterMode.WindowsQos => activeCount == 0
                    ? "Windows QoS active — add an app upload limit to apply policies."
                    : (_qosEngine.IsApplied
                        ? $"Windows QoS active ({activeCount} upload rule(s) applied, driverless)."
                        : (_qosEngine.LastError ?? "Windows QoS ready.")),
                BandwidthLimiterMode.WinDivert => !installed
                    ? "WinDivert add-on is not installed yet."
                    : (_winDivertEngine.IsRunning
                        ? $"WinDivert pacer active ({activeCount} rule(s))."
                        : (_config.AutoUnloadWinDivertWhenIdle && activeCount == 0
                            ? "WinDivert idle (driver unloaded until a rule is enabled)."
                            : (_winDivertEngine.LastError ?? "WinDivert stopped."))),
                _ => "Unknown"
            };

            return new BandwidthLimiterStatusDto
            {
                Mode = _config.Mode,
                AutoUnloadWinDivertWhenIdle = _config.AutoUnloadWinDivertWhenIdle,
                IsActive = isActive,
                IsWinDivertInstalled = installed,
                IsWinDivertDriverLoaded = driverLoaded,
                IsElevatedOrService = WindowsFirewallManager.IsProcessElevated(),
                ActiveRuleCount = activeCount,
                WinDivertInstallPath = WinDivertAddonManager.ResolveInstalledDirectory() ?? WinDivertAddonManager.AddonDirectory,
                StatusMessage = msg,
                LastError = _lastError ?? (_config.Mode == BandwidthLimiterMode.WindowsQos ? _qosEngine.LastError : _winDivertEngine.LastError)
            };
        }
    }

    public List<BandwidthRuleDto> GetRules()
    {
        lock (_lock)
        {
            return _config.Rules
                .Select(CloneRule)
                .OrderBy(r => r.DisplayAppName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public List<BandwidthAppUsageDto> GetUsage()
    {
        lock (_lock)
        {
            if (_config.Mode == BandwidthLimiterMode.WinDivert && _winDivertEngine.IsRunning)
                return _winDivertEngine.GetUsageSnapshot();
            return new List<BandwidthAppUsageDto>();
        }
    }

    public async Task<BandwidthLimiterStatusDto> SetModeAsync(BandwidthLimiterMode mode, bool autoUnloadWhenIdle, CancellationToken ct = default)
    {
        lock (_lock)
        {
            _config.Mode = mode;
            _config.AutoUnloadWinDivertWhenIdle = autoUnloadWhenIdle;
            _lastError = null;
            SaveInternal();
        }

        await ReconcileEngineAsync(ct).ConfigureAwait(false);
        return GetStatus();
    }

    public async Task<BandwidthRuleDto> SaveRuleAsync(BandwidthRuleDto rule, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rule.ApplicationPath))
            throw new ArgumentException("Application path is required.", nameof(rule));

        BandwidthRuleDto saved;
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(rule.Id))
                rule.Id = Guid.NewGuid().ToString("N");

            if (string.IsNullOrWhiteSpace(rule.ApplicationName))
                rule.ApplicationName = Path.GetFileName(rule.ApplicationPath);

            rule.DownloadLimitKBps = Math.Max(0, rule.DownloadLimitKBps);
            rule.UploadLimitKBps = Math.Max(0, rule.UploadLimitKBps);
            rule.UpdatedUtc = DateTimeOffset.UtcNow;

            if (rule.TemporaryMinutes.HasValue && rule.TemporaryMinutes.Value > 0 && !rule.ExpiresAtUtc.HasValue)
                rule.ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(rule.TemporaryMinutes.Value);

            int idx = _config.Rules.FindIndex(r =>
                r.Id == rule.Id ||
                string.Equals(r.ApplicationPath, rule.ApplicationPath, StringComparison.OrdinalIgnoreCase));

            if (idx >= 0)
            {
                rule.Id = _config.Rules[idx].Id;
                _config.Rules[idx] = CloneRule(rule);
            }
            else
            {
                _config.Rules.Add(CloneRule(rule));
            }

            saved = CloneRule(rule);
            SaveInternal();
        }

        await ReconcileEngineAsync(ct).ConfigureAwait(false);
        return saved;
    }

    public async Task DeleteRuleAsync(string ruleId, CancellationToken ct = default)
    {
        lock (_lock)
        {
            _config.Rules.RemoveAll(r => r.Id == ruleId);
            SaveInternal();
        }

        await ReconcileEngineAsync(ct).ConfigureAwait(false);
    }

    public async Task<int> CleanupExpiredRulesAsync(CancellationToken ct = default)
    {
        int removed = 0;
        var now = DateTimeOffset.UtcNow;

        lock (_lock)
        {
            removed = _config.Rules.RemoveAll(r => r.ExpiresAtUtc.HasValue && r.ExpiresAtUtc.Value <= now);
            if (removed > 0)
                SaveInternal();
        }

        if (removed > 0)
            await ReconcileEngineAsync(ct).ConfigureAwait(false);

        return removed;
    }

    public async Task<BandwidthLimiterStatusDto> InstallWinDivertAddonAsync(CancellationToken ct = default)
    {
        var (ok, msg) = await WinDivertAddonManager.InstallAsync(ct).ConfigureAwait(false);
        lock (_lock)
        {
            _lastError = ok ? null : msg;
        }

        if (ok && _config.Mode == BandwidthLimiterMode.WinDivert)
            await ReconcileEngineAsync(ct).ConfigureAwait(false);

        return GetStatus();
    }

    public async Task ReconcileEngineAsync(CancellationToken ct = default)
    {
        BandwidthLimiterMode mode;
        bool autoUnload;
        List<BandwidthRuleDto> rules;

        lock (_lock)
        {
            mode = _config.Mode;
            autoUnload = _config.AutoUnloadWinDivertWhenIdle;
            rules = _config.Rules.Select(CloneRule).ToList();
        }

        if (mode != BandwidthLimiterMode.WindowsQos && _qosEngine.IsApplied)
        {
            await _qosEngine.ClearAllAsync(ct).ConfigureAwait(false);
        }

        if (mode != BandwidthLimiterMode.WinDivert && _winDivertEngine.IsRunning)
        {
            _winDivertEngine.Stop(unloadDriver: true);
        }

        switch (mode)
        {
            case BandwidthLimiterMode.Disabled:
                break;

            case BandwidthLimiterMode.WindowsQos:
                var (ok, err) = await _qosEngine.ApplyRulesAsync(rules, ct).ConfigureAwait(false);
                lock (_lock) { _lastError = ok ? null : err; }
                break;

            case BandwidthLimiterMode.WinDivert:
                bool hasActive = rules.Any(r => r.Enabled && (r.DownloadLimitKBps > 0 || r.UploadLimitKBps > 0));
                if (!hasActive && autoUnload)
                {
                    if (_winDivertEngine.IsRunning)
                        _winDivertEngine.Stop(unloadDriver: true);
                    else
                        WinDivertAddonManager.UnloadDriver();
                    lock (_lock) { _lastError = null; }
                }
                else
                {
                    bool started = _winDivertEngine.Start(rules, _liveConnections);
                    lock (_lock) { _lastError = started ? null : _winDivertEngine.LastError; }
                }
                break;
        }
    }

    private void Load()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                _config = JsonSerializer.Deserialize<BandwidthLimiterConfigDto>(json) ?? new BandwidthLimiterConfigDto();
            }
        }
        catch
        {
            _config = new BandwidthLimiterConfigDto();
        }
    }

    private void SaveInternal()
    {
        try
        {
            var dir = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch { }
    }

    private static BandwidthRuleDto CloneRule(BandwidthRuleDto r) => new()
    {
        Id = r.Id,
        ApplicationPath = r.ApplicationPath,
        ApplicationName = r.ApplicationName,
        Enabled = r.Enabled,
        DownloadLimitKBps = r.DownloadLimitKBps,
        UploadLimitKBps = r.UploadLimitKBps,
        TemporaryMinutes = r.TemporaryMinutes,
        ExpiresAtUtc = r.ExpiresAtUtc,
        UpdatedUtc = r.UpdatedUtc
    };

    public void Dispose()
    {
        _winDivertEngine.Dispose();
    }
}
