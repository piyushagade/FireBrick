using System.Diagnostics;
using FireBrick.Core.Engine;
using FireBrick.Core.Ipc;
using FireBrick.Core.Models;

namespace FireBrick.App.Services;

/// <summary>
/// Unified backend facade for FireBrick.App.
/// Prefers talking to the privileged FireBrick.Service via Named Pipes, and falls back
/// seamlessly to in-process engines when running standalone.
/// </summary>
public sealed class FirewallBackendService : IDisposable
{
    public static FirewallBackendService Instance { get; } = new();

    private readonly FireBrickIpcClient _ipc = new();
    private readonly WindowsFirewallManager _localFirewall = new();
    private readonly LiveConnectionsMonitor _localLive = new();
    private readonly SecurityAuditMonitor _localAudit = new();
    private readonly TemporaryRuleManager _localTempRules = new();
    private readonly TcpConnectionKiller _localTcpKiller = new();
    private readonly NetworkProfileMonitor _localNetworkMonitor = new();
    private readonly RuleLockMonitor _localRuleLock = new();
    private readonly BlocklistManager _localBlocklists = new();
    private readonly AutoRuleManager _localAutoRules = new();
    private readonly HostsFileManager _localHosts = new();
    private readonly SettingsStore _settingsStore = new();
    private readonly object _autoRulesLock = new();
    private List<AutoRuleDto> _cachedAutoRules = new();
    private readonly UsageAnalyticsService _analytics;
    private readonly DnsResolverCache _dnsCache = new();
    private readonly GeoIpResolverCache _geoIpCache = new();
    private readonly Timer _expiryTimer;
    private readonly Timer _serviceEventPollTimer;
    private readonly Timer _dailyAnalyticsTimer;
    private readonly string? _selfExecutablePath = Environment.ProcessPath;
    private readonly HashSet<string> _notifiedApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _seenServiceEventKeys = new(StringComparer.Ordinal);
    private readonly DateTimeOffset _sessionStartUtc = DateTimeOffset.UtcNow;
    private int _isPollingEvents;
    private DateTimeOffset _lastServiceProbeUtc = DateTimeOffset.MinValue;

    public bool IsUsingService { get; private set; }
    public bool IsElevated => WindowsFirewallManager.IsProcessElevated();
    public DnsResolverCache DnsCache => _dnsCache;
    public GeoIpResolverCache GeoIpCache => _geoIpCache;
    public UsageAnalyticsService Analytics => _analytics;
    public string? PendingRulesSearchFilter { get; set; }

    public event EventHandler<ConnectionEventDto>? BlockedConnectionPromptRequested;
    public event EventHandler<ConnectionEventDto>? ConnectionEventArrived;
    public event EventHandler<FirewallProfileMode>? ProfileModeChanged;
    public event EventHandler<NotificationMode>? NotificationModeChanged;
    public event EventHandler<bool>? ServiceConnectionChanged;
    public event EventHandler? AutoRulesChanged;

    private FirewallBackendService()
    {
        _analytics = new UsageAnalyticsService(() => _settingsStore.Get().SendDiagnosticsAndUsage);
        _localAudit.ConnectionEventReceived += OnLocalAuditEvent;
        _expiryTimer = new Timer(_ => CheckLocalExpiredRules(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        _serviceEventPollTimer = new Timer(_ => _ = PollServiceEventsAsync(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        _dailyAnalyticsTimer = new Timer(_ => _ = TrackDailyAnalyticsAsync(), null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));
    }

    public async Task InitializeAsync()
    {
        // If launched elevated and bundled service needs install/start/update, self-heal automatically with zero prompts
        if (IsElevated)
        {
            await Task.Run(() =>
            {
                var health = StartupManager.InspectServiceHealth();
                if (health.NeedsInstall || health.NeedsStart || health.NeedsUpdate)
                {
                    try { StartupManager.InstallOrRepairService(health.BundledBinaryPath); } catch { }
                }
            }).ConfigureAwait(false);
        }

        await ReconnectServiceAsync().ConfigureAwait(false);
        if (!IsUsingService)
        {
            _localAudit.TryStart(loadRecentHistory: true);
        }

        try { await GetAutoRulesAsync().ConfigureAwait(false); } catch { }
        _ = TrackLaunchAnalyticsAsync();
    }

    private async Task TrackLaunchAnalyticsAsync()
    {
        try
        {
            await EnsureSelfOutboundRuleAsync().ConfigureAwait(false);
            var status = await GetStatusAsync().ConfigureAwait(false);
            await _analytics.TrackAppLaunchAsync(status.ProfileMode, IsUsingService).ConfigureAwait(false);
        }
        catch { }
    }

    private async Task EnsureSelfOutboundRuleAsync()
    {
        if (string.IsNullOrWhiteSpace(_selfExecutablePath))
            return;

        var cfg = _settingsStore.Get();
        if (!cfg.SendDiagnosticsAndUsage && !cfg.EnableGeoIpLookup)
            return;

        try
        {
            var rules = await GetRulesAsync().ConfigureAwait(false);
            bool hasExistingSelfRule = rules.Any(r =>
                r.Direction == RuleDirection.Outbound &&
                (string.Equals(r.ExpandedApplicationPath, _selfExecutablePath, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(r.ApplicationName, _selfExecutablePath, StringComparison.OrdinalIgnoreCase)));

            if (hasExistingSelfRule)
                return;

            await CreateRuleAsync(new FirewallRuleDto
            {
                Name = "FireBrick: Allow Self Outbound (HTTP/HTTPS)",
                Description = "Allows FireBrick to perform GeoIP lookups, blocklist syncs, and anonymous usage analytics (when enabled in Settings).",
                ApplicationName = _selfExecutablePath,
                ExpandedApplicationPath = _selfExecutablePath,
                Protocol = 6, // TCP
                RemotePorts = "80,443",
                Direction = RuleDirection.Outbound,
                Action = RuleAction.Allow,
                Enabled = true,
                Profiles = FirewallProfileFlags.All,
                Grouping = "FireBrick Rules"
            }).ConfigureAwait(false);
        }
        catch
        {
            // Non-fatal if running unprivileged without service
        }
    }

    private async Task TrackDailyAnalyticsAsync()
    {
        try
        {
            var status = await GetStatusAsync().ConfigureAwait(false);
            await _analytics.TrackDailyActiveIfNeededAsync(status.ProfileMode, IsUsingService).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task<bool> ReconnectServiceAsync()
    {
        bool wasConnected = IsUsingService;
        bool connected = false;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (await _ipc.IsServiceAvailableAsync().ConfigureAwait(false))
            {
                connected = true;
                break;
            }
            await Task.Delay(350).ConfigureAwait(false);
        }

        IsUsingService = connected;
        if (connected != wasConnected)
        {
            ServiceConnectionChanged?.Invoke(this, connected);
        }
        return connected;
    }

    public AppSettingsDto GetSettings() => _settingsStore.Get();

    public void SaveSettings(AppSettingsDto settings) => _settingsStore.Save(settings);

    private void MarkServiceDisconnected()
    {
        bool was = IsUsingService;
        IsUsingService = false;
        _lastServiceProbeUtc = DateTimeOffset.UtcNow;
        if (was)
        {
            ServiceConnectionChanged?.Invoke(this, false);
        }
    }

    public async Task<FirewallStatusDto> GetStatusAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                var status = await _ipc.SendAndDeserializeAsync<FirewallStatusDto>(IpcCommands.GetStatus, null, 2500).ConfigureAwait(false);
                if (status != null) return status;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() =>
        {
            var states = _localFirewall.GetProfileEnabledStates();
            var tempMap = _localTempRules.GetActiveMap();
            var rules = _localFirewall.GetRules(tempMap);
            var cfg = _settingsStore.Get();

            return new FirewallStatusDto
            {
                ProfileMode = _localFirewall.GetCurrentProfileMode(),
                NotificationMode = cfg.NotificationMode,
                DomainFirewallEnabled = states.Domain,
                PrivateFirewallEnabled = states.Private,
                PublicFirewallEnabled = states.Public,
                TotalRulesCount = rules.Count,
                EnabledRulesCount = rules.Count(r => r.Enabled),
                InvalidRulesCount = rules.Count(r => r.IsInvalidPath),
                TemporaryRulesCount = tempMap.Count,
                BlockedEventsCount = _localAudit.GetBlockedCount(),
                IsServiceConnected = false,
                IsElevated = IsElevated,
                IsAuditPolicyEnabled = SecurityAuditMonitor.CheckWfpAuditPolicyEnabled(),
                IsRuleLockEnabled = cfg.EnableRuleLock
            };
        }).ConfigureAwait(false);
    }

    public async Task SetProfileModeAsync(FirewallProfileMode mode)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            await _ipc.SendAsync(IpcCommands.SetProfileMode, mode).ConfigureAwait(false);
        }
        else
        {
            await Task.Run(() => _localFirewall.SetProfileMode(mode)).ConfigureAwait(false);
        }

        ProfileModeChanged?.Invoke(this, mode);
    }

    public async Task SetNotificationModeAsync(NotificationMode mode)
    {
        var cfg = _settingsStore.Get();
        cfg.NotificationMode = mode;
        _settingsStore.Save(cfg);

        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            await _ipc.SendAsync(IpcCommands.SetNotificationMode, mode).ConfigureAwait(false);
        }

        NotificationModeChanged?.Invoke(this, mode);
    }

    public async Task<List<FirewallRuleDto>> GetRulesAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return await _ipc.SendAndDeserializeAsync<List<FirewallRuleDto>>(IpcCommands.GetRules, null, 4000).ConfigureAwait(false)
                       ?? new List<FirewallRuleDto>();
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localFirewall.GetRules(_localTempRules.GetActiveMap())).ConfigureAwait(false);
    }

    public async Task CreateRuleAsync(FirewallRuleDto rule)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            var resp = await _ipc.SendAsync(IpcCommands.CreateRule, rule).ConfigureAwait(false);
            if (!resp.Success) throw new InvalidOperationException(resp.Error);
            return;
        }

        await Task.Run(() =>
        {
            _localFirewall.CreateRule(rule);
            if (rule.IsTemporary && rule.ExpiresAtUtc.HasValue)
            {
                _localTempRules.Register(new TemporaryRuleDto
                {
                    RuleName = rule.Name,
                    ApplicationPath = rule.ExpandedApplicationPath.Length > 0 ? rule.ExpandedApplicationPath : rule.ApplicationName,
                    Direction = rule.Direction,
                    Action = rule.Action,
                    ExpiresAtUtc = rule.ExpiresAtUtc.Value
                });
            }
        }).ConfigureAwait(false);
    }

    public async Task UpdateRuleAsync(string originalName, FirewallRuleDto updated)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            var resp = await _ipc.SendAsync(IpcCommands.UpdateRule, new UpdateRulePayload
            {
                OriginalName = originalName,
                Rule = updated
            }).ConfigureAwait(false);
            if (!resp.Success) throw new InvalidOperationException(resp.Error);
            return;
        }

        await Task.Run(() => _localFirewall.UpdateRule(originalName, updated)).ConfigureAwait(false);
    }

    public async Task SetRuleEnabledAsync(string ruleName, bool enabled)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            var resp = await _ipc.SendAsync(IpcCommands.SetRuleEnabled, new ToggleRulePayload
            {
                RuleName = ruleName,
                Enabled = enabled
            }).ConfigureAwait(false);
            if (!resp.Success) throw new InvalidOperationException(resp.Error);
            return;
        }

        await Task.Run(() => _localFirewall.SetRuleEnabled(ruleName, enabled)).ConfigureAwait(false);
    }

    public async Task DeleteRuleAsync(string ruleName)
    {
        // Clear notified cache so if the user deletes a rule and re-tests the app, notifications trigger again
        lock (_notifiedApps)
        {
            _notifiedApps.Clear();
        }

        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            var resp = await _ipc.SendAsync(IpcCommands.DeleteRule, ruleName).ConfigureAwait(false);
            if (!resp.Success) throw new InvalidOperationException(resp.Error);
            return;
        }

        await Task.Run(() =>
        {
            _localFirewall.DeleteRule(ruleName);
            _localTempRules.Remove(ruleName);
        }).ConfigureAwait(false);
    }

    public async Task<int> CleanupInvalidRulesAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<int>(IpcCommands.CleanupInvalidRules).ConfigureAwait(false);
        }

        return await Task.Run(() => _localFirewall.CleanupInvalidRules()).ConfigureAwait(false);
    }

    public async Task<FirewallRuleDto> CreateQuickRuleAsync(
        string appPath,
        RuleAction action,
        RuleDirection direction = RuleDirection.Outbound,
        int? temporaryMinutes = null)
    {
        FirewallRuleDto result;
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            result = (await _ipc.SendAndDeserializeAsync<FirewallRuleDto>(IpcCommands.CreateQuickRule, new QuickRulePayload
            {
                ApplicationPath = appPath,
                Action = action,
                Direction = direction,
                TemporaryMinutes = temporaryMinutes
            }).ConfigureAwait(false))!;
        }
        else
        {
            result = await Task.Run(() =>
            {
                bool isTemp = temporaryMinutes.HasValue && temporaryMinutes.Value > 0;
                var dto = _localFirewall.CreateQuickAppRule(appPath, action, direction, isTemp);
                if (isTemp)
                {
                    dto.ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(temporaryMinutes!.Value);
                    _localTempRules.Register(new TemporaryRuleDto
                    {
                        RuleName = dto.Name,
                        ApplicationPath = dto.ExpandedApplicationPath,
                        Direction = dto.Direction,
                        Action = dto.Action,
                        ExpiresAtUtc = dto.ExpiresAtUtc.Value
                    });
                }
                return dto;
            }).ConfigureAwait(false);
        }

        if (action == RuleAction.Block && _settingsStore.Get().KillConnectionsOnBlock && !string.IsNullOrWhiteSpace(appPath))
        {
            try { await KillConnectionsForAppAsync(appPath).ConfigureAwait(false); } catch { }
        }

        return result;
    }

    public async Task<int> KillConnectionsForAppAsync(string appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath)) return 0;
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<int>(IpcCommands.KillConnectionsForApp, appPath).ConfigureAwait(false);
        }

        return await Task.Run(() => _localTcpKiller.KillConnectionsForExecutable(appPath)).ConfigureAwait(false);
    }

    public async Task SetRuleLockAsync(bool enabled)
    {
        var cfg = _settingsStore.Get();
        cfg.EnableRuleLock = enabled;
        _settingsStore.Save(cfg);

        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            await _ipc.SendAsync(IpcCommands.SetRuleLock, enabled).ConfigureAwait(false);
            return;
        }

        await Task.Run(() =>
        {
            if (enabled) _localRuleLock.Arm(_localFirewall.GetRules());
            else _localRuleLock.Disarm();
        }).ConfigureAwait(false);
    }

    public async Task<List<RuleLockAlertDto>> GetRuleLockAlertsAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<List<RuleLockAlertDto>>(IpcCommands.GetRuleLockAlerts).ConfigureAwait(false)
                   ?? new List<RuleLockAlertDto>();
        }

        return _localRuleLock.GetAlerts();
    }

    public async Task<int> SyncBlocklistAsync(BlocklistSubscriptionDto sub)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<int>(IpcCommands.SyncBlocklist, sub, 20000).ConfigureAwait(false);
        }

        return await _localBlocklists.SyncSubscriptionAsync(sub, _localFirewall, _localRuleLock).ConfigureAwait(false);
    }

    public async Task RemoveBlocklistAsync(string name)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            await _ipc.SendAsync(IpcCommands.RemoveBlocklist, name).ConfigureAwait(false);
            return;
        }

        await Task.Run(() => _localBlocklists.RemoveSubscriptionRules(name, _localFirewall, _localRuleLock)).ConfigureAwait(false);
    }

    public async Task<string> GetCurrentNetworkNameAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<string>(IpcCommands.GetCurrentNetworkName).ConfigureAwait(false)
                   ?? "Unknown";
        }

        return await Task.Run(() => _localNetworkMonitor.GetCurrentNetworkName()).ConfigureAwait(false);
    }

    public async Task<List<ConnectionEventDto>> GetRecentEventsAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return await _ipc.SendAndDeserializeAsync<List<ConnectionEventDto>>(IpcCommands.GetRecentEvents, null, 3000).ConfigureAwait(false)
                       ?? new List<ConnectionEventDto>();
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localAudit.GetRecentEvents(500)).ConfigureAwait(false);
    }

    public async Task<List<ActiveConnectionDto>> GetActiveConnectionsAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return await _ipc.SendAndDeserializeAsync<List<ActiveConnectionDto>>(IpcCommands.GetActiveConnections, null, 3000).ConfigureAwait(false)
                       ?? new List<ActiveConnectionDto>();
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localLive.GetActiveConnections()).ConfigureAwait(false);
    }

    public async Task<List<TemporaryRuleDto>> GetTemporaryRulesAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return await _ipc.SendAndDeserializeAsync<List<TemporaryRuleDto>>(IpcCommands.GetTemporaryRules, null, 2500).ConfigureAwait(false)
                       ?? new List<TemporaryRuleDto>();
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return _localTempRules.GetActive().ToList();
    }

    public async Task RemoveTemporaryRuleAsync(string ruleName)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            await _ipc.SendAsync(IpcCommands.RemoveTemporaryRule, ruleName).ConfigureAwait(false);
            return;
        }

        await Task.Run(() =>
        {
            try { _localFirewall.DeleteRule(ruleName); } catch { }
            _localTempRules.Remove(ruleName);
        }).ConfigureAwait(false);
    }

    public async Task<List<AutoRuleDto>> GetAutoRulesAsync()
    {
        List<AutoRuleDto> list;
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                list = await _ipc.SendAndDeserializeAsync<List<AutoRuleDto>>(IpcCommands.GetAutoRules, null, 2500).ConfigureAwait(false)
                       ?? new List<AutoRuleDto>();
                lock (_autoRulesLock) { _cachedAutoRules = list; }
                return list;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        list = _localAutoRules.GetAll();
        lock (_autoRulesLock) { _cachedAutoRules = list; }
        return list;
    }

    public async Task SaveAutoRulesAsync(List<AutoRuleDto> rules)
    {
        _localAutoRules.SaveAll(rules);
        var normalized = _localAutoRules.GetAll();
        lock (_autoRulesLock) { _cachedAutoRules = normalized; }

        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                await _ipc.SendAsync(IpcCommands.SaveAutoRules, normalized).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        AutoRulesChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task UpsertAutoRuleAsync(AutoRuleDto rule)
    {
        var current = await GetAutoRulesAsync().ConfigureAwait(false);
        int idx = current.FindIndex(r => string.Equals(r.Id, rule.Id, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0) current[idx] = rule;
        else current.Add(rule);
        await SaveAutoRulesAsync(current).ConfigureAwait(false);
    }

    public async Task RecordAutoRuleHitAsync(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId)) return;

        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                await _ipc.SendAsync(IpcCommands.RecordAutoRuleHit, ruleId).ConfigureAwait(false);
                _ = GetAutoRulesAsync();
                return;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        _localAutoRules.RecordHit(ruleId);
        lock (_autoRulesLock) { _cachedAutoRules = _localAutoRules.GetAll(); }
        AutoRulesChanged?.Invoke(this, EventArgs.Empty);
    }

    public AutoRuleDto? MatchAutoRule(ConnectionEventDto evt)
    {
        List<AutoRuleDto> snapshot;
        lock (_autoRulesLock)
        {
            snapshot = _cachedAutoRules.Count > 0 ? _cachedAutoRules : _localAutoRules.GetAll();
        }
        return AutoRuleManager.Match(evt, snapshot);
    }

    public async Task<bool> EnableAuditPolicyAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            return await _ipc.SendAndDeserializeAsync<bool>(IpcCommands.EnableAuditPolicy).ConfigureAwait(false);
        }

        return await Task.Run(() =>
        {
            bool ok = SecurityAuditMonitor.EnableWfpAuditPolicy();
            if (ok && !_localAudit.IsRunning)
                _localAudit.TryStart(loadRecentHistory: true);
            return ok;
        }).ConfigureAwait(false);
    }

    public async Task<int> ApplyPresetAsync(RulePresetDto preset)
    {
        int created = 0;
        var existing = await GetRulesAsync().ConfigureAwait(false);
        var names = new HashSet<string>(existing.Select(r => r.Name), StringComparer.OrdinalIgnoreCase);

        foreach (var rule in preset.Rules)
        {
            if (names.Contains(rule.Name)) continue;
            await CreateRuleAsync(rule).ConfigureAwait(false);
            created++;
        }

        if (created > 0)
            _analytics.TrackPresetApplied();

        return created;
    }

    public string ExportRulesJson(IEnumerable<FirewallRuleDto> rules) => _localFirewall.ExportRulesJson(rules);

    public Task<int> ImportRulesJsonAsync(string json) => Task.Run(() => _localFirewall.ImportRulesJson(json));

    public async Task<HostsFileDocumentDto> GetHostsFileAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                var doc = await _ipc.SendAndDeserializeAsync<HostsFileDocumentDto>(IpcCommands.GetHostsFile).ConfigureAwait(false);
                if (doc != null) return doc;
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command", StringComparison.OrdinalIgnoreCase))
            {
                // Older service binary running; hosts file is readable directly
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localHosts.LoadDocument()).ConfigureAwait(false);
    }

    public async Task<HostsFileDocumentDto> SaveHostsEntriesAsync(List<HostsEntryDto> entries)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return (await _ipc.SendAndDeserializeAsync<HostsFileDocumentDto>(IpcCommands.SaveHostsEntries, entries).ConfigureAwait(false))!;
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command", StringComparison.OrdinalIgnoreCase))
            {
                // Fall back to direct write (requires elevation or updating FireBrickService)
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localHosts.SaveEntries(entries)).ConfigureAwait(false);
    }

    public async Task<HostsFileDocumentDto> SaveHostsRawAsync(string rawContent)
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return (await _ipc.SendAndDeserializeAsync<HostsFileDocumentDto>(IpcCommands.SaveHostsRaw, rawContent).ConfigureAwait(false))!;
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command", StringComparison.OrdinalIgnoreCase))
            {
                // Fall back to direct write
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localHosts.SaveRaw(rawContent)).ConfigureAwait(false);
    }

    public async Task<HostsFileDocumentDto> RestoreHostsBackupAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return (await _ipc.SendAndDeserializeAsync<HostsFileDocumentDto>(IpcCommands.RestoreHostsBackup).ConfigureAwait(false))!;
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command", StringComparison.OrdinalIgnoreCase))
            {
                // Fall back to direct write
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(() => _localHosts.RestoreBackup()).ConfigureAwait(false);
    }

    public async Task<bool> FlushDnsCacheAsync()
    {
        if (await TryUseServiceAsync().ConfigureAwait(false))
        {
            try
            {
                return await _ipc.SendAndDeserializeAsync<bool>(IpcCommands.FlushDnsCache).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command", StringComparison.OrdinalIgnoreCase))
            {
                // Fall back to local ipconfig /flushdns
            }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                MarkServiceDisconnected();
            }
        }

        return await Task.Run(HostsFileManager.FlushDnsCache).ConfigureAwait(false);
    }

    public static void RelaunchAsAdministrator()
    {
        var exe = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exe)) return;

        Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = true,
            Verb = "runas"
        });
    }

    private async Task<bool> TryUseServiceAsync()
    {
        if (IsUsingService)
            return true;

        // Re-probe at most every 5 seconds so starting FireBrickService connects automatically
        if ((DateTimeOffset.UtcNow - _lastServiceProbeUtc).TotalSeconds < 5)
            return false;

        _lastServiceProbeUtc = DateTimeOffset.UtcNow;
        IsUsingService = await _ipc.IsServiceAvailableAsync().ConfigureAwait(false);
        return IsUsingService;
    }

    private async Task PollServiceEventsAsync()
    {
        if (!IsUsingService) return;
        if (Interlocked.Exchange(ref _isPollingEvents, 1) == 1) return;

        try
        {
            var events = await _ipc.SendAndDeserializeAsync<List<ConnectionEventDto>>(IpcCommands.GetRecentEvents, null, 3000).ConfigureAwait(false);
            if (events == null || events.Count == 0) return;

            foreach (var evt in events)
            {
                // Only notify on fresh events occurring after this UI session started
                if (evt.TimestampUtc <= _sessionStartUtc)
                    continue;

                var key = $"{evt.TimestampUtc.UtcTicks}|{evt.EventId}|{evt.ProcessId}|{evt.ApplicationPath}|{evt.RemoteAddress}:{evt.RemotePort}";
                lock (_seenServiceEventKeys)
                {
                    if (!_seenServiceEventKeys.Add(key))
                        continue;
                    if (_seenServiceEventKeys.Count > 2000)
                        _seenServiceEventKeys.Clear();
                }

                HandleIncomingConnectionEvent(evt, allowLocalAutoRule: false);
            }
        }
        catch
        {
            // Non-fatal background poll error
        }
        finally
        {
            Interlocked.Exchange(ref _isPollingEvents, 0);
        }
    }

    private void OnLocalAuditEvent(object? sender, ConnectionEventDto evt)
    {
        HandleIncomingConnectionEvent(evt, allowLocalAutoRule: true);
    }

    private void HandleIncomingConnectionEvent(ConnectionEventDto evt, bool allowLocalAutoRule)
    {
        ConnectionEventArrived?.Invoke(this, evt);

        if (evt.Action != RuleAction.Block || evt.Direction != RuleDirection.Outbound)
            return;

        // Skip raw kernel packet drops (e.g. Event 5152 ICMP/PID 0 with Application "-") from interactive app prompts
        if (string.IsNullOrWhiteSpace(evt.ApplicationPath) ||
            evt.ApplicationPath.Trim() == "-" ||
            (evt.EventId == 5152 && evt.ProcessId == 0))
            return;

        // Avoid self-prompt loops if FireBrick.App.exe itself is blocked in Medium/High filtering mode
        if (!string.IsNullOrWhiteSpace(_selfExecutablePath) &&
            string.Equals(evt.ApplicationPath, _selfExecutablePath, StringComparison.OrdinalIgnoreCase))
            return;

        // Already handled silently by a service-side Instant Auto-Rule
        if (!string.IsNullOrWhiteSpace(evt.AutoRuleHandled))
            return;

        // Evaluate user-defined Auto-Rules
        var matchedAutoRule = MatchAutoRule(evt);
        if (matchedAutoRule != null)
        {
            if (matchedAutoRule.TriggerMode == AutoRuleTriggerMode.Instant)
            {
                if (allowLocalAutoRule)
                {
                    lock (_notifiedApps)
                    {
                        if (!_notifiedApps.Add($"auto|{matchedAutoRule.Id}|{evt.ApplicationPath}|{evt.RemoteEndpoint}"))
                            return;
                    }
                    try
                    {
                        var fwRule = AutoRuleManager.BuildFirewallRule(matchedAutoRule, evt);
                        _localFirewall.CreateRule(fwRule);
                        if (fwRule.IsTemporary && fwRule.ExpiresAtUtc.HasValue)
                        {
                            _localTempRules.Register(new TemporaryRuleDto
                            {
                                RuleName = fwRule.Name,
                                ApplicationPath = fwRule.ExpandedApplicationPath,
                                Direction = fwRule.Direction,
                                Action = fwRule.Action,
                                ExpiresAtUtc = fwRule.ExpiresAtUtc.Value
                            });
                        }
                        if (matchedAutoRule.Action == RuleAction.Block && _settingsStore.Get().KillConnectionsOnBlock)
                        {
                            _localTcpKiller.KillConnectionsForExecutable(evt.ApplicationPath);
                        }
                        _localAutoRules.RecordHit(matchedAutoRule.Id);
                        lock (_autoRulesLock) { _cachedAutoRules = _localAutoRules.GetAll(); }
                        AutoRulesChanged?.Invoke(this, EventArgs.Empty);
                    }
                    catch { }
                }
                return;
            }

            // Countdown Auto-Rule: show the alert window so the countdown runs with cancel/override
            lock (_notifiedApps)
            {
                if (!_notifiedApps.Add(evt.ApplicationPath)) return;
            }
            _analytics.TrackInterception();
            BlockedConnectionPromptRequested?.Invoke(this, evt);
            return;
        }

        var mode = _settingsStore.Get().NotificationMode;
        if (mode == NotificationMode.Disabled) return;

        if (mode == NotificationMode.LowNotification && evt.SignatureStatus == SignatureTrustStatus.Trusted)
            return;

        if (mode == NotificationMode.LearningMode && evt.SignatureStatus == SignatureTrustStatus.Trusted)
        {
            if (allowLocalAutoRule && !string.IsNullOrWhiteSpace(evt.ApplicationPath))
            {
                lock (_notifiedApps)
                {
                    if (!_notifiedApps.Add(evt.ApplicationPath)) return;
                }
                try { _localFirewall.CreateQuickAppRule(evt.ApplicationPath, RuleAction.Allow); } catch { }
            }
            return;
        }

        if (!string.IsNullOrWhiteSpace(evt.ApplicationPath))
        {
            lock (_notifiedApps)
            {
                if (!_notifiedApps.Add(evt.ApplicationPath)) return;
            }
            _analytics.TrackInterception();
            BlockedConnectionPromptRequested?.Invoke(this, evt);
        }
    }

    private void CheckLocalExpiredRules()
    {
        if (IsUsingService) return;
        try
        {
            var expired = _localTempRules.PopExpired();
            foreach (var r in expired)
            {
                try { _localFirewall.DeleteRule(r.RuleName); } catch { }
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _dailyAnalyticsTimer.Dispose();
        _serviceEventPollTimer.Dispose();
        _expiryTimer.Dispose();
        _localAudit.Dispose();
        _analytics.Dispose();
    }
}
