using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using FireBrick.Core.Engine;
using FireBrick.Core.Ipc;
using FireBrick.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FireBrick.Service;

/// <summary>
/// Privileged background service for FireBrick:
/// - Hosts the Named Pipe IPC server for FireBrick.App
/// - Monitors WFP Security Audit events in real time
/// - Auto-allows trusted signed executables in Learning Mode
/// - Automatically expires and removes temporary firewall rules
/// </summary>
public sealed class FireBrickWorker : BackgroundService
{
    private readonly ILogger<FireBrickWorker> _logger;
    private readonly WindowsFirewallManager _firewall;
    private readonly LiveConnectionsMonitor _liveConnections;
    private readonly SecurityAuditMonitor _auditMonitor;
    private readonly TemporaryRuleManager _tempRules;
    private readonly TcpConnectionKiller _tcpKiller;
    private readonly NetworkProfileMonitor _networkMonitor;
    private readonly RuleLockMonitor _ruleLock;
    private readonly BlocklistManager _blocklists;
    private readonly SettingsStore _settings;
    private readonly HashSet<string> _learningAutoAllowed = new(StringComparer.OrdinalIgnoreCase);
    private string _lastNetworkName = string.Empty;

    public FireBrickWorker(
        ILogger<FireBrickWorker> logger,
        WindowsFirewallManager firewall,
        LiveConnectionsMonitor liveConnections,
        SecurityAuditMonitor auditMonitor,
        TemporaryRuleManager tempRules,
        TcpConnectionKiller tcpKiller,
        NetworkProfileMonitor networkMonitor,
        RuleLockMonitor ruleLock,
        BlocklistManager blocklists,
        SettingsStore settings)
    {
        _logger = logger;
        _firewall = firewall;
        _liveConnections = liveConnections;
        _auditMonitor = auditMonitor;
        _tempRules = tempRules;
        _tcpKiller = tcpKiller;
        _networkMonitor = networkMonitor;
        _ruleLock = ruleLock;
        _blocklists = blocklists;
        _settings = settings;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FireBrick Service starting...");

        _auditMonitor.ConnectionEventReceived += OnConnectionEventReceived;
        if (!_auditMonitor.TryStart(loadRecentHistory: true))
        {
            _logger.LogWarning("SecurityAuditMonitor did not start: {Error}", _auditMonitor.LastError);
        }

        if (_settings.Get().EnableRuleLock)
        {
            try { _ruleLock.Arm(_firewall.GetRules()); } catch { }
        }

        var pipeTask = RunPipeServerLoopAsync(stoppingToken);
        var expiryTask = RunTempRuleExpiryLoopAsync(stoppingToken);
        var guardTask = RunProtectionLoopAsync(stoppingToken);

        await Task.WhenAll(pipeTask, expiryTask, guardTask).ConfigureAwait(false);
        _auditMonitor.Stop();
    }

    private async Task RunProtectionLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_ruleLock.IsArmed)
                {
                    var alerts = _ruleLock.CheckAndEnforce(_firewall);
                    foreach (var a in alerts)
                    {
                        _logger.LogWarning("Rule Lock detected external rule '{Rule}' (Reverted={Reverted})", a.RuleName, a.Reverted);
                    }
                }

                var cfg = _settings.Get();
                if (cfg.AutoSwitchNetworkProfiles && cfg.NetworkProfileRules.Count > 0)
                {
                    var netName = _networkMonitor.GetCurrentNetworkName();
                    if (!string.Equals(netName, _lastNetworkName, StringComparison.OrdinalIgnoreCase))
                    {
                        _lastNetworkName = netName;
                        var match = NetworkProfileMonitor.MatchRule(netName, cfg.NetworkProfileRules);
                        if (match != null)
                        {
                            _firewall.SetProfileMode(match.TargetProfileMode);
                            _logger.LogInformation("Auto-switched profile to {Mode} for network '{Net}'", match.TargetProfileMode, netName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Protection loop error.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void OnConnectionEventReceived(object? sender, ConnectionEventDto evt)
    {
        if (evt.Action != RuleAction.Block || evt.Direction != RuleDirection.Outbound)
            return;

        var mode = _settings.Get().NotificationMode;
        if (mode != NotificationMode.LearningMode)
            return;

        if (string.IsNullOrWhiteSpace(evt.ApplicationPath) ||
            evt.SignatureStatus != SignatureTrustStatus.Trusted)
            return;

        lock (_learningAutoAllowed)
        {
            if (!_learningAutoAllowed.Add(evt.ApplicationPath))
                return;
        }

        try
        {
            _firewall.CreateQuickAppRule(evt.ApplicationPath, RuleAction.Allow, RuleDirection.Outbound);
            _logger.LogInformation("Learning Mode auto-allowed signed app: {App}", evt.ApplicationPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Learning Mode failed to create rule for {App}", evt.ApplicationPath);
        }
    }

    private async Task RunTempRuleExpiryLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var expired = _tempRules.PopExpired();
                foreach (var rule in expired)
                {
                    try
                    {
                        _firewall.DeleteRule(rule.RuleName);
                        _logger.LogInformation("Expired temporary rule removed: {Rule}", rule.RuleName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete expired temporary rule: {Rule}", rule.RuleName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking temporary rule expirations.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RunPipeServerLoopAsync(CancellationToken ct)
    {
        var security = BuildPipeSecurity();

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = NamedPipeServerStreamAcl.Create(
                    IpcConstants.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096,
                    4096,
                    security);

                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                var clientPipe = server;
                server = null;
                _ = Task.Run(() => HandleClientAsync(clientPipe, ct), ct);
            }
            catch (OperationCanceledException)
            {
                server?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                server?.Dispose();
                _logger.LogError(ex, "Named pipe server loop error.");
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            try
            {
                var req = await PipeFraming.ReadMessageAsync<IpcRequest>(pipe, ct).ConfigureAwait(false);
                if (req == null) return;

                var resp = DispatchRequest(req);
                await PipeFraming.WriteMessageAsync(pipe, resp, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling IPC request.");
                try
                {
                    await PipeFraming.WriteMessageAsync(pipe, IpcResponse.Fail(ex.Message), ct).ConfigureAwait(false);
                }
                catch { }
            }
        }
    }

    private IpcResponse DispatchRequest(IpcRequest req)
    {
        try
        {
            switch (req.Command)
            {
                case IpcCommands.Ping:
                    return IpcResponse.Ok("pong");

                case IpcCommands.GetStatus:
                {
                    var states = _firewall.GetProfileEnabledStates();
                    var tempMap = _tempRules.GetActiveMap();
                    var rules = _firewall.GetRules(tempMap);
                    var cfg = _settings.Get();
                    var status = new FirewallStatusDto
                    {
                        ProfileMode = _firewall.GetCurrentProfileMode(),
                        NotificationMode = cfg.NotificationMode,
                        DomainFirewallEnabled = states.Domain,
                        PrivateFirewallEnabled = states.Private,
                        PublicFirewallEnabled = states.Public,
                        TotalRulesCount = rules.Count,
                        EnabledRulesCount = rules.Count(r => r.Enabled),
                        InvalidRulesCount = rules.Count(r => r.IsInvalidPath),
                        TemporaryRulesCount = tempMap.Count,
                        BlockedEventsCount = _auditMonitor.GetBlockedCount(),
                        IsServiceConnected = true,
                        IsElevated = WindowsFirewallManager.IsProcessElevated(),
                        IsAuditPolicyEnabled = SecurityAuditMonitor.CheckWfpAuditPolicyEnabled(),
                        IsRuleLockEnabled = cfg.EnableRuleLock
                    };
                    return IpcResponse.Ok(status);
                }

                case IpcCommands.SetProfileMode:
                {
                    var mode = JsonSerializer.Deserialize<FirewallProfileMode>(req.PayloadJson ?? "1");
                    _firewall.SetProfileMode(mode);
                    return IpcResponse.Ok();
                }

                case IpcCommands.SetNotificationMode:
                {
                    var mode = JsonSerializer.Deserialize<NotificationMode>(req.PayloadJson ?? "1");
                    var cfg = _settings.Get();
                    cfg.NotificationMode = mode;
                    _settings.Save(cfg);
                    return IpcResponse.Ok();
                }

                case IpcCommands.GetRules:
                    return IpcResponse.Ok(_firewall.GetRules(_tempRules.GetActiveMap()));

                case IpcCommands.CreateRule:
                {
                    var rule = JsonSerializer.Deserialize<FirewallRuleDto>(req.PayloadJson!)!;
                    _firewall.CreateRule(rule);
                    _ruleLock.NotifyAuthorizedRuleAdded(rule.Name);
                    if (rule.IsTemporary && rule.ExpiresAtUtc.HasValue)
                    {
                        _tempRules.Register(new TemporaryRuleDto
                        {
                            RuleName = rule.Name,
                            ApplicationPath = rule.ExpandedApplicationPath.Length > 0 ? rule.ExpandedApplicationPath : rule.ApplicationName,
                            Direction = rule.Direction,
                            Action = rule.Action,
                            ExpiresAtUtc = rule.ExpiresAtUtc.Value
                        });
                    }
                    return IpcResponse.Ok();
                }

                case IpcCommands.UpdateRule:
                {
                    var payload = JsonSerializer.Deserialize<UpdateRulePayload>(req.PayloadJson!)!;
                    _firewall.UpdateRule(payload.OriginalName, payload.Rule);
                    _ruleLock.NotifyAuthorizedRuleRemoved(payload.OriginalName);
                    _ruleLock.NotifyAuthorizedRuleAdded(payload.Rule.Name);
                    return IpcResponse.Ok();
                }

                case IpcCommands.DeleteRule:
                {
                    var ruleName = JsonSerializer.Deserialize<string>(req.PayloadJson!)!;
                    _firewall.DeleteRule(ruleName);
                    _ruleLock.NotifyAuthorizedRuleRemoved(ruleName);
                    _tempRules.Remove(ruleName);
                    return IpcResponse.Ok();
                }

                case IpcCommands.SetRuleEnabled:
                {
                    var payload = JsonSerializer.Deserialize<ToggleRulePayload>(req.PayloadJson!)!;
                    _firewall.SetRuleEnabled(payload.RuleName, payload.Enabled);
                    return IpcResponse.Ok();
                }

                case IpcCommands.CleanupInvalidRules:
                    return IpcResponse.Ok(_firewall.CleanupInvalidRules());

                case IpcCommands.GetRecentEvents:
                    return IpcResponse.Ok(_auditMonitor.GetRecentEvents(500));

                case IpcCommands.GetActiveConnections:
                    return IpcResponse.Ok(_liveConnections.GetActiveConnections());

                case IpcCommands.GetTemporaryRules:
                    return IpcResponse.Ok(_tempRules.GetActive());

                case IpcCommands.CreateQuickRule:
                {
                    var payload = JsonSerializer.Deserialize<QuickRulePayload>(req.PayloadJson!)!;
                    bool isTemp = payload.TemporaryMinutes.HasValue && payload.TemporaryMinutes.Value > 0;
                    var dto = _firewall.CreateQuickAppRule(payload.ApplicationPath, payload.Action, payload.Direction, isTemp);
                    _ruleLock.NotifyAuthorizedRuleAdded(dto.Name);
                    if (isTemp)
                    {
                        _tempRules.Register(new TemporaryRuleDto
                        {
                            RuleName = dto.Name,
                            ApplicationPath = dto.ExpandedApplicationPath,
                            Direction = dto.Direction,
                            Action = dto.Action,
                            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(payload.TemporaryMinutes!.Value)
                        });
                    }
                    return IpcResponse.Ok(dto);
                }

                case IpcCommands.RemoveTemporaryRule:
                {
                    var ruleName = JsonSerializer.Deserialize<string>(req.PayloadJson!)!;
                    _firewall.DeleteRule(ruleName);
                    _tempRules.Remove(ruleName);
                    return IpcResponse.Ok();
                }

                case IpcCommands.EnableAuditPolicy:
                    return IpcResponse.Ok(SecurityAuditMonitor.EnableWfpAuditPolicy());

                case IpcCommands.KillConnectionsForApp:
                {
                    var appPath = JsonSerializer.Deserialize<string>(req.PayloadJson!)!;
                    return IpcResponse.Ok(_tcpKiller.KillConnectionsForExecutable(appPath));
                }

                case IpcCommands.SetRuleLock:
                {
                    var enabled = JsonSerializer.Deserialize<bool>(req.PayloadJson ?? "false");
                    var cfg = _settings.Get();
                    cfg.EnableRuleLock = enabled;
                    _settings.Save(cfg);
                    if (enabled) _ruleLock.Arm(_firewall.GetRules());
                    else _ruleLock.Disarm();
                    return IpcResponse.Ok();
                }

                case IpcCommands.GetRuleLockAlerts:
                    return IpcResponse.Ok(_ruleLock.GetAlerts());

                case IpcCommands.SyncBlocklist:
                {
                    var sub = JsonSerializer.Deserialize<BlocklistSubscriptionDto>(req.PayloadJson!)!;
                    int count = _blocklists.SyncSubscriptionAsync(sub, _firewall, _ruleLock).GetAwaiter().GetResult();
                    return IpcResponse.Ok(count);
                }

                case IpcCommands.RemoveBlocklist:
                {
                    var name = JsonSerializer.Deserialize<string>(req.PayloadJson!)!;
                    _blocklists.RemoveSubscriptionRules(name, _firewall, _ruleLock);
                    return IpcResponse.Ok();
                }

                case IpcCommands.GetCurrentNetworkName:
                    return IpcResponse.Ok(_networkMonitor.GetCurrentNetworkName());

                default:
                    return IpcResponse.Fail($"Unknown command: {req.Command}");
            }
        }
        catch (Exception ex)
        {
            return IpcResponse.Fail(ex.Message);
        }
    }

    private static PipeSecurity BuildPipeSecurity()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        return ps;
    }
}
