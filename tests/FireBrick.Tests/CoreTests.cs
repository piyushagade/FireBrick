using System.Net;
using System.Net.Http;
using FireBrick.Core.Engine;
using FireBrick.Core.Ipc;
using FireBrick.Core.Models;
using Xunit;

namespace FireBrick.Tests;

public class CoreTests
{
    [Fact]
    public void DevicePathConverter_HandlesSystemAndStandardPaths()
    {
        Assert.Equal("System", DevicePathConverter.ConvertToWin32Path("System"));
        Assert.Equal(string.Empty, DevicePathConverter.ConvertToWin32Path(""));
        var expanded = DevicePathConverter.ConvertToWin32Path(@"%SystemRoot%\System32\notepad.exe");
        Assert.Contains("notepad.exe", expanded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("%SystemRoot%", expanded, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FindDuplicateRules_GroupsExactDuplicates()
    {
        var r1 = new FirewallRuleDto { Name = "Rule A", ApplicationName = @"C:\app.exe", Direction = RuleDirection.Outbound, Action = RuleAction.Allow, Protocol = 6, RemotePorts = "443" };
        var r2 = new FirewallRuleDto { Name = "Rule B", ApplicationName = @"C:\app.exe", Direction = RuleDirection.Outbound, Action = RuleAction.Allow, Protocol = 6, RemotePorts = "443" };
        var r3 = new FirewallRuleDto { Name = "Rule C", ApplicationName = @"C:\other.exe", Direction = RuleDirection.Outbound, Action = RuleAction.Block, Protocol = 6, RemotePorts = "443" };

        var groups = WindowsFirewallManager.FindDuplicateRules([r1, r2, r3]);
        Assert.Single(groups);
        Assert.Equal(2, groups[0].Rules.Count);
    }

    [Fact]
    public void TemporaryRuleManager_RegistersAndExpiresRules()
    {
        var tmpFile = Path.Combine(Path.GetTempPath(), $"firebrick_test_{Guid.NewGuid():N}.json");
        try
        {
            var mgr = new TemporaryRuleManager(tmpFile);
            var now = DateTimeOffset.UtcNow;

            mgr.Register(new TemporaryRuleDto
            {
                RuleName = "TempAllow1",
                ApplicationPath = @"C:\test.exe",
                ExpiresAtUtc = now.AddMinutes(10)
            });
            mgr.Register(new TemporaryRuleDto
            {
                RuleName = "TempAllowExpired",
                ApplicationPath = @"C:\old.exe",
                ExpiresAtUtc = now.AddMinutes(-1)
            });

            var active = mgr.GetActive();
            Assert.Single(active);
            Assert.Equal("TempAllow1", active[0].RuleName);

            var expired = mgr.PopExpired(now);
            Assert.Single(expired);
            Assert.Equal("TempAllowExpired", expired[0].RuleName);
        }
        finally
        {
            if (File.Exists(tmpFile)) File.Delete(tmpFile);
        }
    }

    [Fact]
    public void SecurityAuditMonitor_ParsesWfp5157EventXml()
    {
        const string sampleXml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <EventData>
                <Data Name="ProcessID">4321</Data>
                <Data Name="Application">C:\Windows\System32\curl.exe</Data>
                <Data Name="Direction">%%14593</Data>
                <Data Name="SourceAddress">192.168.1.50</Data>
                <Data Name="SourcePort">54321</Data>
                <Data Name="DestAddress">1.1.1.1</Data>
                <Data Name="DestPort">443</Data>
                <Data Name="Protocol">6</Data>
                <Data Name="FilterOrigin">AppContainer Loopback</Data>
              </EventData>
            </Event>
            """;

        var dto = SecurityAuditMonitor.ParseEventXml(sampleXml, 5157, DateTime.UtcNow);
        Assert.NotNull(dto);
        Assert.Equal(RuleAction.Block, dto!.Action);
        Assert.Equal(RuleDirection.Outbound, dto.Direction);
        Assert.Equal("curl.exe", dto.ApplicationName);
        Assert.Equal("TCP", dto.Protocol);
        Assert.Equal("1.1.1.1:443", dto.RemoteEndpoint);
        Assert.Equal(4321, dto.ProcessId);
    }

    [Fact]
    public async Task PipeFraming_RoundTripsIpcRequestAndResponse()
    {
        using var ms = new MemoryStream();
        var req = new IpcRequest { Command = IpcCommands.GetStatus, PayloadJson = "{}" };
        await PipeFraming.WriteMessageAsync(ms, req, CancellationToken.None);

        ms.Position = 0;
        var decoded = await PipeFraming.ReadMessageAsync<IpcRequest>(ms, CancellationToken.None);
        Assert.NotNull(decoded);
        Assert.Equal(IpcCommands.GetStatus, decoded!.Command);
    }

    [Fact]
    public void LiveConnectionsMonitor_EnumeratesActiveSockets()
    {
        var monitor = new LiveConnectionsMonitor();
        var conns = monitor.GetActiveConnections();
        Assert.NotNull(conns);
        Assert.True(conns.Count > 0);
    }

    [Fact]
    public void PresetCatalog_ContainsValidPresets()
    {
        var presets = PresetCatalog.GetPresets();
        Assert.True(presets.Count >= 4);
        Assert.All(presets, p => Assert.NotEmpty(p.Rules));
    }

    [Fact]
    public void WindowsFirewallManager_ReadsStatusAndRules()
    {
        var fw = new WindowsFirewallManager();
        var states = fw.GetProfileEnabledStates();
        var mode = fw.GetCurrentProfileMode();
        var rules = fw.GetRules();
        Assert.NotNull(rules);
        Assert.True(rules.Count > 0);
    }

    [Fact]
    public void GeoIpResolverCache_IdentifiesPrivateAndPublicIps()
    {
        Assert.True(GeoIpResolverCache.IsPrivateOrLocalIp("127.0.0.1"));
        Assert.True(GeoIpResolverCache.IsPrivateOrLocalIp("192.168.1.50"));
        Assert.True(GeoIpResolverCache.IsPrivateOrLocalIp("10.0.0.1"));
        Assert.True(GeoIpResolverCache.IsPrivateOrLocalIp("172.16.5.4"));
        Assert.False(GeoIpResolverCache.IsPrivateOrLocalIp("1.1.1.1"));
        Assert.False(GeoIpResolverCache.IsPrivateOrLocalIp("8.8.8.8"));
    }

    [Fact]
    public void NetworkProfileMonitor_MatchesConfiguredSsid()
    {
        var rules = new List<NetworkProfileRuleDto>
        {
            new() { NetworkName = "CoffeeShopWiFi", TargetProfileMode = FirewallProfileMode.HighFiltering, Enabled = true },
            new() { NetworkName = "HomeWiFi", TargetProfileMode = FirewallProfileMode.MediumFiltering, Enabled = true }
        };

        var match = NetworkProfileMonitor.MatchRule("coffeeshopwifi", rules);
        Assert.NotNull(match);
        Assert.Equal(FirewallProfileMode.HighFiltering, match!.TargetProfileMode);
        Assert.Null(NetworkProfileMonitor.MatchRule("UnknownSSID", rules));
    }

    [Fact]
    public void AppAggregator_GroupsRulesAndComputesCharts()
    {
        var rules = new List<FirewallRuleDto>
        {
            new() { Name = "R1", ApplicationName = @"C:\app.exe", ExpandedApplicationPath = @"C:\app.exe", Action = RuleAction.Allow, Enabled = true },
            new() { Name = "R2", ApplicationName = @"C:\app.exe", ExpandedApplicationPath = @"C:\app.exe", Action = RuleAction.Block, Enabled = true }
        };
        var live = new List<ActiveConnectionDto>
        {
            new() { ProcessName = "app", ProcessPath = @"C:\app.exe", Protocol = "TCP", RemoteAddress = "1.1.1.1", RemotePort = 443 }
        };
        var events = new List<ConnectionEventDto>
        {
            new() { ApplicationName = "app.exe", ApplicationPath = @"C:\app.exe", Action = RuleAction.Block, TimestampUtc = DateTimeOffset.UtcNow.AddMinutes(-2) },
            new() { ApplicationName = "app.exe", ApplicationPath = @"C:\app.exe", Action = RuleAction.Block, TimestampUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }
        };

        var groups = AppAggregator.GroupByApplication(rules, live, events);
        Assert.Single(groups);
        Assert.Equal(2, groups[0].RuleCount);
        Assert.Equal(1, groups[0].ActiveConnectionCount);
        Assert.Equal(2, groups[0].BlockedEventsCount);

        var top = AppAggregator.BuildTopBlockedApps(events);
        Assert.Single(top);
        Assert.Equal(2, top[0].BlockedCount);

        var buckets = AppAggregator.BuildActivityBuckets(events);
        Assert.Equal(12, buckets.Count);
        Assert.True(buckets.Sum(b => b.BlockedCount) >= 2);
    }

    [Fact]
    public void AppSettingsDto_DefaultsSendDiagnosticsAndUsageToTrue()
    {
        var settings = new AppSettingsDto();
        Assert.True(settings.SendDiagnosticsAndUsage);
    }

    [Fact]
    public async Task UsageAnalyticsService_RespectsOptOutAndSendsExpectedPostUrls()
    {
        var calls = new List<(HttpMethod Method, string Url)>();
        var handler = new StubHttpHandler(req =>
        {
            calls.Add((req.Method, req.RequestUri!.ToString()));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"namespace":"firebrick","key":"test","count":1}""")
            };
        });

        bool enabled = false;
        var statePath = Path.Combine(Path.GetTempPath(), $"firebrick_analytics_{Guid.NewGuid():N}.json");
        try
        {
            using var svc = new UsageAnalyticsService(
                isEnabled: () => enabled,
                statePath: statePath,
                crashLogPath: Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid():N}.log"),
                httpHandler: handler);

            Assert.False(await svc.IncrementAsync("app-launches"));
            Assert.Empty(calls);

            enabled = true;
            Assert.True(await svc.IncrementAsync("app-launches"));
            Assert.Single(calls);
            Assert.Equal(HttpMethod.Post, calls[0].Method);
            Assert.Equal("https://app.piyushagade.xyz/counter/firebrick/app-launches/up", calls[0].Url);
        }
        finally
        {
            if (File.Exists(statePath)) File.Delete(statePath);
        }
    }

    [Fact]
    public async Task UsageAnalyticsService_DeduplicatesDailyPingAndFirstRunAndTracksCrashGrowth()
    {
        var keys = new List<string>();
        var handler = new StubHttpHandler(req =>
        {
            var segments = req.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            // .../counter/firebrick/<key>/up
            keys.Add(segments[^2]);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        var now = new DateTimeOffset(2026, 11, 22, 14, 0, 0, TimeSpan.Zero);
        var statePath = Path.Combine(Path.GetTempPath(), $"firebrick_analytics_{Guid.NewGuid():N}.json");
        var crashPath = Path.Combine(Path.GetTempPath(), $"firebrick_crash_{Guid.NewGuid():N}.log");
        try
        {
            File.WriteAllText(crashPath, "crash 1\n");

            using var svc = new UsageAnalyticsService(
                isEnabled: () => true,
                statePath: statePath,
                crashLogPath: crashPath,
                httpHandler: handler,
                utcNow: () => now);

            await svc.TrackAppLaunchAsync(FirewallProfileMode.MediumFiltering, isServiceConnected: true, appVersion: "1.1.0");
            Assert.Contains("app-launches", keys);
            Assert.Contains("first-run", keys);
            Assert.Contains("crash-count", keys);
            Assert.Contains("dau-2026-11-22", keys);
            Assert.Contains("dau-total", keys);
            Assert.Contains("version-1_1_0", keys);
            Assert.Contains("profile-medium", keys);
            Assert.Contains("service-connected", keys);

            // Second launch on the same UTC day should not re-send first-run, crash-count, or dau-2026-11-22
            keys.Clear();
            await svc.TrackAppLaunchAsync(FirewallProfileMode.MediumFiltering, isServiceConnected: true, appVersion: "1.1.0");
            Assert.Contains("app-launches", keys);
            Assert.DoesNotContain("first-run", keys);
            Assert.DoesNotContain("crash-count", keys);
            Assert.DoesNotContain("dau-2026-11-22", keys);

            // Next UTC day + new crash entry should fire new DAU and crash-count
            keys.Clear();
            now = now.AddDays(1);
            File.AppendAllText(crashPath, "crash 2\n");
            await svc.TrackAppLaunchAsync(FirewallProfileMode.HighFiltering, isServiceConnected: false, appVersion: "1.1.0");
            Assert.Contains("dau-2026-11-23", keys);
            Assert.Contains("profile-high", keys);
            Assert.Contains("crash-count", keys);
            Assert.DoesNotContain("first-run", keys);
        }
        finally
        {
            if (File.Exists(statePath)) File.Delete(statePath);
            if (File.Exists(crashPath)) File.Delete(crashPath);
        }
    }

    [Fact]
    public async Task UsageAnalyticsService_CircuitBreakerGuardsOutagesAndRecoversAfterCooldown()
    {
        int httpCalls = 0;
        bool shouldFail = true;
        var handler = new StubHttpHandler(_ =>
        {
            httpCalls++;
            if (shouldFail)
                throw new HttpRequestException("Counter API unavailable");
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        var now = new DateTimeOffset(2026, 11, 22, 14, 0, 0, TimeSpan.Zero);
        var statePath = Path.Combine(Path.GetTempPath(), $"firebrick_analytics_{Guid.NewGuid():N}.json");
        try
        {
            using var svc = new UsageAnalyticsService(
                isEnabled: () => true,
                statePath: statePath,
                crashLogPath: Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid():N}.log"),
                httpHandler: handler,
                utcNow: () => now);

            // Two consecutive failures open the circuit
            Assert.False(await svc.IncrementAsync("interceptions-total"));
            Assert.False(svc.IsCircuitOpen);
            Assert.False(await svc.IncrementAsync("interceptions-total"));
            Assert.True(svc.IsCircuitOpen);
            Assert.Equal(2, httpCalls);

            // Subsequent calls during cooldown are skipped with zero network traffic
            Assert.False(await svc.IncrementAsync("interceptions-total"));
            Assert.Equal(2, httpCalls);

            // Advance past 15-minute cooldown and restore API -> circuit closes
            now = now.AddMinutes(16);
            shouldFail = false;
            Assert.True(await svc.IncrementAsync("interceptions-total"));
            Assert.False(svc.IsCircuitOpen);
            Assert.Equal(0, svc.ConsecutiveFailures);
            Assert.Equal(3, httpCalls);
        }
        finally
        {
            if (File.Exists(statePath)) File.Delete(statePath);
        }
    }

    private sealed class StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responder(request));
    }
}
