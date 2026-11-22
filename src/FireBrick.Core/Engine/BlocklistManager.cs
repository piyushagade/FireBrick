using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Resolves domain blocklists and remote IP/CIDR blocklist URLs into managed Windows Defender Firewall block rules.
/// </summary>
public sealed class BlocklistManager
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    public static List<BlocklistSubscriptionDto> GetDefaultSubscriptions() =>
    [
        new BlocklistSubscriptionDto
        {
            Id = "builtin-telemetry-domains",
            Name = "Windows Telemetry Domains",
            Description = "Resolves common Microsoft telemetry endpoints to IP addresses and blocks outbound traffic.",
            Domains =
            [
                "vortex.data.microsoft.com",
                "settings-win.data.microsoft.com",
                "watson.telemetry.microsoft.com",
                "oca.telemetry.microsoft.com",
                "telemetry.microsoft.com"
            ],
            Enabled = true
        },
        new BlocklistSubscriptionDto
        {
            Id = "builtin-spamhaus-drop",
            Name = "Spamhaus DROP (High-Risk CIDRs)",
            Description = "Industry-standard hijacked/malicious netblock list from Spamhaus.",
            SourceUrl = "https://www.spamhaus.org/drop/drop.txt",
            Enabled = false
        }
    ];

    public async Task<int> SyncSubscriptionAsync(
        BlocklistSubscriptionDto sub,
        WindowsFirewallManager firewall,
        RuleLockMonitor? ruleLock = null,
        CancellationToken ct = default)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Resolve configured domains to IPv4 addresses
        foreach (var domain in sub.Domains.Where(d => !string.IsNullOrWhiteSpace(d)))
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(domain.Trim(), ct).ConfigureAwait(false);
                foreach (var ip in addrs)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && !GeoIpResolverCache.IsPrivateOrLocalIp(ip.ToString()))
                    {
                        targets.Add(ip.ToString());
                    }
                }
            }
            catch { }
        }

        // 2. Fetch remote IP/CIDR list if SourceUrl is provided
        if (!string.IsNullOrWhiteSpace(sub.SourceUrl))
        {
            try
            {
                var text = await Http.GetStringAsync(sub.SourceUrl, ct).ConfigureAwait(false);
                foreach (var rawLine in text.Split('\n'))
                {
                    var line = rawLine.Split(';', '#')[0].Trim();
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    // Accept valid IPv4 or IPv4/CIDR
                    var ipPart = line.Split('/')[0];
                    if (IPAddress.TryParse(ipPart, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork)
                    {
                        targets.Add(line);
                    }
                }
            }
            catch { }
        }

        var rulePrefix = GetRulePrefix(sub.Name);
        RemoveExistingRules(rulePrefix, firewall, ruleLock);

        if (targets.Count == 0)
        {
            sub.RuleEntryCount = 0;
            sub.LastSyncedUtc = DateTimeOffset.UtcNow;
            return 0;
        }

        // Windows Firewall supports ~1000 remote addresses per rule; chunk safely at 200 per rule
        var allTargets = targets.Take(2000).ToList();
        const int chunkSize = 200;
        int chunkIndex = 1;

        for (int i = 0; i < allTargets.Count; i += chunkSize)
        {
            var chunk = allTargets.Skip(i).Take(chunkSize);
            var ruleName = allTargets.Count <= chunkSize
                ? rulePrefix
                : $"{rulePrefix} (#{chunkIndex++})";

            var dto = new FirewallRuleDto
            {
                Name = ruleName,
                Description = $"Managed by FireBrick Blocklist '{sub.Name}' ({allTargets.Count} entries).",
                Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_ANY,
                RemoteAddresses = string.Join(",", chunk),
                Direction = RuleDirection.Outbound,
                Action = RuleAction.Block,
                Enabled = true,
                Profiles = FirewallProfileFlags.All,
                Grouping = "FireBrick Blocklists"
            };

            firewall.CreateRule(dto);
            ruleLock?.NotifyAuthorizedRuleAdded(ruleName);
        }

        sub.RuleEntryCount = allTargets.Count;
        sub.LastSyncedUtc = DateTimeOffset.UtcNow;
        return allTargets.Count;
    }

    public void RemoveSubscriptionRules(string subscriptionName, WindowsFirewallManager firewall, RuleLockMonitor? ruleLock = null)
    {
        RemoveExistingRules(GetRulePrefix(subscriptionName), firewall, ruleLock);
    }

    private static string GetRulePrefix(string name) => $"FireBrick Blocklist: {name.Trim()}";

    private static void RemoveExistingRules(string rulePrefix, WindowsFirewallManager firewall, RuleLockMonitor? ruleLock)
    {
        var existing = firewall.GetRules()
            .Where(r => r.Name.StartsWith(rulePrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var r in existing)
        {
            try
            {
                firewall.DeleteRule(r.Name);
                ruleLock?.NotifyAuthorizedRuleRemoved(r.Name);
            }
            catch { }
        }
    }
}
