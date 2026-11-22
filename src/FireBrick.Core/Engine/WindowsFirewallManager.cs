using System.Security.Principal;
using System.Text.Json;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Manages Windows Defender Firewall policies, profiles, and rules via INetFwPolicy2 COM API.
/// Replicates WFC's 4 filtering profiles, rule CRUD, invalid-path scanner, duplicate detector, and JSON import/export.
/// </summary>
public sealed class WindowsFirewallManager
{
    private const string HighLockdownRuleName = "FireBrick: High Filtering Outbound Block";

    public static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public FirewallProfileMode GetCurrentProfileMode()
    {
        var policy = NetFwFactory.CreatePolicy2();
        bool domainOn = policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_DOMAIN);
        bool privateOn = policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_PRIVATE);
        bool publicOn = policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_PUBLIC);

        if (!domainOn && !privateOn && !publicOn)
            return FirewallProfileMode.NoFiltering;

        int activeProfile = GetPrimaryActiveProfile(policy);
        int defaultOut = policy.get_DefaultOutboundAction(activeProfile);
        bool blockAllInbound = policy.get_BlockAllInboundTraffic(activeProfile);

        if (defaultOut == NetFwConstants.NET_FW_ACTION_BLOCK)
        {
            if (blockAllInbound && HasRule(policy, HighLockdownRuleName, enabledOnly: true))
                return FirewallProfileMode.HighFiltering;

            return FirewallProfileMode.MediumFiltering;
        }

        return FirewallProfileMode.LowFiltering;
    }

    public void SetProfileMode(FirewallProfileMode mode)
    {
        var policy = NetFwFactory.CreatePolicy2();
        int[] profiles =
        [
            NetFwConstants.NET_FW_PROFILE2_DOMAIN,
            NetFwConstants.NET_FW_PROFILE2_PRIVATE,
            NetFwConstants.NET_FW_PROFILE2_PUBLIC
        ];

        switch (mode)
        {
            case FirewallProfileMode.HighFiltering:
                foreach (var p in profiles)
                {
                    policy.set_FirewallEnabled(p, true);
                    policy.set_BlockAllInboundTraffic(p, true);
                    policy.set_DefaultInboundAction(p, NetFwConstants.NET_FW_ACTION_BLOCK);
                    policy.set_DefaultOutboundAction(p, NetFwConstants.NET_FW_ACTION_BLOCK);
                }
                EnsureHighLockdownRule(policy, enable: true);
                break;

            case FirewallProfileMode.MediumFiltering:
                EnsureHighLockdownRule(policy, enable: false);
                foreach (var p in profiles)
                {
                    policy.set_FirewallEnabled(p, true);
                    policy.set_BlockAllInboundTraffic(p, false);
                    policy.set_DefaultInboundAction(p, NetFwConstants.NET_FW_ACTION_BLOCK);
                    policy.set_DefaultOutboundAction(p, NetFwConstants.NET_FW_ACTION_BLOCK);
                }
                break;

            case FirewallProfileMode.LowFiltering:
                EnsureHighLockdownRule(policy, enable: false);
                foreach (var p in profiles)
                {
                    policy.set_FirewallEnabled(p, true);
                    policy.set_BlockAllInboundTraffic(p, false);
                    policy.set_DefaultInboundAction(p, NetFwConstants.NET_FW_ACTION_BLOCK);
                    policy.set_DefaultOutboundAction(p, NetFwConstants.NET_FW_ACTION_ALLOW);
                }
                break;

            case FirewallProfileMode.NoFiltering:
                EnsureHighLockdownRule(policy, enable: false);
                foreach (var p in profiles)
                {
                    policy.set_BlockAllInboundTraffic(p, false);
                    policy.set_FirewallEnabled(p, false);
                }
                break;
        }
    }

    public (bool Domain, bool Private, bool Public) GetProfileEnabledStates()
    {
        var policy = NetFwFactory.CreatePolicy2();
        return (
            policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_DOMAIN),
            policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_PRIVATE),
            policy.get_FirewallEnabled(NetFwConstants.NET_FW_PROFILE2_PUBLIC)
        );
    }

    public List<FirewallRuleDto> GetRules(IReadOnlyDictionary<string, TemporaryRuleDto>? tempRules = null)
    {
        var policy = NetFwFactory.CreatePolicy2();
        var list = new List<FirewallRuleDto>();

        foreach (INetFwRule rule in policy.Rules)
        {
            var appName = rule.ApplicationName ?? string.Empty;
            var expanded = string.IsNullOrWhiteSpace(appName)
                ? string.Empty
                : Environment.ExpandEnvironmentVariables(appName);

            bool isInvalid = false;
            if (!string.IsNullOrWhiteSpace(expanded) &&
                !expanded.Equals("System", StringComparison.OrdinalIgnoreCase) &&
                !expanded.StartsWith(@"\\", StringComparison.Ordinal))
            {
                isInvalid = !File.Exists(expanded);
            }

            var dto = new FirewallRuleDto
            {
                Name = rule.Name ?? string.Empty,
                Description = rule.Description ?? string.Empty,
                ApplicationName = appName,
                ExpandedApplicationPath = expanded,
                ServiceName = rule.ServiceName ?? string.Empty,
                Protocol = rule.Protocol,
                LocalPorts = string.IsNullOrWhiteSpace(rule.LocalPorts) ? "*" : rule.LocalPorts,
                RemotePorts = string.IsNullOrWhiteSpace(rule.RemotePorts) ? "*" : rule.RemotePorts,
                LocalAddresses = string.IsNullOrWhiteSpace(rule.LocalAddresses) ? "*" : rule.LocalAddresses,
                RemoteAddresses = string.IsNullOrWhiteSpace(rule.RemoteAddresses) ? "*" : rule.RemoteAddresses,
                Direction = rule.Direction == NetFwConstants.NET_FW_RULE_DIR_IN
                    ? RuleDirection.Inbound
                    : RuleDirection.Outbound,
                Action = rule.Action == NetFwConstants.NET_FW_ACTION_ALLOW
                    ? RuleAction.Allow
                    : RuleAction.Block,
                Enabled = rule.Enabled,
                Profiles = MapProfileFlags(rule.Profiles),
                Grouping = rule.Grouping ?? string.Empty,
                EdgeTraversal = rule.EdgeTraversal,
                IsInvalidPath = isInvalid
            };

            if (tempRules != null && tempRules.TryGetValue(dto.Name, out var temp))
            {
                dto.IsTemporary = true;
                dto.ExpiresAtUtc = temp.ExpiresAtUtc;
            }

            list.Add(dto);
        }

        return list;
    }

    public void CreateRule(FirewallRuleDto dto)
    {
        var policy = NetFwFactory.CreatePolicy2();
        var rule = NetFwFactory.CreateRule();
        ApplyDtoToRule(dto, rule);
        policy.Rules.Add(rule);
    }

    public void UpdateRule(string originalName, FirewallRuleDto updated)
    {
        var policy = NetFwFactory.CreatePolicy2();
        // Remove and re-add cleanly if renamed, or update in-place
        if (!string.Equals(originalName, updated.Name, StringComparison.OrdinalIgnoreCase))
        {
            TryRemoveRule(policy, originalName);
            var newRule = NetFwFactory.CreateRule();
            ApplyDtoToRule(updated, newRule);
            policy.Rules.Add(newRule);
            return;
        }

        try
        {
            var existing = policy.Rules.Item(originalName);
            ApplyDtoToRule(updated, existing);
        }
        catch
        {
            var newRule = NetFwFactory.CreateRule();
            ApplyDtoToRule(updated, newRule);
            policy.Rules.Add(newRule);
        }
    }

    public void SetRuleEnabled(string ruleName, bool enabled)
    {
        var policy = NetFwFactory.CreatePolicy2();
        var rule = policy.Rules.Item(ruleName);
        rule.Enabled = enabled;
    }

    public void DeleteRule(string ruleName)
    {
        var policy = NetFwFactory.CreatePolicy2();
        policy.Rules.Remove(ruleName);
    }

    public int CleanupInvalidRules()
    {
        var rules = GetRules();
        var invalid = rules.Where(r => r.IsInvalidPath).ToList();
        var policy = NetFwFactory.CreatePolicy2();
        int removed = 0;
        foreach (var r in invalid)
        {
            if (TryRemoveRule(policy, r.Name))
                removed++;
        }
        return removed;
    }

    public static List<DuplicateGroupDto> FindDuplicateRules(IEnumerable<FirewallRuleDto> rules)
    {
        return rules
            .GroupBy(r => r.GetDuplicateKey(), StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => new DuplicateGroupDto
            {
                Key = g.Key,
                Rules = g.ToList()
            })
            .ToList();
    }

    public string ExportRulesJson(IEnumerable<FirewallRuleDto>? subset = null)
    {
        var rules = subset?.ToList() ?? GetRules();
        return JsonSerializer.Serialize(rules, new JsonSerializerOptions { WriteIndented = true });
    }

    public int ImportRulesJson(string json, bool skipExistingNames = true)
    {
        var imported = JsonSerializer.Deserialize<List<FirewallRuleDto>>(json) ?? new();
        var policy = NetFwFactory.CreatePolicy2();
        var existingNames = new HashSet<string>(
            GetRules().Select(r => r.Name),
            StringComparer.OrdinalIgnoreCase);

        int count = 0;
        foreach (var dto in imported)
        {
            if (string.IsNullOrWhiteSpace(dto.Name))
                continue;
            if (skipExistingNames && existingNames.Contains(dto.Name))
                continue;

            var rule = NetFwFactory.CreateRule();
            ApplyDtoToRule(dto, rule);
            policy.Rules.Add(rule);
            existingNames.Add(dto.Name);
            count++;
        }

        return count;
    }

    public FirewallRuleDto CreateQuickAppRule(string appPath, RuleAction action, RuleDirection direction = RuleDirection.Outbound, bool isTemporary = false)
    {
        var expanded = Environment.ExpandEnvironmentVariables(appPath);
        var fileName = Path.GetFileName(expanded);
        var actionLabel = action == RuleAction.Allow ? "Allow" : "Block";
        var dirLabel = direction == RuleDirection.Outbound ? "Out" : "In";
        var prefix = isTemporary ? "[FireBrick Temp]" : "FireBrick:";
        var ruleName = $"{prefix} {actionLabel} {dirLabel} - {fileName}";

        if (isTemporary)
        {
            ruleName += $" ({DateTime.Now:HHmmss})";
        }

        var dto = new FirewallRuleDto
        {
            Name = ruleName,
            Description = $"Created by FireBrick on {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            ApplicationName = expanded,
            ExpandedApplicationPath = expanded,
            Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_ANY,
            Direction = direction,
            Action = action,
            Enabled = true,
            Profiles = FirewallProfileFlags.All,
            Grouping = isTemporary ? "FireBrick Temporary Rules" : "FireBrick Rules",
            IsTemporary = isTemporary
        };

        CreateRule(dto);
        return dto;
    }

    private static void ApplyDtoToRule(FirewallRuleDto dto, INetFwRule rule)
    {
        rule.Name = dto.Name;
        rule.Description = dto.Description ?? string.Empty;
        rule.ApplicationName = string.IsNullOrWhiteSpace(dto.ApplicationName) ? null! : dto.ApplicationName;
        rule.ServiceName = string.IsNullOrWhiteSpace(dto.ServiceName) ? null! : dto.ServiceName;
        rule.Protocol = dto.Protocol;

        // Ports are only valid on TCP (6) or UDP (17)
        if (dto.Protocol is NetFwConstants.NET_FW_IP_PROTOCOL_TCP or NetFwConstants.NET_FW_IP_PROTOCOL_UDP)
        {
            rule.LocalPorts = string.IsNullOrWhiteSpace(dto.LocalPorts) ? "*" : dto.LocalPorts;
            rule.RemotePorts = string.IsNullOrWhiteSpace(dto.RemotePorts) ? "*" : dto.RemotePorts;
        }

        if (!string.IsNullOrWhiteSpace(dto.LocalAddresses))
            rule.LocalAddresses = dto.LocalAddresses;
        if (!string.IsNullOrWhiteSpace(dto.RemoteAddresses))
            rule.RemoteAddresses = dto.RemoteAddresses;

        rule.Direction = dto.Direction == RuleDirection.Inbound
            ? NetFwConstants.NET_FW_RULE_DIR_IN
            : NetFwConstants.NET_FW_RULE_DIR_OUT;
        rule.Action = dto.Action == RuleAction.Allow
            ? NetFwConstants.NET_FW_ACTION_ALLOW
            : NetFwConstants.NET_FW_ACTION_BLOCK;
        rule.Profiles = MapProfileFlagsToCom(dto.Profiles);
        if (!string.IsNullOrWhiteSpace(dto.Grouping))
            rule.Grouping = dto.Grouping;
        rule.EdgeTraversal = dto.EdgeTraversal;
        rule.Enabled = dto.Enabled;
    }

    private static void EnsureHighLockdownRule(INetFwPolicy2 policy, bool enable)
    {
        if (!enable)
        {
            TryRemoveRule(policy, HighLockdownRuleName);
            return;
        }

        if (HasRule(policy, HighLockdownRuleName, enabledOnly: false))
        {
            try
            {
                var existing = policy.Rules.Item(HighLockdownRuleName);
                existing.Enabled = true;
                return;
            }
            catch { }
        }

        var blockAll = NetFwFactory.CreateRule();
        blockAll.Name = HighLockdownRuleName;
        blockAll.Description = "Enforces High Filtering lockdown mode by blocking all outbound connections.";
        blockAll.Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_ANY;
        blockAll.Direction = NetFwConstants.NET_FW_RULE_DIR_OUT;
        blockAll.Action = NetFwConstants.NET_FW_ACTION_BLOCK;
        blockAll.Profiles = NetFwConstants.NET_FW_PROFILE2_ALL;
        blockAll.Grouping = "FireBrick System";
        blockAll.Enabled = true;
        policy.Rules.Add(blockAll);
    }

    private static bool HasRule(INetFwPolicy2 policy, string name, bool enabledOnly)
    {
        try
        {
            var r = policy.Rules.Item(name);
            return !enabledOnly || r.Enabled;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryRemoveRule(INetFwPolicy2 policy, string name)
    {
        try
        {
            policy.Rules.Remove(name);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int GetPrimaryActiveProfile(INetFwPolicy2 policy)
    {
        int current = policy.CurrentProfileTypes;
        if ((current & NetFwConstants.NET_FW_PROFILE2_PRIVATE) != 0)
            return NetFwConstants.NET_FW_PROFILE2_PRIVATE;
        if ((current & NetFwConstants.NET_FW_PROFILE2_DOMAIN) != 0)
            return NetFwConstants.NET_FW_PROFILE2_DOMAIN;
        return NetFwConstants.NET_FW_PROFILE2_PUBLIC;
    }

    private static FirewallProfileFlags MapProfileFlags(int comFlags)
    {
        if (comFlags == NetFwConstants.NET_FW_PROFILE2_ALL)
            return FirewallProfileFlags.All;

        var flags = FirewallProfileFlags.None;
        if ((comFlags & NetFwConstants.NET_FW_PROFILE2_DOMAIN) != 0) flags |= FirewallProfileFlags.Domain;
        if ((comFlags & NetFwConstants.NET_FW_PROFILE2_PRIVATE) != 0) flags |= FirewallProfileFlags.Private;
        if ((comFlags & NetFwConstants.NET_FW_PROFILE2_PUBLIC) != 0) flags |= FirewallProfileFlags.Public;
        return flags;
    }

    private static int MapProfileFlagsToCom(FirewallProfileFlags flags)
    {
        if (flags == FirewallProfileFlags.All || flags == FirewallProfileFlags.None)
            return NetFwConstants.NET_FW_PROFILE2_ALL;

        int com = 0;
        if (flags.HasFlag(FirewallProfileFlags.Domain)) com |= NetFwConstants.NET_FW_PROFILE2_DOMAIN;
        if (flags.HasFlag(FirewallProfileFlags.Private)) com |= NetFwConstants.NET_FW_PROFILE2_PRIVATE;
        if (flags.HasFlag(FirewallProfileFlags.Public)) com |= NetFwConstants.NET_FW_PROFILE2_PUBLIC;
        return com;
    }
}
