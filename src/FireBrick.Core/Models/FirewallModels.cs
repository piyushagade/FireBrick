using System.Text.Json.Serialization;

namespace FireBrick.Core.Models;

/// <summary>
/// Classic WFC 4-level filtering profiles mapped to Windows Defender Firewall policies.
/// </summary>
public enum FirewallProfileMode
{
    /// <summary>Blocks all outbound and inbound connections regardless of rules (lockdown).</summary>
    HighFiltering = 0,

    /// <summary>Blocks outbound connections that do not match an explicit Allow rule (WFC recommended mode).</summary>
    MediumFiltering = 1,

    /// <summary>Allows outbound connections unless an explicit Block rule matches (Windows default).</summary>
    LowFiltering = 2,

    /// <summary>Disables Windows Defender Firewall across active profiles.</summary>
    NoFiltering = 3
}

/// <summary>
/// Notification and learning behavior when blocked outbound connections occur.
/// </summary>
public enum NotificationMode
{
    /// <summary>No notifications are shown; blocked connections are logged silently.</summary>
    Disabled = 0,

    /// <summary>Show interactive Allow/Block notifications for all blocked outbound programs.</summary>
    DisplayNotifications = 1,

    /// <summary>Only show notifications for unsigned or untrusted executables.</summary>
    LowNotification = 2,

    /// <summary>Automatically create Allow rules for digitally signed outbound programs.</summary>
    LearningMode = 3
}

public enum RuleDirection
{
    Inbound = 1,
    Outbound = 2
}

public enum RuleAction
{
    Block = 0,
    Allow = 1
}

[Flags]
public enum FirewallProfileFlags
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public
}

public enum SignatureTrustStatus
{
    Unknown = 0,
    Trusted = 1,
    Unsigned = 2,
    Untrusted = 3,
    FileMissing = 4
}

public sealed class SignatureInfoDto
{
    public SignatureTrustStatus Status { get; set; } = SignatureTrustStatus.Unknown;
    public string Publisher { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
}

public sealed class FirewallRuleDto
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public string ExpandedApplicationPath { get; set; } = string.Empty;
    public string ServiceName { get; set; } = string.Empty;
    public int Protocol { get; set; } = 256; // NET_FW_IP_PROTOCOL_ANY = 256, TCP = 6, UDP = 17, ICMPv4 = 1, ICMPv6 = 58
    public string LocalPorts { get; set; } = "*";
    public string RemotePorts { get; set; } = "*";
    public string LocalAddresses { get; set; } = "*";
    public string RemoteAddresses { get; set; } = "*";
    public RuleDirection Direction { get; set; } = RuleDirection.Outbound;
    public RuleAction Action { get; set; } = RuleAction.Allow;
    public bool Enabled { get; set; } = true;
    public FirewallProfileFlags Profiles { get; set; } = FirewallProfileFlags.All;
    public string Grouping { get; set; } = string.Empty;
    public bool EdgeTraversal { get; set; }
    public bool IsInvalidPath { get; set; }
    public bool IsTemporary { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
    public SignatureTrustStatus SignatureStatus { get; set; } = SignatureTrustStatus.Unknown;

    [JsonIgnore]
    public string ProtocolDisplay => Protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMPv4",
        58 => "ICMPv6",
        256 => "Any",
        _ => Protocol.ToString()
    };

    [JsonIgnore]
    public string DirectionDisplay => Direction == RuleDirection.Outbound ? "Outbound" : "Inbound";

    [JsonIgnore]
    public string ActionDisplay => Action == RuleAction.Allow ? "Allow" : "Block";

    [JsonIgnore]
    public string ProfilesDisplay
    {
        get
        {
            if (Profiles == FirewallProfileFlags.All) return "All";
            var parts = new List<string>(3);
            if (Profiles.HasFlag(FirewallProfileFlags.Domain)) parts.Add("Domain");
            if (Profiles.HasFlag(FirewallProfileFlags.Private)) parts.Add("Private");
            if (Profiles.HasFlag(FirewallProfileFlags.Public)) parts.Add("Public");
            return parts.Count == 0 ? "None" : string.Join(", ", parts);
        }
    }

    [JsonIgnore]
    public string DisplayName => FormatIndirectString(Name);

    [JsonIgnore]
    public string DisplayGrouping => FormatIndirectString(Grouping);

    [JsonIgnore]
    public string ApplicationDisplay => string.IsNullOrWhiteSpace(ApplicationName)
        ? (string.IsNullOrWhiteSpace(ServiceName) ? "System / Any" : $"Service: {ServiceName}")
        : Path.GetFileName(ExpandedApplicationPath.Length > 0 ? ExpandedApplicationPath : ApplicationName);

    private static string FormatIndirectString(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        if (!raw.StartsWith("@{", StringComparison.Ordinal)) return raw;

        // Clean up UWP/MSIX indirect strings like "@{Microsoft.WindowsStore_1234...?ms-resource://...}"
        int end = raw.IndexOf('_');
        if (end < 0) end = raw.IndexOf('?');
        if (end > 2)
        {
            var pkg = raw[2..end];
            // Strip common publisher prefixes for readability
            if (pkg.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
                pkg = pkg["Microsoft.".Length..];
            return pkg;
        }
        return raw;
    }

    public string GetDuplicateKey() =>
        $"{(ExpandedApplicationPath.Length > 0 ? ExpandedApplicationPath : ApplicationName).Trim().ToLowerInvariant()}|" +
        $"{ServiceName.Trim().ToLowerInvariant()}|{(int)Direction}|{(int)Action}|{Protocol}|" +
        $"{LocalPorts.Trim()}|{RemotePorts.Trim()}|{LocalAddresses.Trim()}|{RemoteAddresses.Trim()}|{(int)Profiles}";
}

public sealed class DuplicateGroupDto
{
    public string Key { get; set; } = string.Empty;
    public List<FirewallRuleDto> Rules { get; set; } = new();
}

public sealed class ConnectionEventDto
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public int EventId { get; set; }
    public RuleDirection Direction { get; set; } = RuleDirection.Outbound;
    public RuleAction Action { get; set; } = RuleAction.Block;
    public int ProcessId { get; set; }
    public string ApplicationPath { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string RemoteHostName { get; set; } = string.Empty;
    public string GeoLocation { get; set; } = string.Empty;
    public string FilterOrigin { get; set; } = string.Empty;
    public SignatureTrustStatus SignatureStatus { get; set; } = SignatureTrustStatus.Unknown;
    public string Publisher { get; set; } = string.Empty;

    [JsonIgnore]
    public string LocalEndpoint => LocalPort > 0 ? $"{LocalAddress}:{LocalPort}" : LocalAddress;

    [JsonIgnore]
    public string RemoteEndpoint => RemotePort > 0 ? $"{RemoteAddress}:{RemotePort}" : RemoteAddress;

    [JsonIgnore]
    public string LocalTimeDisplay => TimestampUtc.ToLocalTime().ToString("HH:mm:ss");
}

public sealed class ActiveConnectionDto
{
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string RemoteHostName { get; set; } = string.Empty;
    public string GeoLocation { get; set; } = string.Empty;

    [JsonIgnore]
    public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";

    [JsonIgnore]
    public string RemoteEndpoint => RemotePort > 0 ? $"{RemoteAddress}:{RemotePort}" : RemoteAddress;
}

public sealed class TemporaryRuleDto
{
    public string RuleName { get; set; } = string.Empty;
    public string ApplicationPath { get; set; } = string.Empty;
    public RuleDirection Direction { get; set; } = RuleDirection.Outbound;
    public RuleAction Action { get; set; } = RuleAction.Allow;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAtUtc { get; set; }

    [JsonIgnore]
    public TimeSpan Remaining => ExpiresAtUtc > DateTimeOffset.UtcNow
        ? ExpiresAtUtc - DateTimeOffset.UtcNow
        : TimeSpan.Zero;

    [JsonIgnore]
    public string RemainingDisplay
    {
        get
        {
            var r = Remaining;
            if (r <= TimeSpan.Zero) return "Expired";
            if (r.TotalHours >= 1) return $"{(int)r.TotalHours}h {r.Minutes}m";
            return $"{r.Minutes}m {r.Seconds}s";
        }
    }
}

public sealed class FirewallStatusDto
{
    public FirewallProfileMode ProfileMode { get; set; } = FirewallProfileMode.LowFiltering;
    public NotificationMode NotificationMode { get; set; } = NotificationMode.DisplayNotifications;
    public bool DomainFirewallEnabled { get; set; }
    public bool PrivateFirewallEnabled { get; set; }
    public bool PublicFirewallEnabled { get; set; }
    public int TotalRulesCount { get; set; }
    public int EnabledRulesCount { get; set; }
    public int InvalidRulesCount { get; set; }
    public int TemporaryRulesCount { get; set; }
    public int BlockedEventsCount { get; set; }
    public bool IsServiceConnected { get; set; }
    public bool IsElevated { get; set; }
    public bool IsAuditPolicyEnabled { get; set; }
    public bool IsRuleLockEnabled { get; set; }
}

public sealed class AppSettingsDto
{
    public NotificationMode NotificationMode { get; set; } = NotificationMode.DisplayNotifications;
    public int DefaultTempRuleMinutes { get; set; } = 15;
    public bool EnableReverseDns { get; set; } = true;
    public bool EnableGeoIpLookup { get; set; } = true;
    public bool KillConnectionsOnBlock { get; set; } = true;
    public bool EnableShellContextMenu { get; set; }
    public bool EnableRuleLock { get; set; }
    public bool AutoSwitchNetworkProfiles { get; set; }
    public bool StartWithWindows { get; set; }
    public bool ShowAllowedConnections { get; set; } = true;
    public bool CloseToTray { get; set; } = true;
    public bool StartMinimizedToTray { get; set; }
    public bool IsSidebarOpen { get; set; } = false;
    public string Theme { get; set; } = "System"; // System, Dark, Light
    public int MaxLogEntries { get; set; } = 1000;
    public List<NetworkProfileRuleDto> NetworkProfileRules { get; set; } = new();
    public List<BlocklistSubscriptionDto> Blocklists { get; set; } = new();
}

public sealed class GeoIpInfoDto
{
    public string IpAddress { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string CountryName { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Org { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;

    [JsonIgnore]
    public string DisplaySummary
    {
        get
        {
            if (string.IsNullOrWhiteSpace(CountryCode) && string.IsNullOrWhiteSpace(Org))
                return string.Empty;
            var parts = new List<string>(2);
            if (!string.IsNullOrWhiteSpace(CountryCode)) parts.Add(CountryCode);
            if (!string.IsNullOrWhiteSpace(Org)) parts.Add(Org);
            return string.Join(" • ", parts);
        }
    }
}

public sealed class AppGroupSummaryDto
{
    public string ApplicationPath { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public int RuleCount { get; set; }
    public int AllowRuleCount { get; set; }
    public int BlockRuleCount { get; set; }
    public int EnabledRuleCount { get; set; }
    public int ActiveConnectionCount { get; set; }
    public int BlockedEventsCount { get; set; }
    public SignatureTrustStatus SignatureStatus { get; set; } = SignatureTrustStatus.Unknown;
    public string Publisher { get; set; } = string.Empty;

    [JsonIgnore]
    public string RulesSummary => $"{AllowRuleCount} Allow  •  {BlockRuleCount} Block  ({EnabledRuleCount} active)";

    [JsonIgnore]
    public string ActivitySummary => $"{ActiveConnectionCount} live socket(s)  •  {BlockedEventsCount} blocked";
}

public sealed class NetworkProfileRuleDto
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string NetworkName { get; set; } = string.Empty;
    public FirewallProfileMode TargetProfileMode { get; set; } = FirewallProfileMode.MediumFiltering;
    public bool Enabled { get; set; } = true;

    [JsonIgnore]
    public string ProfileDisplay => TargetProfileMode switch
    {
        FirewallProfileMode.HighFiltering => "High Filtering",
        FirewallProfileMode.MediumFiltering => "Medium Filtering",
        FirewallProfileMode.LowFiltering => "Low Filtering",
        FirewallProfileMode.NoFiltering => "No Filtering",
        _ => TargetProfileMode.ToString()
    };
}

public sealed class BlocklistSubscriptionDto
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SourceUrl { get; set; } = string.Empty;
    public List<string> Domains { get; set; } = new();
    public bool Enabled { get; set; } = true;
    public int RuleEntryCount { get; set; }
    public DateTimeOffset? LastSyncedUtc { get; set; }

    [JsonIgnore]
    public string StatusDisplay => LastSyncedUtc.HasValue
        ? $"{RuleEntryCount} blocked targets  •  Synced {LastSyncedUtc.Value.ToLocalTime():MMM d, HH:mm}"
        : "Not synced yet";
}

public sealed class RuleLockAlertDto
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string RuleName { get; set; } = string.Empty;
    public string ChangeType { get; set; } = "Injected";
    public bool Reverted { get; set; }

    [JsonIgnore]
    public string TimeDisplay => TimestampUtc.ToLocalTime().ToString("HH:mm:ss");
}

public sealed class TopAppStatDto
{
    public string ApplicationName { get; set; } = string.Empty;
    public string ApplicationPath { get; set; } = string.Empty;
    public int BlockedCount { get; set; }
    public double BarWidth { get; set; }
    public bool IsAllowed { get; set; }

    [JsonIgnore]
    public string ButtonLabel => IsAllowed ? "Allowed ✓" : "Allow";

    [JsonIgnore]
    public bool CanAllow => !IsAllowed;
}

public sealed class ActivityBucketDto
{
    public string Label { get; set; } = string.Empty;
    public int BlockedCount { get; set; }
    public int AllowedCount { get; set; }
    public double BlockedBarHeight { get; set; }
    public double AllowedBarHeight { get; set; }
}

public sealed class RulePresetDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<FirewallRuleDto> Rules { get; set; } = new();
}
