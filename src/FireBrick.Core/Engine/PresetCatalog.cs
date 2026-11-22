using FireBrick.Core.Interop;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Built-in modern rule presets (beyond classic WFC) for rapid hardening and onboarding.
/// </summary>
public static class PresetCatalog
{
    public static List<RulePresetDto> GetPresets() =>
    [
        new RulePresetDto
        {
            Id = "core-networking",
            Name = "Core Networking Essentials",
            Category = "Recommended for Medium Filtering",
            Description = "Allows essential DNS (UDP/TCP 53), DHCP (UDP 67-68), and NTP time sync (UDP 123) so Windows connectivity works smoothly in Medium Filtering.",
            Rules =
            [
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Allow Outbound DNS (UDP 53)",
                    Description = "Allows DNS resolution in Medium Filtering mode.",
                    ApplicationName = @"%SystemRoot%\System32\svchost.exe",
                    ServiceName = "Dnscache",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
                    RemotePorts = "53",
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Allow,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Presets"
                },
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Allow Outbound DHCP (UDP 67-68)",
                    Description = "Allows DHCP lease acquisition.",
                    ApplicationName = @"%SystemRoot%\System32\svchost.exe",
                    ServiceName = "Dhcp",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
                    RemotePorts = "67-68",
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Allow,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Presets"
                },
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Allow Outbound NTP (UDP 123)",
                    Description = "Allows Windows Time synchronization.",
                    ApplicationName = @"%SystemRoot%\System32\svchost.exe",
                    ServiceName = "W32Time",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
                    RemotePorts = "123",
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Allow,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Presets"
                }
            ]
        },
        new RulePresetDto
        {
            Id = "windows-telemetry-block",
            Name = "Privacy: Block Windows Telemetry",
            Category = "Privacy & Hardening",
            Description = "Blocks outbound connections from CompatTelRunner and DiagTrack telemetry executables.",
            Rules =
            [
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Block CompatTelRunner",
                    Description = "Blocks Microsoft Compatibility Telemetry outbound traffic.",
                    ApplicationName = @"%SystemRoot%\System32\CompatTelRunner.exe",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_ANY,
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Block,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Privacy"
                },
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Block DeviceCensus",
                    Description = "Blocks Windows Device Census telemetry.",
                    ApplicationName = @"%SystemRoot%\System32\DeviceCensus.exe",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_ANY,
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Block,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Privacy"
                }
            ]
        },
        new RulePresetDto
        {
            Id = "dev-essentials",
            Name = "Developer Essentials",
            Category = "Productivity",
            Description = "Allows outbound HTTPS (443) and SSH (22) for Git and .NET CLI when running in Medium Filtering.",
            Rules =
            [
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Allow Outbound HTTPS (TCP 443)",
                    Description = "Permits standard encrypted web & API traffic.",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                    RemotePorts = "443",
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Allow,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Developer"
                },
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Allow Outbound SSH (TCP 22)",
                    Description = "Permits SSH and Git-over-SSH connections.",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                    RemotePorts = "22",
                    Direction = RuleDirection.Outbound,
                    Action = RuleAction.Allow,
                    Profiles = FirewallProfileFlags.All,
                    Grouping = "FireBrick Developer"
                }
            ]
        },
        new RulePresetDto
        {
            Id = "lan-isolation",
            Name = "Block Inbound SMB & Remote Admin",
            Category = "Security Hardening",
            Description = "Explicitly blocks inbound SMB (445), NetBIOS (137-139), and RDP (3389) on Public networks.",
            Rules =
            [
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Block Inbound SMB (TCP 445 Public)",
                    Description = "Prevents SMB lateral movement on untrusted public networks.",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                    LocalPorts = "445",
                    Direction = RuleDirection.Inbound,
                    Action = RuleAction.Block,
                    Profiles = FirewallProfileFlags.Public,
                    Grouping = "FireBrick Hardening"
                },
                new FirewallRuleDto
                {
                    Name = "FireBrick Preset: Block Inbound RDP (TCP 3389 Public)",
                    Description = "Blocks Remote Desktop on public networks.",
                    Protocol = NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                    LocalPorts = "3389",
                    Direction = RuleDirection.Inbound,
                    Action = RuleAction.Block,
                    Profiles = FirewallProfileFlags.Public,
                    Grouping = "FireBrick Hardening"
                }
            ]
        }
    ];
}
