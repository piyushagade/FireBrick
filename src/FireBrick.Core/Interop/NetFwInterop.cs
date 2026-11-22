using System.Collections;
using System.Runtime.InteropServices;

namespace FireBrick.Core.Interop;

/// <summary>
/// Strongly-typed COM interop definitions for Windows Firewall with Advanced Security (HNetCfg.FwPolicy2).
/// Avoids needing external PIA assemblies while remaining clean and fast.
/// </summary>
public static class NetFwConstants
{
    public const int NET_FW_PROFILE2_DOMAIN = 0x0001;
    public const int NET_FW_PROFILE2_PRIVATE = 0x0002;
    public const int NET_FW_PROFILE2_PUBLIC = 0x0004;
    public const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;

    public const int NET_FW_ACTION_BLOCK = 0;
    public const int NET_FW_ACTION_ALLOW = 1;

    public const int NET_FW_RULE_DIR_IN = 1;
    public const int NET_FW_RULE_DIR_OUT = 2;

    public const int NET_FW_IP_PROTOCOL_TCP = 6;
    public const int NET_FW_IP_PROTOCOL_UDP = 17;
    public const int NET_FW_IP_PROTOCOL_ANY = 256;
}

[ComImport]
[Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwPolicy2
{
    int CurrentProfileTypes { get; }

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_FirewallEnabled(int profileType);
    void set_FirewallEnabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool enabled);

    object get_ExcludedInterfaces(int profileType);
    void set_ExcludedInterfaces(int profileType, object interfaces);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_BlockAllInboundTraffic(int profileType);
    void set_BlockAllInboundTraffic(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool block);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_NotificationsDisabled(int profileType);
    void set_NotificationsDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_UnicastResponsesToMulticastBroadcastDisabled(int profileType);
    void set_UnicastResponsesToMulticastBroadcastDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);

    INetFwRules Rules { get; }

    object ServiceRestriction { get; }

    void EnableRuleGroup(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group, [MarshalAs(UnmanagedType.VariantBool)] bool enable);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool IsRuleGroupEnabled(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group);

    void RestoreLocalFirewallDefaults();

    int get_DefaultInboundAction(int profileType);
    void set_DefaultInboundAction(int profileType, int action);

    int get_DefaultOutboundAction(int profileType);
    void set_DefaultOutboundAction(int profileType, int action);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_IsRuleGroupCurrentlyEnabled([MarshalAs(UnmanagedType.BStr)] string group);

    int LocalPolicyModifyState { get; }
}

[ComImport]
[Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRules : IEnumerable
{
    int Count { get; }
    void Add(INetFwRule rule);
    void Remove([MarshalAs(UnmanagedType.BStr)] string name);
    INetFwRule Item([MarshalAs(UnmanagedType.BStr)] string name);
    new IEnumerator GetEnumerator();
}

[ComImport]
[Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRule
{
    [DispId(1)] string Name { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(2)] string Description { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(3)] string ApplicationName { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(4)] string ServiceName { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(5)] int Protocol { get; set; }
    [DispId(6)] string LocalPorts { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(7)] string RemotePorts { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(8)] string LocalAddresses { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(9)] string RemoteAddresses { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(10)] string IcmpTypesAndCodes { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(11)] int Direction { get; set; }
    [DispId(12)] object Interfaces { get; set; }
    [DispId(13)] string InterfaceTypes { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(14)] bool Enabled { [return: MarshalAs(UnmanagedType.VariantBool)] get; [param: MarshalAs(UnmanagedType.VariantBool)] set; }
    [DispId(15)] string Grouping { [return: MarshalAs(UnmanagedType.BStr)] get; [param: MarshalAs(UnmanagedType.BStr)] set; }
    [DispId(16)] int Profiles { get; set; }
    [DispId(17)] bool EdgeTraversal { [return: MarshalAs(UnmanagedType.VariantBool)] get; [param: MarshalAs(UnmanagedType.VariantBool)] set; }
    [DispId(18)] int Action { get; set; }
}

internal static class NetFwFactory
{
    private static readonly Guid ClsidFwPolicy2 = new("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");
    private static readonly Guid ClsidFwRule = new("2C5BC43E-3369-4C33-AB0C-BE9469677AF4");

    public static INetFwPolicy2 CreatePolicy2()
    {
        var type = Type.GetTypeFromCLSID(ClsidFwPolicy2, throwOnError: true)!;
        return (INetFwPolicy2)Activator.CreateInstance(type)!;
    }

    public static INetFwRule CreateRule()
    {
        var type = Type.GetTypeFromCLSID(ClsidFwRule, throwOnError: true)!;
        return (INetFwRule)Activator.CreateInstance(type)!;
    }
}
