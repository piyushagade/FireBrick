using System.Reflection;
using System.Runtime.InteropServices;

namespace FireBrick.Core.Interop;

public enum WinDivertLayer : byte
{
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4
}

public enum WinDivertEvent : byte
{
    NetworkPacket = 0,
    FlowEstablished = 0,
    FlowDeleted = 1,
    SocketBind = 0,
    SocketConnect = 1,
    SocketListen = 2,
    SocketAccept = 3,
    SocketClose = 4,
    ReflectOpen = 0,
    ReflectClose = 1
}

[Flags]
public enum WinDivertFlags : ulong
{
    None = 0,
    Sniff = 0x0001,
    Drop = 0x0002,
    RecvOnly = 0x0004,
    SendOnly = 0x0008,
    NoInstall = 0x0010,
    Fragments = 0x0020
}

/// <summary>
/// Exact 80-byte WINDIVERT_ADDRESS structure for WinDivert 2.2.x (x64).
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public unsafe struct WinDivertAddress
{
    [FieldOffset(0)]
    public long Timestamp;

    [FieldOffset(8)]
    public uint Flags;

    [FieldOffset(12)]
    public uint Reserved2;

    // Network union (offset 16)
    [FieldOffset(16)]
    public uint IfIdx;

    [FieldOffset(20)]
    public uint SubIfIdx;

    // Flow union (offset 16)
    [FieldOffset(16)]
    public ulong EndpointId;

    [FieldOffset(24)]
    public ulong ParentEndpointId;

    [FieldOffset(32)]
    public uint ProcessId;

    [FieldOffset(36)]
    public fixed uint LocalAddr[4];

    [FieldOffset(52)]
    public fixed uint RemoteAddr[4];

    [FieldOffset(68)]
    public ushort LocalPort;

    [FieldOffset(70)]
    public ushort RemotePort;

    [FieldOffset(72)]
    public byte Protocol;

    public WinDivertLayer Layer => (WinDivertLayer)(Flags & 0xFF);
    public WinDivertEvent Event => (WinDivertEvent)((Flags >> 8) & 0xFF);
    public bool Sniffed => (Flags & (1u << 16)) != 0;
    public bool Outbound => (Flags & (1u << 17)) != 0;
    public bool Loopback => (Flags & (1u << 18)) != 0;
    public bool Impostor => (Flags & (1u << 19)) != 0;
    public bool IPv6 => (Flags & (1u << 20)) != 0;
}

public static class WinDivertInterop
{
    public static readonly IntPtr InvalidHandleValue = new(-1);
    private static string? _customDllPath;

    static WinDivertInterop()
    {
        NativeLibrary.SetDllImportResolver(typeof(WinDivertInterop).Assembly, ResolveWinDivert);
    }

    public static void SetDllSearchPath(string? dllPath)
    {
        _customDllPath = dllPath;
    }

    private static IntPtr ResolveWinDivert(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, "WinDivert.dll", StringComparison.OrdinalIgnoreCase))
            return IntPtr.Zero;

        if (!string.IsNullOrWhiteSpace(_customDllPath) && File.Exists(_customDllPath))
        {
            if (NativeLibrary.TryLoad(_customDllPath, out var handle))
                return handle;
        }

        var localPath = Path.Combine(AppContext.BaseDirectory, "WinDivert.dll");
        if (File.Exists(localPath) && NativeLibrary.TryLoad(localPath, out var localHandle))
            return localHandle;

        return IntPtr.Zero;
    }

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        short priority,
        ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        out uint readLen,
        out WinDivertAddress pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        IntPtr pPacket,
        uint packetLen,
        IntPtr pRecvLen,
        out WinDivertAddress pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        out uint writeLen,
        ref WinDivertAddress pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);
}
