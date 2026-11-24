using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Enumerates live TCP and UDP connections with owning process IDs via iphlpapi.dll.
/// Provides real-time visibility into active network activity beyond classic WFC.
/// </summary>
public sealed class LiveConnectionsMonitor
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public int owningPid;
    }

    public List<ActiveConnectionDto> GetActiveConnections()
    {
        var results = new List<ActiveConnectionDto>();
        var processCache = new Dictionary<int, (string Name, string Path)>();

        CollectTcpV4(results, processCache);
        CollectTcpV6(results, processCache);
        CollectUdpV4(results, processCache);

        return results;
    }

    private static void CollectTcpV4(List<ActiveConnectionDto> results, Dictionary<int, (string Name, string Path)> processCache)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var (name, path) = ResolveProcess(row.owningPid, processCache);
                results.Add(new ActiveConnectionDto
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(row.localAddr).ToString(),
                    LocalPort = ConvertPort(row.localPort),
                    RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                    RemotePort = ConvertPort(row.remotePort),
                    State = MapTcpState(row.state),
                    ProcessId = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void CollectTcpV6(List<ActiveConnectionDto> results, Dictionary<int, (string Name, string Path)> processCache)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL) != 0)
                return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var (name, path) = ResolveProcess(row.owningPid, processCache);
                results.Add(new ActiveConnectionDto
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(row.localAddr).ToString(),
                    LocalPort = ConvertPort(row.localPort),
                    RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                    RemotePort = ConvertPort(row.remotePort),
                    State = MapTcpState(row.state),
                    ProcessId = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void CollectUdpV4(List<ActiveConnectionDto> results, Dictionary<int, (string Name, string Path)> processCache)
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID);
        if (bufferSize <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedUdpTable(buffer, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID) != 0)
                return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var (name, path) = ResolveProcess(row.owningPid, processCache);
                results.Add(new ActiveConnectionDto
                {
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(row.localAddr).ToString(),
                    LocalPort = ConvertPort(row.localPort),
                    RemoteAddress = "*",
                    RemotePort = 0,
                    State = "Bound",
                    ProcessId = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ConvertPort(uint networkOrderPort)
    {
        return ((int)(networkOrderPort & 0xFF) << 8) | (int)((networkOrderPort >> 8) & 0xFF);
    }

    private static (string Name, string Path) ResolveProcess(int pid, Dictionary<int, (string Name, string Path)> cache)
    {
        if (cache.TryGetValue(pid, out var existing))
            return existing;

        if (pid == 0) return cache[pid] = ("System Idle", string.Empty);
        if (pid == 4) return cache[pid] = ("System", "System");

        try
        {
            using var proc = Process.GetProcessById(pid);
            string name = proc.ProcessName;
            string path = string.Empty;
            try
            {
                path = proc.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                // Protected or elevated process when running non-elevated
            }

            return cache[pid] = (name, path);
        }
        catch
        {
            return cache[pid] = ($"PID {pid}", string.Empty);
        }
    }

    private static string MapTcpState(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => state.ToString()
    };
}
