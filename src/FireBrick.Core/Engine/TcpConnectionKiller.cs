using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FireBrick.Core.Engine;

/// <summary>
/// Immediately terminates active IPv4 TCP connections belonging to a process path or PID
/// using iphlpapi.dll SetTcpEntry (MIB_TCP_STATE_DELETE_TCB).
/// </summary>
public sealed class TcpConnectionKiller
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint MIB_TCP_STATE_ESTAB = 5;
    private const uint MIB_TCP_STATE_DELETE_TCB = 12;

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
    private struct MIB_TCPROW
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    public int KillConnectionsForExecutable(string applicationPath)
    {
        if (string.IsNullOrWhiteSpace(applicationPath))
            return 0;

        var targetFull = Environment.ExpandEnvironmentVariables(applicationPath).Trim();
        var matchingPids = new HashSet<int>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var path = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(path) &&
                    string.Equals(path, targetFull, StringComparison.OrdinalIgnoreCase))
                {
                    matchingPids.Add(proc.Id);
                }
            }
            catch
            {
                // Access denied on protected processes if non-elevated
            }
            finally
            {
                proc.Dispose();
            }
        }

        if (matchingPids.Count == 0)
            return 0;

        return KillConnectionsForPids(matchingPids);
    }

    public int KillConnectionsForPid(int pid)
    {
        if (pid <= 4) return 0;
        return KillConnectionsForPids(new HashSet<int> { pid });
    }

    private static int KillConnectionsForPids(HashSet<int> pids)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return 0;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        int killed = 0;
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return 0;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                if (!pids.Contains(row.owningPid))
                    continue;

                if (row.state != MIB_TCP_STATE_ESTAB)
                    continue;

                var killRow = new MIB_TCPROW
                {
                    state = MIB_TCP_STATE_DELETE_TCB,
                    localAddr = row.localAddr,
                    localPort = row.localPort,
                    remoteAddr = row.remoteAddr,
                    remotePort = row.remotePort
                };

                if (SetTcpEntry(ref killRow) == 0)
                    killed++;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return killed;
    }
}
