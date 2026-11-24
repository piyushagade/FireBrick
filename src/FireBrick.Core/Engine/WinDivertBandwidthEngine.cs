using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Optional WinDivert-backed per-application bandwidth pacer supporting both download and upload limits.
/// </summary>
public sealed class WinDivertBandwidthEngine : IDisposable
{
    private readonly record struct FlowKey(byte Protocol, ushort LocalPort, ushort RemotePort);

    private sealed class AppThrottleState
    {
        public string ApplicationPath { get; init; } = string.Empty;
        public string ApplicationName { get; init; } = string.Empty;
        public TokenBucket DownloadBucket { get; } = new(0);
        public TokenBucket UploadBucket { get; } = new(0);
        public long IntervalDownBytes;
        public long IntervalUpBytes;
        public long TotalDownBytes;
        public long TotalUpBytes;
        public long CurrentDownBps;
        public long CurrentUpBps;
    }

    private readonly object _lifecycleLock = new();
    private readonly ConcurrentDictionary<FlowKey, string> _flowAppMap = new();
    private readonly ConcurrentDictionary<uint, string> _pidPathCache = new();
    private readonly ConcurrentDictionary<string, AppThrottleState> _appStates = new(StringComparer.OrdinalIgnoreCase);

    private IntPtr _flowHandle = WinDivertInterop.InvalidHandleValue;
    private IntPtr _networkHandle = WinDivertInterop.InvalidHandleValue;
    private LiveConnectionsMonitor? _liveConnections;
    private long _lastSeedTicks;
    private CancellationTokenSource? _cts;
    private Thread? _flowThread;
    private Thread? _networkThread;
    private Timer? _statsTimer;
    private long _flowEvents;
    private long _flowMapped;
    private long _netPackets;
    private long _matchedPackets;
    private int _flowLastErr;
    private int _netLastErr;
    private byte _lastFlowEvent;
    private uint _lastFlowPid;
    private int _lastResolveErr;

    public bool IsRunning { get; private set; }
    public string? LastError { get; private set; }

    public string GetDiagnosticSummary() =>
        $"flows={Interlocked.Read(ref _flowEvents)} mapped={Interlocked.Read(ref _flowMapped)} pkts={Interlocked.Read(ref _netPackets)} matched={Interlocked.Read(ref _matchedPackets)} mapSize={_flowAppMap.Count} flowErr={_flowLastErr} netErr={_netLastErr} lastEvt={_lastFlowEvent} lastPid={_lastFlowPid} resErr={_lastResolveErr}";

    public void UpdateRules(IEnumerable<BandwidthRuleDto> rules)
    {
        var active = rules
            .Where(r => r.Enabled && !string.IsNullOrWhiteSpace(r.ApplicationPath) && (r.DownloadLimitKBps > 0 || r.UploadLimitKBps > 0))
            .ToList();

        var activePaths = new HashSet<string>(active.Select(r => NormalizePath(r.ApplicationPath)), StringComparer.OrdinalIgnoreCase);

        foreach (var existing in _appStates.Keys.ToList())
        {
            if (!activePaths.Contains(existing))
                _appStates.TryRemove(existing, out _);
        }

        foreach (var rule in active)
        {
            var norm = NormalizePath(rule.ApplicationPath);
            var state = _appStates.GetOrAdd(norm, _ => new AppThrottleState
            {
                ApplicationPath = rule.ApplicationPath,
                ApplicationName = rule.DisplayAppName
            });

            state.DownloadBucket.SetRate(rule.DownloadLimitKBps > 0 ? (long)rule.DownloadLimitKBps * 1024L : 0);
            state.UploadBucket.SetRate(rule.UploadLimitKBps > 0 ? (long)rule.UploadLimitKBps * 1024L : 0);
        }
    }

    public bool Start(IEnumerable<BandwidthRuleDto> rules, LiveConnectionsMonitor? liveConnections = null)
    {
        lock (_lifecycleLock)
        {
            UpdateRules(rules);

            if (IsRunning)
                return true;

            var addonDir = WinDivertAddonManager.ResolveInstalledDirectory();
            if (addonDir == null)
            {
                LastError = "WinDivert add-on is not installed. Click 'Install WinDivert Add-on' first.";
                return false;
            }

            WinDivertInterop.SetDllSearchPath(Path.Combine(addonDir, "WinDivert.dll"));

            try
            {
                _liveConnections = liveConnections;
                SeedFromLiveConnections(liveConnections);

                _flowHandle = WinDivertInterop.WinDivertOpen(
                    "tcp or udp",
                    WinDivertLayer.Flow,
                    0,
                    (ulong)(WinDivertFlags.Sniff | WinDivertFlags.RecvOnly));

                if (_flowHandle == WinDivertInterop.InvalidHandleValue)
                {
                    int err = Marshal.GetLastWin32Error();
                    LastError = $"Failed to open WinDivert FLOW layer (Win32 error {err}). Ensure FireBrick runs as Administrator or Service.";
                    return false;
                }

                _networkHandle = WinDivertInterop.WinDivertOpen(
                    "tcp or udp",
                    WinDivertLayer.Network,
                    0,
                    (ulong)WinDivertFlags.None);

                if (_networkHandle == WinDivertInterop.InvalidHandleValue)
                {
                    int err = Marshal.GetLastWin32Error();
                    WinDivertInterop.WinDivertClose(_flowHandle);
                    _flowHandle = WinDivertInterop.InvalidHandleValue;
                    LastError = $"Failed to open WinDivert NETWORK layer (Win32 error {err}).";
                    return false;
                }

                _cts = new CancellationTokenSource();
                var token = _cts.Token;

                _flowThread = new Thread(() => RunFlowLoop(token))
                {
                    IsBackground = true,
                    Name = "FireBrick-WinDivert-Flow"
                };
                _networkThread = new Thread(() => RunNetworkLoop(token))
                {
                    IsBackground = true,
                    Priority = ThreadPriority.AboveNormal,
                    Name = "FireBrick-WinDivert-Network"
                };

                _statsTimer = new Timer(_ => RollStats(), null, 1000, 1000);
                _flowThread.Start();
                _networkThread.Start();

                IsRunning = true;
                LastError = null;
                return true;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                StopInternal(unloadDriver: false);
                return false;
            }
        }
    }

    public void Stop(bool unloadDriver = true)
    {
        lock (_lifecycleLock)
        {
            StopInternal(unloadDriver);
        }
    }

    public List<BandwidthAppUsageDto> GetUsageSnapshot()
    {
        return _appStates.Values
            .Select(s => new BandwidthAppUsageDto
            {
                ApplicationPath = s.ApplicationPath,
                ApplicationName = s.ApplicationName,
                CurrentDownloadBps = Interlocked.Read(ref s.CurrentDownBps),
                CurrentUploadBps = Interlocked.Read(ref s.CurrentUpBps),
                TotalDownloadedBytes = Interlocked.Read(ref s.TotalDownBytes),
                TotalUploadedBytes = Interlocked.Read(ref s.TotalUpBytes),
                IsThrottled = s.DownloadBucket.BytesPerSecond > 0 || s.UploadBucket.BytesPerSecond > 0
            })
            .OrderByDescending(x => x.CurrentDownloadBps + x.CurrentUploadBps)
            .ThenBy(x => x.ApplicationName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void StopInternal(bool unloadDriver)
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _statsTimer?.Dispose(); } catch { }
        _statsTimer = null;

        if (_networkHandle != WinDivertInterop.InvalidHandleValue)
        {
            WinDivertInterop.WinDivertClose(_networkHandle);
            _networkHandle = WinDivertInterop.InvalidHandleValue;
        }

        if (_flowHandle != WinDivertInterop.InvalidHandleValue)
        {
            WinDivertInterop.WinDivertClose(_flowHandle);
            _flowHandle = WinDivertInterop.InvalidHandleValue;
        }

        try { _networkThread?.Join(1500); } catch { }
        try { _flowThread?.Join(1500); } catch { }
        _networkThread = null;
        _flowThread = null;

        _cts?.Dispose();
        _cts = null;

        _flowAppMap.Clear();
        _pidPathCache.Clear();

        if (unloadDriver)
        {
            WinDivertAddonManager.UnloadDriver();
        }
    }

    private void RollStats()
    {
        foreach (var state in _appStates.Values)
        {
            long d = Interlocked.Exchange(ref state.IntervalDownBytes, 0);
            long u = Interlocked.Exchange(ref state.IntervalUpBytes, 0);
            Interlocked.Exchange(ref state.CurrentDownBps, d);
            Interlocked.Exchange(ref state.CurrentUpBps, u);
        }
    }

    private void SeedFromLiveConnections(LiveConnectionsMonitor? monitor)
    {
        if (monitor == null) return;
        try
        {
            var conns = monitor.GetActiveConnections();
            foreach (var c in conns)
            {
                if (string.IsNullOrWhiteSpace(c.ProcessPath) || c.ProcessPath == "-")
                    continue;

                byte proto = string.Equals(c.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) ? (byte)17 : (byte)6;
                var key = new FlowKey(proto, (ushort)c.LocalPort, (ushort)c.RemotePort);
                _flowAppMap[key] = NormalizePath(c.ProcessPath);
            }
        }
        catch { }
    }

    private void RunFlowLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _flowHandle != WinDivertInterop.InvalidHandleValue)
        {
            if (!WinDivertInterop.WinDivertRecv(_flowHandle, IntPtr.Zero, 0, IntPtr.Zero, out var addr))
            {
                _flowLastErr = Marshal.GetLastWin32Error();
                break;
            }

            Interlocked.Increment(ref _flowEvents);
            _lastFlowEvent = (byte)addr.Event;
            _lastFlowPid = addr.ProcessId;
            var key = new FlowKey(addr.Protocol, addr.LocalPort, addr.RemotePort);
            if (addr.Event == WinDivertEvent.FlowEstablished)
            {
                var path = ResolveProcessPath(addr.ProcessId);
                if (!string.IsNullOrEmpty(path))
                {
                    _flowAppMap[key] = path;
                    Interlocked.Increment(ref _flowMapped);
                }
            }
            else if (addr.Event == WinDivertEvent.FlowDeleted)
            {
                _flowAppMap.TryRemove(key, out _);
            }
        }
    }

    private void RunNetworkLoop(CancellationToken ct)
    {
        var packet = new byte[65536];
        while (!ct.IsCancellationRequested && _networkHandle != WinDivertInterop.InvalidHandleValue)
        {
            if (!WinDivertInterop.WinDivertRecv(_networkHandle, packet, (uint)packet.Length, out uint readLen, out var addr))
            {
                _netLastErr = Marshal.GetLastWin32Error();
                break;
            }

            if (readLen == 0)
                continue;

            Interlocked.Increment(ref _netPackets);
            bool allow = ShouldAllowPacket(packet, (int)readLen, addr.Outbound);
            if (allow)
            {
                WinDivertInterop.WinDivertSend(_networkHandle, packet, readLen, out _, ref addr);
            }
        }
    }

    private bool ShouldAllowPacket(byte[] packet, int len, bool outbound)
    {
        if (_appStates.IsEmpty || len < 20)
            return true;

        if (!TryExtractFlowKey(packet, len, outbound, out var key, out int payloadLen))
            return true;

        if (!_flowAppMap.TryGetValue(key, out var appPath))
        {
            long now = Environment.TickCount64;
            long prev = Interlocked.Read(ref _lastSeedTicks);
            if (_liveConnections != null && now - prev > 200 && Interlocked.CompareExchange(ref _lastSeedTicks, now, prev) == prev)
            {
                SeedFromLiveConnections(_liveConnections);
                _flowAppMap.TryGetValue(key, out appPath);
            }
        }

        if (string.IsNullOrEmpty(appPath))
            return true;

        if (!_appStates.TryGetValue(appPath, out var state))
            return true;

        Interlocked.Increment(ref _matchedPackets);

        if (outbound)
        {
            if (state.UploadBucket.BytesPerSecond > 0)
            {
                // Never drop tiny pure TCP ACKs when upload-throttling unless payload > 0, so downloads aren't choked.
                if (payloadLen > 0 && !state.UploadBucket.TryConsume(len))
                    return false;
            }

            Interlocked.Add(ref state.IntervalUpBytes, len);
            Interlocked.Add(ref state.TotalUpBytes, len);
        }
        else
        {
            if (state.DownloadBucket.BytesPerSecond > 0)
            {
                if (payloadLen > 0 && !state.DownloadBucket.TryConsume(len))
                    return false;
            }

            Interlocked.Add(ref state.IntervalDownBytes, len);
            Interlocked.Add(ref state.TotalDownBytes, len);
        }

        return true;
    }

    private static bool TryExtractFlowKey(byte[] packet, int len, bool outbound, out FlowKey key, out int payloadLen)
    {
        key = default;
        payloadLen = 0;

        if (len < 24)
            return false;

        int version = packet[0] >> 4;
        byte protocol;
        int l4Offset;

        if (version == 4)
        {
            int ihl = (packet[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl + 4)
                return false;
            protocol = packet[9];
            l4Offset = ihl;
        }
        else if (version == 6)
        {
            if (len < 44)
                return false;
            protocol = packet[6];
            l4Offset = 40;
        }
        else
        {
            return false;
        }

        if (protocol != 6 && protocol != 17)
            return false;

        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(l4Offset, 2));
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(l4Offset + 2, 2));

        if (protocol == 6 && len >= l4Offset + 13)
        {
            int tcpHeaderLen = ((packet[l4Offset + 12] >> 4) & 0x0F) * 4;
            payloadLen = Math.Max(0, len - l4Offset - tcpHeaderLen);
        }
        else if (protocol == 17)
        {
            payloadLen = Math.Max(0, len - l4Offset - 8);
        }

        key = outbound
            ? new FlowKey(protocol, srcPort, dstPort)
            : new FlowKey(protocol, dstPort, srcPort);

        return true;
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private string ResolveProcessPath(uint pid)
    {
        if (pid == 0) return string.Empty;
        if (_pidPathCache.TryGetValue(pid, out var cached))
            return cached;

        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            _lastResolveErr = Marshal.GetLastWin32Error();
            return string.Empty;
        }

        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            if (QueryFullProcessImageNameW(hProc, 0, sb, ref size) && size > 0)
            {
                var norm = NormalizePath(sb.ToString(0, (int)size));
                _pidPathCache[pid] = norm;
                return norm;
            }
            _lastResolveErr = Marshal.GetLastWin32Error();
        }
        finally
        {
            CloseHandle(hProc);
        }

        return string.Empty;
    }

    private static string NormalizePath(string path) => path.Trim().ToLowerInvariant();

    public void Dispose()
    {
        Stop(unloadDriver: true);
    }
}
