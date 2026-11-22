using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Monitors Windows Filtering Platform (WFP) Security Event Log events (5152, 5156, 5157)
/// for real-time blocked and allowed connection notifications — the same mechanism used by WFC.
/// </summary>
public sealed class SecurityAuditMonitor : IDisposable
{
    private const string WfpQuery = "*[System[(EventID=5152 or EventID=5156 or EventID=5157)]]";
    private EventLogWatcher? _watcher;
    private readonly object _lock = new();
    private readonly LinkedList<ConnectionEventDto> _recentEvents = new();
    private int _maxEntries = 1000;

    public event EventHandler<ConnectionEventDto>? ConnectionEventReceived;
    public bool IsRunning { get; private set; }
    public string? LastError { get; private set; }

    public int MaxEntries
    {
        get => _maxEntries;
        set => _maxEntries = Math.Clamp(value, 100, 10000);
    }

    public bool TryStart(bool loadRecentHistory = true)
    {
        if (IsRunning) return true;
        LastError = null;

        try
        {
            if (loadRecentHistory)
            {
                LoadRecentEvents(150);
            }

            var query = new EventLogQuery("Security", PathType.LogName, WfpQuery);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;
            IsRunning = true;
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            LastError = "Requires Administrator privileges or FireBrick Service to read Windows Security Event Log.";
            Debug.WriteLine(ex);
            return false;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Debug.WriteLine(ex);
            return false;
        }
    }

    public void Stop()
    {
        if (_watcher != null)
        {
            try
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnEventRecordWritten;
                _watcher.Dispose();
            }
            catch { }
            _watcher = null;
        }
        IsRunning = false;
    }

    public List<ConnectionEventDto> GetRecentEvents(int maxCount = 500)
    {
        lock (_lock)
        {
            return _recentEvents.Take(maxCount).ToList();
        }
    }

    public int GetBlockedCount()
    {
        lock (_lock)
        {
            return _recentEvents.Count(e => e.Action == RuleAction.Block);
        }
    }

    public void ClearHistory()
    {
        lock (_lock)
        {
            _recentEvents.Clear();
        }
    }

    public static bool EnableWfpAuditPolicy()
    {
        try
        {
            bool r1 = RunAuditPol("/set /subcategory:\"Filtering Platform Connection\" /success:enable /failure:enable");
            bool r2 = RunAuditPol("/set /subcategory:\"Filtering Platform Packet Drop\" /failure:enable");
            return r1 && r2;
        }
        catch
        {
            return false;
        }
    }

    public static bool CheckWfpAuditPolicyEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/get /subcategory:\"Filtering Platform Connection\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            return output.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool RunAuditPol(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "auditpol.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc == null) return false;
        proc.WaitForExit(5000);
        return proc.ExitCode == 0;
    }

    private void LoadRecentEvents(int count)
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, WfpQuery)
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(query);
            var loaded = new List<ConnectionEventDto>(count);
            for (int i = 0; i < count; i++)
            {
                using var record = reader.ReadEvent();
                if (record == null) break;
                var dto = ParseEventRecord(record);
                if (dto != null)
                    loaded.Add(dto);
            }

            lock (_lock)
            {
                _recentEvents.Clear();
                foreach (var item in loaded)
                {
                    _recentEvents.AddLast(item);
                }
            }
        }
        catch
        {
            // Non-fatal if history read fails
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;
        try
        {
            var dto = ParseEventRecord(e.EventRecord);
            if (dto == null) return;

            lock (_lock)
            {
                _recentEvents.AddFirst(dto);
                while (_recentEvents.Count > _maxEntries)
                {
                    _recentEvents.RemoveLast();
                }
            }

            ConnectionEventReceived?.Invoke(this, dto);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error parsing WFP event: {ex.Message}");
        }
    }

    public static ConnectionEventDto? ParseEventXml(string xml, int eventId, DateTime? timeCreatedUtc)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        var doc = XDocument.Parse(xml);
        XNamespace ns = doc.Root?.Name.Namespace ?? XNamespace.None;

        var dataMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var data in doc.Descendants(ns + "Data"))
        {
            var name = data.Attribute("Name")?.Value;
            if (!string.IsNullOrEmpty(name))
            {
                dataMap[name] = data.Value;
            }
        }

        dataMap.TryGetValue("Application", out var rawApp);
        bool isNoProcess = string.IsNullOrWhiteSpace(rawApp) || rawApp.Trim() == "-";
        var win32Path = isNoProcess ? string.Empty : DevicePathConverter.ConvertToWin32Path(rawApp);
        var appName = isNoProcess
            ? "System / Kernel"
            : (win32Path.Equals("System", StringComparison.OrdinalIgnoreCase) ? "System" : Path.GetFileName(win32Path));

        dataMap.TryGetValue("Direction", out var dirRaw);
        // %%14592 = Inbound, %%14593 = Outbound
        var direction = string.Equals(dirRaw, "%%14592", StringComparison.OrdinalIgnoreCase)
            ? RuleDirection.Inbound
            : RuleDirection.Outbound;

        var action = eventId == 5156 ? RuleAction.Allow : RuleAction.Block;

        dataMap.TryGetValue("ProcessID", out var pidStr);
        int.TryParse(pidStr, out var pid);

        dataMap.TryGetValue("SourceAddress", out var srcAddr);
        dataMap.TryGetValue("SourcePort", out var srcPortStr);
        int.TryParse(srcPortStr, out var srcPort);

        dataMap.TryGetValue("DestAddress", out var dstAddr);
        dataMap.TryGetValue("DestPort", out var dstPortStr);
        int.TryParse(dstPortStr, out var dstPort);

        dataMap.TryGetValue("Protocol", out var protoStr);
        var protocol = protoStr switch
        {
            "6" => "TCP",
            "17" => "UDP",
            "1" => "ICMPv4",
            "58" => "ICMPv6",
            _ => string.IsNullOrWhiteSpace(protoStr) ? "Any" : protoStr
        };

        dataMap.TryGetValue("FilterOrigin", out var filterOrigin);

        var sig = AuthenticodeVerifier.Verify(win32Path);

        return new ConnectionEventDto
        {
            TimestampUtc = timeCreatedUtc.HasValue
                ? new DateTimeOffset(DateTime.SpecifyKind(timeCreatedUtc.Value, DateTimeKind.Utc))
                : DateTimeOffset.UtcNow,
            EventId = eventId,
            Direction = direction,
            Action = action,
            ProcessId = pid,
            ApplicationPath = win32Path,
            ApplicationName = appName,
            Protocol = protocol,
            LocalAddress = direction == RuleDirection.Outbound ? (srcAddr ?? string.Empty) : (dstAddr ?? string.Empty),
            LocalPort = direction == RuleDirection.Outbound ? srcPort : dstPort,
            RemoteAddress = direction == RuleDirection.Outbound ? (dstAddr ?? string.Empty) : (srcAddr ?? string.Empty),
            RemotePort = direction == RuleDirection.Outbound ? dstPort : srcPort,
            FilterOrigin = filterOrigin ?? string.Empty,
            SignatureStatus = sig.Status,
            Publisher = sig.Publisher
        };
    }

    private static ConnectionEventDto? ParseEventRecord(EventRecord record)
    {
        return ParseEventXml(record.ToXml(), record.Id, record.TimeCreated?.ToUniversalTime());
    }

    public void Dispose()
    {
        Stop();
    }
}
