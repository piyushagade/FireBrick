using System.Runtime.InteropServices;

namespace FireBrick.Core.Engine;

/// <summary>
/// Converts NT kernel device paths (e.g. \device\harddiskvolume3\windows\system32\svchost.exe)
/// reported by WFP Security Event Log into standard Win32 paths (C:\windows\system32\svchost.exe).
/// </summary>
public static class DevicePathConverter
{
    private static readonly object LockObj = new();
    private static Dictionary<string, string>? _deviceMap;
    private static DateTime _lastRefreshUtc = DateTime.MinValue;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, char[] lpTargetPath, uint ucchMax);

    public static string ConvertToWin32Path(string? devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath))
            return string.Empty;

        var trimmed = devicePath.Trim();
        if (trimmed.Equals("System", StringComparison.OrdinalIgnoreCase))
            return "System";

        if (!trimmed.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
            return Environment.ExpandEnvironmentVariables(trimmed);

        var map = GetDeviceMap();
        foreach (var kvp in map)
        {
            if (trimmed.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                var rest = trimmed[kvp.Key.Length..];
                if (rest.Length == 0 || rest[0] == '\\')
                {
                    return kvp.Value + rest;
                }
            }
        }

        return trimmed;
    }

    private static Dictionary<string, string> GetDeviceMap()
    {
        lock (LockObj)
        {
            if (_deviceMap != null && (DateTime.UtcNow - _lastRefreshUtc).TotalMinutes < 5)
                return _deviceMap;

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var buffer = new char[512];

            foreach (var drive in Environment.GetLogicalDrives())
            {
                var driveLetter = drive.TrimEnd('\\'); // e.g., "C:"
                uint len = QueryDosDeviceW(driveLetter, buffer, (uint)buffer.Length);
                if (len > 0)
                {
                    int nullIdx = Array.IndexOf(buffer, '\0');
                    var target = nullIdx >= 0 ? new string(buffer, 0, nullIdx) : new string(buffer, 0, (int)len);
                    if (!string.IsNullOrEmpty(target))
                    {
                        map[target] = driveLetter;
                    }
                }
            }

            _deviceMap = map;
            _lastRefreshUtc = DateTime.UtcNow;
            return _deviceMap;
        }
    }
}
