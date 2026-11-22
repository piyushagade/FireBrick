using System.Diagnostics;
using System.Net.NetworkInformation;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Detects the active Wi-Fi SSID (or active wired network interface) and matches
/// user-configured NetworkProfileRuleDto entries for automatic profile switching.
/// </summary>
public sealed class NetworkProfileMonitor
{
    public string GetCurrentNetworkName()
    {
        var ssid = TryGetWifiSsid();
        if (!string.IsNullOrWhiteSpace(ssid))
            return ssid;

        try
        {
            var active = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

            return active?.Name ?? "Disconnected";
        }
        catch
        {
            return "Unknown";
        }
    }

    public static NetworkProfileRuleDto? MatchRule(string networkName, IEnumerable<NetworkProfileRuleDto> rules)
    {
        if (string.IsNullOrWhiteSpace(networkName))
            return null;

        return rules.FirstOrDefault(r =>
            r.Enabled &&
            !string.IsNullOrWhiteSpace(r.NetworkName) &&
            string.Equals(r.NetworkName.Trim(), networkName.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    private static string TryGetWifiSsid()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "wlan show interfaces",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return string.Empty;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(2000);

            foreach (var rawLine in output.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) &&
                    !line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                {
                    int colon = line.IndexOf(':');
                    if (colon >= 0 && colon + 1 < line.Length)
                    {
                        var ssid = line[(colon + 1)..].Trim();
                        if (!string.IsNullOrWhiteSpace(ssid))
                            return ssid;
                    }
                }
            }
        }
        catch { }

        return string.Empty;
    }
}
