using System.Diagnostics;
using Microsoft.Win32;

namespace FireBrick.Core.Engine;

/// <summary>
/// Manages Start-with-Windows registry registration (HKCU Run) and FireBrickService lifecycle queries.
/// </summary>
public static class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "FireBrick";

    public static bool IsStartWithWindowsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            return key?.GetValue(ValueName) is string s && !string.IsNullOrWhiteSpace(s);
        }
        catch
        {
            return false;
        }
    }

    public static void SetStartWithWindows(bool enable, string? exePath = null)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
        if (enable)
        {
            var path = exePath ?? Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrWhiteSpace(path))
            {
                key.SetValue(ValueName, $"\"{path}\"");
            }
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }

    public static string QueryServiceState(string serviceName = "FireBrickService")
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {serviceName}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return "Unknown";
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(2000);

            if (output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase)) return "Running";
            if (output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase)) return "Stopped";
            if (output.Contains("START_PENDING", StringComparison.OrdinalIgnoreCase)) return "Starting";
            if (output.Contains("1060", StringComparison.OrdinalIgnoreCase)) return "Not Installed";
            return "Not Installed";
        }
        catch
        {
            return "Unknown";
        }
    }

    public static void RunElevatedScCommand(string arguments)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }
}
