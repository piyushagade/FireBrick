using System.Diagnostics;
using Microsoft.Win32;

namespace FireBrick.Core.Engine;

public sealed class ServiceHealthInfo
{
    public string State { get; set; } = "Unknown";
    public string InstalledBinaryPath { get; set; } = string.Empty;
    public string BundledBinaryPath { get; set; } = string.Empty;
    public bool IsInstalled => !string.Equals(State, "Not Installed", StringComparison.OrdinalIgnoreCase) &&
                               !string.Equals(State, "Unknown", StringComparison.OrdinalIgnoreCase);
    public bool IsRunning => string.Equals(State, "Running", StringComparison.OrdinalIgnoreCase);
    public bool HasBundledService => !string.IsNullOrWhiteSpace(BundledBinaryPath) && File.Exists(BundledBinaryPath);
    public bool NeedsInstall => !IsInstalled && HasBundledService;
    public bool NeedsStart => IsInstalled && !IsRunning;
    public bool NeedsUpdate => IsInstalled && HasBundledService &&
                               !string.Equals(NormalizePath(InstalledBinaryPath), NormalizePath(BundledBinaryPath), StringComparison.OrdinalIgnoreCase);

    private static string NormalizePath(string p) => p.Trim().Trim('"');
}

/// <summary>
/// Manages Start-with-Windows registry registration (HKCU Run) and FireBrickService lifecycle,
/// including automatic installation, path/version sync, and Windows SCM crash recovery.
/// </summary>
public static class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "FireBrick";
    public const string ServiceName = "FireBrickService";

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

    public static string FindBundledServicePath()
    {
        var appDir = AppContext.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(appDir, "FireBrick.Service.exe"),
            Path.Combine(appDir, "service", "FireBrick.Service.exe")
        ];

        foreach (var path in candidates)
        {
            if (File.Exists(path)) return path;
        }

        return string.Empty;
    }

    public static string QueryServiceState(string serviceName = ServiceName)
    {
        try
        {
            var output = RunScCapture($"query {serviceName}");
            if (output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase)) return "Running";
            if (output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase)) return "Stopped";
            if (output.Contains("START_PENDING", StringComparison.OrdinalIgnoreCase)) return "Starting";
            return "Not Installed";
        }
        catch
        {
            return "Unknown";
        }
    }

    public static string QueryInstalledServiceBinaryPath(string serviceName = ServiceName)
    {
        try
        {
            var output = RunScCapture($"qc {serviceName}");
            foreach (var rawLine in output.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("BINARY_PATH_NAME", StringComparison.OrdinalIgnoreCase))
                {
                    int colon = line.IndexOf(':');
                    if (colon >= 0 && colon + 1 < line.Length)
                    {
                        return line[(colon + 1)..].Trim().Trim('"');
                    }
                }
            }
        }
        catch { }
        return string.Empty;
    }

    public static ServiceHealthInfo InspectServiceHealth()
    {
        var state = QueryServiceState();
        return new ServiceHealthInfo
        {
            State = state,
            InstalledBinaryPath = state != "Not Installed" ? QueryInstalledServiceBinaryPath() : string.Empty,
            BundledBinaryPath = FindBundledServicePath()
        };
    }

    /// <summary>
    /// Installs, updates binPath, configures Windows SCM auto-restart crash recovery, and starts FireBrickService.
    /// Runs silently if already elevated, or triggers a single UAC prompt if running as standard user.
    /// </summary>
    public static bool InstallOrRepairService(string? bundledServiceExePath = null)
    {
        var exePath = string.IsNullOrWhiteSpace(bundledServiceExePath)
            ? FindBundledServicePath()
            : bundledServiceExePath;

        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return false;

        // Atomic PowerShell script: create or reconfigure binPath, add SCM auto-restart recovery, and start
        var escapedPath = exePath.Replace("'", "''");
        var psScript =
            $"$svc = Get-Service -Name '{ServiceName}' -ErrorAction SilentlyContinue; " +
            $"if ($svc) {{ " +
            $"  if ($svc.Status -ne 'Stopped') {{ sc.exe stop {ServiceName} | Out-Null; Start-Sleep -Seconds 2 }}; " +
            $"  sc.exe config {ServiceName} binPath= '\"{escapedPath}\"' start= auto | Out-Null; " +
            $"}} else {{ " +
            $"  sc.exe create {ServiceName} binPath= '\"{escapedPath}\"' start= auto DisplayName= 'FireBrick Firewall Service' | Out-Null; " +
            $"}}; " +
            $"sc.exe failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null; " +
            $"sc.exe start {ServiceName} | Out-Null";

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psScript}\"",
            WindowStyle = ProcessWindowStyle.Hidden
        };

        if (WindowsFirewallManager.IsProcessElevated())
        {
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
        }
        else
        {
            psi.UseShellExecute = true;
            psi.Verb = "runas";
        }

        using var proc = Process.Start(psi);
        if (proc == null) return false;
        proc.WaitForExit(15000);
        return proc.ExitCode == 0;
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

    private static string RunScCapture(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc == null) return string.Empty;
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(2000);
        return output;
    }
}
