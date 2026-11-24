using System.Diagnostics;
using System.IO.Compression;

namespace FireBrick.Core.Engine;

/// <summary>
/// Manages installation, discovery, and unloading of the optional signed WinDivert 2.2.x (x64) add-on.
/// </summary>
public static class WinDivertAddonManager
{
    private const string PrimaryDownloadUrl = "https://reqrypt.org/download/WinDivert-2.2.2-A.zip";
    private const string FallbackDownloadUrl = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

    public static string AddonDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FireBrick",
        "addons",
        "windivert");

    public static string? ResolveInstalledDirectory()
    {
        var appDir = AppContext.BaseDirectory;
        if (HasWinDivertBinaries(appDir))
            return appDir;

        if (HasWinDivertBinaries(AddonDirectory))
            return AddonDirectory;

        return null;
    }

    public static bool IsInstalled() => ResolveInstalledDirectory() != null;

    public static bool IsDriverLoaded()
    {
        foreach (var name in new[] { "WinDivert", "WinDivert1.4" })
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"query {name}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                if (p == null) continue;
                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(3000);
                if (p.ExitCode == 0 && output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { }
        }

        return false;
    }

    public static void UnloadDriver()
    {
        foreach (var name in new[] { "WinDivert", "WinDivert1.4" })
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"stop {name}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(4000);
            }
            catch { }
        }
    }

    public static async Task<(bool Success, string Message)> InstallAsync(CancellationToken ct = default)
    {
        if (IsInstalled())
            return (true, $"WinDivert is already installed in {ResolveInstalledDirectory()}.");

        Directory.CreateDirectory(AddonDirectory);

        try
        {
            byte[]? zipBytes = null;
            Exception? lastEx = null;

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("FireBrick/1.0");

            foreach (var url in new[] { PrimaryDownloadUrl, FallbackDownloadUrl })
            {
                try
                {
                    zipBytes = await http.GetByteArrayAsync(url, ct).ConfigureAwait(false);
                    if (zipBytes.Length > 100_000)
                        break;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    zipBytes = null;
                }
            }

            if (zipBytes == null)
                return (false, $"Failed to download WinDivert: {lastEx?.Message ?? "Unknown error"}");

            bool foundDll = false;
            bool foundSys = false;

            using (var ms = new MemoryStream(zipBytes, writable: false))
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                foreach (var entry in archive.Entries)
                {
                    var normalized = entry.FullName.Replace('\\', '/');
                    if (normalized.EndsWith("/x64/WinDivert.dll", StringComparison.OrdinalIgnoreCase) ||
                        normalized.Equals("x64/WinDivert.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        entry.ExtractToFile(Path.Combine(AddonDirectory, "WinDivert.dll"), overwrite: true);
                        foundDll = true;
                    }
                    else if (normalized.EndsWith("/x64/WinDivert64.sys", StringComparison.OrdinalIgnoreCase) ||
                             normalized.Equals("x64/WinDivert64.sys", StringComparison.OrdinalIgnoreCase))
                    {
                        entry.ExtractToFile(Path.Combine(AddonDirectory, "WinDivert64.sys"), overwrite: true);
                        foundSys = true;
                    }
                }
            }

            if (!foundDll || !foundSys)
                return (false, "Downloaded archive did not contain x64/WinDivert.dll and x64/WinDivert64.sys.");

            return (true, $"WinDivert 2.2.2 (x64) installed to {AddonDirectory}.");
        }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x800700E1) ||
                                   ex.Message.Contains("virus", StringComparison.OrdinalIgnoreCase) ||
                                   ex.Message.Contains("potentially unwanted", StringComparison.OrdinalIgnoreCase))
        {
            return (false,
                $"Windows Defender blocked WinDivert as a Potentially Unwanted Application (PUA). " +
                $"To use WinDivert, add an exclusion for '{AddonDirectory}' in Windows Security (or allow it in Protection History) and click Install again. " +
                $"Alternatively, use 'Windows QoS (Driverless)' for upload limiting.");
        }
        catch (Exception ex)
        {
            return (false, $"WinDivert installation failed: {ex.Message}");
        }
    }

    private static bool HasWinDivertBinaries(string directory)
    {
        if (!Directory.Exists(directory)) return false;
        return File.Exists(Path.Combine(directory, "WinDivert.dll")) &&
               File.Exists(Path.Combine(directory, "WinDivert64.sys"));
    }
}
