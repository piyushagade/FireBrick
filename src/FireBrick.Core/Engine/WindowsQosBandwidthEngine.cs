using System.Diagnostics;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Driverless outbound (upload) bandwidth limiter using built-in Windows QoS Packet Scheduler (NetQos).
/// </summary>
public sealed class WindowsQosBandwidthEngine
{
    private const string PolicyPrefix = "FireBrick_QoS_";
    public string? LastError { get; private set; }
    public bool IsApplied { get; private set; }

    public Task<(bool Success, string? Error)> ApplyRulesAsync(IEnumerable<BandwidthRuleDto> rules, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            try
            {
                var activeRules = rules
                    .Where(r => r.Enabled && r.UploadLimitKBps > 0 && !string.IsNullOrWhiteSpace(r.ApplicationPath))
                    .ToList();

                var commands = new List<string>
                {
                    $"Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '{PolicyPrefix}*' }} | Remove-NetQosPolicy -Confirm:$false -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
                    $"Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '{PolicyPrefix}*' }} | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
                };

                foreach (var rule in activeRules)
                {
                    // NetQos expects bits per second. 1 KB/s = 1024 * 8 = 8192 bps.
                    long bps = Math.Max(8192L, (long)rule.UploadLimitKBps * 8192L);
                    string safeName = $"{PolicyPrefix}{SanitizeName(rule.Id)}";
                    string appCondition = EscapePs(rule.ApplicationPath);

                    commands.Add(
                        $"New-NetQosPolicy -Name '{safeName}' -AppPathNameMatchCondition '{appCondition}' -ThrottleRateActionBitsPerSecond {bps} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null");
                }

                var script = string.Join("; ", commands);
                var (exitCode, stderr) = RunPowerShell(script);
                if (exitCode != 0)
                {
                    LastError = string.IsNullOrWhiteSpace(stderr)
                        ? "Windows QoS policy command failed. Note: Windows Home editions may not enforce Policy-based QoS."
                        : stderr.Trim();
                    IsApplied = false;
                    return (false, LastError);
                }

                LastError = null;
                IsApplied = activeRules.Count > 0;
                return (true, (string?)null);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                IsApplied = false;
                return (false, LastError);
            }
        }, ct);
    }

    public Task ClearAllAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            try
            {
                var script =
                    $"Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '{PolicyPrefix}*' }} | Remove-NetQosPolicy -Confirm:$false -PolicyStore ActiveStore -ErrorAction SilentlyContinue; " +
                    $"Get-NetQosPolicy -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '{PolicyPrefix}*' }} | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue";
                RunPowerShell(script);
            }
            catch { }
            finally
            {
                IsApplied = false;
                LastError = null;
            }
        }, ct);
    }

    private static (int ExitCode, string StdErr) RunPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start powershell.exe");
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(15000);
        return (proc.ExitCode, stderr);
    }

    private static string SanitizeName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return Guid.NewGuid().ToString("N")[..8];
        return new string(raw.Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-').ToArray());
    }

    private static string EscapePs(string value) => value.Replace("'", "''");
}
