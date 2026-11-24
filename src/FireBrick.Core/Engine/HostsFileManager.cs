using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Reads, parses, validates, and safely writes the Windows hosts file
/// (%SystemRoot%\System32\drivers\etc\hosts) while preserving comments and formatting.
/// </summary>
public sealed class HostsFileManager
{
    private static readonly Regex ValidHostTokenRegex = new(
        @"^[A-Za-z0-9](?:[A-Za-z0-9\-_]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-_]*[A-Za-z0-9])?)*\.?$",
        RegexOptions.Compiled);

    private readonly string _hostsPath;
    private readonly string _backupPath;

    public HostsFileManager(string? hostsPath = null, string? backupPath = null)
    {
        _hostsPath = hostsPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        _backupPath = backupPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireBrick", "hosts.bak");
    }

    public string HostsFilePath => _hostsPath;
    public string BackupFilePath => _backupPath;

    public HostsFileDocumentDto LoadDocument()
    {
        string raw = File.Exists(_hostsPath)
            ? File.ReadAllText(_hostsPath, Encoding.UTF8)
            : string.Empty;

        var entries = ParseEntries(raw);
        DateTimeOffset? modified = File.Exists(_hostsPath)
            ? new DateTimeOffset(File.GetLastWriteTimeUtc(_hostsPath), TimeSpan.Zero)
            : null;

        return new HostsFileDocumentDto
        {
            FilePath = _hostsPath,
            RawContent = raw,
            Entries = entries,
            HasBackup = File.Exists(_backupPath),
            LastModifiedUtc = modified
        };
    }

    public static List<HostsEntryDto> ParseEntries(string rawContent)
    {
        var result = new List<HostsEntryDto>();
        if (string.IsNullOrEmpty(rawContent)) return result;

        var lines = SplitLines(rawContent);
        for (int i = 0; i < lines.Length; i++)
        {
            if (TryParseEntryLine(lines[i], i, out var entry))
            {
                result.Add(entry!);
            }
        }

        return result;
    }

    public static bool TryParseEntryLine(string line, int lineIndex, out HostsEntryDto? entry)
    {
        entry = null;
        if (string.IsNullOrWhiteSpace(line)) return false;

        var trimmed = line.Trim();
        bool enabled = true;
        string body = trimmed;

        if (trimmed.StartsWith('#'))
        {
            enabled = false;
            body = trimmed.TrimStart('#').TrimStart();
            if (string.IsNullOrWhiteSpace(body)) return false;
        }

        string comment = string.Empty;
        int commentIdx = body.IndexOf('#');
        if (commentIdx >= 0)
        {
            comment = body[(commentIdx + 1)..].Trim();
            body = body[..commentIdx].Trim();
        }

        if (string.IsNullOrWhiteSpace(body)) return false;

        var tokens = body.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 2) return false;

        var ipToken = tokens[0];
        if (!IPAddress.TryParse(ipToken, out _)) return false;

        var hostTokens = tokens.Skip(1).ToArray();
        if (!hostTokens.All(IsValidHostToken)) return false;

        entry = new HostsEntryDto
        {
            Enabled = enabled,
            Address = ipToken,
            Hosts = string.Join(" ", hostTokens),
            Comment = comment,
            LineIndex = lineIndex
        };
        return true;
    }

    public static bool ValidateEntry(HostsEntryDto entry, out string error)
    {
        if (entry == null)
        {
            error = "Entry cannot be null.";
            return false;
        }

        var addr = entry.Address?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(addr) || !IPAddress.TryParse(addr, out _))
        {
            error = "Enter a valid IPv4 or IPv6 address (e.g. 0.0.0.0, 127.0.0.1, ::1).";
            return false;
        }

        var hostsRaw = entry.Hosts?.Trim() ?? string.Empty;
        var hostTokens = hostsRaw.Split([' ', '\t', ','], StringSplitOptions.RemoveEmptyEntries);
        if (hostTokens.Length == 0)
        {
            error = "Enter at least one hostname (e.g. example.com).";
            return false;
        }

        foreach (var token in hostTokens)
        {
            if (!IsValidHostToken(token))
            {
                error = $"Invalid hostname: '{token}'.";
                return false;
            }
        }

        error = string.Empty;
        return true;
    }

    public static string FormatEntryLine(HostsEntryDto entry)
    {
        var addr = entry.Address.Trim();
        var hostTokens = entry.Hosts.Split([' ', '\t', ','], StringSplitOptions.RemoveEmptyEntries);
        var hosts = string.Join(" ", hostTokens);
        var comment = entry.Comment?.Trim() ?? string.Empty;
        var prefix = entry.Enabled ? string.Empty : "# ";
        return string.IsNullOrWhiteSpace(comment)
            ? $"{prefix}{addr}\t{hosts}"
            : $"{prefix}{addr}\t{hosts}\t# {comment}";
    }

    /// <summary>
    /// Merges structured entry edits back into the original hosts text while preserving
    /// all non-entry comments and blank lines in place.
    /// </summary>
    public static string ApplyEntriesToRaw(string originalRaw, IReadOnlyList<HostsEntryDto> updatedEntries)
    {
        var originalLines = string.IsNullOrEmpty(originalRaw)
            ? Array.Empty<string>()
            : SplitLines(originalRaw);

        var entryByLine = new Dictionary<int, HostsEntryDto>();
        var appendedEntries = new List<HostsEntryDto>();

        foreach (var e in updatedEntries)
        {
            if (e.LineIndex >= 0 && e.LineIndex < originalLines.Length && !entryByLine.ContainsKey(e.LineIndex))
                entryByLine[e.LineIndex] = e;
            else
                appendedEntries.Add(e);
        }

        var output = new List<string>(originalLines.Length + appendedEntries.Count);
        for (int i = 0; i < originalLines.Length; i++)
        {
            bool wasEntry = TryParseEntryLine(originalLines[i], i, out _);
            if (!wasEntry)
            {
                output.Add(originalLines[i]);
            }
            else if (entryByLine.TryGetValue(i, out var replacement))
            {
                output.Add(FormatEntryLine(replacement));
            }
            // else: entry was deleted by the user, omit line
        }

        foreach (var added in appendedEntries)
        {
            output.Add(FormatEntryLine(added));
        }

        return string.Join(Environment.NewLine, output) + (output.Count > 0 ? Environment.NewLine : string.Empty);
    }

    public HostsFileDocumentDto SaveEntries(IReadOnlyList<HostsEntryDto> entries)
    {
        foreach (var e in entries)
        {
            if (!ValidateEntry(e, out var err))
                throw new ArgumentException(err);
        }

        var currentRaw = File.Exists(_hostsPath)
            ? File.ReadAllText(_hostsPath, Encoding.UTF8)
            : string.Empty;

        var merged = ApplyEntriesToRaw(currentRaw, entries);
        return SaveRaw(merged);
    }

    public HostsFileDocumentDto SaveRaw(string rawContent)
    {
        EnsureBackupExists();

        var dir = Path.GetDirectoryName(_hostsPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        bool wasReadOnly = false;
        if (File.Exists(_hostsPath))
        {
            var attrs = File.GetAttributes(_hostsPath);
            if ((attrs & FileAttributes.ReadOnly) != 0)
            {
                wasReadOnly = true;
                File.SetAttributes(_hostsPath, attrs & ~FileAttributes.ReadOnly);
            }
        }

        try
        {
            // Write UTF-8 without BOM (standard Windows hosts format)
            File.WriteAllText(_hostsPath, rawContent ?? string.Empty, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        finally
        {
            if (wasReadOnly && File.Exists(_hostsPath))
            {
                try
                {
                    var attrs = File.GetAttributes(_hostsPath);
                    File.SetAttributes(_hostsPath, attrs | FileAttributes.ReadOnly);
                }
                catch { }
            }
        }

        return LoadDocument();
    }

    public HostsFileDocumentDto RestoreBackup()
    {
        if (!File.Exists(_backupPath))
            throw new FileNotFoundException("No hosts file backup exists yet.", _backupPath);

        var backupContent = File.ReadAllText(_backupPath, Encoding.UTF8);
        return SaveRaw(backupContent);
    }

    public static bool FlushDnsCache()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig.exe",
                Arguments = "/flushdns",
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
        catch
        {
            return false;
        }
    }

    private void EnsureBackupExists()
    {
        if (File.Exists(_backupPath) || !File.Exists(_hostsPath))
            return;

        try
        {
            var dir = Path.GetDirectoryName(_backupPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.Copy(_hostsPath, _backupPath, overwrite: false);
        }
        catch
        {
            // Non-fatal if backup directory cannot be created
        }
    }

    private static bool IsValidHostToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 253) return false;
        return ValidHostTokenRegex.IsMatch(token);
    }

    private static string[] SplitLines(string text)
        => text.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd('\n').Split('\n');
}
