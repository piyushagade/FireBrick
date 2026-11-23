using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Persists and evaluates user-defined Auto-Allow / Auto-Block rules against incoming
/// blocked outbound connection events (by App Name/Path, Trusted Publisher, IP/CIDR, or Domain/Host).
/// Rules are evaluated in priority order (first enabled match wins).
/// </summary>
public sealed class AutoRuleManager
{
    private readonly string _storagePath;
    private readonly string? _fallbackPath;
    private readonly object _lock = new();
    private List<AutoRuleDto> _rules = new();

    public AutoRuleManager(string? storagePath = null)
    {
        if (storagePath != null)
        {
            _storagePath = storagePath;
            _fallbackPath = null;
        }
        else
        {
            _storagePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireBrick",
                "auto_rules.json");
            _fallbackPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FireBrick",
                "auto_rules.json");
        }

        Load();
    }

    public List<AutoRuleDto> GetAll()
    {
        lock (_lock)
        {
            return _rules.Select(Clone).ToList();
        }
    }

    public bool HasEnabledDomainRules()
    {
        lock (_lock)
        {
            return _rules.Any(r => r.Enabled && r.MatchField == AutoRuleMatchField.DomainOrHost);
        }
    }

    public void SaveAll(IEnumerable<AutoRuleDto> rules)
    {
        lock (_lock)
        {
            _rules = rules.Select(Normalize).ToList();
            Save();
        }
    }

    public void Upsert(AutoRuleDto rule)
    {
        var normalized = Normalize(rule);
        lock (_lock)
        {
            int idx = _rules.FindIndex(r => string.Equals(r.Id, normalized.Id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
                _rules[idx] = normalized;
            else
                _rules.Add(normalized);
            Save();
        }
    }

    public bool Delete(string id)
    {
        lock (_lock)
        {
            int removed = _rules.RemoveAll(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) Save();
            return removed > 0;
        }
    }

    public bool Move(string id, int delta)
    {
        lock (_lock)
        {
            int idx = _rules.FindIndex(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            int target = idx + delta;
            if (target < 0 || target >= _rules.Count) return false;
            (_rules[idx], _rules[target]) = (_rules[target], _rules[idx]);
            Save();
            return true;
        }
    }

    public void RecordHit(string id)
    {
        lock (_lock)
        {
            var rule = _rules.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
            if (rule == null) return;
            rule.HitCount++;
            rule.LastMatchedUtc = DateTimeOffset.UtcNow;
            Save();
        }
    }

    /// <summary>
    /// Returns the first enabled AutoRuleDto that matches the given connection event, or null.
    /// </summary>
    public AutoRuleDto? Match(ConnectionEventDto evt)
    {
        List<AutoRuleDto> snapshot;
        lock (_lock)
        {
            if (_rules.Count == 0) return null;
            snapshot = _rules.Where(r => r.Enabled).ToList();
        }

        return Match(evt, snapshot);
    }

    public static AutoRuleDto? Match(ConnectionEventDto evt, IEnumerable<AutoRuleDto> rules)
    {
        foreach (var rule in rules)
        {
            if (!rule.Enabled) continue;
            if (IsMatch(rule, evt))
                return Clone(rule);
        }
        return null;
    }

    public static bool IsMatch(AutoRuleDto rule, ConnectionEventDto evt)
    {
        if (string.IsNullOrWhiteSpace(rule.Pattern))
            return false;

        var rawPattern = rule.Pattern.Trim();

        // Allow comma or semicolon separated patterns within a single rule
        var tokens = rawPattern.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0) return false;

        return rule.MatchField switch
        {
            AutoRuleMatchField.AppNameOrPath => tokens.Any(t => MatchAppNameOrPath(t, evt)),
            AutoRuleMatchField.Publisher => MatchPublisher(tokens, rule.RequireTrustedSignature, evt),
            AutoRuleMatchField.IpOrCidr => tokens.Any(t => MatchIpOrCidr(t, evt)),
            AutoRuleMatchField.DomainOrHost => tokens.Any(t => MatchDomainOrHost(t, evt)),
            _ => false
        };
    }

    private static bool MatchAppNameOrPath(string pattern, ConnectionEventDto evt)
    {
        var appName = evt.ApplicationName?.Trim() ?? string.Empty;
        var appPath = evt.ApplicationPath?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(appName) && string.IsNullOrEmpty(appPath))
            return false;

        bool hasWildcard = pattern.Contains('*') || pattern.Contains('?');
        if (hasWildcard)
        {
            return (!string.IsNullOrEmpty(appName) && WildcardMatches(appName, pattern)) ||
                   (!string.IsNullOrEmpty(appPath) && WildcardMatches(appPath, pattern));
        }

        // If user entered a bare executable name (e.g. "m365copilotsetup.exe"), require exact filename match
        // so "app.exe" doesn't accidentally match "malware_app.exe".
        if (!pattern.Contains('\\') && !pattern.Contains('/') &&
            pattern.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return string.Equals(appName, pattern, StringComparison.OrdinalIgnoreCase);
        }

        return (!string.IsNullOrEmpty(appName) && appName.Contains(pattern, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(appPath) && appPath.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchPublisher(string[] tokens, bool requireTrusted, ConnectionEventDto evt)
    {
        if (requireTrusted && evt.SignatureStatus != SignatureTrustStatus.Trusted)
            return false;

        var publisher = evt.Publisher?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(publisher) || string.Equals(publisher, "Unknown", StringComparison.OrdinalIgnoreCase))
            return false;

        foreach (var token in tokens)
        {
            bool hasWildcard = token.Contains('*') || token.Contains('?');
            if (hasWildcard)
            {
                if (WildcardMatches(publisher, token)) return true;
            }
            else if (publisher.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool MatchIpOrCidr(string pattern, ConnectionEventDto evt)
    {
        var remoteIpStr = evt.RemoteAddress?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(remoteIpStr))
            return false;

        // Optional :port suffix (e.g. "40.79.167.9:443" or "40.79.0.0/16:443")
        string ipPattern = pattern;
        int? requiredPort = null;

        // Only split on ':' for IPv4/wildcard patterns (avoid splitting IPv6 addresses unless bracketed)
        if (pattern.StartsWith('[') && pattern.Contains("]:"))
        {
            int closeBracket = pattern.IndexOf("]:", StringComparison.Ordinal);
            ipPattern = pattern[1..closeBracket];
            if (int.TryParse(pattern[(closeBracket + 2)..], out int p)) requiredPort = p;
        }
        else if (pattern.Count(c => c == ':') == 1)
        {
            int colon = pattern.IndexOf(':');
            ipPattern = pattern[..colon];
            if (int.TryParse(pattern[(colon + 1)..], out int p)) requiredPort = p;
        }

        if (requiredPort.HasValue && evt.RemotePort != requiredPort.Value)
            return false;

        if (ipPattern.Contains('*') || ipPattern.Contains('?'))
            return WildcardMatches(remoteIpStr, ipPattern);

        if (ipPattern.Contains('/'))
            return IsIpInCidr(remoteIpStr, ipPattern);

        if (IPAddress.TryParse(remoteIpStr, out var remoteIp) && IPAddress.TryParse(ipPattern, out var targetIp))
            return remoteIp.Equals(targetIp);

        return string.Equals(remoteIpStr, ipPattern, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchDomainOrHost(string pattern, ConnectionEventDto evt)
    {
        var clean = NormalizeHostPattern(pattern);
        if (string.IsNullOrEmpty(clean))
            return false;

        var host = evt.RemoteHostName?.Trim().TrimEnd('.') ?? string.Empty;
        var geo = evt.GeoLocation?.Trim() ?? string.Empty;

        bool hasWildcard = clean.Contains('*') || clean.Contains('?');

        if (!string.IsNullOrEmpty(host))
        {
            if (hasWildcard)
            {
                if (WildcardMatches(host, clean)) return true;
            }
            else
            {
                // Exact host match or subdomain match (e.g. "azure.com" matches "one.azure.com")
                if (string.Equals(host, clean, StringComparison.OrdinalIgnoreCase) ||
                    host.EndsWith("." + clean, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        // Also allow matching GeoIP Org summary (e.g. "Microsoft Azure", "Cloudflare")
        if (!string.IsNullOrEmpty(geo))
        {
            if (hasWildcard)
            {
                if (WildcardMatches(geo, clean)) return true;
            }
            else if (geo.Contains(clean, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Strips http(s):// scheme, path, query, and port if the user pasted a full URL.
    /// </summary>
    public static string NormalizeHostPattern(string input)
    {
        var s = input.Trim();
        if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            s = s[8..];
        else if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            s = s[7..];

        int slash = s.IndexOf('/');
        if (slash >= 0) s = s[..slash];

        int query = s.IndexOf('?');
        if (query >= 0) s = s[..query];

        int colon = s.IndexOf(':');
        if (colon >= 0) s = s[..colon];

        return s.Trim().TrimEnd('.');
    }

    public static bool IsIpInCidr(string ipString, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(ipString, out var ip)) return false;
        if (!IPAddress.TryParse(parts[0], out var network)) return false;
        if (!int.TryParse(parts[1], out int prefixLen)) return false;

        if (ip.AddressFamily != network.AddressFamily) return false;

        var ipBytes = ip.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        int maxBits = ipBytes.Length * 8;
        if (prefixLen < 0 || prefixLen > maxBits) return false;

        int fullBytes = prefixLen / 8;
        int remainingBits = prefixLen % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (ipBytes[i] != netBytes[i]) return false;
        }

        if (remainingBits > 0)
        {
            byte mask = (byte)(0xFF << (8 - remainingBits));
            if ((ipBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }

    public static bool WildcardMatches(string value, string pattern)
    {
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace(@"\*", ".*")
            .Replace(@"\?", ".") + "$";
        return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Materializes a Windows Defender Firewall rule from a matched AutoRuleDto and ConnectionEventDto.
    /// </summary>
    public static FirewallRuleDto BuildFirewallRule(AutoRuleDto autoRule, ConnectionEventDto evt)
    {
        bool isTemp = autoRule.TemporaryMinutes.HasValue && autoRule.TemporaryMinutes.Value > 0;

        int protocol = autoRule.RuleScope == AutoRuleScope.Any
            ? NetFwConstants.NET_FW_IP_PROTOCOL_ANY
            : evt.Protocol.ToUpperInvariant() switch
            {
                "TCP" => NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                "UDP" => NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
                _ => NetFwConstants.NET_FW_IP_PROTOCOL_ANY
            };

        string remotePorts = (autoRule.RuleScope is AutoRuleScope.PortOnly or AutoRuleScope.IpAndPort) && evt.RemotePort > 0
            ? evt.RemotePort.ToString()
            : "*";

        string remoteAddr = autoRule.RuleScope == AutoRuleScope.IpAndPort && !string.IsNullOrWhiteSpace(evt.RemoteAddress)
            ? evt.RemoteAddress
            : "*";

        var prefix = isTemp ? "[FireBrick Temp]" : "FireBrick Auto:";
        var actionLabel = autoRule.Action == RuleAction.Allow ? "Allow" : "Block";
        var appName = string.IsNullOrWhiteSpace(evt.ApplicationName)
            ? Path.GetFileName(evt.ApplicationPath)
            : evt.ApplicationName;

        var suffix = autoRule.RuleScope switch
        {
            AutoRuleScope.PortOnly when evt.RemotePort > 0 => $" ({evt.Protocol} {evt.RemotePort})",
            AutoRuleScope.IpAndPort => $" ({evt.RemoteEndpoint})",
            _ => string.Empty
        };
        if (isTemp) suffix += $" [{DateTime.Now:HHmmss}]";

        var ruleLabel = string.IsNullOrWhiteSpace(autoRule.Name) ? autoRule.Pattern : autoRule.Name;

        return new FirewallRuleDto
        {
            Name = $"{prefix} {actionLabel} Out - {appName}{suffix}",
            Description = $"Auto-Rule: {ruleLabel} ({autoRule.MatchFieldDisplay}: {autoRule.Pattern}) on {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            ApplicationName = evt.ApplicationPath,
            ExpandedApplicationPath = evt.ApplicationPath,
            Protocol = protocol,
            RemotePorts = remotePorts,
            RemoteAddresses = remoteAddr,
            Direction = RuleDirection.Outbound,
            Action = autoRule.Action,
            Enabled = true,
            Profiles = FirewallProfileFlags.All,
            Grouping = isTemp ? "FireBrick Temporary Rules" : "FireBrick Auto-Rules",
            IsTemporary = isTemp,
            ExpiresAtUtc = isTemp ? DateTimeOffset.UtcNow.AddMinutes(autoRule.TemporaryMinutes!.Value) : null
        };
    }

    private static AutoRuleDto Normalize(AutoRuleDto r)
    {
        var copy = Clone(r);
        if (string.IsNullOrWhiteSpace(copy.Id)) copy.Id = Guid.NewGuid().ToString("N");
        copy.Pattern = copy.Pattern?.Trim() ?? string.Empty;
        copy.Name = string.IsNullOrWhiteSpace(copy.Name) ? $"{copy.ActionDisplay} {copy.MatchFieldDisplay}: {copy.Pattern}" : copy.Name.Trim();
        copy.CountdownSeconds = Math.Clamp(copy.CountdownSeconds, 2, 60);
        if (copy.TemporaryMinutes.HasValue && copy.TemporaryMinutes.Value <= 0)
            copy.TemporaryMinutes = null;
        return copy;
    }

    private static AutoRuleDto Clone(AutoRuleDto r) => new()
    {
        Id = r.Id,
        Name = r.Name,
        Enabled = r.Enabled,
        MatchField = r.MatchField,
        Pattern = r.Pattern,
        RequireTrustedSignature = r.RequireTrustedSignature,
        Action = r.Action,
        TriggerMode = r.TriggerMode,
        CountdownSeconds = r.CountdownSeconds,
        RuleScope = r.RuleScope,
        TemporaryMinutes = r.TemporaryMinutes,
        HitCount = r.HitCount,
        LastMatchedUtc = r.LastMatchedUtc
    };

    private void Load()
    {
        if (TryLoadFrom(_storagePath))
            return;

        if (_fallbackPath != null && TryLoadFrom(_fallbackPath))
            return;

        _rules = new();
    }

    private bool TryLoadFrom(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                _rules = JsonSerializer.Deserialize<List<AutoRuleDto>>(json) ?? new();
                return true;
            }
        }
        catch { }
        return false;
    }

    private void Save()
    {
        var json = JsonSerializer.Serialize(_rules, new JsonSerializerOptions { WriteIndented = true });
        if (TrySaveTo(_storagePath, json))
            return;

        if (_fallbackPath != null)
            TrySaveTo(_fallbackPath, json);
    }

    private static bool TrySaveTo(string path, string json)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, json);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
