using System.Text.Json;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Tracks auto-expiring temporary firewall rules (e.g., "Allow for 15 minutes")
/// and removes them automatically once their TTL expires.
/// </summary>
public sealed class TemporaryRuleManager
{
    private readonly string _storagePath;
    private readonly object _lock = new();
    private List<TemporaryRuleDto> _rules = new();

    public TemporaryRuleManager(string? storagePath = null)
    {
        _storagePath = storagePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireBrick",
            "temporary_rules.json");
        Load();
    }

    public IReadOnlyList<TemporaryRuleDto> GetActive()
    {
        lock (_lock)
        {
            return _rules.Where(r => r.ExpiresAtUtc > DateTimeOffset.UtcNow).ToList();
        }
    }

    public IReadOnlyDictionary<string, TemporaryRuleDto> GetActiveMap()
    {
        lock (_lock)
        {
            var dict = new Dictionary<string, TemporaryRuleDto>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in _rules)
            {
                if (r.ExpiresAtUtc > DateTimeOffset.UtcNow)
                    dict[r.RuleName] = r;
            }
            return dict;
        }
    }

    public void Register(TemporaryRuleDto rule)
    {
        lock (_lock)
        {
            _rules.RemoveAll(r => string.Equals(r.RuleName, rule.RuleName, StringComparison.OrdinalIgnoreCase));
            _rules.Add(rule);
            Save();
        }
    }

    public bool Remove(string ruleName)
    {
        lock (_lock)
        {
            int removed = _rules.RemoveAll(r => string.Equals(r.RuleName, ruleName, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) Save();
            return removed > 0;
        }
    }

    public List<TemporaryRuleDto> PopExpired(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_lock)
        {
            var expired = _rules.Where(r => r.ExpiresAtUtc <= now).ToList();
            if (expired.Count > 0)
            {
                _rules.RemoveAll(r => r.ExpiresAtUtc <= now);
                Save();
            }
            return expired;
        }
    }

    private void Load()
    {
        try
        {
            if (File.Exists(_storagePath))
            {
                var json = File.ReadAllText(_storagePath);
                _rules = JsonSerializer.Deserialize<List<TemporaryRuleDto>>(json) ?? new();
            }
        }
        catch
        {
            _rules = new();
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(_storagePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(_rules, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_storagePath, json);
        }
        catch
        {
            // Fallback silently if running non-elevated against ProgramData
        }
    }
}
