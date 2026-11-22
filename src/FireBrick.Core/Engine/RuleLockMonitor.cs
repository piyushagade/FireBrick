using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Implements WFC-style Rule Lock & Tamper Protection.
/// Snapshots known firewall rule names and detects/reverts unauthorized external rule injections.
/// </summary>
public sealed class RuleLockMonitor
{
    private readonly object _lock = new();
    private HashSet<string> _knownRuleNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<RuleLockAlertDto> _alerts = new();
    private bool _isArmed;

    public bool IsArmed
    {
        get { lock (_lock) return _isArmed; }
    }

    public void Arm(IEnumerable<FirewallRuleDto> currentRules)
    {
        lock (_lock)
        {
            _knownRuleNames = new HashSet<string>(
                currentRules.Select(r => r.Name),
                StringComparer.OrdinalIgnoreCase);
            _isArmed = true;
        }
    }

    public void Disarm()
    {
        lock (_lock)
        {
            _isArmed = false;
        }
    }

    public void NotifyAuthorizedRuleAdded(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName)) return;
        lock (_lock)
        {
            _knownRuleNames.Add(ruleName);
        }
    }

    public void NotifyAuthorizedRuleRemoved(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName)) return;
        lock (_lock)
        {
            _knownRuleNames.Remove(ruleName);
        }
    }

    public List<RuleLockAlertDto> CheckAndEnforce(WindowsFirewallManager firewall)
    {
        lock (_lock)
        {
            if (!_isArmed) return new List<RuleLockAlertDto>();
        }

        var current = firewall.GetRules();
        var newAlerts = new List<RuleLockAlertDto>();

        lock (_lock)
        {
            if (!_isArmed) return newAlerts;

            foreach (var rule in current)
            {
                if (_knownRuleNames.Contains(rule.Name))
                    continue;

                // Never flag FireBrick's own managed lockdown/system rules as unauthorized injections
                if (rule.Name.Equals("FireBrick: High Filtering Outbound Block", StringComparison.OrdinalIgnoreCase) ||
                    rule.Grouping.Equals("FireBrick System", StringComparison.OrdinalIgnoreCase))
                {
                    _knownRuleNames.Add(rule.Name);
                    continue;
                }

                // Unauthorized external rule detected — attempt to revert it
                bool reverted = false;
                try
                {
                    firewall.DeleteRule(rule.Name);
                    reverted = true;
                }
                catch
                {
                    // If Windows protected rule cannot be deleted, accept it into snapshot so we don't alert repeatedly
                    _knownRuleNames.Add(rule.Name);
                }

                var alert = new RuleLockAlertDto
                {
                    TimestampUtc = DateTimeOffset.UtcNow,
                    RuleName = rule.Name,
                    ChangeType = "External Rule Injected",
                    Reverted = reverted
                };

                _alerts.AddFirst(alert);
                while (_alerts.Count > 200)
                    _alerts.RemoveLast();

                newAlerts.Add(alert);
            }
        }

        return newAlerts;
    }

    public List<RuleLockAlertDto> GetAlerts()
    {
        lock (_lock)
        {
            return _alerts.ToList();
        }
    }
}
