using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Pure aggregation helpers for Per-App Grouped View, Dashboard Top Blocked Apps, and Activity Charts.
/// </summary>
public static class AppAggregator
{
    public static List<AppGroupSummaryDto> GroupByApplication(
        IEnumerable<FirewallRuleDto> rules,
        IEnumerable<ActiveConnectionDto> activeConnections,
        IEnumerable<ConnectionEventDto> recentEvents)
    {
        var map = new Dictionary<string, AppGroupSummaryDto>(StringComparer.OrdinalIgnoreCase);

        AppGroupSummaryDto GetOrAdd(string path, string fallbackName)
        {
            var normalized = string.IsNullOrWhiteSpace(path) ? fallbackName : path.Trim();
            if (!map.TryGetValue(normalized, out var summary))
            {
                var name = normalized.Contains('\\') ? Path.GetFileName(normalized) : normalized;
                summary = new AppGroupSummaryDto
                {
                    ApplicationPath = normalized,
                    ApplicationName = string.IsNullOrWhiteSpace(name) ? "System" : name
                };
                map[normalized] = summary;
            }
            return summary;
        }

        foreach (var r in rules)
        {
            var path = !string.IsNullOrWhiteSpace(r.ExpandedApplicationPath)
                ? r.ExpandedApplicationPath
                : r.ApplicationName;
            if (string.IsNullOrWhiteSpace(path)) continue;

            var g = GetOrAdd(path, r.ApplicationDisplay);
            g.RuleCount++;
            if (r.Action == RuleAction.Allow) g.AllowRuleCount++;
            else g.BlockRuleCount++;
            if (r.Enabled) g.EnabledRuleCount++;
        }

        foreach (var c in activeConnections)
        {
            var path = !string.IsNullOrWhiteSpace(c.ProcessPath) ? c.ProcessPath : c.ProcessName;
            if (string.IsNullOrWhiteSpace(path)) continue;
            var g = GetOrAdd(path, c.ProcessName);
            g.ActiveConnectionCount++;
        }

        foreach (var e in recentEvents)
        {
            if (e.Action != RuleAction.Block) continue;
            var path = !string.IsNullOrWhiteSpace(e.ApplicationPath) ? e.ApplicationPath : e.ApplicationName;
            if (string.IsNullOrWhiteSpace(path)) continue;
            var g = GetOrAdd(path, e.ApplicationName);
            g.BlockedEventsCount++;
            if (g.SignatureStatus == SignatureTrustStatus.Unknown && e.SignatureStatus != SignatureTrustStatus.Unknown)
            {
                g.SignatureStatus = e.SignatureStatus;
                g.Publisher = e.Publisher;
            }
        }

        return map.Values
            .OrderByDescending(g => g.ActiveConnectionCount > 0 ? 1 : 0)
            .ThenByDescending(g => g.BlockedEventsCount)
            .ThenByDescending(g => g.RuleCount)
            .ThenBy(g => g.ApplicationName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static List<TopAppStatDto> BuildTopBlockedApps(
        IEnumerable<ConnectionEventDto> events,
        IEnumerable<FirewallRuleDto>? currentRules = null,
        int topCount = 5,
        double maxBarWidth = 180)
    {
        var allowedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (currentRules != null)
        {
            foreach (var r in currentRules)
            {
                if (r.Enabled && r.Direction == RuleDirection.Outbound && r.Action == RuleAction.Allow)
                {
                    var p = !string.IsNullOrWhiteSpace(r.ExpandedApplicationPath)
                        ? r.ExpandedApplicationPath
                        : r.ApplicationName;
                    if (!string.IsNullOrWhiteSpace(p))
                        allowedPaths.Add(p.Trim());
                }
            }
        }

        var grouped = events
            .Where(e => e.Action == RuleAction.Block && !string.IsNullOrWhiteSpace(e.ApplicationName))
            .GroupBy(e => string.IsNullOrWhiteSpace(e.ApplicationPath) ? e.ApplicationName : e.ApplicationPath, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                Path = g.First().ApplicationPath,
                Name = g.First().ApplicationName,
                Count = g.Count()
            })
            .OrderByDescending(x => x.Count)
            .Take(topCount)
            .ToList();

        int max = grouped.Count > 0 ? grouped.Max(x => x.Count) : 1;
        return grouped.Select(x => new TopAppStatDto
        {
            ApplicationName = x.Name,
            ApplicationPath = x.Path,
            BlockedCount = x.Count,
            BarWidth = Math.Max(14, (x.Count / (double)max) * maxBarWidth),
            IsAllowed = !string.IsNullOrWhiteSpace(x.Path) && allowedPaths.Contains(x.Path.Trim())
        }).ToList();
    }

    public static List<ActivityBucketDto> BuildActivityBuckets(IEnumerable<ConnectionEventDto> events, int bucketCount = 12, double maxHeight = 64)
    {
        var list = events.ToList();
        var now = DateTimeOffset.Now;
        var buckets = new List<ActivityBucketDto>(bucketCount);

        // 12 buckets spanning the last 60 minutes (5 minutes per bucket)
        const int minutesPerBucket = 5;
        for (int i = bucketCount - 1; i >= 0; i--)
        {
            var end = now.AddMinutes(-i * minutesPerBucket);
            var start = end.AddMinutes(-minutesPerBucket);
            int blocked = list.Count(e => e.Action == RuleAction.Block && e.TimestampUtc.ToLocalTime() >= start && e.TimestampUtc.ToLocalTime() < end);
            int allowed = list.Count(e => e.Action == RuleAction.Allow && e.TimestampUtc.ToLocalTime() >= start && e.TimestampUtc.ToLocalTime() < end);

            buckets.Add(new ActivityBucketDto
            {
                Label = end.ToString("HH:mm"),
                BlockedCount = blocked,
                AllowedCount = allowed
            });
        }

        int maxVal = Math.Max(1, buckets.Max(b => Math.Max(b.BlockedCount, b.AllowedCount)));
        foreach (var b in buckets)
        {
            b.BlockedBarHeight = b.BlockedCount == 0 ? 3 : Math.Max(6, (b.BlockedCount / (double)maxVal) * maxHeight);
            b.AllowedBarHeight = b.AllowedCount == 0 ? 3 : Math.Max(6, (b.AllowedCount / (double)maxVal) * maxHeight);
        }

        return buckets;
    }
}
