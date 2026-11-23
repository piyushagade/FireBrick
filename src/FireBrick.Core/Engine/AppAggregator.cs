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
            if (e.Action != RuleAction.Block || !IsValidApplicationEvent(e)) continue;
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
            .Where(e => e.Action == RuleAction.Block && IsValidApplicationEvent(e))
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

    public static List<LiveAppSummaryDto> BuildLiveActiveApps(
        IEnumerable<ActiveConnectionDto> activeConnections,
        int topCount = 6)
    {
        return activeConnections
            .Where(c => !string.IsNullOrWhiteSpace(c.ProcessPath) || !string.IsNullOrWhiteSpace(c.ProcessName))
            .GroupBy(
                c => !string.IsNullOrWhiteSpace(c.ProcessPath) ? c.ProcessPath.Trim() : c.ProcessName.Trim(),
                StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var first = g.First();
                var path = first.ProcessPath?.Trim() ?? string.Empty;
                var name = !string.IsNullOrWhiteSpace(path) && path.Contains('\\')
                    ? Path.GetFileName(path)
                    : (!string.IsNullOrWhiteSpace(first.ProcessName) ? first.ProcessName : "System");

                int tcpCount = g.Count(c => string.Equals(c.Protocol, "TCP", StringComparison.OrdinalIgnoreCase));
                int udpCount = g.Count(c => string.Equals(c.Protocol, "UDP", StringComparison.OrdinalIgnoreCase));
                var protoParts = new List<string>(2);
                if (tcpCount > 0) protoParts.Add($"{tcpCount} TCP");
                if (udpCount > 0) protoParts.Add($"{udpCount} UDP");

                var topPorts = g.Where(c => c.RemotePort > 0)
                    .Select(c => c.RemotePort)
                    .Distinct()
                    .OrderBy(p => p)
                    .Take(3)
                    .Select(p => p.ToString())
                    .ToList();

                var detail = string.Join(", ", protoParts);
                if (topPorts.Count > 0)
                    detail = $"{detail} • ports {string.Join(", ", topPorts)}";

                return new LiveAppSummaryDto
                {
                    ApplicationName = name,
                    ApplicationPath = path,
                    ConnectionCount = g.Count(),
                    DetailSummary = detail
                };
            })
            .OrderByDescending(x => x.ConnectionCount)
            .ThenBy(x => x.ApplicationName, StringComparer.OrdinalIgnoreCase)
            .Take(topCount)
            .ToList();
    }

    public static List<RecentBlockedItemDto> BuildRecentBlockedFeed(
        IEnumerable<ConnectionEventDto> events,
        IEnumerable<FirewallRuleDto>? currentRules = null,
        int maxCount = 6)
    {
        var allowedOutbound = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allowedInbound = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (currentRules != null)
        {
            foreach (var r in currentRules)
            {
                if (r.Enabled && r.Action == RuleAction.Allow)
                {
                    var p = !string.IsNullOrWhiteSpace(r.ExpandedApplicationPath)
                        ? r.ExpandedApplicationPath
                        : r.ApplicationName;
                    if (string.IsNullOrWhiteSpace(p)) continue;

                    if (r.Direction == RuleDirection.Outbound)
                        allowedOutbound.Add(p.Trim());
                    else
                        allowedInbound.Add(p.Trim());
                }
            }
        }

        return events
            .Where(e => e.Action == RuleAction.Block && IsValidApplicationEvent(e))
            .GroupBy(
                e => $"{e.ApplicationPath.Trim()}|{e.Direction}|{e.Protocol}|{e.RemoteEndpoint}",
                StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var latest = g.OrderByDescending(x => x.TimestampUtc).First();
                var dir = latest.Direction == RuleDirection.Inbound ? "IN" : "OUT";
                var endpoint = !string.IsNullOrWhiteSpace(latest.RemoteHostName)
                    ? $"{latest.RemoteHostName}:{latest.RemotePort}"
                    : latest.RemoteEndpoint;
                if (!string.IsNullOrWhiteSpace(latest.GeoLocation))
                    endpoint = $"{endpoint} ({latest.GeoLocation})";

                var trimmedPath = latest.ApplicationPath.Trim();
                bool isAllowed = !string.IsNullOrWhiteSpace(trimmedPath) &&
                    (latest.Direction == RuleDirection.Inbound
                        ? allowedInbound.Contains(trimmedPath)
                        : allowedOutbound.Contains(trimmedPath));

                return new
                {
                    latest.TimestampUtc,
                    Item = new RecentBlockedItemDto
                    {
                        TimeDisplay = latest.LocalTimeDisplay,
                        ApplicationName = latest.ApplicationName,
                        ApplicationPath = latest.ApplicationPath,
                        Direction = latest.Direction,
                        DirectionProtocol = $"{dir} • {latest.Protocol}",
                        RemoteEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "—" : endpoint,
                        HitCount = g.Count(),
                        IsAllowed = isAllowed
                    }
                };
            })
            .OrderByDescending(x => x.TimestampUtc)
            .Take(maxCount)
            .Select(x => x.Item)
            .ToList();
    }

    private static bool IsValidApplicationEvent(ConnectionEventDto e)
    {
        if (string.IsNullOrWhiteSpace(e.ApplicationName)) return false;
        var name = e.ApplicationName.Trim();
        if (name == "-" || name.Equals("System / Kernel", StringComparison.OrdinalIgnoreCase)) return false;
        var path = e.ApplicationPath?.Trim();
        if (string.IsNullOrWhiteSpace(path) || path == "-") return false;
        return true;
    }
}
