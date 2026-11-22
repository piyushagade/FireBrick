using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

namespace FireBrick.App.Pages;

public sealed partial class ConnectionsLogPage : Page
{
    private List<ConnectionEventDto> _allAudit = new();
    private List<ActiveConnectionDto> _allLive = new();
    private readonly ObservableCollection<ConnectionEventDto> _visibleAudit = new();
    private readonly ObservableCollection<ActiveConnectionDto> _visibleLive = new();
    private bool _showingLive;

    public ConnectionsLogPage()
    {
        InitializeComponent();
        AuditListView.ItemsSource = _visibleAudit;
        LiveListView.ItemsSource = _visibleLive;
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var cfg = FirewallBackendService.Instance.GetSettings();
            var enableDns = cfg.EnableReverseDns;
            var enableGeo = cfg.EnableGeoIpLookup;

            if (_showingLive)
            {
                _allLive = await FirewallBackendService.Instance.GetActiveConnectionsAsync();
                if (enableDns || enableGeo)
                {
                    await EnrichLiveAsync(_allLive, enableDns, enableGeo);
                }
                ApplyFilter();
                SubtitleText.Text = $"{_allLive.Count:N0} active TCP/UDP sockets currently open.";
            }
            else
            {
                _allAudit = await FirewallBackendService.Instance.GetRecentEventsAsync();
                if (enableDns || enableGeo)
                {
                    await EnrichAuditAsync(_allAudit, enableDns, enableGeo);
                }
                ApplyFilter();
                SubtitleText.Text = _allAudit.Count > 0
                    ? $"{_allAudit.Count:N0} recent WFP audit events loaded."
                    : "No WFP audit events found yet. Ensure WFP Connection Auditing is enabled in Settings and run elevated or via FireBrick Service.";
            }
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to load connections", ex.Message);
        }
    }

    private static async Task EnrichAuditAsync(List<ConnectionEventDto> events, bool doDns, bool doGeo)
    {
        var dns = FirewallBackendService.Instance.DnsCache;
        var geo = FirewallBackendService.Instance.GeoIpCache;
        var ips = events.Select(e => e.RemoteAddress).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Take(30).ToList();

        var tasks = new List<Task>();
        if (doDns) tasks.AddRange(ips.Select(ip => dns.ResolveAsync(ip)));
        if (doGeo) tasks.AddRange(ips.Select(ip => geo.ResolveAsync(ip)));
        await Task.WhenAll(tasks);

        foreach (var e in events)
        {
            if (string.IsNullOrEmpty(e.RemoteAddress)) continue;
            if (doDns) e.RemoteHostName = dns.TryGetCached(e.RemoteAddress) ?? string.Empty;
            if (doGeo) e.GeoLocation = geo.TryGetCached(e.RemoteAddress)?.DisplaySummary ?? string.Empty;
        }
    }

    private static async Task EnrichLiveAsync(List<ActiveConnectionDto> conns, bool doDns, bool doGeo)
    {
        var dns = FirewallBackendService.Instance.DnsCache;
        var geo = FirewallBackendService.Instance.GeoIpCache;
        var ips = conns.Select(c => c.RemoteAddress).Where(ip => !string.IsNullOrEmpty(ip) && ip != "*").Distinct().Take(30).ToList();

        var tasks = new List<Task>();
        if (doDns) tasks.AddRange(ips.Select(ip => dns.ResolveAsync(ip)));
        if (doGeo) tasks.AddRange(ips.Select(ip => geo.ResolveAsync(ip)));
        await Task.WhenAll(tasks);

        foreach (var c in conns)
        {
            if (string.IsNullOrEmpty(c.RemoteAddress)) continue;
            if (doDns) c.RemoteHostName = dns.TryGetCached(c.RemoteAddress) ?? string.Empty;
            if (doGeo) c.GeoLocation = geo.TryGetCached(c.RemoteAddress)?.DisplaySummary ?? string.Empty;
        }
    }

    private void ApplyFilter()
    {
        if (SearchBox == null || BlockedOnlyCheck == null)
            return;

        var q = SearchBox.Text?.Trim() ?? string.Empty;

        if (_showingLive)
        {
            IEnumerable<ActiveConnectionDto> items = _allLive;
            if (!string.IsNullOrWhiteSpace(q))
            {
                items = items.Where(c =>
                    c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.ProcessPath.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.RemoteAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.RemoteHostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.Protocol.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.RemotePort.ToString().Contains(q, StringComparison.OrdinalIgnoreCase));
            }

            _visibleLive.Clear();
            foreach (var item in items.Take(400))
                _visibleLive.Add(item);
        }
        else
        {
            IEnumerable<ConnectionEventDto> items = _allAudit;
            if (BlockedOnlyCheck.IsChecked == true)
                items = items.Where(e => e.Action == RuleAction.Block);

            if (!string.IsNullOrWhiteSpace(q))
            {
                items = items.Where(e =>
                    e.ApplicationName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    e.ApplicationPath.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    e.RemoteAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    e.RemoteHostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    e.Protocol.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    e.RemotePort.ToString().Contains(q, StringComparison.OrdinalIgnoreCase));
            }

            _visibleAudit.Clear();
            foreach (var item in items.Take(400))
                _visibleAudit.Add(item);
        }
    }

    private async void ModeToggle_Click(object sender, RoutedEventArgs e)
    {
        _showingLive = ReferenceEquals(sender, LiveModeBtn);
        AuditModeBtn.IsChecked = !_showingLive;
        LiveModeBtn.IsChecked = _showingLive;

        AuditListView.Visibility = _showingLive ? Visibility.Collapsed : Visibility.Visible;
        LiveListView.Visibility = _showingLive ? Visibility.Visible : Visibility.Collapsed;
        BlockedOnlyCheck.Visibility = _showingLive ? Visibility.Collapsed : Visibility.Visible;

        await RefreshAsync();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await RefreshAsync();
    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();
    private void FilterOption_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private async void QuickAllow_Click(object sender, RoutedEventArgs e)
    {
        await CreateQuickRuleFromButtonAsync(sender, RuleAction.Allow, null);
    }

    private async void QuickTempAllow_Click(object sender, RoutedEventArgs e)
    {
        int mins = FirewallBackendService.Instance.GetSettings().DefaultTempRuleMinutes;
        await CreateQuickRuleFromButtonAsync(sender, RuleAction.Allow, mins);
    }

    private async void QuickBlock_Click(object sender, RoutedEventArgs e)
    {
        await CreateQuickRuleFromButtonAsync(sender, RuleAction.Block, null);
    }

    private async void QuickKill_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string appPath || string.IsNullOrWhiteSpace(appPath))
        {
            ShowInfo(InfoBarSeverity.Warning, "Executable Path Unavailable", "Cannot kill sockets for a protected process without path.");
            return;
        }

        try
        {
            int killed = await FirewallBackendService.Instance.KillConnectionsForAppAsync(appPath);
            ShowInfo(InfoBarSeverity.Success, "Connections Terminated", $"Closed {killed} active TCP socket(s) for {Path.GetFileName(appPath)}.");
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to kill connections", ex.Message);
        }
    }

    private async Task CreateQuickRuleFromButtonAsync(object sender, RuleAction action, int? tempMinutes)
    {
        if (sender is not Button btn || btn.Tag is not string appPath || string.IsNullOrWhiteSpace(appPath))
        {
            ShowInfo(InfoBarSeverity.Warning, "Executable Path Unavailable", "Run as Administrator or start FireBrick Service to inspect protected process paths.");
            return;
        }

        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(appPath, action, RuleDirection.Outbound, tempMinutes);
            var suffix = tempMinutes.HasValue ? $" (expires in {tempMinutes} min)" : string.Empty;
            ShowInfo(InfoBarSeverity.Success, "Rule Created", $"Created '{rule.Name}'{suffix}.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to create rule", ex.Message);
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        LogInfoBar.Severity = severity;
        LogInfoBar.Title = title;
        LogInfoBar.Message = message;
        LogInfoBar.IsOpen = true;
    }
}
