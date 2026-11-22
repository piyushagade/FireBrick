using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class AppsPage : Page
{
    private List<AppGroupSummaryDto> _allApps = new();
    private readonly ObservableCollection<AppGroupSummaryDto> _visibleApps = new();

    public AppsPage()
    {
        InitializeComponent();
        AppsListView.ItemsSource = _visibleApps;
        Loaded += async (_, _) => await LoadAppsAsync();
    }

    private async Task LoadAppsAsync()
    {
        try
        {
            AppsSubtitle.Text = "Aggregating rules, live connections, and WFP events...";
            var rulesTask = FirewallBackendService.Instance.GetRulesAsync();
            var liveTask = FirewallBackendService.Instance.GetActiveConnectionsAsync();
            var eventsTask = FirewallBackendService.Instance.GetRecentEventsAsync();

            await Task.WhenAll(rulesTask, liveTask, eventsTask);
            _allApps = AppAggregator.GroupByApplication(rulesTask.Result, liveTask.Result, eventsTask.Result);
            ApplyFilters();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to load applications", ex.Message);
        }
    }

    private void ApplyFilters()
    {
        if (SearchBox == null || AppFilterCombo == null) return;

        var q = SearchBox.Text?.Trim() ?? string.Empty;
        var filterTag = (AppFilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";

        IEnumerable<AppGroupSummaryDto> items = _allApps;
        if (!string.IsNullOrWhiteSpace(q))
        {
            items = items.Where(a =>
                a.ApplicationName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                a.ApplicationPath.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        items = filterTag switch
        {
            "Active" => items.Where(a => a.ActiveConnectionCount > 0),
            "Blocked" => items.Where(a => a.BlockedEventsCount > 0),
            "Rules" => items.Where(a => a.RuleCount > 0),
            _ => items
        };

        _visibleApps.Clear();
        foreach (var item in items.Take(350))
            _visibleApps.Add(item);

        AppsSubtitle.Text = $"Showing {_visibleApps.Count:N0} of {_allApps.Count:N0} applications ({_allApps.Count(a => a.ActiveConnectionCount > 0)} currently connected)";
    }

    private void FilterChanged(object sender, object e) => ApplyFilters();
    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await LoadAppsAsync();

    private async void AllowApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not AppGroupSummaryDto app) return;
        try
        {
            await FirewallBackendService.Instance.CreateQuickRuleAsync(app.ApplicationPath, RuleAction.Allow, RuleDirection.Outbound);
            ShowInfo(InfoBarSeverity.Success, "App Allowed", $"Created outbound Allow rule for {app.ApplicationName}.");
            await LoadAppsAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to allow app", ex.Message);
        }
    }

    private async void BlockAndKillApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not AppGroupSummaryDto app) return;
        try
        {
            await FirewallBackendService.Instance.CreateQuickRuleAsync(app.ApplicationPath, RuleAction.Block, RuleDirection.Outbound);
            int killed = await FirewallBackendService.Instance.KillConnectionsForAppAsync(app.ApplicationPath);
            ShowInfo(InfoBarSeverity.Success, "App Blocked",
                $"Blocked {app.ApplicationName} and terminated {killed} active TCP socket(s).");
            await LoadAppsAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to block app", ex.Message);
        }
    }

    private void InspectRules_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not AppGroupSummaryDto app) return;
        FirewallBackendService.Instance.PendingRulesSearchFilter = app.ApplicationName;
        Frame?.Navigate(typeof(RulesPage));
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        AppsInfoBar.Severity = severity;
        AppsInfoBar.Title = title;
        AppsInfoBar.Message = message;
        AppsInfoBar.IsOpen = true;
    }
}
