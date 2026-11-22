using System.Diagnostics;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class DashboardPage : Page
{
    private bool _isLoading;

    public DashboardPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        FirewallBackendService.Instance.ProfileModeChanged += OnExternalStateChanged;
        FirewallBackendService.Instance.NotificationModeChanged += OnExternalNotifChanged;
        await LoadStatusAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        FirewallBackendService.Instance.ProfileModeChanged -= OnExternalStateChanged;
        FirewallBackendService.Instance.NotificationModeChanged -= OnExternalNotifChanged;
    }

    private void OnExternalStateChanged(object? sender, FirewallProfileMode mode)
    {
        DispatcherQueue.TryEnqueue(() => _ = LoadStatusAsync());
    }

    private void OnExternalNotifChanged(object? sender, NotificationMode mode)
    {
        DispatcherQueue.TryEnqueue(() => _ = LoadStatusAsync());
    }

    private async Task LoadStatusAsync()
    {
        _isLoading = true;
        try
        {
            var status = await FirewallBackendService.Instance.GetStatusAsync();
            var recentEvents = await FirewallBackendService.Instance.GetRecentEventsAsync();

            var buckets = AppAggregator.BuildActivityBuckets(recentEvents, bucketCount: 12, maxHeight: 62);
            ActivityChartItems.ItemsSource = buckets;

            var topBlocked = AppAggregator.BuildTopBlockedApps(recentEvents, topCount: 5, maxBarWidth: 160);
            TopBlockedList.ItemsSource = topBlocked;
            EmptyTopBlockedText.Visibility = topBlocked.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            EnabledRulesText.Text = status.EnabledRulesCount.ToString("N0");
            TotalRulesSubText.Text = $"of {status.TotalRulesCount:N0} total rules";
            BlockedEventsText.Text = status.BlockedEventsCount.ToString("N0");
            TempRulesText.Text = status.TemporaryRulesCount.ToString("N0");
            InvalidRulesText.Text = status.InvalidRulesCount.ToString("N0");
            CleanupInvalidLink.Visibility = status.InvalidRulesCount > 0 ? Visibility.Visible : Visibility.Collapsed;

            NetworkProfilesSummary.Text =
                $"Domain: {(status.DomainFirewallEnabled ? "ON" : "OFF")}   •   " +
                $"Private: {(status.PrivateFirewallEnabled ? "ON" : "OFF")}   •   " +
                $"Public: {(status.PublicFirewallEnabled ? "ON" : "OFF")}   •   " +
                $"WFP Auditing: {(status.IsAuditPolicyEnabled ? "Enabled" : "Not Enabled")}";

            HighProfileRadio.IsChecked = status.ProfileMode == FirewallProfileMode.HighFiltering;
            MediumProfileRadio.IsChecked = status.ProfileMode == FirewallProfileMode.MediumFiltering;
            LowProfileRadio.IsChecked = status.ProfileMode == FirewallProfileMode.LowFiltering;
            NoProfileRadio.IsChecked = status.ProfileMode == FirewallProfileMode.NoFiltering;

            NotifDisabledRadio.IsChecked = status.NotificationMode == NotificationMode.Disabled;
            NotifDisplayRadio.IsChecked = status.NotificationMode == NotificationMode.DisplayNotifications;
            NotifLowRadio.IsChecked = status.NotificationMode == NotificationMode.LowNotification;
            NotifLearningRadio.IsChecked = status.NotificationMode == NotificationMode.LearningMode;

            bool canWrite = status.IsServiceConnected || status.IsElevated;
            ElevateButton.Visibility = canWrite ? Visibility.Collapsed : Visibility.Visible;

            if (!canWrite)
            {
                ShowBanner(InfoBarSeverity.Warning, "Read-Only Mode",
                    "FireBrick is running without Administrator privileges and FireBrick.Service is not installed. Click 'Run as Administrator' to modify firewall rules or profiles.");
            }
            else if (!status.IsAuditPolicyEnabled)
            {
                ShowBanner(InfoBarSeverity.Informational, "WFP Connection Auditing Disabled",
                    "Enable WFP Auditing in Settings to see real-time blocked connection notifications in the Connections Log.");
            }
            else
            {
                StatusBanner.IsOpen = false;
            }
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Failed to load firewall status", ex.Message);
        }
        finally
        {
            _isLoading = false;
        }
    }

    private async void ProfileRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
        if (sender is not RadioButton rb || rb.Tag is not string tag) return;
        if (!Enum.TryParse<FirewallProfileMode>(tag, out var mode)) return;

        try
        {
            await FirewallBackendService.Instance.SetProfileModeAsync(mode);
            ShowBanner(InfoBarSeverity.Success, "Profile Updated", $"Switched Windows Firewall to {mode}.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Failed to switch profile", ex.Message);
            await LoadStatusAsync();
        }
    }

    private async void NotificationRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_isLoading) return;
        if (sender is not RadioButton rb || rb.Tag is not string tag) return;
        if (!Enum.TryParse<NotificationMode>(tag, out var mode)) return;

        try
        {
            await FirewallBackendService.Instance.SetNotificationModeAsync(mode);
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Failed to update notification mode", ex.Message);
        }
    }

    private async void CleanupInvalidLink_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int removed = await FirewallBackendService.Instance.CleanupInvalidRulesAsync();
            ShowBanner(InfoBarSeverity.Success, "Cleanup Complete", $"Removed {removed} invalid/orphaned firewall rules.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Cleanup Failed", ex.Message);
        }
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await LoadStatusAsync();

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            FirewallBackendService.RelaunchAsAdministrator();
            Application.Current.Exit();
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Elevation Cancelled", ex.Message);
        }
    }

    private async void QuickAllowTopApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string appPath || string.IsNullOrWhiteSpace(appPath)) return;
        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(appPath, RuleAction.Allow, RuleDirection.Outbound);
            ShowBanner(InfoBarSeverity.Success, "Rule Created", $"Allowed '{rule.ApplicationDisplay}' outbound.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, "Failed to allow app", ex.Message);
        }
    }

    private void OpenWfMscButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("wf.msc") { UseShellExecute = true });
        }
        catch { }
    }

    private void ShowBanner(InfoBarSeverity severity, string title, string message)
    {
        StatusBanner.Severity = severity;
        StatusBanner.Title = title;
        StatusBanner.Message = message;
        StatusBanner.IsOpen = true;
    }
}
