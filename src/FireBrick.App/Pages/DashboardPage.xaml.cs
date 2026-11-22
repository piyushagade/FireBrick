using System.Diagnostics;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

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

    private async Task LoadStatusAsync(bool preserveBanner = false)
    {
        _isLoading = true;
        try
        {
            var statusTask = FirewallBackendService.Instance.GetStatusAsync();
            var eventsTask = FirewallBackendService.Instance.GetRecentEventsAsync();
            var rulesTask = FirewallBackendService.Instance.GetRulesAsync();
            await Task.WhenAll(statusTask, eventsTask, rulesTask);

            var status = statusTask.Result;
            var recentEvents = eventsTask.Result;
            var currentRules = rulesTask.Result;

            var buckets = AppAggregator.BuildActivityBuckets(recentEvents, bucketCount: 12, maxHeight: 62);
            ActivityChartItems.ItemsSource = buckets;

            var topBlocked = AppAggregator.BuildTopBlockedApps(recentEvents, currentRules, topCount: 5, maxBarWidth: 160);
            TopBlockedList.ItemsSource = topBlocked;
            EmptyTopBlockedText.Visibility = topBlocked.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            EnabledRulesText.Text = status.EnabledRulesCount.ToString("N0");
            TotalRulesSubText.Text = $"of {status.TotalRulesCount:N0} total rules";
            BlockedEventsText.Text = status.BlockedEventsCount.ToString("N0");
            TempRulesText.Text = status.TemporaryRulesCount.ToString("N0");
            InvalidRulesText.Text = status.InvalidRulesCount.ToString("N0");
            CleanupInvalidLink.Visibility = status.InvalidRulesCount > 0 ? Visibility.Visible : Visibility.Collapsed;

            var onBrush = new SolidColorBrush(Color.FromArgb(255, 16, 185, 129));
            var offBrush = new SolidColorBrush(Color.FromArgb(255, 156, 163, 175));
            var warnBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));

            DomainDot.Fill = status.DomainFirewallEnabled ? onBrush : offBrush;
            DomainPillText.Text = $"Domain: {(status.DomainFirewallEnabled ? "ON" : "OFF")}";

            PrivateDot.Fill = status.PrivateFirewallEnabled ? onBrush : offBrush;
            PrivatePillText.Text = $"Private: {(status.PrivateFirewallEnabled ? "ON" : "OFF")}";

            PublicDot.Fill = status.PublicFirewallEnabled ? onBrush : offBrush;
            PublicPillText.Text = $"Public: {(status.PublicFirewallEnabled ? "ON" : "OFF")}";

            AuditDot.Fill = status.IsAuditPolicyEnabled ? onBrush : warnBrush;
            AuditPillText.Text = $"WFP Auditing: {(status.IsAuditPolicyEnabled ? "Enabled" : "Off")}";

            if (status.IsServiceConnected)
            {
                ServiceStatusDot.Fill = onBrush;
                ServiceStatusText.Text = "Service Connected";
            }
            else if (status.IsElevated)
            {
                ServiceStatusDot.Fill = onBrush;
                ServiceStatusText.Text = "Administrator Mode";
            }
            else
            {
                ServiceStatusDot.Fill = warnBrush;
                ServiceStatusText.Text = "Read-Only";
            }

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

            var svcHealth = await Task.Run(StartupManager.InspectServiceHealth);
            if (svcHealth.NeedsInstall || svcHealth.NeedsStart || svcHealth.NeedsUpdate)
            {
                string label = svcHealth.NeedsInstall ? "Set Up Service" : (svcHealth.NeedsUpdate ? "Update Service" : "Start Service");
                string desc = svcHealth.NeedsInstall
                    ? "Install FireBrickService once (with automatic boot start & crash recovery) so FireBrick works without UAC prompts."
                    : svcHealth.NeedsUpdate
                        ? "A newer FireBrickService binary is bundled with this build. Click to update and restart the background service."
                        : "FireBrickService is installed but currently stopped. Click to start it.";

                var actionBtn = new Button
                {
                    Content = label,
                    HorizontalAlignment = HorizontalAlignment.Right
                };
                actionBtn.Click += async (_, _) =>
                {
                    actionBtn.IsEnabled = false;
                    actionBtn.Content = "Working...";
                    bool ok = await Task.Run(() => StartupManager.InstallOrRepairService(svcHealth.BundledBinaryPath));
                    if (ok)
                    {
                        await FirewallBackendService.Instance.ReconnectServiceAsync();
                        ShowBanner(InfoBarSeverity.Success, "FireBrickService Ready", "Background service is installed, running, and configured for automatic recovery.");
                        await LoadStatusAsync();
                    }
                    else
                    {
                        actionBtn.IsEnabled = true;
                        actionBtn.Content = label;
                        ShowBanner(InfoBarSeverity.Warning, "Service Setup Cancelled", "Administrator approval is required once to configure FireBrickService.");
                    }
                };

                string bannerTitle = svcHealth.NeedsInstall
                    ? "Background Service Not Installed"
                    : svcHealth.NeedsStart
                        ? "Background Service Stopped"
                        : "Background Service Update Available";
                ShowBanner(InfoBarSeverity.Warning, bannerTitle, desc, actionBtn);
            }
            else if (!canWrite)
            {
                ShowBanner(InfoBarSeverity.Warning, "Read-Only Mode",
                    "FireBrick is running without Administrator privileges and FireBrick.Service is not installed. Click 'Run as Administrator' to modify firewall rules or profiles.");
            }
            else if (!status.IsAuditPolicyEnabled)
            {
                ShowBanner(InfoBarSeverity.Informational, "WFP Connection Auditing Disabled",
                    "Enable WFP Auditing in Settings to see real-time blocked connection notifications in the Connections Log.");
            }
            else if (!preserveBanner)
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
        btn.IsEnabled = false;
        btn.Content = "Allowing...";
        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(appPath, RuleAction.Allow, RuleDirection.Outbound);
            btn.Content = "Allowed ✓";
            ShowBanner(InfoBarSeverity.Success, "Rule Created", $"Allowed '{rule.ApplicationDisplay}' outbound.");
            await LoadStatusAsync(preserveBanner: true);
        }
        catch (Exception ex)
        {
            btn.IsEnabled = true;
            btn.Content = "Allow";
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

    private void ShowBanner(InfoBarSeverity severity, string title, string message, Microsoft.UI.Xaml.Controls.Primitives.ButtonBase? actionButton = null)
    {
        StatusBanner.Severity = severity;
        StatusBanner.Title = title;
        StatusBanner.Message = message;
        StatusBanner.ActionButton = actionButton;
        StatusBanner.IsOpen = true;
    }
}
