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
    private CancellationTokenSource? _toastDismissCts;

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
        _toastDismissCts?.Cancel();
        _toastDismissCts?.Dispose();
        _toastDismissCts = null;
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
            var liveTask = FirewallBackendService.Instance.GetActiveConnectionsAsync();
            var netTask = FirewallBackendService.Instance.GetCurrentNetworkNameAsync();
            var tempTask = FirewallBackendService.Instance.GetTemporaryRulesAsync();
            var lockAlertsTask = FirewallBackendService.Instance.GetRuleLockAlertsAsync();
            await Task.WhenAll(statusTask, eventsTask, rulesTask, liveTask, netTask, tempTask, lockAlertsTask);

            var status = statusTask.Result;
            var recentEvents = eventsTask.Result;
            var currentRules = rulesTask.Result;
            var activeConns = liveTask.Result;
            var currentNetwork = netTask.Result;
            var tempRules = tempTask.Result;
            var lockAlerts = lockAlertsTask.Result;
            var settings = FirewallBackendService.Instance.GetSettings();

            // Live Active Apps
            var liveApps = AppAggregator.BuildLiveActiveApps(activeConns, topCount: 6);
            LiveActiveAppsList.ItemsSource = liveApps;
            EmptyLiveAppsText.Visibility = liveApps.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            int uniqueLiveApps = activeConns
                .Where(c => !string.IsNullOrWhiteSpace(c.ProcessPath) || !string.IsNullOrWhiteSpace(c.ProcessName))
                .Select(c => !string.IsNullOrWhiteSpace(c.ProcessPath) ? c.ProcessPath.Trim() : c.ProcessName.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            LiveSocketsBadgeText.Text = $"{activeConns.Count} sockets • {uniqueLiveApps} apps";

            // Recent Blocked Connections Feed
            var recentBlocked = AppAggregator.BuildRecentBlockedFeed(recentEvents, currentRules, maxCount: 6);
            RecentBlockedList.ItemsSource = recentBlocked;
            EmptyRecentBlockedText.Visibility = recentBlocked.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            RecentBlockedSummaryText.Text = recentBlocked.Count > 0 ? $"Showing latest {recentBlocked.Count}" : string.Empty;

            EnabledRulesText.Text = status.EnabledRulesCount.ToString("N0");
            TotalRulesSubText.Text = $"of {status.TotalRulesCount:N0} total rules";
            BlockedEventsText.Text = status.BlockedEventsCount.ToString("N0");
            TempRulesText.Text = status.TemporaryRulesCount.ToString("N0");
            InvalidRulesText.Text = status.InvalidRulesCount.ToString("N0");
            CleanupInvalidLink.Visibility = status.InvalidRulesCount > 0 ? Visibility.Visible : Visibility.Collapsed;
            NoInvalidRulesText.Visibility = status.InvalidRulesCount == 0 ? Visibility.Visible : Visibility.Collapsed;

            var onBrush = new SolidColorBrush(Color.FromArgb(255, 16, 185, 129));
            var offBrush = new SolidColorBrush(Color.FromArgb(255, 156, 163, 175));
            var warnBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
            var lockBrush = new SolidColorBrush(Color.FromArgb(255, 59, 130, 246));
            var dangerBrush = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));

            bool anyProfileOn = status.DomainFirewallEnabled || status.PrivateFirewallEnabled || status.PublicFirewallEnabled;
            (string headline, SolidColorBrush shieldFg, Color shieldBg) = status.ProfileMode switch
            {
                FirewallProfileMode.HighFiltering when anyProfileOn =>
                    ("Firewall Active — High Filtering (Lockdown)", lockBrush, Color.FromArgb(36, 59, 130, 246)),
                FirewallProfileMode.MediumFiltering when anyProfileOn =>
                    ("Firewall Active — Medium Filtering", onBrush, Color.FromArgb(36, 16, 185, 129)),
                FirewallProfileMode.LowFiltering when anyProfileOn =>
                    ("Firewall Active — Low Filtering", warnBrush, Color.FromArgb(36, 245, 158, 11)),
                _ =>
                    ("Firewall Disabled — No Filtering", dangerBrush, Color.FromArgb(36, 239, 68, 68))
            };
            FirewallHeadlineText.Text = headline;
            StatusShieldIcon.Foreground = shieldFg;
            StatusShieldBadge.Background = new SolidColorBrush(shieldBg);

            DomainDot.Fill = status.DomainFirewallEnabled ? onBrush : offBrush;
            DomainPillText.Text = $"Domain: {(status.DomainFirewallEnabled ? "ON" : "OFF")}";

            PrivateDot.Fill = status.PrivateFirewallEnabled ? onBrush : offBrush;
            PrivatePillText.Text = $"Private: {(status.PrivateFirewallEnabled ? "ON" : "OFF")}";

            PublicDot.Fill = status.PublicFirewallEnabled ? onBrush : offBrush;
            PublicPillText.Text = $"Public: {(status.PublicFirewallEnabled ? "ON" : "OFF")}";

            AuditDot.Fill = status.IsAuditPolicyEnabled ? onBrush : warnBrush;
            AuditPillText.Text = $"WFP Auditing: {(status.IsAuditPolicyEnabled ? "Enabled" : "Off")}";

            // Security Posture & Rule Health
            CurrentNetworkText.Text = string.IsNullOrWhiteSpace(currentNetwork) ? "Disconnected" : currentNetwork;

            if (settings.EnableRuleLock)
            {
                RuleLockDot.Fill = lockAlerts.Count > 0 ? warnBrush : onBrush;
                RuleLockStatusText.Text = lockAlerts.Count > 0 ? $"Active ({lockAlerts.Count} alerts)" : "Active";
            }
            else
            {
                RuleLockDot.Fill = offBrush;
                RuleLockStatusText.Text = "Off";
            }

            var enabledBlocklists = settings.Blocklists.Where(b => b.Enabled).ToList();
            if (enabledBlocklists.Count > 0)
            {
                int totalTargets = enabledBlocklists.Sum(b => b.RuleEntryCount);
                BlocklistDot.Fill = onBrush;
                BlocklistStatusText.Text = totalTargets > 0
                    ? $"{enabledBlocklists.Count} active ({totalTargets:N0} targets)"
                    : $"{enabledBlocklists.Count} active";
            }
            else
            {
                BlocklistDot.Fill = offBrush;
                BlocklistStatusText.Text = "None enabled";
            }

            int enabledNetRules = settings.NetworkProfileRules.Count(r => r.Enabled);
            if (settings.AutoSwitchNetworkProfiles && enabledNetRules > 0)
            {
                NetSwitchDot.Fill = onBrush;
                NetSwitchStatusText.Text = $"Active ({enabledNetRules} rules)";
            }
            else
            {
                NetSwitchDot.Fill = offBrush;
                NetSwitchStatusText.Text = enabledNetRules > 0 ? "Paused" : "Off";
            }

            if (tempRules.Count > 0)
            {
                var soonest = tempRules.OrderBy(t => t.ExpiresAtUtc).First();
                TempRulesDot.Fill = new SolidColorBrush(Color.FromArgb(255, 224, 90, 43));
                TempRulesStatusText.Text = $"{tempRules.Count} active (next: {soonest.RemainingDisplay})";
            }
            else
            {
                TempRulesDot.Fill = offBrush;
                TempRulesStatusText.Text = "None active";
            }

            int outCount = currentRules.Count(r => r.Enabled && r.Direction == RuleDirection.Outbound);
            int inCount = currentRules.Count(r => r.Enabled && r.Direction == RuleDirection.Inbound);
            int allowCount = currentRules.Count(r => r.Enabled && r.Action == RuleAction.Allow);
            int blockCount = currentRules.Count(r => r.Enabled && r.Action == RuleAction.Block);
            RuleBreakdownText.Text = $"{outCount:N0} Out / {inCount:N0} In  ({allowCount:N0} Allow, {blockCount:N0} Block)";

            int dupGroups = WindowsFirewallManager.FindDuplicateRules(currentRules).Count;
            if (dupGroups == 0 && status.InvalidRulesCount == 0)
            {
                RuleHealthDot.Fill = onBrush;
                RuleHealthText.Text = "All clean";
            }
            else
            {
                RuleHealthDot.Fill = warnBrush;
                var healthParts = new List<string>(2);
                if (dupGroups > 0) healthParts.Add($"{dupGroups} duplicate groups");
                if (status.InvalidRulesCount > 0) healthParts.Add($"{status.InvalidRulesCount} invalid");
                RuleHealthText.Text = string.Join(" • ", healthParts);
            }

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
                        ShowToast(InfoBarSeverity.Success, "FireBrickService Ready", "Background service is installed, running, and configured for automatic recovery.");
                        await LoadStatusAsync();
                    }
                    else
                    {
                        actionBtn.IsEnabled = true;
                        actionBtn.Content = label;
                        ShowToast(InfoBarSeverity.Warning, "Service Setup Cancelled", "Administrator approval is required once to configure FireBrickService.");
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
            ShowToast(InfoBarSeverity.Success, "Profile Updated", $"Switched Windows Firewall to {mode}.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Failed to switch profile", ex.Message);
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
            ShowToast(InfoBarSeverity.Success, "Notification Mode Updated", $"Switched notifications to {mode}.");
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Failed to update notification mode", ex.Message);
        }
    }

    private async void CleanupInvalidLink_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int removed = await FirewallBackendService.Instance.CleanupInvalidRulesAsync();
            ShowToast(InfoBarSeverity.Success, "Cleanup Complete", $"Removed {removed} invalid/orphaned firewall rules.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Cleanup Failed", ex.Message);
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
            ShowToast(InfoBarSeverity.Error, "Elevation Cancelled", ex.Message);
        }
    }

    private async void QuickBlockLiveApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string appPath || string.IsNullOrWhiteSpace(appPath)) return;
        btn.IsEnabled = false;
        btn.Content = "Blocking...";
        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(appPath, RuleAction.Block, RuleDirection.Outbound);
            btn.Content = "Blocked";
            ShowToast(InfoBarSeverity.Success, "Application Blocked", $"Blocked '{rule.ApplicationDisplay}' outbound.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            btn.IsEnabled = true;
            btn.Content = "Block";
            ShowToast(InfoBarSeverity.Error, "Failed to block app", ex.Message);
        }
    }

    private async void QuickAllowRecent_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not RecentBlockedItemDto item || string.IsNullOrWhiteSpace(item.ApplicationPath)) return;
        btn.IsEnabled = false;
        btn.Content = "Allowing...";
        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(item.ApplicationPath, RuleAction.Allow, item.Direction);
            btn.Content = "Allowed ✓";
            var dirLabel = item.Direction == RuleDirection.Inbound ? "inbound" : "outbound";
            ShowToast(InfoBarSeverity.Success, "Rule Created", $"Allowed '{rule.ApplicationDisplay}' {dirLabel}.");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            btn.IsEnabled = true;
            btn.Content = "Allow";
            ShowToast(InfoBarSeverity.Error, "Failed to allow app", ex.Message);
        }
    }

    private async void QuickTempAllowRecent_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not RecentBlockedItemDto item || string.IsNullOrWhiteSpace(item.ApplicationPath)) return;
        int mins = Math.Clamp(FirewallBackendService.Instance.GetSettings().DefaultTempRuleMinutes, 1, 1440);
        btn.IsEnabled = false;
        btn.Content = "Allowing...";
        try
        {
            var rule = await FirewallBackendService.Instance.CreateQuickRuleAsync(item.ApplicationPath, RuleAction.Allow, item.Direction, temporaryMinutes: mins);
            btn.Content = $"{mins}m ✓";
            var dirLabel = item.Direction == RuleDirection.Inbound ? "inbound" : "outbound";
            ShowToast(InfoBarSeverity.Success, "Temporary Rule Created", $"Allowed '{rule.ApplicationDisplay}' {dirLabel} for {mins} minute(s).");
            await LoadStatusAsync();
        }
        catch (Exception ex)
        {
            btn.IsEnabled = true;
            btn.Content = "Temp";
            ShowToast(InfoBarSeverity.Error, "Failed to create temporary rule", ex.Message);
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

    private async void ShowToast(InfoBarSeverity severity, string title, string message, int lingerSeconds = 5)
    {
        _toastDismissCts?.Cancel();
        _toastDismissCts?.Dispose();
        var cts = new CancellationTokenSource();
        _toastDismissCts = cts;

        ActionToast.Severity = severity;
        ActionToast.Title = title;
        ActionToast.Message = message;
        ActionToast.IsOpen = true;

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(lingerSeconds), cts.Token);
            if (!cts.IsCancellationRequested)
            {
                ActionToast.IsOpen = false;
            }
        }
        catch (TaskCanceledException)
        {
            // Replaced by a newer toast or manually dismissed
        }
    }

    private void ActionToast_Closed(InfoBar sender, InfoBarClosedEventArgs args)
    {
        _toastDismissCts?.Cancel();
    }
}
