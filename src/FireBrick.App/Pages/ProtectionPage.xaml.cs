using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class ProtectionPage : Page
{
    private readonly ObservableCollection<RuleLockAlertDto> _lockAlerts = new();
    private readonly ObservableCollection<NetworkProfileRuleDto> _networkRules = new();
    private readonly ObservableCollection<BlocklistSubscriptionDto> _blocklists = new();
    private bool _loading = true;
    private string _currentNetwork = string.Empty;

    public ProtectionPage()
    {
        InitializeComponent();
        RuleLockAlertsList.ItemsSource = _lockAlerts;
        NetworkRulesList.ItemsSource = _networkRules;
        BlocklistsList.ItemsSource = _blocklists;
        Loaded += async (_, _) => await LoadAsync();
    }

    private async Task LoadAsync()
    {
        _loading = true;
        try
        {
            var cfg = FirewallBackendService.Instance.GetSettings();
            if (cfg.Blocklists.Count == 0)
            {
                cfg.Blocklists = BlocklistManager.GetDefaultSubscriptions();
                FirewallBackendService.Instance.SaveSettings(cfg);
            }

            RuleLockToggle.IsOn = cfg.EnableRuleLock;
            AutoSwitchToggle.IsOn = cfg.AutoSwitchNetworkProfiles;

            _networkRules.Clear();
            foreach (var r in cfg.NetworkProfileRules) _networkRules.Add(r);
            EmptyNetworkRulesText.Visibility = _networkRules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            _blocklists.Clear();
            foreach (var b in cfg.Blocklists) _blocklists.Add(b);

            _currentNetwork = await FirewallBackendService.Instance.GetCurrentNetworkNameAsync();
            CurrentNetworkText.Text = $"Current Network / SSID: {_currentNetwork}";

            var alerts = await FirewallBackendService.Instance.GetRuleLockAlertsAsync();
            _lockAlerts.Clear();
            foreach (var a in alerts) _lockAlerts.Add(a);
            RuleLockEmptyText.Visibility = _lockAlerts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to load protection settings", ex.Message);
        }
        finally
        {
            _loading = false;
        }
    }

    private async void RuleLockToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try
        {
            await FirewallBackendService.Instance.SetRuleLockAsync(RuleLockToggle.IsOn);
            ShowInfo(InfoBarSeverity.Success,
                RuleLockToggle.IsOn ? "Rule Lock Armed" : "Rule Lock Disarmed",
                RuleLockToggle.IsOn
                    ? "FireBrick will monitor and revert unauthorized external firewall rule injections."
                    : "External firewall rule changes will no longer be reverted.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Rule Lock Error", ex.Message);
        }
    }

    private void AutoSwitchToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.AutoSwitchNetworkProfiles = AutoSwitchToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private async void AddNetworkRule_Click(object sender, RoutedEventArgs e)
    {
        var ssidBox = new TextBox { Header = "Wi-Fi SSID or Network Name", Text = _currentNetwork, PlaceholderText = "e.g. HomeWiFi or Starbucks" };
        var modeCombo = new ComboBox { Header = "Target Filtering Profile", HorizontalAlignment = HorizontalAlignment.Stretch };
        modeCombo.Items.Add("High Filtering (Lockdown)");
        modeCombo.Items.Add("Medium Filtering (Recommended)");
        modeCombo.Items.Add("Low Filtering (Default)");
        modeCombo.SelectedIndex = 1;

        var panel = new StackPanel { Spacing = 10, MinWidth = 360 };
        panel.Children.Add(ssidBox);
        panel.Children.Add(modeCombo);

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Add Network Profile Rule",
            Content = panel,
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrWhiteSpace(ssidBox.Text)) return;

        var mode = modeCombo.SelectedIndex switch
        {
            0 => FirewallProfileMode.HighFiltering,
            2 => FirewallProfileMode.LowFiltering,
            _ => FirewallProfileMode.MediumFiltering
        };

        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.NetworkProfileRules.Add(new NetworkProfileRuleDto
        {
            NetworkName = ssidBox.Text.Trim(),
            TargetProfileMode = mode,
            Enabled = true
        });
        FirewallBackendService.Instance.SaveSettings(cfg);
        await LoadAsync();
    }

    private async void DeleteNetworkRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.NetworkProfileRules.RemoveAll(r => r.Id == id);
        FirewallBackendService.Instance.SaveSettings(cfg);
        await LoadAsync();
    }

    private async void AddBlocklist_Click(object sender, RoutedEventArgs e)
    {
        var nameBox = new TextBox { Header = "Blocklist Name", PlaceholderText = "e.g. Custom Trackers" };
        var domainsBox = new TextBox { Header = "Domains to Block (comma or newline separated)", AcceptsReturn = true, Height = 80, PlaceholderText = "tracker.example.com" };
        var urlBox = new TextBox { Header = "Or Remote IP/CIDR List URL (optional)", PlaceholderText = "https://..." };

        var panel = new StackPanel { Spacing = 10, MinWidth = 400 };
        panel.Children.Add(nameBox);
        panel.Children.Add(domainsBox);
        panel.Children.Add(urlBox);

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Add Custom Blocklist",
            Content = panel,
            PrimaryButtonText = "Add & Sync",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrWhiteSpace(nameBox.Text)) return;

        var domains = domainsBox.Text
            .Split([',', '\r', '\n', ' '], StringSplitOptions.RemoveEmptyEntries)
            .Select(d => d.Trim())
            .Where(d => d.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sub = new BlocklistSubscriptionDto
        {
            Name = nameBox.Text.Trim(),
            Description = domains.Count > 0 ? $"Custom domain blocklist ({domains.Count} domains)" : $"Remote IP/CIDR blocklist ({urlBox.Text.Trim()})",
            Domains = domains,
            SourceUrl = urlBox.Text.Trim(),
            Enabled = true
        };

        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.Blocklists.Add(sub);
        FirewallBackendService.Instance.SaveSettings(cfg);

        await SyncSubAsync(sub);
    }

    private async void SyncBlocklist_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not BlocklistSubscriptionDto sub) return;
        await SyncSubAsync(sub);
    }

    private async Task SyncSubAsync(BlocklistSubscriptionDto sub)
    {
        try
        {
            ShowInfo(InfoBarSeverity.Informational, "Syncing Blocklist...", $"Resolving targets for '{sub.Name}'...");
            int count = await FirewallBackendService.Instance.SyncBlocklistAsync(sub);

            var cfg = FirewallBackendService.Instance.GetSettings();
            var stored = cfg.Blocklists.FirstOrDefault(b => b.Id == sub.Id);
            if (stored != null)
            {
                stored.RuleEntryCount = count;
                stored.LastSyncedUtc = DateTimeOffset.UtcNow;
                FirewallBackendService.Instance.SaveSettings(cfg);
            }

            ShowInfo(InfoBarSeverity.Success, "Blocklist Synced", $"Blocked {count} IP/CIDR target(s) for '{sub.Name}'.");
            await LoadAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Blocklist Sync Failed", ex.Message);
        }
    }

    private async void RemoveBlocklist_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not BlocklistSubscriptionDto sub) return;
        try
        {
            await FirewallBackendService.Instance.RemoveBlocklistAsync(sub.Name);
            var cfg = FirewallBackendService.Instance.GetSettings();
            var stored = cfg.Blocklists.FirstOrDefault(b => b.Id == sub.Id);
            if (stored != null)
            {
                stored.RuleEntryCount = 0;
                stored.LastSyncedUtc = null;
                FirewallBackendService.Instance.SaveSettings(cfg);
            }
            ShowInfo(InfoBarSeverity.Success, "Blocklist Rules Removed", $"Removed managed firewall rules for '{sub.Name}'.");
            await LoadAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Remove Failed", ex.Message);
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        ProtectionInfoBar.Severity = severity;
        ProtectionInfoBar.Title = title;
        ProtectionInfoBar.Message = message;
        ProtectionInfoBar.IsOpen = true;
    }
}
