using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class ProtectionPage : Page
{
    private readonly ObservableCollection<AutoRuleDto> _autoRules = new();
    private readonly ObservableCollection<RuleLockAlertDto> _lockAlerts = new();
    private readonly ObservableCollection<NetworkProfileRuleDto> _networkRules = new();
    private readonly ObservableCollection<BlocklistSubscriptionDto> _blocklists = new();
    private bool _loading = true;
    private string _currentNetwork = string.Empty;

    public ProtectionPage()
    {
        InitializeComponent();
        AutoRulesList.ItemsSource = _autoRules;
        RuleLockAlertsList.ItemsSource = _lockAlerts;
        NetworkRulesList.ItemsSource = _networkRules;
        BlocklistsList.ItemsSource = _blocklists;
        Loaded += async (_, _) =>
        {
            FirewallBackendService.Instance.AutoRulesChanged += OnAutoRulesChanged;
            await LoadAsync();
        };
        Unloaded += (_, _) =>
        {
            FirewallBackendService.Instance.AutoRulesChanged -= OnAutoRulesChanged;
        };
    }

    private void OnAutoRulesChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(async () => await ReloadAutoRulesAsync());
    }

    private async Task ReloadAutoRulesAsync()
    {
        _loading = true;
        try
        {
            var autoRules = await FirewallBackendService.Instance.GetAutoRulesAsync();
            _autoRules.Clear();
            foreach (var r in autoRules) _autoRules.Add(r);
            EmptyAutoRulesText.Visibility = _autoRules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch { }
        finally
        {
            _loading = false;
        }
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

            var autoRules = await FirewallBackendService.Instance.GetAutoRulesAsync();
            _autoRules.Clear();
            foreach (var r in autoRules) _autoRules.Add(r);
            EmptyAutoRulesText.Visibility = _autoRules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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

    private async void AddAutoRule_Click(object sender, RoutedEventArgs e)
    {
        await ShowAutoRuleDialogAsync(null);
    }

    private async void EditAutoRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var existing = _autoRules.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
        if (existing == null) return;
        await ShowAutoRuleDialogAsync(existing);
    }

    private async void AutoRuleEnabled_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        if (sender is not ToggleSwitch sw || sw.Tag is not string id) return;

        var list = await FirewallBackendService.Instance.GetAutoRulesAsync();
        var item = list.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
        if (item == null || item.Enabled == sw.IsOn) return;

        item.Enabled = sw.IsOn;
        await FirewallBackendService.Instance.SaveAutoRulesAsync(list);
    }

    private async void MoveAutoRuleUp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        await MoveAutoRuleAsync(id, -1);
    }

    private async void MoveAutoRuleDown_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        await MoveAutoRuleAsync(id, +1);
    }

    private async Task MoveAutoRuleAsync(string id, int delta)
    {
        var list = await FirewallBackendService.Instance.GetAutoRulesAsync();
        int idx = list.FindIndex(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
        int target = idx + delta;
        if (idx < 0 || target < 0 || target >= list.Count) return;

        (list[idx], list[target]) = (list[target], list[idx]);
        await FirewallBackendService.Instance.SaveAutoRulesAsync(list);
        await ReloadAutoRulesAsync();
    }

    private async void DeleteAutoRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var list = await FirewallBackendService.Instance.GetAutoRulesAsync();
        if (list.RemoveAll(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase)) > 0)
        {
            await FirewallBackendService.Instance.SaveAutoRulesAsync(list);
            await ReloadAutoRulesAsync();
            ShowInfo(InfoBarSeverity.Informational, "Auto-Rule Deleted", "Removed the auto-rule from FireBrick.");
        }
    }

    private async Task ShowAutoRuleDialogAsync(AutoRuleDto? existing)
    {
        bool isEdit = existing != null;

        var nameBox = new TextBox
        {
            Header = "Rule Name (optional)",
            Text = existing?.Name ?? string.Empty,
            PlaceholderText = "e.g. Allow Microsoft Apps or Block Copilot"
        };

        var matchFieldCombo = new ComboBox
        {
            Header = "Match Criterion",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        matchFieldCombo.Items.Add("App Name / Path");
        matchFieldCombo.Items.Add("Publisher (Authenticode)");
        matchFieldCombo.Items.Add("IP Address / CIDR");
        matchFieldCombo.Items.Add("Domain / Hostname / Org");
        matchFieldCombo.SelectedIndex = (int)(existing?.MatchField ?? AutoRuleMatchField.Publisher);

        var patternBox = new TextBox
        {
            Header = "Pattern (supports * and ? wildcards; comma-separate multiple)",
            Text = existing?.Pattern ?? string.Empty
        };

        var trustedOnlyCheck = new CheckBox
        {
            Content = "Require valid Trusted Authenticode signature (recommended)",
            IsChecked = existing?.RequireTrustedSignature ?? true
        };

        var actionCombo = new ComboBox
        {
            Header = "Action",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        actionCombo.Items.Add("Allow");
        actionCombo.Items.Add("Block");
        actionCombo.SelectedIndex = existing?.Action == RuleAction.Block ? 1 : 0;

        var triggerCombo = new ComboBox
        {
            Header = "Execution Mode",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        triggerCombo.Items.Add("Instantaneous (silent, no notification shown)");
        triggerCombo.Items.Add("Countdown (show alert with cancel/override)");
        triggerCombo.SelectedIndex = existing?.TriggerMode == AutoRuleTriggerMode.Countdown ? 1 : 0;

        var countdownBox = new NumberBox
        {
            Header = "Countdown Duration (seconds)",
            Minimum = 2,
            Maximum = 60,
            Value = existing?.CountdownSeconds ?? 5,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };

        var scopeCombo = new ComboBox
        {
            Header = "Generated Firewall Rule Scope",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        scopeCombo.Items.Add("Any IP & port");
        scopeCombo.Items.Add("Port only");
        scopeCombo.Items.Add("IP & port");
        scopeCombo.SelectedIndex = (int)(existing?.RuleScope ?? AutoRuleScope.Any);

        var durationCombo = new ComboBox
        {
            Header = "Generated Firewall Rule Duration",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        durationCombo.Items.Add("Permanent");
        durationCombo.Items.Add("Temporary — 5 minutes");
        durationCombo.Items.Add("Temporary — 15 minutes");
        durationCombo.Items.Add("Temporary — 1 hour");
        durationCombo.Items.Add("Temporary — 4 hours");
        durationCombo.SelectedIndex = existing?.TemporaryMinutes switch
        {
            5 => 1,
            15 => 2,
            60 => 3,
            240 => 4,
            _ => 0
        };

        var hintText = new TextBlock
        {
            FontSize = 11,
            Opacity = 0.75,
            TextWrapping = TextWrapping.Wrap
        };

        void RefreshDynamicFields()
        {
            var field = (AutoRuleMatchField)Math.Clamp(matchFieldCombo.SelectedIndex, 0, 3);
            trustedOnlyCheck.Visibility = field == AutoRuleMatchField.Publisher ? Visibility.Visible : Visibility.Collapsed;
            countdownBox.Visibility = triggerCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;

            patternBox.PlaceholderText = field switch
            {
                AutoRuleMatchField.AppNameOrPath => @"e.g. *copilot*.exe or C:\Program Files\MyApp\*.exe",
                AutoRuleMatchField.Publisher => "e.g. Microsoft Corporation",
                AutoRuleMatchField.IpOrCidr => "e.g. 40.79.0.0/16 or 40.79.167.9:443",
                AutoRuleMatchField.DomainOrHost => "e.g. *.azure.com, telemetry.microsoft.com, or Microsoft Azure",
                _ => string.Empty
            };

            hintText.Text = field switch
            {
                AutoRuleMatchField.AppNameOrPath => "Tip: For Auto-Allow rules, prefer a full folder path wildcard (e.g. C:\\Program Files\\Vendor\\*.exe) over a bare filename.",
                AutoRuleMatchField.Publisher => "Matches the verified digital signature publisher. Keeping 'Require valid Trusted Authenticode signature' enabled prevents spoofing.",
                AutoRuleMatchField.IpOrCidr => "Supports exact IPv4/IPv6, CIDR ranges (e.g. 10.0.0.0/8), wildcards (40.79.*), and optional :port suffix.",
                AutoRuleMatchField.DomainOrHost => "Matches against Reverse DNS (PTR) hostnames and GeoIP organization names. Full URLs are automatically trimmed to their hostname.",
                _ => string.Empty
            };
        }

        matchFieldCombo.SelectionChanged += (_, _) => RefreshDynamicFields();
        triggerCombo.SelectionChanged += (_, _) => RefreshDynamicFields();
        RefreshDynamicFields();

        var panel = new StackPanel { Spacing = 10, MinWidth = 420 };
        panel.Children.Add(nameBox);
        panel.Children.Add(matchFieldCombo);
        panel.Children.Add(patternBox);
        panel.Children.Add(trustedOnlyCheck);
        panel.Children.Add(actionCombo);
        panel.Children.Add(triggerCombo);
        panel.Children.Add(countdownBox);
        panel.Children.Add(scopeCombo);
        panel.Children.Add(durationCombo);
        panel.Children.Add(hintText);

        var scroll = new ScrollViewer
        {
            Content = panel,
            MaxHeight = 520,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = isEdit ? "Edit Auto-Rule" : "Add Auto-Rule",
            Content = scroll,
            PrimaryButtonText = isEdit ? "Save Changes" : "Create Auto-Rule",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrWhiteSpace(patternBox.Text))
        {
            ShowInfo(InfoBarSeverity.Warning, "Pattern Required", "Please enter a match pattern for the auto-rule.");
            return;
        }

        int? tempMinutes = durationCombo.SelectedIndex switch
        {
            1 => 5,
            2 => 15,
            3 => 60,
            4 => 240,
            _ => null
        };

        var rule = new AutoRuleDto
        {
            Id = existing?.Id ?? Guid.NewGuid().ToString("N"),
            Name = nameBox.Text.Trim(),
            Enabled = existing?.Enabled ?? true,
            MatchField = (AutoRuleMatchField)Math.Clamp(matchFieldCombo.SelectedIndex, 0, 3),
            Pattern = patternBox.Text.Trim(),
            RequireTrustedSignature = trustedOnlyCheck.IsChecked ?? true,
            Action = actionCombo.SelectedIndex == 1 ? RuleAction.Block : RuleAction.Allow,
            TriggerMode = triggerCombo.SelectedIndex == 1 ? AutoRuleTriggerMode.Countdown : AutoRuleTriggerMode.Instant,
            CountdownSeconds = double.IsNaN(countdownBox.Value) ? 5 : Math.Clamp((int)Math.Round(countdownBox.Value), 2, 60),
            RuleScope = (AutoRuleScope)Math.Clamp(scopeCombo.SelectedIndex, 0, 2),
            TemporaryMinutes = tempMinutes,
            HitCount = existing?.HitCount ?? 0,
            LastMatchedUtc = existing?.LastMatchedUtc
        };

        await FirewallBackendService.Instance.UpsertAutoRuleAsync(rule);
        await ReloadAutoRulesAsync();
        ShowInfo(InfoBarSeverity.Success,
            isEdit ? "Auto-Rule Updated" : "Auto-Rule Created",
            $"'{(string.IsNullOrWhiteSpace(rule.Name) ? rule.Pattern : rule.Name)}' is now active.");
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        ProtectionInfoBar.Severity = severity;
        ProtectionInfoBar.Title = title;
        ProtectionInfoBar.Message = message;
        ProtectionInfoBar.IsOpen = true;
    }
}
