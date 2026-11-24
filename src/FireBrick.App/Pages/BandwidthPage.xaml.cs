using FireBrick.App.Services;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace FireBrick.App.Pages;

public sealed partial class BandwidthPage : Page
{
    private bool _suppressEvents;
    private List<BandwidthRuleDto> _rules = new();
    private BandwidthLimiterStatusDto _status = new();
    private DispatcherTimer? _usageTimer;

    public BandwidthPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = LoadAsync();

        _usageTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        _usageTimer.Tick += (_, _) => _ = RefreshUsageAsync();
        _usageTimer.Start();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _usageTimer?.Stop();
        _usageTimer = null;
        base.OnNavigatedFrom(e);
    }

    private async Task LoadAsync()
    {
        try
        {
            _status = await FirewallBackendService.Instance.GetBandwidthStatusAsync();
            _rules = await FirewallBackendService.Instance.GetBandwidthRulesAsync();
            BindUi();
            await RefreshUsageAsync();
        }
        catch (Exception ex)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Error;
            StatusInfoBar.Message = ex.Message;
        }
    }

    private void BindUi()
    {
        _suppressEvents = true;
        try
        {
            ModeDisabledRadio.IsChecked = _status.Mode == BandwidthLimiterMode.Disabled;
            ModeQosRadio.IsChecked = _status.Mode == BandwidthLimiterMode.WindowsQos;
            ModeWinDivertRadio.IsChecked = _status.Mode == BandwidthLimiterMode.WinDivert;
            AutoUnloadToggle.IsOn = _status.AutoUnloadWinDivertWhenIdle;
        }
        finally
        {
            _suppressEvents = false;
        }

        if (!string.IsNullOrWhiteSpace(_status.LastError))
        {
            StatusInfoBar.Severity = InfoBarSeverity.Warning;
            StatusInfoBar.Message = _status.LastError;
        }
        else if (_status.IsActive)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Success;
            StatusInfoBar.Message = _status.StatusMessage;
        }
        else
        {
            StatusInfoBar.Severity = InfoBarSeverity.Informational;
            StatusInfoBar.Message = _status.StatusMessage;
        }

        if (_status.IsWinDivertInstalled)
        {
            string driverState = _status.IsWinDivertDriverLoaded ? "Driver loaded" : "Driver unloaded";
            WinDivertStatusText.Text = $"Installed at {_status.WinDivertInstallPath}  •  {driverState}";
            InstallWinDivertBtn.Content = "Installed ✓";
            InstallWinDivertBtn.IsEnabled = false;
        }
        else
        {
            WinDivertStatusText.Text = "Not installed. Click 'Install WinDivert Add-on' to download the signed WinDivert 2.2.2 (x64) binaries.";
            InstallWinDivertBtn.Content = "Install WinDivert Add-on";
            InstallWinDivertBtn.IsEnabled = true;
        }

        RulesList.ItemsSource = null;
        RulesList.ItemsSource = _rules;
        EmptyRulesText.Visibility = _rules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        LiveUsageCard.Visibility = _status.Mode == BandwidthLimiterMode.WinDivert ? Visibility.Visible : Visibility.Collapsed;
    }

    private async Task RefreshUsageAsync()
    {
        if (_status.Mode != BandwidthLimiterMode.WinDivert) return;
        try
        {
            var usage = await FirewallBackendService.Instance.GetBandwidthUsageAsync();
            UsageList.ItemsSource = usage;
            EmptyUsageText.Visibility = usage.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch { }
    }

    private async void ModeRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents) return;
        if (sender is not RadioButton rb || rb.Tag is not string tag) return;
        if (!Enum.TryParse<BandwidthLimiterMode>(tag, out var mode)) return;

        try
        {
            _status = await FirewallBackendService.Instance.SetBandwidthModeAsync(mode, AutoUnloadToggle.IsOn);
            BindUi();
        }
        catch (Exception ex)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Error;
            StatusInfoBar.Message = ex.Message;
        }
    }

    private async void AutoUnloadToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents) return;
        try
        {
            _status = await FirewallBackendService.Instance.SetBandwidthModeAsync(_status.Mode, AutoUnloadToggle.IsOn);
            BindUi();
        }
        catch { }
    }

    private async void InstallWinDivert_Click(object sender, RoutedEventArgs e)
    {
        InstallWinDivertBtn.IsEnabled = false;
        InstallProgressRing.IsActive = true;
        InstallProgressRing.Visibility = Visibility.Visible;
        WinDivertStatusText.Text = "Downloading signed WinDivert 2.2.2 (x64) add-on...";

        try
        {
            _status = await FirewallBackendService.Instance.InstallWinDivertAddonAsync();
            BindUi();
        }
        catch (Exception ex)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Error;
            StatusInfoBar.Message = ex.Message;
        }
        finally
        {
            InstallProgressRing.IsActive = false;
            InstallProgressRing.Visibility = Visibility.Collapsed;
        }
    }

    private async void RuleEnabled_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents || sender is not ToggleSwitch ts || ts.Tag is not string id) return;
        var rule = _rules.FirstOrDefault(r => r.Id == id);
        if (rule == null) return;

        rule.Enabled = ts.IsOn;
        await FirewallBackendService.Instance.SaveBandwidthRuleAsync(rule);
        await LoadAsync();
    }

    private async void AddRule_Click(object sender, RoutedEventArgs e)
    {
        await ShowRuleDialogAsync(null);
    }

    private async void EditRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var rule = _rules.FirstOrDefault(r => r.Id == id);
        if (rule != null)
            await ShowRuleDialogAsync(rule);
    }

    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        await FirewallBackendService.Instance.DeleteBandwidthRuleAsync(id);
        await LoadAsync();
    }

    private async Task ShowRuleDialogAsync(BandwidthRuleDto? existing)
    {
        var appPathBox = new TextBox
        {
            Header = "Application Executable Path",
            PlaceholderText = @"C:\Program Files\...\app.exe",
            Text = existing?.ApplicationPath ?? string.Empty
        };

        var browseBtn = new Button { Content = "Browse...", VerticalAlignment = VerticalAlignment.Bottom };
        browseBtn.Click += async (_, _) =>
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".exe");
            var hwnd = WindowNative.GetWindowHandle(App.MainWindowInstance);
            InitializeWithWindow.Initialize(picker, hwnd);
            var file = await picker.PickSingleFileAsync();
            if (file != null)
                appPathBox.Text = file.Path;
        };

        var pathRow = new Grid { ColumnSpacing = 8 };
        pathRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        pathRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(appPathBox, 0);
        Grid.SetColumn(browseBtn, 1);
        pathRow.Children.Add(appPathBox);
        pathRow.Children.Add(browseBtn);

        var activeAppsCombo = new ComboBox
        {
            Header = "Or pick from active connections",
            HorizontalAlignment = HorizontalAlignment.Stretch,
            PlaceholderText = "Select running app..."
        };

        try
        {
            var conns = await FirewallBackendService.Instance.GetActiveConnectionsAsync();
            var apps = conns
                .Where(c => !string.IsNullOrWhiteSpace(c.ProcessPath) && c.ProcessPath.Contains('\\'))
                .Select(c => c.ProcessPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(p => Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)
                .ToList();
            foreach (var p in apps)
                activeAppsCombo.Items.Add(p);
        }
        catch { }

        activeAppsCombo.SelectionChanged += (_, _) =>
        {
            if (activeAppsCombo.SelectedItem is string p)
                appPathBox.Text = p;
        };

        var downBox = new NumberBox
        {
            Header = "Download Limit (KB/s, 0 = Unlimited) — WinDivert only",
            Value = existing?.DownloadLimitKBps ?? 0,
            Minimum = 0,
            Maximum = 1_000_000,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline
        };

        var upBox = new NumberBox
        {
            Header = "Upload Limit (KB/s, 0 = Unlimited)",
            Value = existing?.UploadLimitKBps ?? 512,
            Minimum = 0,
            Maximum = 1_000_000,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline
        };

        var tempCombo = new ComboBox
        {
            Header = "Duration",
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        tempCombo.Items.Add("Permanent");
        tempCombo.Items.Add("15 minutes");
        tempCombo.Items.Add("60 minutes");
        tempCombo.SelectedIndex = 0;

        var panel = new StackPanel { Spacing = 12, MinWidth = 440 };
        panel.Children.Add(pathRow);
        if (activeAppsCombo.Items.Count > 0)
            panel.Children.Add(activeAppsCombo);
        panel.Children.Add(downBox);
        panel.Children.Add(upBox);
        if (existing == null)
            panel.Children.Add(tempCombo);

        var dialog = new ContentDialog
        {
            Title = existing == null ? "Add Bandwidth Limit" : "Edit Bandwidth Limit",
            Content = panel,
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary) return;

        var path = appPathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path)) return;

        int? tempMins = existing == null
            ? (tempCombo.SelectedIndex == 1 ? 15 : (tempCombo.SelectedIndex == 2 ? 60 : null))
            : existing.TemporaryMinutes;

        var dto = new BandwidthRuleDto
        {
            Id = existing?.Id ?? Guid.NewGuid().ToString("N"),
            ApplicationPath = path,
            ApplicationName = Path.GetFileName(path),
            Enabled = existing?.Enabled ?? true,
            DownloadLimitKBps = double.IsNaN(downBox.Value) ? 0 : (int)Math.Max(0, downBox.Value),
            UploadLimitKBps = double.IsNaN(upBox.Value) ? 0 : (int)Math.Max(0, upBox.Value),
            TemporaryMinutes = tempMins,
            ExpiresAtUtc = existing?.ExpiresAtUtc
        };

        await FirewallBackendService.Instance.SaveBandwidthRuleAsync(dto);
        await LoadAsync();
    }
}
