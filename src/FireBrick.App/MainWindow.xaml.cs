using System.Reflection;
using System.Runtime.InteropServices;
using FireBrick.App.Pages;
using FireBrick.App.Services;
using FireBrick.App.Windows;
using FireBrick.Core.Models;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics;
using WinRT.Interop;

namespace FireBrick.App;

public sealed partial class MainWindow : Window
{
    private readonly TrayIconService _trayIcon;
    private readonly IntPtr _hwnd;
    private ConnectionAlertWindow? _alertWindow;
    private TrayFlyoutWindow? _trayFlyout;
    private bool _isExiting;
    private bool _shownMinimizeHint;
    private FirewallProfileMode _lastProfile = FirewallProfileMode.LowFiltering;
    private NotificationMode _lastNotif = NotificationMode.DisplayNotifications;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private const int SW_RESTORE = 9;

    public MainWindow()
    {
        InitializeComponent();

        _hwnd = WindowNative.GetWindowHandle(this);

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        AppWindow.Resize(new SizeInt32(1240, 820));
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "FireBrick.ico");
        if (File.Exists(iconPath)) AppWindow.SetIcon(iconPath);
        var logoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "FireBrick.png");
        if (File.Exists(logoPath)) TitleLogoImage.Source = new BitmapImage(new Uri(logoPath));
        AppWindow.Closing += OnAppWindowClosing;

        ApplyThemeFromSettings();
        var ver = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
        VersionBadgeText.Text = $"v{ver}";
        NavView.IsPaneOpen = FirewallBackendService.Instance.GetSettings().IsSidebarOpen;

        // Initialize System Tray Icon & Custom WinUI 3 Flyout Menu
        _trayIcon = new TrayIconService(_hwnd);
        _trayIcon.OpenRequested += () => DispatcherQueue.TryEnqueue(RestoreFromTray);
        _trayIcon.ContextMenuRequested += (x, y) => DispatcherQueue.TryEnqueue(() => ShowTrayFlyout(x, y));

        var svc = FirewallBackendService.Instance;
        svc.BlockedConnectionPromptRequested += OnBlockedConnectionPromptRequested;
        svc.ProfileModeChanged += OnProfileModeChanged;
        svc.NotificationModeChanged += OnNotificationModeChanged;

        NavView.SelectedItem = NavView.MenuItems[0];

        _ = SyncTrayStateAsync();
    }

    public void RestoreFromTray()
    {
        AppWindow.Show();
        ShowWindow(_hwnd, SW_RESTORE);
        SetForegroundWindow(_hwnd);
    }

    public void HideToTray(string? notificationTitle = null, string? notificationMessage = null)
    {
        AppWindow.Hide();
        if (!string.IsNullOrWhiteSpace(notificationTitle) && !string.IsNullOrWhiteSpace(notificationMessage))
        {
            _trayIcon.ShowBalloonTip(notificationTitle, notificationMessage);
        }
    }

    private void ShowTrayFlyout(int x, int y)
    {
        if (_trayFlyout == null)
        {
            _trayFlyout = new TrayFlyoutWindow();
            _trayFlyout.OpenRequested += RestoreFromTray;
            _trayFlyout.NavigateRequested += tag =>
            {
                RestoreFromTray();
                NavigateToTag(tag);
            };
            _trayFlyout.ProfileSwitchRequested += mode => _ = SwitchProfileFromTrayAsync(mode);
            _trayFlyout.NotificationSwitchRequested += mode => _ = SwitchNotificationFromTrayAsync(mode);
            _trayFlyout.ExitRequested += ExitApplication;
        }

        _trayFlyout.ShowAt(x, y, _lastProfile, _lastNotif);
    }

    public void ExitApplication()
    {
        _isExiting = true;
        _trayFlyout?.ForceClose();
        _alertWindow?.ForceClose();
        _trayIcon.Dispose();
        FirewallBackendService.Instance.Dispose();
        (Application.Current as App)?.ReleaseSingleInstanceLock();
        Close();
        Application.Current.Exit();
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_isExiting && FirewallBackendService.Instance.GetSettings().CloseToTray)
        {
            args.Cancel = true;
            if (!_shownMinimizeHint)
            {
                _shownMinimizeHint = true;
                HideToTray("FireBrick is still running", "Minimized to the system tray. Right-click the shield icon to switch profiles or exit.");
            }
            else
            {
                HideToTray();
            }
            return;
        }

        _trayFlyout?.ForceClose();
        _alertWindow?.ForceClose();
        _trayIcon.Dispose();
    }

    private async Task SyncTrayStateAsync()
    {
        try
        {
            var status = await FirewallBackendService.Instance.GetStatusAsync();
            _lastProfile = status.ProfileMode;
            _lastNotif = status.NotificationMode;
            DispatcherQueue.TryEnqueue(() => _trayIcon.UpdateState(_lastProfile, _lastNotif));
        }
        catch { }
    }

    private void OnProfileModeChanged(object? sender, FirewallProfileMode mode)
    {
        _lastProfile = mode;
        DispatcherQueue.TryEnqueue(() => _trayIcon.UpdateState(_lastProfile, _lastNotif));
    }

    private void OnNotificationModeChanged(object? sender, NotificationMode mode)
    {
        _lastNotif = mode;
        DispatcherQueue.TryEnqueue(() => _trayIcon.UpdateState(_lastProfile, _lastNotif));
    }

    private async Task SwitchProfileFromTrayAsync(FirewallProfileMode mode)
    {
        try
        {
            await FirewallBackendService.Instance.SetProfileModeAsync(mode);
        }
        catch
        {
            // If running standard user without service, bring window forward so user sees elevation option
            RestoreFromTray();
        }
    }

    private async Task SwitchNotificationFromTrayAsync(NotificationMode mode)
    {
        try
        {
            await FirewallBackendService.Instance.SetNotificationModeAsync(mode);
        }
        catch { }
    }

    public void ApplyThemeFromSettings()
    {
        var theme = FirewallBackendService.Instance.GetSettings().Theme;
        RootGrid.RequestedTheme = theme switch
        {
            "Dark" => ElementTheme.Dark,
            "Light" => ElementTheme.Light,
            _ => ElementTheme.Default
        };
    }

    public void NavigateToTag(string tag)
    {
        foreach (var item in NavView.MenuItems.OfType<NavigationViewItem>())
        {
            if ((string?)item.Tag == tag)
            {
                NavView.SelectedItem = item;
                return;
            }
        }
    }

    private void NavView_PaneStateChanged(NavigationView sender, object args)
    {
        var cfg = FirewallBackendService.Instance.GetSettings();
        if (cfg.IsSidebarOpen != sender.IsPaneOpen)
        {
            cfg.IsSidebarOpen = sender.IsPaneOpen;
            FirewallBackendService.Instance.SaveSettings(cfg);
        }
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            ContentFrame.Navigate(typeof(SettingsPage));
            return;
        }

        var tag = (args.SelectedItem as NavigationViewItem)?.Tag?.ToString();
        switch (tag)
        {
            case "dashboard":
                ContentFrame.Navigate(typeof(DashboardPage));
                break;
            case "apps":
                ContentFrame.Navigate(typeof(AppsPage));
                break;
            case "rules":
                ContentFrame.Navigate(typeof(RulesPage));
                break;
            case "connections":
                ContentFrame.Navigate(typeof(ConnectionsLogPage));
                break;
            case "presets":
                ContentFrame.Navigate(typeof(PresetsPage));
                break;
            case "protection":
                ContentFrame.Navigate(typeof(ProtectionPage));
                break;
            case "hosts":
                ContentFrame.Navigate(typeof(HostsPage));
                break;
            case "bandwidth":
                ContentFrame.Navigate(typeof(BandwidthPage));
                break;
            case "donate":
                ContentFrame.Navigate(typeof(DonatePage));
                break;
        }
    }

    private void OnBlockedConnectionPromptRequested(object? sender, ConnectionEventDto evt)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                _alertWindow ??= new ConnectionAlertWindow();
                _alertWindow.EnqueueAlert(evt);
            }
            catch { }
        });
    }
}
