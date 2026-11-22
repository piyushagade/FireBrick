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
using Windows.Graphics;
using WinRT.Interop;

namespace FireBrick.App;

public sealed partial class MainWindow : Window
{
    private readonly TrayIconService _trayIcon;
    private readonly IntPtr _hwnd;
    private ConnectionAlertWindow? _alertWindow;
    private bool _isExiting;
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
        AppWindow.Closing += OnAppWindowClosing;

        ApplyThemeFromSettings();
        UpdateStatusPill();
        var ver = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
        VersionBadgeText.Text = $"v{ver}";
        NavView.IsPaneOpen = FirewallBackendService.Instance.GetSettings().IsSidebarOpen;

        // Initialize System Tray Icon & Flyout Menu
        _trayIcon = new TrayIconService(_hwnd);
        _trayIcon.OpenRequested += () => DispatcherQueue.TryEnqueue(RestoreFromTray);
        _trayIcon.NavigateRequested += tag => DispatcherQueue.TryEnqueue(() =>
        {
            RestoreFromTray();
            NavigateToTag(tag);
        });
        _trayIcon.ProfileSwitchRequested += mode => DispatcherQueue.TryEnqueue(() => _ = SwitchProfileFromTrayAsync(mode));
        _trayIcon.NotificationSwitchRequested += mode => DispatcherQueue.TryEnqueue(() => _ = SwitchNotificationFromTrayAsync(mode));
        _trayIcon.ExitRequested += () => DispatcherQueue.TryEnqueue(ExitApplication);

        var svc = FirewallBackendService.Instance;
        svc.BlockedConnectionPromptRequested += OnBlockedConnectionPromptRequested;
        svc.ProfileModeChanged += OnProfileModeChanged;
        svc.NotificationModeChanged += OnNotificationModeChanged;
        svc.ServiceConnectionChanged += (_, _) => DispatcherQueue.TryEnqueue(UpdateStatusPill);

        NavView.SelectedItem = NavView.MenuItems[0];

        _ = SyncTrayStateAsync();
    }

    public void RestoreFromTray()
    {
        AppWindow.Show();
        ShowWindow(_hwnd, SW_RESTORE);
        SetForegroundWindow(_hwnd);
    }

    public void HideToTray()
    {
        AppWindow.Hide();
    }

    public void ExitApplication()
    {
        _isExiting = true;
        _alertWindow?.ForceClose();
        _trayIcon.Dispose();
        FirewallBackendService.Instance.Dispose();
        Close();
        Application.Current.Exit();
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_isExiting && FirewallBackendService.Instance.GetSettings().CloseToTray)
        {
            args.Cancel = true;
            HideToTray();
            return;
        }

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

    public void UpdateStatusPill()
    {
        var svc = FirewallBackendService.Instance;
        if (svc.IsUsingService)
        {
            StatusPillText.Text = "Service Connected";
            StatusDot.Fill = new SolidColorBrush(Colors.LimeGreen);
        }
        else if (svc.IsElevated)
        {
            StatusPillText.Text = "Administrator Mode";
            StatusDot.Fill = new SolidColorBrush(Colors.LimeGreen);
        }
        else
        {
            StatusPillText.Text = "Standard User (Read-Only)";
            StatusDot.Fill = new SolidColorBrush(Colors.Orange);
        }
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
