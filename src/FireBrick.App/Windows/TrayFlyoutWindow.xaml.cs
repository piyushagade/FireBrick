using System.Runtime.InteropServices;
using FireBrick.App.Services;
using FireBrick.Core.Models;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using WinRT.Interop;

namespace FireBrick.App.Windows;

/// <summary>
/// Custom theme-aware WinUI 3 System Tray flyout with non-activating behavior (WS_EX_NOACTIVATE)
/// so the Windows 11 system tray overflow stays open while interacting with the menu,
/// plus compact inline submenus for Notifications and page navigation.
/// </summary>
public sealed partial class TrayFlyoutWindow : Window
{
    private const int GWL_EXSTYLE = -20;
    private const nint WS_EX_NOACTIVATE = 0x08000000;
    private const int WH_MOUSE_LL = 14;
    private const int WM_LBUTTONDOWN = 0x0201;
    private const int WM_RBUTTONDOWN = 0x0204;

    private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSLLHOOKSTRUCT
    {
        public POINT pt;
        public uint mouseData;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const double LogicalWidth = 268.0;
    private const double FallbackLogicalHeight = 408.0;

    private readonly IntPtr _hwnd;
    private readonly LowLevelMouseProc _mouseHookDelegate;
    private IntPtr _mouseHook = IntPtr.Zero;
    private bool _allowClose;
    private double _currentLogicalHeight;
    private int _lastCursorX;
    private int _lastCursorY;

    public event Action? OpenRequested;
    public event Action<string>? NavigateRequested;
    public event Action<FirewallProfileMode>? ProfileSwitchRequested;
    public event Action<NotificationMode>? NotificationSwitchRequested;
    public event Action? ExitRequested;

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hWnd);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern nint GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
    private static extern nint SetWindowLongPtr(IntPtr hWnd, int nIndex, nint dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookExW(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    public TrayFlyoutWindow()
    {
        InitializeComponent();

        _hwnd = WindowNative.GetWindowHandle(this);
        _mouseHookDelegate = MouseHookCallback;

        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.SetBorderAndTitleBar(true, false);
            presenter.IsAlwaysOnTop = true;
            presenter.IsResizable = false;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
        }

        // Prevent stealing focus from Windows 11 system tray overflow popup
        var exStyle = GetWindowLongPtr(_hwnd, GWL_EXSTYLE);
        SetWindowLongPtr(_hwnd, GWL_EXSTYLE, exStyle | WS_EX_NOACTIVATE);

        AppWindow.IsShownInSwitchers = false;
        AppWindow.Closing += OnWindowClosing;
        MainView.SizeChanged += OnActiveViewSizeChanged;
        NotifSubmenuView.SizeChanged += OnActiveViewSizeChanged;
        NavSubmenuView.SizeChanged += OnActiveViewSizeChanged;
    }

    public void ShowAt(int cursorX, int cursorY, FirewallProfileMode profile, NotificationMode notif)
    {
        _lastCursorX = cursorX;
        _lastCursorY = cursorY;

        ApplyTheme();
        ShowMainView();
        UpdateVisualState(profile, notif);
        ResizeAndPositionToContent();

        // Show WITHOUT activating so the Windows 11 system tray overflow stays open!
        AppWindow.Show(activateWindow: false);
        InstallOutsideClickHook();
    }

    private void ResizeAndPositionToContent()
    {
        FrameworkElement active = MainView.Visibility == Visibility.Visible
            ? MainView
            : (NotifSubmenuView.Visibility == Visibility.Visible ? NotifSubmenuView : NavSubmenuView);

        double innerWidth = LogicalWidth - RootGrid.Padding.Left - RootGrid.Padding.Right;
        active.Measure(new global::Windows.Foundation.Size(innerWidth, double.PositiveInfinity));
        double desired = Math.Ceiling(active.DesiredSize.Height + RootGrid.Padding.Top + RootGrid.Padding.Bottom);
        double targetHeight = desired > 80 ? desired : FallbackLogicalHeight;
        ResizeAndPosition(_lastCursorX, _lastCursorY, targetHeight);
    }

    private void OnActiveViewSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Visibility != Visibility.Visible || e.NewSize.Height <= 0)
            return;

        double neededLogicalHeight = Math.Ceiling(e.NewSize.Height + RootGrid.Padding.Top + RootGrid.Padding.Bottom);
        if (AppWindow.IsVisible && Math.Abs(neededLogicalHeight - _currentLogicalHeight) >= 1.0)
        {
            ResizeAndPosition(_lastCursorX, _lastCursorY, neededLogicalHeight);
        }
    }

    private void ResizeAndPosition(int cursorX, int cursorY, double logicalHeight)
    {
        double scale = RootGrid.XamlRoot?.RasterizationScale ?? (GetDpiForWindow(_hwnd) / 96.0);
        scale = Math.Max(1.0, scale);

        _currentLogicalHeight = logicalHeight;
        int outerWidth = (int)Math.Ceiling((LogicalWidth + 2) * scale);
        int outerHeight = (int)Math.Ceiling((logicalHeight + 10) * scale);
        // Use AppWindow.Resize (not ResizeClient) because WinUI 3 ResizeClient adds phantom titlebar height on borderless windows
        AppWindow.Resize(new SizeInt32(outerWidth, outerHeight));

        var outerSize = AppWindow.Size;
        int width = outerSize.Width > 0 ? outerSize.Width : outerWidth;
        int height = outerSize.Height > 0 ? outerSize.Height : outerHeight;

        // Position cleanly above the tray cursor, clamped inside the monitor's work area
        try
        {
            var displayArea = DisplayArea.GetFromPoint(new PointInt32(cursorX, cursorY), DisplayAreaFallback.Primary);
            var work = displayArea.WorkArea;
            int margin = (int)Math.Round(8 * scale);

            int x = cursorX - width + (int)Math.Round(24 * scale);
            int y = cursorY - height - margin;

            if (x + width > work.X + work.Width - margin)
                x = work.X + work.Width - width - margin;
            if (x < work.X + margin)
                x = work.X + margin;

            if (y < work.Y + margin)
                y = cursorY + margin;
            if (y + height > work.Y + work.Height - margin)
                y = work.Y + work.Height - height - margin;

            AppWindow.Move(new PointInt32(x, y));
        }
        catch { }
    }

    public void HideFlyout()
    {
        RemoveOutsideClickHook();
        AppWindow.Hide();
    }

    public void ForceClose()
    {
        RemoveOutsideClickHook();
        _allowClose = true;
        Close();
    }

    private void InstallOutsideClickHook()
    {
        if (_mouseHook != IntPtr.Zero) return;
        _mouseHook = SetWindowsHookExW(WH_MOUSE_LL, _mouseHookDelegate, IntPtr.Zero, 0);
    }

    private void RemoveOutsideClickHook()
    {
        if (_mouseHook != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_mouseHook);
            _mouseHook = IntPtr.Zero;
        }
    }

    private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && (wParam == (IntPtr)WM_LBUTTONDOWN || wParam == (IntPtr)WM_RBUTTONDOWN))
        {
            var info = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
            if (GetWindowRect(_hwnd, out var rect))
            {
                bool inside = info.pt.X >= rect.Left && info.pt.X <= rect.Right &&
                              info.pt.Y >= rect.Top && info.pt.Y <= rect.Bottom;
                if (!inside)
                {
                    DispatcherQueue.TryEnqueue(HideFlyout);
                }
            }
        }

        return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
    }

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_allowClose)
        {
            args.Cancel = true;
            HideFlyout();
        }
    }

    private void ApplyTheme()
    {
        var theme = FirewallBackendService.Instance.GetSettings().Theme;
        RootGrid.RequestedTheme = theme switch
        {
            "Dark" => ElementTheme.Dark,
            "Light" => ElementTheme.Light,
            _ => ElementTheme.Default
        };
    }

    private void ShowMainView()
    {
        MainView.Visibility = Visibility.Visible;
        NotifSubmenuView.Visibility = Visibility.Collapsed;
        NavSubmenuView.Visibility = Visibility.Collapsed;
    }

    private void UpdateVisualState(FirewallProfileMode profile, NotificationMode notif)
    {
        var shieldColor = profile switch
        {
            FirewallProfileMode.HighFiltering => global::Windows.UI.Color.FromArgb(255, 59, 130, 246),   // Blue
            FirewallProfileMode.MediumFiltering => global::Windows.UI.Color.FromArgb(255, 34, 197, 94),  // Green
            FirewallProfileMode.LowFiltering => global::Windows.UI.Color.FromArgb(255, 245, 158, 11),    // Orange
            _ => global::Windows.UI.Color.FromArgb(255, 239, 68, 68)                                     // Red
        };
        HeaderShieldIcon.Foreground = new SolidColorBrush(shieldColor);

        var svc = FirewallBackendService.Instance;
        if (svc.IsUsingService)
        {
            HeaderStatusText.Text = "Service";
            HeaderStatusDot.Fill = new SolidColorBrush(Colors.LimeGreen);
        }
        else if (svc.IsElevated)
        {
            HeaderStatusText.Text = "Admin";
            HeaderStatusDot.Fill = new SolidColorBrush(Colors.LimeGreen);
        }
        else
        {
            HeaderStatusText.Text = "Read-Only";
            HeaderStatusDot.Fill = new SolidColorBrush(Colors.Orange);
        }

        CheckHigh.Visibility = profile == FirewallProfileMode.HighFiltering ? Visibility.Visible : Visibility.Collapsed;
        CheckMedium.Visibility = profile == FirewallProfileMode.MediumFiltering ? Visibility.Visible : Visibility.Collapsed;
        CheckLow.Visibility = profile == FirewallProfileMode.LowFiltering ? Visibility.Visible : Visibility.Collapsed;
        CheckNone.Visibility = profile == FirewallProfileMode.NoFiltering ? Visibility.Visible : Visibility.Collapsed;

        NotifSummaryText.Text = notif switch
        {
            NotificationMode.Disabled => "Disabled",
            NotificationMode.DisplayNotifications => "Alerts",
            NotificationMode.LowNotification => "Unsigned",
            NotificationMode.LearningMode => "Learning",
            _ => notif.ToString()
        };

        CheckNotifDisabled.Visibility = notif == NotificationMode.Disabled ? Visibility.Visible : Visibility.Collapsed;
        CheckNotifDisplay.Visibility = notif == NotificationMode.DisplayNotifications ? Visibility.Visible : Visibility.Collapsed;
        CheckNotifLow.Visibility = notif == NotificationMode.LowNotification ? Visibility.Visible : Visibility.Collapsed;
        CheckNotifLearning.Visibility = notif == NotificationMode.LearningMode ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OpenNotifSubmenu_Click(object sender, RoutedEventArgs e)
    {
        MainView.Visibility = Visibility.Collapsed;
        NotifSubmenuView.Visibility = Visibility.Visible;
        NavSubmenuView.Visibility = Visibility.Collapsed;
        ResizeAndPositionToContent();
    }

    private void OpenNavSubmenu_Click(object sender, RoutedEventArgs e)
    {
        MainView.Visibility = Visibility.Collapsed;
        NotifSubmenuView.Visibility = Visibility.Collapsed;
        NavSubmenuView.Visibility = Visibility.Visible;
        ResizeAndPositionToContent();
    }

    private void BackToMain_Click(object sender, RoutedEventArgs e)
    {
        ShowMainView();
        ResizeAndPositionToContent();
    }

    private void ProfileItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag && Enum.TryParse<FirewallProfileMode>(tag, out var mode))
        {
            HideFlyout();
            ProfileSwitchRequested?.Invoke(mode);
        }
    }

    private void NotifItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag && Enum.TryParse<NotificationMode>(tag, out var mode))
        {
            HideFlyout();
            NotificationSwitchRequested?.Invoke(mode);
        }
    }

    private void OpenMain_Click(object sender, RoutedEventArgs e)
    {
        HideFlyout();
        OpenRequested?.Invoke();
    }

    private void NavItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
        {
            HideFlyout();
            NavigateRequested?.Invoke(tag);
        }
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        HideFlyout();
        ExitRequested?.Invoke();
    }
}
