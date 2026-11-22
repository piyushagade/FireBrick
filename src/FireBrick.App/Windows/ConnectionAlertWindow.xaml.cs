using System.Diagnostics;
using System.Runtime.InteropServices;
using FireBrick.App.Services;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;
using Windows.UI;
using WinRT.Interop;

namespace FireBrick.App.Windows;

/// <summary>
/// Standalone, draggable, always-on-top WinUI 3 floating notification window for blocked outbound connections.
/// Supports queued alerts (1 of N pager), reverse DNS lookup, trust badges, rule scoping, and temporary allow durations.
/// </summary>
public sealed partial class ConnectionAlertWindow : Window
{
    private const uint WM_NCLBUTTONDBLCLK = 0x00A3;
    private const uint WM_SYSCOMMAND = 0x0112;
    private const nuint SC_MAXIMIZE = 0xF030;

    private delegate IntPtr SubclassProc(
        IntPtr hWnd,
        uint uMsg,
        IntPtr wParam,
        IntPtr lParam,
        nuint uIdSubclass,
        nuint dwRefData);

    private readonly List<ConnectionEventDto> _queue = new();
    private readonly IntPtr _hwnd;
    private readonly SubclassProc _subclassDelegate;
    private int _currentIndex;
    private bool _positionedOnce;
    private bool _allowClose;

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hWnd);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass, nuint dwRefData);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass);

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    public ConnectionAlertWindow()
    {
        InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(DragHeader);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Standard;

        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
            presenter.IsResizable = false;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
        }

        _hwnd = WindowNative.GetWindowHandle(this);
        _subclassDelegate = WndProcSubclass;
        SetWindowSubclass(_hwnd, _subclassDelegate, 2, 0);

        double scale = Math.Max(1.0, GetDpiForWindow(_hwnd) / 96.0);
        AppWindow.Resize(new SizeInt32((int)Math.Round(420 * scale), (int)Math.Round(348 * scale)));
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "FireBrick.ico");
        if (File.Exists(iconPath)) AppWindow.SetIcon(iconPath);
        AppWindow.Closing += OnWindowClosing;

        ApplyTheme();
    }

    private IntPtr WndProcSubclass(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, nuint uIdSubclass, nuint dwRefData)
    {
        if (uMsg == WM_NCLBUTTONDBLCLK)
            return IntPtr.Zero;

        if (uMsg == WM_SYSCOMMAND && (((nuint)wParam & 0xFFF0) == SC_MAXIMIZE))
            return IntPtr.Zero;

        return DefSubclassProc(hWnd, uMsg, wParam, lParam);
    }

    public void EnqueueAlert(ConnectionEventDto evt)
    {
        ApplyTheme();

        int existingIdx = _queue.FindIndex(x =>
            string.Equals(x.ApplicationPath, evt.ApplicationPath, StringComparison.OrdinalIgnoreCase));

        if (existingIdx >= 0)
        {
            _queue[existingIdx] = evt;
        }
        else
        {
            _queue.Add(evt);
        }

        if (_currentIndex >= _queue.Count)
            _currentIndex = 0;

        if (!_positionedOnce)
        {
            PositionBottomRight();
            _positionedOnce = true;
        }

        RenderCurrentAlert();
        AppWindow.Show(activateWindow: false);
    }

    public void ForceClose()
    {
        _allowClose = true;
        RemoveWindowSubclass(_hwnd, _subclassDelegate, 2);
        Close();
    }

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_allowClose)
        {
            args.Cancel = true;
            _queue.Clear();
            _currentIndex = 0;
            AppWindow.Hide();
        }
    }

    private void PositionBottomRight()
    {
        try
        {
            var displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary);
            var work = displayArea.WorkArea;
            var size = AppWindow.Size;
            int x = work.X + work.Width - size.Width - 16;
            int y = work.Y + work.Height - size.Height - 16;
            AppWindow.Move(new PointInt32(Math.Max(work.X, x), Math.Max(work.Y, y)));
        }
        catch { }
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

    private void RenderCurrentAlert()
    {
        if (_queue.Count == 0)
        {
            AppWindow.Hide();
            return;
        }

        _currentIndex = Math.Clamp(_currentIndex, 0, _queue.Count - 1);
        var evt = _queue[_currentIndex];

        // Queue pager
        QueuePagerPanel.Visibility = _queue.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        QueueCounterText.Text = $"{_currentIndex + 1} of {_queue.Count}";

        // App & Trust details
        AppNameText.Text = string.IsNullOrWhiteSpace(evt.ApplicationName) ? "Unknown Application" : evt.ApplicationName;
        AppPathText.Text = evt.ApplicationPath;
        ToolTipService.SetToolTip(AppPathText, evt.ApplicationPath);
        PublisherText.Text = string.IsNullOrWhiteSpace(evt.Publisher)
            ? "Publisher: Unknown"
            : $"Publisher: {evt.Publisher}";

        switch (evt.SignatureStatus)
        {
            case SignatureTrustStatus.Trusted:
                TrustBadgeText.Text = "Trusted";
                TrustBadgeIcon.Glyph = "\uE73E";
                TrustBadgeIcon.Foreground = new SolidColorBrush(Color.FromArgb(255, 16, 185, 129));
                TrustBadgeText.Foreground = new SolidColorBrush(Color.FromArgb(255, 16, 185, 129));
                break;
            case SignatureTrustStatus.Unsigned:
                TrustBadgeText.Text = "Unsigned";
                TrustBadgeIcon.Glyph = "\uE7BA";
                TrustBadgeIcon.Foreground = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
                TrustBadgeText.Foreground = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
                break;
            case SignatureTrustStatus.Untrusted:
                TrustBadgeText.Text = "Untrusted";
                TrustBadgeIcon.Glyph = "\uEA39";
                TrustBadgeIcon.Foreground = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));
                TrustBadgeText.Foreground = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));
                break;
            default:
                TrustBadgeText.Text = "Unknown";
                TrustBadgeIcon.Glyph = "\uE946";
                TrustBadgeIcon.Foreground = new SolidColorBrush(Colors.Gray);
                TrustBadgeText.Foreground = new SolidColorBrush(Colors.Gray);
                break;
        }

        // Connection details
        RemoteEndpointText.Text = evt.RemoteEndpoint;
        ProtocolPidText.Text = $"{evt.Protocol}  •  PID {evt.ProcessId}";

        // Scope labels
        ScopePortItem.Content = evt.RemotePort > 0
            ? $"Remote port only ({evt.Protocol} {evt.RemotePort})"
            : $"Protocol only ({evt.Protocol})";
        ScopeIpPortItem.Content = $"This remote IP & port only ({evt.RemoteEndpoint})";
        ScopeCombo.SelectedIndex = 0;

        // Default temp button text
        int defaultMins = FirewallBackendService.Instance.GetSettings().DefaultTempRuleMinutes;
        TempAllowButton.Content = $"Allow ({defaultMins}m)";

        // Async Reverse DNS + GeoIP resolution
        var cfg = FirewallBackendService.Instance.GetSettings();
        if (!string.IsNullOrWhiteSpace(evt.RemoteHostName) || !string.IsNullOrWhiteSpace(evt.GeoLocation))
        {
            RemoteHostText.Text = FormatHostAndGeo(evt.RemoteHostName, evt.GeoLocation);
            RemoteHostText.Visibility = Visibility.Visible;
        }
        else if ((cfg.EnableReverseDns || cfg.EnableGeoIpLookup) && !string.IsNullOrWhiteSpace(evt.RemoteAddress))
        {
            RemoteHostText.Text = "Resolving destination...";
            RemoteHostText.Visibility = Visibility.Visible;
            _ = ResolveDestinationInfoAsync(evt, cfg.EnableReverseDns, cfg.EnableGeoIpLookup);
        }
        else
        {
            RemoteHostText.Visibility = Visibility.Collapsed;
        }
    }

    private static string FormatHostAndGeo(string host, string geo)
    {
        if (!string.IsNullOrWhiteSpace(geo) && !string.IsNullOrWhiteSpace(host))
            return $"{geo}  •  {host}";
        return !string.IsNullOrWhiteSpace(geo) ? geo : host;
    }

    private async Task ResolveDestinationInfoAsync(ConnectionEventDto evt, bool doDns, bool doGeo)
    {
        var dnsTask = doDns
            ? FirewallBackendService.Instance.DnsCache.ResolveAsync(evt.RemoteAddress)
            : Task.FromResult(string.Empty);
        var geoTask = doGeo
            ? FirewallBackendService.Instance.GeoIpCache.ResolveAsync(evt.RemoteAddress)
            : Task.FromResult(new GeoIpInfoDto());

        await Task.WhenAll(dnsTask, geoTask);
        evt.RemoteHostName = dnsTask.Result;
        evt.GeoLocation = geoTask.Result.DisplaySummary;

        var combined = FormatHostAndGeo(evt.RemoteHostName, evt.GeoLocation);
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_queue.Count > 0 && _currentIndex < _queue.Count && ReferenceEquals(_queue[_currentIndex], evt))
            {
                if (!string.IsNullOrWhiteSpace(combined))
                {
                    RemoteHostText.Text = combined;
                    RemoteHostText.Visibility = Visibility.Visible;
                }
                else
                {
                    RemoteHostText.Visibility = Visibility.Collapsed;
                }
            }
        });
    }

    private FirewallRuleDto BuildScopedRule(ConnectionEventDto evt, RuleAction action, int? tempMinutes)
    {
        var scopeTag = (ScopeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Any";
        bool isTemp = tempMinutes.HasValue && tempMinutes.Value > 0;

        int protocol = scopeTag == "Any"
            ? NetFwConstants.NET_FW_IP_PROTOCOL_ANY
            : evt.Protocol.ToUpperInvariant() switch
            {
                "TCP" => NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
                "UDP" => NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
                _ => NetFwConstants.NET_FW_IP_PROTOCOL_ANY
            };

        string remotePorts = (scopeTag is "PortOnly" or "IpAndPort") && evt.RemotePort > 0
            ? evt.RemotePort.ToString()
            : "*";

        string remoteAddr = scopeTag == "IpAndPort" && !string.IsNullOrWhiteSpace(evt.RemoteAddress)
            ? evt.RemoteAddress
            : "*";

        var prefix = isTemp ? "[FireBrick Temp]" : "FireBrick:";
        var actionLabel = action == RuleAction.Allow ? "Allow" : "Block";
        var suffix = scopeTag switch
        {
            "PortOnly" when evt.RemotePort > 0 => $" ({evt.Protocol} {evt.RemotePort})",
            "IpAndPort" => $" ({evt.RemoteEndpoint})",
            _ => string.Empty
        };
        if (isTemp) suffix += $" [{DateTime.Now:HHmmss}]";

        return new FirewallRuleDto
        {
            Name = $"{prefix} {actionLabel} Out - {evt.ApplicationName}{suffix}",
            Description = $"Created from FireBrick Alert on {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            ApplicationName = evt.ApplicationPath,
            ExpandedApplicationPath = evt.ApplicationPath,
            Protocol = protocol,
            RemotePorts = remotePorts,
            RemoteAddresses = remoteAddr,
            Direction = RuleDirection.Outbound,
            Action = action,
            Enabled = true,
            Profiles = FirewallProfileFlags.All,
            Grouping = isTemp ? "FireBrick Temporary Rules" : "FireBrick Rules",
            IsTemporary = isTemp,
            ExpiresAtUtc = isTemp ? DateTimeOffset.UtcNow.AddMinutes(tempMinutes!.Value) : null
        };
    }

    private async Task ApplyActionAndAdvanceAsync(RuleAction action, int? tempMinutes)
    {
        if (_queue.Count == 0) return;
        var evt = _queue[_currentIndex];
        try
        {
            var rule = BuildScopedRule(evt, action, tempMinutes);
            await FirewallBackendService.Instance.CreateRuleAsync(rule);
            if (action == RuleAction.Block && FirewallBackendService.Instance.GetSettings().KillConnectionsOnBlock)
            {
                await FirewallBackendService.Instance.KillConnectionsForAppAsync(evt.ApplicationPath);
            }
        }
        catch
        {
            // Non-fatal
        }

        RemoveCurrentAndAdvance();
    }

    private void RemoveCurrentAndAdvance()
    {
        if (_queue.Count == 0) return;
        _queue.RemoveAt(_currentIndex);
        if (_currentIndex >= _queue.Count && _queue.Count > 0)
            _currentIndex = _queue.Count - 1;
        RenderCurrentAlert();
    }

    private async void AllowPermanent_Click(object sender, RoutedEventArgs e)
        => await ApplyActionAndAdvanceAsync(RuleAction.Allow, null);

    private async void AllowTempDefault_Click(SplitButton sender, SplitButtonClickEventArgs args)
    {
        int mins = FirewallBackendService.Instance.GetSettings().DefaultTempRuleMinutes;
        await ApplyActionAndAdvanceAsync(RuleAction.Allow, mins);
    }

    private async void AllowTempMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem item && int.TryParse(item.Tag?.ToString(), out int mins))
        {
            await ApplyActionAndAdvanceAsync(RuleAction.Allow, mins);
        }
    }

    private async void BlockPermanent_Click(object sender, RoutedEventArgs e)
        => await ApplyActionAndAdvanceAsync(RuleAction.Block, null);

    private void IgnoreOnce_Click(object sender, RoutedEventArgs e) => RemoveCurrentAndAdvance();

    private void PrevAlert_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count <= 1) return;
        _currentIndex = (_currentIndex - 1 + _queue.Count) % _queue.Count;
        RenderCurrentAlert();
    }

    private void NextAlert_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count <= 1) return;
        _currentIndex = (_currentIndex + 1) % _queue.Count;
        RenderCurrentAlert();
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count == 0) return;
        var path = _queue[_currentIndex].ApplicationPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch { }
    }

    private void CopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count == 0) return;
        var path = _queue[_currentIndex].ApplicationPath;
        if (string.IsNullOrWhiteSpace(path)) return;
        var pkg = new DataPackage();
        pkg.SetText(path);
        Clipboard.SetContent(pkg);
        Clipboard.Flush();
    }
}
