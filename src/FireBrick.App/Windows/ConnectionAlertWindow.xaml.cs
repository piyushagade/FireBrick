using System.Diagnostics;
using System.Runtime.InteropServices;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
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

    private const int ExpandedWidthDip = 420;
    private const int ExpandedHeightDip = 348;
    private const int CondensedWidthDip = 396;
    private const int CondensedHeightDip = 96;
    private const int CountdownExtraHeightDip = 52;

    private readonly List<ConnectionEventDto> _queue = new();
    private readonly HashSet<string> _cancelledCountdownIds = new(StringComparer.Ordinal);
    private readonly DispatcherTimer _countdownTimer;
    private readonly IntPtr _hwnd;
    private readonly SubclassProc _subclassDelegate;
    private int _currentIndex;
    private bool _positionedOnce;
    private bool _allowClose;
    private bool _isCompactView;
    private bool _isCountdownVisible;
    private bool _countdownPausedByHover;
    private AutoRuleDto? _activeCountdownRule;
    private ConnectionEventDto? _activeCountdownEvent;
    private int _countdownTotalMs;
    private int _countdownRemainingMs;

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

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "FireBrick.ico");
        if (File.Exists(iconPath)) AppWindow.SetIcon(iconPath);
        AppWindow.Closing += OnWindowClosing;

        _countdownTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _countdownTimer.Tick += OnCountdownTick;

        ApplyTheme();
        ApplyViewMode(FirewallBackendService.Instance.GetSettings().CompactAlertView, anchorBottomRight: false);
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
        var wantsCompact = FirewallBackendService.Instance.GetSettings().CompactAlertView;
        if (wantsCompact != _isCompactView)
        {
            ApplyViewMode(wantsCompact, anchorBottomRight: _positionedOnce);
        }

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
        StopCountdown(updateLayout: false);
        _allowClose = true;
        RemoveWindowSubclass(_hwnd, _subclassDelegate, 2);
        Close();
    }

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_allowClose)
        {
            args.Cancel = true;
            StopCountdown(updateLayout: false);
            _queue.Clear();
            _cancelledCountdownIds.Clear();
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

    private void ApplyViewMode(bool isCompact, bool anchorBottomRight)
    {
        _isCompactView = isCompact;

        RootGrid.RowSpacing = isCompact ? 0 : 10;
        HeaderTitleText.Text = isCompact ? "Blocked Connection" : "Blocked Outbound Connection";

        CondensedContentPanel.Visibility = isCompact ? Visibility.Visible : Visibility.Collapsed;
        ExpandedContentPanel.Visibility = isCompact ? Visibility.Collapsed : Visibility.Visible;
        ExpandedFooterBorder.Visibility = isCompact ? Visibility.Collapsed : Visibility.Visible;

        ViewModeToggleIcon.Glyph = isCompact ? "\uE70D" : "\uE70E";
        ToolTipService.SetToolTip(
            ViewModeToggleButton,
            isCompact ? "Switch to Expanded view" : "Switch to Condensed view");

        double scale = Math.Max(1.0, GetDpiForWindow(_hwnd) / 96.0);
        int baseHeight = isCompact ? CondensedHeightDip : ExpandedHeightDip;
        if (_isCountdownVisible) baseHeight += CountdownExtraHeightDip;
        int targetW = (int)Math.Round((isCompact ? CondensedWidthDip : ExpandedWidthDip) * scale);
        int targetH = (int)Math.Round(baseHeight * scale);

        var oldPos = AppWindow.Position;
        var oldSize = AppWindow.Size;

        AppWindow.Resize(new SizeInt32(targetW, targetH));

        if (anchorBottomRight)
        {
            try
            {
                var displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary);
                var work = displayArea.WorkArea;
                int newX = oldPos.X + (oldSize.Width - targetW);
                int newY = oldPos.Y + (oldSize.Height - targetH);
                newX = Math.Clamp(newX, work.X, Math.Max(work.X, work.X + work.Width - targetW));
                newY = Math.Clamp(newY, work.Y, Math.Max(work.Y, work.Y + work.Height - targetH));
                AppWindow.Move(new PointInt32(newX, newY));
            }
            catch { }
        }
    }

    private void RenderCurrentAlert()
    {
        StopCountdown(updateLayout: false);

        if (_queue.Count == 0)
        {
            if (_isCountdownVisible)
            {
                _isCountdownVisible = false;
                CountdownBannerBorder.Visibility = Visibility.Collapsed;
                ApplyViewMode(_isCompactView, anchorBottomRight: _positionedOnce);
            }
            AppWindow.Hide();
            return;
        }

        _currentIndex = Math.Clamp(_currentIndex, 0, _queue.Count - 1);
        var evt = _queue[_currentIndex];

        // Queue pager
        QueuePagerPanel.Visibility = _queue.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        QueueCounterText.Text = $"{_currentIndex + 1} of {_queue.Count}";

        // App & Trust details
        var appName = string.IsNullOrWhiteSpace(evt.ApplicationName) ? "Unknown Application" : evt.ApplicationName;
        var publisher = string.IsNullOrWhiteSpace(evt.Publisher) ? "Unknown" : evt.Publisher;

        AppNameText.Text = appName;
        AppPathText.Text = evt.ApplicationPath;
        ToolTipService.SetToolTip(AppPathText, evt.ApplicationPath);
        PublisherText.Text = $"Publisher: {publisher}";

        CondensedAppNameText.Text = appName;
        CondensedPublisherText.Text = publisher;
        ToolTipService.SetToolTip(
            CondensedAppInfoPanel,
            string.IsNullOrWhiteSpace(evt.ApplicationPath) ? appName : $"{appName}\n{publisher}\n{evt.ApplicationPath}");

        // App icon (cached synchronously when available, otherwise loaded asynchronously)
        if (AppIconHelper.TryGetCachedIcon(evt.ApplicationPath, out var cachedIcon))
        {
            ApplyAppIcon(cachedIcon);
        }
        else
        {
            ApplyAppIcon(null);
            _ = LoadAppIconAsync(evt);
        }

        switch (evt.SignatureStatus)
        {
            case SignatureTrustStatus.Trusted:
                ApplyTrustBadge("Trusted", "\uE73E", Color.FromArgb(255, 16, 185, 129));
                break;
            case SignatureTrustStatus.Unsigned:
                ApplyTrustBadge("Unsigned", "\uE7BA", Color.FromArgb(255, 245, 158, 11));
                break;
            case SignatureTrustStatus.Untrusted:
                ApplyTrustBadge("Untrusted", "\uEA39", Color.FromArgb(255, 239, 68, 68));
                break;
            default:
                ApplyTrustBadge("Unknown", "\uE946", Colors.Gray);
                break;
        }

        // Connection details
        RemoteEndpointText.Text = evt.RemoteEndpoint;
        ProtocolPidText.Text = $"{evt.Protocol}  •  PID {evt.ProcessId}";

        // Scope labels (concise so dropdown fits cleanly inside the alert card)
        ScopePortItem.Content = evt.RemotePort > 0
            ? $"Port only ({evt.Protocol} {evt.RemotePort})"
            : $"Protocol only ({evt.Protocol})";
        ScopeIpPortItem.Content = $"IP & port ({evt.RemoteEndpoint})";
        ScopeCombo.SelectedIndex = 0;

        // Default temp button text & search engine tooltip
        var cfg = FirewallBackendService.Instance.GetSettings();
        int defaultMins = cfg.DefaultTempRuleMinutes;
        TempAllowButton.Content = $"Allow ({defaultMins}m)";
        ToolTipService.SetToolTip(
            CondensedTempAllowButton,
            $"Allow for {defaultMins} minutes (right-click for other durations)");

        var engine = string.IsNullOrWhiteSpace(cfg.SearchEngine) ? "Google" : cfg.SearchEngine;
        ToolTipService.SetToolTip(
            SearchWebButton,
            $"Look up on {engine} (right-click to switch engine)");

        // Async Reverse DNS + GeoIP resolution
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

        // Check if an Auto-Rule matches this alert (Countdown mode starts timer; Instant shouldn't reach here, but handled safely)
        EvaluateAutoRuleForCurrentAlert(evt);
    }

    private void ApplyTrustBadge(string label, string glyph, Color color)
    {
        var brush = new SolidColorBrush(color);
        TrustBadgeText.Text = label;
        TrustBadgeIcon.Glyph = glyph;
        TrustBadgeIcon.Foreground = brush;
        TrustBadgeText.Foreground = brush;

        CondensedTrustIcon.Glyph = glyph;
        CondensedTrustIcon.Foreground = brush;
        ToolTipService.SetToolTip(CondensedTrustIcon, label);
    }

    private void ApplyAppIcon(ImageSource? icon)
    {
        if (icon is not null)
        {
            AppIconImage.Source = icon;
            AppIconImage.Visibility = Visibility.Visible;
            AppIconFallback.Visibility = Visibility.Collapsed;

            CondensedAppIconImage.Source = icon;
            CondensedAppIconImage.Visibility = Visibility.Visible;
            CondensedAppIconFallback.Visibility = Visibility.Collapsed;
        }
        else
        {
            AppIconImage.Source = null;
            AppIconImage.Visibility = Visibility.Collapsed;
            AppIconFallback.Visibility = Visibility.Visible;

            CondensedAppIconImage.Source = null;
            CondensedAppIconImage.Visibility = Visibility.Collapsed;
            CondensedAppIconFallback.Visibility = Visibility.Visible;
        }
    }

    private async Task LoadAppIconAsync(ConnectionEventDto evt)
    {
        try
        {
            var icon = await AppIconHelper.GetAppIconAsync(evt.ApplicationPath);
            if (_queue.Count > 0 && _currentIndex < _queue.Count && ReferenceEquals(_queue[_currentIndex], evt))
            {
                ApplyAppIcon(icon);
            }
        }
        catch
        {
            // Keep fallback glyph if icon extraction fails
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

                // Re-evaluate Domain/Host auto-rules now that Reverse DNS & GeoIP are resolved
                if (_activeCountdownRule == null)
                {
                    EvaluateAutoRuleForCurrentAlert(evt);
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
        StopCountdown(updateLayout: false);
        if (_queue.Count == 0) return;
        var evt = _queue[_currentIndex];
        try
        {
            var rule = BuildScopedRule(evt, action, tempMinutes);
            await FirewallBackendService.Instance.CreateRuleAsync(rule);
            FirewallBackendService.Instance.Analytics.TrackAlertDecision(action, rule.IsTemporary);
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

    private async void AllowTempCondensed_Click(object sender, RoutedEventArgs e)
    {
        int mins = FirewallBackendService.Instance.GetSettings().DefaultTempRuleMinutes;
        await ApplyActionAndAdvanceAsync(RuleAction.Allow, mins);
    }

    private void ToggleViewMode_Click(object sender, RoutedEventArgs e)
    {
        bool nextCompact = !_isCompactView;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.CompactAlertView = nextCompact;
        FirewallBackendService.Instance.SaveSettings(cfg);
        ApplyViewMode(nextCompact, anchorBottomRight: true);
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

    private void SearchWeb_Click(object sender, RoutedEventArgs e)
    {
        var engine = FirewallBackendService.Instance.GetSettings().SearchEngine;
        OpenAppWebSearch(engine);
    }

    private void SearchWebWithEngine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem item && item.Tag is string engine && !string.IsNullOrWhiteSpace(engine))
        {
            var cfg = FirewallBackendService.Instance.GetSettings();
            cfg.SearchEngine = engine;
            FirewallBackendService.Instance.SaveSettings(cfg);
            ToolTipService.SetToolTip(SearchWebButton, $"Look up on {engine} (right-click to switch engine)");
            OpenAppWebSearch(engine);
        }
    }

    private void OpenAppWebSearch(string? searchEngine)
    {
        if (_queue.Count == 0) return;
        var evt = _queue[_currentIndex];
        var appName = string.IsNullOrWhiteSpace(evt.ApplicationName)
            ? Path.GetFileName(evt.ApplicationPath)
            : evt.ApplicationName;
        if (string.IsNullOrWhiteSpace(appName)) return;

        var publisher = evt.Publisher?.Trim();
        var query = !string.IsNullOrWhiteSpace(publisher) &&
                    !string.Equals(publisher, "Unknown", StringComparison.OrdinalIgnoreCase)
            ? $"what is {appName} {publisher}"
            : $"what is {appName}";

        var encoded = Uri.EscapeDataString(query);
        var url = searchEngine?.Trim() switch
        {
            "Bing" => $"https://www.bing.com/search?q={encoded}",
            "DuckDuckGo" => $"https://duckduckgo.com/?q={encoded}",
            _ => $"https://www.google.com/search?q={encoded}"
        };

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
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

    private void EvaluateAutoRuleForCurrentAlert(ConnectionEventDto evt)
    {
        if (_cancelledCountdownIds.Contains(evt.Id))
        {
            SetCountdownBannerVisible(false);
            return;
        }

        var matched = FirewallBackendService.Instance.MatchAutoRule(evt);
        if (matched == null)
        {
            SetCountdownBannerVisible(false);
            return;
        }

        if (matched.TriggerMode == AutoRuleTriggerMode.Instant)
        {
            // Late match (e.g. after async DNS/GeoIP resolution) -> apply silently and advance
            _ = ApplyMatchedAutoRuleAsync(matched, evt);
            return;
        }

        StartCountdown(matched, evt);
    }

    private void StartCountdown(AutoRuleDto rule, ConnectionEventDto evt)
    {
        _activeCountdownRule = rule;
        _activeCountdownEvent = evt;
        _countdownTotalMs = Math.Clamp(rule.CountdownSeconds, 2, 60) * 1000;
        _countdownRemainingMs = _countdownTotalMs;
        _countdownPausedByHover = false;

        var accent = rule.Action == RuleAction.Allow
            ? Color.FromArgb(255, 16, 185, 129)
            : Color.FromArgb(255, 239, 68, 68);
        CountdownIcon.Foreground = new SolidColorBrush(accent);
        CountdownProgressBar.Foreground = new SolidColorBrush(accent);
        CountdownProgressBar.Value = 100;

        UpdateCountdownBannerText();
        SetCountdownBannerVisible(true);
        _countdownTimer.Start();
    }

    private void StopCountdown(bool updateLayout)
    {
        _countdownTimer.Stop();
        _activeCountdownRule = null;
        _activeCountdownEvent = null;
        _countdownPausedByHover = false;
        if (updateLayout)
        {
            SetCountdownBannerVisible(false);
        }
    }

    private void SetCountdownBannerVisible(bool visible)
    {
        if (_isCountdownVisible == visible)
            return;

        _isCountdownVisible = visible;
        CountdownBannerBorder.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        ApplyViewMode(_isCompactView, anchorBottomRight: _positionedOnce);
    }

    private void UpdateCountdownBannerText()
    {
        if (_activeCountdownRule == null) return;
        int secs = Math.Max(1, (int)Math.Ceiling(_countdownRemainingMs / 1000.0));
        var verb = _activeCountdownRule.Action == RuleAction.Allow ? "Auto-Allowing" : "Auto-Blocking";
        var ruleName = string.IsNullOrWhiteSpace(_activeCountdownRule.Name)
            ? _activeCountdownRule.Pattern
            : _activeCountdownRule.Name;

        CountdownStatusText.Text = _countdownPausedByHover
            ? $"Paused (hover) — {verb} in {secs}s ({ruleName})"
            : $"{verb} in {secs}s… ({ruleName})";
    }

    private void OnCountdownTick(object? sender, object e)
    {
        if (_activeCountdownRule == null || _activeCountdownEvent == null)
        {
            StopCountdown(updateLayout: true);
            return;
        }

        if (_countdownPausedByHover)
            return;

        _countdownRemainingMs -= 100;
        if (_countdownRemainingMs <= 0)
        {
            var rule = _activeCountdownRule;
            var evt = _activeCountdownEvent;
            StopCountdown(updateLayout: false);
            _ = ApplyMatchedAutoRuleAsync(rule, evt);
            return;
        }

        CountdownProgressBar.Value = _countdownTotalMs > 0
            ? (_countdownRemainingMs * 100.0) / _countdownTotalMs
            : 0;
        UpdateCountdownBannerText();
    }

    private void RootGrid_PointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (_activeCountdownRule != null && !_countdownPausedByHover)
        {
            _countdownPausedByHover = true;
            UpdateCountdownBannerText();
        }
    }

    private void RootGrid_PointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (_activeCountdownRule != null && _countdownPausedByHover)
        {
            _countdownPausedByHover = false;
            UpdateCountdownBannerText();
        }
    }

    private void CancelCountdown_Click(object sender, RoutedEventArgs e)
    {
        if (_activeCountdownEvent != null)
        {
            _cancelledCountdownIds.Add(_activeCountdownEvent.Id);
        }
        StopCountdown(updateLayout: true);
    }

    private async Task ApplyMatchedAutoRuleAsync(AutoRuleDto autoRule, ConnectionEventDto evt)
    {
        try
        {
            var fwRule = AutoRuleManager.BuildFirewallRule(autoRule, evt);
            await FirewallBackendService.Instance.CreateRuleAsync(fwRule);
            await FirewallBackendService.Instance.RecordAutoRuleHitAsync(autoRule.Id);
            FirewallBackendService.Instance.Analytics.TrackAlertDecision(autoRule.Action, fwRule.IsTemporary);

            if (autoRule.Action == RuleAction.Block && FirewallBackendService.Instance.GetSettings().KillConnectionsOnBlock)
            {
                await FirewallBackendService.Instance.KillConnectionsForAppAsync(evt.ApplicationPath);
            }
        }
        catch
        {
            // Non-fatal
        }

        int idx = _queue.IndexOf(evt);
        if (idx >= 0)
        {
            _queue.RemoveAt(idx);
            if (_currentIndex >= _queue.Count && _queue.Count > 0)
                _currentIndex = _queue.Count - 1;
            RenderCurrentAlert();
        }
    }

    private void AutoRuleQuickButton_Click(object sender, RoutedEventArgs e)
    {
        if (_queue.Count == 0) return;
        var evt = _queue[_currentIndex];

        var flyout = new MenuFlyout { Placement = Microsoft.UI.Xaml.Controls.Primitives.FlyoutPlacementMode.TopEdgeAlignedRight };

        bool hasTrustedPublisher = evt.SignatureStatus == SignatureTrustStatus.Trusted &&
                                   !string.IsNullOrWhiteSpace(evt.Publisher) &&
                                   !string.Equals(evt.Publisher, "Unknown", StringComparison.OrdinalIgnoreCase);

        if (hasTrustedPublisher)
        {
            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Allow Publisher \"{evt.Publisher}\" (Instant)",
                new AutoRuleDto
                {
                    Name = $"Allow Publisher: {evt.Publisher}",
                    MatchField = AutoRuleMatchField.Publisher,
                    Pattern = evt.Publisher,
                    RequireTrustedSignature = true,
                    Action = RuleAction.Allow,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = GetSelectedAutoRuleScope()
                }, evt));

            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Allow Publisher \"{evt.Publisher}\" (5s Countdown)",
                new AutoRuleDto
                {
                    Name = $"Allow Publisher: {evt.Publisher}",
                    MatchField = AutoRuleMatchField.Publisher,
                    Pattern = evt.Publisher,
                    RequireTrustedSignature = true,
                    Action = RuleAction.Allow,
                    TriggerMode = AutoRuleTriggerMode.Countdown,
                    CountdownSeconds = 5,
                    RuleScope = GetSelectedAutoRuleScope()
                }, evt));

            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Block Publisher \"{evt.Publisher}\" (Instant)",
                new AutoRuleDto
                {
                    Name = $"Block Publisher: {evt.Publisher}",
                    MatchField = AutoRuleMatchField.Publisher,
                    Pattern = evt.Publisher,
                    RequireTrustedSignature = true,
                    Action = RuleAction.Block,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = GetSelectedAutoRuleScope()
                }, evt));

            flyout.Items.Add(new MenuFlyoutSeparator());
        }

        if (!string.IsNullOrWhiteSpace(evt.ApplicationName))
        {
            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Allow App \"{evt.ApplicationName}\" (5s Countdown)",
                new AutoRuleDto
                {
                    Name = $"Allow App: {evt.ApplicationName}",
                    MatchField = AutoRuleMatchField.AppNameOrPath,
                    Pattern = evt.ApplicationName,
                    RequireTrustedSignature = false,
                    Action = RuleAction.Allow,
                    TriggerMode = AutoRuleTriggerMode.Countdown,
                    CountdownSeconds = 5,
                    RuleScope = GetSelectedAutoRuleScope()
                }, evt));

            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Block App \"{evt.ApplicationName}\" (Instant)",
                new AutoRuleDto
                {
                    Name = $"Block App: {evt.ApplicationName}",
                    MatchField = AutoRuleMatchField.AppNameOrPath,
                    Pattern = evt.ApplicationName,
                    RequireTrustedSignature = false,
                    Action = RuleAction.Block,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = GetSelectedAutoRuleScope()
                }, evt));
        }

        if (!string.IsNullOrWhiteSpace(evt.RemoteAddress))
        {
            flyout.Items.Add(new MenuFlyoutSeparator());
            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Allow IP {evt.RemoteAddress} (Instant)",
                new AutoRuleDto
                {
                    Name = $"Allow IP: {evt.RemoteAddress}",
                    MatchField = AutoRuleMatchField.IpOrCidr,
                    Pattern = evt.RemoteAddress,
                    RequireTrustedSignature = false,
                    Action = RuleAction.Allow,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = AutoRuleScope.IpAndPort
                }, evt));

            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Block IP {evt.RemoteAddress} (Instant)",
                new AutoRuleDto
                {
                    Name = $"Block IP: {evt.RemoteAddress}",
                    MatchField = AutoRuleMatchField.IpOrCidr,
                    Pattern = evt.RemoteAddress,
                    RequireTrustedSignature = false,
                    Action = RuleAction.Block,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = AutoRuleScope.IpAndPort
                }, evt));
        }

        if (!string.IsNullOrWhiteSpace(evt.RemoteHostName))
        {
            flyout.Items.Add(CreateQuickAutoRuleItem(
                $"Auto-Block Host \"{evt.RemoteHostName}\" (Instant)",
                new AutoRuleDto
                {
                    Name = $"Block Host: {evt.RemoteHostName}",
                    MatchField = AutoRuleMatchField.DomainOrHost,
                    Pattern = evt.RemoteHostName,
                    RequireTrustedSignature = false,
                    Action = RuleAction.Block,
                    TriggerMode = AutoRuleTriggerMode.Instant,
                    RuleScope = AutoRuleScope.IpAndPort
                }, evt));
        }

        flyout.ShowAt(AutoRuleQuickButton);
    }

    private AutoRuleScope GetSelectedAutoRuleScope()
    {
        var scopeTag = (ScopeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Any";
        return scopeTag switch
        {
            "PortOnly" => AutoRuleScope.PortOnly,
            "IpAndPort" => AutoRuleScope.IpAndPort,
            _ => AutoRuleScope.Any
        };
    }

    private MenuFlyoutItem CreateQuickAutoRuleItem(string label, AutoRuleDto rule, ConnectionEventDto evt)
    {
        var item = new MenuFlyoutItem { Text = label };
        item.Click += async (_, _) =>
        {
            StopCountdown(updateLayout: false);
            try
            {
                await FirewallBackendService.Instance.UpsertAutoRuleAsync(rule);
            }
            catch { }
            await ApplyMatchedAutoRuleAsync(rule, evt);
        };
        return item;
    }
}
