using System.Runtime.InteropServices;
using FireBrick.Core.Models;

namespace FireBrick.App.Services;

/// <summary>
/// Native Win32 System Tray icon & flyout menu for FireBrick.
/// Features a color-coded shield icon (like classic WFC) that reflects the active filtering profile,
/// quick profile/notification switching, direct page navigation, and explorer.exe restart recovery.
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private const uint WM_APP = 0x8000;
    private const uint WM_TRAYICON = WM_APP + 101;
    private const uint WM_LBUTTONUP = 0x0202;
    private const uint WM_LBUTTONDBLCLK = 0x0203;
    private const uint WM_RBUTTONUP = 0x0205;
    private const uint WM_CONTEXTMENU = 0x007B;

    private const uint NIM_ADD = 0x00000000;
    private const uint NIM_MODIFY = 0x00000001;
    private const uint NIM_DELETE = 0x00000002;

    private const uint NIF_MESSAGE = 0x00000001;
    private const uint NIF_ICON = 0x00000002;
    private const uint NIF_TIP = 0x00000004;
    private const uint NIF_INFO = 0x00000010;
    private const uint NIIF_USER = 0x00000004;
    private const uint NIIF_NOSOUND = 0x00000010;

    private const uint MF_STRING = 0x00000000;
    private const uint MF_SEPARATOR = 0x00000800;
    private const uint MF_CHECKED = 0x00000008;
    private const uint MF_POPUP = 0x00000010;
    private const uint TPM_RIGHTALIGN = 0x0008;
    private const uint TPM_BOTTOMALIGN = 0x0020;
    private const uint TPM_RETURNCMD = 0x0100;
    private const uint TPM_NONOTIFY = 0x0080;

    // Menu Command IDs
    private const uint CMD_OPEN = 1001;
    private const uint CMD_PROFILE_HIGH = 1010;
    private const uint CMD_PROFILE_MEDIUM = 1011;
    private const uint CMD_PROFILE_LOW = 1012;
    private const uint CMD_PROFILE_NONE = 1013;
    private const uint CMD_NOTIF_DISABLED = 1020;
    private const uint CMD_NOTIF_DISPLAY = 1021;
    private const uint CMD_NOTIF_LOW = 1022;
    private const uint CMD_NOTIF_LEARNING = 1023;
    private const uint CMD_NAV_RULES = 1030;
    private const uint CMD_NAV_CONNECTIONS = 1031;
    private const uint CMD_EXIT = 1099;

    private readonly IntPtr _hwnd;
    private readonly uint _taskbarCreatedMsg;
    private readonly SubclassProc _subclassDelegate;
    private IntPtr _currentIcon;
    private FirewallProfileMode _currentProfile = FirewallProfileMode.LowFiltering;
    private NotificationMode _currentNotif = NotificationMode.DisplayNotifications;
    private bool _iconAdded;
    private bool _disposed;

    public event Action? OpenRequested;
    public event Action<int, int>? ContextMenuRequested;

    private delegate IntPtr SubclassProc(
        IntPtr hWnd,
        uint uMsg,
        IntPtr wParam,
        IntPtr lParam,
        nuint uIdSubclass,
        nuint dwRefData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        public bool fIcon;
        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass, nuint dwRefData);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass);

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string lpString);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, nuint uIDNewItem, string? lpNewItem);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetMenuDefaultItem(IntPtr hMenu, uint uItem, uint fByPos);

    [DllImport("user32.dll")]
    private static extern uint TrackPopupMenuEx(IntPtr hMenu, uint uFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr CreateIconIndirect(ref ICONINFO piconinfo);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateBitmap(int nWidth, int nHeight, uint nPlanes, uint nBitCount, IntPtr lpBits);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr hObject);

    public TrayIconService(IntPtr hwnd)
    {
        _hwnd = hwnd;
        _taskbarCreatedMsg = RegisterWindowMessageW("TaskbarCreated");
        _subclassDelegate = WndProcSubclass;

        SetWindowSubclass(_hwnd, _subclassDelegate, 1, 0);
        AddOrUpdateIcon();
    }

    public void UpdateState(FirewallProfileMode profile, NotificationMode notif)
    {
        _currentProfile = profile;
        _currentNotif = notif;
        AddOrUpdateIcon();
    }

    public void ShowBalloonTip(string title, string message, bool silent = true)
    {
        if (_disposed || !_iconAdded) return;

        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hwnd,
            uID = 1,
            uFlags = NIF_INFO,
            szTip = string.Empty,
            szInfoTitle = title.Length > 63 ? title[..63] : title,
            szInfo = message.Length > 255 ? message[..255] : message,
            dwInfoFlags = NIIF_USER | (silent ? NIIF_NOSOUND : 0u),
            hBalloonIcon = _currentIcon
        };

        Shell_NotifyIconW(NIM_MODIFY, ref data);
    }

    private void AddOrUpdateIcon()
    {
        if (_disposed) return;

        var newIcon = CreateShieldIcon(_currentProfile);
        var tip = $"FireBrick — {FormatProfileName(_currentProfile)}";

        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hwnd,
            uID = 1,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAYICON,
            hIcon = newIcon,
            szTip = tip,
            szInfo = string.Empty,
            szInfoTitle = string.Empty
        };

        if (!_iconAdded)
        {
            _iconAdded = Shell_NotifyIconW(NIM_ADD, ref data);
        }
        else
        {
            Shell_NotifyIconW(NIM_MODIFY, ref data);
        }

        if (_currentIcon != IntPtr.Zero)
        {
            DestroyIcon(_currentIcon);
        }
        _currentIcon = newIcon;
    }

    private IntPtr WndProcSubclass(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, nuint uIdSubclass, nuint dwRefData)
    {
        if (uMsg == WM_TRAYICON)
        {
            uint mouseMsg = (uint)((ulong)lParam & 0xFFFF);
            if (mouseMsg == WM_LBUTTONUP || mouseMsg == WM_LBUTTONDBLCLK)
            {
                OpenRequested?.Invoke();
                return IntPtr.Zero;
            }
            if (mouseMsg == WM_RBUTTONUP || mouseMsg == WM_CONTEXTMENU)
            {
                GetCursorPos(out var pt);
                ContextMenuRequested?.Invoke(pt.X, pt.Y);
                return IntPtr.Zero;
            }
        }
        else if (_taskbarCreatedMsg != 0 && uMsg == _taskbarCreatedMsg)
        {
            // Explorer restarted — re-register tray icon
            _iconAdded = false;
            AddOrUpdateIcon();
        }

        return DefSubclassProc(hWnd, uMsg, wParam, lParam);
    }

    private static string FormatProfileName(FirewallProfileMode mode) => mode switch
    {
        FirewallProfileMode.HighFiltering => "High Filtering",
        FirewallProfileMode.MediumFiltering => "Medium Filtering",
        FirewallProfileMode.LowFiltering => "Low Filtering",
        FirewallProfileMode.NoFiltering => "No Filtering",
        _ => mode.ToString()
    };

    /// <summary>
    /// Generates a 2x2 supersampled, anti-aliased 32x32 ARGB two-tone interlocking brick-shield icon
    /// matching FireBrick's B2 silhouette (without the flame), color-coded by filtering profile:
    /// Blue = High, Green = Medium, Orange = Low, Red = No Filtering.
    /// </summary>
    private static IntPtr CreateShieldIcon(FirewallProfileMode mode)
    {
        const int size = 32;
        const int ss = 2; // 2x2 supersampling for silky anti-aliased edges
        const int hi = size * ss;

        // (TopLight RGB, TopDark RGB, BotLight RGB, BotDark RGB)
        var palette = mode switch
        {
            FirewallProfileMode.HighFiltering => (
                TR1: 96, TG1: 165, TB1: 250,   // #60A5FA
                TR2: 59, TG2: 130, TB2: 246,   // #3B82F6
                BR1: 37, BG1: 99,  BB1: 235,   // #2563EB
                BR2: 29, BG2: 78,  BB2: 216),  // #1D4ED8
            FirewallProfileMode.MediumFiltering => (
                TR1: 74, TG1: 222, TB1: 128,   // #4ADE80
                TR2: 34, TG2: 197, TB2: 94,    // #22C55E
                BR1: 22, BG1: 163, BB1: 74,    // #16A34A
                BR2: 21, BG2: 128, BB2: 61),   // #15803D
            FirewallProfileMode.LowFiltering => (
                TR1: 251, TG1: 191, TB1: 36,   // #FBBF24
                TR2: 245, TG2: 158, TB2: 11,   // #F59E0B
                BR1: 234, BG1: 88,  BB1: 12,   // #EA580C
                BR2: 194, BG2: 65,  BB2: 12),  // #C2410C
            _ => (
                TR1: 248, TG1: 113, TB1: 113,  // #F87171
                TR2: 239, TG2: 68,  TB2: 68,   // #EF4444
                BR1: 220, BG1: 38,  BB1: 38,   // #DC2626
                BR2: 153, BG2: 27,  BB2: 27)   // #991B1B
        };

        var pixels = new byte[size * size * 4];
        var maskBits = new byte[(size / 8) * size];

        static double ShieldHalfWidth(double nx, double ny)
        {
            // Normalized coordinates: ny in [0..1], center nx = 0.5
            if (ny < 0.06 || ny > 0.94) return -1;

            // Angled top crest (B2 roof): peaks at (0.5, 0.06), shoulders at (0.12/0.88, 0.22)
            if (ny < 0.22)
            {
                double t = (ny - 0.06) / 0.16;
                return 0.38 * t;
            }

            // Straight vertical upper sides down to ny = 0.52
            if (ny <= 0.52)
                return 0.38;

            // Smooth curved taper to bottom tip at ny = 0.94
            double u = (ny - 0.52) / 0.42;
            return 0.38 * Math.Sqrt(Math.Max(0, 1.0 - u * u * 0.96)) * (1.0 - 0.22 * u * u);
        }

        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                double accR = 0, accG = 0, accB = 0, accA = 0;

                for (int sy = 0; sy < ss; sy++)
                {
                    for (int sx = 0; sx < ss; sx++)
                    {
                        double nx = (x * ss + sx + 0.5) / hi;
                        double ny = (y * ss + sy + 0.5) / hi;
                        double dx = Math.Abs(nx - 0.5);
                        double hw = ShieldHalfWidth(nx, ny);

                        if (hw <= 0 || dx > hw)
                            continue;

                        // B2 interlocking brick seam: horizontal at ny=0.51, stepping down to ny=0.59 in center band
                        double seamY = dx < 0.20 ? 0.59 : 0.51;
                        bool isVerticalStep = Math.Abs(dx - 0.20) < 0.022 && ny >= 0.50 && ny <= 0.60;
                        bool isHorizontalSeam = Math.Abs(ny - seamY) < 0.022;
                        bool isSeam = isVerticalStep || isHorizontalSeam;

                        // Top bevel highlight
                        bool isTopHighlight = ny < 0.24 && (hw - dx < 0.045 || ny < 0.11);
                        bool isOuterRim = (hw - dx) < 0.026 || ny > 0.91;

                        double sr, sg, sb;
                        if (isSeam)
                        {
                            // Crisp dark interlocking groove
                            sr = palette.BR2 * 0.42;
                            sg = palette.BG2 * 0.42;
                            sb = palette.BB2 * 0.42;
                        }
                        else if (ny < seamY)
                        {
                            // Upper lighter brick plate
                            double t = Math.Clamp((ny - 0.06) / 0.52, 0, 1);
                            sr = palette.TR1 + (palette.TR2 - palette.TR1) * t;
                            sg = palette.TG1 + (palette.TG2 - palette.TG1) * t;
                            sb = palette.TB1 + (palette.TB2 - palette.TB1) * t;
                            if (isTopHighlight)
                            {
                                sr = Math.Min(255, sr + 38);
                                sg = Math.Min(255, sg + 38);
                                sb = Math.Min(255, sb + 38);
                            }
                        }
                        else
                        {
                            // Lower deeper brick plate
                            double t = Math.Clamp((ny - 0.50) / 0.44, 0, 1);
                            sr = palette.BR1 + (palette.BR2 - palette.BR1) * t;
                            sg = palette.BG1 + (palette.BG2 - palette.BG1) * t;
                            sb = palette.BB1 + (palette.BB2 - palette.BB1) * t;
                        }

                        if (isOuterRim && !isTopHighlight)
                        {
                            sr = Math.Min(255, sr * 1.12);
                            sg = Math.Min(255, sg * 1.12);
                            sb = Math.Min(255, sb * 1.12);
                        }

                        accR += sr;
                        accG += sg;
                        accB += sb;
                        accA += 255.0;
                    }
                }

                double samples = ss * ss;
                int idx = (y * size + x) * 4;
                if (accA > 0)
                {
                    double coverage = accA / (samples * 255.0);
                    double invHits = 255.0 / accA;
                    pixels[idx + 0] = (byte)Math.Clamp(accB * invHits, 0, 255);
                    pixels[idx + 1] = (byte)Math.Clamp(accG * invHits, 0, 255);
                    pixels[idx + 2] = (byte)Math.Clamp(accR * invHits, 0, 255);
                    pixels[idx + 3] = (byte)Math.Clamp(coverage * 255.0, 0, 255);
                }
                else
                {
                    maskBits[y * (size / 8) + (x / 8)] |= (byte)(0x80 >> (x % 8));
                }
            }
        }

        var colorHandle = GCHandle.Alloc(pixels, GCHandleType.Pinned);
        var maskHandle = GCHandle.Alloc(maskBits, GCHandleType.Pinned);
        IntPtr hbmColor = IntPtr.Zero;
        IntPtr hbmMask = IntPtr.Zero;
        try
        {
            hbmColor = CreateBitmap(size, size, 1, 32, colorHandle.AddrOfPinnedObject());
            hbmMask = CreateBitmap(size, size, 1, 1, maskHandle.AddrOfPinnedObject());

            var iconInfo = new ICONINFO
            {
                fIcon = true,
                xHotspot = 0,
                yHotspot = 0,
                hbmMask = hbmMask,
                hbmColor = hbmColor
            };

            return CreateIconIndirect(ref iconInfo);
        }
        finally
        {
            if (hbmColor != IntPtr.Zero) DeleteObject(hbmColor);
            if (hbmMask != IntPtr.Zero) DeleteObject(hbmMask);
            colorHandle.Free();
            maskHandle.Free();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_iconAdded)
        {
            var data = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hwnd,
                uID = 1,
                szTip = string.Empty,
                szInfo = string.Empty,
                szInfoTitle = string.Empty
            };
            Shell_NotifyIconW(NIM_DELETE, ref data);
            _iconAdded = false;
        }

        RemoveWindowSubclass(_hwnd, _subclassDelegate, 1);

        if (_currentIcon != IntPtr.Zero)
        {
            DestroyIcon(_currentIcon);
            _currentIcon = IntPtr.Zero;
        }
    }
}
