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
    public event Action<string>? NavigateRequested;
    public event Action<FirewallProfileMode>? ProfileSwitchRequested;
    public event Action<NotificationMode>? NotificationSwitchRequested;
    public event Action? ExitRequested;

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
                ShowContextMenu();
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

    private void ShowContextMenu()
    {
        IntPtr menu = CreatePopupMenu();
        IntPtr notifSub = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;

        try
        {
            AppendMenuW(menu, MF_STRING, CMD_OPEN, "Open FireBrick");
            SetMenuDefaultItem(menu, CMD_OPEN, 0);
            AppendMenuW(menu, MF_SEPARATOR, 0, null);

            AppendMenuW(menu, MF_STRING | (_currentProfile == FirewallProfileMode.HighFiltering ? MF_CHECKED : 0), CMD_PROFILE_HIGH, "High Filtering (Lockdown)");
            AppendMenuW(menu, MF_STRING | (_currentProfile == FirewallProfileMode.MediumFiltering ? MF_CHECKED : 0), CMD_PROFILE_MEDIUM, "Medium Filtering (Recommended)");
            AppendMenuW(menu, MF_STRING | (_currentProfile == FirewallProfileMode.LowFiltering ? MF_CHECKED : 0), CMD_PROFILE_LOW, "Low Filtering (Default)");
            AppendMenuW(menu, MF_STRING | (_currentProfile == FirewallProfileMode.NoFiltering ? MF_CHECKED : 0), CMD_PROFILE_NONE, "No Filtering (Disabled)");

            AppendMenuW(menu, MF_SEPARATOR, 0, null);

            if (notifSub != IntPtr.Zero)
            {
                AppendMenuW(notifSub, MF_STRING | (_currentNotif == NotificationMode.Disabled ? MF_CHECKED : 0), CMD_NOTIF_DISABLED, "Disabled");
                AppendMenuW(notifSub, MF_STRING | (_currentNotif == NotificationMode.DisplayNotifications ? MF_CHECKED : 0), CMD_NOTIF_DISPLAY, "Display Notifications");
                AppendMenuW(notifSub, MF_STRING | (_currentNotif == NotificationMode.LowNotification ? MF_CHECKED : 0), CMD_NOTIF_LOW, "Low (Unsigned Only)");
                AppendMenuW(notifSub, MF_STRING | (_currentNotif == NotificationMode.LearningMode ? MF_CHECKED : 0), CMD_NOTIF_LEARNING, "Learning Mode");
                AppendMenuW(menu, MF_POPUP, (nuint)notifSub, "Notifications");
            }

            AppendMenuW(menu, MF_SEPARATOR, 0, null);
            AppendMenuW(menu, MF_STRING, CMD_NAV_RULES, "Firewall Rules...");
            AppendMenuW(menu, MF_STRING, CMD_NAV_CONNECTIONS, "Connections Log...");
            AppendMenuW(menu, MF_SEPARATOR, 0, null);
            AppendMenuW(menu, MF_STRING, CMD_EXIT, "Exit FireBrick");

            GetCursorPos(out var pt);
            SetForegroundWindow(_hwnd);

            uint cmd = TrackPopupMenuEx(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD | TPM_NONOTIFY, pt.X, pt.Y, _hwnd, IntPtr.Zero);
            HandleMenuCommand(cmd);
        }
        finally
        {
            DestroyMenu(menu);
            // notifSub is owned and destroyed by menu
        }
    }

    private void HandleMenuCommand(uint cmd)
    {
        switch (cmd)
        {
            case CMD_OPEN:
                OpenRequested?.Invoke();
                break;
            case CMD_PROFILE_HIGH:
                ProfileSwitchRequested?.Invoke(FirewallProfileMode.HighFiltering);
                break;
            case CMD_PROFILE_MEDIUM:
                ProfileSwitchRequested?.Invoke(FirewallProfileMode.MediumFiltering);
                break;
            case CMD_PROFILE_LOW:
                ProfileSwitchRequested?.Invoke(FirewallProfileMode.LowFiltering);
                break;
            case CMD_PROFILE_NONE:
                ProfileSwitchRequested?.Invoke(FirewallProfileMode.NoFiltering);
                break;
            case CMD_NOTIF_DISABLED:
                NotificationSwitchRequested?.Invoke(NotificationMode.Disabled);
                break;
            case CMD_NOTIF_DISPLAY:
                NotificationSwitchRequested?.Invoke(NotificationMode.DisplayNotifications);
                break;
            case CMD_NOTIF_LOW:
                NotificationSwitchRequested?.Invoke(NotificationMode.LowNotification);
                break;
            case CMD_NOTIF_LEARNING:
                NotificationSwitchRequested?.Invoke(NotificationMode.LearningMode);
                break;
            case CMD_NAV_RULES:
                OpenRequested?.Invoke();
                NavigateRequested?.Invoke("rules");
                break;
            case CMD_NAV_CONNECTIONS:
                OpenRequested?.Invoke();
                NavigateRequested?.Invoke("connections");
                break;
            case CMD_EXIT:
                ExitRequested?.Invoke();
                break;
        }
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
    /// Generates a crisp 32x32 ARGB shield icon colored by the active filtering profile.
    /// </summary>
    private static IntPtr CreateShieldIcon(FirewallProfileMode mode)
    {
        const int size = 32;
        var (r, g, b) = mode switch
        {
            FirewallProfileMode.HighFiltering => ((byte)0xD1, (byte)0x34, (byte)0x38),   // Red
            FirewallProfileMode.MediumFiltering => ((byte)0xE0, (byte)0x5A, (byte)0x2B), // FireBrick Orange
            FirewallProfileMode.LowFiltering => ((byte)0x10, (byte)0x89, (byte)0x3E),    // Green
            _ => ((byte)0x7A, (byte)0x7A, (byte)0x7A)                                    // Gray
        };

        var pixels = new byte[size * size * 4];
        var maskBits = new byte[(size / 8) * size];

        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                // Draw a clean shield silhouette centered at x=15.5
                double dx = Math.Abs(x - 15.5);
                double halfWidth;
                if (y < 3 || y > 29)
                {
                    halfWidth = -1;
                }
                else if (y < 6)
                {
                    // Gently curved top crest
                    halfWidth = 11.5;
                }
                else if (y <= 16)
                {
                    halfWidth = 11.5 - (y - 6) * 0.12;
                }
                else
                {
                    // Taper smoothly to bottom point
                    double t = (y - 16) / 13.0;
                    halfWidth = 10.3 * (1.0 - t * t);
                }

                bool inside = halfWidth > 0 && dx <= halfWidth;
                bool isBorder = inside && (dx > halfWidth - 2.0 || y <= 4 || y >= 28);

                int idx = (y * size + x) * 4;
                if (inside)
                {
                    if (isBorder)
                    {
                        pixels[idx + 0] = 0xFF; // B
                        pixels[idx + 1] = 0xFF; // G
                        pixels[idx + 2] = 0xFF; // R
                        pixels[idx + 3] = 0xF0; // A
                    }
                    else
                    {
                        // Subtle top-to-bottom shading
                        double shade = 1.0 - (y / 48.0);
                        pixels[idx + 0] = (byte)(b * shade);
                        pixels[idx + 1] = (byte)(g * shade);
                        pixels[idx + 2] = (byte)(r * shade);
                        pixels[idx + 3] = 0xFF;
                    }
                }
                else
                {
                    // Transparent pixel in mask
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
