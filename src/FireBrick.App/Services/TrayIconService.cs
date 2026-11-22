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
    /// Generates a crisp 32x32 ARGB shield icon colored by the active filtering profile.
    /// </summary>
    private static IntPtr CreateShieldIcon(FirewallProfileMode mode)
    {
        const int size = 32;
        var (r, g, b) = mode switch
        {
            FirewallProfileMode.HighFiltering => ((byte)0xE8, (byte)0x11, (byte)0x23),   // Vivid Red (Lockdown)
            FirewallProfileMode.MediumFiltering => ((byte)0xF5, (byte)0x9E, (byte)0x0B), // Vivid Amber (Recommended)
            FirewallProfileMode.LowFiltering => ((byte)0x10, (byte)0xB9, (byte)0x81),    // Emerald Green (Default)
            _ => ((byte)0x88, (byte)0x8E, (byte)0x96)                                    // Neutral Gray (Disabled)
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
