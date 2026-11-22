using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage;
using Windows.Storage.FileProperties;

namespace FireBrick.App.Services;

/// <summary>
/// Extracts and caches WinUI 3 <see cref="ImageSource"/> icons for Windows executables.
/// Uses WinRT shell thumbnails first (DPI-aware, modern icons) and falls back to Win32 SHGetFileInfoW.
/// Must be called from the UI thread.
/// </summary>
public static class AppIconHelper
{
    private const int MaxCacheEntries = 256;

    private const uint SHGFI_ICON = 0x000000100;
    private const uint SHGFI_LARGEICON = 0x000000000;
    private const uint BI_RGB = 0;
    private const uint DIB_RGB_COLORS = 0;

    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool fIcon;
        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAP
    {
        public int bmType;
        public int bmWidth;
        public int bmHeight;
        public int bmWidthBytes;
        public ushort bmPlanes;
        public ushort bmBitsPixel;
        public IntPtr bmBits;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfoW(
        string pszPath,
        uint dwFileAttributes,
        out SHFILEINFOW psfi,
        uint cbFileInfo,
        uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIconInfo(IntPtr hIcon, out ICONINFO piconinfo);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int GetObject(IntPtr hgdiobj, int cbBuffer, out BITMAP lpvObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int GetDIBits(
        IntPtr hdc,
        IntPtr hbm,
        uint start,
        uint cLines,
        [Out] byte[] lpvBits,
        ref BITMAPINFOHEADER lpbmi,
        uint usage);

    public static bool TryGetCachedIcon(string? appPath, out ImageSource? icon)
    {
        if (string.IsNullOrWhiteSpace(appPath))
        {
            icon = null;
            return true;
        }

        return Cache.TryGetValue(appPath.Trim(), out icon);
    }

    public static async Task<ImageSource?> GetAppIconAsync(string? appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath))
            return null;

        var normalized = appPath.Trim();
        if (Cache.TryGetValue(normalized, out var cached))
            return cached;

        ImageSource? icon = null;

        if (Path.IsPathRooted(normalized))
        {
            icon = await TryLoadViaStorageThumbnailAsync(normalized);
            icon ??= await TryLoadViaShellAsync(normalized);
        }

        if (Cache.Count >= MaxCacheEntries)
            Cache.Clear();

        Cache[normalized] = icon;
        return icon;
    }

    private static async Task<ImageSource?> TryLoadViaStorageThumbnailAsync(string path)
    {
        try
        {
            var file = await StorageFile.GetFileFromPathAsync(path);
            using var thumbnail = await file.GetThumbnailAsync(
                ThumbnailMode.SingleItem,
                32,
                ThumbnailOptions.UseCurrentScale);

            if (thumbnail is null || thumbnail.Size == 0)
                return null;

            var bitmap = new BitmapImage();
            await bitmap.SetSourceAsync(thumbnail);
            return bitmap;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<ImageSource?> TryLoadViaShellAsync(string path)
    {
        var extracted = await Task.Run(() => ExtractIconPixels(path));
        if (extracted is null)
            return null;

        var (width, height, pixels) = extracted.Value;
        var wb = new WriteableBitmap(width, height);
        using (var stream = wb.PixelBuffer.AsStream())
        {
            stream.Write(pixels, 0, pixels.Length);
        }
        wb.Invalidate();
        return wb;
    }

    private static (int Width, int Height, byte[] Pixels)? ExtractIconPixels(string path)
    {
        var result = SHGetFileInfoW(
            path,
            0,
            out var shfi,
            (uint)Marshal.SizeOf<SHFILEINFOW>(),
            SHGFI_ICON | SHGFI_LARGEICON);

        if (result == IntPtr.Zero || shfi.hIcon == IntPtr.Zero)
            return null;

        try
        {
            if (!GetIconInfo(shfi.hIcon, out var iconInfo))
                return null;

            try
            {
                if (iconInfo.hbmColor == IntPtr.Zero)
                    return null;

                if (GetObject(iconInfo.hbmColor, Marshal.SizeOf<BITMAP>(), out var bmp) == 0)
                    return null;

                int width = bmp.bmWidth;
                int height = Math.Abs(bmp.bmHeight);
                if (width <= 0 || height <= 0 || width > 256 || height > 256)
                    return null;

                var pixels = new byte[width * height * 4];
                var bmi = new BITMAPINFOHEADER
                {
                    biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                    biWidth = width,
                    biHeight = -height, // top-down DIB
                    biPlanes = 1,
                    biBitCount = 32,
                    biCompression = BI_RGB
                };

                var hdc = GetDC(IntPtr.Zero);
                if (hdc == IntPtr.Zero)
                    return null;

                try
                {
                    if (GetDIBits(hdc, iconInfo.hbmColor, 0, (uint)height, pixels, ref bmi, DIB_RGB_COLORS) == 0)
                        return null;

                    bool hasAlpha = false;
                    for (int i = 3; i < pixels.Length; i += 4)
                    {
                        if (pixels[i] != 0)
                        {
                            hasAlpha = true;
                            break;
                        }
                    }

                    if (!hasAlpha && iconInfo.hbmMask != IntPtr.Zero)
                    {
                        var maskPixels = new byte[width * height * 4];
                        var maskBmi = bmi;
                        if (GetDIBits(hdc, iconInfo.hbmMask, 0, (uint)height, maskPixels, ref maskBmi, DIB_RGB_COLORS) != 0)
                        {
                            for (int i = 0; i < pixels.Length; i += 4)
                            {
                                // Mask bit 0 = opaque, non-zero = transparent
                                pixels[i + 3] = maskPixels[i] == 0 ? (byte)255 : (byte)0;
                            }
                        }
                    }

                    // Premultiply RGB by alpha for WinUI WriteableBitmap (BGRA8 premultiplied)
                    for (int i = 0; i < pixels.Length; i += 4)
                    {
                        byte a = pixels[i + 3];
                        if (a == 0)
                        {
                            pixels[i] = 0;
                            pixels[i + 1] = 0;
                            pixels[i + 2] = 0;
                        }
                        else if (a < 255)
                        {
                            pixels[i] = (byte)((pixels[i] * a + 127) / 255);
                            pixels[i + 1] = (byte)((pixels[i + 1] * a + 127) / 255);
                            pixels[i + 2] = (byte)((pixels[i + 2] * a + 127) / 255);
                        }
                    }

                    return (width, height, pixels);
                }
                finally
                {
                    ReleaseDC(IntPtr.Zero, hdc);
                }
            }
            finally
            {
                if (iconInfo.hbmColor != IntPtr.Zero) DeleteObject(iconInfo.hbmColor);
                if (iconInfo.hbmMask != IntPtr.Zero) DeleteObject(iconInfo.hbmMask);
            }
        }
        finally
        {
            DestroyIcon(shfi.hIcon);
        }
    }
}
