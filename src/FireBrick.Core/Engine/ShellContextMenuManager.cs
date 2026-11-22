using Microsoft.Win32;

namespace FireBrick.Core.Engine;

/// <summary>
/// Manages Windows Explorer right-click context menu integration for .exe files
/// (replicating classic WFC Shell Integration: Allow / Block through Firewall).
/// Uses HKCU\Software\Classes\exefile\shell so it works cleanly per-user.
/// </summary>
public static class ShellContextMenuManager
{
    private const string AllowKeyPath = @"Software\Classes\exefile\shell\FireBrickAllow";
    private const string BlockKeyPath = @"Software\Classes\exefile\shell\FireBrickBlock";

    public static bool IsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(AllowKeyPath);
        return key != null;
    }

    public static void Install(string fireBrickAppExePath)
    {
        CreateVerb(AllowKeyPath, "FireBrick: Allow through Firewall", $"\"{fireBrickAppExePath}\" --allow \"%1\"");
        CreateVerb(BlockKeyPath, "FireBrick: Block in Firewall", $"\"{fireBrickAppExePath}\" --block \"%1\"");
    }

    public static void Uninstall()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(AllowKeyPath, throwOnMissingSubKey: false); } catch { }
        try { Registry.CurrentUser.DeleteSubKeyTree(BlockKeyPath, throwOnMissingSubKey: false); } catch { }
    }

    private static void CreateVerb(string keyPath, string label, string command)
    {
        using var key = Registry.CurrentUser.CreateSubKey(keyPath);
        key.SetValue(string.Empty, label);
        using var cmdKey = key.CreateSubKey("command");
        cmdKey.SetValue(string.Empty, command);
    }
}
