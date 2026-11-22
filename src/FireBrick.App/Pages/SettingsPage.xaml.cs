using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Windows.ApplicationModel.DataTransfer;

namespace FireBrick.App.Pages;

public sealed partial class SettingsPage : Page
{
    private bool _loading = true;

    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadSettings();
    }

    private void LoadSettings()
    {
        _loading = true;
        try
        {
            var cfg = FirewallBackendService.Instance.GetSettings();

            for (int i = 0; i < ThemeCombo.Items.Count; i++)
            {
                if (ThemeCombo.Items[i] is ComboBoxItem item && (string?)item.Tag == cfg.Theme)
                {
                    ThemeCombo.SelectedIndex = i;
                    break;
                }
            }

            ReverseDnsToggle.IsOn = cfg.EnableReverseDns;
            GeoIpToggle.IsOn = cfg.EnableGeoIpLookup;
            KillOnBlockToggle.IsOn = cfg.KillConnectionsOnBlock;
            DefaultTempMinsBox.Value = cfg.DefaultTempRuleMinutes;
            CloseToTrayToggle.IsOn = cfg.CloseToTray;
            StartMinimizedToggle.IsOn = cfg.StartMinimizedToTray;
            StartWithWindowsToggle.IsOn = StartupManager.IsStartWithWindowsEnabled();
            ShellMenuToggle.IsOn = ShellContextMenuManager.IsInstalled();

            var svc = FirewallBackendService.Instance;
            var svcState = StartupManager.QueryServiceState();
            PrivilegeStatusText.Text =
                $"Service Status: {svcState} (IPC: {(svc.IsUsingService ? "Connected" : "Local Fallback")})   •   " +
                $"UI Process Elevated: {(svc.IsElevated ? "Yes (Administrator)" : "No (Standard User)")}";

            var ver = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
            AboutVersionText.Text = $"FireBrick v{ver}   •   {RuntimeInformation.FrameworkDescription}   •   {Environment.OSVersion}";
        }
        finally
        {
            _loading = false;
        }
    }

    private void ThemeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        var tag = (ThemeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "System";
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.Theme = tag;
        FirewallBackendService.Instance.SaveSettings(cfg);

        if (XamlRoot?.Content is FrameworkElement root)
        {
            root.RequestedTheme = tag switch
            {
                "Dark" => ElementTheme.Dark,
                "Light" => ElementTheme.Light,
                _ => ElementTheme.Default
            };
        }
    }

    private void ReverseDnsToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.EnableReverseDns = ReverseDnsToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void GeoIpToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.EnableGeoIpLookup = GeoIpToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void KillOnBlockToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.KillConnectionsOnBlock = KillOnBlockToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void StartWithWindowsToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try
        {
            StartupManager.SetStartWithWindows(StartWithWindowsToggle.IsOn);
            var cfg = FirewallBackendService.Instance.GetSettings();
            cfg.StartWithWindows = StartWithWindowsToggle.IsOn;
            FirewallBackendService.Instance.SaveSettings(cfg);
            ShowInfo(InfoBarSeverity.Success,
                StartWithWindowsToggle.IsOn ? "Startup Enabled" : "Startup Disabled",
                StartWithWindowsToggle.IsOn ? "FireBrick will start automatically when you sign in." : "Removed FireBrick from Windows startup.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Startup Update Failed", ex.Message);
        }
    }

    private void StartServiceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StartupManager.RunElevatedScCommand("start FireBrickService");
            ShowInfo(InfoBarSeverity.Success, "Starting FireBrickService", "Requested service start via sc.exe.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Start Service Failed", ex.Message);
        }
    }

    private void StopServiceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StartupManager.RunElevatedScCommand("stop FireBrickService");
            ShowInfo(InfoBarSeverity.Informational, "Stopping FireBrickService", "Requested service stop via sc.exe.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Stop Service Failed", ex.Message);
        }
    }

    private void UninstallServiceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"sc.exe stop FireBrickService; Start-Sleep -Seconds 1; sc.exe delete FireBrickService\"",
                UseShellExecute = true,
                Verb = "runas"
            });
            ShowInfo(InfoBarSeverity.Informational, "Uninstall Initiated", "Stopping and removing FireBrickService.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Uninstall Failed", ex.Message);
        }
    }

    private void DefaultTempMinsBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_loading || double.IsNaN(args.NewValue)) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.DefaultTempRuleMinutes = Math.Clamp((int)args.NewValue, 1, 1440);
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void CloseToTrayToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.CloseToTray = CloseToTrayToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void StartMinimizedToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var cfg = FirewallBackendService.Instance.GetSettings();
        cfg.StartMinimizedToTray = StartMinimizedToggle.IsOn;
        FirewallBackendService.Instance.SaveSettings(cfg);
    }

    private void ShellMenuToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try
        {
            if (ShellMenuToggle.IsOn)
            {
                var exe = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(exe))
                {
                    ShellContextMenuManager.Install(exe);
                    ShowInfo(InfoBarSeverity.Success, "Shell Integration Enabled", "Right-click any .exe file in Explorer to Allow or Block it with FireBrick.");
                }
            }
            else
            {
                ShellContextMenuManager.Uninstall();
                ShowInfo(InfoBarSeverity.Informational, "Shell Integration Disabled", "Removed FireBrick Explorer context menu entries.");
            }
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Shell Integration Failed", ex.Message);
        }
    }

    private async void EnableAuditButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            bool ok = await FirewallBackendService.Instance.EnableAuditPolicyAsync();
            ShowInfo(ok ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                ok ? "WFP Auditing Enabled" : "Could Not Enable Auditing",
                ok ? "Windows Filtering Platform connection auditing is now active." : "Administrator privileges are required to modify audit policy.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Error", ex.Message);
        }
    }

    private void RelaunchAdminButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            FirewallBackendService.RelaunchAsAdministrator();
            Application.Current.Exit();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Warning, "Elevation Cancelled", ex.Message);
        }
    }

    private string FindServiceExePath()
    {
        var appDir = AppContext.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(appDir, "FireBrick.Service.exe"),
            Path.Combine(appDir, "service", "FireBrick.Service.exe")
        ];

        foreach (var path in candidates)
        {
            if (File.Exists(path)) return path;
        }

        return string.Empty;
    }

    private string BuildServiceInstallCommand(string? serviceExePath = null)
    {
        var path = string.IsNullOrEmpty(serviceExePath) ? @"<path>\FireBrick.Service.exe" : serviceExePath;
        return $"sc.exe create FireBrickService binPath= \"{path}\" start= auto; sc.exe start FireBrickService";
    }

    private void CopyTextToClipboard(string text)
    {
        var pkg = new DataPackage();
        pkg.SetText(text);
        Clipboard.SetContent(pkg);
        Clipboard.Flush();
    }

    private void CopyServiceCommandButton_Click(object sender, RoutedEventArgs e)
    {
        var exePath = FindServiceExePath();
        var cmd = BuildServiceInstallCommand(exePath);
        CopyTextToClipboard(cmd);
        ShowInfo(InfoBarSeverity.Success, "Command Copied to Clipboard", cmd);
    }

    private void InstallServiceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var candidate = FindServiceExePath();
            var cmd = BuildServiceInstallCommand(candidate);

            if (string.IsNullOrEmpty(candidate))
            {
                var copyBtn = new Button { Content = "Copy Command" };
                copyBtn.Click += (_, _) =>
                {
                    CopyTextToClipboard(cmd);
                    copyBtn.Content = "Copied!";
                };

                ShowInfo(InfoBarSeverity.Informational, "Service Binary Location",
                    $"Build FireBrick.Service and install it via elevated PowerShell:\n{cmd}",
                    copyBtn);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{cmd.Replace("\"", "\\\"")}\"",
                UseShellExecute = true,
                Verb = "runas"
            });

            var copyAction = new Button { Content = "Copy Command" };
            copyAction.Click += (_, _) =>
            {
                CopyTextToClipboard(cmd);
                copyAction.Content = "Copied!";
            };

            ShowInfo(InfoBarSeverity.Success, "Service Install Initiated",
                $"Installing and starting FireBrickService from {candidate}",
                copyAction);
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Service Install Failed", ex.Message);
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message, ButtonBase? actionButton = null)
    {
        SettingsInfoBar.Severity = severity;
        SettingsInfoBar.Title = title;
        SettingsInfoBar.Message = message;
        SettingsInfoBar.ActionButton = actionButton;
        SettingsInfoBar.IsOpen = true;
    }
}
