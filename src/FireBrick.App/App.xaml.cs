using FireBrick.App.Services;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;

namespace FireBrick.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FireBrick");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.Message}\n{e.Exception}\n\n");
        }
        catch { }
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        await FirewallBackendService.Instance.InitializeAsync();

        // Support Explorer shell context menu CLI verbs: --allow "<exe>" or --block "<exe>"
        var cmdArgs = Environment.GetCommandLineArgs();
        if (cmdArgs.Length >= 3 && (cmdArgs[1] == "--allow" || cmdArgs[1] == "--block"))
        {
            var action = cmdArgs[1] == "--allow" ? RuleAction.Allow : RuleAction.Block;
            var targetPath = cmdArgs[2];
            try
            {
                await FirewallBackendService.Instance.CreateQuickRuleAsync(targetPath, action, RuleDirection.Outbound);
            }
            catch
            {
                // Fall through to launch UI so user sees elevation prompt if needed
            }
        }

        var mainWindow = new MainWindow();
        _window = mainWindow;

        if (FirewallBackendService.Instance.GetSettings().StartMinimizedToTray)
        {
            mainWindow.HideToTray();
        }
        else
        {
            mainWindow.Activate();
        }
    }
}
