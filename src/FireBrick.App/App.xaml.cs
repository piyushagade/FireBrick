using System.Threading;
using FireBrick.App.Services;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;

namespace FireBrick.App;

public partial class App : Application
{
    private const string SingleInstanceMutexName = @"Local\FireBrick_SingleInstance_Mutex_v1";
    private const string ActivateEventName = @"Local\FireBrick_ActivateExisting_Event_v1";

    private Mutex? _instanceMutex;
    private EventWaitHandle? _activateEvent;
    private CancellationTokenSource? _activateListenerCts;
    private MainWindow? _mainWindow;

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
        // Handle Explorer shell context menu verbs first
        var cmdArgs = Environment.GetCommandLineArgs();
        bool isShellVerb = cmdArgs.Length >= 3 && (cmdArgs[1] == "--allow" || cmdArgs[1] == "--block");

        _instanceMutex = new Mutex(true, SingleInstanceMutexName, out bool createdNew);

        if (!createdNew)
        {
            // Another instance is already running
            if (isShellVerb)
            {
                await FirewallBackendService.Instance.InitializeAsync();
                var action = cmdArgs[1] == "--allow" ? RuleAction.Allow : RuleAction.Block;
                try { await FirewallBackendService.Instance.CreateQuickRuleAsync(cmdArgs[2], action, RuleDirection.Outbound); } catch { }
            }
            else
            {
                // Signal existing instance to restore and focus its window
                try
                {
                    using var evt = EventWaitHandle.OpenExisting(ActivateEventName);
                    evt.Set();
                }
                catch { }
            }

            Environment.Exit(0);
            return;
        }

        await FirewallBackendService.Instance.InitializeAsync();

        if (isShellVerb)
        {
            var action = cmdArgs[1] == "--allow" ? RuleAction.Allow : RuleAction.Block;
            try { await FirewallBackendService.Instance.CreateQuickRuleAsync(cmdArgs[2], action, RuleDirection.Outbound); } catch { }
        }

        _mainWindow = new MainWindow();
        StartActivationListener();

        if (FirewallBackendService.Instance.GetSettings().StartMinimizedToTray)
        {
            _mainWindow.HideToTray(
                "FireBrick is running in the tray",
                "Click the FireBrick shield icon in your system tray to open the dashboard or switch filtering profiles.");
        }
        else
        {
            _mainWindow.Activate();
        }
    }

    private void StartActivationListener()
    {
        _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateEventName);
        _activateListenerCts = new CancellationTokenSource();
        var token = _activateListenerCts.Token;

        var thread = new Thread(() =>
        {
            var handles = new WaitHandle[] { _activateEvent, token.WaitHandle };
            while (!token.IsCancellationRequested)
            {
                int signaled = WaitHandle.WaitAny(handles);
                if (signaled == 0)
                {
                    _mainWindow?.DispatcherQueue.TryEnqueue(() => _mainWindow.RestoreFromTray());
                }
                else
                {
                    break;
                }
            }
        })
        {
            IsBackground = true,
            Name = "FireBrick.SingleInstanceListener"
        };
        thread.Start();
    }

    public void ReleaseSingleInstanceLock()
    {
        try { _activateListenerCts?.Cancel(); } catch { }
        try { _activateEvent?.Dispose(); } catch { }
        try { _instanceMutex?.ReleaseMutex(); } catch { }
        try { _instanceMutex?.Dispose(); } catch { }
    }
}
