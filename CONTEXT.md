# FireBrick — Project Context & Architecture Guide

**FireBrick** is a modern **WinUI 3 (.NET 8)** replication and evolution of **Windows Firewall Control (WFC)** built on top of Windows Defender Firewall (`INetFwPolicy2`) and Windows Filtering Platform (WFP) — requiring no kernel driver or EV code signing.

- **Repository**: `https://github.com/piyushagade/FireBrick.git` (`main`)
- **Current Version**: Defined centrally in `Directory.Build.props` (`VersionPrefix`, currently `1.1.0`)
- **Target Platform**: Windows 10/11 (`net8.0-windows10.0.19041.0`, `win-x64`, unpackaged WinUI 3 with `WindowsPackageType=None` and `WindowsAppSDKSelfContained=true`)

---

## Solution Structure

```text
FireBrick/
├── Directory.Build.props            # Single source of truth for Version, AssemblyVersion, FileVersion, Product metadata
├── FireBrick.sln
├── NuGet.config                     # Self-contained nuget.org source config
├── src/
│   ├── FireBrick.Core/              # Shared firewall engine, COM interop, WFP/socket monitors, IPC protocol
│   ├── FireBrick.Service/           # Privileged Windows Service (LocalSystem) hosting Named Pipe IPC & background guards
│   └── FireBrick.App/               # Unpackaged WinUI 3 Fluent Desktop + System Tray app
└── tests/
    └── FireBrick.Tests/             # xUnit unit & live Windows integration tests (11 tests)
```

---

## Core Architecture & Key Files

### 1. `src/FireBrick.Core`
- **`Models/FirewallModels.cs`**: All enums (`FirewallProfileMode`, `NotificationMode`, `RuleDirection`, `RuleAction`, `FirewallProfileFlags`, `SignatureTrustStatus`) and DTOs (`FirewallRuleDto`, `ConnectionEventDto`, `ActiveConnectionDto`, `TemporaryRuleDto`, `FirewallStatusDto`, `AppSettingsDto`, `GeoIpInfoDto`, `AppGroupSummaryDto`, `NetworkProfileRuleDto`, `BlocklistSubscriptionDto`, `RuleLockAlertDto`, `TopAppStatDto`, `ActivityBucketDto`).
  - `FirewallRuleDto.DisplayName` / `DisplayGrouping` automatically clean up UWP/MSIX indirect strings (`@{Package_version?ms-resource://...}`).
- **`Interop/NetFwInterop.cs`**: Strongly-typed `[ComImport]` interfaces for `INetFwPolicy2`, `INetFwRules`, and `INetFwRule` (`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`).
  - **Important**: `INetFwRule` vtable slots must match Windows SDK `netfw.h` exactly (`Direction` is slot 11, right after `IcmpTypesAndCodes`, before `Interfaces`).
- **`Engine/WindowsFirewallManager.cs`**:
  - Maps WFC's 4 filtering profiles (`HighFiltering`, `MediumFiltering`, `LowFiltering`, `NoFiltering`) to Windows Defender Firewall policies (`HighFiltering` also adds an explicit `FireBrick: High Filtering Outbound Block` lockdown rule).
  - Full rule CRUD, invalid/orphaned path scanner (`IsInvalidPath`), duplicate rule detector, and JSON export/import.
- **`Engine/SecurityAuditMonitor.cs`** & **`Engine/DevicePathConverter.cs`**:
  - Subscribes to Windows Security Event Log WFP events (`5152` packet drop, `5156` allowed, `5157` blocked) and translates NT device paths (`\Device\HarddiskVolume3\...`) to Win32 paths via `QueryDosDeviceW`.
  - Normalizes kernel packet drops (`Application == "-"`, `PID 0`) to `System / Kernel` so they don't trigger blank app popups.
- **`Engine/LiveConnectionsMonitor.cs`** & **`Engine/TcpConnectionKiller.cs`**:
  - Enumerates live IPv4 TCP/UDP sockets with owning PIDs via `iphlpapi.dll` (`GetExtendedTcpTable` / `GetExtendedUdpTable`).
  - Terminates established IPv4 TCP sockets for a blocked executable via `SetTcpEntry` (`MIB_TCP_STATE_DELETE_TCB = 12`).
- **`Engine/AuthenticodeVerifier.cs`**: Cached `WinVerifyTrust` + `X509Certificate2` publisher verification.
- **`Engine/DnsResolverCache.cs`** & **`Engine/GeoIpResolverCache.cs`**: Throttled async reverse DNS (PTR) and public GeoIP/Org (`ip-api.com`) caches (skipping private/loopback/link-local IPs).
- **`Engine/TemporaryRuleManager.cs`**: Persists auto-expiring temporary rules (`%ProgramData%\FireBrick\temporary_rules.json`).
- **`Engine/RuleLockMonitor.cs`**: Snapshots authorized rules and detects/reverts unauthorized external rule injections.
- **`Engine/NetworkProfileMonitor.cs`**: Detects active Wi-Fi SSID (`netsh wlan show interfaces`) or active network interface for automatic profile switching.
- **`Engine/BlocklistManager.cs`**: Resolves domain lists (via DNS) and remote IP/CIDR blocklists (e.g., Spamhaus DROP) into chunked `FireBrick Blocklist: <Name>` rules.
- **`Engine/StartupManager.cs`**: Manages HKCU `Run` startup registration, `FireBrickService` health inspection (`sc.exe query`/`qc`), one-click install/repair with Windows SCM auto-restart recovery (`sc.exe failure FireBrickService reset= 86400 actions= restart/5000/...`).
- **`Engine/ShellContextMenuManager.cs`**: Registers/removes HKCU Explorer `.exe` right-click context menu verbs (`--allow` / `--block`).
- **`Engine/AppAggregator.cs`**: Groups rules, live connections, and blocked events per application and builds Dashboard 60-minute activity buckets & Top Blocked Apps stats.
- **`Ipc/IpcProtocol.cs`** & **`Ipc/FireBrickIpcClient.cs`**: Length-prefixed JSON over Named Pipe `FireBrick_IPC_v1`.

### 2. `src/FireBrick.Service`
- **`Program.cs`** & **`FireBrickWorker.cs`**:
  - Runs as a Windows Service (`FireBrickService`, `LocalSystem`) with `PipeSecurity` granting `AuthenticatedUsers` ReadWrite access so standard-user UI can communicate without UAC prompts.
  - Runs continuous `SecurityAuditMonitor`, `LearningMode` auto-allow for trusted signed apps, 5-second temporary rule expiration loop, and 10-second protection loop (Rule Lock enforcement + Network SSID auto-switching).

### 3. `src/FireBrick.App` (WinUI 3)
- **`App.xaml.cs`**: Single-instance enforcement (`Local\FireBrick_SingleInstance_Mutex_v1` + `Local\FireBrick_ActivateExisting_Event_v1` to restore existing window), Explorer shell verb handling (`--allow`/`--block`), `UnhandledException` logger (`%LocalAppData%\FireBrick\crash.log`), and Start-Minimized tray toast hint.
- **`Services/FirewallBackendService.cs`**: Unified facade preferring `FireBrickService` over Named Pipes (with 5-second auto-reconnect and graceful in-process fallback), plus 2-second service event polling for real-time blocked connection prompts (filtering out raw Event `5152` / `PID 0` kernel drops).
- **`Services/TrayIconService.cs`**: Native Win32 `Shell_NotifyIconW` + `SetWindowSubclass` tray icon with dynamic profile-colored shield (`Red` = High, `Amber` = Medium, `Green` = Low, `Gray` = No Filtering), `TaskbarCreated` recovery, and `NIF_INFO` balloon/toast notifications.
- **`Windows/TrayFlyoutWindow.xaml(.cs)`**: Custom theme-aware WinUI 3 tray flyout using `WS_EX_NOACTIVATE` + `Show(activateWindow: false)` + `WH_MOUSE_LL` outside-click dismiss so the Windows 11 system tray overflow stays open; includes inline submenus for **Notifications** and **Go to...**.
- **`Windows/ConnectionAlertWindow.xaml(.cs)`**: Standalone, draggable, always-on-top bottom-right floating alert window with `1 of N` queue pager, Publisher Trust badge, Reverse DNS + GeoIP destination info, Rule Scope selector (`Any IP & port`, `Port only`, `IP & port`), Temp Allow split button, and `WM_NCLBUTTONDBLCLK` / `SC_MAXIMIZE` blocking.
- **`MainWindow.xaml(.cs)`**: Mica backdrop, custom extended title bar with live profile-colored shield, version badge, service/elevation status pill, `LeftCompact` sidebar (starts collapsed, persists `IsSidebarOpen`).
- **Pages**:
  - `DashboardPage`: Stat cards, 4 Filtering Profile cards, 4 Notification Mode cards, 60-min Activity Bar Chart, Top 5 Blocked Apps (with live `Allowed ✓` state), Windows Defender Firewall status pills, and 1-click Service Setup/Update banner.
  - `AppsPage`: Per-application grouped view with Allow, Block & Kill Sockets, and Inspect Rules.
  - `RulesPage`: Search, direction/action/state filters, inline enable toggle, Tools dropdown (Find Duplicates, Clean Invalid, Export/Import JSON), and Add/Edit Rule dialog.
  - `ConnectionsLogPage`: Dual-mode WFP Audit Log + Live TCP/UDP monitor with Reverse DNS, GeoIP/Org, and quick Allow / Temp Allow / Block / Kill actions.
  - `PresetsPage`: Built-in rule packs + live Temporary Rules manager with revoke.
  - `ProtectionPage`: Rule Lock toggle + alert history, Wi-Fi/Network Auto-Switch rules, and Domain/IP Blocklist subscriptions.
  - `SettingsPage`: Theme, Reverse DNS, GeoIP, Kill on Block, Default Temp Rule duration, Tray/Startup toggles, Explorer shell integration, WFP auditing enabler, full Service Manager, and About card.
  - `DonatePage`: Sidebar footer link (red heart icon above Settings) with Cash App (`$piyushagade`) and Venmo (`@piyushagade`) cards.

---

## Build, Test & Publish Commands

```powershell
# Run all unit & integration tests
dotnet test tests/FireBrick.Tests/FireBrick.Tests.csproj

# Publish Release WinUI 3 App and Service to dist/
dotnet publish src/FireBrick.App/FireBrick.App.csproj -c Release -r win-x64 -p:Platform=x64 -o dist
dotnet publish src/FireBrick.Service/FireBrick.Service.csproj -c Release -r win-x64 -o dist/service
```

> **Tip on Rebuilding Icons or Running Binaries**:
> - If `FireBrick.App.exe` is running, exit it from the tray first before publishing to `dist/`.
> - If `FireBrickService` is running from `dist\service\`, stop it (`sc.exe stop FireBrickService`) before overwriting `dist\service\`, or click **Update Service** on the Dashboard when running from a new folder.
> - After replacing `Assets\FireBrick.ico`, run `dotnet clean src/FireBrick.App/FireBrick.App.csproj -c Release -p:Platform=x64` before `dotnet publish` so MSBuild re-embeds the icon into the AppHost `.exe`.

---

## Persisted Data Locations

- **User Settings**: `%LocalAppData%\FireBrick\settings.json`
- **Crash Log**: `%LocalAppData%\FireBrick\crash.log`
- **Temporary Rules**: `%ProgramData%\FireBrick\temporary_rules.json`
- **Startup Registration**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (`FireBrick`)
- **Shell Context Menu**: `HKCU\Software\Classes\exefile\shell\FireBrickAllow` & `FireBrickBlock`
