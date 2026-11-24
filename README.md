# FireBrick

A modern **WinUI 3** replication and evolution of **Windows Firewall Control (WFC)** built on .NET 8, Windows Defender Firewall (`INetFwPolicy2`), and Windows Filtering Platform (WFP).

## Architecture

- **`src/FireBrick.Core`** — Shared firewall engine:
  - `WindowsFirewallManager`: WFC 4-profile policy controller (`High`, `Medium`, `Low`, `No Filtering`), full rule CRUD, invalid/orphaned rule scanner, duplicate rule detector, JSON export/import.
  - `SecurityAuditMonitor`: Real-time WFP Security Event Log watcher (`Event ID 5152 / 5156 / 5157`) with NT device-path conversion (`DevicePathConverter`).
  - `LiveConnectionsMonitor`: Live active TCP/UDP socket monitor with owning PID/process resolution via `iphlpapi.dll`.
  - `AuthenticodeVerifier`: WinTrust digital signature & publisher verification (powers unsigned-only notifications & trust badges).
  - `DnsResolverCache`: Throttled async reverse DNS (PTR) cache.
  - `TemporaryRuleManager`: Auto-expiring temporary rules (e.g., Allow for 15 minutes).
  - `PresetCatalog`: One-click rule packs (Core Networking, Privacy/Telemetry Block, Developer Essentials, Public Network Hardening).
  - `ShellContextMenuManager`: Classic WFC Windows Explorer `.exe` right-click context menu integration.
- **`src/FireBrick.Service`** — Privileged Windows Service (`LocalSystem`) hosting a Named Pipe IPC server (`FireBrick_IPC_v1`), continuous WFP event monitoring, Learning Mode auto-allow, and temporary rule expiration.
- **`src/FireBrick.App`** — Fluent WinUI 3 Desktop application (Mica backdrop, Dashboard, Rules Panel, Connections Log + Live TCP/UDP Monitor, Presets & Temporary Rules, Settings, and interactive blocked-connection prompts).
- **`tests/FireBrick.Tests`** — xUnit tests for core engines.

## Build & Run

```powershell
# Build entire solution (x64 for WinUI 3)
dotnet build FireBrick.sln -p:Platform=x64

# Run unit tests
dotnet test tests/FireBrick.Tests/FireBrick.Tests.csproj

# Launch FireBrick WinUI 3 app
dotnet run --project src/FireBrick.App/FireBrick.App.csproj -p:Platform=x64
```

### Optional: Install Background Service (Elevated PowerShell)

```powershell
dotnet publish src/FireBrick.Service/FireBrick.Service.csproj -c Release -r win-x64 -o publish/service
sc.exe create FireBrickService binPath= "$PWD\publish\service\FireBrick.Service.exe" start= auto
sc.exe start FireBrickService
```

## Releases & Versioning

Version metadata is managed centrally in [`Directory.Build.props`](Directory.Build.props) using Semantic Versioning (`MAJOR.MINOR.PATCH`).

The GitHub Actions workflow ([`.github/workflows/release.yml`](.github/workflows/release.yml)) automatically builds self-contained `win-x64` binaries, packages an Inno Setup Windows installer (`FireBrick-Setup-<version>-win-x64.exe`) and portable archive (`FireBrick-Portable-<version>-win-x64.zip`) with `SHA256SUMS.txt`, and publishes a GitHub Release:

- **Tag-triggered release**:
  ```powershell
  git tag -a v1.2.1 -m "Release v1.2.1"
  git push origin v1.2.1
  ```
- **Manual release from GitHub Actions**: Go to **Actions → Release Windows Installer → Run workflow** and select `patch`, `minor`, `major`, or `custom` to automatically bump `Directory.Build.props`, commit, tag, build, and publish the release.
