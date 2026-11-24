<div align="center">

<img src="src/FireBrick.App/Assets/FireBrick.png" alt="FireBrick" width="96" />

# FireBrick

**A modern WinUI 3 frontend for Windows Defender Firewall & Windows Filtering Platform (WFP).**

[![Latest Release](https://img.shields.io/github/v/release/piyushagade/FireBrick?style=flat-square&logo=github)](https://github.com/piyushagade/FireBrick/releases/latest)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-Scanned-10b981?style=flat-square&logo=virustotal&logoColor=white)](https://github.com/piyushagade/FireBrick/releases/latest)
[![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011%20(x64)-0078D6?style=flat-square&logo=windows)](https://github.com/piyushagade/FireBrick/releases/latest)
[![.NET 8](https://img.shields.io/badge/.NET-8.0%20%7C%20WinUI%203-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-orange?style=flat-square)](LICENSE)

*Inspired by Windows Firewall Control (WFC) — built natively on `INetFwPolicy2` and WFP with **no kernel driver** required.*

[Download Latest Release](https://github.com/piyushagade/FireBrick/releases/latest) · [Features](#features) · [Architecture](#architecture) · [Build from Source](#build--run) · [License](#license)

</div>

---

## Download

Grab the latest Windows `x64` release from [**GitHub Releases**](https://github.com/piyushagade/FireBrick/releases/latest):

| Package | File | Description |
| :--- | :--- | :--- |
| **Installer (Recommended)** | `FireBrick-Setup-<version>-win-x64.exe` | Inno Setup installer with Start Menu shortcut and optional background service setup |
| **Portable** | `FireBrick-Portable-<version>-win-x64.zip` | Self-contained archive — extract and run anywhere |
| **Checksums** | `SHA256SUMS.txt` | SHA-256 verification hashes for all release artifacts |

**Requirements:** Windows 10 (build 19041+) or Windows 11 (`x64`). Self-contained — no separate .NET or Windows App SDK installation needed.

> **Windows SmartScreen Note:** FireBrick is an independent, unsigned binary. Windows SmartScreen may display a warning on first run. You can verify the download against `SHA256SUMS.txt` or build directly from source below.

---

## Features

### Firewall Control & Profiles
- **4 Filtering Profiles** — Switch between **High Filtering** (block all outbound), **Medium Filtering** (block outbound unless explicitly allowed), **Low Filtering**, and **No Filtering** from the Dashboard or system tray.
- **Custom WinUI 3 Tray Flyout** — Profile-colored shield icon (`Red` / `Amber` / `Green` / `Gray`) with quick profile switching, notification mode submenus, and navigation.
- **Background Windows Service** — Optional privileged `FireBrickService` (`LocalSystem`) with Named Pipe IPC so the desktop UI runs smoothly without repeated UAC prompts.

### Real-Time Connection Alerts & Automation
- **Floating Connection Alert Window** — Always-on-top prompt when an app is blocked, with **Standard** and **Condensed** (icon-only) views, app icon, Authenticode publisher trust badge, Reverse DNS, and GeoIP/Org details.
- **Granular Rule Scoping** — Allow or block by *Any IP & port*, *Port only*, or *IP & port*.
- **Temporary Rules** — Grant time-limited access (e.g., 15 minutes) that automatically expires and cleans itself up.
- **Auto-Allow / Auto-Block Rules** — Automate decisions with instant or countdown modes, plus Learning Mode for trusted signed apps.

### Monitoring & Rule Management
- **Live TCP/UDP Monitor & Audit Log** — Inspect active sockets per process (`iphlpapi.dll`), browse real-time WFP Security Event Log entries (`Event ID 5152 / 5156 / 5157`), and **terminate active TCP sockets** immediately when blocking an app.
- **Per-App View & Rule Tools** — Group rules and activity by application, detect duplicate or orphaned rules, and export/import rules as JSON.
- **Windows Explorer Integration** — Right-click any `.exe` to **Allow** or **Block** directly from the context menu.
- **One-Click Presets** — Built-in rule packs for Core Networking, Privacy/Telemetry Block, Developer Essentials, and Public Network Hardening.

### Protection Suite
- **Rule Lock** — Snapshots authorized rules and detects/reverts unauthorized external firewall modifications.
- **Network / Wi-Fi Auto-Switch** — Automatically switch filtering profiles based on the active Wi-Fi SSID or network interface.
- **Blocklist Subscriptions** — Subscribe to remote IP/CIDR and domain blocklists (e.g., Spamhaus DROP).
- **Hosts File Manager** — View, search, toggle, and manage Windows `hosts` entries directly inside FireBrick.

---

## Privacy & Diagnostics

FireBrick sends strictly anonymous aggregate usage counters (e.g., launch count, active profile, alert decision tallies) when **Settings → Send diagnostics & usage** is enabled. No personal data, IP addresses, machine IDs, or file paths are ever collected. See [`analytics.md`](analytics.md) for the complete list of counters and endpoints.

---

## Architecture

- **`src/FireBrick.Core`** — Shared firewall engine:
  - `WindowsFirewallManager`: 4-profile policy controller (`High`, `Medium`, `Low`, `No Filtering`), full rule CRUD, invalid/orphaned rule scanner, duplicate detector, JSON export/import.
  - `SecurityAuditMonitor`: Real-time WFP Security Event Log watcher (`Event ID 5152 / 5156 / 5157`) with NT device-path conversion (`DevicePathConverter`).
  - `LiveConnectionsMonitor` & `TcpConnectionKiller`: Live active TCP/UDP socket monitor (`iphlpapi.dll`) with instant TCP socket termination.
  - `AuthenticodeVerifier`: WinTrust digital signature & publisher verification.
  - `DnsResolverCache` & `GeoIpResolverCache`: Throttled async reverse DNS (PTR) and GeoIP/Org caches.
  - `TemporaryRuleManager`: Auto-expiring temporary rules.
  - `RuleLockMonitor`, `NetworkProfileMonitor`, `BlocklistManager`, `HostsFileManager`, `PresetCatalog`, & `ShellContextMenuManager`.
- **`src/FireBrick.Service`** — Privileged Windows Service (`LocalSystem`) hosting a Named Pipe IPC server (`FireBrick_IPC_v1`), continuous WFP event monitoring, Learning Mode, Rule Lock, Network Auto-Switch, and temporary rule expiration.
- **`src/FireBrick.App`** — Fluent WinUI 3 Desktop application (Mica backdrop, Dashboard, Apps, Rules, Connections Log + Live Monitor, Presets & Temp Rules, Protection & Hosts Manager, Settings, Tray Flyout, and floating Connection Alerts).
- **`tests/FireBrick.Tests`** — xUnit tests for core engines.

---

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

---

## Releases & Versioning

Version metadata is managed centrally in [`Directory.Build.props`](Directory.Build.props) using Semantic Versioning (`MAJOR.MINOR.PATCH`).

The GitHub Actions workflow ([`.github/workflows/release.yml`](.github/workflows/release.yml)) automatically builds self-contained `win-x64` binaries, packages an Inno Setup Windows installer (`FireBrick-Setup-<version>-win-x64.exe`) and portable archive (`FireBrick-Portable-<version>-win-x64.zip`) with `SHA256SUMS.txt`, and publishes a GitHub Release:

- **Tag-triggered release:**
  ```powershell
  git tag -a v1.2.1 -m "Release v1.2.1"
  git push origin v1.2.1
  ```
- **Manual release from GitHub Actions:** Go to **Actions → Release Windows Installer → Run workflow** and select `patch`, `minor`, `major`, or `custom` to automatically bump `Directory.Build.props`, commit, tag, build, and publish the release.

---

## License

FireBrick is licensed under the [**PolyForm Noncommercial License 1.0.0**](LICENSE). You are free to use, modify, and share FireBrick for personal and noncommercial purposes.

> Required Notice: Copyright © 2026 Piyush Agade (https://github.com/piyushagade/FireBrick)
