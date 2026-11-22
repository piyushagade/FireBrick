# FireBrick Usage Analytics Reference

FireBrick sends strictly anonymous aggregate counters to the counter API (`POST https://app.piyushagade.xyz/counter/firebrick/<key>/up`) when **Settings → Send diagnostics & usage** is enabled (default: **On**). No personal data, machine IDs, IP addresses, or executable paths are ever collected.

---

## App Usage & Installs

| Metric | Description | GET URL |
| :--- | :--- | :--- |
| **Total App Launches** | Incremented on every app launch | https://app.piyushagade.xyz/counter/firebrick/app-launches |
| **First-Run Installs** | Incremented once per install | https://app.piyushagade.xyz/counter/firebrick/first-run |
| **Total Active App-Days** | Cumulative daily active usage count | https://app.piyushagade.xyz/counter/firebrick/dau-total |
| **Daily Active Usage (UTC)** | Unique installs active on a UTC date (`dau-YYYY-MM-DD`) | https://app.piyushagade.xyz/counter/firebrick/dau-2026-11-22 |

---

## Interceptions & Alert Decisions

| Metric | Description | GET URL |
| :--- | :--- | :--- |
| **Total Interceptions** | All-time blocked connection prompts shown | https://app.piyushagade.xyz/counter/firebrick/interceptions-total |
| **Daily Interceptions (UTC)** | Interceptions on a UTC date (`interceptions-YYYY-MM-DD`) | https://app.piyushagade.xyz/counter/firebrick/interceptions-2026-11-22 |
| **Alert: Allow (Permanent)** | User clicked **Allow** on an alert | https://app.piyushagade.xyz/counter/firebrick/alert-allow |
| **Alert: Allow (Temporary)** | User clicked **Allow (Temporary)** on an alert | https://app.piyushagade.xyz/counter/firebrick/alert-temp-allow |
| **Alert: Block** | User clicked **Block** on an alert | https://app.piyushagade.xyz/counter/firebrick/alert-block |

---

## Filtering Profiles, Features & Versions (Sampled Daily)

| Metric | Description | GET URL |
| :--- | :--- | :--- |
| **Profile: High Filtering** | Active profile on daily ping | https://app.piyushagade.xyz/counter/firebrick/profile-high |
| **Profile: Medium Filtering** | Active profile on daily ping | https://app.piyushagade.xyz/counter/firebrick/profile-medium |
| **Profile: Low Filtering** | Active profile on daily ping | https://app.piyushagade.xyz/counter/firebrick/profile-low |
| **Profile: No Filtering** | Active profile on daily ping | https://app.piyushagade.xyz/counter/firebrick/profile-none |
| **Background Service Connected** | `FireBrickService` IPC connected on daily ping | https://app.piyushagade.xyz/counter/firebrick/service-connected |
| **Presets Applied** | Rule preset pack applied | https://app.piyushagade.xyz/counter/firebrick/preset-applied |
| **Version (`1.1.0`)** | Active app version (`version-<major>_<minor>_<patch>`) | https://app.piyushagade.xyz/counter/firebrick/version-1_1_0 |

---

## Diagnostics

| Metric | Description | GET URL |
| :--- | :--- | :--- |
| **Crash Count** | Incremented on next launch when `crash.log` grows | https://app.piyushagade.xyz/counter/firebrick/crash-count |

---

## Implementation & Outage Guard Notes

- **Source**: `src/FireBrick.Core/Engine/UsageAnalyticsService.cs`
- **Local deduplication state**: `%LocalAppData%\FireBrick\analytics_state.json`
- **Outage Guard**: `4s` HTTP timeout, max `2` concurrent requests, circuit breaker opens after `2` consecutive failures with exponential backoff (`15 min` → `1 hr` → `6 hr` cap).
- **Opt-out**: Controlled by `Settings → Send diagnostics & usage` (`AppSettingsDto.SendDiagnosticsAndUsage` in `%LocalAppData%\FireBrick\settings.json`).
