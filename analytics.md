# FireBrick Usage Analytics & Privacy Transparency

Because FireBrick is a **firewall application**, you deserve complete transparency about every single network request it makes, why it exists, and how to turn it off.

---

## TL;DR

- **What it is:** A minimal `+1` integer counter (`POST https://app.piyushagade.xyz/counter/firebrick/<key>/up`) with an **empty request body**.
- **What it is NOT:** There are no user IDs, machine IDs, hardware fingerprints, cookies, third-party analytics SDKs, crash stack traces, app lists, or firewall rules sent anywhere.
- **Easy opt-out:** Turn off **Settings → Send diagnostics & usage** at any time (or set `"SendDiagnosticsAndUsage": false` in `%LocalAppData%\FireBrick\settings.json`).
- **Fully inspectable:** The entire implementation lives in a single file: [`src/FireBrick.Core/Engine/UsageAnalyticsService.cs`](src/FireBrick.Core/Engine/UsageAnalyticsService.cs).

---

## Why Collect These Metrics?

FireBrick is an independent desktop app distributed directly via GitHub Releases rather than an app store with built-in telemetry. Without basic aggregate counters, it is impossible to answer simple maintenance questions like:

- *Is anyone actually using FireBrick day to day?*
- *Did the latest release introduce a spike in crashes?*
- *Are most people on `v1.2.0`, or are users stuck on older versions?*
- *Which filtering profiles (`High`, `Medium`, `Low`, `No Filtering`) and alert actions (`Allow`, `Temp Allow`, `Block`) do people rely on most so development effort goes to the right places?*
- *Are users successfully running the background Windows Service?*

---

## Why This Is Innocuous

FireBrick's analytics were intentionally designed to be **structurally incapable of profiling or identifying you**:

1. **Empty HTTP POST requests — literally just `+1`:**
   Every analytics call sends an empty body (`Content = ""`) to increment a shared aggregate integer on the server:
   ```http
   POST https://app.piyushagade.xyz/counter/firebrick/<counter-key>/up
   User-Agent: FireBrick/<version>
   Content-Length: 0
   ```
   There is no JSON payload, no query parameters, and no custom tracking headers.

2. **Zero persistent identifiers:**
   FireBrick does not generate a UUID, installation ID, machine ID, or session token. Deduplication (such as reporting `first-run` once or daily active usage once per UTC day) is tracked **strictly locally** in `%LocalAppData%\FireBrick\analytics_state.json` using simple booleans/dates — that file is never uploaded.

3. **Zero firewall or system data:**
   FireBrick never transmits your installed apps, executable paths, blocked/allowed destinations, IP addresses, DNS lookups, firewall rules, Wi-Fi SSIDs, Hosts file entries, or `crash.log` contents. Even crash counting only checks whether your local `crash.log` grew in byte size and increments the global `crash-count` integer by `+1`.

4. **No third-party trackers:**
   No Google Analytics, Sentry, Mixpanel, Application Insights, or external telemetry SDKs are bundled.

5. **Zero performance or reliability impact:**
   All requests run asynchronously in the background with a `4-second` timeout, a concurrency cap of `2`, and an automatic circuit breaker (after `2` consecutive failures, it backs off exponentially: `15 min` → `1 hr` → `6 hr`). It never throws exceptions or slows down the UI or firewall engine.

---

## Complete List of Metrics Collected

Every single counter key that FireBrick can ever increment is listed below.

### 1. App Usage & Installs

| Metric | Counter Key | Trigger | Why It's Useful |
| :--- | :--- | :--- | :--- |
| **Total App Launches** | `app-launches` | Once per app launch | Measures overall usage volume |
| **First-Run Installs** | `first-run` | Once per install (tracked locally) | Estimates total unique installations |
| **Total Active App-Days** | `dau-total` | At most once per UTC day | Tracks cumulative active days |
| **Daily Active Usage** | `dau-YYYY-MM-DD` | At most once per UTC day | Shows active user trend over time |

### 2. Interceptions & Alert Decisions

| Metric | Counter Key | Trigger | Why It's Useful |
| :--- | :--- | :--- | :--- |
| **Total Interceptions** | `interceptions-total` | Blocked connection prompt shown | Measures real-world alert activity |
| **Daily Interceptions** | `interceptions-YYYY-MM-DD` | Blocked connection prompt shown | Tracks daily alert volume |
| **Alert: Allow (Permanent)** | `alert-allow` | User clicks **Allow** | Understands how prompts are used |
| **Alert: Allow (Temporary)** | `alert-temp-allow` | User clicks **Allow (Temporary)** | Measures adoption of temporary rules |
| **Alert: Block** | `alert-block` | User clicks **Block** | Understands how prompts are used |

### 3. Profiles, Features & Versions (Sampled Once Per UTC Day)

| Metric | Counter Key | Trigger | Why It's Useful |
| :--- | :--- | :--- | :--- |
| **Active Filtering Profile** | `profile-high` / `profile-medium` / `profile-low` / `profile-none` | Daily ping | Shows which profiles matter most |
| **Background Service Connected** | `service-connected` | Daily ping (if connected) | Verifies service installation reliability |
| **Active App Version** | `version-<major>_<minor>_<patch>` | Daily ping | Tracks adoption of new releases |
| **Rule Preset Applied** | `preset-applied` | User applies a rule preset | Measures usefulness of built-in presets |

### 4. Crash Diagnostics

| Metric | Counter Key | Trigger | Why It's Useful |
| :--- | :--- | :--- | :--- |
| **Crash Count** | `crash-count` | Next launch if local `crash.log` grew | Alerts the developer to regressions without uploading stack traces or logs |

---

## What Is NEVER Collected

- No IP addresses stored or logged by the app
- No machine IDs, MAC addresses, Windows product keys, or hardware fingerprints
- No Windows usernames, hostnames, or email addresses
- No executable names, file paths, or process lists
- No firewall rules, allowed/blocked domains, GeoIP results, or Hosts file entries
- No Wi-Fi SSIDs or network adapter details
- No crash log contents or stack traces

---

## How to Disable (Opt Out)

You have full control and can disable analytics at any time:

1. **In the app:** Open **Settings → Send diagnostics & usage** and toggle it **Off**.
2. **Via config file:** Set `"SendDiagnosticsAndUsage": false` in `%LocalAppData%\FireBrick\settings.json`.
3. **At the network level:** You can even block `app.piyushagade.xyz` in FireBrick's own Hosts File Manager or Firewall Rules — FireBrick will function 100% identically and the built-in circuit breaker will silently back off.

---

## Technical Reference

- **Source code:** [`src/FireBrick.Core/Engine/UsageAnalyticsService.cs`](src/FireBrick.Core/Engine/UsageAnalyticsService.cs)
- **Endpoint base:** `https://app.piyushagade.xyz/counter/firebrick/<key>/up` (`HTTP POST`, empty body)
- **Local deduplication state:** `%LocalAppData%\FireBrick\analytics_state.json`
- **Outage guard:** `4s` HTTP timeout, max `2` concurrent requests, circuit breaker opens after `2` consecutive failures (`15 min` → `1 hr` → `6 hr` backoff).
