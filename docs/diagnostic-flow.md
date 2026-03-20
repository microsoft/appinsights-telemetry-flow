# Diagnostic Flow

> Why the script checks what it checks, in the order it checks it, and when it
> skips phases entirely.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Phase Map](#phase-map)
- [Phase-by-Phase Walkthrough](#phase-by-phase-walkthrough)
  - [Phase 0: Initialisation](#phase-0-initialisation)
  - [Phase 1: Environment Detection](#phase-1-environment-detection)
  - [Phase 2: Connection String Validation](#phase-2-connection-string-validation)
  - [Phase 3: Consent Gates](#phase-3-consent-gates)
  - [Phase 4: DNS Resolution](#phase-4-dns-resolution)
  - [Phase 5: TCP Connectivity](#phase-5-tcp-connectivity)
  - [Phase 6: TLS Handshake Validation](#phase-6-tls-handshake-validation)
  - [Phase 7: AMPLS Validation](#phase-7-ampls-validation)
  - [Phase 8: Known Issue Checks](#phase-8-known-issue-checks)
  - [Phase 9: Telemetry Ingestion Test](#phase-9-telemetry-ingestion-test)
  - [Phase 10: End-to-End Verification](#phase-10-end-to-end-verification)
  - [Phase 11: Diagnosis and Reporting](#phase-11-diagnosis-and-reporting)
- [Skip Logic](#skip-logic)
  - [Automatic Skips (Dependency Failures)](#automatic-skips-dependency-failures)
  - [Explicit Skips (User Switches)](#explicit-skips-user-switches)
  - [Conditional Skips (Environment / Consent)](#conditional-skips-environment--consent)
- [Consent Model](#consent-model)
- [Step Numbering](#step-numbering)
- [Timing and Performance](#timing-and-performance)
- [Compact vs. Verbose Execution Differences](#compact-vs-verbose-execution-differences)
- [Bash Script Parity](#bash-script-parity)
- [Further Reading](#further-reading)

---

## Design Philosophy

The diagnostic flow follows three principles:

1. **Mirror the telemetry path.** Checks run in the same order that real
   telemetry traverses: DNS → TCP → TLS → Ingestion → Pipeline → Storage →
   Query. A failure at layer N makes all layers > N irrelevant, so the script
   stops testing downstream layers when an upstream dependency is broken.

2. **Fail fast, explain clearly.** If DNS fails, there is no reason to wait
   for a TCP timeout. If the backend workspace is deleted, there is no reason
   to send a test record that will be silently dropped. Each skip includes an
   explanation so the user knows *why* a phase was bypassed and *what to fix
   first*.

3. **Read-only by default, write-only with consent.** The script's only write
   operation is sending a single test telemetry record. Everything else is
   read-only — DNS queries, TCP socket connects, TLS handshakes, ARM GET
   requests, Resource Graph queries. The ingestion test requires explicit user
   consent (or `-AutoApprove`).

---

## Phase Map

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 0: Initialization                                         │
  │  • Console colour detection, Write-HostLog override, helpers     │
  │  • Module auto-detection ($CheckAzure flag)                      │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 1: Environment Detection                                  │
  │  • OS, Azure PaaS host type, proxy settings, PowerShell version  │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 2: Connection String Validation                           │
  │  • Parse, extract iKey/endpoints, detect cloud, build endpoints  │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 3: Consent Gates (interactive)                            │
  │  • Azure resource checks consent                                 │
  │  • Ingestion test consent                                        │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 4: DNS Resolution (all endpoints)                         │
  │  • Resolve 10-12 hostnames, classify IPs, detect AMPLS signals   │
  ├──────────────────────────┬───────────────────────────────────────┤
  │  DNS passed              │  DNS failed (critical endpoints)      │
  └──────────┬───────────────┘  └─── TCP/TLS/Ingestion → SKIP        │
             ▼                                                       │
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 5: TCP Connectivity (port 443)                            │
  │  • Test TCP to every resolved endpoint                           │
  ├──────────────────────────┬───────────────────────────────────────┤
  │  Ingestion TCP passed    │  Ingestion TCP failed                 │
  └──────────┬───────────────┘  └─── TLS/Ingestion → SKIP            │
             ▼                                                       │
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 6: TLS Handshake Validation                               │
  │  • TLS 1.2/1.3 negotiation, cert inspection, deprecated probing  │
  │  • TLS inspection / MITM detection                               │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 7: AMPLS Validation (conditional)                         │
  │  • Manual: -AmplsExpectedIps comparison                          │
  │  • Automated: Azure login → Resource Graph → ARM → IP comparison │
  │  • Network access mode assessment                                │
  ├──────────────────────────┬───────────────────────────────────────┤
  │  Ingestion allowed       │  Ingestion BLOCKED (pre-flight)       │
  └──────────┬───────────────┘  └─── Ingestion test → SKIP           │
             ▼                                                       │
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 8: Known Issue Checks (conditional, requires Azure)       │
  │  • Auth mode, sampling, daily cap, workspace health, DCRs, etc.  │
  ├──────────────────────────┬───────────────────────────────────────┤
  │  Pipeline healthy        │  Pipeline broken (ws deleted/suspended)│
  └──────────┬───────────────┘  └─── Ingestion test → SKIP           │
             ▼                                                       │
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 9: Telemetry Ingestion Test                               │
  │  • POST one availabilityResults record to v2.1/track             │
  ├──────────────────────────┬───────────────────────────────────────┤
  │  HTTP 200 received       │  Ingestion failed or skipped          │
  └──────────┬───────────────┘  └─── E2E verification → SKIP         │
             ▼                                                       │
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 10: End-to-End Verification (conditional)                 │
  │  • Query data plane API with progressive backoff (~65 sec max)   │
  │  • Confirm test record is queryable in workspace                 │
  └──────────────────────────┬───────────────────────────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  Phase 11: Diagnosis and Reporting                               │
  │  • Aggregate findings, render DIAGNOSIS SUMMARY + WHAT TO DO     │
  │  • Save JSON + TXT reports, set exit code                        │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Phase-by-Phase Walkthrough

### Phase 0: Initialization

**Line range:** ~275–2688 (configuration, helper functions, main execution
preamble)

**What happens:**
- Script version, `$ErrorActionPreference`, `$ProgressPreference` set.
- Console colour detection — determines if the terminal supports ANSI colours
  (Kudu web console, Azure Cloud Shell classic, and some CI environments
  don't).
- `Write-HostLog` override installed to capture all console output for the TXT
  report while still displaying to the user.
- Helper functions defined: `Write-Header`, `Write-Result`,
  `Write-ProgressStart`, `Write-ProgressLine`, `Add-Diagnosis`,
  `Write-Wrapped`, `Get-ConsoleWidth`.
- Diagnostic functions defined: `Test-DnsResolution`, `Test-TcpConnectivity`,
  `Test-TlsHandshake`, `Test-IngestionEndpoint`, AMPLS functions, data plane
  query functions.
- `$CheckAzure` auto-detection: if `Az.Accounts` and `Az.ResourceGraph` are
  importable and `-NetworkOnly` was not specified, `$CheckAzure` is set to
  `$true`.

**Can be skipped:** No — always runs.

**Time cost:** < 1 second.

---

### Phase 1: Environment Detection

**What happens:**
- OS detection (Windows, Linux, macOS).
- Azure PaaS host detection via environment variables:
  `WEBSITE_SITE_NAME` (App Service), `FUNCTIONS_WORKER_RUNTIME` (Functions),
  `CONTAINER_APP_NAME` (Container Apps), IMDS metadata (generic Azure VM),
  Cloud Shell detection.
- Proxy detection: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and
  `[System.Net.WebProxy]::GetDefaultProxy()` on Windows.
- PowerShell version and edition.
- Computer name and OS version for the report header.

**Can be skipped:** No — always runs. Results used by banner, consent logic,
and report metadata.

**Time cost:** < 1 second (IMDS call has a 2-second timeout on non-Azure
machines).

---

### Phase 2: Connection String Validation

**What happens:**
- Parses the `-ConnectionString` parameter (or auto-detects from environment
  variables `APPLICATIONINSIGHTS_CONNECTION_STRING` /
  `APPINSIGHTS_INSTRUMENTATIONKEY`).
- Extracts: `InstrumentationKey`, `IngestionEndpoint`, `LiveEndpoint`,
  `ProfilerEndpoint`, `SnapshotEndpoint`.
- Detects Azure cloud from TLD suffix (`.com`, `.us`, `.cn`).
- Detects global/legacy endpoint and raises an INFO finding if found.
- Builds the full endpoint list (10-12 hostnames) that DNS/TCP/TLS phases will
  test.
- Displays the resource header (masked iKey, endpoint, host, Azure context).

**Can be skipped:** No — all downstream phases depend on the parsed connection
string.

**Failure mode:** If the connection string is invalid or missing, the script
terminates with an error message. No diagnostic phases run.

**Time cost:** < 1 second.

---

### Phase 3: Consent Gates

**What happens:**

Two consent prompts may be shown, depending on mode and switches:

1. **Azure resource checks consent** — Asks permission to sign in to Azure and
   query ARM/Resource Graph. Only shown when `$CheckAzure` is `$true` and
   `-AutoApprove` is not set.
2. **Ingestion test consent** — Asks permission to send one test telemetry
   record. Only shown when `-SkipIngestionTest` is not set and `-AutoApprove`
   is not set.

**Timing within the flow differs by output mode:**

| Mode | When Consent Is Shown |
|------|-----------------------|
| **Compact** | Both prompts shown *before* the progress table begins, so the clean compact layout is uninterrupted. |
| **Verbose** | Each prompt shown *just-in-time* — Azure consent before AMPLS validation, ingestion consent before the ingestion test. |

**Can be skipped:** Yes — `-AutoApprove` silently accepts both. `-NetworkOnly`
suppresses the Azure consent. `-SkipIngestionTest` suppresses the ingestion
consent.

**Failure mode:** If consent is declined, the relevant phases are marked as
SKIP and the script continues with the remaining checks.

**Time cost:** Depends on user interaction (0 seconds with `-AutoApprove`).

---

### Phase 4: DNS Resolution

**Step label:** `STEP {N}: DNS Resolution`

**What happens:**
- Resolves all 10-12 endpoints built in Phase 2 using
  `[System.Net.Dns]::GetHostAddresses()`.
- For each hostname: records resolved IP(s), classifies as public or private,
  records CNAME chain where available.
- Aggregates: total pass/fail counts, public/private/mixed IP classification,
  AMPLS signal detection (any private IP = AMPLS signal).
- In verbose mode: displays a table of all results with IP addresses and
  categories.

**Findings produced:**
- **DNS Resolution Failures** (BLOCKING) — if any critical endpoint fails.
- **Mixed Public / Private DNS Results** (INFO) — if some resolve to public
  and some to private.

**Skip triggers on downstream phases:**
- If all critical DNS entries fail → TCP and TLS are SKIPPED.

**Time cost:** 1-3 seconds typical. DNS timeouts (usually 5 seconds per
hostname) can extend this on misconfigured networks.

---

### Phase 5: TCP Connectivity

**Step label:** `STEP {N}: TCP Connectivity (Port 443)`

**What happens:**
- For every endpoint that resolved in Phase 4, opens a TCP connection to port
  443 using `System.Net.Sockets.TcpClient` with a 5-second timeout.
- Records: pass/fail, connection latency, timeout detection.
- Tracks whether the *ingestion endpoint specifically* passed TCP — this is
  the critical gate for TLS and ingestion tests.

**Findings produced:**
- **TCP Connection Failures Port 443** (BLOCKING) — if any critical endpoint
  is blocked.

**Skip triggers on downstream phases:**
- If the ingestion endpoint fails TCP → TLS handshake test is SKIPPED for that
  endpoint.
- If the ingestion endpoint fails TCP → Ingestion test is SKIPPED entirely
  (`$script:ingestionTcpBlocked` flag set).

**Time cost:** 1-5 seconds (5-second timeout per blocked endpoint).

---

### Phase 6: TLS Handshake Validation

**Step label:** `STEP {N}: TLS Handshake Validation`

**What happens:**
- Establishes TLS connections to endpoints that passed TCP.
- Checks current (TLS 1.2/1.3) negotiation first.
- Inspects the certificate chain: subject, issuer, expiry, whether the issuer
  is Microsoft or a third party.
- If a non-Microsoft issuer is found: identifies the proxy product (Zscaler,
  Palo Alto, Fortinet, Netskope, Blue Coat, etc.) from the issuer CN/OU.
- Probes deprecated TLS protocols (1.0, 1.1) with a short 3-second timeout to
  detect TLS-terminating proxies.
- Records which protocol version the OS negotiated by default (this is what
  your SDK actually uses).

**Findings produced:**
- **TLS Handshake Failure** (BLOCKING)
- **TLS Inspection Detected** (INFO) — includes proxy product name when
  identifiable.
- **Deprecated TLS Protocol Accepted** (INFO)
- **Deprecated TLS Accepted with Microsoft Certificate** (INFO)

**Skip triggers on downstream phases:**
- If no eligible endpoints passed TCP → entire TLS phase is SKIPPED.
- TLS failures do not block the ingestion test (the ingestion HTTP client
  handles TLS independently).

**Time cost:** 2-8 seconds. The deprecated protocol probes add ~3 seconds each
but are parallelised where possible. TLS inspection proxy environments can add
latency.

---

### Phase 7: AMPLS Validation

**Step label:** `STEP {N}: AMPLS Validation` (number is dynamic)

**What happens — two paths:**

**Path A: Manual IP comparison** (when `-AmplsExpectedIps` is provided)
- Compares user-supplied expected IPs against actual DNS resolution from
  Phase 4.
- Reports matches and mismatches.

**Path B: Automated discovery** (when `$CheckAzure` is `$true`)
- Authenticates to Azure (interactive browser or existing session).
- Queries Azure Resource Graph to find the App Insights resource by iKey.
- Discovers AMPLS resources linked to it.
- Retrieves private endpoint IP configurations from ARM.
- Compares expected IPs against DNS results.
- Reads AMPLS access modes (Private Only vs. Open).
- Assesses network access settings (`publicNetworkAccessForIngestion`,
  `publicNetworkAccessForQuery`).

**Findings produced:**
- **AMPLS DNS Mismatches** (WARNING)
- **Ghost AMPLS** (WARNING) — private IPs but no AMPLS link. When detected,
  the script automatically performs a reverse IP lookup (IP → NIC → PE → AMPLS)
  to identify the responsible AMPLS resource.
- **Ghost AMPLS Ingestion Mismatch** (WARNING) — the ingestion endpoint IP
  doesn't match the expected PE IP for a linked AMPLS. Reverse lookup auto-triggers
  for the mismatched IP.
- **App Insights Resource Not Found** (INFO)
- **Ingestion BLOCKED From This Machine** (BLOCKING)
- **Query Access BLOCKED From This Machine** (WARNING)

**Skip triggers on downstream phases:**
- If ingestion is assessed as BLOCKED → Ingestion test is SKIPPED
  (`$script:ingestionBlockedPreFlight` flag set).

**Can be skipped:** Yes — `-NetworkOnly` skips entirely. Consent declined
skips. Missing Az modules skip.

**Time cost:** 3-15 seconds (Azure login may add time; Resource Graph and ARM
queries are typically fast).

---

### Phase 8: Known Issue Checks

**Step label:** `STEP {N}: Known Issue Checks`

**Prerequisites:** `$CheckAzure` is `$true` AND the App Insights resource was
found in Phase 7.

**What happens — six sub-checks:**

| # | Sub-Check | What It Reads |
|---|-----------|---------------|
| 1 | **Authentication mode** | `properties.DisableLocalAuth` on the AI resource |
| 2 | **Ingestion sampling** | `properties.IngestionMode` / sampling percentage |
| 3 | **Backend LA workspace health** | ARM GET on `WorkspaceResourceId` — provisioning state, quotaNextResetTime, sku |
| 4 | **Daily cap settings** | AI daily cap vs. LA daily cap — detects mismatches and OverQuota |
| 5 | **Diagnostic Settings** | ARM GET on AI resource diagnostic settings — detects duplication to same workspace |
| 6 | **Workspace transforms / DCRs** | Resource Graph query for DCRs targeting AI-related tables |

**Findings produced:**
- **Local Authentication Disabled** (INFO)
- **Ingestion Sampling Enabled** (INFO)
- **Log Analytics Daily Cap Reached** (BLOCKING)
- **Azure Subscription Suspended** (BLOCKING)
- **Backend Log Analytics Workspace Not Found** (BLOCKING)
- **Cannot Query Backend LA Workspace** (INFO)
- **Daily Cap Mismatch LA < AI** (WARNING)
- **Log Analytics Daily Cap is the Effective Limit** (INFO)
- **Workspace Access: Require Workspace Permissions** (INFO)
- **Diagnostic Settings Exporting to LA** (INFO)
- **Workspace Transforms Detected** (INFO)

**Skip triggers on downstream phases:**
- If workspace is deleted or subscription is suspended →
  `$script:pipelineBroken` flag set → Ingestion test is SKIPPED (the ingestion
  API will return 200 but data is silently dropped — sending a test record
  would produce a false "pass").

**Can be skipped:** Yes — `-NetworkOnly` skips entirely. Missing Az modules
skip. AI resource not found skips.

**Time cost:** 2-10 seconds (multiple sequential ARM REST calls).

---

### Phase 9: Telemetry Ingestion Test

**Step label:** `STEP {N}: Telemetry Ingestion Test`

**Prerequisites:** Consent granted, ingestion not blocked (TCP, pre-flight,
pipeline), `-SkipIngestionTest` not set.

**What happens:**
- Constructs a minimal `availabilityResults` JSON envelope with a unique
  `diagnosticRunId` in `customDimensions`.
- POSTs to `{IngestionEndpoint}/v2.1/track` using the instrumentation key.
- Records: HTTP status code, response body, round-trip duration.
- Interprets the response:
  - HTTP 200 → telemetry accepted.
  - HTTP 401 + local auth disabled → expected (Entra ID enforcement).
  - HTTP 401/403 without known context → BLOCKING finding.
  - HTTP 429/439 → daily cap / throttling.
- If ingestion passed and local auth was reported as disabled by ARM → raises
  an INFO finding about ARM/ingestion auth mismatch.

**Findings produced:**
- **Telemetry Ingestion Failed** (BLOCKING)
- **Ingestion Returned 401 (Entra ID Auth Required)** (INFO)
- **Ingestion Block Confirmed by Test** (INFO)
- **ARM / Ingestion Auth Mismatch** (INFO)

**Skip triggers on downstream phases:**
- If ingestion did not return HTTP 200 → E2E verification SKIPPED.

**Can be skipped:** Yes — six distinct skip conditions:
1. `-SkipIngestionTest` flag.
2. Ingestion consent declined.
3. `$script:pipelineBroken` (workspace deleted/suspended).
4. `$script:ingestionBlockedPreFlight` (AMPLS network block).
5. `$script:ingestionTcpBlocked` (TCP to ingestion endpoint failed).
6. DNS failed for ingestion endpoint (implicit — no resolved IP to POST to).

**Time cost:** 1-5 seconds (single HTTP POST + response parsing).

---

### Phase 10: End-to-End Verification

**Step label:** `End-to-End Verification`

**Prerequisites:** Ingestion returned HTTP 200 AND `$CheckAzure` is `$true`
AND Azure login is active AND the AI resource was found.

**What happens:**
- Queries the App Insights data plane API
  (`api.applicationinsights.io`) with a KQL query:
  ```kusto
  availabilityResults
  | where customDimensions.diagnosticRunId == '{unique-id}'
  ```
  The query intentionally omits `| take 1` so it returns **all copies** of the
  test record.  If Diagnostic Settings are exporting App Insights logs to a Log
  Analytics workspace, each setting produces an additional copy of every record.
  Returning all copies lets the tool detect and report duplicate telemetry.
- Uses progressive backoff polling: waits increasing intervals, up to ~65
  seconds total.
- If the record is found: reports success with the send-to-queryable latency.
  When multiple copies are returned, a **DUPLICATE TELEMETRY DETECTED** warning
  is shown and correlated with any Diagnostic Settings findings from the earlier
  known-issue checks.
- If the record is not found within the polling window: reports timeout and
  provides the KQL query for manual verification.

**Findings produced:** None directly. The verification result is reported as a
progress line status (OK/SKIP/TIMEOUT) and included in the report JSON.

**Can be skipped:** Yes — if any phase 9 prerequisite fails, or if
`-NetworkOnly` is active (no data plane query API access), or if the AI
resource was not found.

**Time cost:** 10-65 seconds (polling with backoff). This is typically the
longest single phase in a full run. In `-NetworkOnly` mode, this phase is
skipped and the script provides a manual KQL query for the user to run.

---

### Phase 11: Diagnosis and Reporting

**What happens:**
- Collects all per-check results (DNS, TCP, TLS, Ingestion, AMPLS) into a
  summary array.
- Counts: total checks, passed, failed, warnings, info.
- Orders diagnosis items: BLOCKING first, then WARNING, then INFO.
- Renders the DIAGNOSIS SUMMARY table (verbose mode only).
- Renders the WHAT TO DO section (always, when findings exist).
- Renders the footer with tips (Compact, NetworkOnly, AutoApprove,
  Az.Accounts install hint).
- Saves JSON and TXT report files (if `-OutputPath` is set).
- Sets the exit code: 0 (clean), 1 (INFO), 2 (WARNING), 3 (BLOCKING).

**Can be skipped:** No — always runs.

**Time cost:** < 1 second.

---

## Skip Logic

Skip logic is the most important design pattern in the diagnostic flow. It
prevents three problems:

1. **Wasted time** — waiting 30 seconds for a TLS timeout when TCP is blocked.
2. **Confusing cascading errors** — a DNS failure causes TCP to fail which
   causes TLS to fail which causes ingestion to fail, each producing its own
   error. Instead, only the root cause (DNS) is reported.
3. **False positives** — sending an ingestion test when the workspace is
   deleted would return HTTP 200 (the ingestion API accepts it) but the data
   is silently dropped. The script detects the broken pipeline *first* and
   skips the test to avoid a misleading "ingestion passed" result.

### Automatic Skips (Dependency Failures)

These skips fire automatically based on upstream phase results:

| Upstream Failure | Phases Skipped | Reason |
|-----------------|----------------|--------|
| DNS resolution fails (critical endpoints) | TCP, TLS, Ingestion, E2E | No IP to connect to. |
| TCP to ingestion endpoint fails | TLS (for that endpoint), Ingestion, E2E | Can't POST without TCP. |
| Ingestion returned non-200 | E2E verification | Nothing to verify. |
| Backend workspace deleted/suspended | Ingestion test, E2E | API returns 200 but data is silently dropped — would produce a false positive. |
| Ingestion BLOCKED (AMPLS pre-flight) | Ingestion test, E2E | POST would fail; root cause is network access settings. |

### Explicit Skips (User Switches)

| Switch | What It Skips |
|--------|---------------|
| `-NetworkOnly` | All Azure resource checks (AMPLS automated, known issues, E2E verification). Network checks (DNS, TCP, TLS, ingestion POST) still run. |
| `-SkipIngestionTest` | Ingestion POST and E2E verification. All other checks still run. |
| `-Compact` | Does not skip any *checks* — only changes the output format (suppresses verbose explanations and the DIAGNOSIS SUMMARY table). |

### Conditional Skips (Environment / Consent)

| Condition | What It Skips | Why |
|-----------|---------------|-----|
| Az modules not installed | AMPLS automated check, known issue checks, E2E verification | Cannot authenticate to Azure without `Az.Accounts`. |
| Non-interactive PaaS (Kudu web console) | Azure login-dependent operations | Cannot display an interactive browser login prompt from Kudu. |
| Azure consent declined | AMPLS automated check, known issue checks, E2E verification | User explicitly opted out. |
| Ingestion consent declined | Ingestion test, E2E verification | User explicitly opted out. |
| AI resource not found (Resource Graph) | Known issue checks, E2E verification | Nothing to inspect. |

---

## Consent Model

The script sends exactly one piece of data (a test telemetry record) and
authenticates to Azure using the user's own identity. Both actions require
explicit consent:

| Consent Prompt | What It Gates | Bypass |
|----------------|---------------|--------|
| **Azure resource checks** | Azure login, Resource Graph, ARM, data plane query | `-AutoApprove` or `-NetworkOnly` |
| **Ingestion test** | POST of one `availabilityResults` record | `-AutoApprove` or `-SkipIngestionTest` |

Consent prompts adapt to the environment:

- **Non-interactive PaaS** (Windows Kudu, Container Apps without PTY):
  Automatically skipped with explanation.
- **Redirected stdin** (piped input, CI runners): Automatically skipped with
  hint to use `-AutoApprove`.
- **Interactive terminal**: Shows a bordered consent box with details about
  what will happen, then waits for Y/N.

See [security-model.md](security-model.md) for the full security and data
handling documentation.

---

## Step Numbering

The STEP numbers displayed in verbose output are **dynamic** — they increment
based on which phases actually run. This means:

- In a `-NetworkOnly` run, you might see Steps 1–5 (Environment, Connection
  String, DNS, TCP, TLS) then jump to Diagnosis.
- In a full run with Azure checks, you might see Steps 1–9+.
- AMPLS validation and Known Issue Checks only get step numbers if they
  actually execute.

This design avoids confusing "Step 7 of 9" labels when Steps 6 and 8 were
skipped. Each step number represents a check that actually ran.

---

## Timing and Performance

Typical execution times by scenario:

| Scenario | Typical Duration | Bottleneck |
|----------|-----------------|------------|
| `-NetworkOnly -AutoApprove` (all passing) | 10-20 seconds | TLS probes (~3 sec each) |
| `-NetworkOnly -AutoApprove` (firewall blocking) | 15-30 seconds | TCP timeouts (5 sec each) |
| Full run with Azure checks (all passing) | 30-90 seconds | E2E polling (~65 sec max) |
| Full run, workspace over daily cap | 15-25 seconds | Skips ingestion (no E2E wait) |
| `-Compact -AutoApprove` vs. verbose | Same duration | Output mode doesn't affect check execution |

**Performance-sensitive phases:**

| Phase | Time Cost | Scaling Factor |
|-------|-----------|----------------|
| DNS Resolution | 1-3 sec | Per-hostname timeout (5 sec on failure) |
| TCP Connectivity | 1-5 sec | 5-sec timeout per blocked endpoint |
| TLS Handshake | 2-8 sec | Deprecated protocol probes add ~3 sec each |
| AMPLS / Azure Checks | 3-15 sec | ARM REST calls are sequential |
| Ingestion Test | 1-5 sec | Single HTTP POST |
| E2E Verification | 10-65 sec | Progressive backoff polling |

**Total worst case** (every endpoint blocked, every timeout hit): ~2-3
minutes. **Typical healthy run**: 30-60 seconds.

---

## Compact vs. Verbose Execution Differences

Both modes run exactly the same checks. The differences are purely in output
and consent prompt timing:

| Aspect | Verbose (default) | Compact (`-Compact`) |
|--------|-------------------|----------------------|
| Progress display | One line per endpoint per phase | One line per phase (aggregated) |
| Step headers | Full `STEP N: Title` with WHY THIS MATTERS and verbose detail | Suppressed |
| Consent timing | Just-in-time (Azure consent before AMPLS, ingestion consent before POST) | Up-front (both prompts before the progress table) |
| DIAGNOSIS SUMMARY table | Shown | Suppressed |
| WHAT TO DO section | Shown | Shown (identical) |
| Check execution | All checks run | All checks run (identical) |
| JSON/TXT reports | Identical content | Identical content |
| Exit code | Identical | Identical |

The up-front consent in compact mode ensures the clean progress table (with
its aligned columns and status labels) is never interrupted by interactive
prompts.

---

## Bash Script Parity

The companion Bash script (`test-appinsights-telemetry-flow.sh`) implements
the same diagnostic flow with equivalent phases, skip logic, and findings.
Key differences:

| Aspect | PowerShell | Bash |
|--------|-----------|------|
| DNS resolution | `[System.Net.Dns]::GetHostAddresses()` | `dig`, `nslookup`, or `getent hosts` |
| TCP connectivity | `System.Net.Sockets.TcpClient` | `timeout` + `/dev/tcp` or `nc` |
| TLS handshake | `System.Net.Security.SslStream` | `openssl s_client` |
| Azure checks | Az.Accounts + Az.ResourceGraph | `az` CLI + `az graph query` |
| Exit codes | `exit 0/1/2/3` | `exit 0/1/2/3` (identical semantics) |
| Consent model | `Read-Host` Y/N prompt | `read -p` Y/N prompt |

The phase ordering, skip logic conditions, and finding severities are
identical between both scripts.

---

## Further Reading

- [Architecture](architecture.md) — Layer-by-layer breakdown of the telemetry
  path and the 4D symptoms framework.
- [Interpreting Results](interpreting-results.md) — How to read the output,
  severity levels, and finding-by-finding reference.
- [Security Model](security-model.md) — What data the scripts access and
  send, consent gates, and SDL controls.
- [Automation & CI](automation-ci.md) — Running headlessly in pipelines with
  `-AutoApprove`.
