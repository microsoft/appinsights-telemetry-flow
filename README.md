# appinsights-telemetry-flow

Self-service diagnostic scripts for Azure Application Insights. Validate connectivity, TLS, AMPLS/Private Link, ingestion, sampling, workspace health, and agent installation — directly from the machine where your app runs. Available for PowerShell (Windows) and Bash (Linux).

## Telemetry Flow Overview

At a high level, telemetry travels from your applications, or this diagnostic script, through the following stages:

<p align="center">
  <img src="docs/images/telemetry-flow-architecture.svg" alt="Application Insights telemetry flow architecture — from app/SDK through DNS, TCP, TLS, ingestion endpoint, pipeline, and storage to query surface" />
</p>

Each box represents a layer that can independently fail, degrade, or silently
drop data. The scripts test every layer from top to bottom.

For a detailed walkthrough of each layer — what it does, what fails, and how the scripts detect it — see [Architecture: Application Insights Telemetry Flow](docs/architecture.md).

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Architecture](docs/architecture.md) | End-to-end telemetry path from SDK to query surface, the "4D" symptom model, and what can fail at every layer |
| [Running the Script](docs/running-the-script.md) | Step-by-step instructions for every Azure hosting environment — App Service, Functions, AKS, VMs, Container Apps, Cloud Shell, and more |
| [Diagnostic Flow](docs/diagnostic-flow.md) | Why the script checks what it checks, in what order, and when it skips phases |
| [Interpreting Results](docs/interpreting-results.md) | How to read the console output, understand severity levels, and act on each finding |
| [AMPLS & Private Link Deep Dive](docs/ampls-private-link-deep-dive.md) | Methodical approach to troubleshooting Private Link Scope configurations |
| [Known Issues Reference](docs/known-issues-reference.md) | Every known-issue check explained — symptom, root cause, detection logic, and fix |
| [Security Model & Data Handling](docs/security-model.md) | What the script reads, writes, and intentionally does not do — plus SDL controls |
| [Automation & CI/CD](docs/automation-ci.md) | Batch operations, JSON parsing at scale, Azure DevOps and GitHub Actions integration |
| [FAQ](docs/faq.md) | Common questions about results, edge cases, and environment-specific behavior |

---

## Test-AppInsightsTelemetryFlow

The primary diagnostic script. Runs a comprehensive, read-only connectivity and configuration check against your Application Insights resource from the machine experiencing telemetry issues.

### What It Checks

| Step | Check | Requires Azure Login |
|------|-------|:---:|
| 1 | **Environment Detection** -- OS, PowerShell version, Azure host detection (App Service, Function App, Container Apps, AKS, Cloud Shell), proxy settings | -- |
| 2 | **Connection String Parsing** -- Validates format, extracts endpoints, detects global vs. regional | -- |
| 3 | **DNS Resolution** -- All Azure Monitor endpoints (ingestion, live metrics, profiler, snapshot debugger, query API, JS SDK CDN), public/private IP classification | -- |
| 4 | **TCP Connectivity** -- Port 443 reachability with resolved IP display and latency measurement | -- |
| 5 | **TLS Handshake** -- TLS 1.2/1.3 negotiation, certificate validation, TLS inspection/MITM detection, deprecated protocol (1.0/1.1) probing | -- |
| 6 | **AMPLS Validation** -- Private Link scope discovery via Azure Resource Graph, private endpoint IP comparison against DNS, access mode analysis (Private Only vs. Open), network access assessment | :heavy_check_mark: |
| 7 | **Known Issue Checks** -- Local auth disabled, Entra ID auth mismatch, ingestion sampling %, daily cap (AI + LA with mismatch detection), workspace health (deleted/suspended), diagnostic settings duplicate telemetry, DCR workspace transforms | :heavy_check_mark: |
| 8 | **Telemetry Ingestion Test** -- Sends a test `availabilityResults` record to `v2.1/track`, verifies HTTP 200, then queries the data plane API to confirm the record arrived with latency breakdown | -- (E2E verification: :heavy_check_mark:) |

The script uses **smart skip logic**: if TCP connectivity to the ingestion endpoint fails, TLS handshake and telemetry ingestion tests are automatically skipped (since they cannot succeed without an open TCP connection). This avoids wasting 20+ seconds on pointless TLS timeouts in firewall-blocked environments. See [Diagnostic Flow](docs/diagnostic-flow.md) for the complete phase map and skip-logic rules.

All Azure operations are **read-only**. The script never modifies any resource.

### Quick Start

**Option 1: Download and run directly**

```powershell
# Download
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/appinsights-telemetry-flow/main/powershell/Test-AppInsightsTelemetryFlow.ps1" -OutFile "Test-AppInsightsTelemetryFlow.ps1"

# Full diagnostic (verbose output, Azure checks auto-detected)
.\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..."

# Compact output for quick checks
.\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -Compact

# Network checks only (no Azure login required)
.\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -NetworkOnly
```

**Option 2: Install from PowerShell Gallery**

```powershell
Install-Script -Name Test-AppInsightsTelemetryFlow
Test-AppInsightsTelemetryFlow -ConnectionString "InstrumentationKey=xxx;..."
```

**Option 3: Auto-detect in App Service (Kudu console)**

```powershell
# If APPLICATIONINSIGHTS_CONNECTION_STRING is set in app settings, just run:
.\Test-AppInsightsTelemetryFlow.ps1
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ConnectionString` | No* | App Insights connection string. Auto-detected from environment variables if not provided. |
| `-Compact` | No | Compact progress-line output. Default is verbose with full tables and educational explanations. |
| `-NetworkOnly` | No | Skip all Azure-authenticated checks. Only run DNS, TCP, TLS, and ingestion tests. |
| `-TenantId` | No | Entra ID tenant for multi-tenant scenarios. |
| `-SkipIngestionTest` | No | Skip the test telemetry send (DNS/TCP/TLS only). |
| `-OutputPath` | No | Directory or filepath for report files. Defaults to the script's directory. |
| `-AutoApprove` | No | Bypass interactive consent prompts. Equivalent to answering "Y" to every consent prompt. Required for non-interactive/automated environments. |
| `-AmplsExpectedIps` | No | Hashtable of FQDN-to-IP mappings for manual AMPLS validation without Azure login. |
| `-LookupAmplsIp` | No | Private IP address to reverse-lookup. Finds the AMPLS resource that owns the private endpoint for this IP. The IP must have been resolved during the current run. |

\* Auto-detected from `APPLICATIONINSIGHTS_CONNECTION_STRING` or `APPINSIGHTS_INSTRUMENTATIONKEY` environment variables.

### Interactive Consent Prompts

The script asks for consent before performing operations that leave the local machine:

| Prompt | When | What it gates |
|--------|------|---------------|
| **Azure Resource Queries** | Before Azure login / resource discovery | All Azure Resource Graph queries, ARM REST API GET calls, and data plane KQL verification |
| **Telemetry Ingestion Test** | Before sending the test record | The single `availabilityResults` POST to your ingestion endpoint (~0.5 KB) |

**Behavior by environment:**

| Mode | Behavior |
|------|----------|
| Interactive (default) | Y/N prompt shown before each operation |
| `-AutoApprove` | Automatic YES -- no prompts shown |
| Non-interactive (App Service, AKS, etc.) without `-AutoApprove` | Fail closed -- gated operations are skipped with a warning |
| Non-interactive + `-AutoApprove` | Automatic YES -- operations proceed without prompts |

**Verbose mode** shows the prompts just-in-time at the natural point in the diagnostic flow. **Compact mode** shows both prompts before the progress table so the table output stays clean.

To skip the gated operations entirely, use `-NetworkOnly` (skip Azure checks) and `-SkipIngestionTest` (skip the test telemetry send).

### Azure Resource Checks (Automatic)

If the `Az.Accounts` module is installed and you have an active Azure login (`Connect-AzAccount`), the script automatically performs:

- AMPLS / Private Link validation with private endpoint IP comparison
- Network access assessment (public ingestion enabled/disabled, query access)
- Known issue checks (local auth, daily cap, workspace health, sampling, DCR transforms)
- End-to-end data plane verification with latency breakdown

No extra switches needed. If the module isn't found, these checks are skipped gracefully and the script runs network-only checks. If the module is installed but you're not logged in, the script will attempt an interactive login (on desktops and Cloud Shell) or skip gracefully (on App Service, Function App, Container Apps, and AKS where interactive login isn't available).

Use `-NetworkOnly` to explicitly skip Azure checks even when logged in.

### Output Modes

**Default (verbose)** -- Full tables, educational explanations for each step ("Why This Matters", "What We're Checking", "What Success Looks Like"), and detailed diagnostics. Designed for support engineers walking users through troubleshooting, or for customers running the script themselves.

**Compact (`-Compact`)** -- Compact progress lines with pass/fail status and a focused diagnosis summary at the end. Ideal for quick checks and automation.

```
  DNS Resolution ...................... OK     12/12 resolved (all public IPs)
  TCP Connectivity .................... OK     12/12 reachable on :443
  TLS Handshake ....................... OK     TLS 1.2, Microsoft cert
  Telemetry Ingestion ................. OK     HTTP 200, accepted [412ms]
  End-to-End Verification ............. OK     Record arrived (E2E: 8.2s)
```

Both modes produce a **Diagnosis Summary** at the end with a prioritized action plan when issues are found:

```
  ================================================================
  DIAGNOSIS SUMMARY                                   2 findings
  ================================================================

  BLOCKING  #1  10 endpoint(s) blocked on port 443 (firewall or NSG)
  INFO      #2  TLS inspection detected (Zscaler)

  ================================================================
  WHAT TO DO (in priority order)
  ================================================================

  #1 [BLOCKING] TCP Connection Failures (Port 443)
     10 endpoint(s) blocked. A firewall or NSG is preventing outbound connections.
     -> Fix: Check NSG outbound rules, Azure Firewall, UDRs, and proxy settings.
     -> Docs: https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses
```

### Report Files

Every run automatically saves two report files:

- **JSON** (`AppInsights-Diag_{hostname}_{resource}_{timestamp}.json`) -- Machine-parseable with all raw results, environment info, and diagnosis details. Attach this to support tickets.
- **TXT** (`AppInsights-Diag_{hostname}_{resource}_{timestamp}.txt`) -- Human-readable console output mirror with metadata header and diagnosis summary. Useful to attach alongside the JSON when filing support tickets.

When the App Insights resource name is discovered via Azure checks it is included in the filename; otherwise the `{resource}` segment is omitted.

### Exit Codes

The script returns exit codes for use in automation and batch scripts:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No issues found (all checks passed, no diagnosis findings) |
| `1` | INFO findings only (informational items, no action required) |
| `2` | WARNING detected (telemetry at risk but may still work) |
| `3` | BLOCKING issue detected (telemetry is broken) |

```powershell
# Example: automation usage
.\Test-AppInsightsTelemetryFlow.ps1 -Compact
if ($LASTEXITCODE -eq 3) { Write-Host "CRITICAL: Telemetry pipeline is broken" }
```

For batch operations, CI/CD pipeline integration, and JSON report parsing at scale, see [Automation & CI/CD](docs/automation-ci.md).

### Where to Run It

The script is designed to run from both a developer machine and from the machine or environment currently experiencing telemetry issues:

| Environment | Notes |
|-------------|-------|
| Azure App Service | Kudu/SCM PowerShell console -- auto-detects SKU and region |
| Azure Function App | Kudu console -- auto-detects runtime and extension version |
| Azure Logic Apps (Standard) | Kudu console -- same App Service platform |
| Azure Container Apps | Portal console or `az containerapp exec` -- auto-detects app name and revision |
| AKS / Kubernetes | `kubectl exec` into pods -- auto-detects cluster API endpoint |
| Azure Spring Apps | `az spring app connect` -- Linux containers |
| Azure VMs / VMSS | RDP, SSH, Bastion, or Run Command -- full PowerShell/Bash environment |
| Azure Cloud Shell | Pre-authenticated -- useful for comparison testing |
| On-premises servers | Behind VPN/ExpressRoute for AMPLS scenarios |
| Developer workstations | Local debugging and validation |

For detailed step-by-step instructions with screenshots for each environment, see [Running the Script](docs/running-the-script.md).

Azure hosting environments are detected automatically via platform-injected environment variables (no network calls or authentication required).

### Kudu / Web Console Compatibility

The script automatically detects Kudu and web consoles that lack full console color support and switches to plain text output mode. All formatting (tables, progress lines, multi-segment output lines) renders correctly in Kudu without relying on `Start-Transcript` or `SetConsoleTextAttribute`.

### Requirements

| Requirement | Network checks | Azure resource checks |
|-------------|:---:|:---:|
| PowerShell 5.1+ (Windows) or 7+ (Linux/macOS) | :heavy_check_mark: | :heavy_check_mark: |
| Network access to Azure Monitor endpoints | :heavy_check_mark: | :heavy_check_mark: |
| `Az.Accounts` module | -- | :heavy_check_mark: (auto-detected) |
| `Az.ResourceGraph` module | -- | :heavy_check_mark: (auto-detected) |
| Azure RBAC: Reader on the App Insights resource | -- | :heavy_check_mark: |

---

## Troubleshooting Common Scenarios

For detailed guidance on reading the output and acting on every finding, see [Interpreting Results](docs/interpreting-results.md).

### "I'm not seeing any telemetry"

The script checks whether telemetry can reach Azure (DNS, TCP, TLS), whether it's accepted (ingestion API returns HTTP 200), and whether it actually lands in storage (E2E data plane verification). If you're logged in to Azure, it also checks for configuration issues that may silently drop data: disabled local auth, daily cap reached, deleted workspace, suspended subscription, and ingestion sampling. See [Known Issues Reference](docs/known-issues-reference.md) for the complete list of silent-failure checks.

### "Telemetry is delayed"

Run with Azure login active to enable E2E verification. The latency breakdown shows how long the test record took from send to queryable, helping distinguish between network latency and pipeline processing time.

### "Some telemetry types are missing"

The known issue checks detect common causes of partial data loss: ingestion sampling reducing volume, daily caps silently dropping data after the limit, DCR workspace transforms that filter specific rows, and diagnostic settings that duplicate telemetry across tables.

### "I think Private Link / AMPLS is misconfigured"

With Azure login active, the script discovers all AMPLS resources linked to your App Insights component via Azure Resource Graph, retrieves expected private endpoint IPs, compares them against DNS results from the machine, reports access mode settings (Private Only vs. Open), and assesses whether the current network location is allowed to send telemetry. For a deep walkthrough of AMPLS scenarios, DNS zone behavior, and access modes, see [AMPLS & Private Link Deep Dive](docs/ampls-private-link-deep-dive.md).

### "Firewall or NSG is blocking telemetry"

The script tests TCP connectivity to all 12 Azure Monitor endpoints. When the ingestion endpoint is blocked, TLS and ingestion tests are automatically skipped with clear messaging, and the diagnosis summary identifies the exact IPs and ports that need to be allowed.

---

---

## Security, Privacy & Consent

For a comprehensive treatment of the security model — including SDL controls, threat model, data classification, and enterprise deployment recommendations — see [Security Model & Data Handling](docs/security-model.md).

### What the script reads

All Azure operations are **read-only**. The script never creates, modifies, or deletes any Azure resource. Specifically:

- **Azure Resource Graph** (read): Finds your App Insights resource by instrumentation key, discovers linked AMPLS resources, and locates workspace transform DCRs.
- **ARM REST API** (GET only): Retrieves AMPLS access modes, scoped resources, private endpoint DNS/NIC configurations, daily cap settings, diagnostic settings, and Log Analytics workspace state.
- **Data plane** (read): If the ingestion test returns HTTP 200, the script queries the App Insights data plane API (KQL) to verify the test record arrived.

### What the script sends

The only data written is a single **test telemetry record** (~0.5 KB `availabilityResults` document) sent to your Application Insights ingestion endpoint. This record:

- Appears in your resource's Availability blade as `Telemetry-Flow-Diag Ingestion Validation`
- Uses your connection string's instrumentation key
- Is subject to standard ingestion costs
- Can be skipped entirely with `-SkipIngestionTest`

### Consent model

The script prompts for interactive consent before Azure resource queries and before the telemetry send. Use `-AutoApprove` to bypass prompts in automated environments, or `-NetworkOnly` / `-SkipIngestionTest` to skip the gated operations entirely. See [Interactive Consent Prompts](#interactive-consent-prompts) above for details.

### Credentials and authentication

The script does not collect, store, or transmit any credentials. Azure authentication is handled entirely by `Az.Accounts` (PowerShell) or `az login` (Bash), using your existing login session. If no active session exists, and the environment supports it, the script invokes the standard interactive login flow provided by these tools.

### Report files

The JSON and TXT report files are saved locally and contain diagnostic results, environment metadata (hostname, OS, Azure host type), and your connection string's instrumentation key. Review these files before attaching them to support tickets or sharing externally.

---

## test-appinsights-telemetry-flow.sh (Bash)

A Bash port of the PowerShell script with the same capabilities and output format. Use this on Linux hosts, containers, and environments where PowerShell is not available.

```bash
# Full diagnostic
./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..."

# Compact output
./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --compact

# Network only (no Azure login)
./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --network-only

# Non-interactive / CI
./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --auto-approve
```

Requires Bash 5.0+ and `curl`. Azure resource checks require the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) with the `resource-graph` extension.

---

## Repository Structure

```
appinsights-telemetry-flow/
+-- powershell/
|   +-- Test-AppInsightsTelemetryFlow.ps1  # Primary diagnostic script (PowerShell)
|   +-- Test-AppInsightsAgentStatus.ps1    # Agent auto-instrumentation diagnostics
+-- bash/
|   +-- test-appinsights-telemetry-flow.sh # Bash port (Linux/macOS/WSL)
+-- docs/
|   +-- architecture.md                    # Telemetry flow architecture and failure modes
|   +-- diagnostic-flow.md                 # Script phases, ordering, and skip logic
|   +-- interpreting-results.md            # Reading output, severity levels, finding reference
|   +-- ampls-private-link-deep-dive.md    # AMPLS troubleshooting framework
|   +-- known-issues-reference.md          # Known-issue checks explained
|   +-- security-model.md                  # Security, SDL controls, data handling
|   +-- automation-ci.md                   # Batch ops, CI/CD pipelines, JSON parsing
|   +-- faq.md                             # Frequently asked questions
|   +-- running-the-script.md              # Per-environment instructions with screenshots
|   +-- images/                            # Diagrams and architecture SVGs
+-- README.md
+-- LICENSE
```

---

## Contributing

Please open an issue to discuss proposed changes. For contributing information see [Contributing Details](CONTRIBUTING.md)

## Support

This tool is provided as-is to assist with troubleshooting. For Azure Monitor support, please use the [Azure support channels](https://azure.microsoft.com/support/).

If you find a bug or have a feature request, please [open an issue](https://github.com/microsoft/appinsights-telemetry-flow/issues).

## Disclaimer

These scripts are provided as samples for diagnostic and troubleshooting purposes. They are not official Microsoft products and are not supported under any Microsoft standard support program or service.

These scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of these scripts and their documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of these scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use these scripts or their documentation, even if Microsoft has been advised of the possibility of such damages.

## License

[MIT License](LICENSE)