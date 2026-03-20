# Security Model & Data Handling

> How the script protects your data, what it reads, what it writes, and what
> it intentionally does **not** do.

---

## Table of Contents

- [Design Principles](#design-principles)
- [Data Classification](#data-classification)
- [Read Operations Inventory](#read-operations-inventory)
- [Write Operations (Single POST)](#write-operations-single-post)
- [Consent Gates](#consent-gates)
- [Security Development Lifecycle Controls](#security-development-lifecycle-controls)
  - [TLS 1.2+ Enforcement](#tls-12-enforcement)
  - [iKey GUID Validation](#ikey-guid-validation)
  - [Endpoint SSRF Protection](#endpoint-ssrf-protection)
  - [OutputPath Validation](#outputpath-validation)
  - [iKey Masking](#ikey-masking)
  - [Email Masking](#email-masking)
  - [Debug Output Truncation](#debug-output-truncation)
- [Report File Contents](#report-file-contents)
- [Credential & Token Handling](#credential--token-handling)
- [PaaS Environment Detection](#paas-environment-detection)
- [What the Script Does NOT Do](#what-the-script-does-not-do)
- [Network Exposure Summary](#network-exposure-summary)
- [Threat Model Summary](#threat-model-summary)
- [Bash Parity](#bash-parity)
- [Recommendations for Enterprise Deployment](#recommendations-for-enterprise-deployment)

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Read-only by default** | Every Azure API call is a GET or a query. The script never creates, modifies, or deletes any Azure resource. |
| **Informed consent** | Two separate Y/N prompts — one for Azure resource queries, one for the ingestion test — each explain exactly what will happen before the user types `Y`. |
| **Minimal footprint** | One self-contained `.ps1` file. No modules bundled, no external dependencies downloaded at runtime, no background services installed. |
| **No phone-home** | The script sends **zero** telemetry to the script author or any third party. The only outbound POST is the optional test record directed at **your own** Application Insights resource. |
| **Least privilege** | Azure checks use whatever identity the operator already has (`Connect-AzAccount`). The script never requests elevated roles or creates service principals. |
| **Defense in depth** | Multiple Security Development Lifecycle (SDL) controls (described below) validate inputs before they reach any network call or file-system operation. |

---

## Data Classification

The script handles several categories of data during a diagnostic run.
None of these are treated as secrets, but the script still minimizes
exposure through masking and consent.

| Category | Examples | Sensitivity | How the Script Handles It |
|----------|----------|-------------|---------------------------|
| **Connection string** | `InstrumentationKey=<GUID>;IngestionEndpoint=https://…` | Addressing — **not** a secret (iKey is an addressing mechanism, not an auth credential) | iKey masked to `abcdefab...ef12` (first 8 + last 4 chars) in console and reports |
| **Hostnames & IPs** | Ingestion FQDN, resolved IP addresses, private endpoint IPs | Infrastructure metadata | Displayed in full (needed for diagnosis); saved in reports |
| **Azure resource names** | App Insights resource name, Log Analytics workspace name, AMPLS name | Organisational metadata | Displayed in full when Azure checks are active |
| **Azure identity** | UPN of the logged-in user (from `Get-AzContext`) | PII | Masked via `Get-MaskedEmail` → `us***@contoso.com` |
| **Machine identity** | `$env:COMPUTERNAME`, OS version, PowerShell version, Azure host type | Infrastructure metadata | Included in reports; hostname sanitised for filename safety |
| **Telemetry ingestion response** | HTTP status, `itemsReceived` / `itemsAccepted` counts | Operational | Displayed in full |
| **Bearer tokens** | Azure AD / Entra ID access tokens for ARM and data plane | Credential | Held in memory only, never written to reports or console; see [Credential Handling](#credential--token-handling) |

---

## Read Operations Inventory

Every outbound operation the script performs is listed here.
"Authentication Required" means the operation uses an `Az.Accounts`
session obtained via `Connect-AzAccount`.

### Network Tests (no authentication)

| Protocol | Target | Purpose |
|----------|--------|---------|
| **DNS** | `Resolve-DnsName` / `nslookup` for each endpoint FQDN | Verify DNS resolution and detect AMPLS private-link IPs |
| **TCP** | `TcpClient` connect to port 443 | Verify network path to ingestion and live endpoints |
| **TLS** | `SslStream` handshake on port 443 | Verify TLS negotiation, certificate chain, and protocol version |

### Azure Resource Graph Queries (authentication required)

| Query | Purpose |
|-------|---------|
| `Search-AzGraph` — find App Insights resource by iKey | Locate the resource and its subscription / resource group |
| `Search-AzGraph` — find AMPLS scoped resources | Discover any Private Link Scope linked to the App Insights resource |
| `Search-AzGraph` — find workspace transform DCRs | Detect data collection rules with transforms that may drop or alter telemetry |
| `Search-AzGraph` — find NIC by private IP | Ghost AMPLS reverse lookup: locate the network interface that owns a specific private IP |
| `Search-AzGraph` — find Private Endpoint by NIC | Ghost AMPLS reverse lookup: trace the NIC to its parent private endpoint |

### ARM REST API GETs (authentication required)

| Endpoint | Purpose |
|----------|---------|
| AMPLS scoped resources | Read which resources are linked to the AMPLS |
| Private endpoint DNS configuration | Read expected private IP mappings |
| AMPLS access modes (ingestion / query) | Determine if Private Only or Open |
| AMPLS resource details (via PE connection) | Ghost AMPLS reverse lookup: read AMPLS properties from a private endpoint's service connection |
| Log Analytics workspace properties | Check workspace health, access mode |
| Pricing plans / daily cap | Read daily cap GB and reset time |
| Diagnostic settings | Detect duplicate diagnostic settings |

### Data Plane Query (authentication required)

| Endpoint | Purpose |
|----------|---------|
| `POST api.applicationinsights.io` (or gov/china equivalent) — KQL query | Verify the test record arrived; measure end-to-end latency |

> **All of the above are read-only.**  The script uses only `GET` methods
> against ARM and `POST` with a KQL query body against the data plane.
> No `PUT`, `PATCH`, or `DELETE` calls exist in the codebase.

---

## Write Operations (Single POST)

The script performs exactly **one** write operation — the optional
telemetry ingestion test — and only after explicit user consent.

| Field | Value |
|-------|-------|
| **HTTP Method** | `POST` |
| **URL** | `{IngestionEndpoint}/v2.1/track` |
| **Content-Type** | `application/json` |
| **Payload size** | ~0.5 KB |
| **Record type** | `AvailabilityData` (availability results — deliberately chosen because this type is never sampled out by ingestion sampling) |
| **Record name** | `"Telemetry-Flow-Diag Ingestion Validation"` |
| **Message** | `"[{ComputerName}] Telemetry flow diagnostic test record - safe to ignore"` |
| **Custom properties** | `diagnosticRunId` (GUID), `scriptVersion` |
| **Tags** | `ai.cloud.roleInstance = "Telemetry-Flow-Diag"`, `ai.internal.sdkVersion = "telemetry-flow-diag:{version}"` |
| **Authentication** | None — the iKey in the JSON body is the only addressing mechanism. No Entra ID token is used for this POST. |
| **Consent required** | Yes — via the "TELEMETRY INGESTION TEST" consent prompt |
| **Cost impact** | Standard ingestion and retention rates apply. For a single ~0.5 KB record this is negligible. |

The record is deliberately benign:

- It contains **no** PII or environment details beyond the
  computer name in the `message` field.
- The `diagnosticRunId` is a random GUID generated fresh each run — it
  carries no identifying information.
- The record is self-describing (`"safe to ignore"`) so anyone reviewing
  the App Insights data knows what it is.

---

## Consent Gates

The script has a layered consent model with two independent gates.
Each gate is a full-screen prompt that describes **what will happen**
and **how to skip** before asking for Y/N confirmation.

### Gate 1 — Azure Resource Checks

| Aspect | Detail |
|--------|--------|
| **Trigger** | Az modules detected and not `-NetworkOnly` |
| **What it discloses** | Resource Graph queries, ARM GET calls, data plane KQL (conditional) |
| **Skip options** | Press N, or re-run with `-NetworkOnly` |
| **Session variable** | `$script:AzureConsentDeclined` |

### Gate 2 — Telemetry Ingestion Test

| Aspect | Detail |
|--------|--------|
| **Trigger** | Not `-SkipIngestionTest` and no upstream blocker |
| **What it discloses** | Record type, name, size, source machine, destination endpoint, cost |
| **Skip options** | Press N, or re-run with `-SkipIngestionTest` |
| **Session variable** | `$script:IngestionConsentDeclined` |

### Consent Bypass Mechanisms

| Mechanism | Behaviour |
|-----------|-----------|
| `-AutoApprove` | Answers `Y` to both prompts automatically. Designed for CI/CD and scheduled tasks. |
| Non-interactive PaaS detection | If the script detects it is running on App Service / Function App / Container App / AKS (and not Cloud Shell) **and** the operation requires Azure login, the consent is **auto-declined** with a message explaining why. The ingestion test (which does not require Azure login) still prompts normally. |
| Redirected stdin | If `[Console]::IsInputRedirected` is `$true`, consent is auto-declined with guidance to use `-AutoApprove`. |
| Console handle failure | If `Read-Host` throws (e.g., Windows Kudu web console), consent is auto-declined with the same guidance. |

### Timing

| Output Mode | Azure Consent | Ingestion Consent |
|-------------|---------------|-------------------|
| **Compact** (`-Compact`) | Before the progress table (up-front) | Before the progress table (up-front) |
| **Verbose** (default) | Just-in-time, before AMPLS validation step | Just-in-time, before ingestion test step |

---

## Security Development Lifecycle Controls

### TLS 1.2+ Enforcement

```powershell
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor
    [Net.SecurityProtocolType]::Tls12
```

Set at script startup. Forces all `Invoke-WebRequest` and
`Invoke-RestMethod` calls to negotiate TLS 1.2 or higher, even on
older .NET Framework versions that default to TLS 1.0/1.1.

Does **not** affect the `SslStream`-based TLS diagnostic probes, which
specify their protocol explicitly (the whole point of those probes is to
test what the endpoint supports).

### iKey GUID Validation

```
^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$
```

The `Test-InstrumentationKeyFormat` function validates that the iKey
extracted from the connection string is a strict GUID before it is used
in any Azure Resource Graph query or KQL expression. This prevents
injection attacks via crafted connection strings where a malicious iKey
could alter the query semantics.

If validation fails, the script exits immediately with exit code 1.

### Endpoint SSRF Protection

The `Test-AzureMonitorEndpoint` function validates every endpoint URL
parsed from the connection string before any network call is made:

1. **Scheme** — must be `https://`
2. **IP addresses blocked** — no raw IPs allowed (prevents SSRF to
   IMDS `169.254.169.254`, WireServer `168.63.129.16`, loopback,
   RFC 1918, link-local addresses)
3. **Localhost / internal hostnames blocked** — `localhost`, `.internal`,
   `.local` all rejected
4. **Domain allowlist** — hostname must match one of these patterns:
   - `*.in.applicationinsights.azure.{com|us|cn}` (regional ingestion)
   - `*.applicationinsights.azure.{com|us|cn}` (App Insights services)
   - `*.monitor.azure.{com|us|cn}` (Azure Monitor services)
   - `*.services.visualstudio.com` (legacy endpoints)
   - `*.applicationinsights.{io|us}` (data plane API)

If validation fails, the script exits immediately with exit code 1.

### OutputPath Validation

Before writing any report file, `-OutputPath` is validated:

| Check | What It Blocks | Action |
|-------|---------------|--------|
| **UNC path** | `^\\\\` pattern matches network shares (`\\server\share`) | Falls back to script directory with error message |
| **Path traversal** | `..` components resolved via `[IO.Path]::GetFullPath()` | Resolved to absolute path with a warning; continues with the resolved path |
| **Hostname sanitisation** | `$env:COMPUTERNAME` is cleaned with `[\\/:*?"<>|\s\(\)]` → `_` | Prevents malformed filenames |

These controls prevent reports (which contain partial iKeys and internal
hostnames) from being written to unexpected network locations.

### iKey Masking

```powershell
$maskedKey = $iKey.Substring(0, 8) + "..." + $iKey.Substring($iKey.Length - 4)
#  abcdefab-1234-5678-9abc-def012345678  →  abcdefab...5678
```

The masked form appears in:
- Console banner
- Progress lines
- DIAGNOSIS SUMMARY
- JSON report (`ConnectionString.InstrumentationKey`)
- TXT report header

The full iKey is **only** present in:
- The original connection string (if the user typed it at the command line — visible in their shell history, not the script's output)
- The JSON body of the ingestion POST (sent directly to the user's own endpoint)
- Memory during script execution

### Email Masking

```powershell
Get-MaskedEmail "username@contoso.com"  →  "us***@contoso.com"
```

The currently logged-in Azure identity (UPN) is masked before display.
Only the first two characters of the local part are shown.

### Debug Output Truncation

When `-Debug` is passed, HTTP request/response bodies are logged to the
console. A configurable `$DebugTruncateLength` (default: 500 characters)
truncates large bodies to prevent accidental exposure of full API
responses.

```
[DEBUG] <<< Body: {"tables":[{"name":"PrimaryResult"...  (4821 chars total)
```

Set `$DebugTruncateLength = 0` to disable truncation (full dump).

---

## Report File Contents

Two files are written after every run:

### JSON Report (`AppInsights-Diag_{host}_{resource}_{timestamp}.json`)

Machine-parseable. Contains:

| Section | Fields | Notes |
|---------|--------|-------|
| `ToolVersion` | Script version string | |
| `Timestamp` | UTC ISO 8601 | |
| `Environment` | Computer name, OS, PowerShell version, Azure host type/detail, proxy info, color support | Identifies the machine and runtime |
| `ConnectionString` | **Masked** iKey, ingestion endpoint, live endpoint, cloud label | Full iKey is never written |
| `Results.DNS` | Per-endpoint FQDN, resolved IPs, response time | |
| `Results.TCP` | Per-endpoint FQDN, port 443 reachability, response time | |
| `Results.TLS` | Per-endpoint FQDN, protocol version, cipher, certificate chain | |
| `Results.AMPLS` | Checked flag, resource found, linked, access modes, IP comparison results, access assessment | Only present when Azure checks ran |
| `Results.Ingestion` | HTTP status, response body, duration, test record ID/timestamp | Only present when ingestion test ran |
| `Results.EndToEndVerification` | Status, record found, poll attempts, latency breakdown | Only present when E2E verify ran |
| `KnownIssues` | Local auth, sampling %, workspace status, daily cap, transforms | Only present when Azure checks ran |
| `Diagnosis` | Array of `{ Severity, Title, Summary, Description, Fix, Portal, Docs }` | The WHAT TO DO findings |
| `Summary` | Pass/warn/fail counts, AMPLS flags, Azure check status | |

### TXT Report (`AppInsights-Diag_{host}_{resource}_{timestamp}.txt`)

Human-readable. Contains:

- Header block (timestamp, host, masked iKey, endpoint, Azure resource names)
- DIAGNOSIS SUMMARY (severity + one-line summary per finding)
- Full console output (captured via `Write-HostLog` override — a `StringBuilder` that mirrors everything written to the console, with colour information stripped)

### What Is NOT in Reports

- Full instrumentation key
- Azure AD / Entra ID bearer tokens
- Connection string in raw form (beyond the masked iKey and plain-text endpoints)
- Environment variable values (only names are checked)
- File system contents
- Process lists or system configuration

---

## Credential & Token Handling

| Aspect | Behaviour |
|--------|-----------|
| **Azure login** | `Connect-AzAccount` — interactive browser flow. The script never handles passwords or client secrets. |
| **Token acquisition** | `Get-AzAccessToken -ResourceUrl "https://api.applicationinsights.io"` (or gov/china).  Returns a token scoped to the data plane API. |
| **SecureString handling** | Az.Accounts 5.x returns tokens as `SecureString`. The script converts to plain text in memory (required for HTTP `Authorization` headers) via `Marshal::SecureStringToBSTR`. |
| **Token storage** | Tokens are held in local variables during script execution. They are **never** written to any file, log, or console output — even in `-Debug` mode (debug logging shows `Token acquired (N chars)` but not the token value). |
| **Token lifetime** | Tokens are not refreshed. The script's execution window (30–90 seconds) is well within the default token lifetime. |
| **Credential caching** | The script does not manage any credential cache. `Az.Accounts` handles its own token cache in `~/.Azure/` as part of normal Azure PowerShell behaviour. The script does not read from or write to this cache directly. |

---

## PaaS Environment Detection

The script reads environment variable **names** (not arbitrary values)
to determine what Azure compute platform it is running on:

| Variable | Detects |
|----------|---------|
| `FUNCTIONS_WORKER_RUNTIME` | Azure Function App |
| `FUNCTIONS_EXTENSION_VERSION` | Function App version (detail) |
| `WEBSITE_SITE_NAME` | Azure App Service |
| `WEBSITE_SKU` | App Service SKU (detail) |
| `REGION_NAME` | App Service region (detail) |
| `CONTAINER_APP_NAME` | Azure Container App |
| `CONTAINER_APP_REVISION` | Container App revision (detail) |
| `KUBERNETES_SERVICE_HOST` / `_PORT` | Kubernetes (AKS or other) |
| `ACC_CLOUD` | Azure Cloud Shell |
| `KUDU_APPPATH` | Kudu / SCM console (supplemental) |
| `COMPUTERNAME` | Machine name |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Connection string auto-detection |
| `APPINSIGHTS_INSTRUMENTATIONKEY` | Legacy iKey auto-detection |
| `ApplicationInsights__ConnectionString` | .NET config convention |
| `APPLICATIONINSIGHTS_CONNECTIONSTRING` | Alternate spelling |

The script reads the **value** of the connection string variables (to
parse the connection string) and the Azure host detail variables (SKU,
region, revision — for display). It does **not** enumerate all
environment variables or read any variable not listed above.

Docker container detection uses `Test-Path /.dockerenv` — a file
existence check only, no content read.

---

## What the Script Does NOT Do

This section exists to provide explicit negative assurances for security
review.

| Category | Assurance |
|----------|-----------|
| **No phone-home telemetry** | The script sends no data to the script author, GitHub, NuGet, or any third-party endpoint. The only outbound POST is to your own Application Insights ingestion endpoint. |
| **No external downloads** | The script does not fetch executables, scripts, modules, or updates from the internet at runtime. It is fully self-contained. |
| **No credential storage** | The script does not save, export, or persist any credentials, tokens, or secrets to disk. |
| **No resource modifications** | The script never calls ARM PUT, PATCH, DELETE, or any Azure management operation that changes state. |
| **No background processes** | The script does not install services, scheduled tasks, registry entries, or background agents. |
| **No elevation required** | The script runs in the user's current session. It does not request or require administrator / root privileges. |
| **No module installation** | The script does not install PowerShell modules. If `Az.Accounts` or `Az.ResourceGraph` are missing, it tells the user and skips Azure checks. |
| **No file system scanning** | The script reads only its own parameters and the specific environment variables listed above. It does not scan directories, read application config files, or inspect other processes. |
| **No network scanning** | The script connects only to the endpoints derived from the connection string (plus the Azure management plane if Azure checks are enabled). It does not scan ports, subnets, or other hosts. |
| **No certificate export** | TLS probes inspect the server certificate chain in memory during the handshake. No certificates are saved to disk or transmitted. |

---

## Network Exposure Summary

All outbound connections target well-known Azure endpoints on port 443 (HTTPS).

| Destination | When | Auth |
|-------------|------|------|
| `{region}.in.applicationinsights.azure.{com\|us\|cn}` | Always (DNS, TCP, TLS) + ingestion POST | None (iKey in body) |
| `dc.{services.visualstudio.com\|applicationinsights.azure.us\|applicationinsights.azure.cn}` | Always (DNS, TCP, TLS) | None |
| `live.applicationinsights.azure.{com\|us\|cn}` | Always (DNS, TCP, TLS) | None |
| `rt.{services.visualstudio.com\|applicationinsights.azure.us\|applicationinsights.azure.cn}` | Always (DNS, TCP, TLS) | None |
| `management.azure.{com\|us\|cn}` | Azure checks only | Entra ID token (via Az.Accounts) |
| `api.applicationinsights.{io\|us\|azure.cn}` | E2E verification only | Entra ID token (via Az.Accounts) |
| `login.microsoftonline.{com\|us}` / `login.chinacloudapi.cn` | Azure login (if needed) | Interactive browser flow |

No inbound connections are opened. No listening sockets are created.

---

## Threat Model Summary

| Threat | Mitigation |
|--------|------------|
| **Malicious connection string (SSRF)** | `Test-AzureMonitorEndpoint` blocks IP addresses, localhost, internal hostnames, and non-Azure domains before any network call. |
| **Injection via crafted iKey** | `Test-InstrumentationKeyFormat` enforces strict GUID regex before iKey is used in KQL or ARG queries. |
| **Report exfiltration via UNC path** | `OutputPath` rejects `\\server\share` paths; reports stay local. |
| **Path traversal via OutputPath** | Path components with `..` are resolved to absolute before use. |
| **Token leakage in logs** | Bearer tokens are never written to console, debug output, or report files. Debug logging shows only length. |
| **iKey leakage in reports** | iKey is masked to first-8 + last-4 characters in all output. |
| **Identity leakage** | Azure UPN is masked to `xx***@domain.com`. |
| **Consent bypass** | Two independent consent gates with graceful fallback for non-interactive environments. `-AutoApprove` is an explicit, auditable opt-in. |
| **Stale TLS / weak protocols** | Script forces TLS 1.2+ for its own HTTP calls at startup. |
| **Supply chain** | Single self-contained `.ps1` — no dependencies to compromise. |

---

## Bash Parity

The Bash port (`test-appinsights-telemetry-flow.sh`) implements the same
security model with platform-appropriate equivalents:

| PS Mechanism | Bash Equivalent |
|--------------|-----------------|
| `Test-InstrumentationKeyFormat` (GUID regex) | Bash regex (`[[ $ikey =~ ^[0-9a-fA-F]{8}-... ]]`) |
| `Test-AzureMonitorEndpoint` (SSRF allowlist) | `validate_endpoint_url()` with the same domain patterns |
| iKey masking (`Substring`) | `${ikey:0:8}...${ikey: -4}` |
| Consent prompts (`Read-Host`) | `read -r -p` with the same prompt text |
| TLS enforcement | Curl `--tlsv1.2` flag |
| OutputPath UNC blocking | N/A (UNC paths do not apply on Linux/macOS) |
| Debug truncation | `${body:0:$truncate_len}` |

Azure resource checks in PowerShell use `Az.Accounts` and
`Az.ResourceGraph`. The Bash script performs equivalent network-level
checks and, when Azure CLI (`az`) is installed and authenticated
(`az login`), also runs Azure Resource Graph queries (`az graph query`)
and ARM calls (`az rest`) for AMPLS / known-issues / end-to-end
verification.

---

## Recommendations for Enterprise Deployment

1. **Use `-AutoApprove` in automation** — enables unattended execution
   in CI/CD pipelines and scheduled tasks. Consent prompts are
   designed for interactive use; automation should explicitly opt in.

2. **Store reports locally** — the script defaults to writing reports
   in the script's own directory. If you specify `-OutputPath`, point
   it to a local directory with appropriate ACLs — not a network share.

3. **Review reports before sharing** — reports contain masked iKeys,
   resolved IPs, Azure resource names, and (in verbose TXT) full
   console output including endpoint hostnames. This is safe for
   internal support tickets but should be reviewed before posting
   publicly.

4. **Use `-NetworkOnly` for least-privilege runs** — when you only need
   to validate network path (DNS → TCP → TLS), skip all Azure
   authenticated operations entirely.

5. **Use `-SkipIngestionTest` when writes are unwanted** — if
   organisational policy prohibits sending test data to production
   resources, this flag skips the only write operation.

6. **Pin the script version** — download a specific release rather
   than running from `main` branch. Validate the file hash before
   deploying to production environments.

---

*See also: [architecture.md](architecture.md) for how the telemetry
pipeline works, [diagnostic-flow.md](diagnostic-flow.md) for the
phase-by-phase walkthrough, and
[interpreting-results.md](interpreting-results.md) for the
finding-by-finding reference.*
