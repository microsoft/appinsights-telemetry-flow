# Interpreting Results

> How to read the console output, understand severity levels, and act on each
> finding produced by `Test-AppInsightsTelemetryFlow`.

---

## Table of Contents

- [Mapping Findings to the 4D Symptoms](#mapping-findings-to-the-4d-symptoms)
- [Output Modes](#output-modes)
- [Progress Lines](#progress-lines)
- [Severity Levels](#severity-levels)
- [Exit Codes](#exit-codes)
- [WHAT TO DO Section](#what-to-do-section)
- [Finding Reference](#finding-reference)
  - [Network Findings](#network-findings)
  - [AMPLS / Private Link Findings](#ampls--private-link-findings)
  - [Azure Resource Findings](#azure-resource-findings)
  - [Ingestion Findings](#ingestion-findings)
- [IP Classification](#ip-classification)
- [Report Files](#report-files)
- [Automating Result Evaluation](#automating-result-evaluation)

---

## Mapping Findings to the 4D Symptoms

Most Application Insights support issues boil down to four observable symptoms
— **Drops, Delays, Duplicates, Discrepancies** (see the
[Architecture: 4D Symptoms](architecture.md#the-4d-symptoms) section for the
full framework). The table below maps every finding category in this script to
the symptom(s) it helps explain:

| Finding | Drops | Delayed | Duplicates | Discrepancies |
|---------|:-----:|:-------:|:----------:|:-------------:|
| DNS Resolution Failures | **X** | | | |
| TCP Connection Failures | **X** | | | |
| TLS Handshake Failure | **X** | | | |
| TLS Inspection Detected | **X** | **X** | | |
| AMPLS DNS Mismatches | **X** | | | |
| Ghost AMPLS | **X** | | | |
| Ingestion BLOCKED | **X** | | | |
| Query Access BLOCKED | | | | |
| Local Auth Disabled (401) | **X** | | | |
| Ingestion Sampling | **X** | | | |
| Daily Cap Reached | **X** | | | |
| Daily Cap Mismatch (LA < AI) | **X** | | | |
| Subscription Suspended | **X** | | | |
| Workspace Not Found | **X** | | | |
| Diagnostic Settings Duplication | | | **X** | |
| Workspace Transforms (DCR) | **X** | | | **X** |
| Ingestion Failed (HTTP error) | **X** | | | |
| Global/Legacy Endpoint | | **X** | | |
| E2E Verification Latency | | **X** | **X** | |

**How to use this table:** Start from your symptom (column), scan down for
**X** marks, and focus on those findings in the output. For example, if your
problem is *Duplicates*, the only finding to look for is Diagnostic Settings
Duplication. If your problem is *Drops*, most findings are relevant — work
through them in the priority order shown in the WHAT TO DO section.

> **Note:** *Delayed* symptoms are harder to diagnose from a point-in-time
> test because pipeline latency is transient. The script measures E2E latency
> for the test record it sends, but production latency may differ. If the
> script shows a healthy path with normal E2E timing but your data is still
> delayed, the cause is likely upstream (SDK buffering, batch intervals) or a
> transient pipeline backlog.

---

## Output Modes

The script supports two output modes selected by the `-Compact` switch.

| Mode | What You See |
|------|-------------|
| **Verbose** (default) | Full progress lines for every check, a DIAGNOSIS SUMMARY table listing each finding with severity, and the WHAT TO DO section with remediation steps. |
| **Compact** (`-Compact`) | One-line progress per phase (DNS, TCP, TLS, etc.), then only the WHAT TO DO section. The summary table is suppressed. |

In both modes, the WHAT TO DO section is always printed when findings exist.
If there are no findings, a single "No issues found" message appears instead,
with context-specific wording depending on which checks ran:

| Situation | Message |
|-----------|---------|
| Azure checks ran and resource was found | "No issues found. All checks passed." |
| Azure checks ran but resource was not found | "Network checks passed. Azure resource checks SKIPPED." |
| Network-only mode or no Az module | "All network checks passed. Resource checks not performed." |

---

## Progress Lines

Each diagnostic phase prints a progress line in the format:

```
  [STATUS]  Phase Name            Summary text
```

Status labels and their meaning:

| Status | Colour | Meaning |
|--------|--------|---------|
| `OK` | Green | Phase completed with no issues. |
| `FAIL` | Red | Phase detected a blocking problem. |
| `WARN` | Yellow | Phase completed but found a concern. |
| `INFO` | Yellow (lighter) | Informational observation — not a failure. |
| `SKIP` | Dark grey | Phase was intentionally skipped (prerequisite failed or feature not applicable). |

A `SKIP` status always includes an explanation, e.g.
`Skipped (DNS failed)` or
`Skipped (ingestion endpoint TCP blocked -- resolve firewall first)`.

---

## Severity Levels

Every finding in the WHAT TO DO section is tagged with one of three severity
levels, listed here from most to least urgent.

### BLOCKING

> **Telemetry is broken. Data is not reaching Azure Monitor.**

| Attribute | Value |
|-----------|-------|
| Colour | Red |
| Exit code | `3` |
| Action required | Yes — resolve before investigating anything else. |

Typical causes: DNS resolution failure, TCP port 443 blocked, TLS handshake
failure, ingestion HTTP error (400/403/429), daily cap reached, backend
workspace deleted, subscription suspended.

### WARNING

> **Telemetry may still flow, but something is at risk or degraded.**

| Attribute | Value |
|-----------|-------|
| Colour | Yellow |
| Exit code | `2` (if no BLOCKING exists) |
| Action required | Recommended — these can become BLOCKING without warning. |

Typical causes: AMPLS DNS mismatches, query access blocked (ingestion OK),
daily cap mismatch (LA cap < AI cap), ghost AMPLS (private IPs but no AMPLS
link).

### INFO

> **Awareness item. No immediate action required, but worth understanding.**

| Attribute | Value |
|-----------|-------|
| Colour | Yellow (lighter) |
| Exit code | `1` (if no BLOCKING/WARNING) |
| Action required | Optional — informational context. |

Typical causes: TLS inspection detected, local auth disabled (Entra ID
required), ingestion sampling enabled, global/legacy endpoint in use, workspace
access mode set to require-workspace-permissions, DCR transforms detected.

---

## Exit Codes

The script sets a process exit code that can be consumed by CI pipelines,
monitoring scripts, or batch wrappers.

| Code | Meaning | Condition |
|------|---------|-----------|
| `0` | Clean | No diagnosis findings at all. |
| `1` | Info | At least one INFO finding exists, but no WARNING or BLOCKING. |
| `2` | Warning | At least one WARNING finding exists, but no BLOCKING. |
| `3` | Blocking | At least one BLOCKING finding exists. |

In PowerShell, check `$LASTEXITCODE` after the script runs:

```powershell
.\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "..." -AutoApprove
if ($LASTEXITCODE -eq 3) { Write-Error "BLOCKING issue detected" }
```

In Bash (using the companion script):

```bash
./test-appinsights-telemetry-flow.sh --connection-string "..."
rc=$?
[ "$rc" -eq 3 ] && echo "BLOCKING" || echo "Exit code: $rc"
```

---

## WHAT TO DO Section

When findings exist, the WHAT TO DO section is rendered in priority order
(BLOCKING first, then WARNING, then INFO). Each finding includes up to five
fields:

```
  #1 [BLOCKING] Title
     Description of the problem in plain language.
     -> Fix: Step-by-step remediation guidance.
     -> Portal: Azure Portal navigation path (blade > tab > setting).
     -> Docs: Link to Microsoft Learn documentation.
```

- **Fix** — What to change or verify. Written as an actionable instruction.
- **Portal** — A breadcrumb-style navigation path into the Azure Portal, e.g.
  `App Insights > Network Isolation > 'Enabled from all networks'`.
- **Docs** — A direct URL to the relevant Microsoft Learn page.

Not every finding has all three remediation fields. For example, a DNS failure
has a Fix and Docs but no Portal path (DNS is not configured in the App
Insights portal).

---

## Finding Reference

Below is a comprehensive guide to every finding the script can produce,
organised by category.

### Network Findings
---

#### DNS Resolution Failures

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | One or more required hostnames (ingestion, live metrics, quickpulse, profiler, etc.) failed DNS resolution. |
| What it means | Without DNS resolution, TCP connections cannot be established and telemetry cannot flow. |
| Common causes | Corporate DNS server does not forward Azure public DNS zones; split-horizon DNS misconfiguration with Private DNS Zones; machine has no DNS server configured. |
| Fix | Verify DNS server configuration; check conditional forwarders for `monitor.azure.com` and `applicationinsights.azure.com`; for AMPLS, verify Private DNS Zone links to the correct VNet. |

#### Mixed Public / Private DNS Results

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | Some endpoints resolved to public IPs while others resolved to private IPs. |
| What it means | Likely partial AMPLS configuration — only some Azure Monitor private endpoints are configured. This may be intentional (e.g. only ingestion is private) or accidental. |
| Fix | Review AMPLS private endpoint scope. If all traffic should be private, ensure all required Private DNS Zones are linked. |

#### TCP Connection Failures (Port 443)

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | TCP connections to one or more endpoints were refused or timed out on port 443. |
| What it means | A firewall, Network Security Group (NSG), UDR, or proxy is blocking outbound HTTPS to Azure Monitor endpoints. Could also be a transient connection failure that succeeds on a retry. |
| Common causes | If problem persists check if Azure Firewall or NSG missing outbound rules; on-premises proxy requiring explicit configuration; corporate firewall blocking by IP range; UDR sending traffic to an NVA that drops it. |
| Fix | Check NSG outbound rules, Azure Firewall application/network rules, UDRs, Virtual Appliance and proxy settings. Ensure the [`AzureMonitor`](https://learn.microsoft.com/azure/virtual-network/service-tags-overview#available-service-tags) service tag or the specific FQDNs are allowed outbound on port 443. |

#### TLS Handshake Failure

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | TCP connection succeeded but the TLS handshake failed (certificate validation error, protocol mismatch, etc.). |
| What it means | Something between the client and Azure Monitor is interfering with TLS. Common culprits: TLS inspection proxy presenting an untrusted certificate, or the client only supports deprecated TLS versions. |
| Fix | If a proxy is intercepting TLS, add a bypass for `*.monitor.azure.com` and `*.applicationinsights.azure.com`. If the client's TLS library is outdated, upgrade to support TLS 1.2+. Review the trusted root CA certificates in your certificate store to determine whether any require upgrading. |

#### TLS Inspection Detected

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The certificate returned during TLS handshake was issued by a non-Microsoft CA (e.g. Zscaler, Palo Alto, Fortinet, corporate PKI). |
| What it means | A TLS-intercepting proxy or firewall is terminating and re-encrypting traffic to Azure Monitor. This can cause certificate pinning failures in some SDKs, increased latency, and intermittent telemetry drops. |
| Fix | Add a TLS inspection bypass for Azure Monitor domains. The script detects the proxy product name when possible and includes it in the description. |

#### Deprecated TLS Protocol Accepted

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The diagnostic test successfully established a TLS 1.0 or TLS 1.1 connection to the Application Insights ingestion endpoint. |
| What it means | If this test reports success, the connection likely did **not** reach the Azure ingestion service using TLS 1.0/1.1. A network device (such as a proxy, firewall, or SSL inspection appliance) may be terminating TLS and re-establishing the connection using TLS 1.2+. |
| Fix | Verify that the client is connecting directly to the Azure ingestion endpoint without TLS interception. Ensure any proxies or network inspection devices allow end-to-end TLS negotiation with Azure services. |

#### Deprecated TLS with Microsoft Certificate

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | Deprecated TLS was accepted and the certificate is a genuine Microsoft certificate (not from a proxy). |
| What it means | Same as above but confirms no TLS inspection is in path — the risk is purely protocol deprecation. |

### AMPLS / Private Link Findings
---

#### AMPLS DNS Mismatches (Pre-flight)

| Field | Value |
|-------|-------|
| Severity | **WARNING** |
| Trigger | When `-AmplsExpectedIps` is provided, the script compares actual DNS resolution against the supplied IP list. Mismatches trigger this finding. |
| What it means | DNS is resolving Azure Monitor hostnames to different IPs than expected — likely the Private DNS Zone is stale, linked to the wrong VNet, or the private endpoint was recreated. |
| Fix | Update the Private DNS Zone A records or re-link the zone to the correct VNet. |

#### AMPLS DNS Mismatches (Azure Resource Graph)

| Field | Value |
|-------|-------|
| Severity | **WARNING** |
| Trigger | Azure Resource Graph shows AMPLS private endpoint IPs that don't match what DNS resolves. |
| What it means | Same as above, but the expected IPs were discovered automatically from Azure rather than supplied by the user. |
| Fix | Re-sync Private DNS Zones, or verify the private endpoint is healthy in the Portal under AMPLS > Private Endpoint Connections. |

#### Ghost AMPLS (Private IPs without AMPLS Link)

| Field | Value |
|-------|-------|
| Severity | **WARNING** |
| Trigger | DNS resolves to private IP addresses (10.x, 172.16-31.x, 192.168.x) but Azure Resource Graph shows the App Insights resource is **not** linked to any AMPLS. |
| What it means | Traffic is routing to a private IP that Azure Monitor doesn't recognise as an authorised private endpoint. This typically causes silent ingestion failures (HTTP 403). |
| Common causes | AMPLS was deleted but Private DNS Zones were not cleaned up; the resource was moved between AMPLS scopes; a different AMPLS on the same VNet is resolving the DNS. |
| Fix | Do one of the following: <br>• Link the Application Insights resource to the **AMPLS scope currently associated with the network**. <br>• Remove **stale Private DNS zone records** so traffic resolves to the public ingestion endpoint. <br>• Configure **Open Ingestion access mode** on the AMPLS resource so clients on this network can access both public and private Application Insights resources. |

#### Ingestion BLOCKED from This Machine

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | The App Insights resource's network access settings reject ingestion from this machine's network. |
| What it means | The `publicNetworkAccessForIngestion` property is set to `Disabled` and the machine is not connecting via an approved private endpoint. |
| Fix | Navigate to App Insights > Network Isolation and set ingestion access to "Enabled from all networks", or ensure this machine routes through the correct AMPLS private endpoint. |

#### Query Access BLOCKED from This Machine

| Field | Value |
|-------|-------|
| Severity | **WARNING** |
| Trigger | The App Insights resource's network access settings reject query API calls from this machine's network but ingestion is allowed. |
| What it means | Telemetry can still be ingested, but portal queries, API queries, and the E2E verification step will not work from this machine. |
| Fix | Navigate to App Insights > Network Isolation and set query access to "Enabled from all networks", or query from an approved and trusted private network. |

### Azure Resource Findings
---

#### App Insights Resource Not Found

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | Azure Resource Graph did not return any App Insights resource matching the instrumentation key from the connection string. |
| What it means | The signed-in user may lack Reader access, the resource may be in a different tenant, or the instrumentation key may be incorrect. |
| Fix | Verify the connection string. Ensure the signed-in identity has at least Reader role on the App Insights resource. |

#### Local Authentication Disabled

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The App Insights resource has `DisableLocalAuth = true`. |
| What it means | Instrumentation key-based authentication is disabled. Only Entra ID (Azure AD) bearer tokens are accepted. The script's ingestion test (which uses iKey) will get HTTP 401 — this is expected behaviour. |
| Fix | If your application uses Entra ID tokens for telemetry ingestion, no action needed. If not seeing telemetry, verify the SDK's Entra ID configuration and that the managed identity or service principal has the **Monitoring Metrics Publisher** role. |

#### Ingestion Sampling Enabled

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The App Insights resource's server-side ingestion sampling rate is less than 100%. |
| What it means | Azure Monitor may reduce telemetry volume by applying ingestion sampling to incoming data. However, ingestion sampling is only applied when telemetry arrives unsampled. If an SDK already applied sampling, Azure Monitor respects the SDK's sampling decision and does not apply additional sampling. |
| Fix | Review whether ingestion sampling is needed. Navigate to App Insights > Usage and estimated costs > Data Sampling. Set the rate to 100% if full telemetry fidelity is required, or keep the current setting to reduce ingestion volume and cost. |

#### Log Analytics Daily Cap Reached (OverQuota)

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | The backend Log Analytics workspace has reached its daily ingestion cap. |
| What it means | **All new telemetry is being silently dropped** until the cap resets (at the configured reset time, default midnight UTC). This is a common cause of "data stopped appearing" incidents. |
| Fix | Navigate to Log Analytics workspace > Usage and estimated costs > Daily Cap. Increase or remove the cap, or wait for the reset. The script shows the reset time if available. |

#### Daily Cap Mismatch (LA < AI)

| Field | Value |
|-------|-------|
| Severity | **WARNING** |
| Trigger | The Log Analytics workspace daily cap is lower than the App Insights daily cap. |
| What it means | App Insights thinks it can ingest more data than the workspace will accept. When the workspace cap is hit first, data is silently dropped. The AI cap counter keeps going, so the AI cap page may show "under cap" while data is actually being lost. |
| Fix | Align the caps — either raise the LA workspace cap to match or exceed the AI cap, or lower the AI cap. |

#### Azure Subscription Suspended

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | The Log Analytics workspace's provisioning state indicates the subscription is suspended. |
| What it means | All ingestion is halted. The workspace and all its data are inaccessible. |
| Fix | Restore the subscription in Azure Portal > Subscriptions > [subscription name] > Reactivate. |

#### Backend Log Analytics Workspace Not Found

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | The `WorkspaceResourceId` in the App Insights resource points to a workspace that no longer exists or returns 404. |
| What it means | Telemetry has nowhere to land. The workspace was likely deleted. |
| Fix | Verify the linked Log Analytics workspace exists and that you have access to it by opening it in the Azure portal. If the workspace was recently deleted, restore it within the 14-day soft-delete window. Otherwise, create a new workspace and update the Application Insights resource to use the new workspace. |

#### Cannot Query Backend LA Workspace Permissions

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The script could not read workspace details due to insufficient permissions (HTTP 403) or another error. |
| What it means | The signed-in identity lacks Reader or equivalent access to the Log Analytics workspace. The script cannot verify daily cap, access mode, or provisioning state. |
| Fix | Grant at least Reader role on the workspace, or have someone with access run the script. |

#### Workspace Access Mode: Require Workspace Permissions

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The Log Analytics workspace `accessMode` is set to `require workspace permissions`. |
| What it means | Users need explicit LA workspace RBAC roles to query data — App Insights resource-level permissions alone are not sufficient. This is a security best practice but can cause "no data" symptoms for users who only have AI roles but no LA roles. |

#### Diagnostic Settings Exporting to Log Analytics

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The App Insights resource has Azure Diagnostic Settings that export platform metrics or activity logs to the same Log Analytics workspace. |
| What it means | Platform diagnostic data counts toward the workspace daily cap. In high-volume environments, this can consume cap allowance before application telemetry arrives. Not a problem on its own, but relevant context if you're troubleshooting daily cap issues. |

#### Diagnostic Settings Exporting Application Insights Logs

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The Application Insights resource has Diagnostic Settings configured to export logs to a Log Analytics workspace. |
| What it means | Application Insights already stores telemetry in its linked Log Analytics workspace. If Diagnostic Settings also export Application Insights logs to a Log Analytics workspace, duplicate telemetry can appear in queries. Behavior depends on the destination workspace:<br>• **Same workspace** – Queries from Application Insights or Log Analytics may return duplicate records because telemetry is written twice to the same workspace.<br>• **Different workspace** – Queries in Application Insights may show duplicate telemetry because the portal queries both sources. However, queries run directly against either individual workspace will only show that workspace’s copy of the data. |
| Fix | If duplicate telemetry appears in queries, consider one of the following:<br>• Remove the Diagnostic Settings log export for Application Insights logs if it is not required.<br>• Export logs to Event Hubs or Storage accounts instead.<br>• Adjust queries to deduplicate record* when combining data sources. [Learn more](https://learn.microsoft.com/azure/data-explorer/dealing-with-duplicates ) |

#### Workspace Transforms Detected (DCR)

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | Data Collection Rules (DCRs) with workspace transforms are active on tables receiving App Insights telemetry. |
| What it means | Incoming telemetry is being transformed (filtered, enriched, routed) before storage. Transforms can drop records, rename columns, or split data across tables. If telemetry "disappears" but ingestion is healthy, a DCR transform may be filtering it out. |
| Fix | Review DCR transforms in Azure Portal > Monitor > Data Collection Rules, or via `az monitor data-collection rule show`. |

### Ingestion Findings
---

#### Using Global / Legacy Ingestion Endpoint

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The connection string's `IngestionEndpoint` points to the deprecated global endpoint (`dc.services.visualstudio.com` or `dc.applicationinsights.azure.com`) rather than a regional endpoint. |
| What it means | Telemetry is routed through the global front-door instead of a region-local endpoint. Microsoft recommends regional endpoints for lower latency and data residency compliance. |
| Fix | Update the connection string in your application to use the regional endpoint shown in Azure Portal > App Insights > Overview > Connection String. |

#### Ingestion Returned 401 (Entra ID Auth Required)

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The test telemetry POST received HTTP 401, and the resource has local auth disabled. |
| What it means | The script uses iKey-based auth for the test; when local auth is disabled, 401 is the expected response. **This is not a problem** — it simply confirms Entra ID enforcement is working. |
| Fix | If your apps use Entra ID tokens, no action needed. If telemetry is missing, verify the SDK's [Entra ID configuration](https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication). |

#### Ingestion Block Confirmed by Test

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The pre-flight network access check already flagged ingestion as BLOCKED, and the actual POST confirmed it. |
| What it means | Duplicate confirmation — the root cause is the BLOCKING finding above this one. This INFO entry exists only to confirm the test matched the earlier prediction. |
| Fix | Resolve the BLOCKING finding above; this entry clears automatically. |

#### Telemetry Ingestion Failed

| Field | Value |
|-------|-------|
| Severity | **BLOCKING** |
| Trigger | The test telemetry POST returned a non-200 HTTP status and no other finding explains why. |
| What it means | Telemetry cannot be ingested. The HTTP status code narrows the cause: |

| HTTP Status | Likely Cause |
|-------------|-------------|
| `400` | Malformed payload or invalid instrumentation key. Verify the connection string. |
| `401` | Authentication rejected. Check local auth settings or Entra ID token configuration. |
| `403` | Network access denied. The resource's network isolation settings are blocking this source. |
| `429` / `439` | Daily cap or throttling. Application Insights daily cap, or the 32,000 items/sec throttling limit has been reached. |

#### ARM / Ingestion Auth Mismatch

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| Trigger | The Azure Resource Manager (ARM) API and the ingestion endpoint return different authentication behaviour — e.g. ARM says local auth is enabled but ingestion returns 401, or vice versa. |
| What it means | There may be a propagation delay after changing the local auth setting, or an intermediate proxy is altering authentication headers. |
| Fix | Wait 5-10 minutes and re-run. If the mismatch persists, check for proxies or WAFs that modify `Authorization` headers. |

---

## IP Classification
--- 

During DNS resolution, the script classifies resolved IP addresses as
**public** or **private** and reports the mix.

### When to Expect Public IPs

- Standard (non-AMPLS) App Insights deployments.
- The machine resolves Azure Monitor FQDNs through public DNS.
- IP ranges belong to Microsoft's published `AzureMonitor` service tag.

### When to Expect Private IPs

- The App Insights resource is linked to one or more Azure Monitor Private Link Scope(s)
  (AMPLS).
- Private DNS Zones for `monitor.azure.com` (and related zones) are linked to
  the VNet.
- Resolved IPs are typically in `10.x.x.x`, `172.16-31.x.x`, or
  `192.168.x.x` ranges.

### Mixed Public / Private

When some endpoints resolve to public IPs and others to private, the script
reports `Mixed public/private`. This usually means:

1. **Partial AMPLS** — Only some Private DNS Zones are configured. For
   example, the ingestion zone is private but the Live Metrics zone is
   public.
2. **Split-horizon DNS** — Some FQDNs hit an internal DNS server (returning
   private IPs) while others fall through to public DNS.

Mixed results are not necessarily wrong — some architectures intentionally
route only ingestion through AMPLS — but they warrant review.

---

## Report Files

When `-OutputPath` is specified (or defaults to the script directory), two
report files are generated per run:

### JSON Report (`.json`)

Machine-readable structured data containing:

- **Environment** — OS, hostname, Azure host type, detected proxy, PowerShell version.
- **ConnectionString** — Parsed components (ingestion endpoint, iKey prefix, cloud suffix).
- **DNS/TCP/TLS results** — Per-endpoint status with IP addresses, ports, latency, certificate details.
- **Azure resource details** — Resource name, workspace name/id, AMPLS links, network access settings.
- **Ingestion test** — HTTP status, response body, timing.
- **E2E verification** — Whether the test record was confirmed in the workspace.
- **Diagnosis** — Array of all findings with severity, title, description, fix, portal path, docs URL.
- **Summary** — Counts (total checks, passed, failed, warnings), flags (AMPLS detected, Azure checks completed).

Use the JSON report for:

- Automated parsing in CI/CD pipelines.
- Aggregating results across multiple machines or environments.
- Attaching to support tickets for Microsoft Support.
- Programmatic alerting on specific findings.

### Text Report (`.txt`)

Human-readable console output containing:

- Header with timestamp, hostname, masked iKey, endpoint.
- Diagnosis summary (severity + finding summary per item).
- Full console output as captured during the run.

Use the text report for:

- Quick sharing via email or chat.
- Archiving alongside incident timelines.
- Reading on systems without JSON tooling.

### File Naming Convention

```
AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{UTC-TIMESTAMP}.json
AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{UTC-TIMESTAMP}.txt
```

When the App Insights resource name is discovered via Azure checks it is
included in the filename; otherwise the `{RESOURCE}` segment is omitted.

Example: `AppInsights-Diag_WEBSERVER01_my-appinsights_2025-03-15T142533Z.json`

---

## Automating Result Evaluation

### Parse the JSON Report in PowerShell

```powershell
$report = Get-Content .\AppInsights-Diag_*.json | ConvertFrom-Json

# List all BLOCKING findings
$report.Diagnosis | Where-Object Severity -eq 'BLOCKING' | ForEach-Object {
    Write-Output "$($_.Title): $($_.Fix)"
}

# Check if AMPLS was detected
if ($report.Summary.AmplsDetected) {
    Write-Output "AMPLS is in use — validate private DNS zones."
}
```

### Use Exit Codes in a Pipeline

```yaml
# Azure DevOps example
- script: |
    pwsh -File Test-AppInsightsTelemetryFlow.ps1 \
      -ConnectionString "$(AI_CONNECTION_STRING)" \
      -AutoApprove -Compact -OutputPath $(Build.ArtifactStagingDirectory)
  displayName: 'App Insights connectivity check'
  continueOnError: true

- script: |
    if [ $? -eq 3 ]; then
      echo "##vso[task.logissue type=error]BLOCKING connectivity issue detected"
    fi
  displayName: 'Evaluate result'
```

### Aggregate Multiple Machines

```powershell
$results = Get-ChildItem .\reports\*.json | ForEach-Object {
    $r = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
        Host      = $r.Environment.ComputerName
        Blocking  = ($r.Diagnosis | Where-Object Severity -eq 'BLOCKING').Count
        Warnings  = ($r.Diagnosis | Where-Object Severity -eq 'WARNING').Count
        Info      = ($r.Diagnosis | Where-Object Severity -eq 'INFO').Count
        AMPLS     = $r.Summary.AmplsDetected
    }
}
$results | Format-Table -AutoSize
```

---

## Further Reading

- [Architecture Deep-Dive](architecture.md) — How telemetry flows layer by
  layer and where things break.
- [AMPLS / Private Link Deep-Dive](ampls-private-link-deep-dive.md) — DNS
  zones, network isolation modes, and troubleshooting AMPLS.
- [Automation & CI](automation-ci.md) — Running the script headlessly in
  pipelines and processing results.
- [FAQ](faq.md) — Common questions and quick answers.
