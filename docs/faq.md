# Frequently Asked Questions

Common questions about `Test-AppInsightsTelemetryFlow` — what it does, what the results
mean, and how to handle edge cases.

---

## Quick Index

#### General
1. [What does this script actually do?](#what-does-this-script-actually-do)
2. [Does the script send telemetry to my Application Insights resource?](#does-the-script-send-telemetry-to-my-application-insights-resource)
3. [Will the test record affect my dashboards or alerts?](#will-the-test-record-affect-my-dashboards-or-alerts)
4. [Does the script work on PowerShell 5.1?](#does-the-script-work-on-powershell-51)
5. [What is `-NetworkOnly` and when should I use it?](#what-is--networkonly-and-when-should-i-use-it)
6. [What is `-AutoApprove`?](#what-is--autoapprove)
7. [What exit codes does the script return?](#what-exit-codes-does-the-script-return)

#### DNS & AMPLS
8. [Why do I see a public IP address even though I have AMPLS configured?](#why-do-i-see-a-public-ip-address-even-though-i-have-ampls-configured)
9. [What does "Mixed public/private DNS" mean?](#what-does-mixed-publicprivate-dns-mean)
10. [I have AMPLS but DNS shows the correct private IPs. Why is ingestion still failing?](#i-have-ampls-but-dns-shows-the-correct-private-ips-why-is-ingestion-still-failing)
11. [My DNS returns unexpected private IPs. How do I find which AMPLS is responsible?](#my-dns-returns-unexpected-private-ips-how-do-i-find-which-ampls-is-responsible)
12. [Why does "privatelink" appear in the DNS chain even though I don't use AMPLS?](#why-does-privatelink-appear-in-the-dns-chain-even-though-i-dont-use-ampls)

#### TLS & Certificates
13. [Why does TLS inspection show up on my private network?](#why-does-tls-inspection-show-up-on-my-private-network)
14. [Why does the script test TLS 1.0 and 1.1 if they are deprecated?](#why-does-the-script-test-tls-10-and-11-if-they-are-deprecated)
15. [Why does TLS 1.3 show "Not negotiated" on PowerShell 5.1?](#why-does-tls-13-show-not-negotiated-on-powershell-51)

#### Ingestion & E2E Verification
16. [Ingestion returned HTTP 200 but no data appears in queries. Why?](#ingestion-returned-http-200-but-no-data-appears-in-queries-why)
17. [Why does E2E verification sometimes fail (timeout)?](#why-does-e2e-verification-sometimes-fail-timeout)
18. [What does HTTP 206 from the ingestion endpoint mean?](#what-does-http-206-from-the-ingestion-endpoint-mean)
19. [What does HTTP 429 or 439 from the ingestion endpoint mean?](#what-does-http-429-or-439-from-the-ingestion-endpoint-mean)

#### Azure Checks
20. [Why does Azure login get skipped in App Service / Functions / Containers?](#why-does-azure-login-get-skipped-in-app-service--functions--containers)
21. [What permissions does the script need for Azure checks?](#what-permissions-does-the-script-need-for-azure-checks)
22. [Can I run the script without any Azure login at all?](#can-i-run-the-script-without-any-azure-login-at-all)
23. [What is the DIAGNOSIS SUMMARY?](#what-is-the-diagnosis-summary)

#### Proxy & Firewall
24. [What domains and ports does the script need outbound access to?](#what-domains-and-ports-does-the-script-need-outbound-access-to)
25. [The script says TCP connection failed on port 443. What should I check?](#the-script-says-tcp-connection-failed-on-port-443-what-should-i-check)

#### Output & Reports
26. [Where are the output files saved?](#where-are-the-output-files-saved)
27. [How do I share results with Microsoft Support?](#how-do-i-share-results-with-microsoft-support)
28. [Can I suppress the output files?](#can-i-suppress-the-output-files)

#### Troubleshooting the Script Itself
29. [The script hangs during TLS handshake checks](#the-script-hangs-during-tls-handshake-checks)
30. [The script crashes with a red error on PowerShell 5.1](#the-script-crashes-with-a-red-error-on-powershell-51)
31. ["Search-AzGraph" fails or is not recognized](#search-azgraph-fails-or-is-not-recognized)

---

## General

### What does this script actually do?

It walks the entire telemetry pipeline layer by layer — DNS resolution, TCP connectivity
(port 443), TLS handshake, ingestion API POST, and (optionally) Azure resource
configuration checks — to find exactly where and why data is being lost. If you enable
Azure checks, it also queries ARM for known-issue configurations like daily caps,
workspace transforms, and AMPLS settings. The full diagnostic flow is documented in
[Diagnostic Flow](diagnostic-flow.md).

### Does the script send telemetry to my Application Insights resource?

Yes — **one** `AvailabilityResult` record, only if you consent. The record contains:

- **Record type:** `AvailabilityResult`
- **Name:** `Telemetry-Flow-Diag Ingestion Validation`
- **Custom properties:** a `diagnosticRunId` GUID and the script version
- **Cloud role instance:** `Telemetry-Flow-Diag`
- **Message:** `[{ComputerName}] Telemetry flow diagnostic test record - safe to ignore`

This record is used for end-to-end verification: after the ingestion API accepts it, the
script queries the data plane API to confirm it actually landed in Log Analytics. You can
skip this with `-SkipIngestionTest`, and in non-interactive environments the consent
prompt is shown before the test runs.

### Will the test record affect my dashboards or alerts?

It lands in the `availabilityResults` table, so technically it will appear in queries
that scan that table without filters. In practice, it is one record with a distinctive
name (`Telemetry-Flow-Diag Ingestion Validation`) that is easy to filter out:

```kusto
availabilityResults
| where name != "Telemetry-Flow-Diag Ingestion Validation"
```

### Does the script work on PowerShell 5.1?

Yes. The script supports Windows PowerShell 5.1 (Desktop edition) and PowerShell 7+
(Core edition) on Windows, Linux, and macOS. A few differences on 5.1:

- **TLS 1.3** cannot be tested — the .NET Framework version underlying PS 5.1 does not
  expose TLS 1.3 as an `SslProtocols` enum value. The script notes this and recommends
  running in `pwsh` (PowerShell 7+) if you need TLS 1.3 validation.
- **JSON parsing** of certain APIs (like the PricingPlans endpoint) can fail due to
  duplicate keys in the response. The script uses regex extraction as a workaround.
- **Console colors** work natively on PS 5.1. In Kudu/App Service, the script
  automatically falls back to `[System.Console]::WriteLine()` to avoid
  `SetConsoleTextAttribute` crashes.

### What is `-NetworkOnly` and when should I use it?

`-NetworkOnly` skips all Azure resource checks and consent prompts. The script runs only
DNS, TCP, and TLS diagnostics — no Azure login, no ARM queries, no ingestion test.

Use it when:

- You cannot (or do not want to) authenticate to Azure.
- You are troubleshooting from a locked-down jump box or network appliance.
- You only need to verify network-layer connectivity (e.g., after a firewall change).
- You want to run the script with zero side effects.

### What is `-AutoApprove`?

`-AutoApprove` automatically answers "Yes" to all consent prompts (Azure login and
ingestion test). Use it in CI/CD pipelines, scheduled tasks, or fleet scans where no
operator is available. See [Automation & CI](automation-ci.md) for pipeline integration
patterns.

### What exit codes does the script return?

| Exit Code | Meaning |
|-----------|---------|
| 0 | No issues found (all checks passed, no diagnosis findings) |
| 1 | INFO findings only (informational items, no action required) |
| 2 | WARNING detected (telemetry at risk but may still work) |
| 3 | BLOCKING issue detected (telemetry is broken) |

See [Automation & CI](automation-ci.md#exit-codes) for how to use these in pipelines.

---

## DNS & AMPLS

### Why do I see a public IP address even though I have AMPLS configured?

This is the most common AMPLS misconfiguration. There are several possible causes:

1. **The private DNS zone is not linked to your VNet.** AMPLS relies on Azure Private DNS
   zones (e.g., `privatelink.monitor.azure.com`) to override public DNS. If the zone
   exists but is not linked to the VNet where you are running the script, DNS queries
   still resolve to public IPs.

2. **The endpoint is not covered by AMPLS.** AMPLS scopes specific resources. If your
   Application Insights resource or its backing Log Analytics workspace is not added to
   the AMPLS scope, DNS for that resource's endpoints resolves publicly. Some endpoints
   (like the CDN for the JavaScript SDK) are never covered by AMPLS.

3. **Custom DNS server is not forwarding to Azure DNS.** If your VNet uses a custom DNS
   server (e.g., Active Directory DNS, Infoblox), it must have a conditional forwarder
   pointing `privatelink.monitor.azure.com` to Azure DNS (168.63.129.16). Without this,
   the private DNS zone records are never consulted.

4. **You are running the script from outside the VNet.** AMPLS private DNS only works
   from machines that use the linked VNet's DNS. Running from your laptop on a VPN that
   does not route DNS through the VNet will resolve public IPs.

The script flags this as a "Mixed public/private DNS" finding when some endpoints resolve
to private IPs and others to public. See [AMPLS / Private Link Deep Dive](ampls-private-link-deep-dive.md)
for the full troubleshooting framework.

### What does "Mixed public/private DNS" mean?

It means some Azure Monitor endpoints resolved to private IP addresses (10.x, 172.16.x,
192.168.x ranges) while others resolved to public IPs. This indicates an **incomplete
AMPLS setup** — typically a missing private DNS zone link or a missing resource in the
AMPLS scope.

In this state, some traffic goes over the private link and some over the public internet.
Depending on your AMPLS access mode settings, the public traffic may be accepted
(Open mode) or rejected (PrivateOnly mode).

### I have AMPLS but DNS shows the correct private IPs. Why is ingestion still failing?

Check the **AMPLS access mode** on your Application Insights resource:

- **Ingestion access: PrivateOnly** — the ingestion endpoint only accepts traffic from
  the AMPLS private endpoint. If you are running the script from outside the VNet (or
  from a VNet that is not connected to the AMPLS), the ingestion request will be rejected
  even though DNS resolves correctly.
- **Query access: PrivateOnly** — same restriction for data plane queries. The E2E
  verification step will fail.

The script checks these access mode settings when `-CheckAzure` is active and reports
them in the AMPLS Configuration section.

### My DNS returns unexpected private IPs. How do I find which AMPLS is responsible?

The script can identify the AMPLS resource that owns a given private IP through a reverse
lookup: IP → Network Interface → Private Endpoint → AMPLS. This happens in two ways:

1. **Automatically**: When the script detects a "ghost AMPLS" scenario (private IPs but
   your resource is not linked to any AMPLS) or an ingestion endpoint IP mismatch, it
   automatically performs the reverse lookup and displays the AMPLS name, resource group,
   subscription, and access modes.

2. **Manually**: Use the `-LookupAmplsIp` switch (PowerShell) or `--lookup-ampls-ip`
   (Bash) with a private IP address that was resolved during the current run:

   ```powershell
   .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "..." -LookupAmplsIp "10.0.1.5"
   ```

   The IP must be a private RFC1918 address that appeared in DNS resolution or AMPLS PE
   validation during the same execution. This prevents probing arbitrary private IPs.

The lookup requires Azure login and Reader access across the relevant subscriptions. If
the private endpoint is in a subscription your account cannot access, the script reports
that the endpoint could not be identified.

### Why does "privatelink" appear in the DNS chain even though I don't use AMPLS?

This is expected and by design. Azure Monitor's public DNS records include a
`privatelink.monitor.azure.com` (or `privatelink.applicationinsights.azure.com`) CNAME
hop for **all** resources, regardless of whether AMPLS or Private Link is configured.

This CNAME acts as a "hook" in the DNS resolution chain:

- **Without AMPLS / Private Link:** The `privatelink.*` name has no private DNS zone
  override, so it resolves onward through the public CNAME chain (Traffic Manager, etc.)
  to a public IP address. Everything works normally.
- **With AMPLS / Private Link:** A private DNS zone for `privatelink.monitor.azure.com`
  is linked to your VNet. When your client resolves the `privatelink.*` name, the private
  DNS zone intercepts the query and returns the private endpoint IP instead of continuing
  down the public chain.

The script determines whether you are actually using private endpoints by checking the
**resolved IP address** (private RFC1918 range vs. public), not the CNAME chain. So
seeing `privatelink` in the CNAME output does not mean your traffic is going over a
private link — it simply means Azure Monitor's DNS infrastructure is ready to support
private endpoints if you configure them.

---

## TLS & Certificates

### Why does TLS inspection show up on my private network?

The script detects TLS inspection by checking the **certificate issuer** on the TLS
handshake. Legitimate Azure Monitor certificates are issued by Microsoft or DigiCert. If
the issuer is something else (Zscaler, Palo Alto, Fortinet, Netskope, etc.), a
TLS-inspecting proxy is re-signing the certificate.

This is common in corporate environments where a security appliance performs SSL/TLS
inspection on all outbound HTTPS traffic. The script identifies the specific proxy
product when possible and recommends configuring a TLS inspection bypass for Azure
Monitor domains.

**Why it matters:**

- TLS inspection can cause SDK certificate validation failures if the proxy's CA is not
  trusted by the application runtime.
- It adds latency to every telemetry request (decrypt → inspect → re-encrypt).
- It can interfere with connection pooling and HTTP/2.

**What to do:** Configure your proxy to bypass TLS inspection for `*.applicationinsights.azure.com`,
`*.monitor.azure.com`, and (for Azure Commercial) `*.services.visualstudio.com`.

### Why does the script test TLS 1.0 and 1.1 if they are deprecated?

The script tests deprecated TLS versions with a short timeout (3 seconds) specifically
to detect man-in-the-middle (MITM) proxies. Azure Monitor rejects TLS 1.0 and 1.1 —
so if a deprecated version succeeds, something in the network path (a proxy or firewall)
is terminating the TLS connection before it reaches Azure.

If a deprecated version succeeds and the certificate issuer is a known proxy product,
the script flags it as TLS inspection. If the certificate is Microsoft-issued, it may
indicate an Azure front-end edge case (flagged as `DeprecatedAzureEdge`) rather than
a MITM.

### Why does TLS 1.3 show "Not negotiated" on PowerShell 5.1?

PowerShell 5.1 runs on .NET Framework, which does not expose TLS 1.3
(`System.Security.Authentication.SslProtocols.Tls13` does not exist). The script
catches this gracefully and skips the TLS 1.3 test.

To test TLS 1.3 negotiation, run the script in PowerShell 7+ (`pwsh`), which runs on
.NET 6+ where TLS 1.3 is available. TLS 1.3 is not required for Azure Monitor — TLS 1.2
is the minimum — so this is informational only.

---

## Ingestion & E2E Verification

### Ingestion returned HTTP 200 but no data appears in queries. Why?

This is the "silent HTTP 200" problem — the most dangerous class of failures. The
ingestion endpoint returns 200 (accepted) but data is dropped somewhere downstream.
Common causes:

| Cause | How the Script Detects It |
|-------|--------------------------|
| Backing LA workspace deleted | ARM GET returns 404 for workspace |
| LA daily cap reached (OverQuota) | `dataIngestionStatus` = "OverQuota" |
| Cross-subscription suspended | `dataIngestionStatus` = "SubscriptionSuspended" |
| LA daily cap < AI daily cap | PricingPlans API comparison |
| Workspace transform with `where` clause | Azure Resource Graph query for DCRs |

If the script finds any of these, they appear in the DIAGNOSIS SUMMARY. If the script
does *not* find a known issue and data still does not appear, the cause is likely an
ingestion pipeline delay (see the next question) or a configuration not yet covered by
the script.

See [Known Issues Reference](known-issues-reference.md) for the full list and fix
instructions.

### Why does E2E verification sometimes fail (timeout)?

The E2E verification step polls the data plane API every **10 seconds for up to 60
seconds** looking for the test record. If the record does not appear within that window,
the result is `TIMEOUT`.

This does **not** necessarily mean data is lost. Common reasons for a timeout:

1. **Normal ingestion latency.** Application Insights typically ingests data in seconds,
   but pipeline delays of 2-5 minutes or more can occur randomly. The App Insights SLA covers
   data plane API **availability** (that it responds), not **ingestion speed**. A slow
   pipeline is within SLA.

2. **Data plane query permissions.** The E2E check uses the data plane API
   (`api.applicationinsights.io`). If the workspace access control mode is set to
   "Require workspace permissions" and you do not have workspace-level RBAC, the query
   returns zero rows — not an error.

**What to do:** If the script times out but the ingestion POST returned HTTP 200, wait
5-10 minutes and then manually check the `availabilityResults` table:

```kusto
availabilityResults
| where customDimensions.diagnosticRunId == "<the-guid-from-the-script-output>"
| project timestamp, _TimeReceived, ingestion_time()
```

If the record appears, the pipeline is working — it was just temporarily slow.

### What does HTTP 206 from the ingestion endpoint mean?

HTTP 206 (Partial Content) means the ingestion endpoint accepted some items but rejected
others in the same batch. Since the script sends exactly one record, a 206 response
typically indicates **server-side ingestion sampling** accepted the batch but flagged
that sampling is active. The script treats 206 as a pass but notes the sampling
indicator.

### What does HTTP 429 or 439 from the ingestion endpoint mean?

- **HTTP 429 (Too Many Requests):** Rate throttling. The ingestion endpoint is
  temporarily rejecting requests because the resource or workspace is receiving too many
  requests in a short window. This is transient — retry after the `Retry-After` header
  value.

- **HTTP 439:** A daily-cap-specific variant. The workspace or AI resource daily cap
  has been reached. This is not transient — it will not resolve until the cap resets or
  you raise the cap. See [Known Issues: Daily Cap Reached](known-issues-reference.md#5-log-analytics-daily-cap-reached).

---

## Azure Checks

### Why does Azure login get skipped in App Service / Functions / Containers?

When the script detects it is running inside a non-interactive Azure PaaS environment
(App Service Kudu console, Function App, Container App, or AKS pod), it **automatically
skips the Azure login consent prompt** because `Connect-AzAccount` interactive login is
not possible in these environments — there is no browser, no device code flow, and no
interactive terminal.

The script detects these environments via well-known environment variables:

| Environment | Detection Variable |
|------------|-------------------|
| Azure Function App | `FUNCTIONS_WORKER_RUNTIME` |
| Azure App Service | `WEBSITE_INSTANCE_ID` (without Functions) |
| Azure Container App | `CONTAINER_APP_NAME` |
| AKS / Kubernetes | `KUBERNETES_SERVICE_HOST` |
| Azure Cloud Shell | `ACC_CLOUD` |

Cloud Shell is treated as interactive (it has a browser session behind it), so Azure
login is prompted normally there.

**To run Azure checks in non-interactive environments:**

1. Use a managed identity or service principal with `Connect-AzAccount -Identity` or
   `-ServicePrincipal` before running the script.
2. Pass `-AutoApprove` to skip all consent prompts.
3. Or use `-NetworkOnly` if you only need network diagnostics.

### What permissions does the script need for Azure checks?

The script uses **read-only** ARM and data plane calls:

| Operation | Minimum Role |
|-----------|-------------|
| Read AI resource properties | **Reader** on the Application Insights resource |
| Read workspace properties | **Reader** on the Log Analytics workspace |
| Query diagnostic settings | **Reader** on the AI resource |
| Query DCRs via Resource Graph | **Reader** at the scope where DCRs exist |
| Query the data plane (E2E check) | **Reader** on the AI resource (or workspace with correct ACL) |
| AMPLS / Private Endpoint queries | **Reader** on the AMPLS and PE resources |

The script never writes to, modifies, or deletes Azure resources. The only write
operation is the single `AvailabilityResult` POST to the ingestion endpoint (with your
consent).

See [Security Model](security-model.md) for the complete permission model and consent
gates.

### Can I run the script without any Azure login at all?

Yes. Use `-NetworkOnly` to skip all Azure operations. You get DNS, TCP, and TLS
diagnostics — which is often enough to diagnose network-layer issues (firewall blocks,
DNS misconfig, proxy interference). You lose:

- AMPLS configuration analysis
- Known issue detection (daily cap, workspace deleted, transforms, etc.)
- Ingestion test and E2E verification
- The DIAGNOSIS SUMMARY section

### What is the DIAGNOSIS SUMMARY?

The final section of the script output that lists all findings, ordered by severity:

1. **BLOCKING** — ingestion is completely stopped (e.g., workspace deleted, daily cap hit).
2. **WARNING** — data loss is likely (e.g., daily cap mismatch).
3. **INFO** — noteworthy configuration (e.g., TLS inspection detected, sampling active).

Each finding includes a title, description, fix instructions, and relevant Azure Portal
path. In JSON output mode, findings are in the `diagnosisItems` array.

See [Interpreting Results](interpreting-results.md) for a finding-by-finding reference.

---

## Proxy & Firewall

### What domains and ports does the script need outbound access to?

The script connects to the following on **port 443 (HTTPS)**:

| Domain Pattern | Purpose |
|---------------|---------|
| `*.applicationinsights.azure.com` | Ingestion endpoint |
| `*.monitor.azure.com` | Azure Monitor shared endpoints |
| `*.services.visualstudio.com` | Legacy ingestion + Live Metrics (Azure Commercial) |
| `api.applicationinsights.io` | Data plane query API (E2E verification) |
| `management.azure.com` | ARM API (Azure resource checks) |
| `login.microsoftonline.com` | Entra ID authentication (Azure login) |
| `js.monitor.azure.com` | JavaScript SDK CDN (DNS-only, no data sent) |

If you are behind a firewall or proxy, ensure these domains are allowed. The script lists
all endpoints it will check in verbose mode before DNS resolution begins.

### The script says TCP connection failed on port 443. What should I check?

TCP failure means the SYN packet never received a SYN-ACK — the connection was blocked
or timed out. Check:

1. **Firewall rules** — outbound port 443 to the target IP must be allowed.
2. **NSG rules** — if running in an Azure VNet, check the Network Security Group on the
   subnet.
3. **Proxy configuration** — some proxies require explicit configuration (PAC file,
   `HTTPS_PROXY` environment variable) rather than allowing direct connections.
4. **DNS returning wrong IP** — if DNS resolved to an incorrect IP (e.g., a sinkhole or
   block page), TCP will connect to the wrong host. Check the DNS resolution results
   first.

The script tests TCP independently of TLS — a TCP failure means TLS, ingestion, and
everything downstream is also blocked for that endpoint.

---

## Output & Reports

### Where are the output files saved?

The script generates two files in the current working directory:

| File | Format | Contents |
|------|--------|----------|
| `AppInsights-Diag_{hostname}_{resource}_{timestamp}.txt` | Plain text | Full console output (colors stripped) |
| `AppInsights-Diag_{hostname}_{resource}_{timestamp}.json` | JSON | Machine-parseable results — all checks, findings, metadata |

When the App Insights resource name is discovered via Azure checks it is included
in the filename; otherwise the `{resource}` segment is omitted.

Both files are created at the end of every run (regardless of pass/fail). The JSON file
is designed for automation — see [Automation & CI](automation-ci.md) for parsing
patterns.

### How do I share results with Microsoft Support?

Attach **both** the `.txt` and `.json` files to your support case. The text file provides
human-readable context; the JSON file lets support engineers programmatically analyze
your results. Together they give a complete picture without needing a screen-share or
live repro.

### Can I suppress the output files?

Not currently. The files are always generated. They are small (typically 5-50 KB) and
contain only diagnostic metadata — no secrets, tokens, or PII.

---

## Troubleshooting the Script Itself

### The script hangs during TLS handshake checks

TLS checks have built-in timeouts (10 seconds for TLS 1.2/1.3, 3 seconds for deprecated
versions). If the script appears to hang, it is likely waiting for one of these timeouts
to expire — this happens when a firewall silently drops packets rather than actively
refusing the connection (no TCP RST, just silence).

Wait for the timeouts to complete. If multiple endpoints are blocked, the cumulative wait
can be 30-60 seconds. The script processes endpoints sequentially (not in parallel) so
each timeout is additive.

### The script crashes with a red error on PowerShell 5.1

Common causes:

- **Execution policy:** Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
  before running the script, or invoke it with `powershell -ExecutionPolicy Bypass -File .\Test-AppInsightsTelemetryFlow.ps1 ...`.
- **TLS 1.2 not enabled in .NET:** On very old systems, TLS 1.2 may not be the default.
  The script forces it via `[Net.ServicePointManager]::SecurityProtocol`, but if the
  .NET Framework itself is too old (< 4.5), this may fail. Update .NET Framework.
- **Az PowerShell module not installed:** Azure checks require `Az.Accounts` and
  `Az.ResourceGraph`. The script checks for these early and tells you what to install.

### "Search-AzGraph" fails or is not recognized

The `Az.ResourceGraph` module is required for workspace transform (DCR) detection. This
is a separate module from `Az.Accounts`:

```powershell
Install-Module -Name Az.ResourceGraph -Scope CurrentUser
```

If you cannot install it, the script gracefully skips the DCR check and reports "Could
not query" instead of crashing.

---

*See also: [Architecture](architecture.md) for how the telemetry pipeline works,
[Diagnostic Flow](diagnostic-flow.md) for the step-by-step execution sequence, and
[Known Issues Reference](known-issues-reference.md) for deep dives on each known-issue
detection.*
