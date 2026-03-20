# Known Issues Reference

This reference documents every "known issue" that `Test-AppInsightsTelemetryFlow` checks
for in its Azure resource analysis phase (Phase 7). Each issue follows the same structure:
**Symptom**, **Why It Happens**, **How the Script Detects It**, and **How to Fix It**.

These checks require `-CheckAzure` (or the compact-mode default) plus a successfully
resolved Application Insights resource. If the script cannot locate your AI resource in
Azure Resource Manager, the entire known-issues phase is skipped.

> **Common thread.** Many of the issues below share a dangerous characteristic: the
> Application Insights ingestion API returns **HTTP 200** to your SDKs, so your
> application sees no errors — but data is silently dropped or altered before it reaches
> the Log Analytics workspace. The script exists to surface these silent failures.

---

## Table of Contents

| # | Issue | Severity | Silent? |
|---|-------|----------|---------|
| 1 | [Local Authentication Disabled](#1-local-authentication-disabled) | INFO | No (HTTP 401) |
| 2 | [Ingestion Sampling](#2-ingestion-sampling) | INFO | No (HTTP 206) |
| 3 | [Backend Log Analytics Workspace Deleted](#3-backend-log-analytics-workspace-deleted) | BLOCKING | Yes |
| 4 | [Workspace Access Control Mode](#4-workspace-access-control-mode) | INFO | Yes |
| 5 | [Log Analytics Daily Cap Reached](#5-log-analytics-daily-cap-reached) | BLOCKING | Yes |
| 6 | [Azure Subscription Suspended](#6-azure-subscription-suspended) | BLOCKING | Cross-sub only |
| 7 | [Daily Cap Mismatch (AI vs Log Analytics)](#7-daily-cap-mismatch-ai-vs-log-analytics) | WARNING / INFO | Yes |
| 8 | [Diagnostic Settings Duplicate Telemetry](#8-diagnostic-settings-duplicate-telemetry) | INFO | No (extra data) |
| 9 | [Workspace Transforms (DCRs)](#9-workspace-transforms-dcrs) | INFO | Yes |

---

## 1. Local Authentication Disabled

### Symptom

SDKs or agents that authenticate with an instrumentation key (iKey) receive **HTTP 401
Unauthorized** from the ingestion endpoint. No telemetry arrives. SDKs that use Entra ID
(Azure AD) token-based authentication continue to work normally.

### Why It Happens

When `DisableLocalAuth` is set to `true` on the Application Insights resource, the
ingestion endpoint rejects any request that authenticates with an instrumentation key or
API key. This is a security hardening measure that forces all callers to present an
Entra ID bearer token instead.

This setting is typically enabled through Azure Policy in security‑focused environments. It applies only to ingestion endpoints that use iKey-based data submission. The data‑plane API used to read data from your resource will move to [Entra ID–only authentication](https://azure.microsoft.com/updates?id=transition-to-azure-ad-to-query-data-from-azure-monitor-application-insights-by-31-march-2026) on March 31, 2026.

### How the Script Detects It

The script reads the ARM resource property:

```
$aiResource.properties.DisableLocalAuth
```

If the value is `$true`, an **INFO** finding is raised. The script does not treat this as
blocking because the configuration may be intentional — it simply flags it so you can
verify your SDKs are configured for Entra ID authentication.

### How to Fix It

**If you intend to keep local auth disabled** (recommended for production security):

1. Configure your SDKs to use Entra ID token-based authentication instead of iKey.
2. Assign the **Monitoring Metrics Publisher** role to the identity your application
   runs as (managed identity, service principal, or user).
3. Use SDK [Self-Diagnostics](https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics), [SDK Stats](https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats) or Live Metrics to verify telemetry flows after the switch.

**If you need to re-enable local auth** (development / testing scenarios):

1. Navigate to: **Application Insights → Properties → Local Authentication**.
2. Set to **Enabled**.
3. Or via ARM: set `properties.DisableLocalAuth` to `false`.

**Docs:** [Entra ID authentication for Application Insights](https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication)

---

## 2. Ingestion Sampling

### Symptom

You send telemetry from your application and the SDK reports partial success, and Log Analytics
contains fewer records than expected. Record counts in the telemetry do not compensate for
the dropped records. You may see **HTTP 206 Partial Content** responses from the
ingestion endpoint.

### Why It Happens

When **server-side ingestion sampling** is configured (sampling percentage < 100%), the
Application Insights backend randomly drops a percentage of incoming telemetry *after*
the SDK has already sent it. This is distinct from SDK-side adaptive sampling, which
makes the sampling decision before sending.

With server-side sampling:

- The SDK sends all records — your application pays the full serialization and network cost.
- The ingestion endpoint accepts the data and then applies the sampling
  filter to any telemetry that is not already sampled (itemCount > 1) by the SDKs.

This makes server-side sampling a poor choice compared to SDK-side adaptive sampling,
which reduces network traffic *and* correctly sets `itemCount` for query-time
compensation.

### How the Script Detects It

The script reads the ARM resource property:

```
$aiResource.properties.SamplingPercentage
```

If the value is present and less than 100, an **INFO** finding is raised. The finding
includes the configured percentage and the calculated drop rate (e.g., 50% sampling =
approximately 50% of records dropped).

### How to Fix It

1. **Remove server-side sampling:**
   Navigate to **Application Insights → Configure → Usage and estimated costs →
   Data sampling** and set it to **OFF** (or 100%).

2. **Replace with SDK-side adaptive sampling** for cost control without the drawbacks:
   - .NET: `ApplicationInsightsServiceOptions.EnableAdaptiveSampling = true` (default).
   - Java: Configure rate-limited sampling in `applicationinsights.json`.
   - Node.js / Python: Configure sampling in the SDK configuration.

3. After removing server-side sampling, monitor your ingestion volume for a few hours to
   confirm the expected increase in record counts.

**Docs:** [Sampling in Application Insights](https://learn.microsoft.com/azure/azure-monitor/app/sampling-classic-api) and [Sampling with OpenTelemetry](https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-sampling)

---

## 3. Backend Log Analytics Workspace Deleted

### Symptom

Your application sends telemetry and the SDK reports success (HTTP 200). But no data
appears in Application Insights queries, Log Analytics queries, or Workbooks. The
Application Insights resource still exists in the Azure Portal and appears functional.
Live Metrics may still show real-time data because it avoids the LA workspace.

### Why It Happens

Every Application Insights resource stores its data in a backing Log Analytics workspace. 
If that workspace is deleted — whether intentionally, via Infrastructure‑as‑Code (IaC) drift,
or by another team managing the workspace — the ingestion pipeline breaks silently:

- The Application Insights ingestion API continues to return **HTTP 200** to your SDKs.
- Data enters the ingestion pipeline but has nowhere to land, so it is **silently
  dropped**.
- There is no error, no alert, and no SDK-side indication of failure.

This is one of the more dangerous failure modes because it can go unnoticed for days or even weeks, until someone realizes data is missing from a dashboard or alert, or spots the warning banner on the Application Insights overview page indicating that the Log Analytics workspace is no longer available.

### How the Script Detects It

The script extracts the workspace resource ID from the AI resource properties and makes
an ARM GET request:

```
GET {wsResourceId}?api-version=2023-09-01
```

| ARM Response | Script Action |
|-------------|---------------|
| HTTP 200 | Workspace exists — continues with further checks |
| HTTP 404 | Workspace deleted — raises a **BLOCKING** finding and sets `$pipelineBroken = $true` |
| HTTP 401 / 403 | Insufficient permissions to verify — raises an **INFO** advisory |

When a BLOCKING finding is raised, the script skips downstream checks (daily cap,
transforms, etc.) because they are moot if the workspace does not exist.

### How to Fix It

**If deleted within the last 14 days:**

Log Analytics workspaces enter a soft-delete state for 14 days. You can recover:

1. Navigate to **Log Analytics workspaces** in the Azure Portal.
2. Look for the deleted workspace in the **Recently deleted** section.
3. Click **Recover**.

**If deleted more than 14 days ago:**

The workspace is permanently gone. You must:

1. Create a new Log Analytics workspace (or identify an existing one).
2. Go to **Application Insights → Properties → Change workspace**.
3. Re‑associate the Application Insights resource with the all new workspace, or with any re‑created workspace that retains the original Log Analytics URI, but has a new workspace id value.
4. Note: historical data from the deleted workspace is not recoverable.

**Docs:** [Recover a deleted Log Analytics workspace](https://learn.microsoft.com/azure/azure-monitor/logs/delete-workspace#recover-a-workspace)

---

## 4. Workspace Access Control Mode

### Symptom

You run queries in Application Insights or Log Analytics and get **empty results** — no
errors, no permission denied messages, just zero rows. The Application Insights resource
works fine for ingestion and Live Metrics, but queries return nothing. Other users
querying the same resource may see data normally.

### Why It Happens

The backing Log Analytics workspace has its Access Control Mode set to **"Require
workspace permissions"** instead of the default "Use resource or workspace permissions."
In this mode, querying any table requires explicit workspace-level RBAC (e.g., Log
Analytics Reader on the workspace itself).

The critical trap: the query API **does not return HTTP 403**. Instead, it silently
returns HTTP 200 with zero results. This makes the issue extremely difficult to diagnose 
because everything *appears* to work — you just get no data.

### How the Script Detects It

After successfully retrieving the workspace properties, the script checks:

```
$wsProps.features.enableLogAccessUsingOnlyResourcePermissions
```

If this value is `$false`, the workspace is in "Require workspace permissions" mode, and
an **INFO** finding is raised. The script cannot determine whether your specific user has
workspace-level permissions, so it flags the configuration for your awareness.

### How to Fix It

**Option A — Change the access control mode** (if you own the workspace):

1. Navigate to **Log Analytics workspace → Properties**.
2. Change **Access control mode** to **"Use resource or workspace permissions."**

This allows users with resource-level RBAC (e.g., Reader on the Application Insights
resource) to query data originating from that resource, while users with workspace-level
RBAC can query everything.

**Option B — Grant workspace-level permissions** (if the mode is intentional):

1. Navigate to **Log Analytics workspace → Access control (IAM)**.
2. Assign **Log Analytics Reader** (or a custom role) to users who need to query the
   data.

**Docs:** [Manage access to log data and workspaces](https://learn.microsoft.com/azure/azure-monitor/logs/manage-access)

---

## 5. Log Analytics Daily Cap Reached

### Symptom

Telemetry stops appearing in queries at the same time every day (typically aligning with
UTC time listed as "Daily limit will be set at" value). Your application continues sending data and
SDKs report success. After the cap resets, data starts appearing again. You may also
notice gaps in alerts or dashboards that correlate with the cap window.

### Why It Happens

The Log Analytics workspace has a **daily cap** (`dailyQuotaGb`) that limits how much
data can be ingested per day. Once the cap is reached, the workspace enters an
**OverQuota** state:

- All ingestion to the workspace is **stopped**.
- The Application Insights ingestion API still returns **HTTP 200** to your SDKs.
- Data is silently dropped at the Log Analytics layer.
- Ingestion resumes automatically when the quota resets.

This affects *all* data sources writing to the workspace, not just Application Insights.

### How the Script Detects It

The script reads the workspace capping properties:

```
$wsProps.workspaceCapping.dataIngestionStatus  → "OverQuota" or "RespectQuota"
$wsProps.workspaceCapping.dailyQuotaGb         → configured cap in GB
$wsProps.workspaceCapping.quotaNextResetTime   → when the cap resets
```

If `dataIngestionStatus` equals `"OverQuota"`, a **BLOCKING** finding is raised. The
script also parses the reset time (handling both ISO 8601 and the legacy `/Date(epoch)/`
format) to tell you exactly when ingestion will resume.

### How to Fix It

**Immediate relief:**

1. Navigate to **Log Analytics workspace → Usage and estimated costs → Daily cap**.
2. **Increase the cap** or **turn it off** (set to no limit).
3. Ingestion resumes immediately — you do not need to wait for the reset time.

**Long-term cost control** (without the data-loss risk of a hard cap):

1. Use [commitment tiers](https://learn.microsoft.com/azure/azure-monitor/logs/cost-logs#commitment-tiers) for predictable pricing.
2. Implement SDK-side adaptive sampling to reduce volume at the source.
3. Set up **daily cap alerts** (Log Analytics → Alerts) that warn you *before* the cap
   is hit, giving you time to act.
4. Use [data collection rules](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview) to filter low-value telemetry before ingestion.

**Docs:** 
- [Set the daily cap on a Log Analytics workspace](https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap)
- [Troubleshoot high data ingestion in Application Insights](https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/troubleshoot-high-data-ingestion)

---

## 6. Azure Subscription Suspended

### Symptom

The behavior depends on whether Application Insights and its backing Log Analytics
workspace are in the **same** or **different** Azure subscriptions:

**Same subscription:** The ingestion API returns a **non-200 response** to your SDKs, leading to telemetry dopped behaviors. This failure will show up in the SDK self-diagnostic logs without impacting your running application. 

**Cross-subscription (AI in subscription A, LA workspace in subscription B, and
subscription B is suspended):** The Application Insights ingestion API returns **HTTP
200** to your SDKs because the AI resource in subscription A is still healthy. But when
the ingestion pipeline tries to write to the suspended workspace in subscription B, the
data is **silently dropped**. The 200 response was already returned to the SDK — it is
too late to notify the caller.

This cross-subscription variant is the dangerous case: your application sees no errors,
but data never reaches Log Analytics.

### Why It Happens

Common causes for subscription suspension include:

- Expired credit (free trial, Visual Studio subscription, sponsorship).
- Failed payment on a pay-as-you-go subscription.
- Administrative action by the account owner or Azure support.
- Policy enforcement by the organization.

When the **same subscription** hosts both the AI resource and the LA workspace, the
ingestion endpoint itself is affected by the suspension, so it can reject incoming
requests with a non-200 status.

When the resources are in **different subscriptions**, the AI ingestion endpoint (in the
healthy subscription) accepts the telemetry normally. The failure only occurs downstream
when the pipeline attempts to deliver data to the workspace in the suspended
subscription — but the HTTP 200 has already been returned to the SDK at that point.

### How the Script Detects It

While checking the workspace status (as part of the daily cap check), the script detects
if `dataIngestionStatus` returns `"SubscriptionSuspended"`. This triggers a **BLOCKING**
finding and sets `$pipelineBroken = $true`, which halts all downstream known-issue
checks.

### How to Fix It

1. Navigate to **Subscriptions** in the Azure Portal.
2. Select the suspended subscription and follow the reactivation instructions.
3. For billing issues: **Cost Management + Billing → Payment methods** — update your
   payment instrument.
4. For expired credits: convert to pay-as-you-go or add a new credit/sponsorship.
5. Contact Azure support if the suspension reason is unclear.

After reactivation, resources typically resume within minutes, but telemetry sent during
the suspension window is **not recoverable**.

**Docs:** [Reactivate a disabled Azure subscription](https://learn.microsoft.com/azure/cost-management-billing/manage/subscription-disabled)

---

## 7. Daily Cap Misconfiguration (AI vs Log Analytics)

### Symptom

You configured a daily cap on the Application Insights resource (the classic/legacy cap),
but data stops before that cap is reached. Or you removed the AI daily cap expecting
unlimited ingestion, but the Log Analytics workspace has its own cap that kicks in first.
The mismatch in daily cap settings causes silent data loss because the more restrictive cap wins.

### Why It Happens

Workspace-based Application Insights resources have **two independent daily cap
settings**:

1. **Application Insights daily cap** — the legacy setting from classic AI resources,
   configured via the AI portal blade.
2. **Log Analytics daily cap** — the workspace-level setting that controls all data
   flowing into the workspace.

These two caps operate independently. The **more restrictive cap wins**: if the AI cap
is 10 GB/day but the LA workspace cap is 5 GB/day, ingestion stops at 5 GB with no
indication from the AI side that the workspace cap was the bottleneck.

### How the Script Detects It

The script fetches the AI-level daily cap from the legacy PricingPlans API:

```
GET {aiId}/PricingPlans/current?api-version=2017-10-01
```

It then compares this against the workspace-level `dailyQuotaGb` using five-branch logic:

| AI Cap | LA Cap | Result |
|--------|--------|--------|
| Set | LA < AI | **WARNING** — LA cap is more restrictive, silent data drop risk |
| Off | LA has cap | **INFO** — LA cap is the effective limit (may be intentional) |
| Set | LA >= AI | OK — caps are properly aligned |
| Set | LA off | OK — only AI cap applies |
| Off | Off | OK — no caps configured |

### How to Fix It

1. **Align the caps:** Decide which cap you want to be authoritative. Set the other to
   the same value or higher.
   - **AI cap:** Application Insights → Configure → Usage and estimated costs → Daily cap.
   - **LA cap:** Log Analytics workspace → Usage and estimated costs → Daily cap.

2. **Remove the AI cap** and manage costs exclusively at the workspace level (recommended):
   - Set the AI daily cap to **OFF** or a very high value.
   - Use the LA daily cap as the single control point.

3. **Set daily cap alerts** on both resources so you are notified before either cap is
   reached.

**Docs:** [Daily cap on Application Insights](https://learn.microsoft.com/azure/azure-monitor/app/pricing#set-the-daily-cap)

---

## 8. Diagnostic Settings Duplicate Telemetry

### Symptom

KQL queries return **duplicate records**: the same request, dependency, or exception
appears twice (or more) in query results. Counts in dashboards and alerts are inflated.
The duplicates have identical timestamps and nearly identical content, but may differ in
system-generated fields like `_ResourceId`.

### Why It Happens

Azure Diagnostic Settings can export Application Insights logs to a Log Analytics
workspace. But workspace-based Application Insights **already writes its data directly
to Log Analytics**. Adding a Diagnostic Setting that exports AI logs to a workspace
creates a **second copy** of every record.

There are two variants:

**Same-workspace export:**
The Diagnostic Setting exports AI logs to the *same* workspace that the AI resource is
already writing to. Result: duplicate records in both Application Insights queries and
direct Log Analytics queries.

**Different-workspace export** (most common):
The Diagnostic Setting exports AI logs to a *different* workspace. Application Insights
automatically stitches data across workspaces, so AI-scoped queries show duplicates. But
querying each individual workspace directly shows only one copy.

In both cases, the duplication is silent — no errors, no warnings in the portal. It
manifests only when query results look "too high."

### How the Script Detects It

The script fetches diagnostic settings from ARM:

```
GET {aiId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview
```

For each diagnostic setting, it checks:

1. Does it have a `workspaceId` (i.e., export to Log Analytics)?
2. Does it have any enabled log categories that overlap with Application Insights tables?

If both conditions are true, the script counts how many settings export to the **same
workspace** as the AI resource and how many export to **different workspaces**. An
**INFO** finding is raised with the specific log categories and destination workspaces
involved.

### How to Fix It

**Option A — Remove the Diagnostic Setting** (recommended):

1. Navigate to **Application Insights → Diagnostic settings**.
2. Delete any setting that exports Application Insights log categories to a Log
   Analytics workspace. 
3. Data continues to flow through the native AI → LA pipeline — nothing is lost.

> Note: Exporting Diagnostic Settings to Event Hub or Azure Storage does not 
> result in duplicate telemetry in your queries.

**Option B — Keep the export but de-duplicate in queries:**

Add `| distinct *` or `| summarize take_any(*) by OperationId, ...` to your KQL queries
to eliminate duplicates at query time. This is a workaround, not a fix.

**Option C — Query the destination workspace directly** (different-workspace variant
only):

If the Diagnostic Setting exports to a different workspace, query that workspace
directly instead of through the Application Insights portal. Each individual workspace
contains only one copy.

**Docs:** [Diagnostic settings for Application Insights](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings#application-insights)

---

## 9. Workspace Transforms (DCRs)

### Symptom

Telemetry is ingested successfully (HTTP 200 from the API, records appear in Log
Analytics), but records are **missing fields**, have **altered values**, or some records
are **missing entirely**. The issue can affect specific tables (e.g., `AppRequests` but not
`AppExceptions`) or all App Insights tables, and the filtering/modification pattern 
is consistent rather than random.

### Why It Happens

**Workspace transforms** are KQL expressions attached to Data Collection Rules (DCRs)
of kind `WorkspaceTransforms`. They execute on every record *after* it enters the
ingestion pipeline but *before* it lands in the Log Analytics table. Transforms can:

- **Drop rows** — a `| where` clause filters out records that don't match.
- **Remove columns** — a `| project` or `| project-away` clause strips fields.
- **Modify values** — an `| extend` clause overwrites column values.
- **Aggregate rows** — a `| summarize` clause combines multiple records into one,
  losing individual record detail.
- **Limit rows** — a `| take` or `| limit` clause retains only a subset.

Transforms are powerful for cost optimization (dropping verbose debug traces, removing
PII columns), but they operate silently. There is no indication in the Application
Insights UI that data was modified before landing.

A transform DCR can be created in **any subscription** — it does not need to be in the
same subscription as the workspace. This makes them particularly easy to overlook during
troubleshooting.

### How the Script Detects It

The script uses **Azure Resource Graph** to search the entire tenant for
`WorkspaceTransforms` DCRs targeting the backing workspace:

```kusto
resources
| where type =~ 'microsoft.insights/datacollectionrules'
| where kind =~ 'WorkspaceTransforms'
| mv-expand dest = properties.destinations.logAnalytics
| where tolower(tostring(dest.workspaceResourceId)) == tolower('{wsResourceId}')
| mv-expand flow = properties.dataFlows
| mv-expand stream = flow.streams
| where tostring(stream) startswith 'Microsoft-Table-App'
| project name, id, tableName=..., transformKql=...
```

> **Note:** A Data Collection Rule may apply to your workspace even if it does not appear 
> in query results, because the account running the script may lack permissions to view 
> all DCRs in the tenant.

The query:

1. Finds all DCRs of kind `WorkspaceTransforms` across the tenant (using `-UseTenantScope`).
2. Matches DCRs whose destination is your backing workspace.
3. Filters for streams targeting App Insights tables (the `Microsoft-Table-App*` prefix).
4. Extracts the transform KQL for each matching stream.

For each result, the script classifies the transform:

| Transform KQL | Classification |
|--------------|----------------|
| `source` or empty | **Passthrough** — no modification, OK |
| Contains `\| where` | May be dropping rows |
| Contains `\| project` | May be removing columns |
| Contains `\| project-away` | Explicitly removes specific columns |
| Contains `\| extend` | Adds or modifies columns |
| Contains `\| summarize` | Aggregates rows (individual records may be lost) |
| Contains `\| take` / `\| limit` | Only a subset of rows retained |

If any non-passthrough transforms are found, an **INFO** finding is raised listing the
affected tables and the transform KQL.

### How to Fix It

**To review a transform:**

1. Navigate to **Log Analytics workspace → Tables**.
2. Select the affected table (e.g., `AppRequests`).
3. Click the ellipsis (**...**) → **Create or edit transformation**.
4. Review the KQL expression.

**To remove a transform:**

Set the `transformKql` to just `source` — this makes it a passthrough (all data flows
through unchanged):

1. In the table transformation editor, replace the KQL with `source`.
2. Or delete the DCR entirely via **Azure Portal → Data Collection Rules**.

**To verify the transform is gone:**

Re-run the script. The Workspace Transforms check should report "None targeting App
Insights tables" or "Passthrough only."

> **Tip:** If you are intentionally using transforms for cost optimization (e.g.,
> dropping debug-level traces), document the transform logic and set up alerts on
> table row counts so you can distinguish intentional filtering from unexpected data
> loss.

**Docs:** [Workspace data collection transformations](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations)

---

## Quick Reference: Detection Summary

This table summarizes what each check looks at and when it runs.

| Check | ARM Property / API | Requires | Severity |
|-------|-------------------|----------|----------|
| Local Auth Disabled | `properties.DisableLocalAuth` | AI resource | INFO |
| Ingestion Sampling | `properties.SamplingPercentage` | AI resource | INFO |
| Workspace Deleted | ARM GET on `WorkspaceResourceId` | AI resource + workspace ID | BLOCKING |
| Access Control Mode | `features.enableLogAccessUsingOnlyResourcePermissions` | Workspace accessible | INFO |
| Daily Cap Reached | `workspaceCapping.dataIngestionStatus` | Workspace accessible | BLOCKING |
| Subscription Suspended | `workspaceCapping.dataIngestionStatus` | Workspace accessible | BLOCKING |
| Daily Cap Mismatch | PricingPlans API + workspace cap | AI resource + workspace | WARNING / INFO |
| Diagnostic Settings | Diagnostic Settings ARM API | AI resource | INFO |
| Workspace Transforms | Azure Resource Graph | AI resource + workspace ID | INFO |

### Severity Levels

- **BLOCKING** — Ingestion is completely stopped. No telemetry reaches Log Analytics.
  The script sets `$pipelineBroken = $true` and may skip downstream checks.
- **WARNING** — Data loss is likely occurring but ingestion is not fully stopped.
  Action recommended.
- **INFO** — A configuration worth noting. May or may not cause issues depending on
  your intent. Review and confirm the configuration is deliberate.

---

## The "Silent HTTP 200" Pattern

Several of the issues above share the same dangerous pattern:

```
SDK sends telemetry  →  HTTP 200 OK  →  data silently dropped
```

This occurs with:

- **Workspace deleted** — data enters the pipeline but has no destination.
- **Daily cap reached (OverQuota)** — the workspace refuses new data at the LA layer.
- **Daily cap mismatch** — the LA cap fires before the AI cap, dropping data silently.
- **Subscription suspended (cross-subscription only)** — the AI resource accepts data
  but the LA workspace in a different suspended subscription cannot receive it.
- **Workspace transforms** — a `| where` clause filters records after ingestion.

In every case, your application sees no errors. SDK health metrics look normal. The only
way to detect these issues is to check the Azure resource configuration directly — which
is exactly what this script does.

If you are running `Test-AppInsightsTelemetryFlow` as part of a CI pipeline or fleet
scan (see [Automation & CI](automation-ci.md)), consider alerting on any finding with
severity `BLOCKING` or `WARNING` to catch these silent failures early.

---

*See also: [Interpreting Results](interpreting-results.md) for how to read the script's
overall output, and [Diagnostic Flow](diagnostic-flow.md) for where these checks fit
in the full execution sequence.*
