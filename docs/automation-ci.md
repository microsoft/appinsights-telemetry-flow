# Automation & Batch Operations

> How to run the diagnostic script against hundreds or thousands of App
> Insights resources, collect the results, and quickly identify which
> resources need attention.

---

## Table of Contents

- [Exit Codes](#exit-codes)
- [Output Files](#output-files)
  - [JSON Report Structure](#json-report-structure)
  - [TXT Console Log](#txt-console-log)
- [Key Parameters for Automation](#key-parameters-for-automation)
- [Running Against a Single Resource (Non-Interactive)](#running-against-a-single-resource-non-interactive)
- [Batch: Many Resources, One Machine](#batch-many-resources-one-machine)
  - [PowerShell — Loop Over Connection Strings](#powershell--loop-over-connection-strings)
  - [Bash — Loop Over Connection Strings](#bash--loop-over-connection-strings)
  - [Reading Connection Strings from a CSV](#reading-connection-strings-from-a-csv)
  - [Pulling Connection Strings from Azure](#pulling-connection-strings-from-azure)
- [Batch: Many Machines, One Resource](#batch-many-machines-one-resource)
- [Parsing Results at Scale](#parsing-results-at-scale)
  - [Quick Triage: Exit Codes Only](#quick-triage-exit-codes-only)
  - [JSON Deep Parse: Diagnosis Items](#json-deep-parse-diagnosis-items)
  - [Building a Summary Report](#building-a-summary-report)
  - [Filtering for Specific Issues](#filtering-for-specific-issues)
- [CI/CD Pipeline Integration](#cicd-pipeline-integration)
  - [Azure DevOps YAML](#azure-devops-yaml)
  - [GitHub Actions](#github-actions)
- [Tips for Large-Scale Runs](#tips-for-large-scale-runs)
- [Bash Script Differences](#bash-script-differences)
- [Further Reading](#further-reading)

---

## Exit Codes

Both the PowerShell and Bash scripts return the same exit codes, designed
for programmatic consumption:

| Exit Code | Meaning | Action Required |
|-----------|---------|-----------------|
| **0** | No issues found. All checks passed, no diagnosis findings. | None — this resource is healthy. |
| **1** | **INFO** findings only. Informational items, no action required. | Optional — review for awareness. |
| **2** | **WARNING** detected. Telemetry is at risk but may still be flowing. | Review soon — likely to become blocking. |
| **3** | **BLOCKING** issue detected. Telemetry is broken or will be rejected. | Immediate investigation needed. |

The exit code is the **fastest way to triage at scale**. After running
against 500 resources, sort by exit code descending and focus on the 3s
first, then the 2s.

**How exit codes are computed:**

```
if (any diagnosis item has Severity = "BLOCKING") → exit 3
elseif (any diagnosis item has Severity = "WARNING") → exit 2
elseif (any diagnosis item has Severity = "INFO") → exit 1
else → exit 0
```

A single BLOCKING finding makes the entire run exit 3, even if everything
else passed. This is intentional — one broken link in the telemetry chain
means telemetry is not flowing.

---

## Output Files

Every run produces two report files, saved to the `-OutputPath` directory
(PowerShell) or `--output-path` directory (Bash). If no path is given,
files are saved alongside the script.

| File | Format | Purpose |
|------|--------|---------|
| `AppInsights-Diag_{HOST}_{RESOURCE}_{TIMESTAMP}.json` | Machine-parseable JSON | Structured results for programmatic analysis |
| `AppInsights-Diag_{HOST}_{RESOURCE}_{TIMESTAMP}.txt` | Human-readable text | Console output mirror for manual review or ticket attachments |

When the App Insights resource name is discovered via Azure checks it is
included in the filename; otherwise the `{RESOURCE}` segment is omitted.
The filename encodes the hostname, resource name, and UTC timestamp, so
runs from different machines, resources, and times never collide.

### JSON Report Structure

The JSON file contains every check result, environment detail, and
diagnosis item in a single structured object:

```json
{
  "ToolVersion": "1.0.0",
  "Timestamp": "2026-03-03T14:30:00Z",
  "Environment": {
    "ComputerName": "WEBAPP-PROD-01",
    "OS": "Microsoft Windows NT 10.0.20348.0",
    "PowerShellVersion": "7.4.1",
    "AzureHostType": "App Service",
    "AzureHostDetail": "contoso-api / contoso-api-prod",
    "IsAppService": true,
    "ProxyDetected": false,
    "ConsoleColorSupported": true
  },
  "ConnectionString": {
    "InstrumentationKey": "01234567...abcd",
    "IngestionEndpoint": "https://{region}.in.applicationinsights.azure.com/",
    "LiveEndpoint": "https://{region}.livediagnostics.monitor.azure.com/",
    "IsGlobalEndpoint": false,
    "Cloud": "Azure Public",
    "CloudSuffix": "com"
  },
  "KnownIssues": {
    "LocalAuthDisabled": false,
    "IngestionSamplingPct": 100,
    "WorkspaceStatus": "Exists",
    "DailyCapStatus": "Normal",
    "AiDailyCapGb": "OFF",
    "LaDailyCapGb": 10.0,
    "DailyCapMismatch": false,
    "WorkspaceTransforms": null
  },
  "Results": {
    "DNS": [ ... ],
    "TCP": [ ... ],
    "TLS": [ ... ],
    "AMPLS": {
      "Checked": true,
      "ResourceFound": true,
      "AmplsLinked": true,
      "AccessModes": [ ... ],
      "ComparisonResults": [ ... ],
      "AccessAssessment": { ... }
    },
    "Ingestion": {
      "Status": "PASS",
      "HttpStatus": 200,
      "DurationMs": 142,
      "Detail": "Accepted",
      "TestRecordId": "a1b2c3d4-...",
      "TestRecordTimestamp": "2026-03-03T14:30:01.1234567Z"
    },
    "EndToEndVerification": {
      "Status": "PASS",
      "RecordFound": true,
      "PollAttempts": 2,
      "WaitedSeconds": 45,
      "Latency": "43s"
    }
  },
  "Diagnosis": [
    {
      "Severity": "BLOCKING",
      "Title": "Ingestion BLOCKED From This Machine",
      "Summary": "Ingestion BLOCKED From This Machine",
      "Description": "App Insights requires private link but this machine is on a public network.",
      "Fix": "Add this App Insights resource to an AMPLS accessible from this network.",
      "Portal": "App Insights > Network Isolation",
      "Docs": "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security"
    }
  ],
  "Summary": {
    "TotalChecks": 14,
    "Passed": 12,
    "Warnings": 0,
    "Failed": 2,
    "AmplsDetected": true,
    "AmplsValidated": true,
    "AzureChecksRequested": true,
    "AzureChecksCompleted": true,
    "DetectedAppInsights": "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/microsoft.insights/components/my-appinsights-resource",
    "DetectedLogAnalytics": "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.OperationalInsights/workspaces/my-log-analytics-workspace"
  }
}
```

**Key fields for automation:**

| JSON Path | Type | What It Tells You |
|-----------|------|-------------------|
| `Diagnosis` | Array | Every finding. Filter by `.Severity` to find blockers and warnings. |
| `Diagnosis[].Severity` | String | `BLOCKING`, `WARNING`, or `INFO` |
| `Diagnosis[].Title` | String | Machine-readable finding name (stable across versions) |
| `Diagnosis[].Fix` | String | Actionable fix instruction |
| `Summary.Failed` | Int | Count of failed checks |
| `Summary.Warnings` | Int | Count of warnings |
| `Summary.AmplsDetected` | Bool | Whether AMPLS/private link was detected in DNS |
| `Results.Ingestion.HttpStatus` | Int | HTTP status from the ingestion test (200 = accepted) |
| `Results.Ingestion.Status` | String | `PASS`, `FAIL`, or `SKIP` |
| `KnownIssues.DailyCapStatus` | String | `Normal` or `OverQuota` |
| `KnownIssues.LocalAuthDisabled` | Bool | Whether iKey-based ingestion is disabled |

### TXT Console Log

The `.txt` file mirrors the console output and includes a header block
and diagnosis summary. It is useful for:

- Attaching to support tickets
- Quick manual review when you do not have `jq` available
- Archiving alongside the JSON for human context

---

## Key Parameters for Automation

| Parameter (PS) | Parameter (Bash) | Purpose |
|----------------|------------------|---------|
| `-AutoApprove` | `--auto-approve` | **Required for automation.** Bypasses all interactive consent prompts (Azure login, ingestion test). Without this, the script pauses and waits for a human to type Y/N. |
| `-OutputPath "C:\results"` | `--output-path /results` | Where to save JSON + TXT reports. Creates the directory if it does not exist. |
| `-Compact` | `--compact` | Suppress verbose educational output. Keeps console output short for logs. |
| `-NetworkOnly` | `--network-only` | Skip Azure login and resource checks. Pure network tests only (DNS, TCP, TLS, ingestion API). Fastest mode. |
| `-SkipIngestionTest` | `--skip-ingestion-test` | Skip the test telemetry POST. Useful when you only want configuration checks. |
| `-TenantId "guid"` | `--tenant-id "guid"` | Target a specific Entra ID tenant. Essential for multi-tenant environments. |

**Minimum for batch automation:**

```powershell
# PowerShell — non-interactive, reports saved to a shared folder
.\Test-AppInsightsTelemetryFlow.ps1 `
    -ConnectionString $connStr `
    -AutoApprove `
    -Compact `
    -OutputPath "C:\diag-results"
```

```bash
# Bash — non-interactive, reports saved to a shared folder
./test-appinsights-telemetry-flow.sh \
    --connection-string "$conn_str" \
    --auto-approve \
    --compact \
    --output-path /diag-results
```

---

## Running Against a Single Resource (Non-Interactive)

Before scaling up, verify the non-interactive workflow against a single
resource:

```powershell
$cs = "InstrumentationKey=00000000-0000-0000-0000-000000000000;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;LiveEndpoint=https://{region}.livediagnostics.monitor.azure.com/"

.\Test-AppInsightsTelemetryFlow.ps1 `
    -ConnectionString $cs `
    -AutoApprove `
    -Compact `
    -OutputPath "C:\diag-results"

# Check the exit code
$LASTEXITCODE   # 0, 1, 2, or 3
```

Verify that:
1. No interactive prompts appeared
2. A `.json` and `.txt` file were created in `C:\diag-results`
3. The exit code matches what you expected

---

## Batch: Many Resources, One Machine

The most common automation scenario: you have a list of App Insights
connection strings and want to test all of them from a single machine
(e.g., a jump box, build agent, or your workstation).

### PowerShell — Loop Over Connection Strings

```powershell
# List of connection strings to test
$connectionStrings = @(
    "InstrumentationKey=aaaa...;IngestionEndpoint=https://westus2.in.applicationinsights.azure.com/;..."
    "InstrumentationKey=bbbb...;IngestionEndpoint=https://eastus.in.applicationinsights.azure.com/;..."
    "InstrumentationKey=cccc...;IngestionEndpoint=https://northeurope.in.applicationinsights.azure.com/;..."
)

$resultsDir = "C:\diag-results\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

$summary = @()

foreach ($cs in $connectionStrings) {
    # Extract iKey for display (first 8 chars)
    $iKey = if ($cs -match 'InstrumentationKey=([^;]+)') { $Matches[1].Substring(0, 8) } else { "unknown" }
    Write-Host "Testing: $iKey..." -NoNewline

    # Run the script as a child process to get a clean exit code
    $proc = Start-Process -FilePath "pwsh" -ArgumentList @(
        "-NoProfile", "-File", ".\Test-AppInsightsTelemetryFlow.ps1",
        "-ConnectionString", $cs,
        "-AutoApprove",
        "-Compact",
        "-OutputPath", $resultsDir
    ) -Wait -PassThru -NoNewWindow

    $exitCode = $proc.ExitCode
    $status = switch ($exitCode) {
        0 { "PASS" }
        1 { "INFO" }
        2 { "WARNING" }
        3 { "BLOCKING" }
        default { "UNKNOWN ($exitCode)" }
    }

    Write-Host " $status"

    $summary += [PSCustomObject]@{
        iKey = $iKey
        ExitCode = $exitCode
        Status = $status
    }
}

# Show summary table
$summary | Format-Table -AutoSize

# Show only resources that need attention
$needsAttention = $summary | Where-Object { $_.ExitCode -ne 0 }
if ($needsAttention) {
    Write-Host "`n=== RESOURCES NEEDING ATTENTION ===" -ForegroundColor Yellow
    $needsAttention | Format-Table -AutoSize
} else {
    Write-Host "`nAll resources passed." -ForegroundColor Green
}
```

### Bash — Loop Over Connection Strings

```bash
#!/usr/bin/env bash
set -euo pipefail

results_dir="/diag-results/$(date +%Y-%m-%d)"
mkdir -p "$results_dir"

# Connection strings — one per line
mapfile -t conn_strings <<'EOF'
InstrumentationKey=aaaa...;IngestionEndpoint=https://westus2.in.applicationinsights.azure.com/;...
InstrumentationKey=bbbb...;IngestionEndpoint=https://eastus.in.applicationinsights.azure.com/;...
InstrumentationKey=cccc...;IngestionEndpoint=https://northeurope.in.applicationinsights.azure.com/;...
EOF

declare -a results=()

for cs in "${conn_strings[@]}"; do
    ikey="${cs#*InstrumentationKey=}"
    ikey="${ikey%%;*}"
    ikey="${ikey:0:8}"
    printf "Testing: %s..." "$ikey"

    set +e
    ./test-appinsights-telemetry-flow.sh \
        --connection-string "$cs" \
        --auto-approve \
        --compact \
        --output-path "$results_dir" > /dev/null 2>&1
    rc=$?
    set -e

    case $rc in
        0) status="PASS" ;;
        1) status="INFO" ;;
        2) status="WARNING" ;;
        3) status="BLOCKING" ;;
        *) status="UNKNOWN($rc)" ;;
    esac

    printf " %s\n" "$status"
    results+=("$ikey|$rc|$status")
done

echo ""
printf "%-12s %-6s %-10s\n" "iKey" "Exit" "Status"
printf "%-12s %-6s %-10s\n" "--------" "----" "--------"
for r in "${results[@]}"; do
    IFS='|' read -r k e s <<< "$r"
    printf "%-12s %-6s %-10s\n" "$k" "$e" "$s"
done
```

### Reading Connection Strings from a CSV

For large fleets, maintain a CSV inventory file:

```csv
ResourceName,ResourceGroup,ConnectionString
contoso-api-prod,rg-prod,InstrumentationKey=aaaa...;IngestionEndpoint=...
contoso-web-prod,rg-prod,InstrumentationKey=bbbb...;IngestionEndpoint=...
contoso-worker-staging,rg-staging,InstrumentationKey=cccc...;IngestionEndpoint=...
```

```powershell
$inventory = Import-Csv ".\appinsights-inventory.csv"
$resultsDir = "C:\diag-results\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

$summary = foreach ($row in $inventory) {
    Write-Host "Testing: $($row.ResourceName)..." -NoNewline

    $proc = Start-Process -FilePath "pwsh" -ArgumentList @(
        "-NoProfile", "-File", ".\Test-AppInsightsTelemetryFlow.ps1",
        "-ConnectionString", $row.ConnectionString,
        "-AutoApprove", "-Compact",
        "-OutputPath", $resultsDir
    ) -Wait -PassThru -NoNewWindow

    $status = switch ($proc.ExitCode) { 0 { "PASS" } 1 { "INFO" } 2 { "WARNING" } 3 { "BLOCKING" } default { "UNKNOWN" } }
    Write-Host " $status"

    [PSCustomObject]@{
        ResourceName = $row.ResourceName
        ResourceGroup = $row.ResourceGroup
        ExitCode = $proc.ExitCode
        Status = $status
    }
}

# Export results
$summary | Export-Csv ".\batch-results.csv" -NoTypeInformation
$summary | Where-Object { $_.ExitCode -ne 0 } | Format-Table -AutoSize
```

### Pulling Connection Strings from Azure

If you have the Az PowerShell modules, you can pull connection strings
directly from Azure instead of maintaining a CSV:

```powershell
# Requires: Az.Accounts, Az.ApplicationInsights
Connect-AzAccount

# Get all App Insights resources in a subscription
$resources = Get-AzApplicationInsights

# Or filter by resource group
# $resources = Get-AzApplicationInsights -ResourceGroupName "rg-prod"

$resultsDir = "C:\diag-results\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

$summary = foreach ($ai in $resources) {
    $cs = $ai.ConnectionString
    if (-not $cs) {
        Write-Host "Skipping $($ai.Name) — no connection string" -ForegroundColor DarkGray
        continue
    }

    Write-Host "Testing: $($ai.Name)..." -NoNewline

    $proc = Start-Process -FilePath "pwsh" -ArgumentList @(
        "-NoProfile", "-File", ".\Test-AppInsightsTelemetryFlow.ps1",
        "-ConnectionString", $cs,
        "-AutoApprove", "-Compact",
        "-OutputPath", $resultsDir
    ) -Wait -PassThru -NoNewWindow

    $status = switch ($proc.ExitCode) { 0 { "PASS" } 1 { "INFO" } 2 { "WARNING" } 3 { "BLOCKING" } default { "UNKNOWN" } }
    Write-Host " $status"

    [PSCustomObject]@{
        Name = $ai.Name
        ResourceGroup = $ai.ResourceGroupName
        Location = $ai.Location
        ExitCode = $proc.ExitCode
        Status = $status
    }
}

# Show only failures
$summary | Where-Object { $_.ExitCode -ne 0 } | Format-Table -AutoSize
```

---

## Batch: Many Machines, One Resource

Sometimes the problem is not "which resource is broken" but "which
machines can reach a specific resource." This is common with AMPLS
issues where some VMs on a VNet resolve DNS correctly and others do not.

Deploy the script to each machine and run it against the same connection
string. The JSON reports will have different hostnames, so you can
collect them all into a shared directory and compare.

```powershell
# On each machine (via Invoke-Command, SSH, Azure Run Command, etc.)
.\Test-AppInsightsTelemetryFlow.ps1 `
    -ConnectionString $cs `
    -AutoApprove `
    -Compact `
    -NetworkOnly `
    -OutputPath "C:\diag-results"

# Copy reports to a shared location after the script finishes
Copy-Item "C:\diag-results\AppInsights-Diag_*.json" "\\shared\diag-results\" -Force
Copy-Item "C:\diag-results\AppInsights-Diag_*.txt"  "\\shared\diag-results\" -Force
```

> **Note:** The script blocks UNC paths (`\\server\share`) in `-OutputPath`
> for security reasons — reports contain partial instrumentation keys and
> internal hostnames. Write to a local directory first, then copy to
> the shared location.

Then parse the collected JSON files:

```powershell
$files = Get-ChildItem "\\shared\diag-results\*.json"

$machineResults = foreach ($f in $files) {
    $report = Get-Content $f.FullName | ConvertFrom-Json
    $blocking = @($report.Diagnosis | Where-Object { $_.Severity -eq "BLOCKING" })

    [PSCustomObject]@{
        Machine = $report.Environment.ComputerName
        OS = $report.Environment.OS
        AzureHost = $report.Environment.AzureHostType
        ExitCode = if ($blocking.Count -gt 0) { 3 }
                   elseif (@($report.Diagnosis | Where-Object { $_.Severity -eq "WARNING" }).Count -gt 0) { 2 }
                   elseif (@($report.Diagnosis | Where-Object { $_.Severity -eq "INFO" }).Count -gt 0) { 1 }
                   else { 0 }
        BlockingIssues = ($blocking | ForEach-Object { $_.Title }) -join "; "
        AmplsDetected = $report.Summary.AmplsDetected
    }
}

$machineResults | Sort-Object ExitCode -Descending | Format-Table -AutoSize
```

---

## Parsing Results at Scale

### Quick Triage: Exit Codes Only

The fastest approach — no JSON parsing needed:

```powershell
$files = Get-ChildItem "C:\diag-results\*.json"

$triage = foreach ($f in $files) {
    $report = Get-Content $f.FullName | ConvertFrom-Json
    $maxSev = if (@($report.Diagnosis | Where-Object { $_.Severity -eq "BLOCKING" }).Count -gt 0) { "BLOCKING" }
              elseif (@($report.Diagnosis | Where-Object { $_.Severity -eq "WARNING" }).Count -gt 0) { "WARNING" }
              else { "PASS" }

    [PSCustomObject]@{
        File = $f.Name
        Host = $report.Environment.ComputerName
        iKey = $report.ConnectionString.InstrumentationKey
        Endpoint = $report.ConnectionString.IngestionEndpoint
        Status = $maxSev
        Findings = $report.Diagnosis.Count
    }
}

Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "  Total:    $($triage.Count)"
Write-Host "  Blocking: $(@($triage | Where-Object Status -eq 'BLOCKING').Count)" -ForegroundColor Red
Write-Host "  Warning:  $(@($triage | Where-Object Status -eq 'WARNING').Count)" -ForegroundColor Yellow
Write-Host "  Pass:     $(@($triage | Where-Object Status -eq 'PASS').Count)" -ForegroundColor Green

# Show failures first
$triage | Sort-Object { switch ($_.Status) { "BLOCKING" { 0 } "WARNING" { 1 } default { 2 } } } |
    Format-Table -AutoSize
```

### JSON Deep Parse: Diagnosis Items

To extract exactly what is wrong with each resource:

```powershell
$files = Get-ChildItem "C:\diag-results\*.json"

$allFindings = foreach ($f in $files) {
    $report = Get-Content $f.FullName | ConvertFrom-Json

    foreach ($diag in $report.Diagnosis) {
        [PSCustomObject]@{
            Host = $report.Environment.ComputerName
            iKey = $report.ConnectionString.InstrumentationKey
            Severity = $diag.Severity
            Title = $diag.Title
            Fix = $diag.Fix
            Portal = $diag.Portal
        }
    }
}

# All BLOCKING findings across all resources
$allFindings | Where-Object Severity -eq "BLOCKING" | Format-Table -Wrap

# Group by finding type — "How many resources have this problem?"
$allFindings |
    Where-Object { $_.Severity -in "BLOCKING", "WARNING" } |
    Group-Object Title |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize
```

**Example output:**

```
Count Name
----- ----
   47 Ingestion BLOCKED From This Machine
   23 Ghost AMPLS: Private IPs but Resource Not in AMPLS
   12 Daily Cap Reached (OverQuota)
    8 TLS Handshake Failure
    3 DNS Resolution Failures
```

This tells you: 47 resources have ingestion blocked (likely a shared
network issue), 23 have Ghost AMPLS (likely one AMPLS deployment broke
DNS for unrelated resources), and so on.

### Building a Summary Report

Combine triage and detail into a single CSV for stakeholders:

```powershell
$files = Get-ChildItem "C:\diag-results\*.json"

$report = foreach ($f in $files) {
    $r = Get-Content $f.FullName | ConvertFrom-Json
    $blocking = @($r.Diagnosis | Where-Object { $_.Severity -eq "BLOCKING" })
    $warnings = @($r.Diagnosis | Where-Object { $_.Severity -eq "WARNING" })

    [PSCustomObject]@{
        Timestamp        = $r.Timestamp
        Host             = $r.Environment.ComputerName
        AzureHostType    = $r.Environment.AzureHostType
        iKey             = $r.ConnectionString.InstrumentationKey
        Endpoint         = $r.ConnectionString.IngestionEndpoint
        Cloud            = $r.ConnectionString.Cloud
        IngestHttpStatus = $r.Results.Ingestion.HttpStatus
        IngestLatencyMs  = $r.Results.Ingestion.DurationMs
        E2eFound         = $r.Results.EndToEndVerification.RecordFound
        AmplsDetected    = $r.Summary.AmplsDetected
        DailyCapStatus   = $r.KnownIssues.DailyCapStatus
        LocalAuthOff     = $r.KnownIssues.LocalAuthDisabled
        BlockingCount    = $blocking.Count
        WarningCount     = $warnings.Count
        TopBlocking      = ($blocking | Select-Object -First 1).Title
        TopWarning       = ($warnings | Select-Object -First 1).Title
        Status           = if ($blocking.Count -gt 0) { "BLOCKING" }
                           elseif ($warnings.Count -gt 0) { "WARNING" }
                           else { "PASS" }
    }
}

$report | Export-Csv ".\fleet-health-report.csv" -NoTypeInformation
Write-Host "Saved fleet-health-report.csv ($($report.Count) resources)"
```

### Filtering for Specific Issues

Common queries against the batch results:

```powershell
$files = Get-ChildItem "C:\diag-results\*.json"
$reports = $files | ForEach-Object { Get-Content $_.FullName | ConvertFrom-Json }

# Which resources have AMPLS issues?
$reports | Where-Object { $_.Summary.AmplsDetected } |
    ForEach-Object { "$($_.ConnectionString.InstrumentationKey) — AMPLS detected" }

# Which resources hit their daily cap?
$reports | Where-Object { $_.KnownIssues.DailyCapStatus -eq "OverQuota" } |
    ForEach-Object { "$($_.ConnectionString.InstrumentationKey) — Daily cap reached" }

# Which resources have local auth disabled (will break iKey-based SDKs)?
$reports | Where-Object { $_.KnownIssues.LocalAuthDisabled } |
    ForEach-Object { "$($_.ConnectionString.InstrumentationKey) — Local auth disabled" }

# Which resources had ingestion failures (non-200 HTTP status)?
$reports | Where-Object { $_.Results.Ingestion -and $_.Results.Ingestion.HttpStatus -ne 200 } |
    ForEach-Object {
        "$($_.ConnectionString.InstrumentationKey) — HTTP $($_.Results.Ingestion.HttpStatus): $($_.Results.Ingestion.Detail)"
    }

# Which resources had DNS resolve to private IPs but no AMPLS configured?
$reports | Where-Object {
    $_.Summary.AmplsDetected -and
    $_.Diagnosis | Where-Object { $_.Title -match "Ghost AMPLS" }
} | ForEach-Object { "$($_.ConnectionString.InstrumentationKey) — Ghost AMPLS" }
```

Using `jq` for Bash/Linux environments:

```bash
# All BLOCKING findings across all reports
for f in /diag-results/*.json; do
    jq -r '.Diagnosis[] | select(.Severity == "BLOCKING") |
        "\(.Severity)\t\(.Title)"' "$f"
done | sort | uniq -c | sort -rn

# Resources with non-200 ingestion status
for f in /diag-results/*.json; do
    jq -r 'select(.Results.Ingestion.HttpStatus != 200 and .Results.Ingestion != null) |
        "\(.ConnectionString.InstrumentationKey)\tHTTP \(.Results.Ingestion.HttpStatus)\t\(.Results.Ingestion.Detail)"' "$f"
done

# Group findings by title
for f in /diag-results/*.json; do
    jq -r '.Diagnosis[] | select(.Severity != "INFO") | .Title' "$f"
done | sort | uniq -c | sort -rn
```

---

## CI/CD Pipeline Integration

Use the script as a deployment gate: after deploying your application,
verify that telemetry can actually flow before promoting to production.

### Azure DevOps YAML

```yaml
# azure-pipelines.yml
stages:
  - stage: Deploy
    jobs:
      - job: DeployApp
        steps:
          - task: AzureWebApp@1
            inputs:
              appName: 'contoso-api-prod'
              # ... deployment config ...

  - stage: ValidateTelemetry
    dependsOn: Deploy
    jobs:
      - job: DiagCheck
        pool:
          vmImage: 'windows-latest'
        steps:
          - task: PowerShell@2
            displayName: 'Validate App Insights connectivity'
            inputs:
              targetType: 'filePath'
              filePath: './Test-AppInsightsTelemetryFlow.ps1'
              arguments: >
                -ConnectionString "$(AppInsightsConnectionString)"
                -AutoApprove
                -Compact
                -OutputPath "$(Build.ArtifactStagingDirectory)/diag"
            continueOnError: false  # exit 3 fails the stage

          - task: PublishBuildArtifacts@1
            displayName: 'Publish diagnostic reports'
            condition: always()  # publish even on failure
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)/diag'
              artifactName: 'telemetry-diagnostics'
```

**How it works:**
- Exit code 3 (BLOCKING) → pipeline stage fails → deployment does not
  promote
- Exit code 2 (WARNING) → pipeline stage fails (same behavior by default;
  change `continueOnError: true` if you want warnings to pass)
- Exit code 1 (INFO) → pipeline stage fails by default; use
  `continueOnError: true` to let informational findings pass
- Exit code 0 → stage passes → deployment proceeds
- Reports are always published as build artifacts for review

### GitHub Actions

```yaml
# .github/workflows/validate-telemetry.yml
name: Validate Telemetry
on:
  deployment_status:
    types: [success]

jobs:
  check:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run App Insights diagnostics
        shell: pwsh
        run: |
          .\Test-AppInsightsTelemetryFlow.ps1 `
              -ConnectionString "${{ secrets.APPINSIGHTS_CONNECTION_STRING }}" `
              -AutoApprove `
              -Compact `
              -OutputPath "${{ github.workspace }}/diag-results"

      - name: Upload diagnostic reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: telemetry-diagnostics
          path: diag-results/
```

---

## Tips for Large-Scale Runs

| Tip | Details |
|-----|---------|
| **Use `-Compact`** | Reduces console output by ~80%. In a loop of 500 resources, verbose output floods your terminal and log files. |
| **Use `-NetworkOnly` for first pass** | Skips Azure login and resource checks. Runs in ~10 seconds per resource instead of ~60. If network checks pass, the resource is almost certainly fine. Run the full check only on failures. |
| **Use `-SkipIngestionTest` when appropriate** | If you only need configuration checks (AMPLS, daily cap, local auth), skip the ingestion POST to avoid creating test records in every resource. |
| **Run as a child process** | Use `Start-Process -Wait -PassThru` (PowerShell) or a subshell (Bash) to get a clean exit code. Running the script via dot-sourcing (`. .\script.ps1`) would make `exit` terminate your shell. |
| **Parallelize carefully** | You can run multiple instances in parallel (one per resource), but be aware that all instances from the same machine will produce the same DNS/TCP/TLS results. Parallelism is most useful for the Azure resource checks (which are per-resource). |
| **Save reports to a shared path** | Write to a local `-OutputPath` first, then copy reports to a shared network drive or blob-mounted path. The script blocks UNC paths in `-OutputPath` for security reasons. Filenames include hostname and timestamp so they never collide. |
| **Store connection strings securely** | Never hardcode them in scripts. Use Azure Key Vault, environment variables, or pipeline secrets. The JSON report masks the instrumentation key (shows only the last 4 characters). |
| **Schedule regular runs** | Use Azure Automation, Task Scheduler, or cron to run weekly fleet health checks. Compare results over time to catch drift (e.g., someone changed a daily cap or AMPLS mode). |

---

## Bash Script Differences

The Bash script (`test-appinsights-telemetry-flow.sh`) uses long-form
flags instead of PowerShell parameter syntax, but the automation model
is identical:

| PowerShell | Bash |
|------------|------|
| `-ConnectionString $cs` | `--connection-string "$cs"` |
| `-AutoApprove` | `--auto-approve` |
| `-Compact` | `--compact` |
| `-NetworkOnly` | `--network-only` |
| `-SkipIngestionTest` | `--skip-ingestion-test` |
| `-OutputPath "C:\diag"` | `--output-path /diag` |
| `-TenantId "guid"` | `--tenant-id "guid"` |
| `$LASTEXITCODE` | `$?` |

The Bash script can perform the same Azure resource checks as the PowerShell
script (AMPLS validation, known issue checks, and E2E verification) when
Azure CLI authentication is available (for example, `az login` has been run).
When Azure login is not available, it falls back to network-only checks and
focuses on DNS, TCP, TLS, and the ingestion API test.

Exit codes are identical: `0` (clean), `1` (info), `2` (warning), `3` (blocking).

JSON output structure is identical. `AMPLS`, `KnownIssues`, and
`EndToEndVerification` sections are populated when the corresponding Azure
checks run, and are set to `null` when those checks are skipped (for example,
when Azure CLI login is not available).

---

## Further Reading

- [interpreting-results.md](interpreting-results.md) — Finding-by-finding
  reference for every diagnosis item the script can produce
- [diagnostic-flow.md](diagnostic-flow.md) — Phase ordering, skip logic,
  and what triggers each check
- [ampls-private-link-deep-dive.md](ampls-private-link-deep-dive.md) —
  Deep dive on AMPLS findings and what they mean
- [security-model.md](security-model.md) — Read-only guarantees,
  data handling, and why `-AutoApprove` is safe
