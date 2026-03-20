<#PSScriptInfo
.VERSION 1.0.0
.GUID b7e4f2a3-9c1d-4e8f-a5b6-3d2c1e0f9a8b
.AUTHOR Todd Foust (Microsoft)
.COMPANYNAME Microsoft
.COPYRIGHT (c) Microsoft Corporation. All rights reserved.
.TAGS ApplicationInsights AzureMonitor Diagnostics Troubleshooting AMPLS PrivateLink Connectivity PSEdition_Desktop PSEdition_Core Windows Linux MacOS
.PROJECTURI https://github.com/microsoft/appinsights-telemetry-flow
.LICENSEURI https://github.com/microsoft/appinsights-telemetry-flow/blob/main/LICENSE
.RELEASENOTES
  v1.0.0 - Initial public release. DNS, TCP, TLS, ingestion test, E2E verification,
           AMPLS validation, known issue checks (local auth, daily cap, workspace health,
           ingestion sampling, DCR transforms). Azure checks auto-detect Az module.
#>

<#
.SYNOPSIS
    Diagnoses Application Insights connectivity, configuration, and known issues.

.DESCRIPTION
    Comprehensive diagnostic tool for Azure Monitor Application Insights.
    Tests network connectivity (DNS, TCP, TLS), validates AMPLS/Private Link
    configurations, checks for known issues that cause silent data loss, and
    sends a test telemetry record to confirm end-to-end pipeline health.

    QUICK START:
      Install-Script -Name Test-AppInsightsTelemetryFlow
      Test-AppInsightsTelemetryFlow -ConnectionString "InstrumentationKey=..."

    WHAT IT CHECKS:
      - DNS resolution for all Azure Monitor endpoints
      - TCP connectivity (port 443) and TLS handshake validation
      - Proxy and TLS inspection detection
      - AMPLS private link IP validation (with Azure login)
      - Known issues: local auth, ingestion sampling, deleted workspace,
        daily cap, diagnostic settings duplicates, workspace transforms
      - End-to-end telemetry ingestion test with KQL verification query
      - Data plane query to verify record arrived with latency breakdown

    All Azure operations are READ-ONLY. The script never modifies any resource.

    MULTI-CLOUD SUPPORT:
    Azure Public, Azure Government, and Azure China (21Vianet) are detected
    automatically from the connection string endpoints. All API calls, DNS
    zones, and troubleshooting links adapt to the detected cloud.

    AZURE CHECKS (automatic):
    If the Az.Accounts module is installed and you have an active Azure login,
    the script automatically performs AMPLS validation, known issue checks, and
    E2E verification against the data plane API. No extra switches needed.
    Use -NetworkOnly to skip all Azure calls (pure network checks only).

    OUTPUT MODES:
    - Default:  Full verbose output with educational explanations
    - Compact:  Progress lines only with focused diagnosis at the end

    WHAT TO EXPECT:
    The script runs non-interactively in ~10-30 seconds for network checks.
    With Azure checks enabled, total time is ~30-90 seconds (includes ~60s
    of polling for E2E verification). Results display as they complete.
    Two report files (JSON + TXT) are saved automatically to -OutputPath.

    CONSENT PROMPTS:
    Before querying Azure resources or sending test telemetry, the script
    prompts for interactive Y/N consent. Use -AutoApprove to bypass prompts
    in CI/CD, scheduled tasks, or other non-interactive environments.
    Use -NetworkOnly or -SkipIngestionTest to skip gated operations entirely.

    PREREQUISITES:
    Network checks require PowerShell 5.1+ (Windows) or PowerShell 7+
    (Linux/macOS). No external modules are needed for network checks.
    Azure resource checks require Az.Accounts and Az.ResourceGraph modules
    (auto-detected at runtime; the script tells you if they're missing).

    Designed to run from:
    - Azure App Service (Kudu/SCM PowerShell console)
    - Azure Function App (Kudu console)
    - Azure VMs / VMSS
    - AKS node or pod (pwsh)
    - On-premises servers
    - Developer workstations
    - Cloud Shell (connected to VNet)

    AZURE API CALLS (read-only):
    When Az modules are available and logged in, the script makes these calls:

    With authentication (Connect-AzAccount required):
      POST management.azure.com  ARG query to find App Insights resource
      POST management.azure.com  ARG query to find AMPLS/private link scopes
      POST management.azure.com  ARG query to find workspace transform DCRs
      GET  management.azure.com  ARM: Read AMPLS scoped resources, access modes
      GET  management.azure.com  ARM: Read private endpoint DNS configurations
      GET  management.azure.com  ARM: Read backend LA workspace (health, cap, access mode)
      GET  management.azure.com  ARM: Read daily cap (PricingPlans API)
      GET  management.azure.com  ARM: Read diagnostic settings
      POST api.applicationinsights.io  Data plane: KQL query for E2E verify

    Without authentication (always runs):
      DNS  Resolve each endpoint hostname via Resolve-DnsName / nslookup
      TCP  Connect to port 443 via System.Net.Sockets.TcpClient
      TLS  Handshake validation via System.Net.Security.SslStream
      POST {ingestion-endpoint}/v2.1/track  Send one test availability record

    Use -Debug to see every request/response in real time.

.PARAMETER ConnectionString
    The Application Insights connection string. If not provided, the script will
    attempt to read from environment variables (APPLICATIONINSIGHTS_CONNECTION_STRING,
    APPINSIGHTS_INSTRUMENTATIONKEY).

.PARAMETER SkipIngestionTest
    Skip the sample telemetry send test. Useful if you only want DNS/TCP/TLS checks.

.PARAMETER OutputPath
    Directory to save diagnostic report files. Defaults to the script's own directory
    (where the .ps1 file lives). Files are auto-named with hostname, optional App Insights
    resource name (when Azure checks discover it), and UTC timestamp:
    AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{yyyy-MM-ddTHHmmssZ}.json + .txt
    When the resource name is not available the segment is omitted:
    AppInsights-Diag_{HOSTNAME}_{yyyy-MM-ddTHHmmssZ}.json + .txt
    Both JSON (machine-parseable) and TXT (human-readable summary) files are always created.

.PARAMETER Compact
    Show compact progress-line output instead of full verbose output with a focused
    diagnosis at the end. Default output is verbose with full tables and educational
    explanations. Use -Compact for a quick overview or when pasting into a support ticket.

.PARAMETER NetworkOnly
    Skip all Azure-authenticated checks (AMPLS validation, known issue checks,
    E2E data plane verification). Only run pure network connectivity tests:
    DNS, TCP, TLS, and the ingestion API test. Use this when you cannot log in
    to Azure or only need to validate network path.

.PARAMETER TenantId
    Azure AD / Entra ID tenant ID (GUID) to authenticate against.
    Required when your account has access to multiple tenants (common at large enterprises).
    If not specified, the script uses the active Azure login context.
    Example: -TenantId "contoso.onmicrosoft.com" or -TenantId "00000000-..."

.PARAMETER AmplsExpectedIps
    A hashtable of endpoint FQDNs to expected private IPs for manual AMPLS validation
    without Azure login. Copy these from Azure Portal > AMPLS > Private Endpoint > DNS.
    Example: @{ "{region}.in.applicationinsights.azure.com" = "10.0.1.5" }

.PARAMETER LookupAmplsIp
    A private IPv4 address to reverse-lookup through Azure Resource Graph to find
    the AMPLS resource and private endpoint that owns it. Use this when DNS resolves
    an Azure Monitor endpoint to an unexpected private IP and you need to identify
    which AMPLS (possibly in another subscription) is overriding DNS.

    The IP must be:
      (a) A valid IPv4 address
      (b) In a private range (RFC1918: 10.x, 172.16-31.x, 192.168.x)
      (c) One of the IPs that was actually resolved during this script's execution
          (DNS resolution step or AMPLS private endpoint validation)

    Requires Azure login (incompatible with -NetworkOnly). The lookup runs under
    the existing Azure resource checks consent -- no additional prompt is shown.

    Example: -LookupAmplsIp "10.0.1.5"

.PARAMETER AutoApprove
    Bypass interactive consent prompts for operations that query Azure resources
    or send test telemetry. Without this switch, the script prompts for Y/N
    confirmation before:
      - Signing in to Azure and querying your resources (AMPLS, known issues)
      - Sending a test telemetry record to your Application Insights resource
    Use -AutoApprove in non-interactive or automated scenarios (CI/CD pipelines,
    App Service Kudu console) where no operator is available to respond.
    Equivalent to answering "Y" to every consent prompt.

.EXAMPLE
    # Full diagnostic (verbose output, Azure checks auto-detected)
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..."

.EXAMPLE
    # Compact output for quick checks
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -Compact

.EXAMPLE
    # Network checks only (no Azure login required)
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -NetworkOnly

.EXAMPLE
    # Multi-tenant: target a specific Entra ID tenant
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -TenantId "contoso.onmicrosoft.com"

.EXAMPLE
    # Auto-detect from environment variables (e.g., in App Service Kudu console)
    .\Test-AppInsightsTelemetryFlow.ps1

.EXAMPLE
    # Show all HTTP traffic for security review
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -Debug

.EXAMPLE
    # Manual AMPLS IP comparison (no Azure login needed)
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." `
        -AmplsExpectedIps @{ "{region}.in.applicationinsights.azure.com" = "10.0.1.5"; "{region}.livediagnostics.monitor.azure.com" = "10.0.1.6" }

.EXAMPLE
    # Save reports to a specific directory
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -OutputPath "C:\diag"

.EXAMPLE
    # Non-interactive / CI: bypass consent prompts
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -AutoApprove

.EXAMPLE
    # Reverse-lookup a private IP to find the AMPLS resource that owns it
    .\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "InstrumentationKey=xxx;..." -LookupAmplsIp "10.0.1.5"

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    System.Int32
        Exit code: 0 (clean), 1 (INFO), 2 (WARNING), or 3 (BLOCKING).

    The script also writes two report files to -OutputPath (default: script directory):
        AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{yyyy-MM-ddTHHmmssZ}.json
        AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{yyyy-MM-ddTHHmmssZ}.txt
            When the App Insights resource name is discovered via Azure checks it is
            included in the filename; otherwise the {RESOURCE} segment is omitted.
            JSON is machine-parseable with all check results; TXT is a human-readable
            console output mirror.

.LINK
    https://github.com/microsoft/appinsights-telemetry-flow

.NOTES
    DISCLAIMER:
    This script is provided as a sample for diagnostic and
    troubleshooting purposes. It is not an official Microsoft
    product and is not supported under any Microsoft standard
    support program or service.
    This script is provided AS IS without warranty of any kind.
    Microsoft further disclaims all implied warranties including,
    without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose. The entire risk
    arising out of the use or performance of this script and its
    documentation remains with you.
    In no event shall Microsoft, its authors, or anyone else
    involved in the creation, production, or delivery of this
    script be liable for any damages whatsoever (including,
    without limitation, damages for loss of business profits,
    business interruption, loss of business information, or other
    pecuniary loss) arising out of the use of or inability to use
    this script or its documentation, even if Microsoft has been
    advised of the possibility of such damages.

    Version: 1.0.0
    Author:  Todd Foust - Azure Monitor App Insights Supportability Engineer
    Source:  https://github.com/microsoft/appinsights-telemetry-flow
    Install: Install-Script -Name Test-AppInsightsTelemetryFlow
    Docs:    https://github.com/microsoft/appinsights-telemetry-flow

    EXIT CODES:
      0 = No issues found (all checks passed, no diagnosis findings)
      1 = INFO findings only (informational items, no action required)
      2 = WARNING detected (telemetry at risk but may still work)
      3 = BLOCKING issue detected (telemetry is broken)
#>

# Suppress PSAvoidUsingWriteHost: The color detection test (line ~278) must call the real
# Write-Host to detect Kudu/no-console environments, and Write-HostLog intentionally uses
# [System.Console]::Write/WriteLine as a fallback when the console handle is invalid.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateLength(1, 1024)]
    [string]$ConnectionString,

    [Parameter(Mandatory=$false)]
    [switch]$SkipIngestionTest,

    [Parameter(Mandatory=$false)]
    [switch]$NetworkOnly,

    [Parameter(Mandatory=$false)]
    [hashtable]$AmplsExpectedIps,

    [Parameter(Mandatory=$false)]
    [switch]$Compact,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [switch]$AutoApprove,

    [Parameter(Mandatory=$false)]
    [string]$LookupAmplsIp
)

#region Configuration
# ============================================================================
# CONFIGURATION
# ============================================================================
$ScriptVersion = "1.0.0"
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# SDL: Enforce TLS 1.2+ for the script's own outbound HTTP calls (Invoke-WebRequest, Invoke-RestMethod).
# Windows PowerShell 5.1 on older .NET Framework versions may default to TLS 1.0/1.1.
# This does NOT affect the SslStream-based TLS diagnostic probes, which specify their protocol explicitly.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- Debug mode ---
# Detect if -Debug was passed, then take control away from $DebugPreference.
# PowerShell's built-in -Debug sets $DebugPreference = 'Inquire', which:
#   (a) prompts "Continue with this operation?" on EVERY Write-Debug call
#   (b) propagates to Az cmdlets, dumping thousands of lines of MSAL/ConfigManager noise
# We capture the intent, suppress the built-in behavior, and use our own output channel.
$scriptDebugMode = $false
if ($PSBoundParameters.ContainsKey('Debug')) {
    $scriptDebugMode = $true
    $DebugPreference = 'SilentlyContinue'   # suppress Az cmdlet debug noise + prompts
}

# --- Debug output truncation ---
# Maximum characters shown for request/response bodies in debug output.
# Set to 0 to disable truncation (dump full bodies).
$DebugTruncateLength = 500

# --- Output and Azure check flags ---
# Full verbose output is the default. -Compact reduces to progress lines.
$VerboseOutput = -not $Compact

# Azure resource checks are attempted by default if Az.Accounts is available.
# -NetworkOnly explicitly skips all Azure resource calls.
$CheckAzure = $false

# --- Resolved IP Registry ---
# Tracks every IP address resolved during script execution (DNS step + AMPLS PE validation).
# Used to validate -LookupAmplsIp: the supplied IP must appear in this registry.
$script:ResolvedIpRegistry = @()

# --- Validate -LookupAmplsIp / -NetworkOnly mutual exclusion ---
if ($LookupAmplsIp -and $NetworkOnly) {
    Write-Warning "-LookupAmplsIp requires Azure resource access and cannot be used with -NetworkOnly."
    Write-Warning "Remove -NetworkOnly to enable AMPLS reverse-lookup, or omit -LookupAmplsIp for network-only checks."
    exit 1
}
$script:AzLoggedIn = $false
$script:AzModulesFound = $false

if (-not $NetworkOnly) {
    try {
        $azMod = Get-Module -Name Az.Accounts -ListAvailable -ErrorAction SilentlyContinue
        if ($azMod) {
            $script:AzModulesFound = $true
            $CheckAzure = $true
            # Check if already logged in (for banner display)
            try {
                Import-Module Az.Accounts -ErrorAction SilentlyContinue
                $ctx = Get-AzContext -ErrorAction SilentlyContinue
                if ($ctx -and $ctx.Account) {
                    $script:AzLoggedIn = $true
                }
            } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        }
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
}

#endregion Configuration

#region Console Color Detection
# ============================================================================
# CONSOLE COLOR DETECTION
# ============================================================================
# Kudu web console, Azure Cloud Shell (classic), and some CI environments don't
# have a real Win32 console handle. Write-Host -ForegroundColor calls
# SetConsoleTextAttribute which throws "The handle is invalid" (0x6).
# Detect this by actually attempting a colored Write-Host with errors set to Stop.

$script:UseColor = $true
$originalEAP = $ErrorActionPreference
try {
    $ErrorActionPreference = "Stop"
    # This is the real test: attempt a colored Write-Host with no visible output.
    # If SetConsoleTextAttribute fails, this throws a terminating error.
    Write-Host "" -ForegroundColor Gray -NoNewline
    $ErrorActionPreference = $originalEAP
}
catch {
    $ErrorActionPreference = $originalEAP
    $script:UseColor = $false
}

# If UseColor is false, the Write-HostLog function (defined before MAIN EXECUTION)
# will route output through [System.Console]::Write/WriteLine instead of the real
# Write-Host cmdlet, avoiding the SetConsoleTextAttribute crash in Kudu/App Service.

#endregion Console Color Detection

#region Helper Functions
# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Header {
    param([string]$Title)
    if (-not $VerboseOutput) { return }
    $line = "=" * 72
    Write-HostLog ""
    Write-HostLog " $line" -ForegroundColor Cyan
    Write-HostLog " $Title" -ForegroundColor Cyan
    Write-HostLog " $line" -ForegroundColor Cyan
}

function Write-HeaderEntry {
    param([string]$Title)
    $line = "=" * 72
    Write-HostLog ""
    Write-HostLog " $line" -ForegroundColor Cyan
    Write-HostLog " $Title" -ForegroundColor Cyan
    Write-HostLog " $line" -ForegroundColor Cyan
}

function Get-MaskedEmail {
    <# Masks an email address for privacy: user@domain.com -> us***@domain.com #>
    param([string]$Email)
    if (-not $Email) { return "<unknown>" }
    if ($Email -notmatch "@") { return $Email.Substring(0, [Math]::Min(2, $Email.Length)) + "***" }
    $parts = $Email.Split("@", 2)
    $local = $parts[0]
    $domain = $parts[1]
    $visible = [Math]::Min(2, $local.Length)
    return $local.Substring(0, $visible) + "***@" + $domain
}

function Write-Result {
    param(
        [string]$Status,  # PASS, FAIL, WARN, INFO, SKIP
        [string]$Check,
        [string]$Detail,
        [string]$Action
    )
    if (-not $VerboseOutput) { return }
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "DarkYellow" }
        "INFO" { "Gray" }
        "SKIP" { "DarkGray" }
        default { "White" }
    }
    $symbol = switch ($Status) {
        "PASS" { if ($script:UseColor) { [char]0x2713 } else { "+" } }  # checkmark or +
        "FAIL" { if ($script:UseColor) { [char]0x2717 } else { "X" } }  # X mark
        "WARN" { "!" }
        "INFO" { "i" }
        "SKIP" { "-" }
        default { "?" }
    }
    Write-HostLog "  [$symbol] " -ForegroundColor $color -NoNewline
    Write-HostLog "$Check" -ForegroundColor White
    if ($Detail) {
        Write-HostLog "      $Detail" -ForegroundColor Gray
    }
    if ($Action -and $Status -in @("FAIL","WARN","INFO")) {
        Write-HostLog "      ACTION: $Action" -ForegroundColor Yellow
    }
}

function Write-DetailHost {
    <# Writes to host only when verbose output is active (not -Compact). Accepts same params as Write-HostLog. #>
    param(
        [string]$Object = "",
        [string]$ForegroundColor = "White",
        [switch]$NoNewline
    )
    if (-not $VerboseOutput) { return }
    if ($NoNewline) {
        Write-HostLog $Object -ForegroundColor $ForegroundColor -NoNewline
    } else {
        Write-HostLog $Object -ForegroundColor $ForegroundColor
    }
}

$script:progressStartPending = ""   # Name of the in-progress test (compact non-debug only)

function Write-ProgressStart {
    <#
    .SYNOPSIS
        Prints the leading portion of a progress line ("  Name ............... ") with no newline,
        giving the user visual feedback that a test is running. Only outputs in compact mode
        without debug enabled; in verbose/debug modes, enough output already streams to indicate
        progress. Call Write-ProgressLine to complete the line with status and summary.

        If a previous start is still pending (the test had nothing to report), the old
        partial line is silently overwritten by the new one via carriage return.
    #>
    param([string]$Name)

    # Only emit in compact mode without debug (verbose/debug have continuous output already)
    if ($VerboseOutput -or $scriptDebugMode) {
        $script:progressStartPending = $Name
        return
    }

    # If there's already a pending start on the line (previous test had nothing to report),
    # overwrite it with carriage return before printing the new start
    if ($script:progressStartPending) {
        $clearWidth = 80
        Write-HostLog "`r$(' ' * $clearWidth)`r" -NoNewline
    }

    $totalWidth = 36
    $dots = $totalWidth - $Name.Length
    if ($dots -lt 3) { $dots = 3 }
    $leader = " " + ("." * $dots) + " "

    Write-HostLog "  $Name" -NoNewline -ForegroundColor White
    Write-HostLog $leader -NoNewline -ForegroundColor DarkGray

    $script:progressStartPending = $Name
}

function Write-ProgressLine {
    <#
    .SYNOPSIS
        Prints a compact progress line: "  Check Name ............... STATUS  summary"
        Always prints regardless of output mode. If Write-ProgressStart was called earlier
        with the same name (compact non-debug only), appends just the status and summary
        to complete the pending line. If the name differs, uses carriage return to overwrite
        the pending label before printing the full new line.
    #>
    param(
        [string]$Name,
        [string]$Status,   # OK, WARN, INFO, FAIL, SKIP
        [string]$SummaryText
    )

    $statusColor = switch ($Status) {
        "OK"    { "Green" }
        "WARN"  { "DarkYellow" }
        "INFO"  { "Yellow" }
        "FAIL"  { "Red" }
        "SKIP"  { "DarkGray" }
        default { "White" }
    }

    $statusWidth = 5
    $displayStatus = $Status.PadRight($statusWidth)

    $totalWidth = 36
    $dots = $totalWidth - $Name.Length
    if ($dots -lt 3) { $dots = 3 }
    $leader = " " + ("." * $dots) + " "

    if ($script:progressStartPending) {
        if ($script:progressStartPending -eq $Name -and -not $VerboseOutput -and -not $scriptDebugMode) {
            # Same name, compact non-debug: just append status + summary to the pending line
            Write-HostLog $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-HostLog "  $SummaryText" -ForegroundColor Gray
        } elseif (-not $VerboseOutput -and -not $scriptDebugMode) {
            # Different name, compact non-debug: clear the pending label then print new full line
            $clearWidth = 80
            Write-HostLog "`r$(' ' * $clearWidth)`r" -NoNewline
            Write-HostLog "  $Name" -NoNewline -ForegroundColor White
            Write-HostLog $leader -NoNewline -ForegroundColor DarkGray
            Write-HostLog $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-HostLog "  $SummaryText" -ForegroundColor Gray
        } else {
            # Verbose or debug mode: start wasn't printed, just print the full line
            Write-HostLog "  $Name" -NoNewline -ForegroundColor White
            Write-HostLog $leader -NoNewline -ForegroundColor DarkGray
            Write-HostLog $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-HostLog "  $SummaryText" -ForegroundColor Gray
        }
        $script:progressStartPending = ""
    } else {
        # No pending start: print the full progress line normally
        Write-HostLog "  $Name" -NoNewline -ForegroundColor White
        Write-HostLog $leader -NoNewline -ForegroundColor DarkGray
        Write-HostLog $displayStatus -NoNewline -ForegroundColor $statusColor
        Write-HostLog "  $SummaryText" -ForegroundColor Gray
    }
}

# Diagnosis collector: accumulates issues found during checks
$script:diagnosisItems = @()
$script:pipelineBroken = $false    # Set to $true when backend workspace is deleted or subscription suspended
$script:ingestionBlockedPreFlight = $false  # Set to $true when network access assessment detects ingestion BLOCKED
$script:diagSettingsExportCount = 0  # Count of Diagnostic Settings exporting logs to LA (set by Known Issue #6)

function Add-Diagnosis {
    <#
    .SYNOPSIS
        Adds an issue to the diagnosis collector for display in the final summary.
    .PARAMETER Summary
        One-liner for the summary table at the top of the diagnosis section.
        If omitted, the Title is used as the summary line.
    .PARAMETER Portal
        Azure Portal navigation path for the fix (e.g., "App Insights > Network Isolation").
        Shown as "-> Portal:" in the WHAT TO DO section. Omit if no portal action applies.
    #>
    param(
        [ValidateSet("BLOCKING","WARNING","INFO")]
        [string]$Severity,
        [string]$Title,
        [string]$Description,
        [string]$Fix,
        [string]$Portal,
        [string]$Summary,
        [string]$Docs
    )
    $script:diagnosisItems += @{
        Severity = $Severity
        Title = $Title
        Description = $Description
        Fix = $Fix
        Portal = $Portal
        Summary = if ($Summary) { $Summary } else { $Title }
        Docs = $Docs
    }
}

function Get-ConsoleWidth {
    <# Returns the usable console width for word-wrapping, capped at 120 to keep
       diagnostic text readable even on ultra-wide consoles. Falls back to 119. #>
    $w = 0
    try { $w = [Console]::WindowWidth - 1 } catch { $null = $_ }
    if ($w -le 0) { $w = 119 }
    if ($w -gt 120) { $w = 120 }
    return $w
}

function Write-Wrapped {
    <#
    .SYNOPSIS
        Word-wraps text to the console width with a consistent left indent.
        First line uses $FirstPrefix, continuation lines use $ContPrefix.
        If both are omitted, $Indent spaces are used for all lines.
    #>
    param(
        [string]$Text,
        [int]$Indent = 5,
        [string]$FirstPrefix,
        [string]$ContPrefix,
        [string]$ForegroundColor = 'Gray'
    )
    if (-not $FirstPrefix) { $FirstPrefix = ' ' * $Indent }
    if (-not $ContPrefix)  { $ContPrefix  = ' ' * $FirstPrefix.Length }

    $maxWidth = Get-ConsoleWidth
    $available = $maxWidth - $ContPrefix.Length
    if ($available -lt 30) {
        # Console too narrow for wrapping -- just dump it raw
        Write-HostLog "$FirstPrefix$Text" -ForegroundColor $ForegroundColor
        return
    }

    $words = $Text -split ' '
    $line = ''
    $isFirst = $true
    foreach ($word in $words) {
        if ($line.Length -eq 0) {
            $line = $word
        } elseif (($line.Length + 1 + $word.Length) -le $available) {
            $line += " $word"
        } else {
            $prefix = if ($isFirst) { $FirstPrefix } else { $ContPrefix }
            Write-HostLog "$prefix$line" -ForegroundColor $ForegroundColor
            $line = $word
            $isFirst = $false
        }
    }
    if ($line.Length -gt 0) {
        $prefix = if ($isFirst) { $FirstPrefix } else { $ContPrefix }
        Write-HostLog "$prefix$line" -ForegroundColor $ForegroundColor
    }
}

function Get-Timestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

# ---- Console output capture via Write-HostLog ----
# Start-Transcript doesn't handle -NoNewline properly (each Write-Host call
# becomes a separate line), so Write-HostLog wraps Write-Host with a function that
# writes to console AND captures to a StringBuilder with correct line handling.
$script:consoleLog = [System.Text.StringBuilder]::new()
$script:consoleLogPending = ""

function Write-HostLog {
    param(
        [Parameter(Position=0)]
        [object]$Object = "",
        [switch]$NoNewline,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [string]$Separator
    )

    # Route to console: real Write-Host (color) or System.Console (Kudu/no-color)
    if ($script:UseColor) {
        $params = @{ Object = $Object }
        if ($NoNewline) { $params.NoNewline = $true }
        if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $params.ForegroundColor = $ForegroundColor }
        if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $params.BackgroundColor = $BackgroundColor }
        Microsoft.PowerShell.Utility\Write-Host @params
    } else {
        # Kudu/App Service: Write-Host crashes on SetConsoleTextAttribute.
        # Use [System.Console] which writes to stdout without touching console attributes.
        $text = if ($null -ne $Object) { "$Object" } else { "" }
        if ($NoNewline) {
            [System.Console]::Write($text)
        } else {
            [System.Console]::WriteLine($text)
        }
    }

    # Capture to log (color stripped, line breaks preserved)
    if ($NoNewline) {
        $script:consoleLogPending += [string]$Object
    } else {
        [void]$script:consoleLog.AppendLine($script:consoleLogPending + [string]$Object)
        $script:consoleLogPending = ""
    }
}

function Request-UserConsent {
    [CmdletBinding()]
    param(
        [string]$PromptTitle,
        [string[]]$PromptLines,
        [string]$SkipHint,
        [string]$PromptQuestion = "Proceed? [Y/N]",
        [switch]$RequiresAzureLogin   # When set, the PaaS non-interactive check applies (can't az login from Kudu)
    )

    # -AutoApprove: automatic YES (no prompt shown)
    if ($AutoApprove) { return $true }

    # Non-interactive PaaS check (only for Azure login-dependent operations)
    # Kudu SSH is interactive for ingestion tests but can't az login.
    if ($RequiresAzureLogin -and $script:IsNonInteractiveEnv) {
        Write-HostLog ""
        Write-HostLog "  CONSENT REQUIRED: $PromptTitle" -ForegroundColor Yellow
        Write-HostLog "  Skipped -- non-interactive environment detected (Azure login unavailable)." -ForegroundColor Gray
        Write-HostLog "  Use -AutoApprove to enable in automated environments." -ForegroundColor Gray
        Write-HostLog ""
        return $false
    }

    # Stdin/console availability check
    # On Windows Kudu web console, the Win32 console handle is invalid -- [Console]::IsInputRedirected
    # returns $true and Read-Host throws "The handle is invalid". Linux Kudu SSH provides a real PTY
    # where bash read works, but Windows Kudu does not support interactive input in PowerShell.
    try {
        if ([Console]::IsInputRedirected) {
            Write-HostLog ""
            Write-HostLog "  CONSENT REQUIRED: $PromptTitle" -ForegroundColor Yellow
            if ($script:IsNonInteractiveEnv) {
                Write-HostLog "  Skipped -- this console does not support interactive input." -ForegroundColor Gray
                Write-HostLog "  Re-run with -AutoApprove to proceed without prompts." -ForegroundColor Gray
            } else {
                Write-HostLog "  Skipped -- stdin is not a terminal (piped/redirected)." -ForegroundColor Gray
                Write-HostLog "  Use -AutoApprove to enable in non-interactive environments." -ForegroundColor Gray
            }
            Write-HostLog ""
            return $false
        }
    } catch {
        # [Console]::IsInputRedirected not available -- assume interactive
        $null = $_
    }

    # Interactive: show consent box and prompt Y/N
    Write-HostLog ""
    Write-HostLog "  ========================================================================" -ForegroundColor DarkCyan
    Write-HostLog "  $PromptTitle" -ForegroundColor Cyan
    Write-HostLog "  ========================================================================" -ForegroundColor DarkCyan
    foreach ($promptLine in $PromptLines) {
        Write-HostLog "  $promptLine" -ForegroundColor Gray
    }
    Write-HostLog ""
    Write-HostLog "  $SkipHint" -ForegroundColor DarkGray
    Write-HostLog "  ========================================================================" -ForegroundColor DarkCyan
    Write-HostLog ""
    try {
        $response = Read-Host "  $PromptQuestion"
    } catch {
        # Read-Host failed (e.g., Windows Kudu web console -- Win32 console handle invalid)
        Write-HostLog ""
        Write-HostLog "  Skipped -- unable to read input (console handle unavailable)." -ForegroundColor Gray
        Write-HostLog "  Re-run with -AutoApprove to proceed without prompts." -ForegroundColor Gray
        Write-HostLog ""
        return $false
    }
    Write-HostLog ""
    return ($response -match '^[Yy]')
}

#endregion Helper Functions

#region Debug Helpers
# ============================================================================
# DEBUG HELPERS (-Debug mode)
# ============================================================================
# When -Debug is passed, these functions log outbound HTTP requests and
# responses so customers can see exactly what API calls the script makes.
# We use Write-HostLog (not Write-Debug) to avoid $DebugPreference='Inquire'
# prompting and to prevent Az cmdlet debug noise from flooding output.

function Write-DebugRequest {
    param(
        [string]$Method,
        [string]$Url,
        [string]$Body = ""
    )
    if (-not $scriptDebugMode) { return }
    Write-HostLog "  [DEBUG] >>> $Method $Url" -ForegroundColor Yellow
    if ($Body) {
        $preview = if ($DebugTruncateLength -gt 0 -and $Body.Length -gt $DebugTruncateLength) { $Body.Substring(0, $DebugTruncateLength) + "... ($($Body.Length) chars total)" } else { $Body }
        Write-HostLog "  [DEBUG] >>> Body: $preview" -ForegroundColor Yellow
    }
}

function Write-DebugResponse {
    param(
        [string]$Status,
        [string]$Body = ""
    )
    if (-not $scriptDebugMode) { return }
    Write-HostLog "  [DEBUG] <<< $Status" -ForegroundColor Yellow
    if ($Body) {
        $preview = if ($DebugTruncateLength -gt 0 -and $Body.Length -gt $DebugTruncateLength) { $Body.Substring(0, $DebugTruncateLength) + "... ($($Body.Length) chars total)" } else { $Body }
        Write-HostLog "  [DEBUG] <<< Body: $preview" -ForegroundColor Yellow
    }
}

function Write-DebugAzGraph {
    param([string]$Query)
    if (-not $scriptDebugMode) { return }
    Write-HostLog "  [DEBUG] >>> POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" -ForegroundColor Yellow
    Write-HostLog "  [DEBUG] >>> ARG Query: $Query" -ForegroundColor Yellow
}

function Write-DebugAzRest {
    param(
        [string]$Method,
        [string]$Path
    )
    if (-not $scriptDebugMode) { return }
    Write-HostLog "  [DEBUG] >>> $Method https://management.azure.com$Path" -ForegroundColor Yellow
}

function Write-ScriptDebug {
    param([string]$Message)
    if (-not $scriptDebugMode) { return }
    Write-HostLog "  [DEBUG] $Message" -ForegroundColor Yellow
}

#endregion Debug Helpers

#region Parse Connection String
# ============================================================================
# PARSE CONNECTION STRING
# ============================================================================

function ConvertFrom-ConnectionString {
    param([string]$ConnStr)

    $parts = @{}
    foreach ($segment in $ConnStr.Split(';')) {
        if ($segment -match '^\s*([^=]+)=(.+)\s*$') {
            $parts[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $parts
}

function Test-InstrumentationKeyFormat {
    <#
    .SYNOPSIS
        Validates that an InstrumentationKey is a well-formed GUID.
        Prevents KQL/ARG injection via crafted connection strings (SDL 10027/10031).
    #>
    param([string]$Key)
    return ($Key -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Test-AzureMonitorEndpoint {
    <#
    .SYNOPSIS
        Validates that an endpoint URL is a legitimate Azure Monitor hostname.
        Blocks SSRF attacks via crafted connection strings (SDL 10107).
    .DESCRIPTION
        Enforces:
          - HTTPS scheme required
          - Hostname must match known Azure Monitor domain patterns
          - Blocks loopback, link-local, RFC1918, IMDS, WireServer, and IPv6 local addresses
    #>
    param(
        [string]$EndpointUrl,
        [string]$EndpointName
    )

    # Must be a parseable URI with https scheme
    $uri = $null
    try {
        $uri = [System.Uri]::new($EndpointUrl)
    }
    catch {
        return "$EndpointName is not a valid URI: $EndpointUrl"
    }

    if ($uri.Scheme -ne 'https') {
        return "$EndpointName must use HTTPS (got '$($uri.Scheme)'): $EndpointUrl"
    }

    $hostname = $uri.Host.ToLowerInvariant()

    # Block IP-based hostnames (prevents SSRF to IMDS, WireServer, loopback, RFC1918, link-local)
    $ipAddr = $null
    if ([System.Net.IPAddress]::TryParse($hostname, [ref]$ipAddr)) {
        return "$EndpointName must use a hostname, not an IP address: $EndpointUrl"
    }

    # Block localhost and common internal hostnames
    if ($hostname -eq 'localhost' -or $hostname -match '^\.internal$' -or $hostname -match '^\.local$') {
        return "$EndpointName points to a local/internal host: $EndpointUrl"
    }

    # Allowlist of legitimate Azure Monitor endpoint domain patterns
    $allowedPatterns = @(
        '\.in\.applicationinsights\.azure\.(com|us|cn)$',     # Regional ingestion
        '\.applicationinsights\.azure\.(com|us|cn)$',         # App Insights services
        '\.monitor\.azure\.(com|us|cn)$',                     # Azure Monitor services
        '\.services\.visualstudio\.com$',                      # Legacy VS endpoints
        '\.applicationinsights\.(io|us)$'                      # Data plane API
    )

    $isAllowed = $false
    foreach ($pattern in $allowedPatterns) {
        if ($hostname -match $pattern) {
            $isAllowed = $true
            break
        }
    }

    if (-not $isAllowed) {
        return "$EndpointName hostname '$hostname' is not a recognized Azure Monitor domain. If this is a legitimate custom endpoint, verify the connection string in Azure Portal."
    }

    return $null  # Valid
}

#endregion Parse Connection String

#region Main Diagnostic Functions
# ============================================================================
# MAIN DIAGNOSTIC FUNCTIONS
# ============================================================================

function Get-DnsFailureInfo {
    <#
    .SYNOPSIS
        Classifies a DNS resolution exception into a short label, detail message, and action.
        Inspects the full exception chain for a SocketException and categorises the error
        so callers can surface the specific failure mode (NXDOMAIN, timeout, refused, etc.).
    .OUTPUTS
        Hashtable with keys: Label (short column-friendly tag), Detail (one-line explanation),
        Action (recommended next step).
    #>
    param(
        [System.Exception]$Exception,
        [string]$Hostname,
        [int]$DurationMs = 0
    )

    $durationTag = ""
    if ($DurationMs -gt 0) { $durationTag = " [${DurationMs}ms]" }

    $info = @{
        Label  = "(DNS error)"
        Detail = "DNS resolution failed: $($Exception.Message)"
        Action = "Verify DNS server configuration. If using custom DNS, ensure it can resolve Azure Monitor hostnames. If using AMPLS, verify private DNS zones are linked to your VNet."
    }

    # Walk the exception chain to find a SocketException
    $sockEx = $null
    $current = $Exception
    while ($current) {
        if ($current -is [System.Net.Sockets.SocketException]) { $sockEx = $current }
        $current = $current.InnerException
    }

    if ($sockEx) {
        switch ($sockEx.SocketErrorCode) {
            'HostNotFound' {
                $info.Label  = "(NXDOMAIN)"
                $info.Detail = "DNS NXDOMAIN: '$Hostname' -- the DNS server could not find this domain${durationTag}"
                $info.Action = "The DNS server was reachable and responded, but has no record for this hostname. Verify the FQDN is spelled correctly. If using AMPLS, ensure the private DNS zones (privatelink.monitor.azure.com / privatelink.applicationinsights.azure.com) contain A records for this FQDN."
            }
            'TryAgain' {
                $info.Label  = "(DNS SERVFAIL)"
                $info.Detail = "DNS SERVFAIL: temporary server failure resolving '$Hostname'${durationTag}"
                $info.Action = "The DNS server returned a temporary failure (SERVFAIL). Retry in a few minutes. If persistent, check DNS server health, forwarder configuration, and conditional-forwarding rules."
            }
            'TimedOut' {
                $info.Label  = "(DNS timeout)"
                $info.Detail = "DNS timeout: no response from DNS server for '$Hostname'${durationTag}"
                $info.Action = "The DNS query timed out with no response. Possible causes: (1) firewall/NSG blocking UDP/TCP port 53 outbound, (2) the DNS server is unreachable or down, (3) a network device is swallowing DNS response packets."
            }
            'ConnectionRefused' {
                $info.Label  = "(DNS refused)"
                $info.Detail = "DNS connection refused for '$Hostname'${durationTag}"
                $info.Action = "The connection to the DNS server was actively refused. Verify the DNS server address is correct, the service is running, and port 53 is not blocked by a firewall."
            }
            'ConnectionReset' {
                $info.Label  = "(DNS conn reset)"
                $info.Detail = "DNS connection reset for '$Hostname'${durationTag}"
                $info.Action = "The connection to the DNS server was reset (TCP RST). A firewall, NSG, or network virtual appliance may be terminating DNS traffic before it reaches the server."
            }
            'NetworkUnreachable' {
                $info.Label  = "(DNS no route)"
                $info.Detail = "DNS server unreachable for '$Hostname'${durationTag}"
                $info.Action = "No network route to the DNS server. Check routing tables, VNet peering, and whether the DNS server IP is reachable from this machine."
            }
            default {
                $info.Label  = "(DNS error)"
                $info.Detail = "DNS resolution failed for '$Hostname': $($sockEx.Message) (SocketError: $($sockEx.SocketErrorCode))${durationTag}"
                $info.Action = "Unexpected DNS error ($($sockEx.SocketErrorCode)). Verify DNS server configuration and network connectivity."
            }
        }
    }

    return $info
}

function Test-DnsResolution {
    param([string]$Hostname)

    $result = @{
        Hostname = $Hostname
        Status = "FAIL"
        IpAddresses = @()
        IsPrivateIp = $false
        Detail = ""
        Action = ""
        DurationMs = 0
        DnsFailureLabel = ""
    }

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dns = [System.Net.Dns]::GetHostAddresses($Hostname)
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds

        # Force array context for PS 5.1 compatibility
        $ipList = @()
        foreach ($addr in $dns) {
            $ipList += $addr.IPAddressToString
        }
        $result.IpAddresses = $ipList

        if ($ipList.Count -gt 0) {
            $result.Status = "PASS"
            $firstIp = $ipList[0]

            # Check if private IP (RFC1918 / link-local)
            if ($firstIp -match '^10\.' -or $firstIp -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or $firstIp -match '^192\.168\.') {
                $result.IsPrivateIp = $true
                $result.Detail = "$Hostname -> $firstIp (Private IP - AMPLS/Private Endpoint detected) [$($result.DurationMs)ms]"
            } else {
                $result.Detail = "$Hostname -> $firstIp (Public IP) [$($result.DurationMs)ms]"
            }
        } else {
            $result.Detail = "DNS resolved but returned no addresses"
            $result.Action = "Check DNS configuration. If using AMPLS, verify private DNS zones for $domainMonitor and $domainAppInsights exist and contain the correct A records."
        }
    }
    catch {
        if ($sw) { $sw.Stop(); $result.DurationMs = $sw.ElapsedMilliseconds }
        $result.Status = "FAIL"
        $failInfo = Get-DnsFailureInfo -Exception $_.Exception -Hostname $Hostname -DurationMs $result.DurationMs
        $result.DnsFailureLabel = $failInfo.Label
        $result.Detail = $failInfo.Detail
        $result.Action = $failInfo.Action
    }

    return $result
}

function Get-DnsServerAddress {
    # Get the DNS servers being used by this machine
    $dnsServers = @()

    try {
        if ($IsWindows -or $env:OS -eq "Windows_NT") {
            # Windows: Try Get-DnsClientServerAddress first (PowerShell 5.1+)
            try {
                $adapters = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.ServerAddresses.Count -gt 0 }
                foreach ($adapter in $adapters) {
                    foreach ($server in $adapter.ServerAddresses) {
                        if ($server -and $dnsServers -notcontains $server) {
                            $dnsServers += $server
                        }
                    }
                }
            }
            catch {
                # Fallback: Parse ipconfig /all
                $ipconfig = ipconfig /all 2>$null
                if ($ipconfig) {
                    $inDnsSection = $false
                    foreach ($line in $ipconfig) {
                        if ($line -match 'DNS Servers.*:\s*(\d+\.\d+\.\d+\.\d+)') {
                            $dnsServers += $Matches[1]
                            $inDnsSection = $true
                        }
                        elseif ($inDnsSection -and $line -match '^\s+(\d+\.\d+\.\d+\.\d+)') {
                            $dnsServers += $Matches[1]
                        }
                        elseif ($inDnsSection -and $line -notmatch '^\s+\d') {
                            $inDnsSection = $false
                        }
                    }
                }
            }
        }
        else {
            # Linux/macOS: Parse /etc/resolv.conf
            if (Test-Path "/etc/resolv.conf") {
                $resolv = Get-Content "/etc/resolv.conf" -ErrorAction SilentlyContinue
                foreach ($line in $resolv) {
                    if ($line -match '^nameserver\s+(\d+\.\d+\.\d+\.\d+)') {
                        $dnsServers += $Matches[1]
                    }
                }
            }
        }
    }
    catch {
        # Ignore errors, we'll just not show DNS servers
        Write-ScriptDebug "Suppressed: $($_.Exception.Message)"
    }

    # Deduplicate
    $unique = @()
    foreach ($s in $dnsServers) {
        if ($unique -notcontains $s) { $unique += $s }
    }

    return $unique
}

function Test-TcpConnectivity {
    param(
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutMs = 5000
    )

    $result = @{
        Hostname = $Hostname
        Port = $Port
        Status = "FAIL"
        Detail = ""
        Action = ""
        DurationMs = 0
    }

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcp.ConnectAsync($Hostname, $Port)
        $completed = $connectTask.Wait($TimeoutMs)
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds

        if ($completed -and $tcp.Connected) {
            $result.Status = "PASS"
            $result.Detail = "TCP connection to ${Hostname}:${Port} succeeded [$($result.DurationMs)ms]"
            if ($result.DurationMs -gt 3000) {
                $result.Status = "INFO"
                $result.Detail += " (HIGH LATENCY)"
                $result.Action = "Connection succeeded but latency is high. Check network path, proxy, or firewall inspection rules that may add delay."
            }
        } else {
            $result.Detail = "TCP connection to ${Hostname}:${Port} timed out after ${TimeoutMs}ms"
            $result.Action = "Verify outbound port 443 is open in NSG, firewall, and proxy rules. If using AMPLS, verify the private endpoint is healthy and has an approved connection status."
        }
        $tcp.Dispose()
    }
    catch {
        $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        $result.Detail = "TCP connection to ${Hostname}:${Port} failed: $innerMsg"
        $result.Action = "Verify outbound port 443 is allowed. Check NSG rules, Azure Firewall application rules, UDR routing, and any network virtual appliance in the path."
    }

    return $result
}

function Test-TlsHandshake {
    param(
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutMsCurrent = 10000,   # 10s for TLS 1.2/1.3 (must succeed)
        [int]$TimeoutMsDeprecated = 3000  # 3s for TLS 1.0/1.1 (MITM detection only)
    )

    $result = @{
        Hostname = $Hostname
        Status = "FAIL"
        TlsVersions = @{}
        SupportedVersions = @()
        FailedDetails = @{}
        NegotiatedDefault = ""
        CertSubject = ""
        CertIssuer = ""
        CertExpiry = ""
        Detail = ""
        Action = ""
        TlsInspectionDetected = $false
        DeprecatedAzureEdge = $false  # True when deprecated accepted but cert is Microsoft-issued (Azure edge, not MITM)
        DeprecatedAccepted = @()   # TLS 1.0/1.1 that succeeded (MITM indicator)
    }

    # Define TLS versions to test
    # Deprecated versions are tested with a short timeout for MITM/downgrade detection.
    # If a deprecated version succeeds, something in the network path is terminating TLS
    # before traffic reaches Azure Monitor (which rejects TLS < 1.2).
    $tlsVersions = @(
        @{ Name = "TLS 1.0"; Value = [System.Security.Authentication.SslProtocols]::Tls; Deprecated = $true },
        @{ Name = "TLS 1.1"; Value = [System.Security.Authentication.SslProtocols]::Tls11; Deprecated = $true },
        @{ Name = "TLS 1.2"; Value = [System.Security.Authentication.SslProtocols]::Tls12; Deprecated = $false }
    )

    # Try to add TLS 1.3 if available (requires .NET 4.8+ or PowerShell 7+)
    try {
        $tls13Value = [System.Security.Authentication.SslProtocols]::Tls13
        $tlsVersions += @{ Name = "TLS 1.3"; Value = $tls13Value; Deprecated = $false }
    }
    catch {
        # TLS 1.3 not available on this .NET version
        Write-ScriptDebug "Suppressed: $($_.Exception.Message)"
    }

    $certCaptured = $false
    $supportedVersions = @()
    $failedVersions = @()
    $failedDetails = @{}  # Capture WHY each version failed

    foreach ($tlsVer in $tlsVersions) {
        $timeoutMs = if ($tlsVer.Deprecated) { $TimeoutMsDeprecated } else { $TimeoutMsCurrent }

        try {
            # Async TCP connect with timeout (no callback, safe for PS 5.1)
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcp.ConnectAsync($Hostname, $Port)
            $tcpCompleted = $connectTask.Wait($timeoutMs)

            if (-not $tcpCompleted -or -not $tcp.Connected) {
                throw [System.TimeoutException]::new("TCP connect timed out after ${timeoutMs}ms")
            }

            # Set socket-level timeouts so the synchronous TLS handshake won't hang.
            # This is critical for deprecated TLS versions (short timeout for MITM detection)
            # and provides a safety net for current versions too.
            $tcp.SendTimeout = $timeoutMs
            $tcp.ReceiveTimeout = $timeoutMs

            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {
                param($senderObj, $cert, $chain, $errors)
                # Required by RemoteCertificateValidationCallback delegate signature
                $null = $senderObj; $null = $chain; $null = $errors
                # Capture cert info on first successful connection
                if (-not $certCaptured -and $cert) {
                    $result.CertSubject = $cert.Subject
                    $result.CertIssuer = $cert.Issuer
                    $result.CertExpiry = $cert.GetExpirationDateString()
                    $certCaptured = $true
                }
                return $true  # Accept all for diagnostic purposes
            }.GetNewClosure())

            # Synchronous TLS handshake -- MUST be synchronous because the certificate
            # validation callback is a PowerShell scriptblock bound to the current runspace.
            # AuthenticateAsClientAsync invokes the callback on a thread pool thread, which
            # deadlocks in PS 5.1 because the runspace is blocked on .Wait().
            $ssl.AuthenticateAsClient($Hostname, $null, $tlsVer.Value, $false)

            $supportedVersions += $tlsVer.Name
            $result.TlsVersions[$tlsVer.Name] = "SUPPORTED"

            if ($tlsVer.Deprecated) {
                $result.DeprecatedAccepted += $tlsVer.Name
            }

            $ssl.Dispose()
            $tcp.Dispose()
        }
        catch {
            $failedVersions += $tlsVer.Name
            $result.TlsVersions[$tlsVer.Name] = "NOT_NEGOTIATED"
            $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            $failedDetails[$tlsVer.Name] = $innerMsg

            # Clean up on failure
            try { $ssl.Dispose() } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
            try { $tcp.Dispose() } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        }
    }

    # Store failure details for verbose output
    $result.FailedDetails = $failedDetails

    # Additional test: Let the OS negotiate the best version (this is what real SDKs do)
    # SslProtocols.None = "let the OS decide" -- shows what would actually happen in production
    $result.NegotiatedDefault = ""
    try {
        $tcp2 = New-Object System.Net.Sockets.TcpClient
        $connectTask2 = $tcp2.ConnectAsync($Hostname, $Port)
        if ($connectTask2.Wait($TimeoutMsCurrent) -and $tcp2.Connected) {
            $tcp2.SendTimeout = $TimeoutMsCurrent
            $tcp2.ReceiveTimeout = $TimeoutMsCurrent
            $ssl2 = New-Object System.Net.Security.SslStream($tcp2.GetStream(), $false, {
                param($s, $c, $ch, $e) $null = $s; $null = $c; $null = $ch; $null = $e; return $true
            })
            # Synchronous -- same runspace safety as the per-version tests above
            $ssl2.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::None, $false)
            $result.NegotiatedDefault = $ssl2.SslProtocol.ToString()
            $ssl2.Dispose()
        }
        $tcp2.Dispose()
    }
    catch {
        # If even "let the OS decide" fails, something is seriously wrong
        try { $ssl2.Dispose() } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        try { $tcp2.Dispose() } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
    }

    # Build summary
    # Current versions (1.2, 1.3) -- always relevant
    $currentSupported = @($supportedVersions | Where-Object { $_ -match "1\.[23]" })
    $currentSupportedStr = if ($currentSupported.Count -gt 0) { ($currentSupported -join ", ") } else { "NONE" }

    # Legacy -- for full version lists
    $supportedStr = if ($supportedVersions.Count -gt 0) { ($supportedVersions -join ", ") } else { "NONE" }
    $failedStr = if ($failedVersions.Count -gt 0) { ($failedVersions -join ", ") } else { "NONE" }

    # Determine overall status
    $hasTls12 = $result.TlsVersions["TLS 1.2"] -eq "SUPPORTED"
    $hasTls13 = $result.TlsVersions["TLS 1.3"] -eq "SUPPORTED"
    $hasTls10 = $result.TlsVersions["TLS 1.0"] -eq "SUPPORTED"
    $hasTls11 = $result.TlsVersions["TLS 1.1"] -eq "SUPPORTED"

    if ($hasTls12 -or $hasTls13) {
        $result.Status = "PASS"
        $defaultNote = if ($result.NegotiatedDefault) { " | Default: $($result.NegotiatedDefault)" } else { "" }
        $result.Detail = "Supported: $currentSupportedStr$defaultNote"

        if ($result.CertSubject) {
            $result.Detail += " | Cert: $($result.CertSubject)"
        }

        # Flag if deprecated protocols were accepted (MITM/downgrade indicator)
        # Action text is set after the TLS inspection check below (cert-aware)
        if ($hasTls10 -or $hasTls11) {
            $depList = ($result.DeprecatedAccepted -join ", ")
            $result.Status = "INFO"
            $result.Detail += " | [SECURITY] Deprecated protocol(s) accepted: $depList -- possible MITM/proxy downgrade"
        }
    }
    elseif ($hasTls10 -or $hasTls11) {
        # Only deprecated versions work -- likely a proxy downgrading the connection
        $result.Status = "INFO"
        $result.Detail = "Only deprecated TLS versions negotiated: $supportedStr"
        $result.Action = "This client could only negotiate TLS 1.0/1.1 which are deprecated. Azure Monitor requires TLS 1.2+. This typically indicates a proxy/firewall is downgrading the TLS connection. Check: https://learn.microsoft.com/azure/azure-monitor/best-practices-security#secure-logs-data-in-transit"
    }
    else {
        # Nothing works
        $result.Status = "FAIL"
        $result.Detail = "Could not negotiate any TLS version ($failedStr)"
        $result.Action = "TLS handshake failed for all protocol versions. Common causes: (1) Firewall/proxy blocking or modifying TLS traffic, (2) Self-signed or untrusted CA certificate, (3) Network appliance terminating TLS. Ensure outbound HTTPS to Azure Monitor endpoints is unmodified."
    }

    # Check for certificate interception (MITM / TLS inspection proxy)
    # The Issuer is the most reliable indicator -- legitimate Azure certs are issued by Microsoft/DigiCert
    $certToCheck = if ($result.CertIssuer) { $result.CertIssuer } else { $result.CertSubject }
    if ($certToCheck -and $certToCheck -notmatch "microsoft|azure|visualstudio|msedge|digicert|Baltimore|DigiCert|windows\.net") {
        $result.TlsInspectionDetected = $true
        if ($result.Status -eq "PASS") { $result.Status = "INFO" }

        # Try to identify the specific proxy/firewall product
        $proxyProduct = "Unknown proxy/firewall"
        if ($certToCheck -match "Zscaler")       { $proxyProduct = "Zscaler" }
        elseif ($certToCheck -match "Palo Alto")  { $proxyProduct = "Palo Alto Networks" }
        elseif ($certToCheck -match "Fortinet|FortiGate") { $proxyProduct = "Fortinet/FortiGate" }
        elseif ($certToCheck -match "Blue Coat|Symantec.*Proxy") { $proxyProduct = "Blue Coat/Symantec" }
        elseif ($certToCheck -match "Netskope")   { $proxyProduct = "Netskope" }
        elseif ($certToCheck -match "McAfee|Skyhigh") { $proxyProduct = "McAfee/Skyhigh" }
        elseif ($certToCheck -match "Barracuda")  { $proxyProduct = "Barracuda" }
        elseif ($certToCheck -match "Sophos")     { $proxyProduct = "Sophos" }
        elseif ($certToCheck -match "Check Point") { $proxyProduct = "Check Point" }
        elseif ($certToCheck -match "Cisco|Umbrella") { $proxyProduct = "Cisco/Umbrella" }

        $result.Detail += " | [TLS INSPECTION: $proxyProduct]"
        $bypassDomains = "*.$domainAppInsights, *.$domainMonitor"
        if ($cloudSuffix -eq "com") { $bypassDomains += ", *.services.visualstudio.com" }
        $result.Action = "Certificate was NOT issued by Microsoft/DigiCert. Issuer: $($result.CertIssuer). A TLS-inspecting proxy ($proxyProduct) is re-signing certificates. This can cause: SDK certificate validation failures, telemetry drops, and increased latency. Configure a TLS inspection bypass for: $bypassDomains"
    }

    # --- Deprecated protocol action text (cert-aware) ---
    # If TLS inspection was detected, the action was already set by the inspection block above.
    # If deprecated protocols were accepted but the cert IS Microsoft-issued, this is unexpected.
    # Azure Monitor endpoints should reject TLS 1.0/1.1. It's not a third-party MITM,
    # but the behavior is anomalous and worth flagging.
    if ($result.DeprecatedAccepted -and $result.DeprecatedAccepted.Count -gt 0 -and -not $result.TlsInspectionDetected) {
        $result.DeprecatedAzureEdge = $true
        $depList = ($result.DeprecatedAccepted -join ", ")
        # Replace the SECURITY/MITM detail text with unexpected-scenario text
        $result.Detail = $result.Detail -replace "\| \[SECURITY\] Deprecated protocol\(s\) accepted: .+$", "| [UNEXPECTED] Deprecated accepted ($depList) with Microsoft cert"
        $result.Action = "Deprecated TLS ($depList) was accepted and a Microsoft-issued certificate was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1. This is not a third-party proxy (the certificate is legitimate), but the behavior is unexpected. If this persists, contact Microsoft support."
    } elseif ($result.DeprecatedAccepted -and $result.DeprecatedAccepted.Count -gt 0 -and $result.TlsInspectionDetected) {
        # Action already set by TLS inspection block -- leave it
    } elseif ($result.DeprecatedAccepted -and $result.DeprecatedAccepted.Count -gt 0) {
        $depList = ($result.DeprecatedAccepted -join ", ")
        $result.Action = "Azure Monitor rejects TLS 1.0/1.1. A successful handshake with a deprecated protocol means a network device (proxy, firewall, or MITM appliance) is terminating TLS before traffic reaches Azure. Investigate: corporate proxy, transparent proxy, or firewall TLS inspection. Configure bypass for: *.$domainAppInsights, *.$domainMonitor"
    }

    $result.SupportedVersions = $supportedVersions

    return $result
}

function Test-IngestionEndpoint {
    param(
        [string]$IngestionUrl,
        [string]$InstrumentationKey
    )

    $cleanUrl = $IngestionUrl.TrimEnd('/')
    $result = @{
        Endpoint = $cleanUrl
        Status = "FAIL"
        HttpStatus = 0
        ResponseBody = ""
        Detail = ""
        Action = ""
        DurationMs = 0
        TestRecordId = ""
        TestRecordTimestamp = ""
    }

    # Build a sample availability test result (never sampled out)
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
    $testId = [guid]::NewGuid().ToString()
    $result.TestRecordId = $testId
    $result.TestRecordTimestamp = $timestamp

    $runLoc = $env:COMPUTERNAME
    if (-not $runLoc) { $runLoc = "unknown" }

    $availabilityData = @(
        @{
            ver = 1
            name = "Microsoft.ApplicationInsights.Message"
            time = $timestamp
            sampleRate = 100
            iKey = $InstrumentationKey
            tags = @{
                "ai.cloud.roleInstance" = "Telemetry-Flow-Diag"
                "ai.internal.sdkVersion" = "telemetry-flow-diag:$ScriptVersion"
            }
            data = @{
                baseType = "AvailabilityData"
                baseData = @{
                    ver = 2
                    id = $testId
                    name = "Telemetry-Flow-Diag Ingestion Validation"
                    duration = "00:00:00.001"
                    success = $true
                    runLocation = "telemetry-flow-script"
                    message = "[$runLoc] Telemetry flow diagnostic test record - safe to ignore"
                    properties = @{
                        "diagnosticRunId" = $testId
                        "scriptVersion"  = $ScriptVersion
                    }
                }
            }
        }
    ) | ConvertTo-Json -Depth 10

    # Determine the full URL
    # v2.1/track supports both iKey and Entra ID auth (v2/track does NOT support Entra ID)
    $postUrl = $cleanUrl + "/v2.1/track"

    try {
        Write-DebugRequest -Method "POST" -Url $postUrl -Body $availabilityData
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri $postUrl -Method POST -Body $availabilityData -ContentType "application/json" -UseBasicParsing -TimeoutSec 30
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds
        $result.HttpStatus = $response.StatusCode
        $result.ResponseBody = $response.Content
        Write-DebugResponse -Status "HTTP $($response.StatusCode) ($($result.DurationMs)ms)" -Body $response.Content

        # Parse the response JSON
        $responseObj = $null
        try {
            $responseObj = $response.Content | ConvertFrom-Json -ErrorAction Stop
        } catch {
            # Response wasn't valid JSON
            Write-ScriptDebug "Suppressed: $($_.Exception.Message)"
        }

        if ($response.StatusCode -eq 200) {
            $itemsReceived = if ($responseObj -and $null -ne $responseObj.itemsReceived) { $responseObj.itemsReceived } else { "?" }
            $itemsAccepted = if ($responseObj -and $null -ne $responseObj.itemsAccepted) { $responseObj.itemsAccepted } else { "?" }
            $result.Status = "PASS"
            $result.Detail = "HTTP 200 | Items sent: 1, received: $itemsReceived, accepted: $itemsAccepted [$($result.DurationMs)ms]"

            if ($itemsAccepted -eq 0) {
                $result.Status = "INFO"
                $errorMsgs = @()
                if ($responseObj.errors) {
                    foreach ($err in $responseObj.errors) {
                        $errorMsgs += "$($err.index): $($err.statusCode) - $($err.message)"
                    }
                }
                $errors = $errorMsgs -join "; "
                $result.Detail += " | Errors: $errors"
                $result.Action = "Ingestion endpoint accepted the request but rejected the telemetry item. Check the error details above."
            }
        }
    }
    catch {
        if ($sw.IsRunning) { $sw.Stop() }
        $result.DurationMs = $sw.ElapsedMilliseconds
        $statusCode = $null

        # Try to extract response details from the exception
        if ($_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $result.HttpStatus = $statusCode
            } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

            try {
                $responseStream = $_.Exception.Response.GetResponseStream()
                if ($responseStream) {
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    $result.ResponseBody = $reader.ReadToEnd()
                    $reader.Dispose()
                    $responseStream.Dispose()
                }
            } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        }

        # If we still don't have a response body, capture the exception message
        if (-not $result.ResponseBody) {
            $result.ResponseBody = $_.Exception.Message
        }

        switch ($statusCode) {
            400 {
                $result.Detail = "HTTP 400 Bad Request"
                $result.Action = "The ingestion API rejected the payload. This typically means the instrumentation key is invalid or doesn't match any App Insights resource. Verify your connection string."
            }
            401 {
                $result.Detail = "HTTP 401 Unauthorized"
                $result.Action = "Authentication required. Local authentication is likely disabled on this resource. SDKs must use Entra ID (Managed Identity or Service Principal) bearer tokens."
            }
            403 {
                $result.Detail = "HTTP 403 Forbidden"
                $result.Action = "Access denied. The ingestion API blocked this request. Common causes: (1) Public ingestion is disabled and you are sending from outside the private link scope, (2) Local authentication is disabled and no Entra ID bearer token was provided."
            }
            404 {
                $result.Detail = "HTTP 404 Not Found"
                $result.Action = "The ingestion endpoint path was not found. Verify the IngestionEndpoint in your connection string is correct and includes the regional prefix (e.g., westus2-1.in.$domainAppInsights)."
            }
            408 {
                $result.Detail = "HTTP 408 Request Timeout"
                $result.Action = "The request timed out. Check network latency, proxy timeout settings, and firewall rules."
            }
            429 {
                $result.Detail = "HTTP 429 Too Many Requests (Throttled)"
                $result.Action = "You are being rate-limited. This typically occurs when ingestion volume is extremely high or the daily cap has been reached."
            }
            439 {
                $result.Detail = "HTTP 439 Too Many Requests (Daily Cap)"
                $result.Action = "Daily ingestion cap has been reached. No more data will be accepted until the cap resets at the configured reset hour (UTC)."
            }
            500 {
                $result.Detail = "HTTP 500 Internal Server Error"
                $result.Action = "Server-side error at the ingestion endpoint. This is typically transient. Retry in a few minutes. If persistent, check Azure Status at https://status.azure.com for ongoing incidents."
            }
            503 {
                $result.Detail = "HTTP 503 Service Unavailable"
                $result.Action = "Ingestion service is temporarily unavailable. Check Azure Status at https://status.azure.com for ongoing incidents."
            }
            default {
                $result.Detail = "Request failed: $($_.Exception.Message)"
                if ($statusCode) { $result.Detail += " (HTTP $statusCode)" }
                $result.Action = "Unexpected error. Check firewall/proxy logs for blocked requests. Verify the connection string and endpoint URL."
            }
        }

        # Try to extract specific error messages from the response body JSON.
        # The ingestion API returns JSON like: { errors: [{ message: "..." }] }
        # but intermediate devices (proxies, load balancers) may return HTML, plain text,
        # or an empty body -- so this must be completely resilient to non-JSON responses.
        if ($result.ResponseBody) {
            try {
                $responseObj = $result.ResponseBody | ConvertFrom-Json -ErrorAction Stop
                if ($responseObj.errors) {
                    $apiMessages = @()
                    foreach ($err in $responseObj.errors) {
                        if ($err.message) {
                            $apiMessages += $err.message
                        }
                    }
                    if ($apiMessages.Count -gt 0) {
                        $result.Detail += " | API: $($apiMessages -join '; ')"
                    }
                }
            } catch {
                # Response body is not valid JSON (HTML error page, proxy response, etc.) -- ignore
                Write-ScriptDebug "Suppressed: $($_.Exception.Message)"
            }
        }
    }

    return $result
}

#endregion Main Diagnostic Functions

#region Data Plane Query Functions
# ============================================================================
# DATA PLANE QUERY FUNCTIONS
# ============================================================================
# These functions query the App Insights data plane API to verify telemetry
# arrived and to run diagnostic KQL queries. They require an active Az session
# (Connect-AzAccount) and Reader access to the App Insights resource.
# All operations are READ-ONLY queries against logged telemetry data.
# ============================================================================

function Get-AppInsightsDataPlaneToken {
    <#
    .SYNOPSIS
        Gets a bearer token for the App Insights data plane API using the current Az session.
    .PARAMETER ResourceUrl
        The audience/resource URL for the data plane API token.
        Public: https://api.applicationinsights.io  |  Gov: https://api.applicationinsights.us  |  China: https://api.applicationinsights.azure.cn
    .NOTES
        Az.Accounts 5.x changed Get-AzAccessToken to return Token as SecureString by default.
        This function handles both the new (SecureString) and old (plain string) formats.
    .OUTPUTS
        Returns the token as a plain string, or $null if token acquisition fails.
    #>
    param(
        [string]$ResourceUrl = "https://api.applicationinsights.io"
    )
    try {
        Write-ScriptDebug "Get-AzAccessToken -ResourceUrl `"$ResourceUrl`""
        $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop

        $token = $tokenResult.Token

        # Az.Accounts 5.x returns Token as SecureString; older versions return a plain string.
        # Convert SecureString to plain text so it can be used in HTTP Authorization headers.
        if ($token -is [System.Security.SecureString]) {
            $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
            )
        }

        if ($token) {
            Write-ScriptDebug "<<< Token acquired ($($token.Length) chars)"
            return $token
        }
        return $null
    }
    catch {
        if ($VerboseOutput) {
            Write-Result -Status "INFO" -Check "Could not acquire data plane token" `
                -Detail $_.Exception.Message `
                -Action "Ensure your account has Reader access to the App Insights resource."
        }
        return $null
    }
}

function Invoke-DataPlaneQuery {
    <#
    .SYNOPSIS
        Executes a KQL query against the App Insights data plane API.
    .PARAMETER AppId
        The Application Insights Application ID (GUID).
    .PARAMETER Token
        Bearer token from Get-AppInsightsDataPlaneToken.
    .PARAMETER KqlQuery
        The KQL query string to execute.
    .PARAMETER ApiHost
        The data plane API hostname (e.g., api.applicationinsights.io for Public,
        api.applicationinsights.us for Gov, api.applicationinsights.azure.cn for China).
    .PARAMETER PollAttempt
        Optional poll attempt number. When provided, appends a KQL comment
        to bust server-side query result caching between poll iterations.
    .PARAMETER TimeoutSec
        HTTP request timeout in seconds. Default: 30.
    .OUTPUTS
        Returns a hashtable with:
          Success  - $true/$false
          Columns  - Array of column definitions (name, type)
          Rows     - Array of row arrays
          Error    - Error message if failed
          RawResponse - The raw parsed response object
    #>
    param(
        [string]$AppId,
        [string]$Token,
        [string]$KqlQuery,
        [string]$ApiHost = "api.applicationinsights.io",
        [int]$PollAttempt = 0,
        [int]$TimeoutSec = 30
    )

    $result = @{
        Success = $false
        Columns = @()
        Rows = @()
        Error = ""
        IsTransient = $true   # Assume transient unless proven otherwise (safe default for retry logic)
        HttpStatus = 0
        RawResponse = $null
    }

    $apiUrl = "https://$ApiHost/v1/apps/$AppId/query"

    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
        "Cache-Control" = "no-cache"
        "Pragma"        = "no-cache"
    }

    # Append a unique KQL comment per poll attempt to prevent server-side cache hits
    $effectiveQuery = $KqlQuery
    if ($PollAttempt -gt 0) {
        $effectiveQuery = "$KqlQuery`n// poll-$PollAttempt-$(Get-Date -Format 'HHmmss')"
    }

    $body = @{ query = $effectiveQuery } | ConvertTo-Json

    try {
        Write-DebugRequest -Method "POST" -Url $apiUrl -Body $effectiveQuery
        $response = Invoke-RestMethod -Uri $apiUrl -Method POST -Headers $headers `
            -Body $body -TimeoutSec $TimeoutSec -ErrorAction Stop

        $result.RawResponse = $response
        Write-DebugResponse -Status "HTTP 200" -Body ($response | ConvertTo-Json -Depth 3 -Compress -ErrorAction SilentlyContinue)

        # The API returns { tables: [ { name, columns: [{name,type}], rows: [[...]] } ] }
        if ($response.tables -and $response.tables.Count -gt 0) {
            $table = $response.tables[0]
            $result.Columns = @($table.columns)
            $result.Rows = @($table.rows)
            $result.Success = $true
        } else {
            $result.Success = $true  # Query succeeded but returned no data
        }
    }
    catch {
        $errMsg = $_.Exception.Message

        # Try to extract HTTP status code
        $httpStatus = 0
        if ($_.Exception.Response) {
            try { $httpStatus = [int]$_.Exception.Response.StatusCode } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        }
        $result.HttpStatus = $httpStatus

        # Try to extract API error details from the response body
        $apiErrorCode = ""
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $errObj = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
                if ($errObj.error -and $errObj.error.message) {
                    $apiErrorCode = if ($errObj.error.code) { $errObj.error.code } else { "" }
                    $errMsg = "$($apiErrorCode): $($errObj.error.message)"
                }
            } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
        }

        $result.Error = $errMsg

        # Classify: non-transient errors should NOT be retried
        # Auth/permission errors, bad request, not found -- these won't fix themselves
        $nonTransientCodes = @(400, 401, 403, 404)
        $nonTransientPatterns = "Authorization|Unauthorized|Forbidden|InvalidAuthentication|InsufficientAccessError|BadRequest"

        if ($httpStatus -in $nonTransientCodes -or $apiErrorCode -match $nonTransientPatterns -or $errMsg -match $nonTransientPatterns) {
            $result.IsTransient = $false
        }
    }

    return $result
}

function Test-EndToEndVerification {
    <#
    .SYNOPSIS
        Polls the App Insights data plane API to verify the diagnostic test record
        arrived in logs. Shows latency decomposition when found.
    .PARAMETER AppId
        The Application Insights Application ID (GUID).
    .PARAMETER Token
        Bearer token for the data plane API.
    .PARAMETER TestRecordId
        The diagnosticRunId GUID embedded in the test record's custom properties.
    .PARAMETER MaxWaitSeconds
        Maximum time to poll before giving up. Default: 60.
    .PARAMETER PollIntervalSeconds
        Seconds between poll attempts. Default: 10.
    .OUTPUTS
        Returns a hashtable with:
          Status         - PASS, TIMEOUT, SKIPPED, ERROR
          RecordFound    - $true/$false
          DuplicateCount - Number of copies returned (>1 means duplicates)
          PollAttempts   - Number of queries made
          WaitedSeconds  - Total seconds spent polling
          Latency        - Hashtable of latency breakdown (if found)
          Error          - Error message (if failed)
          UserSkipped    - $true if user bailed out during polling
    #>
    param(
        [string]$AppId,
        [string]$Token,
        [string]$TestRecordId,
        [string]$ApiHost = "api.applicationinsights.io",
        [int]$MaxWaitSeconds = 60,
        [int]$PollIntervalSeconds = 10,
        [bool]$ShowPolling = $true
    )

    $result = @{
        Status = "ERROR"
        RecordFound = $false
        DuplicateCount = 0
        PollAttempts = 0
        WaitedSeconds = 0
        Latency = @{}
        Error = ""
        UserSkipped = $false
    }

    # KQL to find the exact test record with latency columns
    # No 'take 1' -- we return all copies so we can detect duplicates
    # caused by Diagnostic Settings exporting to Log Analytics.
    $kql = @"
availabilityResults
| where customDimensions.diagnosticRunId == '$TestRecordId'
| project timestamp, _TimeReceived, ingestion_time()
"@

    # Detect if we can check for keypresses (real console only -- not Kudu/ISE)
    $canCheckKeys = $script:UseColor  # UseColor = real console handle exists

    $totalMaxChecks = [Math]::Ceiling($MaxWaitSeconds / $PollIntervalSeconds)
    $overallSw = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Immediate first attempt (no wait) ---
    $result.PollAttempts = 1
    if ($ShowPolling) { Write-HostLog "  [0s] Querying... " -ForegroundColor DarkGray -NoNewline }

    $queryResult = Invoke-DataPlaneQuery -AppId $AppId -Token $Token -KqlQuery $kql -ApiHost $ApiHost -PollAttempt 1

    if ($queryResult.Success -and $queryResult.Rows.Count -gt 0) {
        $rowCount = $queryResult.Rows.Count
        $foundLabel = if ($rowCount -gt 1) { "found ($rowCount copies)!" } else { "found!" }
        if ($ShowPolling) { Write-HostLog $foundLabel -ForegroundColor Green }
        $overallSw.Stop()
        $result.Status = "PASS"
        $result.RecordFound = $true
        $result.DuplicateCount = $rowCount
        $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)

        # Parse latency (same logic as in the polling loop below)
        try {
            $colNames0 = @(); foreach ($c in $queryResult.Columns) { $colNames0 += $c.name }
            $r0 = $queryResult.Rows[0]
            $tsStr = $r0[$colNames0.IndexOf("timestamp")]
            $trStr = $r0[$colNames0.IndexOf("_TimeReceived")]
            $igStr = $r0[$colNames0.IndexOf("Column1")]  # ingestion_time() alias

            $tsUtc = [datetime]::Parse($tsStr).ToUniversalTime()
            $trUtc = [datetime]::Parse($trStr).ToUniversalTime()
            $igUtc = [datetime]::Parse($igStr).ToUniversalTime()

            $result.Latency = @{
                ClientToPipelineSec = [Math]::Round(($trUtc - $tsUtc).TotalSeconds, 1)
                PipelineToStoreSec = [Math]::Round(($igUtc - $trUtc).TotalSeconds, 1)
                EndToEndSec = [Math]::Round(($igUtc - $tsUtc).TotalSeconds, 1)
            }
        }
        catch {
            $result.Latency = @{ ParseError = $_.Exception.Message }
        }

        return $result
    } elseif ($queryResult.Success) {
        if ($ShowPolling) { Write-HostLog "not yet available" -ForegroundColor DarkGray }
    } elseif (-not $queryResult.IsTransient) {
        # Non-transient error on first attempt -- bail immediately
        if ($ShowPolling) {
            Write-HostLog "query error" -ForegroundColor Red
            if ($VerboseOutput) {
                Write-HostLog "      Error: $($queryResult.Error)" -ForegroundColor DarkGray
            }
        }
        $overallSw.Stop()
        $result.Status = "ERROR"
        $result.Error = $queryResult.Error
        $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)
        return $result
    } else {
        if ($ShowPolling) { Write-HostLog "query error (will retry)" -ForegroundColor DarkGray }
        $result.Error = $queryResult.Error
    }

    # --- Polling loop (wait-then-query for remaining attempts) ---
    for ($attempt = 2; $attempt -le $totalMaxChecks; $attempt++) {
        # --- Wait interval with optional keypress escape ---
        $escaped = $false
        if ($canCheckKeys) {
            # Check for keypress every 500ms during the wait interval
            $subChecks = [Math]::Floor($PollIntervalSeconds * 2)  # 500ms intervals
            for ($w = 0; $w -lt $subChecks; $w++) {
                Start-Sleep -Milliseconds 500
                try {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq [ConsoleKey]::Q) {
                            $escaped = $true
                            break
                        }
                    }
                } catch {
                    # KeyAvailable failed (shouldn't happen if UseColor passed, but be safe)
                    $canCheckKeys = $false
                }
            }
        } else {
            Start-Sleep -Seconds $PollIntervalSeconds
        }

        if ($escaped) {
            $overallSw.Stop()
            $result.Status = "SKIPPED"
            $result.UserSkipped = $true
            $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)
            $result.PollAttempts = $attempt - 1  # Didn't actually query this round
            if ($ShowPolling) { Write-HostLog "  [Q pressed - skipping verification]" -ForegroundColor Yellow }
            return $result
        }

        # --- Execute the query ---
        $result.PollAttempts = $attempt
        $elapsed = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)

        if ($ShowPolling) { Write-HostLog "  [$($elapsed)s] Querying... " -ForegroundColor DarkGray -NoNewline }

        $queryResult = Invoke-DataPlaneQuery -AppId $AppId -Token $Token -KqlQuery $kql -ApiHost $ApiHost -PollAttempt $attempt

        if (-not $queryResult.Success) {
            # Query failed (auth issue, API error, etc.)
            if ($ShowPolling) {
                Write-HostLog "query error" -ForegroundColor Red
                if ($VerboseOutput) {
                    Write-HostLog "      Error: $($queryResult.Error)" -ForegroundColor DarkGray
                }
            }
            $result.Error = $queryResult.Error

            # Non-transient errors (auth, permissions, bad request) won't fix themselves.
            # Bail immediately instead of wasting 60 seconds repeating the same failure.
            if (-not $queryResult.IsTransient) {
                $overallSw.Stop()
                $result.Status = "ERROR"
                $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)
                if ($ShowPolling) { Write-HostLog "  [!] Non-transient error -- skipping remaining poll attempts." -ForegroundColor Yellow }
                return $result
            }

            # Transient errors (throttling, server errors, timeouts) -- keep trying
            continue
        }

        if ($queryResult.Rows.Count -gt 0) {
            # --- Record found! ---
            $rowCount = $queryResult.Rows.Count
            $foundLabel = if ($rowCount -gt 1) { "FOUND ($rowCount copies)" } else { "FOUND" }
            if ($ShowPolling) { Write-HostLog $foundLabel -ForegroundColor Green }
            $overallSw.Stop()

            $result.Status = "PASS"
            $result.RecordFound = $true
            $result.DuplicateCount = $rowCount
            $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)

            # Parse latency from the row
            # Columns: timestamp, _TimeReceived, ingestion_time()
            $row = $queryResult.Rows[0]
            $colNames = @()
            foreach ($c in $queryResult.Columns) { $colNames += $c.name }

            $tsIdx = $colNames.IndexOf("timestamp")
            $trIdx = $colNames.IndexOf("_TimeReceived")
            # ingestion_time() comes back as column name "ingestion_time()"
            $itIdx = $colNames.IndexOf("ingestion_time()")

            try {
                $tsRecord    = [DateTime]::Parse($row[$tsIdx]).ToUniversalTime()
                $trReceived  = [DateTime]::Parse($row[$trIdx]).ToUniversalTime()
                $itIngested  = [DateTime]::Parse($row[$itIdx]).ToUniversalTime()

                $clientToPipeline = ($trReceived - $tsRecord).TotalSeconds
                $pipelineToStore  = ($itIngested - $trReceived).TotalSeconds
                $endToEnd         = ($itIngested - $tsRecord).TotalSeconds

                $result.Latency = @{
                    SentTimestamp         = $tsRecord.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    ReceivedTimestamp     = $trReceived.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    IngestedTimestamp     = $itIngested.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    ClientToPipelineSec   = [Math]::Round($clientToPipeline, 1)
                    PipelineToStoreSec    = [Math]::Round($pipelineToStore, 1)
                    EndToEndSec           = [Math]::Round($endToEnd, 1)
                }
            }
            catch {
                # Couldn't parse timestamps -- still a PASS, just no latency breakdown
                $result.Latency = @{ ParseError = $_.Exception.Message }
            }

            return $result
        } else {
            if ($ShowPolling) { Write-HostLog "not yet available" -ForegroundColor DarkGray }
        }
    }

    # --- Exhausted all attempts ---
    $overallSw.Stop()
    $result.Status = "TIMEOUT"
    $result.WaitedSeconds = [Math]::Round($overallSw.Elapsed.TotalSeconds, 0)
    return $result
}


#endregion Data Plane Query Functions

#region Environment Detection Function
# ============================================================================
# ENVIRONMENT DETECTION FUNCTION
# ============================================================================

function Get-EnvironmentInfo {
    $compName = $env:COMPUTERNAME
    if (-not $compName) { try { $compName = hostname } catch { $compName = "unknown" } }

    $info = @{
        ComputerName = $compName
        OS = ""
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAppService = $false
        IsFunctionApp = $false
        IsKudu = $false
        IsContainer = $false
        IsContainerApp = $false
        IsKubernetes = $false
        IsCloudShell = $false
        AzureHostType = ""          # Friendly label: "Azure App Service", "Azure Function App", etc.
        AzureHostDetail = ""        # Extra detail: SKU, runtime, revision, etc.
        DetectedConnectionString = ""
        Timestamp = Get-Timestamp
    }

    # OS detection
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $info.OS = "Windows"
    } elseif ($IsLinux) {
        $info.OS = "Linux"
    } elseif ($IsMacOS) {
        $info.OS = "macOS"
    } else {
        $info.OS = "Unknown"
    }

    # ---- Azure host environment detection (order matters) ----
    # Function App check FIRST (Functions run on App Service, so WEBSITE_* also present)
    if ($env:FUNCTIONS_WORKER_RUNTIME) {
        $info.IsFunctionApp = $true
        $info.IsAppService = $true
        $info.AzureHostType = "Azure Function App"
        $detail = @()
        if ($env:FUNCTIONS_EXTENSION_VERSION) { $detail += "v$($env:FUNCTIONS_EXTENSION_VERSION)" }
        $detail += "Runtime: $($env:FUNCTIONS_WORKER_RUNTIME)"
        if ($env:WEBSITE_SKU) { $detail += "SKU: $($env:WEBSITE_SKU)" }
        $info.AzureHostDetail = $detail -join " | "
        $workerName = $env:COMPUTERNAME
        if (-not $workerName) { $workerName = "worker" }
        $info.ComputerName = "$($env:WEBSITE_SITE_NAME) ($workerName)"
    }
    # App Service (not a Function App)
    elseif ($env:WEBSITE_SITE_NAME) {
        $info.IsAppService = $true
        $info.AzureHostType = "Azure App Service"
        $detail = @()
        if ($env:WEBSITE_SKU) { $detail += "SKU: $($env:WEBSITE_SKU)" }
        if ($env:REGION_NAME) { $detail += "Region: $($env:REGION_NAME)" }
        $info.AzureHostDetail = $detail -join " | "
        $workerName = $env:COMPUTERNAME
        if (-not $workerName) { $workerName = "worker" }
        $info.ComputerName = "$($env:WEBSITE_SITE_NAME) ($workerName)"
    }
    # Azure Container Apps
    elseif ($env:CONTAINER_APP_NAME) {
        $info.IsContainerApp = $true
        $info.IsContainer = $true
        $info.AzureHostType = "Azure Container App"
        $detail = @()
        if ($env:CONTAINER_APP_REVISION) { $detail += "Revision: $($env:CONTAINER_APP_REVISION)" }
        $info.AzureHostDetail = $detail -join " | "
        $info.ComputerName = $env:CONTAINER_APP_NAME
    }
    # Kubernetes (AKS or other)
    elseif ($env:KUBERNETES_SERVICE_HOST) {
        $info.IsKubernetes = $true
        $info.IsContainer = $true
        $info.AzureHostType = "Kubernetes"
        $info.AzureHostDetail = "API: $($env:KUBERNETES_SERVICE_HOST):$($env:KUBERNETES_SERVICE_PORT)"
    }
    # Azure Cloud Shell
    elseif ($env:ACC_CLOUD) {
        $info.IsCloudShell = $true
        $info.AzureHostType = "Azure Cloud Shell"
    }

    # Kudu/SCM detection (supplemental, not exclusive with App Service)
    if ($env:KUDU_APPPATH) {
        $info.IsKudu = $true
    }
    # Container detection (supplemental)
    if (-not $info.IsContainer -and (Test-Path "/.dockerenv" -ErrorAction SilentlyContinue)) {
        $info.IsContainer = $true
    }

    # Connection string auto-detection
    $envVars = @(
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
        "APPINSIGHTS_INSTRUMENTATIONKEY",
        "ApplicationInsights__ConnectionString",
        "APPLICATIONINSIGHTS_CONNECTIONSTRING"
    )
    foreach ($var in $envVars) {
        $val = [Environment]::GetEnvironmentVariable($var)
        if ($val) {
            $info.DetectedConnectionString = $val
            break
        }
    }

    return $info
}

#endregion Environment Detection Function

#region AMPLS (Azure Monitor Private Link Scope) Functions
# ============================================================================
# AMPLS (AZURE MONITOR PRIVATE LINK SCOPE) FUNCTIONS
# ============================================================================
# These functions are used when Azure checks are active (auto-detected or not -NetworkOnly).
# All operations are READ-ONLY. The script never creates, modifies, or deletes
# any Azure resource. It uses the following read-only operations:
#   - Connect-AzAccount          (interactive browser login)
#   - Search-AzGraph             (Azure Resource Graph read-only query)
#   - Invoke-AzRestMethod -GET   (ARM REST API read-only GET requests)
# ============================================================================

function Test-AmplsIpParameter {
    <#
    .SYNOPSIS
        Validates the -LookupAmplsIp parameter value.
        Checks: (1) valid IPv4, (2) private RFC1918 range, (3) present in resolved IP registry.
    .PARAMETER IpAddress
        The IP address string to validate.
    .OUTPUTS
        Returns a hashtable with Valid (bool), Reason (string).
    #>
    param([string]$IpAddress)

    # (1) Valid IPv4 format
    if ($IpAddress -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        return @{ Valid = $false; Reason = "'$IpAddress' is not a valid IPv4 address." }
    }
    $octets = $IpAddress.Split('.')
    foreach ($o in $octets) {
        if ([int]$o -gt 255) {
            return @{ Valid = $false; Reason = "'$IpAddress' is not a valid IPv4 address (octet $o > 255)." }
        }
    }

    # (2) Private RFC1918 range
    if ($IpAddress -notmatch '^10\.' -and
        $IpAddress -notmatch '^172\.(1[6-9]|2[0-9]|3[01])\.' -and
        $IpAddress -notmatch '^192\.168\.') {
        return @{ Valid = $false; Reason = "'$IpAddress' is not a private IP address (RFC1918: 10.x, 172.16-31.x, 192.168.x). Only private IPs from AMPLS private endpoints can be looked up." }
    }

    # (3) Present in resolved IP registry
    if ($script:ResolvedIpRegistry -notcontains $IpAddress) {
        return @{
            Valid = $false
            Reason = "'$IpAddress' was not resolved by any Azure Monitor endpoint during this script's execution. " +
                     "We can only look up private endpoints for IPs that were actually returned by DNS for the Azure Monitor endpoints tested above. " +
                     "Re-run with -Verbose output to see which IPs were resolved, then supply one of those private IPs."
        }
    }

    return @{ Valid = $true; Reason = "" }
}

function Find-AmplsByPrivateIp {
    <#
    .SYNOPSIS
        Reverse-lookups a private IP to find the owning AMPLS resource.
        3-step chain: IP -> NIC (ARG) -> PE (ARG) -> AMPLS (ARM REST).
    .PARAMETER TargetIp
        The private IPv4 address to look up.
    .OUTPUTS
        Returns a hashtable with Found (bool) and AMPLS details, or $null fields if not found.
    #>
    param([string]$TargetIp)

    $notFound = @{
        Found          = $false
        AmplsName      = $null
        AmplsRg        = $null
        AmplsSub       = $null
        AmplsId        = $null
        PeName         = $null
        PeRg           = $null
        IngestionMode  = $null
        QueryMode      = $null
    }

    # SDL 10031: Escape single quotes to prevent KQL injection
    $safeIp = $TargetIp -replace "'", "''"

    # -- Step 1: Find NIC by private IP via Resource Graph --
    $nicQuery = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| mv-expand ipconfig = properties.ipConfigurations
| where ipconfig.properties.privateIPAddress == '$safeIp'
| project nicId=id, nicName=name, subscriptionId, resourceGroup,
          subnetId=tostring(ipconfig.properties.subnet.id)
"@

    $nicResult = $null
    try {
        Write-DebugAzGraph -Query $nicQuery
        $nicResult = Search-AzGraph -Query $nicQuery -UseTenantScope -ErrorAction Stop
        Write-DebugResponse -Status "NIC lookup: $(@($nicResult).Count) result(s)"
    }
    catch {
        # Fallback to subscription list
        try {
            $currentTenantId = (Get-AzContext).Tenant.Id
            $subs = @(Get-AzSubscription -TenantId $currentTenantId -ErrorAction SilentlyContinue)
            $subIds = @(); foreach ($s in $subs) { $subIds += $s.Id }
            if ($subIds.Count -gt 0) {
                $nicResult = Search-AzGraph -Query $nicQuery -Subscription $subIds -ErrorAction Stop
            } else {
                $nicResult = Search-AzGraph -Query $nicQuery -ErrorAction Stop
            }
        }
        catch {
            Write-ScriptDebug "NIC ARG query failed: $($_.Exception.Message)"
            return $notFound
        }
    }

    if (-not $nicResult -or @($nicResult).Count -eq 0) {
        Write-ScriptDebug "No NIC found for IP $TargetIp"
        return $notFound
    }

    $nicId = $nicResult[0].nicId

    # -- Step 2: Find Private Endpoint by NIC via Resource Graph --
    $safeNicId = ($nicId -replace "'", "''").ToLower()
    $peQuery = @"
resources
| where type =~ 'microsoft.network/privateendpoints'
| mv-expand nic = properties.networkInterfaces
| where tolower(tostring(nic.id)) == '$safeNicId'
| project peId=id, peName=name, subscriptionId, resourceGroup,
          privateLinkServiceConnections=properties.privateLinkServiceConnections,
          manualConnections=properties.manualPrivateLinkServiceConnections
"@

    $peResult = $null
    try {
        Write-DebugAzGraph -Query $peQuery
        $peResult = Search-AzGraph -Query $peQuery -UseTenantScope -ErrorAction Stop
        Write-DebugResponse -Status "PE lookup: $(@($peResult).Count) result(s)"
    }
    catch {
        try {
            $currentTenantId = (Get-AzContext).Tenant.Id
            $subs = @(Get-AzSubscription -TenantId $currentTenantId -ErrorAction SilentlyContinue)
            $subIds = @(); foreach ($s in $subs) { $subIds += $s.Id }
            if ($subIds.Count -gt 0) {
                $peResult = Search-AzGraph -Query $peQuery -Subscription $subIds -ErrorAction Stop
            } else {
                $peResult = Search-AzGraph -Query $peQuery -ErrorAction Stop
            }
        }
        catch {
            Write-ScriptDebug "PE ARG query failed: $($_.Exception.Message)"
            return $notFound
        }
    }

    if (-not $peResult -or @($peResult).Count -eq 0) {
        Write-ScriptDebug "No Private Endpoint found for NIC $nicId"
        return $notFound
    }

    $pe = $peResult[0]

    # -- Step 3: Extract AMPLS resource ID from PE connections + fetch via ARM --
    $amplsResourceId = $null

    # Check both automatic and manual connections
    $allConnections = @()
    if ($pe.privateLinkServiceConnections) { $allConnections += @($pe.privateLinkServiceConnections) }
    if ($pe.manualConnections) { $allConnections += @($pe.manualConnections) }

    foreach ($conn in $allConnections) {
        $linkedId = $null
        if ($conn.properties -and $conn.properties.privateLinkServiceId) {
            $linkedId = $conn.properties.privateLinkServiceId
        } elseif ($conn.privateLinkServiceId) {
            $linkedId = $conn.privateLinkServiceId
        }
        if ($linkedId -and $linkedId -imatch 'microsoft\.insights/privatelinkscopes') {
            $amplsResourceId = $linkedId
            break
        }
    }

    if (-not $amplsResourceId) {
        Write-ScriptDebug "PE $($pe.peName) is not connected to an AMPLS resource (may be a different service type)"
        return $notFound
    }

    # Fetch AMPLS details via ARM REST
    try {
        $apiPath = "${amplsResourceId}?api-version=2021-07-01-preview"
        Write-DebugAzRest -Method "GET" -Path $apiPath
        $response = Invoke-AzRestMethod -Path $apiPath -Method GET -ErrorAction Stop
        Write-DebugResponse -Status "HTTP $($response.StatusCode)" -Body $response.Content

        if ($response.StatusCode -eq 200) {
            $amplsObj = $response.Content | ConvertFrom-Json -ErrorAction Stop

            # Parse subscription and RG from resource ID
            $idParts = $amplsObj.id -split '/'
            $amplsSubId = ""
            $amplsRg = ""
            for ($i = 0; $i -lt $idParts.Count; $i++) {
                if ($idParts[$i] -ieq 'subscriptions' -and ($i + 1) -lt $idParts.Count) {
                    $amplsSubId = $idParts[$i + 1]
                }
                if ($idParts[$i] -ieq 'resourceGroups' -and ($i + 1) -lt $idParts.Count) {
                    $amplsRg = $idParts[$i + 1]
                }
            }

            $ingestionMode = "Unknown"
            $queryMode = "Unknown"
            if ($amplsObj.properties.accessModeSettings) {
                $ingestionMode = $amplsObj.properties.accessModeSettings.ingestionAccessMode
                $queryMode = $amplsObj.properties.accessModeSettings.queryAccessMode
            }

            return @{
                Found          = $true
                AmplsName      = $amplsObj.name
                AmplsRg        = $amplsRg
                AmplsSub       = $amplsSubId
                AmplsId        = $amplsObj.id
                PeName         = $pe.peName
                PeRg           = $pe.resourceGroup
                IngestionMode  = $ingestionMode
                QueryMode      = $queryMode
            }
        } else {
            Write-ScriptDebug "AMPLS ARM fetch returned HTTP $($response.StatusCode)"
        }
    }
    catch {
        Write-ScriptDebug "AMPLS ARM fetch failed: $($_.Exception.Message)"
    }

    # PE found and points to AMPLS, but ARM call failed -- return partial info
    return @{
        Found          = $false
        AmplsName      = $null
        AmplsRg        = $null
        AmplsSub       = $null
        AmplsId        = $amplsResourceId
        PeName         = $pe.peName
        PeRg           = $pe.resourceGroup
        IngestionMode  = $null
        QueryMode      = $null
    }
}

function Get-IngestionEndpointPrefix {
    <#
    .SYNOPSIS
        Extracts the region/endpoint prefix from an ingestion hostname for CNAME matching.
        E.g., "{region}.in.applicationinsights.azure.com" -> "{region}.in"
              "dc.services.visualstudio.com" -> "dc"
              "dc.applicationinsights.azure.com" -> "dc"
    .PARAMETER IngestionHost
        The ingestion endpoint hostname.
    .OUTPUTS
        Returns the prefix string, or $null if it cannot be determined.
    #>
    param([string]$IngestionHost)

    $host_lower = $IngestionHost.ToLower()

    # Regional pattern: {region}.in.applicationinsights.azure.com
    if ($host_lower -match '^([a-z0-9\-]+\.in)\.applicationinsights\.') {
        return $Matches[1]
    }

    # Global/legacy pattern: dc.services.visualstudio.com
    if ($host_lower -match '^(dc)\.services\.visualstudio\.') {
        return $Matches[1]
    }

    # Global pattern: dc.applicationinsights.azure.com
    if ($host_lower -match '^(dc)\.applicationinsights\.') {
        return $Matches[1]
    }

    # Sovereign cloud variant: {region}.in.applicationinsights.azure.{suffix}
    if ($host_lower -match '^([a-z0-9\-]+\.in)\.applicationinsights\.') {
        return $Matches[1]
    }

    # Fallback: take everything before first known domain suffix
    if ($host_lower -match '^([a-z0-9\-]+(?:\.[a-z]+)?)\.(?:applicationinsights|ai\.monitor|ai\.privatelink\.monitor)\.') {
        return $Matches[1]
    }

    return $null
}

function Find-IngestionEndpointInAmplsResult {
    <#
    .SYNOPSIS
        Finds the AMPLS validation table entry that corresponds to the IngestionEndpoint.
        Uses CNAME domain mapping to match the ingestion hostname prefix against PE FQDNs.
    .PARAMETER IngestionHost
        The ingestion endpoint hostname from the connection string.
    .PARAMETER AmplsCheckResults
        Array of hashtables from Show-AmplsValidationTable: Fqdn, ExpectedIp, ActualIp, Match, Status.
    .OUTPUTS
        Returns the matching result hashtable, or $null if no match found.
    #>
    param(
        [string]$IngestionHost,
        [array]$AmplsCheckResults
    )

    if (-not $AmplsCheckResults -or $AmplsCheckResults.Count -eq 0) { return $null }

    $prefix = Get-IngestionEndpointPrefix -IngestionHost $IngestionHost
    if (-not $prefix) { return $null }

    $prefixLower = $prefix.ToLower()

    foreach ($cr in $AmplsCheckResults) {
        $fqdnLower = $cr.Fqdn.ToLower()
        # PE FQDNs look like: {prefix}.ai.privatelink.monitor.azure.com
        # or: {prefix}.ai.monitor.azure.com
        if ($fqdnLower -match "^$([regex]::Escape($prefixLower))\.ai\.(privatelink\.)?monitor\.") {
            return $cr
        }
    }

    # Fallback: if prefix is "dc", also try matching just the leading segment
    if ($prefixLower -eq "dc") {
        foreach ($cr in $AmplsCheckResults) {
            $fqdnLower = $cr.Fqdn.ToLower()
            if ($fqdnLower.StartsWith("dc.")) {
                return $cr
            }
        }
    }

    return $null
}

function Test-AmplsPrerequisite {
    <#
    .SYNOPSIS
        Checks if required Az modules are available.
    .OUTPUTS
        Returns a hashtable with Success, Detail, Action, AccountsVersion, GraphVersion.
    #>

    $result = @{
        Success = $false
        Detail = ""
        Action = ""
        AccountsVersion = $null
        GraphVersion = $null
    }

    # Check for Az.Accounts module
    $azAccounts = Get-Module -ListAvailable -Name "Az.Accounts" | Select-Object -First 1
    if (-not $azAccounts) {
        $result.Detail = "Az.Accounts module not found."
        $result.Action = @"
Install the Az PowerShell module:
      Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
      Or install just the minimum modules needed:
      Install-Module Az.Accounts -Scope CurrentUser -Force
      Install-Module Az.ResourceGraph -Scope CurrentUser -Force
"@
        return $result
    }
    $result.AccountsVersion = $azAccounts.Version.ToString()

    # Check for Az.ResourceGraph module
    $azGraph = Get-Module -ListAvailable -Name "Az.ResourceGraph" | Select-Object -First 1
    if (-not $azGraph) {
        $result.Detail = "Az.ResourceGraph module not found."
        $result.Action = "Install-Module Az.ResourceGraph -Scope CurrentUser -Force"
        return $result
    }
    $result.GraphVersion = $azGraph.Version.ToString()

    # Import modules (with version conflict recovery)
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        Import-Module Az.ResourceGraph -ErrorAction Stop
    }
    catch {
        $importError = $_.Exception.Message

        # Detect version conflict -- try removing old version and re-importing
        if ($importError -match "earlier version.*imported|version.*already.*imported|requires.*version") {
            if ($VerboseOutput) {
                Write-HostLog "  [i] Az module version conflict detected -- attempting to resolve..." -ForegroundColor Yellow
            }
            try {
                Remove-Module Az.Accounts -Force -ErrorAction SilentlyContinue
                Remove-Module Az.ResourceGraph -Force -ErrorAction SilentlyContinue
                Import-Module Az.Accounts -ErrorAction Stop
                Import-Module Az.ResourceGraph -ErrorAction Stop
                # If we get here, recovery succeeded
                $result.Success = $true
                return $result
            }
            catch {
                $retryError = $_.Exception.Message
                $result.Detail = "Az module version conflict. An older Az.Accounts was pre-loaded in this session."
                $result.Action = @"
Fix options (try in order):
      1. Close this PowerShell window, open a NEW one, and run this script again
      2. If your `$PROFILE auto-imports Az, add: Remove-Module Az.Accounts -Force
      3. Update: Install-Module Az -Force -AllowClobber -Scope CurrentUser
      4. Nuclear: Get-Module Az* -ListAvailable | Uninstall-Module -Force; Install-Module Az -Scope CurrentUser
      Error detail: $retryError
"@
                return $result
            }
        }

        $result.Detail = "Failed to import Az modules: $importError"
        return $result
    }

    $result.Success = $true
    return $result
}

function Find-AppInsightsResource {
    <#
    .SYNOPSIS
        Finds the App Insights resource in Azure by InstrumentationKey using Resource Graph.
        Uses -UseTenantScope to search across all subscriptions the user can access in the
        tenant, regardless of whether Get-AzSubscription lists them explicitly.
    .PARAMETER InstrumentationKey
        The iKey to search for.
    .OUTPUTS
        Returns the resource object or $null.
    #>
    param([string]$InstrumentationKey)

    # SDL 10031: Escape single quotes to prevent KQL injection
    $safeIKey = $InstrumentationKey -replace "'", "''"
    $query = "resources | where type =~ 'microsoft.insights/components' | where properties.InstrumentationKey =~ '$safeIKey' | project id, name, resourceGroup, subscriptionId, location, properties"

    # Strategy 1: Use -UseTenantScope (Az.ResourceGraph 0.13.0+) to search entire tenant
    # This finds resources in subscriptions that Get-AzSubscription may not enumerate,
    # e.g. subscriptions accessible through management group inheritance.
    try {
        if ($VerboseOutput) {
            Write-HostLog "    Searching entire tenant with -UseTenantScope..." -ForegroundColor Gray
        }
        Write-DebugAzGraph -Query $query
        $results = Search-AzGraph -Query $query -UseTenantScope -ErrorAction Stop
        if ($results -and $results.Count -gt 0) {
            Write-DebugResponse -Status "Found $($results.Count) result(s)" -Body ($results[0] | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue)
            return $results[0]
        } else {
            Write-DebugResponse -Status "No results"
        }
    }
    catch {
        # -UseTenantScope may not be available in older module versions
        if ($VerboseOutput) {
            Write-HostLog "    Tenant-scope search not available ($($_.Exception.Message)), falling back to subscription list..." -ForegroundColor DarkGray
        }
    }

    # Strategy 2: Fall back to explicit subscription list batching
    try {
        $currentTenantId = (Get-AzContext).Tenant.Id
        $subs = @(Get-AzSubscription -TenantId $currentTenantId -ErrorAction SilentlyContinue)

        if ($subs.Count -eq 0) {
            $subs = @(Get-AzSubscription -ErrorAction SilentlyContinue)
        }

        if ($subs.Count -gt 0) {
            $subIds = @()
            foreach ($s in $subs) { $subIds += $s.Id }

            if ($VerboseOutput) {
                Write-HostLog "    Searching $($subIds.Count) subscription(s) in tenant $currentTenantId..." -ForegroundColor Gray
            }

            $batchSize = 500
            for ($i = 0; $i -lt $subIds.Count; $i += $batchSize) {
                $end = [Math]::Min($i + $batchSize, $subIds.Count)
                $batch = $subIds[$i..($end - 1)]

                Write-DebugAzGraph -Query "$query (batch of $($batch.Count) subscriptions)"
                $results = Search-AzGraph -Query $query -Subscription $batch -ErrorAction Stop
                if ($results -and $results.Count -gt 0) {
                    Write-DebugResponse -Status "Found $($results.Count) result(s)" -Body ($results[0] | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue)
                    return $results[0]
                } else {
                    Write-DebugResponse -Status "No results in batch"
                }
            }
        } else {
            $results = Search-AzGraph -Query $query -ErrorAction Stop
            if ($results -and $results.Count -gt 0) {
                return $results[0]
            }
        }
    }
    catch {
        Write-Result -Status "INFO" -Check "Resource Graph query failed: $($_.Exception.Message)" `
            -Action "Ensure your account has Reader access to the subscription containing the App Insights resource."
    }

    return $null
}

function Find-AmplsForResource {
    <#
    .SYNOPSIS
        Finds AMPLS (Private Link Scope) resources linked to a given App Insights resource.

        Extracts AMPLS resource IDs from the App Insights resource's PrivateLinkScopedResources
        property (refreshed via ARM), then fetches each AMPLS resource directly via ARM for
        accurate, non-cached details.
    .PARAMETER AiResourceProperties
        The properties object from the App Insights resource (ARM-refreshed).
    .OUTPUTS
        Returns an array of AMPLS info objects that contain the target resource.
    #>
    param(
        [object]$AiResourceProperties
    )

    $amplsResults = @()

    # -----------------------------------------------------------------------
    # Extract AMPLS IDs from the AI resource's PrivateLinkScopedResources
    # The array contains ResourceId paths like:
    #   /subscriptions/.../microsoft.insights/privatelinkscopes/MY-AMPLS/scopedresources/scoped-...
    # We parse out the AMPLS resource ID (everything before /scopedresources/).
    # -----------------------------------------------------------------------
    $amplsIdsFromProperties = @()

    if ($AiResourceProperties -and $AiResourceProperties.PrivateLinkScopedResources) {
        foreach ($plsr in $AiResourceProperties.PrivateLinkScopedResources) {
            $scopedResourceId = ""
            if ($plsr.ResourceId) { $scopedResourceId = $plsr.ResourceId }

            # Extract AMPLS ID: everything before /scopedresources/
            $scopedIdx = $scopedResourceId.ToLower().IndexOf("/scopedresources/")
            if ($scopedIdx -gt 0) {
                $amplsId = $scopedResourceId.Substring(0, $scopedIdx)
                # Deduplicate (same AMPLS could have multiple scoped resources)
                if ($amplsIdsFromProperties -notcontains $amplsId.ToLower()) {
                    $amplsIdsFromProperties += $amplsId.ToLower()
                }
            }
        }
    }

    if ($amplsIdsFromProperties.Count -eq 0) {
        if ($VerboseOutput) {
            Write-HostLog "    No AMPLS links found in App Insights resource properties." -ForegroundColor Gray
        }
        return $amplsResults
    }

    if ($VerboseOutput) {
        Write-HostLog "    Found $($amplsIdsFromProperties.Count) AMPLS link(s) in App Insights resource properties." -ForegroundColor Gray
    }

    # -----------------------------------------------------------------------
    # Fetch each linked AMPLS resource directly via ARM for fresh details
    # -----------------------------------------------------------------------
    foreach ($amplsId in $amplsIdsFromProperties) {
        try {
            $apiPath = "${amplsId}?api-version=2021-07-01-preview"
            Write-DebugAzRest -Method "GET" -Path $apiPath
            $response = Invoke-AzRestMethod -Path $apiPath -Method GET -ErrorAction Stop
            Write-DebugResponse -Status "HTTP $($response.StatusCode)" -Body $response.Content

            if ($response.StatusCode -eq 200) {
                $amplsObj = $response.Content | ConvertFrom-Json -ErrorAction Stop

                # Parse resourceGroup and subscriptionId from the ARM resource ID path
                $idParts = $amplsObj.id -split '/'
                $amplsSubId = ""
                $amplsRg = ""
                for ($i = 0; $i -lt $idParts.Count; $i++) {
                    if ($idParts[$i] -ieq 'subscriptions' -and ($i + 1) -lt $idParts.Count) {
                        $amplsSubId = $idParts[$i + 1]
                    }
                    if ($idParts[$i] -ieq 'resourceGroups' -and ($i + 1) -lt $idParts.Count) {
                        $amplsRg = $idParts[$i + 1]
                    }
                }

                # Build a result object matching the shape downstream code expects
                $amplsResult = [PSCustomObject]@{
                    id             = $amplsObj.id
                    name           = $amplsObj.name
                    resourceGroup  = $amplsRg
                    subscriptionId = $amplsSubId
                    location       = $amplsObj.location
                    properties     = $amplsObj.properties
                }

                $amplsResults += $amplsResult
                if ($VerboseOutput) {
                    Write-HostLog "    [MATCH] " -ForegroundColor Green -NoNewline
                    Write-HostLog "$($amplsObj.name) -- linked to this App Insights resource" -ForegroundColor Gray
                }
            } else {
                if ($VerboseOutput) {
                    Write-HostLog "    [SKIP] AMPLS $amplsId -- HTTP $($response.StatusCode) (insufficient permissions?)" -ForegroundColor DarkGray
                }
            }
        }
        catch {
            if ($VerboseOutput) { Write-HostLog "    [SKIP] Could not fetch AMPLS: $($_.Exception.Message)" -ForegroundColor DarkGray }
        }
    }

    return $amplsResults
}

function Get-AmplsAccessMode {
    <#
    .SYNOPSIS
        Gets the access mode settings for an AMPLS resource.
        If AmplsProperties is provided (from a prior ARM fetch), reads directly
        from it without making an additional API call.
    .PARAMETER AmplsResourceId
        Full ARM resource ID of the AMPLS.
    .PARAMETER AmplsProperties
        Optional. The properties object from a prior ARM GET on the AMPLS resource.
        If provided, the function reads access modes directly and skips the ARM call.
    .OUTPUTS
        Returns a hashtable with ingestion and query access modes.
    #>
    param(
        [string]$AmplsResourceId,
        [object]$AmplsProperties = $null
    )

    $result = @{
        IngestionAccessMode = "Unknown"
        QueryAccessMode = "Unknown"
    }

    # Fast path: read from pre-fetched properties
    if ($AmplsProperties -and $AmplsProperties.accessModeSettings) {
        $result.IngestionAccessMode = $AmplsProperties.accessModeSettings.ingestionAccessMode
        $result.QueryAccessMode = $AmplsProperties.accessModeSettings.queryAccessMode
        Write-ScriptDebug "Access modes read from cached AMPLS properties (no extra API call)"
        return $result
    }

    # Fallback: fetch from ARM
    try {
        $apiPath = "${AmplsResourceId}?api-version=2021-07-01-preview"
        Write-DebugAzRest -Method "GET" -Path $apiPath
        $response = Invoke-AzRestMethod -Path $apiPath -Method GET -ErrorAction Stop
        Write-DebugResponse -Status "HTTP $($response.StatusCode)" -Body $response.Content

        if ($response.StatusCode -eq 200) {
            $amplsObj = $response.Content | ConvertFrom-Json -ErrorAction Stop
            if ($amplsObj.properties.accessModeSettings) {
                $result.IngestionAccessMode = $amplsObj.properties.accessModeSettings.ingestionAccessMode
                $result.QueryAccessMode = $amplsObj.properties.accessModeSettings.queryAccessMode
            }
        }
    }
    catch {
        # Silently fail, we'll report Unknown
        Write-ScriptDebug "Suppressed: $($_.Exception.Message)"
    }

    return $result
}

function Get-AmplsPrivateEndpoint {
    <#
    .SYNOPSIS
        Finds private endpoints connected to an AMPLS and retrieves their DNS/IP configs.
    .PARAMETER AmplsResourceId
        Full ARM resource ID of the AMPLS.
    .OUTPUTS
        Returns a hashtable with:
          PrivateEndpoints = @( @{ Name; ResourceGroup; DnsConfigs = @( @{ Fqdn; IpAddress } ) } )
    #>
    param([string]$AmplsResourceId)

    $result = @{
        PrivateEndpoints = @()
    }

    # Find private endpoints linked to this AMPLS via Resource Graph
    $query = @"
resources
| where type =~ 'microsoft.network/privateendpoints'
| mv-expand conn = properties.privateLinkServiceConnections
| where tolower(tostring(conn.properties.privateLinkServiceId)) == tolower('$($AmplsResourceId -replace "'", "''")')
| project id, name, resourceGroup, subscriptionId, location
"@

    try {
        # Strategy 1: Use -UseTenantScope
        $privateEndpoints = $null
        try {
            Write-DebugAzGraph -Query $query
            $privateEndpoints = Search-AzGraph -Query $query -UseTenantScope -ErrorAction Stop
            Write-DebugResponse -Status "Found $(@($privateEndpoints).Count) private endpoint(s)"
        }
        catch {
            # Fallback to subscription list
            $currentTenantId = (Get-AzContext).Tenant.Id
            $subs = @(Get-AzSubscription -TenantId $currentTenantId -ErrorAction SilentlyContinue)
            $subIds = @()
            if ($subs.Count -gt 0) { foreach ($s in $subs) { $subIds += $s.Id } }

            if ($subIds.Count -gt 0) {
                $privateEndpoints = Search-AzGraph -Query $query -Subscription $subIds -ErrorAction Stop
            } else {
                $privateEndpoints = Search-AzGraph -Query $query -ErrorAction Stop
            }
        }

        if (-not $privateEndpoints -or $privateEndpoints.Count -eq 0) {
            return $result
        }

        foreach ($pe in $privateEndpoints) {
            $peEntry = @{
                Name = $pe.name
                ResourceGroup = $pe.resourceGroup
                DnsConfigs = @()
            }

            # Get the full PE resource via ARM REST to get customDnsConfigurations
            $apiPath = "$($pe.id)?api-version=2023-11-01"
            Write-DebugAzRest -Method "GET" -Path $apiPath
            $response = $null
            try {
                $response = Invoke-AzRestMethod -Path $apiPath -Method GET -ErrorAction Stop
                Write-DebugResponse -Status "HTTP $($response.StatusCode)" -Body $response.Content
            } catch { continue }

            if ($response.StatusCode -ne 200) { continue }

            $peObj = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $peObj) { continue }

            # Extract FQDN-to-IP mappings from customDnsConfigurations
            if ($peObj.properties.customDnsConfigurations) {
                foreach ($dnsConfig in $peObj.properties.customDnsConfigurations) {
                    $fqdn = $dnsConfig.fqdn
                    $ipAddr = ""
                    if ($dnsConfig.ipAddresses -and $dnsConfig.ipAddresses.Count -gt 0) {
                        $ipAddr = $dnsConfig.ipAddresses[0]
                    }
                    if ($fqdn -and $ipAddr) {
                        $peEntry.DnsConfigs += @{
                            Fqdn = $fqdn
                            IpAddress = $ipAddr
                        }
                    }
                }
            }

            # Fallback: if customDnsConfigurations is empty, try the NIC approach
            if ($peEntry.DnsConfigs.Count -eq 0 -and $peObj.properties.networkInterfaces) {
                foreach ($nicRef in $peObj.properties.networkInterfaces) {
                    $nicPath = "$($nicRef.id)?api-version=2023-11-01"
                    $nicResponse = $null
                    try {
                        $nicResponse = Invoke-AzRestMethod -Path $nicPath -Method GET -ErrorAction Stop
                    } catch { continue }

                    if ($nicResponse.StatusCode -ne 200) { continue }

                    $nicObj = $nicResponse.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if (-not $nicObj) { continue }

                    foreach ($ipConfig in $nicObj.properties.ipConfigurations) {
                        $ip = $ipConfig.properties.privateIPAddress
                        $fqdns = $ipConfig.properties.privateLinkConnectionProperties.fqdns
                        if ($ip -and $fqdns) {
                            foreach ($f in $fqdns) {
                                $peEntry.DnsConfigs += @{
                                    Fqdn = $f
                                    IpAddress = $ip
                                }
                            }
                        }
                    }
                }
            }

            if ($peEntry.DnsConfigs.Count -gt 0) {
                $result.PrivateEndpoints += $peEntry
            }
        }
    }
    catch {
        Write-Result -Status "INFO" -Check "Private endpoint query failed: $($_.Exception.Message)"
    }

    return $result
}

function Show-AmplsValidationTable {
    <#
    .SYNOPSIS
        Compares Expected (AMPLS) vs Actual (DNS) IPs.
        Resolves each AMPLS FQDN directly from this machine's DNS rather than
        relying on DNS step results, which may use different domain names due to
        CNAME aliasing (e.g. *.applicationinsights.azure.com -> *.ai.monitor.azure.com).
        Displays a full comparison table in verbose mode; always returns result objects.
    .PARAMETER ExpectedMappings
        Array of @{ Fqdn; ExpectedIp; PrivateEndpointName; PrivateEndpointRg }
    .PARAMETER DnsResults
        Array of DNS results from earlier DNS checks (used as fallback cache).
    .OUTPUTS
        Returns an array of comparison result objects.
    #>
    param(
        [array]$ExpectedMappings,
        [array]$DnsResults
    )

    $comparisonResults = @()

    # Build a lookup from DNS step results as fallback cache
    $dnsCache = @{}
    foreach ($r in $DnsResults) {
        if ($r.IpAddresses -and $r.IpAddresses.Count -gt 0) {
            $dnsCache[$r.Hostname.ToLower()] = $r.IpAddresses[0]
        }
    }

    # Table layout
    $fqdnWidth = 50
    $expectedWidth = 18
    $actualWidth = 18
    $matchWidth = 8

    if ($VerboseOutput) {
        $headerLine = "  {0,-$fqdnWidth} {1,-$expectedWidth} {2,-$actualWidth} {3,-$matchWidth}" -f "Endpoint (FQDN)", "Expected (AMPLS)", "Actual (DNS)", "Match?"
        Write-HostLog $headerLine -ForegroundColor White
        $separatorLine = "  " + ("-" * $fqdnWidth) + " " + ("-" * $expectedWidth) + " " + ("-" * $actualWidth) + " " + ("-" * $matchWidth)
        Write-HostLog $separatorLine -ForegroundColor DarkGray
    }

    $matchCount = 0
    $mismatchCount = 0
    $failCount = 0

    foreach ($mapping in $ExpectedMappings) {
        $fqdn = $mapping.Fqdn
        $expectedIp = $mapping.ExpectedIp
        $actualIp = $null

        # First check DNS step cache (exact match)
        if ($dnsCache.ContainsKey($fqdn.ToLower())) {
            $actualIp = $dnsCache[$fqdn.ToLower()]
        } else {
            # Resolve this FQDN directly -- this handles CNAME aliasing
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($fqdn)
                if ($resolved -and $resolved.Count -gt 0) {
                    foreach ($addr in $resolved) {
                        if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                            $actualIp = $addr.IPAddressToString
                            break
                        }
                    }
                    if (-not $actualIp) {
                        $actualIp = $resolved[0].IPAddressToString
                    }
                }
            }
            catch {
                $failInfo = Get-DnsFailureInfo -Exception $_.Exception -Hostname $fqdn
                $actualIp = $failInfo.Label
            }
        }

        $matchStatus = ""
        $matchColor = "White"

        if (-not $actualIp) {
            $actualIp = "(no result)"
            $matchStatus = "FAIL"
            $matchColor = "Red"
            $failCount++
        } elseif ($actualIp -match '^\(DNS |^\(NXDOMAIN\)') {
            $matchStatus = "FAIL"
            $matchColor = "Red"
            $failCount++
        } elseif ($actualIp -eq $expectedIp) {
            $matchStatus = "MATCH"
            $matchColor = "Green"
            $matchCount++
        } else {
            $matchStatus = "MISMATCH"
            $matchColor = "Red"
            $mismatchCount++
        }

        if ($VerboseOutput) {
            $displayFqdn = $fqdn
            if ($displayFqdn.Length -gt $fqdnWidth) { $displayFqdn = $displayFqdn.Substring(0, $fqdnWidth - 2) + ".." }
            $displayExpected = $expectedIp
            if ($displayExpected.Length -gt $expectedWidth) { $displayExpected = $displayExpected.Substring(0, $expectedWidth - 2) + ".." }
            $displayActual = $actualIp
            if ($displayActual.Length -gt $actualWidth) { $displayActual = $displayActual.Substring(0, $actualWidth - 2) + ".." }

            $row = "  {0,-$fqdnWidth} {1,-$expectedWidth} {2,-$actualWidth} " -f $displayFqdn, $displayExpected, $displayActual
            Write-HostLog $row -NoNewline
            Write-HostLog $matchStatus -ForegroundColor $matchColor
        }

        $comparisonResults += @{
            Fqdn = $fqdn
            ExpectedIp = $expectedIp
            ActualIp = $actualIp
            Match = ($actualIp -eq $expectedIp)
            Status = $matchStatus
        }
    }

    if ($VerboseOutput) {
        $separatorLine = "  " + ("-" * $fqdnWidth) + " " + ("-" * $expectedWidth) + " " + ("-" * $actualWidth) + " " + ("-" * $matchWidth)
        Write-HostLog $separatorLine -ForegroundColor DarkGray
    }

    return $comparisonResults
}


#endregion AMPLS (Azure Monitor Private Link Scope) Functions

#region Main Execution
# ============================================================================
# MAIN EXECUTION
# ============================================================================

# ---- Environment detection (needed by banner for Azure PaaS awareness) ----
$envInfo = Get-EnvironmentInfo
$script:IsNonInteractiveEnv = ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp -or $envInfo.IsKubernetes) -and (-not $envInfo.IsCloudShell)

# ---- Consent gate infrastructure ----
$script:AzureConsentDeclined = $false
$script:IngestionConsentDeclined = $false

# ---- Banner (always) ----
Write-HostLog ""
Write-HostLog "  ======================================================================" -ForegroundColor White
Write-HostLog "   Application Insights Telemetry Flow Diagnostics  v$ScriptVersion (PowerShell) " -ForegroundColor White
if ($Compact) {
    Write-HostLog "   Output: Compact (progress lines only)" -ForegroundColor Gray
}
if ($NetworkOnly) {
    Write-HostLog "   Azure: Resource checks skipped (-NetworkOnly)" -ForegroundColor Gray
} elseif ($CheckAzure -and $script:AzLoggedIn) {
    $maskedAcct = Get-MaskedEmail (Get-AzContext).Account.Id
    Write-HostLog "   Azure: Active (logged in as $maskedAcct)" -ForegroundColor Gray
} elseif ($CheckAzure -and -not $script:AzLoggedIn -and $script:IsNonInteractiveEnv) {
    $hostType = if ($envInfo.IsAppService) { "App Service" }
                elseif ($envInfo.IsFunctionApp) { "Function App" }
                elseif ($envInfo.IsContainerApp) { "Container Apps" }
                elseif ($envInfo.IsKubernetes) { "AKS" }
                else { "Azure PaaS" }
    Write-HostLog "   Azure: Not logged in ($hostType -- run from local machine for Azure checks)" -ForegroundColor Yellow
} elseif ($CheckAzure -and -not $script:AzLoggedIn) {
    Write-HostLog "   Azure: Not logged in (will attempt login -- or run Connect-AzAccount first)" -ForegroundColor Yellow
} else {
    Write-HostLog "   Azure: Resource checks skipped (Az.Accounts not found)" -ForegroundColor Gray
}
if (-not $script:UseColor) {
    Write-HostLog "   Console: Plain text mode (no color support detected -- Kudu/web console)"
}
if ($AutoApprove) {
    Write-HostLog "   Consent: Auto-approved (-AutoApprove)" -ForegroundColor Gray
} elseif ($script:IsNonInteractiveEnv) {
    Write-HostLog "   Consent: Non-interactive (Azure login operations will be skipped)" -ForegroundColor Yellow
} else {
    Write-HostLog "   Consent: Y/N prompts ahead (use -AutoApprove to bypass)" -ForegroundColor Gray
}
Write-HostLog "  ======================================================================" -ForegroundColor White

# Dynamic step counter
$stepNumber = 0
$dnsStepNumber = 0

# ============================================================================
# STEP 1: Environment Detection
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-HeaderEntry "STEP $($stepNumber): Environment Detection"
    Write-HostLog ""
    Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
    Write-HostLog "  Understanding where this script is running helps interpret network behavior." -ForegroundColor Gray
    Write-HostLog "  Azure PaaS services (App Service, Functions) have different networking than VMs or containers." -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
    Write-HostLog "  - Host machine identity and OS type" -ForegroundColor Gray
    Write-HostLog "  - Azure PaaS environment (App Service, Function App, Kudu console)" -ForegroundColor Gray
    Write-HostLog "  - Container runtime detection" -ForegroundColor Gray
    Write-HostLog "  - Proxy configuration (environment variables, WinHTTP, .NET, system settings)" -ForegroundColor Gray
    Write-HostLog "  - Presence of connection string in environment variables" -ForegroundColor Gray
    Write-HostLog ""
}

if ($VerboseOutput) {
    Write-Result -Status "INFO" -Check "Host: $($envInfo.ComputerName)" -Detail "OS: $($envInfo.OS) | PowerShell: $($envInfo.PowerShellVersion)"
    if ($envInfo.AzureHostType) {
        $azDetail = $envInfo.AzureHostType
        if ($envInfo.AzureHostDetail) { $azDetail += " | $($envInfo.AzureHostDetail)" }
        Write-Result -Status "INFO" -Check "Azure host detected" -Detail $azDetail
    }
    if ($envInfo.IsContainer -and -not $envInfo.IsContainerApp) { Write-Result -Status "INFO" -Check "Container environment detected" }
}

# --- Proxy Detection ---
$proxyDetected = $false
$proxyDetails = @()

# Check environment variables
$proxyEnvVars = @("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy")
foreach ($pVar in $proxyEnvVars) {
    $pVal = [System.Environment]::GetEnvironmentVariable($pVar)
    if ($pVal) {
        $proxyDetected = $true
        $proxyDetails += "  Env: $pVar = $pVal"
    }
}

# Check WinHTTP proxy (Windows only)
$winHttpProxy = $null
if ($envInfo.OS -match "Windows") {
    try {
        $winHttpOutput = netsh winhttp show proxy 2>&1 | Out-String
        if ($winHttpOutput -match "Proxy Server\(s\)\s*:\s*(.+)" -and $winHttpOutput -notmatch "Direct access") {
            $winHttpProxy = $Matches[1].Trim()
            $proxyDetected = $true
            $proxyDetails += "  WinHTTP: $winHttpProxy"
        }
        # Also check for bypass list
        if ($winHttpOutput -match "Bypass List\s*:\s*(.+)") {
            $bypassList = $Matches[1].Trim()
            if ($bypassList -ne "(none)") {
                $proxyDetails += "  WinHTTP Bypass: $bypassList"
            }
        }
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
}

# Check .NET system default proxy
try {
    $defaultProxy = [System.Net.WebRequest]::DefaultWebProxy
    if ($defaultProxy) {
        $testUri = [System.Uri]"https://dc.applicationinsights.azure.com"
        $proxyUri = $defaultProxy.GetProxy($testUri)
        if ($proxyUri -and $proxyUri.AbsoluteUri -ne $testUri.AbsoluteUri) {
            $proxyDetected = $true
            $proxyDetails += "  .NET Default Proxy: $($proxyUri.AbsoluteUri) (for Azure Monitor endpoints)"
        }
    }
} catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

# Check Internet Explorer / WinINET proxy (registry)
if ($envInfo.OS -match "Windows") {
    try {
        $ieProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($ieProxy.ProxyEnable -eq 1 -and $ieProxy.ProxyServer) {
            $proxyDetected = $true
            $proxyDetails += "  System (IE/WinINET): $($ieProxy.ProxyServer)"
            if ($ieProxy.ProxyOverride) {
                $proxyDetails += "  System Bypass: $($ieProxy.ProxyOverride)"
            }
        }
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
}

if ($proxyDetected) {
    Write-ProgressLine -Name "Proxy Detection" -Status "INFO" -Summary "Proxy configuration detected (see details)"
    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  PROXY CONFIGURATION DETECTED:" -ForegroundColor Yellow
        foreach ($pd in $proxyDetails) {
            Write-HostLog "  $pd" -ForegroundColor Gray
        }
        Write-HostLog ""
        Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
        Write-HostLog "    Proxies can intercept, modify, or block telemetry traffic to Azure Monitor." -ForegroundColor Gray
        Write-HostLog "    Common proxy-related issues:" -ForegroundColor Gray
        Write-HostLog "      - TLS inspection re-signs certificates (causes TLS trust failures)" -ForegroundColor Gray
        Write-HostLog "      - Proxy timeouts for long-running connections (affects Live Metrics)" -ForegroundColor Gray
        Write-HostLog "      - Proxy blocks on specific hostnames or content types" -ForegroundColor Gray
        Write-HostLog "      - .NET HttpClient vs WebRequest may use different proxy settings" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  IF YOU SEE CONNECTIVITY FAILURES BELOW:" -ForegroundColor Cyan
        Write-HostLog "    Verify your proxy allows traffic to these domains:" -ForegroundColor Gray
        Write-HostLog "      *.applicationinsights.azure.com" -ForegroundColor White
        Write-HostLog "      *.monitor.azure.com" -ForegroundColor White
        Write-HostLog "      *.services.visualstudio.com" -ForegroundColor White
        Write-HostLog "      *.in.applicationinsights.azure.com" -ForegroundColor White
        Write-HostLog ""
        Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses" -ForegroundColor DarkGray
    }
} else {
    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  [i] No proxy configuration detected." -ForegroundColor DarkGray
    }
}

# ============================================================================
# STEP 2: Connection String Validation
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-HeaderEntry "STEP $($stepNumber): Connection String Validation"
    Write-HostLog ""
    Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
    Write-HostLog "  The connection string tells your SDK where to send telemetry. It contains:" -ForegroundColor Gray
    Write-HostLog "    - InstrumentationKey: Unique identifier for your App Insights resource" -ForegroundColor Gray
    Write-HostLog "    - IngestionEndpoint: Regional URL where telemetry is sent" -ForegroundColor Gray
    Write-HostLog "    - LiveEndpoint: URL for real-time Live Metrics streaming" -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
    Write-HostLog "  - Connection string is present (provided or in environment variable)" -ForegroundColor Gray
    Write-HostLog "  - Required components can be parsed" -ForegroundColor Gray
    Write-HostLog "  - Regional endpoints are identified for targeted testing" -ForegroundColor Gray
    Write-HostLog ""
}

if (-not $ConnectionString) {
    if ($envInfo.DetectedConnectionString) {
        $ConnectionString = $envInfo.DetectedConnectionString
        Write-Result -Status "PASS" -Check "Connection string found in environment variable"
    } else {
        Write-HostLog ""
        Write-HostLog "  [ERROR] No connection string found." -ForegroundColor Red
        Write-HostLog "  Provide -ConnectionString parameter or set APPLICATIONINSIGHTS_CONNECTION_STRING env variable." -ForegroundColor Yellow
        Write-HostLog ""
        exit 1
    }
} else {
    Write-Result -Status "PASS" -Check "Connection string provided via parameter"
}

# Parse connection string
$csComponents = ConvertFrom-ConnectionString $ConnectionString
$iKey = $csComponents["InstrumentationKey"]
$ingestionEndpoint = $csComponents["IngestionEndpoint"]
$liveEndpoint = $csComponents["LiveEndpoint"]

# Validate required components
if (-not $iKey) {
    Write-HostLog "  [ERROR] InstrumentationKey not found in connection string." -ForegroundColor Red
    Write-HostLog "  Get it from Azure Portal > App Insights > Overview > Connection String." -ForegroundColor Yellow
    exit 1
}

# SDL 10027/10031: Validate iKey is a well-formed GUID to prevent KQL/ARG injection
if (-not (Test-InstrumentationKeyFormat -Key $iKey)) {
    Write-HostLog "  [ERROR] InstrumentationKey is not a valid GUID format." -ForegroundColor Red
    Write-HostLog "  Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ForegroundColor Yellow
    Write-HostLog "  Get the correct connection string from Azure Portal > App Insights > Overview." -ForegroundColor Yellow
    exit 1
}

$maskedKey = $iKey.Substring(0, 8) + "..." + $iKey.Substring($iKey.Length - 4)
Write-Result -Status "PASS" -Check "InstrumentationKey: $maskedKey"

# SDL 10107: Validate endpoints are legitimate Azure Monitor hostnames (SSRF protection)
foreach ($epEntry in @(
    @{ Url = $ingestionEndpoint; Name = 'IngestionEndpoint' },
    @{ Url = $liveEndpoint; Name = 'LiveEndpoint' }
)) {
    if ($epEntry.Url) {
        $validationError = Test-AzureMonitorEndpoint -EndpointUrl $epEntry.Url -EndpointName $epEntry.Name
        if ($validationError) {
            Write-HostLog "  [ERROR] $validationError" -ForegroundColor Red
            Write-HostLog "  The connection string contains an endpoint that does not match any known Azure Monitor domain." -ForegroundColor Yellow
            Write-HostLog "  Verify your connection string in Azure Portal > App Insights > Overview." -ForegroundColor Yellow
            exit 1
        }
    }
}

# ---- Cloud detection ----
# Derive which Azure cloud we're targeting from the IngestionEndpoint domain.
# This drives endpoint construction for DNS/TCP checks, data plane API, and troubleshooting guidance.
$cloudSuffix = "com"  # Default: Public cloud
$cloudLabel = "Public"
if ($ingestionEndpoint -match '\.azure\.us') {
    $cloudSuffix = "us"
    $cloudLabel = "US Government"
} elseif ($ingestionEndpoint -match '\.azure\.cn') {
    $cloudSuffix = "cn"
    $cloudLabel = "China (21Vianet)"
} elseif ($csComponents["EndpointSuffix"]) {
    # Fallback: check EndpointSuffix if IngestionEndpoint didn't reveal the cloud
    $endpointSuffix = $csComponents["EndpointSuffix"]
    if ($endpointSuffix -match '\.us$|\.azure\.us') {
        $cloudSuffix = "us"
        $cloudLabel = "US Government"
    } elseif ($endpointSuffix -match '\.cn$|\.azure\.cn') {
        $cloudSuffix = "cn"
        $cloudLabel = "China (21Vianet)"
    }
}

# Cloud-specific service domains
$domainAppInsights = "applicationinsights.azure.$cloudSuffix"   # e.g. applicationinsights.azure.com
$domainMonitor     = "monitor.azure.$cloudSuffix"               # e.g. monitor.azure.com
$domainPrivateLink = "privatelink.monitor.azure.$cloudSuffix"   # e.g. privatelink.monitor.azure.com

# Data plane API (E2E verification)
$dataPlaneHost = switch ($cloudSuffix) {
    "us" { "api.applicationinsights.us" }
    "cn" { "api.applicationinsights.azure.cn" }
    default { "api.applicationinsights.io" }
}
$dataPlaneResource = "https://$dataPlaneHost"

if (-not $ingestionEndpoint) {
    if ($cloudSuffix -eq "com") {
        Write-Result -Status "INFO" -Check "No IngestionEndpoint in connection string -- using global default" `
            -Detail "This may indicate an older instrumentation key format without regional endpoints." `
            -Action "Consider updating to a full connection string from App Insights > Overview. Global endpoints are being retired."
        $ingestionEndpoint = "https://dc.services.visualstudio.com"
    } else {
        Write-Result -Status "INFO" -Check "No IngestionEndpoint in connection string -- using global default for $cloudLabel cloud" `
            -Detail "Using the global ingestion endpoint for the $cloudLabel cloud." `
            -Action "Consider updating to a full connection string from App Insights > Overview for best reliability."
        $ingestionEndpoint = "https://dc.$domainAppInsights"
    }
}

# Detect global/legacy endpoint usage
$isGlobalEndpoint = $false
if ($ingestionEndpoint -match "dc\.services\.visualstudio\.com|dc\.applicationinsights\.azure\.(com|us|cn)") {
    $isGlobalEndpoint = $true
}

Write-Result -Status "INFO" -Check "Ingestion Endpoint: $ingestionEndpoint"
if ($liveEndpoint) { Write-Result -Status "INFO" -Check "Live Metrics Endpoint: $liveEndpoint" }
if ($cloudSuffix -ne "com") { Write-Result -Status "INFO" -Check "Azure Cloud: $cloudLabel (endpoint suffix: .$cloudSuffix)" }

# Flag global endpoint usage
if ($isGlobalEndpoint) {
    Write-ProgressLine -Name "Endpoint Type" -Status "INFO" -Summary "Global/legacy endpoint (regional recommended)"
    Add-Diagnosis -Severity "INFO" -Title "Using Global/Legacy Ingestion Endpoint" `
        -Summary "Using global endpoint instead of regional (adds latency)" `
        -Description "Your connection string routes telemetry through the global endpoint ($ingestionEndpoint) instead of a regional endpoint. Global endpoints relay traffic to regional endpoints, adding latency." `
        -Fix "Update to a regional connection string from Azure Portal." `
        -Portal "App Insights > Overview > Connection String" `
        -Docs "https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string"

    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  [!] GLOBAL/LEGACY ENDPOINT DETECTED" -ForegroundColor Yellow
        Write-HostLog "  Your ingestion endpoint ($ingestionEndpoint) is the global/legacy endpoint." -ForegroundColor Gray
        Write-HostLog "  This is NOT recommended for production workloads:" -ForegroundColor Gray
        Write-HostLog "    - Global endpoints relay to regional, adding network hops and latency" -ForegroundColor Gray
        Write-HostLog "    - Regional endpoints are required for full support from Microsoft" -ForegroundColor Gray
        Write-HostLog "    - Connection strings with regional endpoints are the modern standard" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  UPDATE: Get the full connection string from Azure Portal > App Insights > Overview" -ForegroundColor Cyan
        Write-HostLog "  It will look like: InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..." -ForegroundColor DarkGray
        Write-HostLog ""
    }
}

# ---- Resource Header (always, after parsing connection string) ----
try {
    $ingestionHost = ([System.Uri]$ingestionEndpoint).Host
} catch {
    $ingestionHost = $ingestionEndpoint -replace 'https://','' -replace 'http://','' -replace '/.*',''
    if ($VerboseOutput) {
        Write-Result -Status "INFO" -Check "Could not parse ingestion endpoint as URI, extracted hostname: $ingestionHost"
    }
}

Write-HostLog ""
Write-HostLog "  ----------------------------------------------------------------" -ForegroundColor DarkGray
Write-HostLog "  iKey:     " -ForegroundColor Gray -NoNewline
Write-HostLog "$maskedKey" -ForegroundColor White -NoNewline
if ($cloudSuffix -ne "com") {
    Write-HostLog " | Cloud: " -ForegroundColor Gray -NoNewline
    Write-HostLog "$cloudLabel" -ForegroundColor Cyan
} else {
    Write-HostLog ""
}
Write-HostLog "  Endpoint: " -ForegroundColor Gray -NoNewline
Write-HostLog "$ingestionHost" -ForegroundColor White
Write-HostLog "  Host:     " -ForegroundColor Gray -NoNewline
Write-HostLog "$($envInfo.ComputerName) ($($envInfo.OS))" -ForegroundColor White
if ($envInfo.AzureHostType) {
    Write-HostLog "  Azure:    " -ForegroundColor Gray -NoNewline
    Write-HostLog "$($envInfo.AzureHostType)" -ForegroundColor Cyan -NoNewline
    if ($envInfo.AzureHostDetail) {
        Write-HostLog " | $($envInfo.AzureHostDetail)" -ForegroundColor DarkGray
    } else {
        Write-HostLog ""
    }
}
Write-HostLog "  ----------------------------------------------------------------" -ForegroundColor DarkGray
Write-HostLog ""

if (-not $VerboseOutput) {
    # Compact mode: consent prompts appear before the clean progress table
    if ($CheckAzure -and -not $NetworkOnly) {
        $azureConsent = Request-UserConsent `
            -RequiresAzureLogin `
            -PromptTitle "AZURE RESOURCE CHECKS -- YOUR CONSENT IS REQUIRED" `
            -PromptLines @(
                ""
                "Some of the checks in this script require access to your Azure resources."
                "You will be asked to sign in to Azure if you are not already"
                "authenticated -- all queries run as YOU, using your own account"
                "and permissions. No resources will be modified."
                ""
                "What your account will be used to query:"
                ""
                "  * Azure Resource Graph -- locate your App Insights resource and"
                "    any AMPLS private link scope linked to it. Discover any workspace"
                "    transform data collection rules that may impact App Insights telemetry"
                ""
                "  * ARM REST API (read-only) -- inspect AMPLS access modes, private"
                "    endpoint DNS config, daily cap settings, diagnostic settings,"
                "    and Log Analytics workspace state"
                ""
                "  * Data plane (conditional) -- if a test telemetry record is sent and"
                "    successfully accepted by the ingestion endpoint, a single KQL"
                "    query will confirm whether the record arrived in your workspace"
            ) `
            -SkipHint "To skip Azure resource checks entirely, press N or re-run with -NetworkOnly." `
            -PromptQuestion "Proceed with Azure resource checks? [Y/N]"
        if (-not $azureConsent) {
            $CheckAzure = $false
            $script:AzureConsentDeclined = $true
        }
    }
    if (-not $SkipIngestionTest) {
        $ingestionConsent = Request-UserConsent `
            -PromptTitle "TELEMETRY INGESTION TEST -- YOUR CONSENT IS REQUIRED" `
            -PromptLines @(
                ""
                "To verify end-to-end ingestion, this test will send ONE small"
                "availability record directly to your Application Insights resource."
                ""
                "What will be sent:"
                ""
                "  * Record type:  AvailabilityResult"
                "  * Record name:  'Telemetry-Flow-Diag Ingestion Validation'"
                "  * Payload size: ~0.5 KB"
                "  * Sent from:    this machine ($($envInfo.ComputerName)) -> your ingestion endpoint"
                "  * Sent as:      anonymous telemetry -- no sign-in required"
                ""
                "Cost: Standard ingestion and data retention rates apply."
                "For a single telemetry record this is negligible."
            ) `
            -SkipHint "To skip this test, press N or re-run with -SkipIngestionTest." `
            -PromptQuestion "Send test telemetry record? [Y/N]"
        if (-not $ingestionConsent) {
            $script:IngestionConsentDeclined = $true
        }
    }
    Write-HostLog "  Running diagnostics..." -ForegroundColor Gray
    Write-HostLog ""
}

# ============================================================================
# Build endpoint list
# ============================================================================

$endpoints = @()
$endpoints += @{ Category = "Ingestion (Regional)"; Hostname = $ingestionHost; Critical = $true }
$endpoints += @{ Category = "Ingestion (Global/Legacy)"; Hostname = "dc.$domainAppInsights"; Critical = $false }
if ($cloudSuffix -eq "com") {
    $endpoints += @{ Category = "Ingestion (Global/Legacy)"; Hostname = "dc.services.visualstudio.com"; Critical = $false }
}

if ($liveEndpoint) {
    try {
        $liveHost = ([System.Uri]$liveEndpoint).Host
    } catch {
        $liveHost = $liveEndpoint -replace 'https://','' -replace 'http://','' -replace '/.*',''
    }
    $endpoints += @{ Category = "Live Metrics"; Hostname = $liveHost; Critical = $false }
}
$endpoints += @{ Category = "Live Metrics (Global/Legacy)"; Hostname = "live.$domainAppInsights"; Critical = $false }
if ($cloudSuffix -eq "com") {
    $endpoints += @{ Category = "Live Metrics (Global/Legacy)"; Hostname = "rt.services.visualstudio.com"; Critical = $false }
}
if ($cloudSuffix -eq "com") {
    $endpoints += @{ Category = "Profiler"; Hostname = "agent.azureserviceprofiler.net"; Critical = $false }
}
$endpoints += @{ Category = "Profiler"; Hostname = "profiler.$domainMonitor"; Critical = $false }
$endpoints += @{ Category = "Snapshot Debugger"; Hostname = "snapshot.$domainMonitor"; Critical = $false }
if ($cloudSuffix -eq "com") {
    $endpoints += @{ Category = "Query API"; Hostname = "api.applicationinsights.io"; Critical = $false }
}
$endpoints += @{ Category = "Query API"; Hostname = "api.$domainAppInsights"; Critical = $false }
if ($cloudSuffix -eq "com") {
    $endpoints += @{ Category = "JS SDK CDN"; Hostname = "js.monitor.azure.com"; Critical = $false }
}

# Deduplicate by hostname (PS 5.1 safe)
$seen = @{}
$uniqueEndpoints = @()
foreach ($ep in $endpoints) {
    if (-not $seen.ContainsKey($ep.Hostname)) {
        $seen[$ep.Hostname] = $true
        $uniqueEndpoints += $ep
    }
}
$endpoints = $uniqueEndpoints

# ============================================================================
# STEP 3: DNS Resolution
# ============================================================================

$stepNumber++
$dnsStepNumber = $stepNumber
if ($VerboseOutput) {
    Write-HeaderEntry "STEP $($stepNumber): DNS Resolution"
    Write-HostLog ""
    Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
    Write-HostLog "  Before sending telemetry, your app must resolve Azure Monitor hostnames to IP addresses." -ForegroundColor Gray
    Write-HostLog "  DNS failures are a common cause of missing telemetry, especially in:" -ForegroundColor Gray
    Write-HostLog "    - Private networks with custom DNS servers" -ForegroundColor Gray
    Write-HostLog "    - Azure Private Link (AMPLS) configurations" -ForegroundColor Gray
    Write-HostLog "    - Hybrid cloud environments with on-premises DNS" -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
    Write-HostLog "  - Ingestion endpoints (where telemetry is sent)" -ForegroundColor Gray
    Write-HostLog "  - Live Metrics endpoints (real-time monitoring)" -ForegroundColor Gray
    Write-HostLog "  - Profiler and Snapshot Debugger endpoints" -ForegroundColor Gray
    Write-HostLog "  - Query API endpoints (for data retrieval)" -ForegroundColor Gray
    Write-HostLog "  - JavaScript SDK CDN (for browser-based apps)" -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT SUCCESS LOOKS LIKE:" -ForegroundColor Cyan
    Write-HostLog "  - All endpoints resolve to IP addresses" -ForegroundColor Gray
    Write-HostLog "  - If using AMPLS: All endpoints resolve to PRIVATE IPs consistently" -ForegroundColor Gray
    Write-HostLog "  - If NOT using AMPLS: All endpoints resolve to PUBLIC Microsoft IPs" -ForegroundColor Gray
    Write-HostLog "  - No mixed public/private results (indicates incomplete AMPLS setup)" -ForegroundColor Gray
    Write-HostLog ""

    # Get DNS server information
    $dnsServers = Get-DnsServerAddress
    if ($dnsServers.Count -gt 0) {
        Write-HostLog "  DNS Server(s): " -ForegroundColor Gray -NoNewline
        Write-HostLog ($dnsServers -join ", ") -ForegroundColor White
    } else {
        Write-HostLog "  DNS Server(s): " -ForegroundColor Gray -NoNewline
        Write-HostLog "(unable to determine)" -ForegroundColor Yellow
    }
    Write-HostLog ""
    Write-HostLog "  Testing $($endpoints.Count) endpoints..." -ForegroundColor Gray
    Write-HostLog ""
}

Write-ProgressStart -Name "DNS Resolution"

# Run DNS checks
$dnsResults = @()
$hasAmplsSignals = $false
$hasPublicIps = $false
$dnsFailures = @()

foreach ($ep in $endpoints) {
    try {
        $dnsResult = Test-DnsResolution -Hostname $ep.Hostname
        $dnsResult.Category = $ep.Category
        $dnsResult.Critical = $ep.Critical
        $dnsResults += $dnsResult

        if ($dnsResult.IsPrivateIp) { $hasAmplsSignals = $true }
        if ($dnsResult.Status -eq "PASS" -and -not $dnsResult.IsPrivateIp) { $hasPublicIps = $true }
        if ($dnsResult.Status -eq "FAIL") { $dnsFailures += $dnsResult }
    }
    catch {
        $failResult = @{
            Hostname = $ep.Hostname
            Category = $ep.Category
            Critical = $ep.Critical
            Status = "FAIL"
            IpAddresses = @()
            IsPrivateIp = $false
            Detail = "Error: $($_.Exception.Message)"
            Action = "Check DNS configuration and network connectivity."
            DurationMs = 0
        }
        $dnsResults += $failResult
        $dnsFailures += $failResult
    }
}

# --- Populate resolved IP registry from DNS results ---
foreach ($dr in $dnsResults) {
    if ($dr.IpAddresses) {
        foreach ($ip in $dr.IpAddresses) {
            if ($ip -and $script:ResolvedIpRegistry -notcontains $ip) {
                $script:ResolvedIpRegistry += $ip
            }
        }
    }
}

# --- DNS progress line (always, BEFORE verbose display) ---
$dnsPassCount = @($dnsResults | Where-Object { $_.Status -eq "PASS" }).Count
$dnsFailCount = @($dnsResults | Where-Object { $_.Status -eq "FAIL" }).Count
$dnsIpType = "all public IPs"
if ($hasAmplsSignals -and -not $hasPublicIps) { $dnsIpType = "all private IPs" }
elseif ($hasAmplsSignals -and $hasPublicIps) { $dnsIpType = "MIXED public/private" }

if ($dnsFailCount -gt 0) {
    Write-ProgressLine -Name "DNS Resolution" -Status "FAIL" -Summary "$dnsPassCount/$($dnsResults.Count) resolved, $dnsFailCount failed"
    Add-Diagnosis -Severity "BLOCKING" -Title "DNS Resolution Failures" `
        -Summary "DNS failed for $dnsFailCount endpoint(s) -- all telemetry blocked" `
        -Description "$dnsFailCount endpoint(s) failed DNS resolution. This blocks all telemetry." `
        -Fix "Verify DNS server config, private DNS zones, and VNet DNS settings." `
        -Docs "https://learn.microsoft.com/azure/azure-monitor/fundamentals/azure-monitor-network-access"
} elseif ($hasAmplsSignals -and $hasPublicIps) {
    Write-ProgressLine -Name "DNS Resolution" -Status "INFO" -Summary "$dnsPassCount/$($dnsResults.Count) resolved ($dnsIpType)"
    Add-Diagnosis -Severity "INFO" -Title "Mixed Public/Private DNS Results" `
        -Summary "Incomplete AMPLS DNS setup (some public, some private IPs)" `
        -Description "Some endpoints resolve to private IPs, others to public. This indicates incomplete AMPLS DNS setup." `
        -Fix "Verify $domainPrivateLink DNS zone is linked to your VNet." `
        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
} else {
    Write-ProgressLine -Name "DNS Resolution" -Status "OK" -Summary "$dnsPassCount/$($dnsResults.Count) resolved ($dnsIpType)"
}

# DNS results display (verbose: full table)
if ($VerboseOutput) {
    Write-HostLog "  DNS Resolution Results:" -ForegroundColor Cyan
    Write-HostLog ""

    $catWidth = 24
    $hostWidth = 48
    $ipWidth = 18
    $typeWidth = 10
    $statusWidth = 6

    $headerLine = "  {0,-$catWidth} {1,-$hostWidth} {2,-$ipWidth} {3,-$typeWidth} {4,-$statusWidth}" -f "Category", "Endpoint", "Resolved IP", "Type", "Status"
    Write-HostLog $headerLine -ForegroundColor White
    $separatorLine = "  " + ("-" * $catWidth) + " " + ("-" * $hostWidth) + " " + ("-" * $ipWidth) + " " + ("-" * $typeWidth) + " " + ("-" * $statusWidth)
    Write-HostLog $separatorLine -ForegroundColor DarkGray

    foreach ($r in $dnsResults) {
        $cat = $r.Category
        if ($cat.Length -gt $catWidth) { $cat = $cat.Substring(0, $catWidth - 2) + ".." }
        $host_ = $r.Hostname
        if ($host_.Length -gt $hostWidth) { $host_ = $host_.Substring(0, $hostWidth - 2) + ".." }
        $ip = "(failed)"
        if ($r.DnsFailureLabel) { $ip = $r.DnsFailureLabel }
        if ($r.IpAddresses -and $r.IpAddresses.Count -gt 0) {
            $ip = $r.IpAddresses[0]
            if ($r.IpAddresses.Count -gt 1) { $ip = $ip + " (+$($r.IpAddresses.Count - 1))" }
        }
        if ($ip.Length -gt $ipWidth) { $ip = $ip.Substring(0, $ipWidth - 2) + ".." }
        $ipType = "Public"
        if ($r.Status -eq "FAIL") { $ipType = "-" }
        elseif ($r.IsPrivateIp) { $ipType = "Private" }

        $row = "  {0,-$catWidth} {1,-$hostWidth} {2,-$ipWidth} {3,-$typeWidth} " -f $cat, $host_, $ip, $ipType
        Write-HostLog $row -NoNewline
        switch ($r.Status) {
            "PASS" { Write-HostLog "PASS" -ForegroundColor Green }
            "INFO" { Write-HostLog "INFO" -ForegroundColor Yellow }
            "FAIL" { Write-HostLog "FAIL" -ForegroundColor Red }
            default { Write-HostLog $r.Status -ForegroundColor Gray }
        }
    }

    Write-HostLog $separatorLine -ForegroundColor DarkGray

    $passCount = ($dnsResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($dnsResults | Where-Object { $_.Status -eq "FAIL" }).Count
    Write-HostLog ""
    Write-HostLog "  Resolved: " -ForegroundColor Gray -NoNewline
    Write-HostLog "$passCount" -ForegroundColor Green -NoNewline
    Write-HostLog " / $($dnsResults.Count)" -ForegroundColor Gray -NoNewline
    if ($failCount -gt 0) {
        Write-HostLog "  |  Failed: " -ForegroundColor Gray -NoNewline
        Write-HostLog "$failCount" -ForegroundColor Red
    } else {
        Write-HostLog ""
    }

    Write-HostLog ""
    Write-HostLog "  NOTE: " -ForegroundColor DarkGray -NoNewline
    Write-HostLog "PASS means this machine resolved the hostname to an IP address. It does NOT" -ForegroundColor DarkGray
    Write-HostLog "  yet confirm whether the returned IP is the correct one for healthy telemetry flow." -ForegroundColor DarkGray
    if ($CheckAzure -or ($AmplsExpectedIps -and $AmplsExpectedIps.Count -gt 0)) {
        Write-HostLog "  The AMPLS validation step will compare these IPs against any expected private endpoint IPs." -ForegroundColor DarkGray
    } elseif (-not $NetworkOnly) {
        Write-HostLog "  To fully validate resolved IPs (including AMPLS/Private Link), run this script from an" -ForegroundColor DarkGray
        Write-HostLog "  environment with the Az PowerShell module installed and an active Azure login." -ForegroundColor DarkGray
    }

    # Show failures with action items
    if ($dnsFailures.Count -gt 0) {
        Write-HostLog ""
        Write-HostLog "  DNS FAILURES DETECTED:" -ForegroundColor Red
        foreach ($f in $dnsFailures) {
            Write-HostLog "    - $($f.Hostname): $($f.Detail)" -ForegroundColor Gray
            if ($f.Action) { Write-HostLog "      ACTION: $($f.Action)" -ForegroundColor Yellow }
        }
    }

    # AMPLS consistency check
    if ($hasAmplsSignals) {
        Write-HostLog ""
        Write-HostLog "  AMPLS ANALYSIS:" -ForegroundColor Cyan
        if ($hasAmplsSignals -and $hasPublicIps) {
            Write-HostLog "  [!] " -ForegroundColor Yellow -NoNewline
            Write-HostLog "INCONSISTENT: Some endpoints resolve to private IPs, others to public." -ForegroundColor Yellow
            Write-HostLog ""
            Write-HostLog "      Private IP endpoints:" -ForegroundColor Gray
            foreach ($r in $dnsResults) {
                if ($r.IsPrivateIp) {
                    Write-HostLog "        - $($r.Category): $($r.Hostname) -> $($r.IpAddresses[0])" -ForegroundColor Gray
                }
            }
            Write-HostLog ""
            Write-HostLog "      Public IP endpoints:" -ForegroundColor Gray
            foreach ($r in $dnsResults) {
                if ($r.Status -eq "PASS" -and -not $r.IsPrivateIp) {
                    Write-HostLog "        - $($r.Category): $($r.Hostname) -> $($r.IpAddresses[0])" -ForegroundColor Gray
                }
            }
            Write-HostLog ""
            Write-HostLog "      ACTION REQUIRED:" -ForegroundColor Yellow
            Write-HostLog "      This typically indicates incomplete private DNS zone configuration." -ForegroundColor Gray
            Write-HostLog "      Verify these private DNS zones exist and are linked to your VNet:" -ForegroundColor Gray
            Write-HostLog "        - $domainPrivateLink" -ForegroundColor White
            Write-HostLog "        - privatelink.oms.opinsights.azure.$cloudSuffix" -ForegroundColor White
            Write-HostLog "        - privatelink.ods.opinsights.azure.$cloudSuffix" -ForegroundColor White
            Write-HostLog "        - privatelink.agentsvc.azure-automation.net" -ForegroundColor White
            Write-HostLog "      Ensure App Insights AND its linked Log Analytics workspace are in the AMPLS." -ForegroundColor Gray
        } else {
            Write-HostLog "  [OK] " -ForegroundColor Green -NoNewline
            Write-HostLog "All tested endpoints resolve to private IPs (consistent AMPLS configuration)." -ForegroundColor Green
            Write-HostLog ""
            Write-HostLog "      To verify these IPs match your AMPLS configuration:" -ForegroundColor Gray
            Write-HostLog "      1. Go to Azure Portal > Your AMPLS resource > Private Endpoint Connections" -ForegroundColor Gray
            Write-HostLog "      2. Click on the private endpoint > DNS Configuration" -ForegroundColor Gray
            Write-HostLog "      3. Compare the IPs listed there against the 'Resolved IP' column above" -ForegroundColor Gray
            Write-HostLog ""
            if ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp) {
                Write-HostLog "      TIP: To automatically validate IPs against AMPLS, run this script from Azure Cloud Shell or a machine with Az.Accounts installed." -ForegroundColor DarkGray
            } else {
                Write-HostLog "      TIP: Install Az.Accounts and Connect-AzAccount to automatically validate IPs against AMPLS" -ForegroundColor DarkGray
            }
        }
    }
}

# ============================================================================
# STEP 4: TCP Connectivity
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-HeaderEntry "STEP $($stepNumber): TCP Connectivity (Port 443)"
    Write-HostLog ""
    Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
    Write-HostLog "  After DNS resolution, your app must establish a TCP connection on port 443 (HTTPS)." -ForegroundColor Gray
    Write-HostLog "  TCP failures typically indicate firewall or network security rules blocking traffic." -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
    Write-HostLog "  - Can we open a TCP socket to each endpoint on port 443?" -ForegroundColor Gray
    Write-HostLog "  - How long does the connection take? (latency indicator)" -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  WHAT SUCCESS LOOKS LIKE:" -ForegroundColor Cyan
    Write-HostLog "  - All endpoints accept TCP connections" -ForegroundColor Gray
    Write-HostLog "  - Connection times are reasonable (under 500ms typically)" -ForegroundColor Gray
    Write-HostLog ""
    Write-HostLog "  IF THIS FAILS, CHECK:" -ForegroundColor Yellow
    Write-HostLog "  - NSG (Network Security Group) outbound rules for port 443" -ForegroundColor Gray
    Write-HostLog "  - Azure Firewall or third-party firewall appliance rules" -ForegroundColor Gray
    Write-HostLog "  - UDR (User Defined Routes) that might redirect traffic" -ForegroundColor Gray
    Write-HostLog "  - On-premises firewall if traffic routes through VPN/ExpressRoute" -ForegroundColor Gray
    Write-HostLog ""
}

Write-ProgressStart -Name "TCP Connectivity"

$tcpResults = @()
$dnsPassedEndpoints = @($dnsResults | Where-Object { $_.Status -eq "PASS" })

# Build a quick lookup of hostname -> first resolved IP from DNS step
$dnsIpLookup = @{}
foreach ($d in $dnsResults) {
    if ($d.IpAddresses -and $d.IpAddresses.Count -gt 0) {
        $dnsIpLookup[$d.Hostname.ToLower()] = $d.IpAddresses[0]
    }
}

if ($dnsPassedEndpoints.Count -eq 0) {
    Write-Result -Status "SKIP" -Check "No endpoints passed DNS -- skipping TCP tests"
} else {
    foreach ($ep in $dnsPassedEndpoints) {
        try {
            $tcpResult = Test-TcpConnectivity -Hostname $ep.Hostname -Port 443
            $tcpResult.Category = $ep.Category
            $tcpResult.ResolvedIP = if ($dnsIpLookup.ContainsKey($ep.Hostname.ToLower())) { $dnsIpLookup[$ep.Hostname.ToLower()] } else { "" }
            $tcpResults += $tcpResult
        }
        catch {
            $tcpResults += @{
                Hostname = $ep.Hostname
                Port = 443
                Category = $ep.Category
                Status = "FAIL"
                Detail = "Error during TCP test: $($_.Exception.Message)"
                Action = ""
                DurationMs = 0
                ResolvedIP = if ($dnsIpLookup.ContainsKey($ep.Hostname.ToLower())) { $dnsIpLookup[$ep.Hostname.ToLower()] } else { "" }
            }
        }
    }
}

# --- TCP progress line (always) ---
$tcpPassCount = @($tcpResults | Where-Object { $_.Status -eq "PASS" -or $_.Status -eq "INFO" }).Count
$tcpFailCount = @($tcpResults | Where-Object { $_.Status -eq "FAIL" }).Count
$tcpTotal = $tcpResults.Count

if ($tcpTotal -eq 0) {
    Write-ProgressLine -Name "TCP Connectivity" -Status "SKIP" -Summary "Skipped (DNS failed)"
} elseif ($tcpFailCount -gt 0) {
    Write-ProgressLine -Name "TCP Connectivity" -Status "FAIL" -Summary "$tcpPassCount/$tcpTotal reachable, $tcpFailCount blocked"
    Add-Diagnosis -Severity "BLOCKING" -Title "TCP Connection Failures (Port 443)" `
        -Summary "$tcpFailCount endpoint(s) blocked on port 443 (firewall or NSG)" `
        -Description "$tcpFailCount endpoint(s) blocked. A firewall or NSG is preventing outbound connections." `
        -Fix "Check NSG outbound rules, Azure Firewall, UDRs, and proxy settings for port 443." `
        -Docs "https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"
} else {
    Write-ProgressLine -Name "TCP Connectivity" -Status "OK" -Summary "$tcpPassCount/$tcpTotal reachable on :443"
}

# TCP results table (verbose output)
if ($VerboseOutput -and $tcpResults.Count -gt 0) {
    Write-HostLog "  TCP Connectivity Results:" -ForegroundColor Cyan
    Write-HostLog ""

    $catWidth = 24
    $hostWidth = 44
    $ipWidth = 16
    $latWidth = 10
    $statusWidth = 6

    $headerLine = "  {0,-$catWidth} {1,-$hostWidth} {2,-$ipWidth} {3,$latWidth} {4,-$statusWidth}" -f "Category", "Endpoint", "Resolved IP", "Latency", "Status"
    Write-HostLog $headerLine -ForegroundColor White
    $separatorLine = "  " + ("-" * $catWidth) + " " + ("-" * $hostWidth) + " " + ("-" * $ipWidth) + " " + ("-" * $latWidth) + " " + ("-" * $statusWidth)
    Write-HostLog $separatorLine -ForegroundColor DarkGray

    foreach ($r in $tcpResults) {
        $cat = $r.Category
        if ($cat.Length -gt $catWidth) { $cat = $cat.Substring(0, $catWidth - 2) + ".." }
        $host_ = $r.Hostname
        if ($host_.Length -gt $hostWidth) { $host_ = $host_.Substring(0, $hostWidth - 2) + ".." }
        $ip = if ($r.ResolvedIP) { $r.ResolvedIP } else { "--" }
        $latency = if ($r.Status -ne "FAIL") { "$($r.DurationMs)ms" } else { "-" }

        $row = "  {0,-$catWidth} {1,-$hostWidth} {2,-$ipWidth} {3,$latWidth} " -f $cat, $host_, $ip, $latency
        Write-HostLog $row -NoNewline
        switch ($r.Status) {
            "PASS" { Write-HostLog "PASS" -ForegroundColor Green }
            "INFO" { Write-HostLog "INFO" -ForegroundColor Yellow }
            "FAIL" { Write-HostLog "FAIL" -ForegroundColor Red }
            default { Write-HostLog $r.Status -ForegroundColor Gray }
        }
    }

    Write-HostLog $separatorLine -ForegroundColor DarkGray
    Write-HostLog ""

    # Summary line
    Write-HostLog "  Reachable: " -ForegroundColor Gray -NoNewline
    Write-HostLog "$tcpPassCount" -ForegroundColor Green -NoNewline
    Write-HostLog " / $tcpTotal" -ForegroundColor Gray -NoNewline
    if ($tcpFailCount -gt 0) {
        Write-HostLog "  |  Blocked: " -ForegroundColor Gray -NoNewline
        Write-HostLog "$tcpFailCount" -ForegroundColor Red
    } else {
        # Show latency range
        $latencies = @($tcpResults | Where-Object { $_.DurationMs -gt 0 } | ForEach-Object { $_.DurationMs })
        if ($latencies.Count -gt 0) {
            $minLat = ($latencies | Measure-Object -Minimum).Minimum
            $maxLat = ($latencies | Measure-Object -Maximum).Maximum
            $avgLat = [math]::Round(($latencies | Measure-Object -Average).Average)
            Write-HostLog "  |  Latency: ${minLat}-${maxLat}ms (avg: ${avgLat}ms)" -ForegroundColor Gray
        } else {
            Write-HostLog ""
        }
    }

    # Compact failure summary (grouped by category instead of per-endpoint spam)
    $tcpFailures = @($tcpResults | Where-Object { $_.Status -eq "FAIL" })
    if ($tcpFailures.Count -gt 0) {
        Write-HostLog ""
        Write-HostLog "  BLOCKED ENDPOINTS:" -ForegroundColor Red

        # Group failures by category for cleaner output
        $failuresByCategory = @{}
        foreach ($f in $tcpFailures) {
            $fCat = $f.Category
            if (-not $failuresByCategory.ContainsKey($fCat)) {
                $failuresByCategory[$fCat] = @()
            }
            $failuresByCategory[$fCat] += $f
        }

        foreach ($fCat in $failuresByCategory.Keys) {
            $fItems = $failuresByCategory[$fCat]
            $hostIpList = ($fItems | ForEach-Object {
                $ipSuffix = if ($_.ResolvedIP) { " ($($_.ResolvedIP))" } else { "" }
                "$($_.Hostname):443$ipSuffix"
            }) -join ", "
            Write-HostLog "    $fCat" -ForegroundColor Yellow
            Write-HostLog "      $hostIpList" -ForegroundColor Gray
        }

        # Single action block instead of repeating per endpoint
        Write-HostLog ""
        Write-HostLog "  ACTION:" -ForegroundColor Yellow
        Write-HostLog "    Verify outbound port 443 is open in NSG, firewall, and proxy rules for" -ForegroundColor Gray
        Write-HostLog "    the IPs listed above. If using AMPLS, verify private endpoints are healthy" -ForegroundColor Gray
        Write-HostLog "    with approved connection status." -ForegroundColor Gray
    }

    # High latency warnings
    $highLatency = @($tcpResults | Where-Object { $_.Status -eq "INFO" })
    if ($highLatency.Count -gt 0) {
        Write-HostLog ""
        Write-HostLog "  HIGH LATENCY DETECTED:" -ForegroundColor Yellow
        foreach ($h in $highLatency) {
            $ipNote = if ($h.ResolvedIP) { " ($($h.ResolvedIP))" } else { "" }
            Write-HostLog "    - $($h.Hostname)${ipNote}: $($h.DurationMs)ms" -ForegroundColor Gray
            if ($h.Action) { Write-HostLog "      $($h.Action)" -ForegroundColor DarkGray }
        }
    }
    Write-HostLog ""
}

# ============================================================================
# STEP 5: TLS Handshake Validation
# ============================================================================

$stepNumber++

$tlsResults = @()
$tcpPassed = @($tcpResults | Where-Object { $_.Status -eq "PASS" -or $_.Status -eq "INFO" })

# Check if the primary ingestion endpoint passed TCP -- if not, TLS and ingestion tests are pointless
$ingestionTcpPassed = @($tcpPassed | Where-Object { $_.Hostname -eq $ingestionHost })
$script:ingestionTcpBlocked = ($ingestionTcpPassed.Count -eq 0)

Write-ProgressStart -Name "TLS Handshake"

if ($script:ingestionTcpBlocked) {
    # Primary ingestion endpoint can't even TCP connect -- skip TLS entirely
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): TLS Handshake Validation [SKIPPED]"
        Write-HostLog ""
        Write-HostLog "  Skipping TLS handshake validation." -ForegroundColor Yellow
        Write-HostLog "  The primary ingestion endpoint ($ingestionHost) failed TCP connectivity." -ForegroundColor Gray
        Write-HostLog "  TLS cannot succeed without an open TCP connection." -ForegroundColor Gray
        Write-HostLog "  Resolve the TCP/firewall issue first, then re-run to validate TLS." -ForegroundColor Gray
        Write-HostLog ""
    }
    Write-ProgressLine -Name "TLS Handshake" -Status "SKIP" -Summary "Skipped (ingestion endpoint TCP blocked -- resolve firewall first)"
} else {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): TLS Handshake Validation"
        Write-HostLog ""
        Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
        Write-HostLog "  Azure Monitor requires TLS 1.2 or higher. TLS failures can occur when:" -ForegroundColor Gray
        Write-HostLog "    - Your OS/runtime defaults to older TLS versions (1.0 or 1.1)" -ForegroundColor Gray
        Write-HostLog "    - A TLS-inspecting proxy/firewall intercepts and re-signs traffic" -ForegroundColor Gray
        Write-HostLog "    - Certificate trust chain issues exist" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
        Write-HostLog "  - Can THIS machine negotiate TLS 1.2+ with Azure Monitor endpoints?" -ForegroundColor Gray
        Write-HostLog "  - Certificate issuer (Microsoft/DigiCert = direct, other = TLS inspection)" -ForegroundColor Gray
        Write-HostLog "  - Protocol versions this client can negotiate (1.2, 1.3)" -ForegroundColor Gray
        Write-HostLog "  - MITM/downgrade detection: deprecated protocols (1.0, 1.1) are also probed" -ForegroundColor Gray
        Write-HostLog "    with a short timeout -- a successful 1.0/1.1 handshake indicates a network" -ForegroundColor Gray
        Write-HostLog "    device is intercepting TLS before it reaches Azure Monitor" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  WHAT SUCCESS LOOKS LIKE:" -ForegroundColor Cyan
        Write-HostLog "  - TLS 1.2 negotiated successfully (minimum required by Azure Monitor)" -ForegroundColor Gray
        Write-HostLog "  - Certificate issued by Microsoft/DigiCert (not a proxy CA)" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  IF TLS 1.2 FAILS, CHECK:" -ForegroundColor Yellow
        Write-HostLog "  - .NET Framework TLS settings (SchUseStrongCrypto registry keys)" -ForegroundColor Gray
        Write-HostLog "  - Proxy/firewall TLS inspection bypass rules for Azure Monitor" -ForegroundColor Gray
        Write-HostLog "  - Root CA certificates are up to date (DigiCert Global Root G2)" -ForegroundColor Gray
        Write-HostLog ""
    }

    $tlsTargets = @($tcpPassed | Where-Object { $_.Category -match "Ingestion|Live Metrics" -and $_.Category -notmatch "Legacy" } | Select-Object -First 3)
    if ($tlsTargets.Count -eq 0) { $tlsTargets = $tcpPassed | Select-Object -First 2 }

foreach ($ep in $tlsTargets) {
    $tlsResult = Test-TlsHandshake -Hostname $ep.Hostname
    $tlsResult.Category = $ep.Category
    $tlsResults += $tlsResult
    Write-Result -Status $tlsResult.Status -Check "$($ep.Category): $($ep.Hostname)" `
        -Detail $tlsResult.Detail -Action $tlsResult.Action

    # Show per-version details in verbose output
    if ($VerboseOutput) {
        # Show deprecated protocol MITM detection results
        if ($tlsResult.DeprecatedAccepted -and $tlsResult.DeprecatedAccepted.Count -gt 0) {
            $depList = $tlsResult.DeprecatedAccepted -join ", "
            if ($tlsResult.DeprecatedAzureEdge) {
                Write-HostLog "      [?] UNEXPECTED: Deprecated protocol(s) accepted: $depList (Microsoft cert)" -ForegroundColor Yellow
                Write-HostLog "          Azure Monitor should reject TLS 1.0/1.1. The certificate is Microsoft-issued" -ForegroundColor Gray
                Write-HostLog "          (not a third-party proxy). If this persists, contact Microsoft support." -ForegroundColor Gray
            } else {
                Write-HostLog "      [!] SECURITY: Deprecated protocol(s) ACCEPTED: $depList" -ForegroundColor Red
                Write-HostLog "          Azure Monitor rejects TLS < 1.2. A successful handshake means a" -ForegroundColor Yellow
                Write-HostLog "          network device is terminating TLS before traffic reaches Azure." -ForegroundColor Yellow
            }
        }

        # Show TLS 1.3 failure reason (useful context, not a problem if 1.2 works)
        if ($tlsResult.FailedDetails -and $tlsResult.FailedDetails.Count -gt 0) {
            if ($tlsResult.FailedDetails["TLS 1.3"]) {
                Write-HostLog "      TLS 1.3 error: $($tlsResult.FailedDetails["TLS 1.3"])" -ForegroundColor DarkGray
            }
        }
    }
}

# TLS 1.3 context note (verbose output only -- single consolidated explanation)
if ($VerboseOutput) {
    $tls13NotNeg = $tlsResults | Where-Object { $_.TlsVersions["TLS 1.3"] -eq "NOT_NEGOTIATED" }
    $tls12OK = $tlsResults | Where-Object { $_.TlsVersions["TLS 1.2"] -eq "SUPPORTED" }
    if ($tls13NotNeg -and $tls12OK) {
        $isPSCore = $PSVersionTable.PSEdition -eq "Core"  # PowerShell 7+ = Core
        Write-HostLog ""
        if (-not $isPSCore) {
            Write-HostLog "  NOTE: TLS 1.3 'Not negotiated' is expected on PowerShell 5.1 / ISE." -ForegroundColor DarkGray
            Write-HostLog "  .NET Framework's SslStream does not support TLS 1.3 negotiation." -ForegroundColor DarkGray
            Write-HostLog "  Run in PowerShell 7+ (pwsh.exe) to test TLS 1.3." -ForegroundColor DarkGray
        } else {
            # PowerShell 7+ -- show the actual error and default negotiation result
            $firstResult = $tls13NotNeg | Select-Object -First 1
            $firstTls13Error = $firstResult.FailedDetails["TLS 1.3"]
            $defaultNeg = $firstResult.NegotiatedDefault

            Write-HostLog "  NOTE: TLS 1.3 could not be negotiated when explicitly requested (.NET $([System.Environment]::Version))." -ForegroundColor Yellow
            if ($firstTls13Error) {
                Write-HostLog "  Error: $firstTls13Error" -ForegroundColor DarkGray
            }
            if ($defaultNeg) {
                if ($defaultNeg -match "Tls13|1\.3") {
                    Write-HostLog "  However, OS auto-negotiation selected TLS 1.3 successfully." -ForegroundColor Green
                    Write-HostLog "  This means TLS 1.3 works in practice (SDKs use OS defaults, not forced versions)." -ForegroundColor DarkGray
                } else {
                    Write-HostLog "  OS auto-negotiation (SslProtocols.None) selected: $defaultNeg" -ForegroundColor DarkGray
                    Write-HostLog "  This is what SDKs will use in practice. Possible causes for no TLS 1.3:" -ForegroundColor Gray
                    Write-HostLog "    - Proxy/firewall stripping TLS 1.3 from handshake" -ForegroundColor Gray
                    Write-HostLog "    - OS TLS 1.3 disabled via registry or group policy" -ForegroundColor Gray
                    Write-HostLog "    - Cipher suite mismatch between SChannel and Azure endpoint" -ForegroundColor Gray
                }
            }
        }
        Write-HostLog "  TLS 1.2 is sufficient -- Azure Monitor requires TLS 1.2 as the minimum." -ForegroundColor DarkGray
        Write-HostLog ""
    }
}

# --- TLS progress line (always) ---
$tlsFailCount = @($tlsResults | Where-Object { $_.Status -eq "FAIL" }).Count
$tlsInfoCount = @($tlsResults | Where-Object { $_.Status -eq "INFO" }).Count
$tlsSummary = ""

if ($tlsResults.Count -eq 0) {
    Write-ProgressLine -Name "TLS Handshake" -Status "SKIP" -Summary "Skipped (no eligible endpoints to test)"
} elseif ($tlsFailCount -gt 0) {
    Write-ProgressLine -Name "TLS Handshake" -Status "FAIL" -Summary "TLS handshake failed"
    Add-Diagnosis -Severity "BLOCKING" -Title "TLS Handshake Failure" `
        -Summary "TLS connection failed (possible TLS inspection or cert issue)" `
        -Description "Could not establish TLS connection. Possible TLS inspection or certificate issue." `
        -Fix "Check for TLS-inspecting proxy/firewall, verify TLS 1.2 is enabled, update root CAs." `
        -Docs "https://learn.microsoft.com/azure/azure-monitor/fundamentals/azure-monitor-network-access"
} elseif ($tlsInfoCount -gt 0) {
    # Determine what triggered the WARN: TLS inspection, deprecated protocol acceptance, or both
    $tlsInspectionResult = $tlsResults | Where-Object { $_.TlsInspectionDetected } | Select-Object -First 1
    $deprecatedResult = $tlsResults | Where-Object { $_.DeprecatedAccepted -and $_.DeprecatedAccepted.Count -gt 0 } | Select-Object -First 1

    if ($tlsInspectionResult) {
        $detectedProxy = "Unknown"
        $detectedIssuer = "(unknown issuer)"
        if ($tlsInspectionResult.Action -match "proxy \(([^)]+)\)") { $detectedProxy = $Matches[1] }
        if ($tlsInspectionResult.CertIssuer) { $detectedIssuer = $tlsInspectionResult.CertIssuer }

        $tlsSummary = "TLS inspection detected ($detectedProxy)"
        if ($deprecatedResult) {
            $depList = $deprecatedResult.DeprecatedAccepted -join ", "
            $tlsSummary += " + deprecated protocol(s) accepted ($depList)"
        }
        Write-ProgressLine -Name "TLS Handshake" -Status "INFO" -Summary $tlsSummary
        Add-Diagnosis -Severity "INFO" -Title "TLS Inspection Detected ($detectedProxy)" `
            -Summary "TLS proxy re-signing traffic ($detectedProxy)" `
            -Description "Certificate issuer ($detectedIssuer) is not Microsoft/DigiCert. A TLS-inspecting proxy is re-signing HTTPS traffic. This can cause SDK certificate validation failures, telemetry drops, and increased latency." `
            -Fix "Configure a TLS inspection bypass for Azure Monitor endpoints: *.$domainAppInsights, *.$domainMonitor, *.in.$domainAppInsights" `
            -Docs "https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  TLS INSPECTION WARNING:" -ForegroundColor Yellow
            Write-HostLog "    Detected proxy: $detectedProxy" -ForegroundColor White
            Write-HostLog "    Certificate issuer: $detectedIssuer" -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "    A TLS-inspecting proxy is intercepting and re-signing HTTPS traffic" -ForegroundColor Gray
            Write-HostLog "    between this machine and Azure Monitor. This can cause:" -ForegroundColor Gray
            Write-HostLog "      - SDK certificate validation failures (if proxy CA not trusted)" -ForegroundColor Gray
            Write-HostLog "      - Silent telemetry drops (if proxy modifies or blocks payloads)" -ForegroundColor Gray
            Write-HostLog "      - Increased latency (extra TLS handshake through proxy)" -ForegroundColor Gray
            Write-HostLog "      - Live Metrics disconnections (proxy timeouts on long-lived connections)" -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "    RECOMMENDED: Add a TLS inspection bypass for Azure Monitor domains:" -ForegroundColor Cyan
            Write-HostLog "      *.$domainAppInsights" -ForegroundColor White
            Write-HostLog "      *.$domainMonitor" -ForegroundColor White
            if ($cloudSuffix -eq "com") {
                Write-HostLog "      *.services.visualstudio.com" -ForegroundColor White
            }
            Write-HostLog "      *.in.$domainAppInsights" -ForegroundColor White
            Write-HostLog ""
        }
    } elseif ($deprecatedResult) {
        # Deprecated protocol accepted WITHOUT cert inspection
        $depList = $deprecatedResult.DeprecatedAccepted -join ", "

        if ($deprecatedResult.DeprecatedAzureEdge) {
            # Microsoft cert + deprecated = unexpected; Azure Monitor should reject TLS < 1.2
            $tlsSummary = "Deprecated protocol(s) accepted: $depList (unexpected -- Microsoft cert)"
            Write-ProgressLine -Name "TLS Handshake" -Status "INFO" -Summary $tlsSummary
            Add-Diagnosis -Severity "INFO" -Title "Unexpected: Deprecated TLS Accepted with Microsoft Certificate ($depList)" `
                -Summary "Deprecated TLS accepted with Microsoft-issued certificate ($depList)" `
                -Description "A deprecated TLS handshake ($depList) succeeded and a Microsoft-issued certificate was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1. This is not a third-party proxy or MITM -- the certificate is legitimate -- but the behavior is unexpected." `
                -Fix "If this persists, contact Microsoft support and reference this diagnostic output." `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/best-practices-security"

            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  UNEXPECTED: DEPRECATED PROTOCOL ACCEPTED WITH MICROSOFT CERTIFICATE:" -ForegroundColor Yellow
                Write-HostLog "    Accepted: $depList" -ForegroundColor White
                Write-HostLog ""
                Write-HostLog "    A deprecated TLS handshake succeeded and a Microsoft-issued certificate" -ForegroundColor Gray
                Write-HostLog "    was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1." -ForegroundColor Gray
                Write-HostLog "    This is NOT a third-party proxy or MITM -- the certificate is legitimate --" -ForegroundColor Gray
                Write-HostLog "    but the behavior is unexpected." -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "    If this persists, contact Microsoft support and reference this output." -ForegroundColor Cyan
                Write-HostLog ""
            }
        } else {
            # Non-Microsoft cert + deprecated accepted -- real MITM/downgrade
            $tlsSummary = "Deprecated protocol(s) accepted: $depList -- possible MITM/proxy downgrade"
            Write-ProgressLine -Name "TLS Handshake" -Status "INFO" -Summary $tlsSummary
            Add-Diagnosis -Severity "INFO" -Title "Deprecated TLS Protocol Accepted ($depList)" `
                -Summary "Middlebox accepting deprecated TLS ($depList)" `
                -Description "This client successfully negotiated $depList with what should be an Azure Monitor endpoint. Azure Monitor rejects TLS < 1.2, so a successful deprecated handshake means a network device (proxy, firewall, or MITM appliance) is terminating TLS before traffic reaches Azure. Telemetry is being decrypted in transit by a middlebox." `
                -Fix "Investigate the network path for transparent proxies, firewall TLS inspection, or other devices intercepting HTTPS traffic. Configure bypass for Azure Monitor endpoints." `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/best-practices-security"

            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  DEPRECATED PROTOCOL ACCEPTANCE WARNING:" -ForegroundColor Yellow
                Write-HostLog "    Accepted: $depList" -ForegroundColor Red
                Write-HostLog ""
                Write-HostLog "    Azure Monitor rejects TLS 1.0 and 1.1. A successful handshake at these" -ForegroundColor Gray
                Write-HostLog "    versions means a device in the network path is terminating TLS before" -ForegroundColor Gray
                Write-HostLog "    traffic reaches Azure. This could be:" -ForegroundColor Gray
                Write-HostLog "      - A transparent proxy not visible in browser proxy settings" -ForegroundColor Gray
                Write-HostLog "      - A firewall performing TLS inspection/decryption" -ForegroundColor Gray
                Write-HostLog "      - A load balancer or network virtual appliance" -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "    SECURITY IMPACT:" -ForegroundColor Cyan
                Write-HostLog "      Telemetry data is being decrypted and re-encrypted in transit." -ForegroundColor Gray
                Write-HostLog "      The middlebox could be dropping, modifying, or logging telemetry." -ForegroundColor Gray
                Write-HostLog ""
            }
        }
    } else {
        # Generic WARN fallback
        $firstInfo = $tlsResults | Where-Object { $_.Status -eq "INFO" } | Select-Object -First 1
        Write-ProgressLine -Name "TLS Handshake" -Status "INFO" -Summary ($firstInfo.Detail -split " \| " | Select-Object -First 1)
    }
} else {
    # Build summary from first result
    $firstTls = $tlsResults[0]

    # Prefer the OS-negotiated default (what SDKs actually use) over the forced-version list
    if ($firstTls.NegotiatedDefault) {
        # Convert .NET enum name to friendly: "Tls12" -> "TLS 1.2", "Tls13" -> "TLS 1.3"
        $friendlyDefault = $firstTls.NegotiatedDefault -replace 'Tls13','TLS 1.3' -replace 'Tls12','TLS 1.2' -replace 'Tls11','TLS 1.1'
        $tlsVer = $friendlyDefault
    } elseif ($firstTls.SupportedVersions -and $firstTls.SupportedVersions.Count -gt 0) {
        $tlsVer = ($firstTls.SupportedVersions -join ", ")
    } else {
        $tlsVer = "connected"
    }
    $certInfo = ""
    if ($firstTls.CertIssuer -and $firstTls.CertIssuer -match "Microsoft|DigiCert") {
        $certInfo = ", Microsoft cert"
    } elseif ($firstTls.CertIssuer) {
        $certInfo = ", cert: $($firstTls.CertIssuer)"
    }
    Write-ProgressLine -Name "TLS Handshake" -Status "OK" -Summary "$tlsVer$certInfo"
}
} # end: else (ingestion TCP passed -- run TLS tests)

# ============================================================================
# STEP: AMPLS Validation (Optional, dynamic number)
# ============================================================================

$amplsCheckResults = @()

$amplsInfo = @{
    Checked = $false
    ResourceFound = $false
    AmplsLinked = $false
    AmplsDetails = @()
    ComparisonResults = @()
    AccessModes = @()
    AiIngestionAccess = $null
    AiQueryAccess = $null
    AccessAssessment = $null
}

# ---- Azure consent gate (verbose mode) ----
# Compact mode: consent was already handled before the progress table.
# Verbose mode: ask just-in-time, right before Azure resource queries begin.
if ($VerboseOutput -and $CheckAzure -and -not $NetworkOnly) {
    $azureConsent = Request-UserConsent `
        -RequiresAzureLogin `
        -PromptTitle "AZURE RESOURCE CHECKS -- YOUR CONSENT IS REQUIRED" `
        -PromptLines @(
            ""
            "The next set of checks require access to your Azure resources."
            "You will be asked to sign in to Azure if you are not already"
            "authenticated -- all queries run as YOU, using your own account"
            "and permissions. No resources will be modified."
            ""
            "What your account will be used to query:"
            ""
            "  * Azure Resource Graph -- locate your App Insights resource and"
            "    any AMPLS private link scope linked to it. Discover any workspace"
            "    transform data collection rules that may impact App Insights telemetry"
            ""
            "  * ARM REST API (read-only) -- inspect AMPLS access modes, private"
            "    endpoint DNS config, daily cap settings, diagnostic settings,"
            "    and Log Analytics workspace state"
            ""
            "  * Data plane (conditional) -- if a test telemetry record is sent and"
            "    successfully accepted by the ingestion endpoint, a single KQL"
            "    query will confirm whether the record arrived in your workspace"
        ) `
        -SkipHint "To skip Azure resource checks entirely, press N or re-run with -NetworkOnly." `
        -PromptQuestion "Proceed with Azure resource checks? [Y/N]"
    if (-not $azureConsent) {
        $CheckAzure = $false
        $script:AzureConsentDeclined = $true
    }
}

# Case 1: Manual AMPLS IP comparison (no Azure login)
if ($AmplsExpectedIps -and $AmplsExpectedIps.Count -gt 0) {
    $stepNumber++
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): AMPLS Validation (Manual IP Comparison)"
        Write-HostLog ""
        Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
        Write-HostLog "  You provided expected private endpoint IPs for your AMPLS configuration." -ForegroundColor Gray
        Write-HostLog "  We'll compare them against what DNS actually resolved on this machine." -ForegroundColor Gray
        Write-HostLog "  Mismatches mean this machine's DNS is not pointing to the correct private endpoints." -ForegroundColor Gray
        Write-HostLog ""
    }

    $amplsInfo.Checked = $true
    $manualMappings = @()
    foreach ($fqdn in $AmplsExpectedIps.Keys) {
        $manualMappings += @{ Fqdn = $fqdn; ExpectedIp = $AmplsExpectedIps[$fqdn]; PrivateEndpointName = "(manual)"; PrivateEndpointRg = "(manual)" }
    }

    if ($VerboseOutput) {
        Write-HostLog "  Comparing $($manualMappings.Count) FQDN(s) against DNS results..." -ForegroundColor Gray
        Write-HostLog ""
    }
    $amplsCheckResults = Show-AmplsValidationTable -ExpectedMappings $manualMappings -DnsResults $dnsResults
    $amplsInfo.ComparisonResults = $amplsCheckResults

    # Populate resolved IP registry from manual AMPLS validation results
    foreach ($cr in $amplsCheckResults) {
        if ($cr.ExpectedIp -and $script:ResolvedIpRegistry -notcontains $cr.ExpectedIp) {
            $script:ResolvedIpRegistry += $cr.ExpectedIp
        }
        if ($cr.ActualIp -and $cr.ActualIp -notmatch '^\(' -and $script:ResolvedIpRegistry -notcontains $cr.ActualIp) {
            $script:ResolvedIpRegistry += $cr.ActualIp
        }
    }

    $mismatches = @($amplsCheckResults | Where-Object { $_.Status -eq "MISMATCH" -or $_.Status -eq "FAIL" })
    if ($mismatches.Count -gt 0) {
        $matchCount = @($amplsCheckResults | Where-Object { $_.Status -eq "MATCH" }).Count
        Write-ProgressLine -Name "AMPLS IP Comparison" -Status "WARN" -Summary "$($mismatches.Count) mismatched, $matchCount matched"
        Add-Diagnosis -Severity "WARNING" -Title "AMPLS DNS Mismatches ($($mismatches.Count) of $($amplsCheckResults.Count) endpoints)" `
            -Summary "AMPLS DNS mismatches ($($mismatches.Count) of $($amplsCheckResults.Count) endpoints resolve to wrong IPs)" `
            -Description "This machine's DNS does not resolve to the expected AMPLS private endpoint IPs." `
            -Fix "Verify private DNS zones ($domainPrivateLink) are linked to your VNet. Flush DNS: ipconfig /flushdns" `
            -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"

        # Auto-trigger ghost AMPLS reverse lookup for IngestionEndpoint mismatch (manual mapping path)
        $ingestionMatch = Find-IngestionEndpointInAmplsResult -IngestionHost $ingestionHost -AmplsCheckResults $amplsCheckResults
        if ($ingestionMatch -and ($ingestionMatch.Status -eq "MISMATCH") -and $ingestionMatch.ActualIp -and $ingestionMatch.ActualIp -notmatch '^\(') {
            if ($ingestionMatch.ActualIp -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.') {
                $ghostResult = Find-AmplsByPrivateIp -TargetIp $ingestionMatch.ActualIp
                if ($ghostResult.Found) {
                    Write-HostLog ""
                    Write-HostLog "      INGESTION ENDPOINT MISMATCH -- AMPLS IDENTIFIED:" -ForegroundColor Cyan
                    Write-HostLog "        AMPLS Name:       $($ghostResult.AmplsName)" -ForegroundColor White
                    Write-HostLog "        Resource Group:   $($ghostResult.AmplsRg)" -ForegroundColor Gray
                    Write-HostLog "        Subscription:     $($ghostResult.AmplsSub)" -ForegroundColor Gray
                    Write-HostLog "        Private Endpoint: $($ghostResult.PeName) ($($ghostResult.PeRg))" -ForegroundColor Gray
                    Write-HostLog "        Access Modes:     Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)" -ForegroundColor Gray
                    Write-HostLog "        PE Expected IP:   $($ingestionMatch.ExpectedIp)  |  Actual DNS: $($ingestionMatch.ActualIp)" -ForegroundColor DarkGray

                    Add-Diagnosis -Severity "WARNING" -Title "Ghost AMPLS Overriding Ingestion Endpoint: $($ghostResult.AmplsName)" `
                        -Summary "Ingestion endpoint resolves to IP $($ingestionMatch.ActualIp) owned by AMPLS '$($ghostResult.AmplsName)'" `
                        -Description "The ingestion FQDN ($($ingestionMatch.Fqdn)) resolves to $($ingestionMatch.ActualIp) which belongs to PE '$($ghostResult.PeName)' connected to AMPLS '$($ghostResult.AmplsName)' (Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode))." `
                        -Fix "Add your App Insights resource to AMPLS '$($ghostResult.AmplsName)' or set its ingestion access mode to 'Open'." `
                        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                } else {
                    Write-HostLog ""
                    Write-HostLog "      The ingestion endpoint resolves to private IP $($ingestionMatch.ActualIp)" -ForegroundColor DarkGray
                    Write-HostLog "      but the owning private endpoint could not be identified." -ForegroundColor DarkGray
                }
            }
        }
    } else {
        $matched = @($amplsCheckResults | Where-Object { $_.Status -eq "MATCH" })
        Write-ProgressLine -Name "AMPLS IP Comparison" -Status "OK" -Summary "$($matched.Count)/$($amplsCheckResults.Count) matched"
    }
}

# Case 2: Automated AMPLS check via Azure login
elseif ($CheckAzure) {
    $stepNumber++
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): AMPLS Validation (Requires Login For Azure Resource Discovery)"
        Write-HostLog ""
        Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
        Write-HostLog "  This check authenticates to Azure and discovers whether your App Insights resource" -ForegroundColor Gray
        Write-HostLog "  is linked to an Azure Monitor Private Link Scope (AMPLS). If it is, we'll retrieve" -ForegroundColor Gray
        Write-HostLog "  the expected private endpoint IPs and compare them against DNS results from this machine." -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  WHAT WE'LL DO (all read-only, no modifications):" -ForegroundColor Cyan
        Write-HostLog "    1. Log you in via interactive browser (standard Azure AD flow)" -ForegroundColor Gray
        Write-HostLog "    2. Search Azure Resource Graph for your App Insights resource (by iKey)" -ForegroundColor Gray
        Write-HostLog "    3. Find any AMPLS resources linked to it" -ForegroundColor Gray
        Write-HostLog "    4. Retrieve private endpoint IP configurations" -ForegroundColor Gray
        Write-HostLog "    5. Compare expected IPs against DNS results from Step $dnsStepNumber" -ForegroundColor Gray
        Write-HostLog "    6. Report AMPLS access mode settings (Private Only vs Open)" -ForegroundColor Gray
        Write-HostLog ""
    }

    $amplsInfo.Checked = $true

    Write-ProgressStart -Name "AMPLS Configuration"

    # AMPLS check: Prerequisites
    if ($VerboseOutput) { Write-HostLog "  Checking prerequisites..." -ForegroundColor Gray }
    $prereqResult = Test-AmplsPrerequisite

    if (-not $prereqResult.Success) {
        $skipReason = if ($prereqResult.Detail -match "version conflict") { "Az module version conflict" }
                      elseif ($prereqResult.Detail -match "not found") { "Az modules not installed" }
                      else { "Az module load failed" }
        Write-ProgressLine -Name "Azure Resource Checks" -Status "SKIP" -Summary $skipReason
        if ($VerboseOutput) {
            Write-Result -Status "INFO" -Check "Azure module prerequisites not met" `
                -Detail $prereqResult.Detail -Action $prereqResult.Action
        }
    } else {
        if ($VerboseOutput) {
            if ($prereqResult.AccountsVersion) { Write-Result -Status "PASS" -Check "Az.Accounts module found (v$($prereqResult.AccountsVersion))" }
            if ($prereqResult.GraphVersion) { Write-Result -Status "PASS" -Check "Az.ResourceGraph module found (v$($prereqResult.GraphVersion))" }
        }

        # AMPLS check: Authenticate (with optional tenant targeting)
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        $needsLogin = $false

        if (-not $azContext) {
            $needsLogin = $true
        } elseif ($TenantId -and $azContext.Tenant.Id -ne $TenantId) {
            # User specified a tenant and current context is a different tenant
            if ($VerboseOutput) {
                Write-HostLog "  Current context is tenant $($azContext.Tenant.Id), switching to requested tenant $TenantId..." -ForegroundColor Gray
            }
            $needsLogin = $true
        }

        if ($needsLogin) {
            if ($script:IsNonInteractiveEnv) {
                # Non-interactive Azure PaaS -- interactive login would hang or fail
                $hostType = if ($envInfo.IsAppService) { "App Service" }
                            elseif ($envInfo.IsFunctionApp) { "Function App" }
                            elseif ($envInfo.IsContainerApp) { "Container Apps" }
                            elseif ($envInfo.IsKubernetes) { "AKS" }
                            else { "Azure PaaS" }
                Write-ProgressLine -Name "Azure Resource Checks" -Status "SKIP" -Summary "$hostType detected -- interactive login not available"
                if ($VerboseOutput) {
                    Write-Result -Status "INFO" -Check "Skipping Azure login ($hostType environment)" `
                        -Detail "Interactive login is not available in this environment. Azure resource checks require an active login context." `
                        -Action "Run this script from your local machine with Connect-AzAccount, or use -NetworkOnly to skip Azure checks."
                }
            } else {
                if ($VerboseOutput) { Write-HostLog "  Logging in to Azure..." -ForegroundColor Gray }
                try {
                    $connectParams = @{ ErrorAction = "Stop" }
                    if ($TenantId) { $connectParams["TenantId"] = $TenantId }
                    Connect-AzAccount @connectParams | Out-Null
                    $azContext = Get-AzContext
                } catch {
                    Write-ProgressLine -Name "Azure Resource Checks" -Status "FAIL" -Summary "Azure login failed"
                    if ($VerboseOutput) {
                        Write-Result -Status "FAIL" -Check "Azure login failed" -Detail $_.Exception.Message
                    }
                }
            }
        }

        if ($azContext) {
            if ($VerboseOutput) {
                Write-Result -Status "PASS" -Check "Logged in as $(Get-MaskedEmail $azContext.Account.Id)" `
                    -Detail "Tenant: $($azContext.Tenant.Id) | Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))"
            }

            # AMPLS check: Find the App Insights resource
            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  Searching for App Insights resource by InstrumentationKey..." -ForegroundColor Gray
            }
            $aiResource = Find-AppInsightsResource -InstrumentationKey $iKey

            if (-not $aiResource) {
                Write-ProgressLine -Name "Azure Resource Checks" -Status "INFO" -Summary "App Insights resource not found for this iKey"
                $notFoundDetail = "The resource may be in a different tenant or a subscription your account cannot access."
                $notFoundAction = "Ensure you have Reader access to the subscription containing this App Insights resource."
                if (-not $TenantId) {
                    $notFoundAction += " If your account spans multiple tenants, specify -TenantId to target the correct one."
                }
                Write-Result -Status "INFO" -Check "App Insights resource not found for iKey: $maskedKey" `
                    -Detail $notFoundDetail -Action $notFoundAction
                if (-not $TenantId) {
                    Add-Diagnosis -Severity "INFO" -Title "App Insights Resource Not Found" `
                        -Summary "Cannot find AI resource in tenant (wrong tenant?)" `
                        -Description "Could not find the AI resource in tenant $($azContext.Tenant.Id). If your account has access to multiple Entra ID tenants, re-run with -TenantId to target the correct tenant." `
                        -Fix "Re-run with -TenantId 'your-tenant-id-or-domain.onmicrosoft.com'" `
                        -Docs "https://learn.microsoft.com/powershell/azure/authenticate-azureps"
                }
            } else {
                $amplsInfo.ResourceFound = $true
                $aiName = $aiResource.name
                $aiRg = $aiResource.resourceGroup
                $aiSubId = $aiResource.subscriptionId
                $aiId = $aiResource.id

                Write-Result -Status "PASS" -Check "Found: $aiName" `
                    -Detail "Resource Group: $aiRg | Subscription: $aiSubId | Location: $($aiResource.location)"

                # ---- Refresh properties via direct ARM call (ARG cache may be stale) ----
                try {
                    $armApiPath = "${aiId}?api-version=2020-02-02"
                    Write-DebugAzRest -Method "GET" -Path $armApiPath
                    $armResponse = Invoke-AzRestMethod -Path $armApiPath -Method GET -ErrorAction Stop
                    Write-DebugResponse -Status "HTTP $($armResponse.StatusCode)" -Body $armResponse.Content

                    if ($armResponse.StatusCode -eq 200) {
                        $armObj = $armResponse.Content | ConvertFrom-Json -ErrorAction Stop
                        if ($armObj.properties) {
                            $aiResource | Add-Member -MemberType NoteProperty -Name "properties" -Value $armObj.properties -Force
                            if ($VerboseOutput) {
                                Write-HostLog "    Refreshed resource properties via ARM (bypassing ARG cache)" -ForegroundColor DarkGray
                            }
                        }
                    }
                } catch {
                    if ($VerboseOutput) {
                        Write-HostLog "    Note: ARM refresh failed, using ARG-cached properties: $($_.Exception.Message)" -ForegroundColor DarkGray
                    }
                }

                # Extract App Insights network isolation settings
                $aiPublicIngestion = "Enabled"
                $aiPublicQuery = "Enabled"
                try {
                    $aiProps = $aiResource.properties
                    if ($aiProps.publicNetworkAccessForIngestion) {
                        $aiPublicIngestion = $aiProps.publicNetworkAccessForIngestion
                    }
                    if ($aiProps.publicNetworkAccessForQuery) {
                        $aiPublicQuery = $aiProps.publicNetworkAccessForQuery
                    }
                } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }
                $amplsInfo.AiIngestionAccess = $aiPublicIngestion
                $amplsInfo.AiQueryAccess = $aiPublicQuery

                # Switch context if needed
                $currentContext = Get-AzContext
                if ($currentContext.Subscription.Id -ne $aiSubId) {
                    try {
                        Set-AzContext -SubscriptionId $aiSubId -ErrorAction Stop | Out-Null
                        Write-Result -Status "INFO" -Check "Switched to subscription: $aiSubId"
                    } catch {
                        Write-Result -Status "INFO" -Check "Could not switch to subscription $aiSubId" `
                            -Detail "AMPLS discovery may be incomplete if the AMPLS is in a different subscription."
                    }
                }

                # AMPLS check: Find AMPLS associations
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  Searching for linked AMPLS resources..." -ForegroundColor Gray
                }
                $amplsList = Find-AmplsForResource -AiResourceProperties $aiResource.properties

                if (-not $amplsList -or $amplsList.Count -eq 0) {
                    Write-Result -Status "INFO" -Check "No AMPLS found linked to this App Insights resource" `
                        -Detail "This resource expects telemetry over public endpoints."

                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  WHAT THIS MEANS:" -ForegroundColor Cyan
                        Write-HostLog "  Your App Insights resource is NOT behind a Private Link Scope." -ForegroundColor Gray
                        Write-HostLog "  Telemetry should flow over public Microsoft IPs." -ForegroundColor Gray

                        if ($hasAmplsSignals) {
                            Write-HostLog ""
                            Write-HostLog "  [!] " -ForegroundColor Yellow -NoNewline
                            Write-HostLog "WARNING: DNS resolved some endpoints to PRIVATE IPs in Step $dnsStepNumber," -ForegroundColor Yellow
                            Write-HostLog "      but this App Insights resource is NOT linked to any AMPLS." -ForegroundColor Yellow
                            Write-HostLog "      This means another AMPLS on this VNet is overriding DNS for Azure Monitor endpoints." -ForegroundColor Yellow
                            Write-HostLog "      Telemetry may be routing to the wrong private endpoint and getting rejected." -ForegroundColor Yellow
                            Write-HostLog ""
                            Write-HostLog "      ACTION: Find the AMPLS that owns the private endpoint on this VNet and either:" -ForegroundColor Yellow
                            Write-HostLog "        (a) Add this App Insights resource to that AMPLS scope, or" -ForegroundColor Yellow
                            Write-HostLog "        (b) Set the AMPLS ingestion access mode to 'Open' to allow public fallback" -ForegroundColor Yellow
                        }
                    }

                    if ($hasAmplsSignals) {
                        Add-Diagnosis -Severity "WARNING" -Title "Ghost AMPLS: Private IPs but Resource Not in AMPLS" `
                            -Summary "Private IPs detected but resource not linked to any AMPLS" `
                            -Description "DNS resolves to private IPs, but $aiName is NOT linked to any AMPLS. Another AMPLS is overriding DNS." `
                            -Fix "Add this App Insights resource to the AMPLS that owns the private endpoint on this VNet." `
                            -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"

                        # Auto-trigger ghost AMPLS reverse lookup for ingestion endpoint IP
                        $ingDnsResult = $dnsResults | Where-Object { $_.Hostname -eq $ingestionHost -and $_.Status -eq "PASS" } | Select-Object -First 1
                        $autoLookupIp = $null
                        if ($ingDnsResult -and $ingDnsResult.IsPrivateIp -and $ingDnsResult.IpAddresses -and $ingDnsResult.IpAddresses.Count -gt 0) {
                            $autoLookupIp = $ingDnsResult.IpAddresses[0]
                        }
                        if ($autoLookupIp) {
                            $ghostResult = Find-AmplsByPrivateIp -TargetIp $autoLookupIp
                            if ($ghostResult.Found) {
                                Write-HostLog ""
                                Write-HostLog "      AMPLS IDENTIFIED: " -ForegroundColor Cyan -NoNewline
                                Write-HostLog "$($ghostResult.AmplsName)" -ForegroundColor White
                                Write-HostLog "        Resource Group:   $($ghostResult.AmplsRg)" -ForegroundColor Gray
                                Write-HostLog "        Subscription:     $($ghostResult.AmplsSub)" -ForegroundColor Gray
                                Write-HostLog "        Private Endpoint: $($ghostResult.PeName) ($($ghostResult.PeRg))" -ForegroundColor Gray
                                Write-HostLog "        Access Modes:     Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)" -ForegroundColor Gray
                                Write-HostLog "        Looked up IP:     $autoLookupIp (resolved for $ingestionHost)" -ForegroundColor DarkGray
                                Write-HostLog ""
                                Write-HostLog "      This AMPLS owns the private endpoint that is overriding DNS for your ingestion endpoint." -ForegroundColor Yellow
                                Write-HostLog "      Add $aiName to this AMPLS, or set its ingestion access mode to 'Open'." -ForegroundColor Yellow

                                Add-Diagnosis -Severity "WARNING" -Title "Ghost AMPLS Identified: $($ghostResult.AmplsName)" `
                                    -Summary "AMPLS '$($ghostResult.AmplsName)' in RG '$($ghostResult.AmplsRg)' owns the PE overriding ingestion DNS" `
                                    -Description "The private IP $autoLookupIp (resolved for $ingestionHost) belongs to a private endpoint ($($ghostResult.PeName)) connected to AMPLS '$($ghostResult.AmplsName)' (Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)). This AMPLS is not linked to $aiName but its private endpoint overrides DNS." `
                                    -Fix "Add $aiName to AMPLS '$($ghostResult.AmplsName)' or set its ingestion access mode to 'Open'." `
                                    -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                            } else {
                                Write-HostLog ""
                                Write-HostLog "      The private endpoint for IP $autoLookupIp could not be identified." -ForegroundColor DarkGray
                                Write-HostLog "      It may be in a subscription your account cannot access, or the private" -ForegroundColor DarkGray
                                Write-HostLog "      DNS zone may have been configured manually." -ForegroundColor DarkGray
                            }
                        }
                    }
                } else {
                    $amplsInfo.AmplsLinked = $true
                    Write-Result -Status "PASS" -Check "Found $($amplsList.Count) linked AMPLS resource(s)"

                    $amplsIndex = 0
                    $anyMismatches = $false
                    $anyPrivateOnly = $false

                    foreach ($ampls in $amplsList) {
                        $amplsIndex++
                        $amplsName = $ampls.name
                        $amplsRg = $ampls.resourceGroup
                        $amplsId = $ampls.id

                        # AMPLS check: Get access mode
                        $accessMode = Get-AmplsAccessMode -AmplsResourceId $amplsId -AmplsProperties $ampls.properties
                        $amplsInfo.AccessModes += @{
                            AmplsName = $amplsName
                            IngestionAccessMode = $accessMode.IngestionAccessMode
                            QueryAccessMode = $accessMode.QueryAccessMode
                        }

                        # Determine mode summary
                        $ingMode = $accessMode.IngestionAccessMode
                        $qMode = $accessMode.QueryAccessMode
                        if ($ingMode -eq "PrivateOnly" -or $qMode -eq "PrivateOnly") { $anyPrivateOnly = $true }

                        $modeParts = @()
                        if ($ingMode -eq $qMode) {
                            $modeParts += "$ingMode (ingestion + query)"
                        } else {
                            $modeParts += "Ingestion: $ingMode"
                            $modeParts += "Query: $qMode"
                        }
                        $modeSummary = $modeParts -join " | "

                        if ($VerboseOutput) {
                            Write-HostLog ""
                            $amplsLabel = "  AMPLS [$amplsIndex/$($amplsList.Count)]: "
                            Write-HostLog $amplsLabel -ForegroundColor Cyan -NoNewline
                            Write-HostLog "$amplsName " -ForegroundColor White -NoNewline
                            Write-HostLog "($amplsRg)" -ForegroundColor DarkGray

                            $modeColor = if ($ingMode -eq "PrivateOnly" -or $qMode -eq "PrivateOnly") { "Yellow" } else { "Green" }
                            Write-HostLog "    Access Mode: " -ForegroundColor Gray -NoNewline
                            Write-HostLog $modeSummary -ForegroundColor $modeColor

                            # Access mode explanation - framed as outbound network policy
                            if ($ingMode -eq "PrivateOnly" -and $qMode -eq "PrivateOnly") {
                                Write-HostLog "    ==> Clients on this VNet can ONLY reach Azure Monitor resources scoped to this AMPLS." -ForegroundColor Yellow
                                Write-HostLog "        Unscoped/public resources are blocked from this network, even if they accept public traffic." -ForegroundColor Yellow
                            } elseif ($ingMode -eq "PrivateOnly" -or $qMode -eq "PrivateOnly") {
                                if ($ingMode -eq "PrivateOnly") {
                                    Write-HostLog "    ==> Ingestion: Clients on this VNet can ONLY send telemetry to AMPLS-scoped resources." -ForegroundColor Yellow
                                }
                                if ($qMode -eq "PrivateOnly") {
                                    Write-HostLog "    ==> Query: Clients on this VNet can ONLY query AMPLS-scoped resources." -ForegroundColor Yellow
                                }
                                if ($ingMode -eq "Open") {
                                    Write-HostLog "    ==> Ingestion: Clients on this VNet can send telemetry to both scoped and public resources." -ForegroundColor Green
                                }
                                if ($qMode -eq "Open") {
                                    Write-HostLog "    ==> Query: Clients on this VNet can query both scoped and public resources." -ForegroundColor Green
                                }
                            } else {
                                Write-HostLog "    ==> Clients on this VNet can reach both AMPLS-scoped and public Azure Monitor resources." -ForegroundColor Green
                            }
                        }

                        # AMPLS check: Get private endpoint IPs
                        $peResults = Get-AmplsPrivateEndpoint -AmplsResourceId $amplsId

                        if ($peResults.PrivateEndpoints.Count -gt 0) {
                            $peMappings = @()
                            foreach ($pe in $peResults.PrivateEndpoints) {
                                foreach ($dns in $pe.DnsConfigs) {
                                    $peMappings += @{
                                        Fqdn = $dns.Fqdn
                                        ExpectedIp = $dns.IpAddress
                                        PrivateEndpointName = $pe.Name
                                        PrivateEndpointRg = $pe.ResourceGroup
                                    }
                                }
                            }

                            if ($peMappings.Count -gt 0) {
                                if ($VerboseOutput) {
                                    $peNames = ($peResults.PrivateEndpoints | ForEach-Object { $_.Name }) -join ", "
                                    Write-HostLog "    Private Endpoint: " -ForegroundColor Gray -NoNewline
                                    Write-HostLog "$peNames " -ForegroundColor White -NoNewline
                                    Write-HostLog "($($peMappings.Count) DNS mappings)" -ForegroundColor DarkGray
                                    Write-HostLog ""
                                }

                                $amplsCheckResults = Show-AmplsValidationTable -ExpectedMappings $peMappings -DnsResults $dnsResults
                                $amplsInfo.ComparisonResults += $amplsCheckResults

                                # Populate resolved IP registry from AMPLS PE validation results
                                foreach ($cr in $amplsCheckResults) {
                                    if ($cr.ExpectedIp -and $script:ResolvedIpRegistry -notcontains $cr.ExpectedIp) {
                                        $script:ResolvedIpRegistry += $cr.ExpectedIp
                                    }
                                    if ($cr.ActualIp -and $cr.ActualIp -notmatch '^\(' -and $script:ResolvedIpRegistry -notcontains $cr.ActualIp) {
                                        $script:ResolvedIpRegistry += $cr.ActualIp
                                    }
                                }

                                $amplsInfo.AmplsDetails += @{
                                    AmplsName = $amplsName
                                    PrivateEndpoints = $peResults.PrivateEndpoints
                                    ComparisonResults = $amplsCheckResults
                                }

                                # Check for mismatches
                                $mismatches = @($amplsCheckResults | Where-Object { $_.Status -eq "MISMATCH" -or $_.Status -eq "FAIL" })

                                if ($mismatches.Count -gt 0) {
                                    $anyMismatches = $true
                                    if ($VerboseOutput) {
                                        $matchedCount = @($amplsCheckResults | Where-Object { $_.Status -eq "MATCH" }).Count
                                        Write-HostLog "    ==> " -ForegroundColor Red -NoNewline
                                        Write-HostLog "$($mismatches.Count) mismatched" -ForegroundColor Red -NoNewline
                                        Write-HostLog ", $matchedCount matched" -ForegroundColor Gray
                                    }

                                    # Auto-trigger ghost AMPLS reverse lookup for IngestionEndpoint mismatch
                                    $ingestionMatch = Find-IngestionEndpointInAmplsResult -IngestionHost $ingestionHost -AmplsCheckResults $amplsCheckResults
                                    if ($ingestionMatch -and ($ingestionMatch.Status -eq "MISMATCH") -and $ingestionMatch.ActualIp -and $ingestionMatch.ActualIp -notmatch '^\(') {
                                        $ghostResult = Find-AmplsByPrivateIp -TargetIp $ingestionMatch.ActualIp
                                        if ($ghostResult.Found) {
                                            Write-HostLog ""
                                            Write-HostLog "      INGESTION ENDPOINT MISMATCH -- AMPLS IDENTIFIED:" -ForegroundColor Cyan
                                            Write-HostLog "        AMPLS Name:       $($ghostResult.AmplsName)" -ForegroundColor White
                                            Write-HostLog "        Resource Group:   $($ghostResult.AmplsRg)" -ForegroundColor Gray
                                            Write-HostLog "        Subscription:     $($ghostResult.AmplsSub)" -ForegroundColor Gray
                                            Write-HostLog "        Private Endpoint: $($ghostResult.PeName) ($($ghostResult.PeRg))" -ForegroundColor Gray
                                            Write-HostLog "        Access Modes:     Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)" -ForegroundColor Gray
                                            Write-HostLog "        PE Expected IP:   $($ingestionMatch.ExpectedIp)  |  Actual DNS: $($ingestionMatch.ActualIp)" -ForegroundColor DarkGray
                                            Write-HostLog ""
                                            Write-HostLog "      The ingestion endpoint ($ingestionHost) resolves to $($ingestionMatch.ActualIp)" -ForegroundColor Yellow
                                            Write-HostLog "      instead of the expected $($ingestionMatch.ExpectedIp) from AMPLS '$amplsName'." -ForegroundColor Yellow
                                            Write-HostLog "      A different AMPLS ('$($ghostResult.AmplsName)') owns the private endpoint at that IP." -ForegroundColor Yellow

                                            Add-Diagnosis -Severity "WARNING" -Title "Ghost AMPLS Overriding Ingestion Endpoint: $($ghostResult.AmplsName)" `
                                                -Summary "Ingestion endpoint resolves to IP $($ingestionMatch.ActualIp) owned by AMPLS '$($ghostResult.AmplsName)' instead of '$amplsName'" `
                                                -Description "The ingestion FQDN ($($ingestionMatch.Fqdn)) resolves to $($ingestionMatch.ActualIp) which belongs to PE '$($ghostResult.PeName)' connected to AMPLS '$($ghostResult.AmplsName)' (Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)). Expected IP was $($ingestionMatch.ExpectedIp) from '$amplsName'." `
                                                -Fix "Ensure only one AMPLS private endpoint is authoritative for ingestion DNS, or add $aiName to AMPLS '$($ghostResult.AmplsName)'." `
                                                -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                                        } elseif ($ingestionMatch.ActualIp -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.') {
                                            Write-HostLog ""
                                            Write-HostLog "      The ingestion endpoint ($ingestionHost) resolves to private IP $($ingestionMatch.ActualIp)" -ForegroundColor DarkGray
                                            Write-HostLog "      but the owning private endpoint could not be identified. It may be in a" -ForegroundColor DarkGray
                                            Write-HostLog "      subscription your account cannot access." -ForegroundColor DarkGray
                                        }
                                    }
                                } else {
                                    if ($VerboseOutput) {
                                        $matchedEntries = @($amplsCheckResults | Where-Object { $_.Status -eq "MATCH" })
                                        if ($matchedEntries.Count -gt 0) {
                                            Write-HostLog "    ==> " -ForegroundColor Green -NoNewline
                                            Write-HostLog "All $($matchedEntries.Count) DNS entries match. Private link is correctly configured." -ForegroundColor Green
                                        }
                                    }
                                }
                            }
                        } else {
                            if ($VerboseOutput) {
                                Write-HostLog "    Private Endpoint: " -ForegroundColor Gray -NoNewline
                                Write-HostLog "(no private endpoints found)" -ForegroundColor DarkGray
                                Write-HostLog ""
                                Write-HostLog "    This AMPLS resource exists but has not been connected to a Private Endpoint" -ForegroundColor DarkGray
                                Write-HostLog "    or VNet. Without a Private Endpoint, no private DNS zones are created and" -ForegroundColor DarkGray
                                Write-HostLog "    no traffic will route through this AMPLS. To complete the setup, create a" -ForegroundColor DarkGray
                                Write-HostLog "    Private Endpoint and link it to a VNet." -ForegroundColor DarkGray
                                Write-HostLog "    Docs: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure" -ForegroundColor DarkGray
                            }
                        }
                    }

                    # Show COMMON CAUSES + RESOLUTION STEPS once after all AMPLS blocks (if any mismatches)
                    if ($VerboseOutput -and $anyMismatches) {
                        Write-HostLog ""
                        Write-HostLog "  =========================================================================" -ForegroundColor DarkGray
                        Write-HostLog "  DNS MISMATCH TROUBLESHOOTING" -ForegroundColor Red
                        Write-HostLog "  =========================================================================" -ForegroundColor DarkGray
                        Write-HostLog ""
                        Write-HostLog "  This machine's DNS is NOT resolving to the expected AMPLS private IPs." -ForegroundColor Gray
                        if ($anyPrivateOnly) {
                            Write-HostLog "  At least one AMPLS uses 'PrivateOnly' mode -- clients on that VNet" -ForegroundColor Yellow
                            Write-HostLog "  will be BLOCKED from reaching unscoped Azure Monitor resources." -ForegroundColor Yellow
                        }
                        Write-HostLog ""
                        Write-HostLog "  COMMON CAUSES:" -ForegroundColor Cyan
                        Write-HostLog "    1. Private DNS zones ($domainPrivateLink) not linked to this VNet" -ForegroundColor Gray
                        Write-HostLog "    2. Custom DNS server not forwarding to Azure DNS (168.63.129.16)" -ForegroundColor Gray
                        Write-HostLog "    3. Another AMPLS private endpoint is overriding DNS for this VNet" -ForegroundColor Gray
                        Write-HostLog "    4. Stale DNS cache on this machine (try: ipconfig /flushdns)" -ForegroundColor Gray
                        Write-HostLog "    5. Private DNS zone A records are missing or incorrect" -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  RESOLUTION STEPS:" -ForegroundColor Cyan
                        Write-HostLog "    1. Azure Portal > Private DNS zones > $domainPrivateLink" -ForegroundColor Gray
                        Write-HostLog "    2. Verify A records exist for each mismatched FQDN above" -ForegroundColor Gray
                        Write-HostLog "    3. Verify the zone is linked to the VNet this machine is connected to" -ForegroundColor Gray
                        Write-HostLog "    4. If using custom DNS: verify conditional forwarder for $domainMonitor" -ForegroundColor Gray
                        Write-HostLog "       points to Azure DNS (168.63.129.16)" -ForegroundColor Gray
                        Write-HostLog "    5. Flush DNS on this machine and re-run this script" -ForegroundColor Gray
                        Write-HostLog "    6. If DNS records are still stale, remove and re-add the Azure Monitor resource" -ForegroundColor Gray
                        Write-HostLog "       in the AMPLS to force a Private DNS zone refresh. This triggers AMPLS to" -ForegroundColor Gray
                        Write-HostLog "       re-broadcast the required A records to the linked Private DNS zone." -ForegroundColor Gray
                        Write-HostLog "       Docs: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure#connect-resources-to-the-ampls" -ForegroundColor Gray
                        Write-HostLog ""
                    } elseif ($VerboseOutput -and -not $anyMismatches) {
                        Write-HostLog ""
                    }
                }

                # =====================================================================
                # NETWORK ACCESS ASSESSMENT
                # =====================================================================

                # Determine this machine's network position
                $clientNetType = "Public"
                $clientIngestionIp = "(unknown)"
                $clientDnsMatchesAmpls = $false

                $ingestionDnsResult = $null
                foreach ($dr in $dnsResults) {
                    if ($dr.Hostname -eq $ingestionHost -and $dr.Status -eq "PASS") {
                        $ingestionDnsResult = $dr
                        break
                    }
                }

                if ($ingestionDnsResult) {
                    if ($ingestionDnsResult.IpAddresses -and $ingestionDnsResult.IpAddresses.Count -gt 0) {
                        $clientIngestionIp = $ingestionDnsResult.IpAddresses[0]
                    }
                    if ($ingestionDnsResult.IsPrivateIp) {
                        $clientNetType = "Private"
                        if ($amplsCheckResults) {
                            foreach ($cr in $amplsCheckResults) {
                                if ($cr.Status -eq "MATCH") {
                                    $clientDnsMatchesAmpls = $true
                                    break
                                }
                            }
                        }
                    }
                } elseif (-not $ingestionDnsResult) {
                    $clientNetType = "Unknown (DNS failed)"
                }

                # Gather AMPLS access mode settings
                $amplsDisplayName = "None linked"
                if ($amplsInfo.AccessModes -and $amplsInfo.AccessModes.Count -gt 0) {
                    $amplsDisplayName = $amplsInfo.AccessModes[0].AmplsName
                }

                # Compute verdicts
                $ingestionVerdict = "UNKNOWN"
                $ingestionReason = ""
                $ingestionFix = @()
                $queryVerdict = "UNKNOWN"
                $queryReason = ""
                $queryFix = @()

                if ($clientNetType -eq "Unknown (DNS failed)") {
                    $ingestionVerdict = "BLOCKED"
                    $ingestionReason = "DNS resolution failed for the ingestion endpoint."
                    $ingestionFix = @("Fix DNS resolution first. See the DNS failures above.")
                    $queryVerdict = "BLOCKED"
                    $queryReason = "DNS resolution failed."
                    $queryFix = @("Fix DNS resolution first.")
                }
                elseif (-not $amplsInfo.AmplsLinked) {
                    if ($clientNetType -eq "Private") {
                        $ingestionVerdict = "BLOCKED"
                        $ingestionReason = "DNS resolves to private IPs, but this App Insights resource is NOT in any AMPLS. Another AMPLS is overriding DNS."
                        $ingestionFix = @(
                            "Add this App Insights resource to the AMPLS that owns the private endpoint on this VNet.",
                            "Or change that AMPLS ingestion access mode to 'Open'."
                        )
                        $queryVerdict = "BLOCKED"
                        $queryReason = $ingestionReason
                        $queryFix = $ingestionFix
                    } else {
                        if ($aiPublicIngestion -eq "Enabled") {
                            $ingestionVerdict = "ALLOWED"
                            $ingestionReason = "No AMPLS configured. App Insights accepts ingestion from all networks."
                        } else {
                            $ingestionVerdict = "BLOCKED"
                            $ingestionReason = "Ingestion restricted to private networks, but no AMPLS configured."
                            $ingestionFix = @(
                                "Enable public ingestion, or configure AMPLS with a private endpoint."
                            )
                        }
                        if ($aiPublicQuery -eq "Enabled") {
                            $queryVerdict = "ALLOWED"
                            $queryReason = "No AMPLS configured. App Insights accepts queries from all networks."
                        } else {
                            $queryVerdict = "BLOCKED"
                            $queryReason = "Query access restricted to private networks, but no AMPLS configured."
                            $queryFix = @(
                                "Enable public query access, or configure AMPLS with a private endpoint."
                            )
                        }
                    }
                }
                elseif ($clientNetType -eq "Private" -and $clientDnsMatchesAmpls) {
                    $ingestionVerdict = "ALLOWED"
                    $ingestionReason = "On AMPLS-connected private network. DNS matches private endpoint."
                    $queryVerdict = "ALLOWED"
                    $queryReason = "On AMPLS-connected private network. Queries flow through private link."
                }
                elseif ($clientNetType -eq "Private" -and -not $clientDnsMatchesAmpls) {
                    $ingestionVerdict = "BLOCKED"
                    $ingestionReason = "Private IPs don't match AMPLS. Traffic going to wrong private endpoint or DNS is stale."
                    $ingestionFix = @(
                        "Verify private DNS zones are linked to VNet. Flush DNS: ipconfig /flushdns"
                    )
                    $queryVerdict = "BLOCKED"
                    $queryReason = $ingestionReason
                    $queryFix = $ingestionFix
                }
                else {
                    # Public client with AMPLS linked
                    if ($aiPublicIngestion -eq "Enabled") {
                        $ingestionVerdict = "ALLOWED"
                        $ingestionReason = "Public network. App Insights accepts ingestion from all networks."
                    } else {
                        $ingestionVerdict = "BLOCKED"
                        $ingestionReason = "Public network, but App Insights has public ingestion disabled (HTTP 403)."
                        $ingestionFix = @(
                            "Run from AMPLS-connected VNet, or enable public ingestion."
                        )
                    }
                    if ($aiPublicQuery -eq "Enabled") {
                        $queryVerdict = "ALLOWED"
                        $queryReason = "Public network. App Insights accepts queries from all networks."
                    } else {
                        $queryVerdict = "BLOCKED"
                        $queryReason = "Public network, but App Insights has public query access disabled."
                        $queryFix = @(
                            "Access Portal from AMPLS-connected VNet, or enable public queries."
                        )
                    }
                }

                $amplsInfo.AccessAssessment = @{
                    ClientNetworkType = $clientNetType
                    ClientIngestionIp = $clientIngestionIp
                    ClientDnsMatchesAmpls = $clientDnsMatchesAmpls
                    AiIngestionAccess = $aiPublicIngestion
                    AiQueryAccess = $aiPublicQuery
                    IngestionVerdict = $ingestionVerdict
                    QueryVerdict = $queryVerdict
                }

                # --- AMPLS progress lines (always, BEFORE verbose display) ---
                if ($amplsInfo.AmplsLinked) {
                    # Use accumulated results across ALL AMPLS (not just the last one)
                    $allAmplsResults = @($amplsInfo.ComparisonResults)
                    $ampMismatches = @($allAmplsResults | Where-Object { $_.Status -eq "MISMATCH" -or $_.Status -eq "FAIL" })
                    $ampMatches = @($allAmplsResults | Where-Object { $_.Status -eq "MATCH" })
                    $modeNote = ""
                    if ($anyPrivateOnly) { $modeNote = " (PrivateOnly mode)" }

                    if ($ampMismatches.Count -gt 0) {
                        Write-ProgressLine -Name "AMPLS Configuration" -Status "WARN" -Summary "$($ampMismatches.Count) DNS mismatches$modeNote"
                        Add-Diagnosis -Severity "WARNING" -Title "AMPLS DNS Mismatches ($($ampMismatches.Count) of $($allAmplsResults.Count) endpoints)" `
                            -Summary "AMPLS DNS mismatches ($($ampMismatches.Count) of $($allAmplsResults.Count) endpoints resolve to wrong IPs)" `
                            -Description "This machine's DNS does not resolve to the expected AMPLS private endpoint IPs." `
                            -Fix "Verify private DNS zones ($domainPrivateLink) are linked to your VNet. Flush DNS: ipconfig /flushdns" `
                            -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                    } elseif ($ampMatches.Count -gt 0) {
                        Write-ProgressLine -Name "AMPLS Configuration" -Status "OK" -Summary "$($ampMatches.Count) IPs matched ($amplsDisplayName)$modeNote"
                    } else {
                        Write-ProgressLine -Name "AMPLS Configuration" -Status "OK" -Summary "Linked to $amplsDisplayName$modeNote"
                    }
                } else {
                    if ($hasAmplsSignals) {
                        Write-ProgressLine -Name "AMPLS Configuration" -Status "WARN" -Summary "No AMPLS linked, but private IPs detected"
                    } else {
                        Write-ProgressLine -Name "AMPLS Configuration" -Status "OK" -Summary "No AMPLS (telemetry accepted at public endpoints)"
                    }
                }

                # App Insights Network Access progress line (shows resource settings)
                $ingestionAccessLabel = if ($aiPublicIngestion -eq "Enabled") { "All networks" } else { "Private only" }
                $queryAccessLabel = if ($aiPublicQuery -eq "Enabled") { "All networks" } else { "Private only" }
                $networkAccessSummary = "Ingestion: $ingestionAccessLabel | Query: $queryAccessLabel"
                if ($aiPublicIngestion -ne "Enabled" -or $aiPublicQuery -ne "Enabled") {
                    Write-ProgressLine -Name "App Insights Network Access" -Status "INFO" -Summary $networkAccessSummary
                } else {
                    Write-ProgressLine -Name "App Insights Network Access" -Status "OK" -Summary $networkAccessSummary
                }
                # Diagnosis items for blocked verdicts (based on machine position + settings)
                if ($ingestionVerdict -eq "BLOCKED") {
                    $script:ingestionBlockedPreFlight = $true
                    Add-Diagnosis -Severity "BLOCKING" -Title "Ingestion BLOCKED From This Machine" `
                        -Summary "Ingestion blocked ($ingestionReason)" `
                        -Description $ingestionReason `
                        -Fix ($ingestionFix -join " ") `
                        -Portal "App Insights ($aiName) > Network Isolation > 'Enabled from all networks'" `
                        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                }
                if ($queryVerdict -eq "BLOCKED") {
                    Add-Diagnosis -Severity "WARNING" -Title "Query Access BLOCKED From This Machine" `
                        -Summary "Query access blocked (Portal charts will show empty)" `
                        -Description "$queryReason If you see empty charts in the Azure Portal, this is likely why." `
                        -Fix ($queryFix -join " ") `
                        -Portal "App Insights ($aiName) > Network Isolation > 'Enabled from all networks'" `
                        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design"
                }

                # Verbose Access Assessment display
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HeaderEntry "NETWORK ACCESS ASSESSMENT FOR THIS MACHINE"
                    Write-HostLog ""
                    Write-HostLog "  This combines your App Insights resource settings, AMPLS configuration," -ForegroundColor Gray
                    Write-HostLog "  and the DNS results from this machine to determine whether telemetry" -ForegroundColor Gray
                    Write-HostLog "  ingestion and data queries will work from HERE." -ForegroundColor Gray
                    Write-HostLog ""

                    $aiIngestionDisplay = if ($aiPublicIngestion -eq "Enabled") { "Enabled from all networks" } else { "Disabled (private only)" }
                    $aiQueryDisplay = if ($aiPublicQuery -eq "Enabled") { "Enabled from all networks" } else { "Disabled (private only)" }
                    $clientNetDisplay = $clientNetType
                    if ($clientNetType -eq "Private" -and $clientDnsMatchesAmpls) {
                        $clientNetDisplay = "Private (DNS matches AMPLS private endpoint)"
                    } elseif ($clientNetType -eq "Private") {
                        $clientNetDisplay = "Private (DNS resolves to private IP, but does NOT match AMPLS)"
                    }

                    Write-HostLog "  YOUR CONFIGURATION:" -ForegroundColor Cyan
                    Write-HostLog ""
                    Write-HostLog "    App Insights ($aiName):" -ForegroundColor White
                    Write-HostLog "      Ingestion access:  $aiIngestionDisplay" -ForegroundColor Gray
                    Write-HostLog "      Query access:      $aiQueryDisplay" -ForegroundColor Gray
                    Write-HostLog ""
                    if ($amplsInfo.AmplsLinked) {
                        # Show all linked AMPLS, not just the first
                        foreach ($am in $amplsInfo.AccessModes) {
                            Write-HostLog "    AMPLS ($($am.AmplsName)):" -ForegroundColor White
                            $ingLabel = if ($am.IngestionAccessMode -eq "PrivateOnly") { "PrivateOnly (VNet clients can only reach scoped resources)" } else { "Open (VNet clients can reach scoped + public resources)" }
                            $qLabel = if ($am.QueryAccessMode -eq "PrivateOnly") { "PrivateOnly (VNet clients can only query scoped resources)" } else { "Open (VNet clients can query scoped + public resources)" }
                            Write-HostLog "      Ingestion mode:    $ingLabel" -ForegroundColor Gray
                            Write-HostLog "      Query mode:        $qLabel" -ForegroundColor Gray
                            Write-HostLog ""
                        }
                    } else {
                        Write-HostLog "    AMPLS: " -ForegroundColor White -NoNewline
                        Write-HostLog "None linked to this App Insights resource" -ForegroundColor Gray
                    }
                    Write-HostLog ""
                    Write-HostLog "    This machine:" -ForegroundColor White
                    Write-HostLog "      Ingestion endpoint: $ingestionHost" -ForegroundColor Gray
                    Write-HostLog "      Resolved to:        $clientIngestionIp" -ForegroundColor Gray
                    Write-HostLog "      Network position:   $clientNetDisplay" -ForegroundColor Gray
                    Write-HostLog ""

                    Write-HostLog "  FROM THIS MACHINE:" -ForegroundColor Cyan
                    Write-HostLog ""
                    $ingColor = if ($ingestionVerdict -eq "ALLOWED") { "Green" } else { "Red" }
                    $ingSymbol = if ($ingestionVerdict -eq "ALLOWED") { if ($script:UseColor) { [char]0x2713 } else { "+" } } else { if ($script:UseColor) { [char]0x2717 } else { "X" } }
                    Write-HostLog "    Ingestion (sending telemetry TO App Insights):" -ForegroundColor White
                    Write-HostLog "    [$ingSymbol] $ingestionVerdict" -ForegroundColor $ingColor
                    Write-HostLog "    $ingestionReason" -ForegroundColor Gray
                    if ($ingestionFix.Count -gt 0) {
                        Write-HostLog ""
                        Write-HostLog "    TO FIX:" -ForegroundColor Yellow
                        foreach ($fix in $ingestionFix) { Write-HostLog "      $fix" -ForegroundColor Gray }
                    }
                    Write-HostLog ""
                    $qColor = if ($queryVerdict -eq "ALLOWED") { "Green" } else { "Red" }
                    $qSymbol = if ($queryVerdict -eq "ALLOWED") { if ($script:UseColor) { [char]0x2713 } else { "+" } } else { if ($script:UseColor) { [char]0x2717 } else { "X" } }
                    Write-HostLog "    Query (reading data FROM App Insights, e.g. Azure Portal, API):" -ForegroundColor White
                    Write-HostLog "    [$qSymbol] $queryVerdict" -ForegroundColor $qColor
                    Write-HostLog "    $queryReason" -ForegroundColor Gray
                    if ($queryFix.Count -gt 0) {
                        Write-HostLog ""
                        Write-HostLog "    TO FIX:" -ForegroundColor Yellow
                        foreach ($fix in $queryFix) { Write-HostLog "      $fix" -ForegroundColor Gray }
                    }

                    if ($queryVerdict -eq "BLOCKED") {
                        Write-HostLog ""
                        Write-HostLog "    IMPORTANT -- this affects the Azure Portal too:" -ForegroundColor Yellow
                        Write-HostLog "      If you see 'no data' or empty charts in App Insights, it may be because" -ForegroundColor Gray
                        Write-HostLog "      your browser is on a public network but query access is restricted." -ForegroundColor Gray
                        Write-HostLog "      The telemetry may actually be there -- you just can't see it from here." -ForegroundColor Gray
                    }

                    Write-HostLog ""
                    Write-HostLog "  For more information on these settings:" -ForegroundColor DarkGray
                    Write-HostLog "    AMPLS access modes:      https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design#select-an-access-mode" -ForegroundColor DarkGray
                    Write-HostLog "    Network isolation:        https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design#control-network-access-to-ampls-resources" -ForegroundColor DarkGray
                    Write-HostLog "    Configure private link:   https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure" -ForegroundColor DarkGray
                }

            }
        }
    }
}

# If AMPLS wasn't checked but we detected private IPs, hint about it
elseif ($script:AzureConsentDeclined) {
    Write-ProgressLine -Name "Azure Resource Checks" -Status "SKIP" -Summary "Consent declined (use -AutoApprove to bypass)"
    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  Azure resource checks skipped (consent declined)." -ForegroundColor Yellow
        Write-HostLog "  Use -AutoApprove to bypass consent prompts, or -NetworkOnly to skip Azure checks." -ForegroundColor Gray
        Write-HostLog ""
    }
}
elseif ($hasAmplsSignals -and -not $CheckAzure -and (-not $AmplsExpectedIps -or $AmplsExpectedIps.Count -eq 0)) {
    if ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp) {
        Write-ProgressLine -Name "AMPLS Configuration" -Status "INFO" -Summary "Private IPs detected. Run from Cloud Shell or use -AmplsExpectedIps to validate."
    } else {
        Write-ProgressLine -Name "AMPLS Configuration" -Status "INFO" -Summary "Private IPs detected. Install Az.Accounts and Connect-AzAccount to validate."
    }
    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-HostLog "  TIP: Private IPs were detected in DNS results. To validate they match your" -ForegroundColor DarkGray
        if ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp) {
            Write-HostLog "  AMPLS configuration, run this script from Azure Cloud Shell or a machine with Az.Accounts installed." -ForegroundColor DarkGray
        } else {
            Write-HostLog "  AMPLS configuration, install the Az.Accounts module and log in:" -ForegroundColor DarkGray
            Write-HostLog "  Install-Module Az.Accounts, Az.ResourceGraph; Connect-AzAccount" -ForegroundColor White
        }
        Write-HostLog ""
        Write-HostLog "  Or provide expected IPs manually:" -ForegroundColor DarkGray
        Write-HostLog "  -AmplsExpectedIps @{ " -ForegroundColor DarkGray -NoNewline
        Write-HostLog '"your-endpoint.azure.com" = "10.0.x.x"' -ForegroundColor White -NoNewline
        Write-HostLog " }" -ForegroundColor DarkGray
        Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
    }
}

# ============================================================================
# Manual -LookupAmplsIp: user-requested reverse lookup of a specific IP
# ============================================================================
if ($LookupAmplsIp) {
    $stepNumber++
    Write-HeaderEntry "STEP $($stepNumber): AMPLS Reverse-Lookup (Manual)"
    Write-HostLog ""
    Write-HostLog "  Validating IP: $LookupAmplsIp" -ForegroundColor Gray

    $ipValidation = Test-AmplsIpParameter -IpAddress $LookupAmplsIp
    if (-not $ipValidation.Valid) {
        Write-Result -Status "FAIL" -Check "IP validation failed"
        Write-HostLog ""
        Write-HostLog "  $($ipValidation.Reason)" -ForegroundColor Yellow
        Write-HostLog ""
    } else {
        Write-Result -Status "PASS" -Check "IP validated -- running reverse lookup"
        $ghostResult = Find-AmplsByPrivateIp -TargetIp $LookupAmplsIp
        if ($ghostResult.Found) {
            Write-HostLog ""
            Write-HostLog "  AMPLS IDENTIFIED: " -ForegroundColor Cyan -NoNewline
            Write-HostLog "$($ghostResult.AmplsName)" -ForegroundColor White
            Write-HostLog "    Resource Group:   $($ghostResult.AmplsRg)" -ForegroundColor Gray
            Write-HostLog "    Subscription:     $($ghostResult.AmplsSub)" -ForegroundColor Gray
            Write-HostLog "    Private Endpoint: $($ghostResult.PeName) ($($ghostResult.PeRg))" -ForegroundColor Gray
            Write-HostLog "    Access Modes:     Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode)" -ForegroundColor Gray
            Write-HostLog "    Looked up IP:     $LookupAmplsIp" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  This AMPLS owns the private endpoint associated with IP $LookupAmplsIp." -ForegroundColor Yellow
            Write-HostLog "  If this is not your expected AMPLS, add your resource to this AMPLS or set its access mode to 'Open'." -ForegroundColor Yellow
            Write-HostLog ""

            Add-Diagnosis -Severity "INFO" -Title "Manual Lookup: AMPLS '$($ghostResult.AmplsName)' owns IP $LookupAmplsIp" `
                -Summary "AMPLS '$($ghostResult.AmplsName)' in RG '$($ghostResult.AmplsRg)' owns the private endpoint for IP $LookupAmplsIp" `
                -Description "Reverse lookup of IP $LookupAmplsIp found NIC -> private endpoint '$($ghostResult.PeName)' -> AMPLS '$($ghostResult.AmplsName)' (Ingestion=$($ghostResult.IngestionMode), Query=$($ghostResult.QueryMode))." `
                -Fix "If this AMPLS is unexpected, add your Azure Monitor resource to it or set its ingestion access mode to 'Open'." `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
        } else {
            Write-HostLog ""
            Write-HostLog "  The private endpoint for IP $LookupAmplsIp could not be identified." -ForegroundColor Yellow
            Write-HostLog "  It may be in a subscription your account cannot access, or the private" -ForegroundColor Gray
            Write-HostLog "  DNS zone may have been configured manually." -ForegroundColor Gray
            Write-HostLog ""

            Add-Diagnosis -Severity "INFO" -Title "Manual Lookup: No AMPLS found for IP $LookupAmplsIp" `
                -Summary "Reverse lookup of $LookupAmplsIp did not find an AMPLS resource in accessible subscriptions" `
                -Description "The IP $LookupAmplsIp could not be traced to an AMPLS-connected private endpoint. The PE may be in an inaccessible subscription or the DNS record may have been configured manually." `
                -Fix "Check private DNS zones for manual A records, or ask the network/subscription owner to investigate." `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
        }
    }
}

# ============================================================================
# STEP: KNOWN ISSUE CHECKS (require Azure login) (Optional, dynamic number)
# ============================================================================

$localAuthDisabled = $false
$aiCapGb = $null
$aiCapOff = $false
$laCapGb = $null
$laCapOff = $true
$dcrFindings = @()

# Show Known Issue Checks step header only when we have Azure resource context
if ($CheckAzure -and $aiResource) {
    $stepNumber++
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Known Issue Checks"
        Write-HostLog ""
        Write-HostLog "  WHY THIS MATTERS:" -ForegroundColor Cyan
        Write-HostLog "  These checks inspect your App Insights and Log Analytics resource configurations" -ForegroundColor Gray
        Write-HostLog "  for common misconfigurations that cause silent data loss, duplication, or unexpected" -ForegroundColor Gray
        Write-HostLog "  telemetry behavior -- even when network connectivity is perfectly healthy." -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  WHAT WE'RE CHECKING:" -ForegroundColor Cyan
        Write-HostLog "  - Authentication mode (local auth vs Entra ID)" -ForegroundColor Gray
        Write-HostLog "  - Ingestion sampling (server-side data reduction)" -ForegroundColor Gray
        Write-HostLog "  - Backend Log Analytics workspace health (exists, not over quota, access mode)" -ForegroundColor Gray
        Write-HostLog "  - Daily cap settings (App Insights cap vs Log Analytics cap)" -ForegroundColor Gray
        Write-HostLog "  - Diagnostic Settings (duplicate telemetry exported to LA)" -ForegroundColor Gray
        Write-HostLog "  - Workspace transforms / DCRs (silent data alteration)" -ForegroundColor Gray
    }
}

# --- Known Issue #1: Local Auth Disabled (Entra ID Required) ---
if ($CheckAzure -and $aiResource) {
    Write-ProgressStart -Name "Authentication"
    try {
        if ($aiResource.properties.DisableLocalAuth -eq $true) {
            $localAuthDisabled = $true
        }
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

    if ($localAuthDisabled) {
        Add-Diagnosis -Severity "INFO" -Title "Local Authentication Disabled (Entra ID Required)" `
            -Summary "Local auth disabled -- SDKs must use Entra ID tokens (iKey returns 401)" `
            -Description "This App Insights resource requires Entra ID (Azure AD) authentication. Standard iKey local auth is rejected with HTTP 401. If your applications are not configured for Entra ID auth, ingestion will fail." `
            -Fix "Configure SDK for Entra ID auth (Managed Identity or Service Principal), or re-enable local auth if unintentional." `
            -Portal "App Insights > Properties > Local Authentication" `
            -Docs "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Authentication Settings" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  Local Authentication: " -ForegroundColor Gray -NoNewline
            Write-HostLog "DISABLED" -ForegroundColor Yellow
            Write-HostLog ""
            Write-HostLog "  This App Insights resource requires Entra ID (Azure AD) authentication." -ForegroundColor Gray
            Write-HostLog "  Standard iKey-based local auth ingestion is rejected with HTTP 401." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  WHAT THIS MEANS FOR YOUR APPLICATION:" -ForegroundColor Cyan
            Write-HostLog "    Your SDKs MUST send an Entra ID bearer token with each telemetry request." -ForegroundColor Gray
            Write-HostLog "    Without it, ingestion fails silently -- SDKs receive 401 but typically" -ForegroundColor Gray
            Write-HostLog "    do not surface this to application logs unless SDK diagnostic logging" -ForegroundColor Gray
            Write-HostLog "    is explicitly enabled." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  IF YOU ARE NOT SEEING TELEMETRY:" -ForegroundColor Cyan
            Write-HostLog "    This is a likely root cause. Verify:" -ForegroundColor Gray
            Write-HostLog "    1. Your SDK is configured for Entra ID auth (Managed Identity or Service Principal)" -ForegroundColor Gray
            Write-HostLog "    2. The identity has 'Monitoring Metrics Publisher' role on this resource" -ForegroundColor Gray
            Write-HostLog "    3. Check SDK diagnostic logs for 401 responses" -ForegroundColor Gray
            Write-HostLog "    4. Enable SDK Stats for visibility into why telemetry is rejected by the ingestion API." -ForegroundColor Gray
            Write-HostLog "       The dashboard surfaces 'Unauthenticated' drop codes when tokens are missing or invalid." -ForegroundColor Gray
            Write-HostLog "       https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  TO RE-ENABLE LOCAL AUTH (if this was unintentional):" -ForegroundColor Cyan
            Write-HostLog "    Azure Portal > App Insights > Properties > Local Authentication > Enabled" -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication" -ForegroundColor DarkGray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Authentication" -Status "INFO" -Summary "Local auth DISABLED (Entra ID required for ingestion)"
    } else {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Authentication Settings" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  Local Authentication: " -ForegroundColor Gray -NoNewline
            Write-HostLog "ENABLED" -ForegroundColor Green
            Write-HostLog "  Telemetry can be sent using the instrumentation key (standard iKey auth)." -ForegroundColor Gray
            Write-HostLog "  Entra ID authentication is also accepted but not required." -ForegroundColor Gray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Authentication" -Status "OK" -Summary "Local auth enabled (iKey accepted)"
    }
}

# --- Known Issue #2: Ingestion Sampling Configured ---
if ($CheckAzure -and $aiResource) {
    Write-ProgressStart -Name "Ingestion Sampling"
    $samplingPct = 100.0
    try {
        if ($null -ne $aiResource.properties.SamplingPercentage) {
            $samplingPct = [double]$aiResource.properties.SamplingPercentage
        }
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

    if ($samplingPct -lt 100) {
        $dropPct = 100 - $samplingPct
        Add-Diagnosis -Severity "INFO" -Title "Ingestion Sampling Enabled ($($samplingPct)%)" `
            -Summary "Ingestion sampling at $($samplingPct)% (dropping $($dropPct)% of accepted telemetry)" `
            -Description "$($dropPct)% of incoming telemetry is dropped during ingestion, AFTER your SDKs have successfully sent it. Telemetry not already sampled by the SDK is subject to this rate." `
            -Fix "Increase to 100% to retain all ingested data (increases cost), or verify this was intentionally configured." `
            -Portal "App Insights > Usage and estimated costs > Data Sampling" `
            -Docs "https://learn.microsoft.com/azure/azure-monitor/app/sampling-classic-api#ingestion-sampling"

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Ingestion Sampling" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  SamplingPercentage: " -ForegroundColor Gray -NoNewline
            Write-HostLog "$samplingPct%" -ForegroundColor Yellow
            Write-HostLog "  Data dropped at ingestion: " -ForegroundColor Gray -NoNewline
            Write-HostLog "$dropPct%" -ForegroundColor Yellow
            Write-HostLog ""
            Write-HostLog "  WHAT THIS MEANS:" -ForegroundColor Cyan
            Write-HostLog "    Your SDKs send telemetry to App Insights and receive HTTP 206 (partial accept)" -ForegroundColor Gray
            Write-HostLog "    for items that are sampled out. Before the data reaches your Log Analytics" -ForegroundColor Gray
            Write-HostLog "    workspace, App Insights randomly drops $($dropPct)% of the telemetry items. This is" -ForegroundColor Gray
            Write-HostLog "    server-side sampling applied during ingestion -- it is NOT the same as" -ForegroundColor Gray
            Write-HostLog "    SDK-side adaptive sampling." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "    Ingestion sampling only applies to telemetry that was NOT already sampled by" -ForegroundColor Gray
            Write-HostLog "    the SDK. Pre-sampled records pass through ingestion sampling untouched." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  IMPACT:" -ForegroundColor Cyan
            Write-HostLog "    - Queries may return fewer results than expected" -ForegroundColor Gray
            Write-HostLog "    - Specific traces, requests, or exceptions may be missing entirely" -ForegroundColor Gray
            Write-HostLog "    - itemCount field on retained records does NOT compensate for ingestion sampling" -ForegroundColor Gray
            Write-HostLog "    - End-to-end transaction views may show gaps" -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  NOTE: Microsoft does not recommend ingestion sampling. Prefer SDK-side" -ForegroundColor Yellow
            Write-HostLog "  adaptive sampling which preserves correlated telemetry items together." -ForegroundColor Yellow
            Write-HostLog ""
            Write-HostLog "  TO CHANGE:" -ForegroundColor Cyan
            Write-HostLog "    Azure Portal > App Insights > Configure > Usage and estimated costs > Data Sampling" -ForegroundColor Gray
            Write-HostLog "    Set to 100% to retain all telemetry (increases cost)." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-sampling#ingestion-sampling-not-recommended" -ForegroundColor DarkGray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Ingestion Sampling" -Status "INFO" -Summary "Sampling at $($samplingPct)% (dropping $($dropPct)% of telemetry)"
    } else {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Ingestion Sampling" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  SamplingPercentage: " -ForegroundColor Gray -NoNewline
            Write-HostLog "100% (no ingestion sampling)" -ForegroundColor Green
            Write-HostLog "  All telemetry accepted by the ingestion API is retained." -ForegroundColor Gray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Ingestion Sampling" -Status "OK" -Summary "100% (all ingested telemetry retained)"
    }
}

# --- Known Issues #3, #4: Backend LA Workspace Deleted, OverQuota (daily cap reached), or suspended ---
if ($CheckAzure -and $aiResource) {
    Write-ProgressStart -Name "Backend LA Workspace"
    $wsResourceId = $null
    $wsResource = $null
    $wsName = "(unknown)"

    try {
        $wsResourceId = $aiResource.properties.WorkspaceResourceId
    } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

    if (-not $wsResourceId) {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Backend Log Analytics Workspace" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  Could not find WorkspaceResourceId in App Insights resource properties." -ForegroundColor Yellow
            Write-HostLog "  This may indicate a classic (non-workspace-based) App Insights resource." -ForegroundColor Gray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Backend LA Workspace" -Status "INFO" -Summary "No WorkspaceResourceId found in AI resource properties"
    } else {
        # Extract workspace name from resource ID for display
        $wsNameParts = $wsResourceId -split "/"
        if ($wsNameParts.Count -gt 0) { $wsName = $wsNameParts[-1] }

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog "  KNOWN ISSUE CHECK: Backend Log Analytics Workspace" -ForegroundColor Cyan
            Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  App Insights sends telemetry to this backend LA workspace:" -ForegroundColor Gray
            Write-HostLog "    Name: $wsName" -ForegroundColor White
            Write-HostLog "    URI:  $wsResourceId" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  Querying workspace resource..." -ForegroundColor Gray
        }

        # Query ARM directly for the workspace (avoids ARG staleness)
        $wsApiPath = "$($wsResourceId)?api-version=2023-09-01"

        try {
            Write-DebugAzRest -Method "GET" -Path $wsApiPath
            $wsResponse = Invoke-AzRestMethod -Path $wsApiPath -Method GET -ErrorAction Stop
            Write-DebugResponse -Status "HTTP $($wsResponse.StatusCode)" -Body $wsResponse.Content

            if ($wsResponse.StatusCode -eq 200) {
                # --- Workspace found ---
                $wsResourceObj = $wsResponse.Content | ConvertFrom-Json
                $wsProps = $wsResourceObj.properties
                $wsCustomerId = "(unknown)"

                try { $wsCustomerId = $wsProps.customerId } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

                if ($VerboseOutput) {
                    Write-HostLog "  [OK] Workspace exists" -ForegroundColor Green
                    Write-HostLog "    Workspace ID (customerId): $wsCustomerId" -ForegroundColor Gray
                    Write-HostLog "    Location: $($wsResourceObj.location)" -ForegroundColor Gray
                }

                # --- Workspace Access Control Mode check ---
                # enableLogAccessUsingOnlyResourcePermissions:
                #   true  = "Use resource or workspace permissions" (default for workspaces created after March 2019)
                #   false/absent = "Require workspace permissions" (legacy default)
                # When set to "Require workspace permissions", users who have Reader on the
                # App Insights resource but NO role on the LA workspace will get HTTP 200
                # with empty results from data plane queries -- the API silently returns nothing.
                $wsAccessResourcePerms = $null
                try { $wsAccessResourcePerms = $wsProps.features.enableLogAccessUsingOnlyResourcePermissions } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

                $wsRequireWorkspacePerms = $false
                if ($wsAccessResourcePerms -eq $true) {
                    $wsAccessModeLabel = "Use resource or workspace permissions"
                } elseif ($wsAccessResourcePerms -eq $false -or $null -eq $wsAccessResourcePerms) {
                    $wsAccessModeLabel = "Require workspace permissions"
                    $wsRequireWorkspacePerms = $true
                } else {
                    $wsAccessModeLabel = "Unknown ($wsAccessResourcePerms)"
                }

                if ($wsRequireWorkspacePerms) {
                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  [i] " -ForegroundColor Yellow -NoNewline
                        Write-HostLog "Workspace Access Control Mode: Require workspace permissions" -ForegroundColor Yellow
                        Write-HostLog ""
                        Write-HostLog "  WHAT THIS MEANS:" -ForegroundColor Cyan
                        Write-HostLog "  This workspace requires EXPLICIT workspace-level RBAC to query data." -ForegroundColor Gray
                        Write-HostLog "  Users who have Reader on the App Insights resource but NO role on the" -ForegroundColor Gray
                        Write-HostLog "  Log Analytics workspace will get HTTP 200 with EMPTY results from" -ForegroundColor Gray
                        Write-HostLog "  data plane queries. The API does not return 403 -- it silently returns" -ForegroundColor Gray
                        Write-HostLog "  no data, which makes this very hard to diagnose." -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  WHO IS AFFECTED:" -ForegroundColor Cyan
                        Write-HostLog "  - Users querying App Insights > Logs in the Azure Portal" -ForegroundColor Gray
                        Write-HostLog "  - SDKs or tools calling the Application Insights data plane API" -ForegroundColor Gray
                        Write-HostLog "  - This diagnostic script's E2E verification step" -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  REQUIRED PERMISSIONS:" -ForegroundColor Cyan
                        Write-HostLog "  Ensure the querying user has one of these on the workspace:" -ForegroundColor Gray
                        Write-HostLog "    - Log Analytics Reader" -ForegroundColor White
                        Write-HostLog "    - Monitoring Reader" -ForegroundColor White
                        Write-HostLog "    - A custom role with Microsoft.OperationalInsights/workspaces/query/*/read" -ForegroundColor White
                        Write-HostLog ""
                        Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/manage-access" -ForegroundColor DarkGray
                        Write-HostLog ""
                    }
                    Add-Diagnosis -Severity "INFO" -Title "Workspace Access: Require Workspace Permissions" `
                        -Summary "LA workspace requires explicit workspace RBAC -- queries may return empty results" `
                        -Description "The backend workspace ($wsName) access control mode is set to 'Require workspace permissions'. Users who have Reader on App Insights but no role on the workspace will get empty query results (HTTP 200, zero rows). The API does not return 403." `
                        -Fix "Ensure querying users have Log Analytics Reader (or equivalent) on the workspace, or change the workspace to 'Use resource or workspace permissions'." `
                        -Portal "Log Analytics workspace ($wsName) > Properties > Access control mode" `
                        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/manage-access"
                } else {
                    if ($VerboseOutput) {
                        Write-HostLog "    Access Control Mode: $wsAccessModeLabel" -ForegroundColor Gray
                    }
                }

                # --- Known Issue #4: Log Analytics reached Daily Cap (OverQuota)---
                $capStatus = "Unknown"
                $capQuotaGb = $null
                $capResetTime = $null

                try {
                    $capStatus = $wsProps.workspaceCapping.dataIngestionStatus
                    $capQuotaGb = $wsProps.workspaceCapping.dailyQuotaGb

                    # ARM returns ISO 8601 format for reset time
                    $resetRaw = "$($wsProps.workspaceCapping.quotaNextResetTime)"
                    if ($resetRaw -and $resetRaw -ne "null" -and $resetRaw -ne "") {
                        if ($resetRaw -match '/Date\((\d+)\)/') {
                            # ARG-style /Date(epoch)/ format (fallback)
                            $epochMs = [long]$Matches[1]
                            $capResetTime = [System.DateTimeOffset]::FromUnixTimeMilliseconds($epochMs).UtcDateTime
                        } else {
                            # ARM-style ISO 8601 format
                            $capResetTime = [DateTime]::Parse($resetRaw).ToUniversalTime()
                        }
                    }
                } catch { Write-ScriptDebug "Suppressed: $($_.Exception.Message)" }

                if ($capStatus -eq "OverQuota") {
                    $resetNote = ""
                    if ($capResetTime) {
                        $timeUntilReset = $capResetTime - [DateTime]::UtcNow
                        if ($timeUntilReset.TotalMinutes -gt 0) {
                            $resetNote = " (resets in ~$([Math]::Floor($timeUntilReset.TotalHours))h $($timeUntilReset.Minutes)m at $($capResetTime.ToString('HH:mm')) UTC)"
                        } else {
                            $resetNote = " (reset time has passed, may take a few minutes to resume)"
                        }
                    }

                    Add-Diagnosis -Severity "BLOCKING" -Title "Log Analytics Daily Cap Reached (OverQuota)" `
                        -Summary "Workspace over quota ($($capQuotaGb) GB cap) -- all ingestion stopped" `
                        -Description "The backend workspace ($wsName) has reached its daily cap of $($capQuotaGb) GB. All ingestion is stopped. The ingestion API still returns HTTP 200, but data is dropped at the LA layer.$resetNote" `
                        -Fix "Increase or remove the daily cap. The cap resets automatically at the configured reset hour (UTC)." `
                        -Portal "Log Analytics > Usage and estimated costs > Daily Cap" `
                        -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  [!] DAILY CAP REACHED" -ForegroundColor Red
                        Write-HostLog ""
                        Write-HostLog "  dataIngestionStatus: " -ForegroundColor Gray -NoNewline
                        Write-HostLog "OverQuota" -ForegroundColor Red
                        Write-HostLog "  dailyQuotaGb:        $capQuotaGb GB" -ForegroundColor Gray
                        if ($capResetTime) {
                            Write-HostLog "  quotaNextResetTime:  $($capResetTime.ToString('yyyy-MM-dd HH:mm')) UTC$resetNote" -ForegroundColor Gray
                        }
                        Write-HostLog ""
                        Write-HostLog "  IMPACT:" -ForegroundColor Cyan
                        Write-HostLog "    ALL data ingestion to this workspace is currently stopped." -ForegroundColor Gray
                        Write-HostLog "    This affects not just this App Insights resource, but any other" -ForegroundColor Gray
                        Write-HostLog "    data sources sending to the same workspace (other AI resources," -ForegroundColor Gray
                        Write-HostLog "    AMA agents, Sentinel, etc.)." -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "    The App Insights ingestion API still returns HTTP 200 to SDKs," -ForegroundColor Gray
                        Write-HostLog "    so your applications believe data is being accepted. It is NOT." -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  FIX:" -ForegroundColor Cyan
                        Write-HostLog "    Azure Portal > Log Analytics workspace ($wsName)" -ForegroundColor Gray
                        Write-HostLog "    > Settings > Usage and estimated costs > Daily Cap" -ForegroundColor Gray
                        Write-HostLog "    Increase the limit or remove the cap entirely." -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap" -ForegroundColor DarkGray
                        Write-HostLog ""
                    }
                    Write-ProgressLine -Name "Backend LA Workspace" -Status "FAIL" -Summary "$wsName exists but OVER DAILY CAP$resetNote"
                    Write-ProgressLine -Name "Daily Cap" -Status "FAIL" -Summary "OverQuota -- cap: $($capQuotaGb)GB/day$resetNote"
                } elseif ($capStatus -eq "SubscriptionSuspended") {
                    Add-Diagnosis -Severity "BLOCKING" -Title "Azure Subscription Suspended" `
                        -Summary "Subscription suspended -- all ingestion blocked" `
                        -Description "The subscription containing the Log Analytics workspace ($wsName) is suspended. All data ingestion is blocked." `
                        -Fix "Resolve the subscription status. Common causes: expired trial, payment issues, or admin action." `
                        -Portal "Azure Portal > Subscriptions" `
                        -Docs "https://learn.microsoft.com/azure/cost-management-billing/manage/subscription-disabled"
                    $script:pipelineBroken = $true

                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  [!] SUBSCRIPTION SUSPENDED" -ForegroundColor Red
                        Write-HostLog "  The Azure subscription for this workspace is suspended." -ForegroundColor Gray
                        Write-HostLog "  No data ingestion or queries will work until the subscription is reactivated." -ForegroundColor Gray
                        Write-HostLog ""
                    }
                    Write-ProgressLine -Name "Backend Workspace" -Status "FAIL" -Summary "$wsName exists but SUBSCRIPTION SUSPENDED"
                    Write-ProgressLine -Name "Daily Cap" -Status "FAIL" -Summary "SubscriptionSuspended"
                } else {
                    # RespectQuota or other normal status
                    $capSummary = "under quota"
                    if ($capQuotaGb) {
                        $capSummary = "cap: $($capQuotaGb) GB/day"
                    }

                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  Daily Cap Status:" -ForegroundColor Gray
                        Write-HostLog "    dataIngestionStatus: " -ForegroundColor Gray -NoNewline
                        Write-HostLog "$capStatus" -ForegroundColor Green
                        if ($capQuotaGb) {
                            Write-HostLog "    dailyQuotaGb:        $capQuotaGb GB" -ForegroundColor Gray
                        }
                        if ($capResetTime) {
                            Write-HostLog "    quotaNextResetTime:  $($capResetTime.ToString('yyyy-MM-dd HH:mm')) UTC" -ForegroundColor Gray
                        }
                        Write-HostLog ""
                    }
                    if ($wsRequireWorkspacePerms) {
                        Write-ProgressLine -Name "Backend LA Workspace" -Status "INFO" -Summary "$wsName exists, $capSummary, access mode = require workspace permissions"
                    } else {
                        Write-ProgressLine -Name "Backend LA Workspace" -Status "OK" -Summary "$wsName exists, $capSummary"
                    }
                    Write-ProgressLine -Name "Daily Cap" -Status "OK" -Summary "RespectQuota ($capSummary)"
                }
            } elseif ($wsResponse.StatusCode -eq 404) {
                # --- Known Issue #3: Backend LA workspace is DELETED ---
                Add-Diagnosis -Severity "BLOCKING" -Title "Backend Log Analytics Workspace Not Found" `
                    -Summary "LA workspace deleted -- accepted telemetry silently dropped" `
                    -Description "The Log Analytics workspace ($wsName) linked to this App Insights resource does not exist. Telemetry accepted by the ingestion API (HTTP 200) is silently dropped because the backend workspace is gone." `
                    -Fix "Recreate the workspace, or link App Insights to a different workspace. After relinking, verify data flows within a few minutes." `
                    -Portal "App Insights > Properties > Change Workspace" `
                    -Docs "https://learn.microsoft.com/azure/azure-monitor/app/create-workspace-resource?#modify-the-associated-workspace"
                $script:pipelineBroken = $true

                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  [!] WORKSPACE NOT FOUND" -ForegroundColor Red
                    Write-HostLog ""
                    Write-HostLog "  The Log Analytics workspace linked to this App Insights resource" -ForegroundColor Gray
                    Write-HostLog "  does not exist in any accessible subscription." -ForegroundColor Gray
                    Write-HostLog ""
                    Write-HostLog "  IMPACT:" -ForegroundColor Cyan
                    Write-HostLog "    The App Insights ingestion API will return HTTP 200 to your SDKs," -ForegroundColor Gray
                    Write-HostLog "    telling them 'data received successfully.' However, the data is" -ForegroundColor Gray
                    Write-HostLog "    silently dropped in the pipeline when it tries to reach the" -ForegroundColor Gray
                    Write-HostLog "    non-existent workspace. You will see ZERO data in App Insights." -ForegroundColor Gray
                    Write-HostLog ""
                    Write-HostLog "  FIX OPTIONS:" -ForegroundColor Cyan
                    Write-HostLog "    1. Recreate the workspace with the same resource URI:" -ForegroundColor Gray
                    Write-HostLog "       $wsResourceId" -ForegroundColor White
                    Write-HostLog "       NOTE: A recreated workspace gets a new Workspace ID (GUID)." -ForegroundColor Yellow
                    Write-HostLog "       After recreating, you must re-associate App Insights to pick up the new ID:" -ForegroundColor Yellow
                    Write-HostLog "       Azure Portal > App Insights > Properties > Change Workspace to a different" -ForegroundColor Yellow
                    Write-HostLog "       workspace, Save, then change it back to the recreated workspace and Save again." -ForegroundColor Yellow
                    Write-HostLog ""
                    Write-HostLog "    2. Link App Insights to a different (existing) workspace:" -ForegroundColor Gray
                    Write-HostLog "       Azure Portal > App Insights > Properties > Change Workspace" -ForegroundColor Gray
                    Write-HostLog ""
                    Write-HostLog "    3. If the workspace was recently deleted (< 14 days), recover it:" -ForegroundColor Gray
                    Write-HostLog "       https://learn.microsoft.com/azure/azure-monitor/logs/delete-workspace#recover-a-workspace" -ForegroundColor DarkGray
                    Write-HostLog ""
                }
                Write-ProgressLine -Name "Backend LA Workspace" -Status "FAIL" -Summary "$wsName NOT FOUND (deleted?)"
            } elseif ($wsResponse.StatusCode -eq 403 -or $wsResponse.StatusCode -eq 401) {
                # --- Insufficient permissions ---
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  [!] INSUFFICIENT PERMISSIONS" -ForegroundColor Yellow
                    Write-HostLog ""
                    Write-HostLog "  Could not query the backend Log Analytics workspace (HTTP $($wsResponse.StatusCode))." -ForegroundColor Gray
                    Write-HostLog "  Your account may not have Reader access to the subscription containing" -ForegroundColor Gray
                    Write-HostLog "  the workspace, or the workspace is in a different tenant." -ForegroundColor Gray
                    Write-HostLog ""
                    Write-HostLog "  Workspace: $wsName" -ForegroundColor Gray
                    Write-HostLog "  URI: $wsResourceId" -ForegroundColor DarkGray
                    Write-HostLog ""
                    Write-HostLog "  TO RESOLVE:" -ForegroundColor Cyan
                    Write-HostLog "  - Ensure your account has Reader on the workspace's subscription" -ForegroundColor Gray
                    Write-HostLog "  - If the workspace is in a different tenant, use -TenantId" -ForegroundColor Gray
                    Write-HostLog ""
                }
                Write-ProgressLine -Name "Backend LA Workspace" -Status "INFO" -Summary "Insufficient permissions to query $wsName (HTTP $($wsResponse.StatusCode))"
                Add-Diagnosis -Severity "INFO" -Title "Cannot Query Backend LA Workspace (Permissions)" `
                    -Summary "Insufficient permissions to read backend LA workspace" `
                    -Description "Could not query the Log Analytics workspace ($wsName) via ARM (HTTP $($wsResponse.StatusCode)). Your account may not have Reader access to the workspace subscription. Workspace health, daily cap, and access mode checks are skipped." `
                    -Fix "Ensure your account has Reader access to the subscription containing the workspace. If the workspace is in a different tenant, specify -TenantId." `
                    -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/manage-access"
            } else {
                # --- Unexpected HTTP status ---
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  [WARN] Unexpected response querying Log Analytics workspace (HTTP $($wsResponse.StatusCode))." -ForegroundColor Yellow
                    Write-HostLog "  Ensure your account has Reader access to the workspace subscription." -ForegroundColor Gray
                    Write-HostLog ""
                }
                Write-ProgressLine -Name "Backend LA Workspace" -Status "INFO" -Summary "Could not query workspace (HTTP $($wsResponse.StatusCode))"
            }
        }
        catch {
            $errMsg = "$($_.Exception.Message)"
            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  [WARN] Could not query the Log Analytics workspace." -ForegroundColor Yellow
                Write-HostLog "  Error: $errMsg" -ForegroundColor DarkGray
                Write-HostLog "  Ensure your account has Reader access to the workspace subscription." -ForegroundColor Gray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Backend LA Workspace" -Status "INFO" -Summary "Could not query workspace: $errMsg"
        }
    }
}

# --- Known Issue #5: AI Daily Cap vs LA Daily Cap Misconfigurations ---
if ($CheckAzure -and $aiResource -and $wsResourceId) {
    Write-ProgressStart -Name "Daily Cap Settings"
    $aiCapGb = $null
    $aiCapOff = $false
    $laCapGb = $capQuotaGb  # already captured from workspace check above
    $laCapOff = ($null -eq $laCapGb -or $laCapGb -eq -1)

    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog "  KNOWN ISSUE CHECK: Daily Cap Settings (App Insights vs Log Analytics)" -ForegroundColor Cyan
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog ""
        Write-HostLog "  Comparing daily cap settings between App Insights and the backend" -ForegroundColor Gray
        Write-HostLog "  Log Analytics workspace to detect silent data drop scenarios..." -ForegroundColor Gray
    }

    # Fetch AI daily cap from PricingPlans API
    try {
        $aiCapPath = "$($aiResource.id)/PricingPlans/current?api-version=2017-10-01"
        Write-DebugAzRest -Method "GET" -Path $aiCapPath
        $aiCapResponse = Invoke-AzRestMethod -Path $aiCapPath -Method GET -ErrorAction Stop
        Write-DebugResponse -Status "HTTP $($aiCapResponse.StatusCode)" -Body $aiCapResponse.Content

        if ($aiCapResponse.StatusCode -eq 200) {
            $aiCapContent = $aiCapResponse.Content
            # Use regex to extract cap value -- the API returns duplicate camelCase/PascalCase
            # keys which break ConvertFrom-Json on PS 5.1
            if ($aiCapContent -match '"cap"\s*:\s*([\d.]+)') {
                $aiCapGb = [double]$Matches[1]
            }
            if ($null -eq $aiCapGb -or $aiCapGb -ge 9999) {
                $aiCapOff = $true
            }
        } else {
            if ($VerboseOutput) {
                Write-HostLog "  [WARN] Could not retrieve AI PricingPlans (HTTP $($aiCapResponse.StatusCode))" -ForegroundColor Yellow
            }
        }
    }
    catch {
        if ($VerboseOutput) {
            Write-HostLog "  [WARN] Could not query AI PricingPlans API: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # --- Comparison Logic ---
    if ($null -ne $aiCapGb -or $aiCapOff) {
        $aiCapDisplay = if ($aiCapOff) { "OFF (no limit)" } else { "$aiCapGb GB/day" }
        $laCapDisplay = if ($laCapOff) { "OFF (no limit)" } else { "$laCapGb GB/day" }

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  App Insights daily cap:    $aiCapDisplay" -ForegroundColor White
            Write-HostLog "  Log Analytics daily cap:   $laCapDisplay" -ForegroundColor White
            Write-HostLog ""
        }

        if (-not $laCapOff -and -not $aiCapOff -and $laCapGb -lt $aiCapGb) {
            # THE KEY SCENARIO: LA cap < AI cap = silent data drop
            Add-Diagnosis -Severity "WARNING" -Title "Daily Cap Mismatch: LA Cap ($($laCapGb) GB) < AI Cap ($($aiCapGb) GB)" `
                -Summary "Daily cap mismatch: LA $($laCapGb) GB < AI $($aiCapGb) GB (silent data drop risk)" `
                -Description "LA workspace hits cap first, silently drops data while SDKs get HTTP 200. Data appears to send successfully but never appears in queries." `
                -Fix "Align caps: increase LA to >= $($aiCapGb) GB, or decrease AI to <= $($laCapGb) GB." `
                -Portal "Log Analytics > Usage and estimated costs > Daily Cap" `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

            if ($VerboseOutput) {
                Write-HostLog "  [!] DAILY CAP MISCONFIGURATION DETECTED" -ForegroundColor Red
                Write-HostLog ""
                Write-HostLog "  WHAT HAPPENS:" -ForegroundColor Cyan
                Write-HostLog "    1. Your SDK sends telemetry to App Insights ingestion API" -ForegroundColor Gray
                Write-HostLog "    2. App Insights returns HTTP 200 (accepted) -- cap not yet reached" -ForegroundColor Gray
                Write-HostLog "    3. Data enters the pipeline toward Log Analytics workspace" -ForegroundColor Gray
                Write-HostLog "    4. LA workspace has already hit its $laCapGb GB daily cap" -ForegroundColor Gray
                Write-HostLog "    5. Data is SILENTLY DROPPED -- no error is returned to the SDK" -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "  SCENARIO:" -ForegroundColor Cyan
                Write-HostLog "    When daily ingestion is between $laCapGb GB and $aiCapGb GB," -ForegroundColor Gray
                Write-HostLog "    the LA workspace stops accepting data while App Insights keeps" -ForegroundColor Gray
                Write-HostLog "    telling your SDKs everything is fine." -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "  FIX:" -ForegroundColor Cyan
                Write-HostLog "    Option 1: Increase LA daily cap to >= $aiCapGb GB" -ForegroundColor Gray
                Write-HostLog "      Log Analytics > Usage and estimated costs > Daily Cap" -ForegroundColor Gray
                Write-HostLog "    Option 2: Decrease AI daily cap to <= $laCapGb GB" -ForegroundColor Gray
                Write-HostLog "      App Insights > Usage and estimated costs > Daily Cap" -ForegroundColor Gray
                Write-HostLog "    Option 3: Remove both caps (set to unlimited) and use" -ForegroundColor Gray
                Write-HostLog "      Azure Cost Management alerts for budget control instead." -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap" -ForegroundColor DarkGray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Daily Cap Settings" -Status "WARN" -Summary "LA cap ($($laCapGb) GB) < AI cap ($($aiCapGb) GB) -- silent data drop risk"
        } elseif (-not $laCapOff -and $aiCapOff) {
            # AI cap off but LA has a cap -- LA is the effective limit
            Add-Diagnosis -Severity "INFO" -Title "Log Analytics Daily Cap is the Effective Limit ($($laCapGb) GB)" `
                -Summary "LA cap ($($laCapGb) GB) is the effective limit (AI cap is off)" `
                -Description "App Insights daily cap is OFF (unlimited), but the LA workspace has a $laCapGb GB cap. If you approach $laCapGb GB/day, data will be silently dropped at the LA layer while App Insights continues to accept it (HTTP 200)." `
                -Fix "Consider setting the AI daily cap to $laCapGb GB so the ingestion API stops accepting data before the LA cap is hit." `
                -Portal "App Insights > Usage and estimated costs > Daily Cap" `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

            if ($VerboseOutput) {
                Write-HostLog "  [!] LOG ANALYTICS CAP IS THE EFFECTIVE LIMIT" -ForegroundColor Yellow
                Write-HostLog ""
                Write-HostLog "  App Insights has no daily cap, but the backend LA workspace" -ForegroundColor Gray
                Write-HostLog "  limits ingestion to $laCapGb GB/day. If this is intentional," -ForegroundColor Gray
                Write-HostLog "  consider also setting the AI daily cap to $laCapGb GB so the" -ForegroundColor Gray
                Write-HostLog "  ingestion API rejects data before the LA cap is hit. This" -ForegroundColor Gray
                Write-HostLog "  gives your SDKs visibility into the throttling via non-200 responses." -ForegroundColor Gray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Daily Cap Settings" -Status "INFO" -Summary "AI cap OFF, LA cap $($laCapGb) GB/day -- LA is effective limit"
        } elseif ($laCapOff -and $aiCapOff) {
            # Both off -- no caps
            if ($VerboseOutput) {
                Write-HostLog "  Both daily caps are off. No daily ingestion limit is enforced." -ForegroundColor Green
                Write-HostLog "  Consider using Azure Cost Management alerts for budget control." -ForegroundColor Gray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Daily Cap Settings" -Status "OK" -Summary "Both caps OFF (no daily limit)"
        } elseif ($laCapOff -and -not $aiCapOff) {
            # AI has cap, LA unlimited -- fine
            if ($VerboseOutput) {
                Write-HostLog "  AI daily cap limits ingestion to $aiCapGb GB/day." -ForegroundColor Green
                Write-HostLog "  LA workspace has no daily cap -- no silent drops risk." -ForegroundColor Gray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Daily Cap Settings" -Status "OK" -Summary "AI cap $($aiCapGb) GB/day, LA unlimited"
        } else {
            # Both have caps, LA >= AI -- properly aligned
            if ($VerboseOutput) {
                Write-HostLog "  Daily caps are properly aligned (LA cap >= AI cap)." -ForegroundColor Green
                Write-HostLog "  The App Insights cap will trigger first, giving SDKs" -ForegroundColor Gray
                Write-HostLog "  visibility into throttling before the LA cap is reached." -ForegroundColor Gray
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Daily Cap Settings" -Status "OK" -Summary "Aligned -- AI cap $($aiCapGb) GB, LA cap $($laCapGb) GB"
        }
    }
}

# --- Known Issue #6: Diagnostic Settings Causing Duplicate Telemetry ---
if ($CheckAzure -and $aiResource) {
    Write-ProgressStart -Name "Diagnostic Settings"
    $aiId = $aiResource.id

    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog "  KNOWN ISSUE CHECK: Diagnostic Settings (Duplicate Telemetry)" -ForegroundColor Cyan
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog ""
        Write-HostLog "  Checking if Diagnostic Settings on this App Insights resource export" -ForegroundColor Gray
        Write-HostLog "  logs to ANY Log Analytics workspace (which causes duplicate telemetry)..." -ForegroundColor Gray
    }

    try {
        $dsApiPath = "${aiId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        Write-DebugAzRest -Method "GET" -Path $dsApiPath
        $dsResponse = Invoke-AzRestMethod -Path $dsApiPath -Method GET -ErrorAction Stop
        Write-DebugResponse -Status "HTTP $($dsResponse.StatusCode)" -Body $dsResponse.Content

        if ($dsResponse.StatusCode -eq 200) {
            $dsObj = $dsResponse.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            $dsValues = @()
            if ($dsObj -and $dsObj.value) { $dsValues = @($dsObj.value) }

            # Find diagnostic settings that export logs to ANY LA workspace
            $dsWithLa = @()
            foreach ($ds in $dsValues) {
                $dsName = $ds.name
                $targetWsId = $null
                if ($ds.properties.workspaceId) {
                    $targetWsId = $ds.properties.workspaceId
                }

                if ($targetWsId) {
                    # Check which log categories are enabled
                    $enabledCategories = @()
                    if ($ds.properties.logs) {
                        foreach ($log in $ds.properties.logs) {
                            if ($log.enabled -eq $true) {
                                if ($log.category) {
                                   $enabledCategories += $log.category
                                } elseif ($log.categoryGroup) {
                                    $enabledCategories += $log.categoryGroup
                                }
                            }
                        }
                    }

                    if ($enabledCategories.Count -gt 0) {
                        $targetWsName = ($targetWsId -split "/")[-1]
                        $isSameWs = $false
                        if ($wsResourceId -and $targetWsId.ToLower() -eq $wsResourceId.ToLower()) {
                            $isSameWs = $true
                        }
                        $dsWithLa += @{
                            Name = $dsName
                            TargetWorkspaceId = $targetWsId
                            TargetWorkspaceName = $targetWsName
                            IsSameWorkspace = $isSameWs
                            EnabledCategories = $enabledCategories
                        }
                    }
                }
            }

            if ($dsWithLa.Count -gt 0) {
                $script:diagSettingsExportCount = $dsWithLa.Count
                $sameWsCount = @($dsWithLa | Where-Object { $_.IsSameWorkspace }).Count
                $diffWsCount = @($dsWithLa | Where-Object { -not $_.IsSameWorkspace }).Count

                # Build summary
                $dsSummary = "$($dsWithLa.Count) setting(s) export to Log Analytics"
                if ($sameWsCount -gt 0) {
                    $dsSummary += " ($sameWsCount to SAME workspace = duplicates)"
                }

                # Build diagnosis description
                $diagDesc = "$($dsWithLa.Count) Diagnostic Setting(s) on this App Insights resource export log data to a Log Analytics workspace. "
                if ($sameWsCount -gt 0) {
                    $diagDesc += "Of these, $sameWsCount export to the SAME workspace that App Insights already writes to, causing duplicate records in both App Insights queries AND direct LA table queries. "
                }
                if ($diffWsCount -gt 0) {
                    $diagDesc += "$diffWsCount export to a DIFFERENT workspace. When querying from App Insights, it stitches data across workspaces, so you will still see duplicates in App Insights query results (Transaction Search, Log queries, end-to-end views)."
                }

                Add-Diagnosis -Severity "INFO" -Title "Diagnostic Settings Exporting to LA (Duplicate Telemetry Risk)" `
                    -Summary "Diagnostic settings exporting to LA (duplicate telemetry in queries)" `
                    -Description $diagDesc `
                    -Fix "Delete export to LA, or keep it and de-duplicate with KQL distinct operator, or query LA tables directly." `
                    -Portal "App Insights > Monitoring > Diagnostic settings" `
                    -Docs "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"

                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  [!] DIAGNOSTIC SETTINGS EXPORTING TO LOG ANALYTICS" -ForegroundColor Yellow
                    Write-HostLog ""
                    Write-HostLog "  Found $($dsValues.Count) diagnostic setting(s), $($dsWithLa.Count) export logs to LA:" -ForegroundColor Gray
                    Write-HostLog ""

                    foreach ($dsItem in $dsWithLa) {
                        Write-HostLog "    Setting: " -ForegroundColor Gray -NoNewline
                        Write-HostLog $dsItem.Name -ForegroundColor White
                        Write-HostLog "    Target:  " -ForegroundColor Gray -NoNewline
                        Write-HostLog "$($dsItem.TargetWorkspaceName)" -ForegroundColor White -NoNewline
                        if ($dsItem.IsSameWorkspace) {
                            Write-HostLog " <-- SAME as AI backend" -ForegroundColor Red
                        } else {
                            Write-HostLog " (different workspace)" -ForegroundColor Yellow
                        }
                        Write-HostLog "    Categories: $($dsItem.EnabledCategories -join ', ')" -ForegroundColor DarkGray
                        Write-HostLog ""
                    }

                    Write-HostLog "  WHY THIS CAUSES DUPLICATES:" -ForegroundColor Cyan
                    Write-HostLog "    App Insights already sends all telemetry to its backend LA workspace." -ForegroundColor Gray
                    Write-HostLog "    Diagnostic Settings create a SECOND copy of the same data in LA." -ForegroundColor Gray
                    Write-HostLog ""
                    if ($sameWsCount -gt 0) {
                        Write-HostLog "    When exported to the SAME workspace:" -ForegroundColor Gray
                        Write-HostLog "      Two copies of every record in the same LA tables (AppRequests, etc.)" -ForegroundColor Gray
                        Write-HostLog "      Duplicates visible in BOTH App Insights and LA direct queries." -ForegroundColor Gray
                        Write-HostLog ""
                    }
                    if ($diffWsCount -gt 0) {
                        Write-HostLog "    When exported to a DIFFERENT workspace:" -ForegroundColor Gray
                        Write-HostLog "      App Insights stitches data from all accessible workspaces," -ForegroundColor Gray
                        Write-HostLog "      so Transaction Search, end-to-end views, and log queries from" -ForegroundColor Gray
                        Write-HostLog "      App Insights will show duplicate results." -ForegroundColor Gray
                        Write-HostLog ""
                    }
                    Write-HostLog "  FIX OPTIONS:" -ForegroundColor Cyan
                    Write-HostLog "    1. Remove the LA export: Azure Portal > App Insights > Monitoring > Diagnostic settings" -ForegroundColor Gray
                    Write-HostLog "       Delete or edit the setting(s) that export log categories to a LA workspace." -ForegroundColor Gray
                    Write-HostLog "       You can still export to Blob Storage or Event Hubs without causing duplicates." -ForegroundColor Gray
                    Write-HostLog ""
                    Write-HostLog "    2. Keep the export but de-duplicate in queries:" -ForegroundColor Gray
                    Write-HostLog "       https://learn.microsoft.com/azure/data-explorer/kusto/query/distinct-operator" -ForegroundColor DarkGray
                    Write-HostLog ""
                    if ($diffWsCount -gt 0) {
                        Write-HostLog "    3. Query from the individual LA workspace(s) directly instead of through" -ForegroundColor Gray
                        Write-HostLog "       App Insights, so you only see a single copy of each record." -ForegroundColor Gray
                        Write-HostLog ""
                    }
                    Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings#application-insights" -ForegroundColor DarkGray
                    Write-HostLog ""
                }
                Write-ProgressLine -Name "Diagnostic Settings" -Status "INFO" -Summary $dsSummary
            } else {
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  Diagnostic Settings: " -ForegroundColor Gray -NoNewline
                    if ($dsValues.Count -eq 0) {
                        Write-HostLog "None configured" -ForegroundColor Green
                    } else {
                        Write-HostLog "$($dsValues.Count) found, none export App Insights logs to LA" -ForegroundColor Green
                    }
                    Write-HostLog "  No duplicate telemetry risk from Diagnostic Settings." -ForegroundColor Gray
                    Write-HostLog ""
                }
                if ($dsValues.Count -gt 0) {
                    Write-ProgressLine -Name "Diagnostic Settings" -Status "OK" -Summary "$($dsValues.Count) setting(s) found, none export logs to LA"
                } else {
                    Write-ProgressLine -Name "Diagnostic Settings" -Status "OK" -Summary "None configured"
                }
            }
        } else {
            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  [WARN] Could not query Diagnostic Settings (HTTP $($dsResponse.StatusCode))." -ForegroundColor Yellow
                Write-HostLog ""
            }
            Write-ProgressLine -Name "Diagnostic Settings" -Status "INFO" -Summary "Could not query (HTTP $($dsResponse.StatusCode))"
        }
    }
    catch {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  [WARN] Error querying Diagnostic Settings: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Diagnostic Settings" -Status "INFO" -Summary "Could not query: $($_.Exception.Message)"
    }
}

# --- Known Issue #7: Workspace Transforms (DCRs) Targeting App Insights Tables ---
if ($CheckAzure -and $aiResource -and $wsResourceId) {
    Write-ProgressStart -Name "Workspace Transforms"

    if ($VerboseOutput) {
        Write-HostLog ""
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog "  KNOWN ISSUE CHECK: Workspace Transforms (Data Collection Rules)" -ForegroundColor Cyan
        Write-HostLog "  ========================================================================" -ForegroundColor DarkGray
        Write-HostLog ""
        Write-HostLog "  Checking for Data Collection Rules with workspace transforms that" -ForegroundColor Gray
        Write-HostLog "  target App Insights tables. These transforms can silently drop or" -ForegroundColor Gray
        Write-HostLog "  alter telemetry before it lands in the Log Analytics workspace." -ForegroundColor Gray
    }

    # App Insights table names (used as Microsoft-Table-{name} in DCR streams)
    $appInsightsTables = @(
        "AppRequests", "AppTraces", "AppExceptions", "AppDependencies",
        "AppEvents", "AppMetrics", "AppPageViews", "AppPerformanceCounters",
        "AppAvailabilityResults", "AppBrowserTimings", "AppSystemEvents"
    )

    $dcrFindings = @()

    try {
        # Use Azure Resource Graph to search the ENTIRE TENANT for WorkspaceTransforms DCRs
        # targeting our workspace. DCRs can be created in ANY subscription (not just the
        # workspace's subscription), so ARG cross-subscription search is required here.
        $dcrArgQuery = @"
resources
| where type =~ 'microsoft.insights/datacollectionrules'
| where kind =~ 'WorkspaceTransforms'
| mv-expand dest = properties.destinations.logAnalytics
| where tolower(tostring(dest.workspaceResourceId)) == tolower('$($wsResourceId -replace "'", "''")')
| mv-expand flow = properties.dataFlows
| mv-expand stream = flow.streams
| where tostring(stream) startswith 'Microsoft-Table-App'
| project name, id, tableName=replace_string(tostring(stream), 'Microsoft-Table-', ''), transformKql=tostring(flow.transformKql)
"@
        Write-DebugAzGraph -Query $dcrArgQuery

        $dcrResults = $null
        try {
            $dcrResults = Search-AzGraph -Query $dcrArgQuery -UseTenantScope -ErrorAction Stop
        }
        catch {
            # Fallback: -UseTenantScope may not be available in older module versions
            $dcrResults = Search-AzGraph -Query $dcrArgQuery -ErrorAction Stop
        }

        if ($dcrResults -and $dcrResults.Count -gt 0) {
            Write-DebugResponse -Status "Found $($dcrResults.Count) DCR stream(s)" -Body ($dcrResults | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue)
            foreach ($row in $dcrResults) {
                $tableName = $row.tableName
                if ($tableName -in $appInsightsTables) {
                    $transformKql = if ($row.transformKql) { $row.transformKql.Trim() } else { "(none)" }
                    $dcrFindings += @{
                        DcrName = $row.name
                        DcrId = $row.id
                        TableName = $tableName
                        Stream = "Microsoft-Table-$tableName"
                        TransformKql = $transformKql
                        IsPassthrough = ($transformKql -eq "source" -or $transformKql -eq "(none)")
                    }
                }
            }
        } else {
            Write-DebugResponse -Status "No matching DCR streams found"
        }
    }
    catch {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  [WARN] Error querying DCRs via Resource Graph: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # --- Report findings ---
    $activeTransforms = @($dcrFindings | Where-Object { -not $_.IsPassthrough })

    if ($activeTransforms.Count -gt 0) {
        $affectedTables = ($activeTransforms | ForEach-Object { $_.TableName } | Sort-Object -Unique) -join ", "

        Add-Diagnosis -Severity "INFO" -Title "Workspace Transforms Detected on App Insights Tables" `
            -Summary "Workspace transforms on $affectedTables (may drop/modify telemetry)" `
            -Description "$($activeTransforms.Count) Data Collection Rule transform(s) modify App Insights data before it reaches Log Analytics. Affected tables: $affectedTables. Transforms can silently drop rows (via 'where' clauses) or remove columns (via 'project')." `
            -Fix "Review the transform KQL for each affected table, or set to 'source' for passthrough." `
            -Portal "Log Analytics > Tables > select table > Create transformation" `
            -Docs "https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations"

        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  [!] WORKSPACE TRANSFORMS FOUND ON APP INSIGHTS TABLES" -ForegroundColor Red
            Write-HostLog ""
            Write-HostLog "  These Data Collection Rules apply KQL transforms to App Insights" -ForegroundColor Gray
            Write-HostLog "  telemetry BEFORE it lands in the Log Analytics workspace." -ForegroundColor Gray
            Write-HostLog "  Transforms can silently drop rows or remove columns." -ForegroundColor Gray
            Write-HostLog ""

            foreach ($finding in $activeTransforms) {
                Write-HostLog "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-HostLog "  Table: " -ForegroundColor Gray -NoNewline
                Write-HostLog "$($finding.TableName)" -ForegroundColor Yellow
                Write-HostLog "  DCR:   $($finding.DcrName)" -ForegroundColor Gray
                Write-HostLog "  Transform KQL:" -ForegroundColor Gray
                # Display KQL, indented and line-by-line
                $kqlLines = $finding.TransformKql -split "`n"
                foreach ($kqlLine in $kqlLines) {
                    $trimmed = $kqlLine.Trim()
                    if ($trimmed) {
                        Write-HostLog "    $trimmed" -ForegroundColor White
                    }
                }
                Write-HostLog ""

                # Analyze the transform for common patterns
                $kql = $finding.TransformKql
                $warnings = @()
                if ($kql -match '\|\s*where\b') {
                    $warnings += "Contains 'where' clause -- may be DROPPING rows that don't match the filter"
                }
                if ($kql -match '\|\s*project\b' -and $kql -notmatch '\|\s*project-away\b') {
                    $warnings += "Contains 'project' clause -- may be REMOVING columns from telemetry records"
                }
                if ($kql -match '\|\s*project-away\b') {
                    $warnings += "Contains 'project-away' clause -- explicitly removes specific columns"
                }
                if ($kql -match '\|\s*extend\b') {
                    $warnings += "Contains 'extend' clause -- adds or modifies columns"
                }
                if ($kql -match '\|\s*summarize\b') {
                    $warnings += "Contains 'summarize' clause -- AGGREGATES rows (individual records may be lost)"
                }
                if ($kql -match '\|\s*take\b|\|\s*limit\b') {
                    $warnings += "Contains 'take/limit' clause -- only a subset of rows will be retained"
                }

                if ($warnings.Count -gt 0) {
                    Write-HostLog "  ANALYSIS:" -ForegroundColor Cyan
                    foreach ($w in $warnings) {
                        Write-HostLog "    [!] $w" -ForegroundColor Yellow
                    }
                    Write-HostLog ""
                }
            }

            Write-HostLog "  HOW TO FIX:" -ForegroundColor Cyan
            Write-HostLog "    To remove a transform: Log Analytics > Tables > select table >" -ForegroundColor Gray
            Write-HostLog "    ... (ellipsis) > Create transformation > set KQL to just 'source'" -ForegroundColor Gray
            Write-HostLog "    Or delete the DCR directly via Azure Portal > Data Collection Rules." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  NOTE: Setting transformKql to 'source' makes the transform a passthrough" -ForegroundColor DarkGray
            Write-HostLog "  (all data flows through unchanged). This is equivalent to no transform." -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations" -ForegroundColor DarkGray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Workspace Transforms" -Status "INFO" -Summary "$($activeTransforms.Count) transform(s) on App Insights tables: $affectedTables"
    } elseif ($dcrFindings.Count -gt 0) {
        # Only passthrough transforms found
        $passthroughTables = ($dcrFindings | ForEach-Object { $_.TableName } | Sort-Object -Unique) -join ", "
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  Workspace transforms exist on: $passthroughTables" -ForegroundColor Green
            Write-HostLog "  All are passthrough ('source' only) -- no data modification." -ForegroundColor Gray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Workspace Transforms" -Status "OK" -Summary "Passthrough only ($passthroughTables)"
    } else {
        if ($VerboseOutput) {
            Write-HostLog ""
            Write-HostLog "  No workspace transforms found targeting App Insights tables." -ForegroundColor Green
            Write-HostLog "  Telemetry flows through to Log Analytics unmodified." -ForegroundColor Gray
            Write-HostLog ""
        }
        Write-ProgressLine -Name "Workspace Transforms" -Status "OK" -Summary "None targeting App Insights tables"
    }
}

# ============================================================================
# STEP: Telemetry Ingestion Test (dynamic number)
# ============================================================================

$stepNumber++
$ingestionResult = $null

Write-ProgressStart -Name "Telemetry Ingestion"

# ---- Ingestion consent gate (verbose mode) ----
# Compact mode: consent was already handled before the progress table.
# Verbose mode: ask just-in-time, right before the ingestion test.
if ($VerboseOutput -and -not $SkipIngestionTest -and -not $script:pipelineBroken -and -not $script:ingestionBlockedPreFlight -and -not $script:ingestionTcpBlocked -and -not $script:IngestionConsentDeclined) {
    $ingestionConsent = Request-UserConsent `
        -PromptTitle "TELEMETRY INGESTION TEST -- YOUR CONSENT IS REQUIRED" `
        -PromptLines @(
            ""
            "To verify end-to-end ingestion, this test will send ONE small"
            "availability record directly to your Application Insights resource."
            ""
            "What will be sent:"
            ""
            "  * Record type:  AvailabilityResult"
            "  * Record name:  'Telemetry-Flow-Diag Ingestion Validation'"
            "  * Payload size: ~0.5 KB"
            "  * Sent from:    this machine ($($envInfo.ComputerName)) -> your ingestion endpoint"
            "  * Sent as:      anonymous telemetry -- no sign-in required"
            ""
            "Cost: Standard ingestion and data retention rates apply."
            "For a single telemetry record this is negligible."
        ) `
        -SkipHint "To skip this test, press N or re-run with -SkipIngestionTest." `
        -PromptQuestion "Send test telemetry record? [Y/N]"
    if (-not $ingestionConsent) {
        $script:IngestionConsentDeclined = $true
    }
}

if ($SkipIngestionTest) {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test [SKIPPED]"
        Write-Result -Status "SKIP" -Check "Ingestion test skipped (-SkipIngestionTest flag)"
        Write-HostLog ""
    }
    Write-ProgressLine -Name "Telemetry Ingestion" -Status "SKIP" -Summary "Skipped (-SkipIngestionTest)"
    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not run)"
} elseif ($script:IngestionConsentDeclined) {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test [SKIPPED]"
        Write-Result -Status "SKIP" -Check "Ingestion test skipped (consent declined)"
        Write-HostLog ""
    }
    Write-ProgressLine -Name "Telemetry Ingestion" -Status "SKIP" -Summary "Consent declined (use -AutoApprove to bypass)"
    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not run)"
} elseif ($script:pipelineBroken) {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test [SKIPPED]"
        Write-HostLog ""
        Write-HostLog "  Skipping telemetry ingestion test and end-to-end verification." -ForegroundColor Yellow
        Write-HostLog "  The backend Log Analytics workspace is deleted or the subscription is suspended." -ForegroundColor Gray
        Write-HostLog "  The ingestion API will return HTTP 200, but data is silently dropped in the pipeline." -ForegroundColor Gray
        Write-HostLog "  Resolve the backend issue above first, then re-run this script to validate end-to-end." -ForegroundColor Gray
        Write-HostLog ""
    }
    Write-ProgressLine -Name "Telemetry Ingestion" -Status "SKIP" -Summary "Skipped (backend pipeline broken -- see diagnosis)"
    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not pass)"
} elseif ($script:ingestionBlockedPreFlight) {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test [SKIPPED]"
        Write-HostLog ""
        Write-HostLog "  Skipping telemetry ingestion test." -ForegroundColor Yellow
        Write-HostLog "  The network access assessment determined ingestion is BLOCKED from this machine." -ForegroundColor Gray
        Write-HostLog "  Resolve the network/AMPLS configuration issue first, then re-run." -ForegroundColor Gray
        Write-HostLog ""
    }
    Write-ProgressLine -Name "Telemetry Ingestion" -Status "SKIP" -Summary "Skipped (ingestion blocked at network level)"
    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not pass)"
} elseif ($script:ingestionTcpBlocked) {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test [SKIPPED]"
        Write-HostLog ""
        Write-HostLog "  Skipping telemetry ingestion test and end-to-end verification." -ForegroundColor Yellow
        Write-HostLog "  The ingestion endpoint ($ingestionHost) failed TCP connectivity." -ForegroundColor Gray
        Write-HostLog "  An HTTP POST cannot succeed without an open TCP connection." -ForegroundColor Gray
        Write-HostLog "  Resolve the TCP/firewall issue first, then re-run to validate ingestion." -ForegroundColor Gray
        Write-HostLog ""
    }
    Write-ProgressLine -Name "Telemetry Ingestion" -Status "SKIP" -Summary "Skipped (ingestion endpoint TCP blocked -- resolve firewall first)"
    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not pass)"
} else {
    if ($VerboseOutput) {
        Write-HeaderEntry "STEP $($stepNumber): Telemetry Ingestion Test"
        Write-HostLog ""
        Write-HostLog "  This test bypasses your app and its Application Insights SDK entirely and" -ForegroundColor Gray
        Write-HostLog "  sends a raw telemetry record directly to your Application Insights resource." -ForegroundColor Gray
        Write-HostLog "  Think of this test as asking the question:" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  Can ANY application running on this machine talk to your App Insights resource?" -ForegroundColor Yellow
        Write-HostLog ""
        Write-HostLog "  WHAT WE TEST:" -ForegroundColor Cyan
        Write-HostLog "    Step 1: POST a unique availabilityResults record to your ingestion endpoint" -ForegroundColor Gray
        Write-HostLog "    Step 2: Query App Insights data plane API to confirm the record arrived at your resource" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  The test record will appear in your resource's Availability blade as a custom" -ForegroundColor Gray
        Write-HostLog "  test named `"Telemetry-Flow-Diag Ingestion Validation`"." -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  If BOTH steps succeed, the entire telemetry pipeline is confirmed working:" -ForegroundColor Gray
        Write-HostLog "    This machine -> Network -> Ingestion API -> Processing Pipeline -> Log Analytics -> Queryable" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  WHAT SUCCESS PROVES (from this machine):" -ForegroundColor Cyan
        Write-HostLog "    - Network: DNS resolves, port 443 open, TLS works, no firewall blocks" -ForegroundColor Gray
        Write-HostLog "    - Auth: Your instrumentation key is accepted by your resource's ingestion endpoint" -ForegroundColor Gray
        Write-HostLog "    - Service: Azure Monitor is accepting data from this machine's network location" -ForegroundColor Gray
        Write-HostLog ""
        Write-HostLog "  SENDING TEST TELEMETRY RECORD..." -ForegroundColor Cyan
        Write-HostLog ""
    }

    $ingestionResult = Test-IngestionEndpoint -IngestionUrl $ingestionEndpoint -InstrumentationKey $iKey

    Write-Result -Status $ingestionResult.Status -Check "POST $($ingestionResult.Endpoint)/v2.1/track" `
        -Detail $ingestionResult.Detail -Action $ingestionResult.Action

    if ($VerboseOutput) {
        Write-HostLog "      InstrumentationKey: " -ForegroundColor Gray -NoNewline
        Write-HostLog "$iKey" -ForegroundColor White
        if ($ingestionResult.ResponseBody) {
            Write-HostLog ""
            Write-HostLog "      API Response:" -ForegroundColor Cyan
            $prettyJson = $null
            try {
                $jsonObj = $ingestionResult.ResponseBody | ConvertFrom-Json -ErrorAction Stop
                $prettyJson = $jsonObj | ConvertTo-Json -Depth 10
                # Collapse empty arrays for cleaner display
                $prettyJson = $prettyJson -replace '\[\s*\]', '[]'
            } catch {
                $prettyJson = $ingestionResult.ResponseBody
            }
            $jsonLines = $prettyJson -split "`r?`n"
            foreach ($line in $jsonLines) { Write-HostLog "      $line" -ForegroundColor Gray }
            Write-HostLog ""
        }
    }

    # --- Ingestion progress line (always) ---
    if ($ingestionResult.Status -eq "PASS") {
        $durationNote = ""
        $latencyWarning = ""
        if ($ingestionResult.DurationMs) {
            $durationNote = " [$($ingestionResult.DurationMs)ms]"
            if ($ingestionResult.DurationMs -gt 3000) {
                $latencyWarning = " (high latency)"
            }
        }
        Write-ProgressLine -Name "Telemetry Ingestion" -Status "OK" -Summary "HTTP 200, accepted$durationNote$latencyWarning"

        # Build the KQL verification query for use in E2E outcome branches
        $verifyKql = "availabilityResults | where customDimensions.diagnosticRunId == '$($ingestionResult.TestRecordId)'"

        # Latency interpretation (verbose only -- doesn't break compact table)
        if ($VerboseOutput -and $ingestionResult.DurationMs -gt 3000) {
            Write-HostLog "  NOTE: " -ForegroundColor Yellow -NoNewline
            Write-HostLog "Round-trip API response time was $($ingestionResult.DurationMs)ms (higher than typical <1000ms)." -ForegroundColor Yellow
            Write-HostLog "  This measures client-to-ingestion-API round-trip only, NOT full pipeline latency." -ForegroundColor DarkGray
            Write-HostLog "  Possible causes: proxy routing, geographic distance, or network congestion." -ForegroundColor DarkGray
            Write-HostLog "  For end-to-end ingestion latency, see: https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time" -ForegroundColor DarkGray
            Write-HostLog ""
        }

        # Correlation: Local auth disabled (ARM) but ingestion accepted iKey-only request
        if ($localAuthDisabled) {
            if ($VerboseOutput) {
                Write-HostLog "  NOTE: " -ForegroundColor Yellow -NoNewline
                Write-HostLog "Local auth is disabled per ARM, but the ingestion endpoint accepted an" -ForegroundColor Yellow
                Write-HostLog "  iKey-only request. This may indicate an ARM/control plane sync issue." -ForegroundColor Yellow
                Write-HostLog "  If this resource was recently modified, wait 10-15 minutes and re-test." -ForegroundColor Yellow
                Write-HostLog "  Quick fix: try adding a tag to your App Insights resource in the Azure Portal" -ForegroundColor Yellow
                Write-HostLog "  (e.g., key: 'sync', value: 'force'), then remove it. This can force a sync" -ForegroundColor Yellow
                Write-HostLog "  between ARM and the App Insights control plane." -ForegroundColor Yellow
                Write-HostLog "  If the mismatch persists, contact Microsoft Azure support" -ForegroundColor Yellow
                Write-HostLog "  https://azure.microsoft.com/support" -ForegroundColor Cyan
                Write-HostLog ""
            }
            Add-Diagnosis -Severity "INFO" -Title "ARM / Ingestion Auth Mismatch" `
                -Summary "Local auth disabled in ARM but ingestion accepted iKey (control plane sync issue)" `
                -Description "Local auth is disabled per ARM, but the ingestion endpoint accepted an iKey-only request. This indicates an ARM/control plane sync delay." `
                -Fix "Wait 10-15 minutes, or add/remove a tag on the App Insights resource to force a sync, then re-test." `
                -Portal "App Insights > Properties" `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
        }

        # BOTTOM LINE for -NetworkOnly: ingestion passed but no E2E verification available
        if ($NetworkOnly -and $VerboseOutput) {
            Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
            Write-HostLog "  BOTTOM LINE: " -ForegroundColor Green -NoNewline
            Write-HostLog "Network connectivity validated. Ingestion API accepted test telemetry record." -ForegroundColor White
            Write-HostLog ""
            Write-HostLog "  E2E verification was not performed (-NetworkOnly skips Azure resource checks)." -ForegroundColor Gray
            Write-HostLog "  Use the KQL query below to manually confirm the record arrived in logs." -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  If telemetry from your application is still missing, focus on:" -ForegroundColor Gray
            Write-HostLog "    1. SDK/Agent configuration and initialization issues" -ForegroundColor Gray
            Write-HostLog "    2. Connection string - Does your app use this same connection string?" -ForegroundColor Gray
            Write-HostLog "    3. Sampling - Is adaptive sampling dropping data?" -ForegroundColor Gray
            Write-HostLog "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing" -ForegroundColor Gray
            Write-HostLog "    5. Process state - Is your app process (w3wp.exe, dotnet, node) healthy?" -ForegroundColor Gray
            Write-HostLog "    6. Review any other WARN or INFO messages reported by this tool" -ForegroundColor Gray
            Write-HostLog ""
            Write-HostLog "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics" -ForegroundColor DarkGray
            Write-HostLog "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats" -ForegroundColor DarkGray
            Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
            Write-HostLog ""
        }

        # NetworkOnly: show manual verification KQL since E2E won't run
        if ($NetworkOnly) {
            Write-HostLog ""
            Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
            Write-HostLog "  The ingestion API accepted the test record (HTTP 200), but -NetworkOnly skips" -ForegroundColor DarkGray
            Write-HostLog "  automated verification. Run the following query in App Insights > Logs to confirm arrival:" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  $verifyKql" -ForegroundColor White
            Write-HostLog ""
        }

        # ================================================================
        # END-TO-END VERIFICATION (Data Plane Query)
        # ================================================================
        # Gate: Azure checks active, AI resource was found, ingestion passed.
        # This queries the App Insights data plane API to confirm the test
        # record actually arrived and is queryable in logs.
        # ================================================================
        $e2eVerification = $null

        if ($CheckAzure -and $aiResource) {
            Write-ProgressStart -Name "End-to-End Verification"

            # Resolve the Application ID needed for the data plane API
            # Priority: 1) connection string ApplicationId, 2) AI resource properties
            $appIdForQuery = $null
            if ($csComponents["ApplicationId"]) {
                $appIdForQuery = $csComponents["ApplicationId"]
            } elseif ($aiResource.properties.AppId) {
                $appIdForQuery = $aiResource.properties.AppId
            }

            if ($appIdForQuery) {
                # Acquire data plane token
                $dataPlaneToken = Get-AppInsightsDataPlaneToken -ResourceUrl $dataPlaneResource

                if ($dataPlaneToken) {
                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
                        Write-HostLog "  END-TO-END VERIFICATION" -ForegroundColor Cyan
                        Write-HostLog "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
                        Write-HostLog ""
                        Write-HostLog "  The ingestion API accepted the test record. Now we can verify it actually" -ForegroundColor Gray
                        Write-HostLog "  arrived in the backend logs by querying your Application Insights resource." -ForegroundColor Gray
                        Write-HostLog "  This closes the loop on the entire telemetry pipeline:" -ForegroundColor Gray
                        Write-HostLog "    This machine -> Ingestion API -> Processing Pipeline -> Log Analytics -> Queryable" -ForegroundColor Gray
                        Write-HostLog ""
                        Write-HostLog "  NOTE ON INGESTION LATENCY:" -ForegroundColor DarkGray
                        Write-HostLog "  Data typically appears in a few seconds to a few minutes, but longer pipeline" -ForegroundColor DarkGray
                        Write-HostLog "  ingestion delays can randomly occur. The App Insights SLA covers data plane" -ForegroundColor DarkGray
                        Write-HostLog "  API availability (that it responds), NOT ingestion speed. A slow but successful" -ForegroundColor DarkGray
                        Write-HostLog "  pipeline is within SLA. For the latest SLA terms:" -ForegroundColor DarkGray
                        Write-HostLog "  https://www.microsoft.com/licensing/docs/view/Service-Level-Agreements-SLA-for-Online-Services" -ForegroundColor DarkGray
                        Write-HostLog ""
                        Write-HostLog "  Verifying record arrived in App Insights logs (press Q between checks to skip)..." -ForegroundColor White
                        Write-HostLog "  Querying your App Insights resource for the test record, polling every 10 seconds for up to 60 seconds." -ForegroundColor Gray
                        Write-HostLog ""
                    }

                        # Run the poll/verify loop (show polling output only in verbose mode)
                        $e2eVerification = Test-EndToEndVerification `
                            -AppId $appIdForQuery `
                            -Token $dataPlaneToken `
                            -TestRecordId $ingestionResult.TestRecordId `
                            -ApiHost $dataPlaneHost `
                            -ShowPolling $VerboseOutput

                        # --- Display results ---
                        if ($e2eVerification.Status -eq "PASS") {
                            $e2eSummary = "Record arrived"
                            $dupCount = $e2eVerification.DuplicateCount
                            if ($dupCount -gt 1) {
                                $e2eSummary += " ($dupCount copies -- duplicates detected)"
                            }
                            if ($e2eVerification.Latency.EndToEndSec) {
                                $e2eSummary += " (E2E: $($e2eVerification.Latency.EndToEndSec)s)"
                            }
                            Write-ProgressLine -Name "End-to-End Verification" -Status "OK" -Summary $e2eSummary

                            if ($VerboseOutput) {
                                # Show KQL reference so support engineers can find the record later
                                Write-HostLog ""
                                Write-HostLog "  VERIFICATION QUERY:" -ForegroundColor Cyan
                                Write-HostLog "  The test record was sent, ingested, and successfully retrieved from your App Insights logs." -ForegroundColor DarkGray
                                Write-HostLog "  To find this record later, run the following query in App Insights > Logs:" -ForegroundColor DarkGray
                                Write-HostLog ""
                                Write-HostLog "  $verifyKql" -ForegroundColor White
                                Write-HostLog ""

                                if ($e2eVerification.Latency.SentTimestamp) {
                                    Write-HostLog "  LATENCY BREAKDOWN:" -ForegroundColor Cyan
                                    Write-HostLog ""
                                    Write-HostLog "  Sent (client):       " -ForegroundColor Gray -NoNewline
                                    Write-HostLog "$($e2eVerification.Latency.SentTimestamp)" -ForegroundColor White
                                    Write-HostLog "  Received (pipeline): " -ForegroundColor Gray -NoNewline
                                    Write-HostLog "$($e2eVerification.Latency.ReceivedTimestamp)" -ForegroundColor White -NoNewline
                                    Write-HostLog "   (client -> pipeline: $($e2eVerification.Latency.ClientToPipelineSec)s)" -ForegroundColor DarkGray
                                    Write-HostLog "  Stored (queryable):  " -ForegroundColor Gray -NoNewline
                                    Write-HostLog "$($e2eVerification.Latency.IngestedTimestamp)" -ForegroundColor White -NoNewline
                                    Write-HostLog "   (pipeline -> storage: $($e2eVerification.Latency.PipelineToStoreSec)s)" -ForegroundColor DarkGray
                                    Write-HostLog "  End-to-end:          " -ForegroundColor Gray -NoNewline
                                    Write-HostLog "$($e2eVerification.Latency.EndToEndSec)s" -ForegroundColor Green
                                    Write-HostLog ""
                                    Write-HostLog "  Note: Negative client->pipeline time indicates clock skew between this" -ForegroundColor DarkGray
                                    Write-HostLog "  machine and Azure. This is normal and does not affect telemetry delivery." -ForegroundColor DarkGray
                                    Write-HostLog "  Azure Monitor rejects records timestamped more than 2 hours in the future." -ForegroundColor DarkGray
                                    Write-HostLog ""
                                    Write-HostLog "  WHAT THIS MEANS:" -ForegroundColor Cyan
                                    Write-HostLog "  Client -> Pipeline measures network transit from this machine to Azure Monitor." -ForegroundColor Gray
                                    Write-HostLog "  Pipeline -> Storage measures Azure's internal processing (parsing, indexing)." -ForegroundColor Gray
                                    Write-HostLog "  E2E latency varies by region and load. A result within a few minutes is typical." -ForegroundColor Gray
                                    Write-HostLog "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time" -ForegroundColor DarkGray
                                    Write-HostLog ""
                                }

                                # --- Duplicate detection messaging ---
                                if ($e2eVerification.DuplicateCount -gt 1) {
                                    $dc = $e2eVerification.DuplicateCount
                                    Write-HostLog "  [!] DUPLICATE TELEMETRY DETECTED" -ForegroundColor Yellow
                                    Write-HostLog ""
                                    Write-HostLog "  We sent 1 unique test record but received $dc copies in the query results." -ForegroundColor Yellow
                                    Write-HostLog "  This confirms duplicate telemetry is being written to your workspace." -ForegroundColor Yellow
                                    Write-HostLog ""
                                    if ($script:diagSettingsExportCount -gt 0) {
                                        Write-HostLog "  ROOT CAUSE IDENTIFIED:" -ForegroundColor Cyan
                                        Write-HostLog "  Earlier in this report we detected $($script:diagSettingsExportCount) Diagnostic Setting(s) exporting" -ForegroundColor Gray
                                        Write-HostLog "  App Insights log data to a Log Analytics workspace. This is the source of the" -ForegroundColor Gray
                                        Write-HostLog "  duplicate records. Each Diagnostic Setting creates an additional copy of every" -ForegroundColor Gray
                                        Write-HostLog "  telemetry record in the target workspace." -ForegroundColor Gray
                                        Write-HostLog ""
                                        Write-HostLog "  See the 'Diagnostic Settings Exporting to LA' finding above for fix options." -ForegroundColor Gray
                                    } else {
                                        Write-HostLog "  POSSIBLE CAUSES:" -ForegroundColor Cyan
                                        Write-HostLog "  1. Diagnostic Settings that were recently removed may still have in-flight data" -ForegroundColor Gray
                                        Write-HostLog "  2. Multiple SDKs or agents sending from the same application" -ForegroundColor Gray
                                        Write-HostLog "  3. Data Collection Rules with transformations that fork telemetry" -ForegroundColor Gray
                                    }
                                    Write-HostLog ""

                                    Add-Diagnosis -Severity "INFO" -Title "Duplicate Telemetry Confirmed (E2E Verification)" `
                                        -Summary "Sent 1 test record, received $dc copies -- duplicates confirmed" `
                                        -Description "The E2E verification query returned $dc copies of the single unique test record sent by this tool. This confirms duplicate telemetry is being written. $(if ($script:diagSettingsExportCount -gt 0) { "The $($script:diagSettingsExportCount) Diagnostic Setting(s) exporting to Log Analytics (detected earlier) are the likely root cause." } else { 'Check for Diagnostic Settings, multiple SDKs, or DCR transforms.' })" `
                                        -Fix "Remove Diagnostic Settings that export to LA, or de-duplicate with KQL distinct operator." `
                                        -Portal "App Insights > Monitoring > Diagnostic settings" `
                                        -Docs "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
                                }

                                Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
                                Write-HostLog "  BOTTOM LINE: " -ForegroundColor Green -NoNewline
                                Write-HostLog "Environment validated. Network, auth, and ingestion are working." -ForegroundColor White
                                Write-HostLog ""
                                Write-HostLog "  If telemetry from your application is still missing, focus on:" -ForegroundColor Gray
                                Write-HostLog "    1. SDK/Agent configuration and initialization issues" -ForegroundColor Gray
                                Write-HostLog "    2. Connection string - Does your app use this same connection string?" -ForegroundColor Gray
                                Write-HostLog "    3. Sampling - Is adaptive sampling dropping data?" -ForegroundColor Gray
                                Write-HostLog "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing" -ForegroundColor Gray
                                Write-HostLog "    5. Process state - Is your app process (w3wp.exe, dotnet, node) healthy?" -ForegroundColor Gray
                                Write-HostLog "    6. Review any other WARN or INFO messages reported by this tool" -ForegroundColor Gray
                                Write-HostLog ""
                                Write-HostLog "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics" -ForegroundColor DarkGray
                                Write-HostLog "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats" -ForegroundColor DarkGray
                                Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
                                Write-HostLog ""
                            }

                        } elseif ($e2eVerification.Status -eq "SKIPPED") {
                            Write-HostLog ""
                            Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (verify manually with KQL below)"
                            Write-HostLog ""
                            Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
                            Write-HostLog "  Automated verification was skipped. The ingestion API accepted the test record (HTTP 200)." -ForegroundColor DarkGray
                            Write-HostLog "  Run the following query in App Insights > Logs to confirm the record arrived:" -ForegroundColor DarkGray
                            Write-HostLog ""
                            Write-HostLog "  $verifyKql" -ForegroundColor White
                            Write-HostLog ""

                        } elseif ($e2eVerification.Status -eq "TIMEOUT") {
                            Write-HostLog ""
                            Write-ProgressLine -Name "End-to-End Verification" -Status "INFO" -Summary "Not found after $($e2eVerification.WaitedSeconds)s (pipeline may still be processing)"
                            if ($VerboseOutput) {
                                Write-HostLog ""
                                Write-HostLog "  The test record was accepted by the ingestion API but hasn't appeared in" -ForegroundColor Gray
                                Write-HostLog "  query results yet. This is not necessarily an error -- pipeline processing" -ForegroundColor Gray
                                Write-HostLog "  can take a few minutes under normal conditions." -ForegroundColor Gray
                            }
                            Write-HostLog ""
                            Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
                            Write-HostLog "  The ingestion API accepted the test record (HTTP 200) but it hasn't appeared in query" -ForegroundColor DarkGray
                            Write-HostLog "  results yet. Run the following query in App Insights > Logs after a few minutes:" -ForegroundColor DarkGray
                            Write-HostLog ""
                            Write-HostLog "  $verifyKql" -ForegroundColor White
                            Write-HostLog ""

                        } else {
                            # ERROR status
                            $isAuthError = $e2eVerification.Error -match "Authorization|Unauthorized|Forbidden|Authentication|403|401"
                            $errorSummary = if ($isAuthError) { "Auth failed" } else { "Query failed" }
                            Write-HostLog ""
                            Write-ProgressLine -Name "End-to-End Verification" -Status "INFO" -Summary "$errorSummary -- verify manually with KQL below"
                            Write-HostLog ""
                            Write-HostLog "  Error: $($e2eVerification.Error)" -ForegroundColor Yellow

                            if ($isAuthError -and $VerboseOutput) {
                                Write-HostLog ""
                                Write-HostLog "  DATA PLANE AUTH TROUBLESHOOTING:" -ForegroundColor Cyan
                                Write-HostLog "  The token was acquired but the API rejected it. Common causes:" -ForegroundColor Gray
                                Write-HostLog "    1. Missing RBAC: Your account needs 'Reader' on the App Insights resource" -ForegroundColor Gray
                                Write-HostLog "       (specifically the 'Microsoft.Insights/components/*/read' permission)" -ForegroundColor DarkGray
                                Write-HostLog "    2. Wrong audience: The token must target '$dataPlaneResource'" -ForegroundColor Gray
                                Write-HostLog "    3. Workspace-based query restrictions: If public query access is disabled," -ForegroundColor Gray
                                Write-HostLog "       queries must come from within the AMPLS/private link scope" -ForegroundColor Gray
                                Write-HostLog ""
                                Write-HostLog "  QUICK DIAGNOSTIC: Run this in PowerShell to inspect your token:" -ForegroundColor Cyan
                                Write-HostLog "    `$t = (Get-AzAccessToken -ResourceUrl '$dataPlaneResource').Token" -ForegroundColor White
                                Write-HostLog "    `$t.Split('.')[1].Replace('-','+').Replace('_','/') |" -ForegroundColor White
                                Write-HostLog "      % { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$_.PadRight(`$_.Length + (4 - `$_.Length % 4) % 4, '='))) } |" -ForegroundColor White
                                Write-HostLog "      ConvertFrom-Json | Select-Object aud, iss, upn, roles" -ForegroundColor White
                                Write-HostLog ""
                                Write-HostLog "  Look for: aud = '$dataPlaneResource'" -ForegroundColor Gray
                                Write-HostLog "  If aud is different, the token targets the wrong API." -ForegroundColor Gray
                                Write-HostLog ""
                                Write-HostLog "  GRANT ACCESS (run as subscription/resource owner):" -ForegroundColor Cyan
                                if ($aiResource) {
                                    Write-HostLog "    New-AzRoleAssignment -SignInName '$(try { Get-MaskedEmail (Get-AzContext).Account.Id } catch { '<your-email>' })' ``" -ForegroundColor White
                                    Write-HostLog "      -RoleDefinitionName 'Reader' -Scope '$($aiResource.id)'" -ForegroundColor White
                                } else {
                                    Write-HostLog "    New-AzRoleAssignment -SignInName '<your-email>' ``" -ForegroundColor White
                                    Write-HostLog "      -RoleDefinitionName 'Reader' -Scope '/subscriptions/<sub>/resourceGroups/<rg>/providers/microsoft.insights/components/<ai-name>'" -ForegroundColor White
                                }
                            } elseif (-not $isAuthError -and $VerboseOutput) {
                                Write-HostLog "  This does not mean ingestion failed -- the API accepted the record (HTTP 200)." -ForegroundColor Gray
                            }
                            Write-HostLog ""
                            Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
                            Write-HostLog "  The ingestion API accepted the test record (HTTP 200) but automated verification" -ForegroundColor DarkGray
                            Write-HostLog "  encountered an error. Run the following query in App Insights > Logs to confirm arrival:" -ForegroundColor DarkGray
                            Write-HostLog ""
                            Write-HostLog "  $verifyKql" -ForegroundColor White
                            Write-HostLog ""
                        }
                } else {
                    # Token acquisition failed
                    if ($VerboseOutput) {
                        Write-HostLog ""
                        Write-HostLog "  [i] Could not acquire data plane API token -- skipping end-to-end verification." -ForegroundColor DarkGray
                        Write-HostLog "      Your account may not have Reader access, or the token endpoint is unreachable." -ForegroundColor DarkGray
                        Write-HostLog ""
                    }
                    Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "No data plane token (verify manually with KQL below)"
                    Write-HostLog ""
                    Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
                    Write-HostLog "  The ingestion API accepted the test record (HTTP 200) but a data plane token could not" -ForegroundColor DarkGray
                    Write-HostLog "  be acquired for automated verification. Run the following query in App Insights > Logs:" -ForegroundColor DarkGray
                    Write-HostLog ""
                    Write-HostLog "  $verifyKql" -ForegroundColor White
                    Write-HostLog ""
                }
            } else {
                # No AppId available
                if ($VerboseOutput) {
                    Write-HostLog ""
                    Write-HostLog "  [i] Application ID not found -- skipping end-to-end verification." -ForegroundColor DarkGray
                    Write-HostLog "      The AppId was not in the connection string or resource properties." -ForegroundColor DarkGray
                    Write-HostLog ""
                }
                Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "No Application ID available"
                Write-HostLog ""
                Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
                Write-HostLog "  The ingestion API accepted the test record (HTTP 200) but the Application ID needed for" -ForegroundColor DarkGray
                Write-HostLog "  automated verification was not available. Run the following query in App Insights > Logs:" -ForegroundColor DarkGray
                Write-HostLog ""
                Write-HostLog "  $verifyKql" -ForegroundColor White
                Write-HostLog ""
            }
        } elseif (-not $NetworkOnly) {
            # No Azure login available -- can't do automated E2E verification.
            # Show manual verification guidance with KQL query.
            Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Azure login not available (verify manually with KQL below)"

            if ($VerboseOutput) {
                Write-HostLog ""
                Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-HostLog "  BOTTOM LINE: " -ForegroundColor Green -NoNewline
                Write-HostLog "Network connectivity validated. Ingestion API accepted test telemetry record." -ForegroundColor White
                Write-HostLog ""
                Write-HostLog "  Automated end-to-end verification requires an Azure login (Az.Accounts module)." -ForegroundColor Gray
                Write-HostLog "  The ingestion API accepted the test record (HTTP 200). To confirm it arrived" -ForegroundColor Gray
                Write-HostLog "  in your App Insights resource, run the KQL query below manually." -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "  If telemetry from your application is still missing, focus on:" -ForegroundColor Gray
                Write-HostLog "    1. SDK/Agent configuration and initialization issues" -ForegroundColor Gray
                Write-HostLog "    2. Connection string - Does your app use this same connection string?" -ForegroundColor Gray
                Write-HostLog "    3. Sampling - Is adaptive sampling dropping data?" -ForegroundColor Gray
                Write-HostLog "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing" -ForegroundColor Gray
                Write-HostLog "    5. Process state - Is your app process (w3wp.exe, dotnet, node) healthy?" -ForegroundColor Gray
                Write-HostLog "    6. Review any other WARN or INFO messages reported by this tool" -ForegroundColor Gray
                Write-HostLog ""
                Write-HostLog "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics" -ForegroundColor DarkGray
                Write-HostLog "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats" -ForegroundColor DarkGray
                Write-HostLog "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
                Write-HostLog ""
            }

            Write-HostLog ""
            Write-HostLog "  MANUAL VERIFICATION QUERY:" -ForegroundColor Cyan
            Write-HostLog "  The ingestion API accepted the test record (HTTP 200) but automated verification" -ForegroundColor DarkGray
            Write-HostLog "  is not available without an Azure login. Open Azure Portal > App Insights > Logs" -ForegroundColor DarkGray
            Write-HostLog "  and run this query to confirm the record arrived:" -ForegroundColor DarkGray
            Write-HostLog ""
            Write-HostLog "  $verifyKql" -ForegroundColor White
            Write-HostLog ""
        }
    } elseif ($ingestionResult.Status -eq "INFO") {
        Write-ProgressLine -Name "Telemetry Ingestion" -Status "INFO" -Summary $ingestionResult.Detail
        Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not pass)"
    } else {
        # Correlate: if 401 and local auth is disabled, this is expected, not blocking
        $is401WithEntraAuth = ($ingestionResult.Detail -match "401" -and $localAuthDisabled)

        if ($is401WithEntraAuth) {
            Write-ProgressLine -Name "Telemetry Ingestion" -Status "INFO" -Summary "HTTP 401 (expected -- Entra ID auth required, test uses iKey)"
            Add-Diagnosis -Severity "INFO" -Title "Ingestion Returned 401 (Entra ID Auth Required)" `
                -Summary "HTTP 401 expected -- script uses iKey and local auth but resource requires Entra ID" `
                -Description "This script sends telemetry using iKey and local auth, however Local auth setting is disabled, so only Entra ID bearer tokens are accepted. This 401 is expected for our test." `
                -Fix "If your apps use Entra ID tokens, this is expected. If not seeing telemetry, verify SDK Entra ID config and Monitoring Metrics Publisher role." `
                -Docs "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
        } else {
            Write-ProgressLine -Name "Telemetry Ingestion" -Status "FAIL" -Summary $ingestionResult.Detail

            # Select Portal path and Docs based on HTTP response code
            $ingFailPortal = ""
            $ingFailDocs = "https://learn.microsoft.com/troubleshoot/azure/azure-monitor/welcome-azure-monitor"
            switch ($ingestionResult.HttpStatus) {
                400 {
                    $ingFailPortal = "App Insights > Overview > Connection String (verify iKey)"
                }
                401 {
                    $ingFailPortal = "App Insights > Properties > Local Authentication"
                    $ingFailDocs = "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
                }
                403 {
                    $ingFailPortal = "App Insights > Network Isolation > 'Enabled from all networks'"
                    $ingFailDocs = "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                }
                429 {
                    $ingFailPortal = "App Insights > Usage and estimated costs > Daily Cap"
                    $ingFailDocs = "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"
                }
                439 {
                    $ingFailPortal = "App Insights > Usage and estimated costs > Daily Cap"
                    $ingFailDocs = "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"
                }
            }

            if ($script:ingestionBlockedPreFlight) {
                # Pre-flight already flagged ingestion as BLOCKED -- don't duplicate.
                # Downgrade to a confirmation note that references the earlier diagnosis.
                Add-Diagnosis -Severity "INFO" -Title "Ingestion Block Confirmed by Test" `
                    -Summary "Confirmed: sample telemetry test returned HTTP $($ingestionResult.HttpStatus) (see blocking issue above)" `
                    -Description "The sample telemetry test confirmed the ingestion block detected earlier. $($ingestionResult.Detail)" `
                    -Fix "Resolve the blocking issue above first, then re-run to verify." `
                    -Portal $ingFailPortal `
                    -Docs $ingFailDocs
            } else {
                Add-Diagnosis -Severity "BLOCKING" -Title "Telemetry Ingestion Failed" `
                    -Summary "Telemetry ingestion failed ($($ingestionResult.Detail))" `
                    -Description "Could not send test telemetry to App Insights. $($ingestionResult.Detail)" `
                    -Fix $ingestionResult.Action `
                    -Portal $ingFailPortal `
                    -Docs $ingFailDocs
            }
        }
        Write-ProgressLine -Name "End-to-End Verification" -Status "SKIP" -Summary "Skipped (ingestion test did not pass)"
    }
}

# ============================================================================
# DIAGNOSIS
# ============================================================================

# Safety net: if a progress start is still pending (shouldn't happen, but defensive),
# close the partial line so the diagnosis section starts clean.
if ($script:progressStartPending -and -not $VerboseOutput -and -not $scriptDebugMode) {
    Write-HostLog ""  # Close the partial line
    $script:progressStartPending = ""
}

# Collect all results for counting
$allResults = @()
foreach ($r in $dnsResults) {
    $allResults += @{ Phase = "DNS"; Status = $r.Status; Check = "$($r.Category): $($r.Hostname)"; Detail = $r.Detail; Action = $r.Action; Critical = $r.Critical }
}
foreach ($r in $tcpResults) {
    $allResults += @{ Phase = "TCP"; Status = $r.Status; Check = "$($r.Category): $($r.Hostname)"; Detail = $r.Detail; Action = $r.Action }
}
foreach ($r in $tlsResults) {
    $allResults += @{ Phase = "TLS"; Status = $r.Status; Check = "$($r.Category): $($r.Hostname)"; Detail = $r.Detail; Action = $r.Action }
}
if (-not $SkipIngestionTest -and $ingestionResult) {
    $allResults += @{ Phase = "Ingestion"; Status = $ingestionResult.Status; Check = "POST $($ingestionResult.Endpoint)"; Detail = $ingestionResult.Detail; Action = $ingestionResult.Action }
}
if ($amplsCheckResults -and $amplsCheckResults.Count -gt 0) {
    foreach ($cr in $amplsCheckResults) {
        $amplsStatus = "PASS"
        if ($cr.Status -eq "MISMATCH" -or $cr.Status -eq "FAIL") { $amplsStatus = "FAIL" }
        elseif ($cr.Status -eq "N/A") { $amplsStatus = "INFO" }
        $allResults += @{ Phase = "AMPLS"; Status = $amplsStatus; Check = "AMPLS IP: $($cr.Fqdn)"; Detail = "Expected: $($cr.ExpectedIp) | Actual: $($cr.ActualIp)"; Action = "" }
    }
}

$passCount = 0
$failCount = 0
$warnCount = 0
$infoCount = 0
foreach ($r in $allResults) {
    switch ($r.Status) {
        "PASS" { $passCount++ }
        "FAIL" { $failCount++ }
        "WARN" { $warnCount++ }
        "INFO" { $infoCount++ }
    }
}
$totalChecks = $allResults.Count

# --- Diagnosis Block (always) ---
$blockingItems = @($script:diagnosisItems | Where-Object { $_.Severity -eq "BLOCKING" })
$warningItems = @($script:diagnosisItems | Where-Object { $_.Severity -eq "WARNING" })
$infoItems = @($script:diagnosisItems | Where-Object { $_.Severity -eq "INFO" })
$totalIssues = $blockingItems.Count + $warningItems.Count + $infoItems.Count

# Build ordered list: BLOCKING first, then WARNING, then INFO
$orderedItems = @()
$orderedItems += $blockingItems
$orderedItems += $warningItems
$orderedItems += $infoItems

Write-HostLog ""

# Did the ingestion test actually run and pass?
$ingestionConfirmed = ($ingestionResult -and $ingestionResult.Status -eq "PASS")

if ($totalIssues -eq 0) {
    # ---- No issues found ----

    $azureSkipped = $CheckAzure -and (-not $aiResource)

    if ($azureSkipped) {
        Write-HostLog "========================================================================" -ForegroundColor White
        Write-HostLog "DIAGNOSIS SUMMARY" -ForegroundColor DarkYellow
        Write-HostLog "========================================================================" -ForegroundColor White
        Write-HostLog ""
        if ($aiResource) {
            Write-HostLog "  App Insights:    " -ForegroundColor DarkGray -NoNewline
            Write-HostLog $aiResource.name -ForegroundColor White
        }
        if ($wsName -and $wsName -ne '(unknown)') {
            Write-HostLog "  Log Analytics:   " -ForegroundColor DarkGray -NoNewline
            Write-HostLog $wsName -ForegroundColor White
        }
        if ($aiResource -or ($wsName -and $wsName -ne '(unknown)')) { Write-HostLog "" }
        if ($ingestionConfirmed) {
            Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS, ingestion)." -ForegroundColor Gray
        } elseif ($SkipIngestionTest) {
            Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
            Write-HostLog "  The telemetry ingestion test was not performed (-SkipIngestionTest)." -ForegroundColor Gray
        } elseif ($script:IngestionConsentDeclined) {
            Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
            Write-HostLog "  The telemetry ingestion test was not performed (consent not granted)." -ForegroundColor Gray
        } else {
            Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
        }
        Write-HostLog "  However, the following checks could not run due to Az module issues:" -ForegroundColor Gray
        Write-HostLog "    - AMPLS private link validation" -ForegroundColor DarkGray
        Write-HostLog "    - Local auth / Entra ID configuration" -ForegroundColor DarkGray
        Write-HostLog "    - Ingestion sampling settings" -ForegroundColor DarkGray
        Write-HostLog "    - Backend workspace health and daily cap" -ForegroundColor DarkGray
        Write-HostLog "    - Daily cap settings (AI vs LA mismatch)" -ForegroundColor DarkGray
        Write-HostLog "    - Workspace transforms / DCRs on App Insights tables" -ForegroundColor DarkGray
        Write-HostLog "    - Diagnostic Settings (duplicate ingestion)" -ForegroundColor DarkGray
        Write-HostLog ""
        Write-HostLog "  To run the full check: fix the Az module issue above, then ensure Az.Accounts is installed and you're logged in (Connect-AzAccount)." -ForegroundColor DarkGray
    } else {
        $azureRanSuccessfully = $CheckAzure -and $aiResource
        if ($azureRanSuccessfully) {
            Write-HostLog "========================================================================" -ForegroundColor White
            Write-HostLog "DIAGNOSIS SUMMARY" -ForegroundColor Green
            Write-HostLog "========================================================================" -ForegroundColor White
            Write-HostLog ""
            if ($aiResource) {
                Write-HostLog "  App Insights:    " -ForegroundColor DarkGray -NoNewline
                Write-HostLog $aiResource.name -ForegroundColor White
            }
            if ($wsName -and $wsName -ne '(unknown)') {
                Write-HostLog "  Log Analytics:   " -ForegroundColor DarkGray -NoNewline
                Write-HostLog $wsName -ForegroundColor White
            }
            if ($aiResource -or ($wsName -and $wsName -ne '(unknown)')) { Write-HostLog "" }
            if ($ingestionConfirmed) {
                Write-HostLog "  All connectivity and resource configuration checks passed." -ForegroundColor Gray
                Write-HostLog "  If telemetry from your application is still missing, the issue is likely" -ForegroundColor Gray
                Write-HostLog "  in SDK/agent configuration, not network connectivity." -ForegroundColor Gray
            } elseif ($SkipIngestionTest) {
                Write-HostLog "  Network connectivity and Azure resource configuration checks all passed." -ForegroundColor Gray
                Write-HostLog "  The telemetry ingestion test was not performed (-SkipIngestionTest)." -ForegroundColor Gray
            } elseif ($script:IngestionConsentDeclined) {
                Write-HostLog "  Network connectivity and Azure resource configuration checks all passed." -ForegroundColor Gray
                Write-HostLog "  The telemetry ingestion test was not performed (consent not granted)." -ForegroundColor Gray
            } else {
                Write-HostLog "  All connectivity and resource configuration checks passed." -ForegroundColor Gray
                Write-HostLog "  If telemetry from your application is still missing, the issue is likely" -ForegroundColor Gray
                Write-HostLog "  in SDK/agent configuration, not network connectivity." -ForegroundColor Gray
            }
        } else {
            Write-HostLog "========================================================================" -ForegroundColor White
            Write-HostLog "DIAGNOSIS SUMMARY" -ForegroundColor Green
            Write-HostLog "========================================================================" -ForegroundColor White
            Write-HostLog ""
            if ($ingestionConfirmed) {
                Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS, ingestion)." -ForegroundColor Gray
            } elseif ($SkipIngestionTest) {
                Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
                Write-HostLog "  The telemetry ingestion test was not performed (-SkipIngestionTest)." -ForegroundColor Gray
            } elseif ($script:IngestionConsentDeclined) {
                Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
                Write-HostLog "  The telemetry ingestion test was not performed (consent not granted)." -ForegroundColor Gray
            } else {
                Write-HostLog "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)." -ForegroundColor Gray
            }
            if ($NetworkOnly) {
                Write-HostLog "  Resource configuration checks were skipped (-NetworkOnly)." -ForegroundColor Gray
                Write-HostLog ""
            } else {
                Write-HostLog "  Resource configuration checks (auth, sampling, daily caps, workspace health)" -ForegroundColor Gray
                if ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp) {
                    Write-HostLog "  were not performed. To include resource checks, run this script from" -ForegroundColor Gray
                    Write-HostLog "  Azure Cloud Shell or a machine with Az.Accounts installed." -ForegroundColor Gray
                } else {
                    Write-HostLog "  were not performed. Install Az.Accounts and " -ForegroundColor Gray -NoNewline
                    Write-HostLog "Connect-AzAccount" -ForegroundColor White -NoNewline
                    Write-HostLog " to enable these checks." -ForegroundColor Gray
                }
            }
        }
    }
} else {
    # ---- Issues found: Two-tier display ----

    # === TIER 1: DIAGNOSIS SUMMARY TABLE (verbose only) ===
    # In Compact mode, the progress lines above already serve as the quick-scan overview.
    # The summary table would be redundant right below them with different terminology.
    if ($VerboseOutput) {
        $findingsLabel = if ($totalIssues -eq 1) { "1 finding" } else { "$totalIssues findings" }
        # Header color: red if any BLOCKING, yellow otherwise
        $headerColor = if ($blockingItems.Count -gt 0) { 'Red' } else { 'DarkYellow' }
        Write-HostLog " ========================================================================" -ForegroundColor White
        Write-HostLog " DIAGNOSIS SUMMARY" -ForegroundColor $headerColor -NoNewline
        Write-HostLog ("$findingsLabel".PadLeft(72 - "DIAGNOSIS SUMMARY".Length)) -ForegroundColor DarkGray
        Write-HostLog " ========================================================================" -ForegroundColor White
        Write-HostLog ""

        $itemNum = 0
        foreach ($item in $orderedItems) {
            $itemNum++
            $numStr = "#$itemNum".PadRight(4)
            $sevLabel = $item.Severity.PadRight(10)

            switch ($item.Severity) {
                "BLOCKING" {
                    Write-HostLog "  " -NoNewline
                    Write-HostLog $sevLabel -ForegroundColor Red -NoNewline
                    Write-HostLog "$numStr" -ForegroundColor Red -NoNewline
                    Write-HostLog $item.Summary -ForegroundColor White
                }
                "WARNING" {
                    Write-HostLog "  " -NoNewline
                    Write-HostLog $sevLabel -ForegroundColor DarkYellow -NoNewline
                    Write-HostLog "$numStr" -ForegroundColor DarkYellow -NoNewline
                    Write-HostLog $item.Summary -ForegroundColor Gray
                }
                "INFO" {
                    Write-HostLog "  " -NoNewline
                    Write-HostLog $sevLabel -ForegroundColor Yellow -NoNewline
                    Write-HostLog "$numStr" -ForegroundColor Yellow -NoNewline
                    Write-HostLog $item.Summary -ForegroundColor Gray
                }
            }
        }
        Write-HostLog ""
    }

    # === TIER 2: WHAT TO DO (in priority order) ===

    # Show detected resources (always -- in Compact mode the Diagnosis Summary is skipped,
    # so this is the only place the user sees which resources were evaluated).
    if ($aiResource) {
        Write-HostLog "  App Insights:    " -ForegroundColor DarkGray -NoNewline
        Write-HostLog $aiResource.name -ForegroundColor White
    }
    if ($wsName -and $wsName -ne '(unknown)') {
        Write-HostLog "  Log Analytics:   " -ForegroundColor DarkGray -NoNewline
        Write-HostLog $wsName -ForegroundColor White
    }

    Write-HostLog ""
    Write-HostLog "  ================================================================" -ForegroundColor White
    Write-HostLog "  WHAT TO DO (in priority order)" -ForegroundColor White
    Write-HostLog "  ================================================================" -ForegroundColor White
    Write-HostLog ""

    $itemNum = 0
    foreach ($item in $orderedItems) {
        $itemNum++

        # Header:  #1 [BLOCKING] Title
        $sevColor = switch ($item.Severity) {
            "BLOCKING" { "Red" }
            "WARNING"  { "DarkYellow" }
            "INFO"     { "Yellow" }
        }
        Write-HostLog "  #$itemNum " -ForegroundColor White -NoNewline
        Write-HostLog "[$($item.Severity)]" -ForegroundColor $sevColor -NoNewline
        Write-HostLog " $($item.Title)" -ForegroundColor White

        # Description (word-wrapped with 5-space indent)
        Write-Wrapped -Text $item.Description -Indent 5 -ForegroundColor Gray

        # Fix (word-wrapped; first line has colored prefix, continuation indented to match)
        if ($item.Fix) {
            $fixPrefix = "     -> Fix: "     # 13 chars
            $fixCont   = ' ' * $fixPrefix.Length
            Write-HostLog "     " -NoNewline
            Write-HostLog "->" -ForegroundColor Cyan -NoNewline
            Write-HostLog " Fix: " -ForegroundColor Cyan -NoNewline
            # Word-wrap the fix text; first chunk goes on same line as prefix
            $fixWidth = (Get-ConsoleWidth) - $fixPrefix.Length
            if ($fixWidth -lt 30) { $fixWidth = 30 }
            $fixWords = $item.Fix -split ' '
            $fixLine = ''
            $fixFirst = $true
            foreach ($fw in $fixWords) {
                if ($fixLine.Length -eq 0) {
                    $fixLine = $fw
                } elseif (($fixLine.Length + 1 + $fw.Length) -le $fixWidth) {
                    $fixLine += " $fw"
                } else {
                    if ($fixFirst) { Write-HostLog $fixLine -ForegroundColor Gray; $fixFirst = $false }
                    else { Write-HostLog "$fixCont$fixLine" -ForegroundColor Gray }
                    $fixLine = $fw
                }
            }
            if ($fixLine.Length -gt 0) {
                if ($fixFirst) { Write-HostLog $fixLine -ForegroundColor Gray }
                else { Write-HostLog "$fixCont$fixLine" -ForegroundColor Gray }
            }
        }

        # Portal navigation (word-wrapped)
        if ($item.Portal) {
            $portalPrefix = "     -> Portal: "  # 16 chars
            $portalCont   = ' ' * $portalPrefix.Length
            Write-HostLog "     " -NoNewline
            Write-HostLog "->" -ForegroundColor Cyan -NoNewline
            Write-HostLog " Portal: " -ForegroundColor Cyan -NoNewline
            $portalWidth = (Get-ConsoleWidth) - $portalPrefix.Length
            if ($portalWidth -lt 30) { $portalWidth = 30 }
            $portalWords = $item.Portal -split ' '
            $portalLine = ''
            $portalFirst = $true
            foreach ($pw in $portalWords) {
                if ($portalLine.Length -eq 0) {
                    $portalLine = $pw
                } elseif (($portalLine.Length + 1 + $pw.Length) -le $portalWidth) {
                    $portalLine += " $pw"
                } else {
                    if ($portalFirst) { Write-HostLog $portalLine -ForegroundColor Gray; $portalFirst = $false }
                    else { Write-HostLog "$portalCont$portalLine" -ForegroundColor Gray }
                    $portalLine = $pw
                }
            }
            if ($portalLine.Length -gt 0) {
                if ($portalFirst) { Write-HostLog $portalLine -ForegroundColor Gray }
                else { Write-HostLog "$portalCont$portalLine" -ForegroundColor Gray }
            }
        }

        # Docs link (word-wrapped)
        if ($item.Docs) {
            $docsPrefix = "     -> Docs: "    # 14 chars
            $docsCont   = ' ' * $docsPrefix.Length
            Write-HostLog "     " -NoNewline
            Write-HostLog "->" -ForegroundColor Cyan -NoNewline
            Write-HostLog " Docs: " -ForegroundColor Cyan -NoNewline
            $docsWidth = (Get-ConsoleWidth) - $docsPrefix.Length
            if ($docsWidth -lt 30) { $docsWidth = 30 }
            $docsWords = $item.Docs -split ' '
            $docsLine = ''
            $docsFirst = $true
            foreach ($dw in $docsWords) {
                if ($docsLine.Length -eq 0) {
                    $docsLine = $dw
                } elseif (($docsLine.Length + 1 + $dw.Length) -le $docsWidth) {
                    $docsLine += " $dw"
                } else {
                    if ($docsFirst) { Write-HostLog $docsLine -ForegroundColor DarkGray; $docsFirst = $false }
                    else { Write-HostLog "$docsCont$docsLine" -ForegroundColor DarkGray }
                    $docsLine = $dw
                }
            }
            if ($docsLine.Length -gt 0) {
                if ($docsFirst) { Write-HostLog $docsLine -ForegroundColor DarkGray }
                else { Write-HostLog "$docsCont$docsLine" -ForegroundColor DarkGray }
            }
        }

        Write-HostLog ""
    }
}

# --- Footer (always, part of console output captured by transcript) ---
Write-HostLog "  ================================================================" -ForegroundColor White
if ($Compact) {
    Write-HostLog "  Tip: Run without " -ForegroundColor DarkGray -NoNewline
    Write-HostLog "-Compact" -ForegroundColor White -NoNewline
    Write-HostLog " for verbose output with full explanations." -ForegroundColor DarkGray
}
if (-not $CheckAzure -and -not $NetworkOnly -and -not $AmplsExpectedIps) {
    if ($script:AzureConsentDeclined) {
        Write-HostLog "  Note: Azure resource checks were skipped. User consent was not granted." -ForegroundColor DarkGray
    } else {
        Write-HostLog "  Note: Azure resource checks were skipped (Az.Accounts module not found)." -ForegroundColor DarkGray
        if ($envInfo.IsAppService -or $envInfo.IsFunctionApp -or $envInfo.IsContainerApp) {
            Write-HostLog "  To include resource checks, run this script from Azure Cloud Shell or a machine with Az.Accounts installed." -ForegroundColor DarkGray
        } else {
            Write-HostLog "  To enable AMPLS, workspace health, and E2E checks: " -ForegroundColor DarkGray -NoNewline
            Write-HostLog "Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser" -ForegroundColor White
            Write-HostLog "  then " -ForegroundColor DarkGray -NoNewline
            Write-HostLog "Connect-AzAccount" -ForegroundColor White -NoNewline
            Write-HostLog " and re-run." -ForegroundColor DarkGray
        }
    }
}
if ($NetworkOnly) {
    Write-HostLog "  Tip: Run without " -ForegroundColor DarkGray -NoNewline
    Write-HostLog "-NetworkOnly" -ForegroundColor White -NoNewline
    Write-HostLog " to include Azure resource checks (AMPLS, workspace health, known issues)." -ForegroundColor DarkGray
}
if (-not $AutoApprove) {
    Write-HostLog "  Tip: Run with " -ForegroundColor DarkGray -NoNewline
    Write-HostLog "-AutoApprove" -ForegroundColor White -NoNewline
    Write-HostLog " to skip consent prompts on repeat runs." -ForegroundColor DarkGray
}
Write-HostLog "  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/welcome-azure-monitor" -ForegroundColor DarkGray
Write-HostLog "  Source: https://github.com/microsoft/appinsights-telemetry-flow" -ForegroundColor DarkGray
Write-HostLog "  ================================================================" -ForegroundColor White
Write-HostLog ""

# ============================================================================
# Save report
# ============================================================================

if ($OutputPath) {
    # SDL 10027: Validate OutputPath against path traversal and UNC paths
    # Block UNC paths (\\server\share) which could write reports containing partial iKeys
    # and internal hostnames to remote network shares.
    if ($OutputPath -match '^\\\\') {
        Write-HostLog "  [ERROR] -OutputPath cannot be a UNC path (network share)." -ForegroundColor Red
        Write-HostLog "  Specify a local filesystem path instead." -ForegroundColor Yellow
        $OutputPath = $null  # fall through to default (script directory)
    } else {
        # Resolve to absolute path and block traversal attempts
        $resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
        if ($resolvedOutput -ne $OutputPath -and $OutputPath -match '\.\.' ) {
            Write-HostLog "  [WARN] -OutputPath contained path traversal ('..'), resolved to: $resolvedOutput" -ForegroundColor Yellow
        }
        $OutputPath = $resolvedOutput
    }

    # --- Resolve output file path ---
    # If OutputPath is a directory (or doesn't end in .json), auto-generate filenames
    # Format: AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{UTC-TIMESTAMP}.json  (and .txt)
    # When the AI resource name is not available the {RESOURCE} segment is omitted.
    $utcTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmmss") + "Z"
    $hostName = $envInfo.ComputerName -replace '[\\/:*?"<>|\s\(\)]', '_'  # sanitize for filename
    $safeAiName = if ($aiResource) { $aiResource.name -replace '[\\/:*?"<>|\s\(\)]', '_' } else { '' }
    $autoName = if ($safeAiName) { "AppInsights-Diag_${hostName}_${safeAiName}_${utcTimestamp}" } else { "AppInsights-Diag_${hostName}_${utcTimestamp}" }

    $isDirectory = (Test-Path -Path $OutputPath -PathType Container)
    $looksLikeDir = (-not $OutputPath.EndsWith(".json")) -and (-not $OutputPath.EndsWith(".txt"))

    if ($isDirectory -or $looksLikeDir) {
        # Treat as directory -- create it if needed, then auto-name
        if (-not (Test-Path $OutputPath)) {
            try {
                New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            } catch {
                Write-HostLog "  [!] Cannot create directory: $OutputPath -- falling back to script directory" -ForegroundColor Yellow
                $OutputPath = $null  # fall through to default
            }
        }
        if ($OutputPath) {
            $jsonPath = Join-Path $OutputPath "$autoName.json"
            $txtPath = Join-Path $OutputPath "$autoName.txt"
        }
    } else {
        # Treat as explicit .json filename
        $jsonPath = $OutputPath
        $txtPath = [System.IO.Path]::ChangeExtension($jsonPath, ".txt")
    }
}

# Default: always save to the script's own directory if no OutputPath was given (or it failed)
if (-not $OutputPath -or -not $jsonPath) {
    $utcTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmmss") + "Z"
    $hostName = $envInfo.ComputerName -replace '[\\/:*?"<>|\s\(\)]', '_'
    $safeAiName = if ($aiResource) { $aiResource.name -replace '[\\/:*?"<>|\s\(\)]', '_' } else { '' }
    $autoName = if ($safeAiName) { "AppInsights-Diag_${hostName}_${safeAiName}_${utcTimestamp}" } else { "AppInsights-Diag_${hostName}_${utcTimestamp}" }

    # $PSScriptRoot = directory where the .ps1 file lives
    # Falls back to current working directory if run from a code block or stdin
    $defaultDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $jsonPath = Join-Path $defaultDir "$autoName.json"
    $txtPath = Join-Path $defaultDir "$autoName.txt"
}

$ingestionForReport = $null
if ($ingestionResult) { $ingestionForReport = $ingestionResult }

$e2eForReport = $null
if ($e2eVerification) {
    $e2eForReport = @{
        Status = $e2eVerification.Status
        RecordFound = $e2eVerification.RecordFound
        PollAttempts = $e2eVerification.PollAttempts
        WaitedSeconds = $e2eVerification.WaitedSeconds
        UserSkipped = $e2eVerification.UserSkipped
        Latency = $e2eVerification.Latency
        Error = $e2eVerification.Error
        VerificationKql = if ($verifyKql) { $verifyKql } else { $null }
    }
}


$amplsForReport = $null
if ($amplsInfo.Checked) {
    $amplsForReport = @{
        Checked = $amplsInfo.Checked
        ResourceFound = $amplsInfo.ResourceFound
        AmplsLinked = $amplsInfo.AmplsLinked
        AccessModes = $amplsInfo.AccessModes
        ComparisonResults = $amplsInfo.ComparisonResults
        AccessAssessment = $amplsInfo.AccessAssessment
    }
}

$report = @{
    ToolVersion = $ScriptVersion
    Timestamp = Get-Timestamp
    Environment = @{
        ComputerName = $envInfo.ComputerName
        OS = $envInfo.OS
        PowerShellVersion = $envInfo.PowerShellVersion
        AzureHostType = $envInfo.AzureHostType
        AzureHostDetail = $envInfo.AzureHostDetail
        IsAppService = $envInfo.IsAppService
        IsFunctionApp = $envInfo.IsFunctionApp
        IsContainerApp = $envInfo.IsContainerApp
        IsKubernetes = $envInfo.IsKubernetes
        IsCloudShell = $envInfo.IsCloudShell
        IsContainer = $envInfo.IsContainer
        ProxyDetected = $proxyDetected
        ProxyDetails = $proxyDetails
        ConsoleColorSupported = $script:UseColor
    }
    ConnectionString = @{
        InstrumentationKey = $maskedKey
        IngestionEndpoint = $ingestionEndpoint
        LiveEndpoint = $liveEndpoint
        IsGlobalEndpoint = $isGlobalEndpoint
        Cloud = $cloudLabel
        CloudSuffix = $cloudSuffix
    }
    KnownIssues = @{
        LocalAuthDisabled = $localAuthDisabled
        IngestionSamplingPct = if ($CheckAzure -and $aiResource) { $samplingPct } else { $null }
        WorkspaceStatus = if ($wsResource) { "Exists" } elseif ($wsResourceId -and -not $wsResource) { "NotFound" } else { $null }
        DailyCapStatus = if ($wsResource) { $capStatus } else { $null }
        AiDailyCapGb = if ($aiCapOff) { "OFF" } elseif ($null -ne $aiCapGb) { $aiCapGb } else { $null }
        LaDailyCapGb = if ($laCapOff) { "OFF" } elseif ($null -ne $laCapGb) { $laCapGb } else { $null }
        DailyCapMismatch = (-not $laCapOff -and -not $aiCapOff -and $null -ne $laCapGb -and $null -ne $aiCapGb -and $laCapGb -lt $aiCapGb)
        WorkspaceTransforms = if ($dcrFindings.Count -gt 0) { $dcrFindings } else { $null }
    }
    Results = @{
        DNS = $dnsResults
        TCP = $tcpResults
        TLS = $tlsResults
        AMPLS = $amplsForReport
        Ingestion = $ingestionForReport
        EndToEndVerification = $e2eForReport
    }
    Diagnosis = $script:diagnosisItems
    Summary = @{
        TotalChecks = $totalChecks
        Passed = $passCount
        Warnings = $warnCount
        Failed = $failCount
        AmplsDetected = $hasAmplsSignals
        AmplsValidated = $amplsInfo.Checked
        AzureChecksRequested = [bool]$CheckAzure
        AzureChecksCompleted = ($CheckAzure -and [bool]$aiResource)
        DetectedAppInsights = if ($aiResource) { $aiResource.id } else { $null }
        DetectedLogAnalytics = if ($wsResourceId) { $wsResourceId } else { $null }
    }
}

# Save JSON report
try {
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
    $script:jsonSaved = $true
} catch {
    $script:jsonSaved = $false
    Write-HostLog "  [!] Could not write report to: $jsonPath" -ForegroundColor Yellow
    Write-HostLog "      Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-HostLog "      Try: -OutputPath to a writable directory, or run from a folder with write access." -ForegroundColor DarkGray
}

# Save console output as TXT (header + transcript mirror)
$txtLines = @()
$txtLines += "============================================================"
$txtLines += "Application Insights Telemetry Flow Diagnostics v$ScriptVersion"
$txtLines += "============================================================"
$txtLines += "Generated:      $(Get-Timestamp)"
$txtLines += "Host:           $($envInfo.ComputerName) ($($envInfo.OS))"
if ($envInfo.AzureHostType) {
    $azureLine = "Azure:          $($envInfo.AzureHostType)"
    if ($envInfo.AzureHostDetail) { $azureLine += " | $($envInfo.AzureHostDetail)" }
    $txtLines += $azureLine
}
$txtLines += "iKey:           $maskedKey"
$txtLines += "Endpoint:       $ingestionEndpoint"
if ($cloudSuffix -ne "com") { $txtLines += "Cloud:          $cloudLabel" }
if ($aiResource) { $txtLines += "App Insights:   $($aiResource.name)" }
if ($wsName) { $txtLines += "Log Analytics:  $wsName" }
$txtLines += ""

# Diagnosis summary (always included in TXT, even if suppressed from Compact console)
if ($orderedItems.Count -gt 0) {
    $findingsLabel = if ($orderedItems.Count -eq 1) { "1 finding" } else { "$($orderedItems.Count) findings" }
    $txtLines += " DIAGNOSIS SUMMARY ($findingsLabel)"
    $txtLines += " ------------------------------------------------------------"
    $txtItemNum = 0
    foreach ($diag in $orderedItems) {
        $txtItemNum++
        $txtLines += "$($diag.Severity.PadRight(10)) #$txtItemNum  $($diag.Summary)"
    }
    $txtLines += ""
} else {
    if ($CheckAzure -and -not $aiResource) {
        $txtLines += " DIAGNOSIS: Network checks passed. Azure resource checks SKIPPED."
    } elseif ($CheckAzure -and $aiResource) {
        $txtLines += " DIAGNOSIS: No issues found. All checks passed."
    } else {
        $txtLines += " DIAGNOSIS: All network checks passed. Resource checks not performed."
    }
    $txtLines += ""
}

# Append captured console output from Write-HostLog override
$consoleContent = $script:consoleLog.ToString().Trim()

if ($consoleContent) {
    $txtLines += "============================================================"
    $txtLines += "CONSOLE OUTPUT"
    $txtLines += "============================================================"
    $txtLines += ""
    $txtLines += $consoleContent
} else {
    # Fallback: Write-HostLog override not captured (shouldn't happen, but be safe)
    if ($orderedItems.Count -gt 0) {
        $txtLines += "WHAT TO DO (in priority order)"
        $txtLines += "------------------------------------------------------------"
        if ($aiResource) { $txtLines += "App Insights:  $($aiResource.name)" }
        if ($wsName) { $txtLines += "Log Analytics:  $wsName" }
        if ($aiResource -or $wsName) { $txtLines += "" }
        $txtItemNum = 0
        foreach ($diag in $orderedItems) {
            $txtItemNum++
            $txtLines += "#$txtItemNum [$($diag.Severity)] $($diag.Title)"
            $txtLines += "   $($diag.Description)"
            if ($diag.Fix) { $txtLines += "   -> Fix: $($diag.Fix)" }
            if ($diag.Portal) { $txtLines += "   -> Portal: $($diag.Portal)" }
            if ($diag.Docs) { $txtLines += "   -> Docs: $($diag.Docs)" }
            $txtLines += ""
        }
    }
}

try {
    ($txtLines -join "`r`n") | Out-File -FilePath $txtPath -Encoding utf8
    if ($script:jsonSaved) { Write-HostLog "  Report saved: $jsonPath" -ForegroundColor Green }
    Write-HostLog "  Console log saved: $txtPath" -ForegroundColor Green
} catch {
    if ($script:jsonSaved) { Write-HostLog "  Report saved: $jsonPath" -ForegroundColor Green }
    Write-HostLog "  [!] Could not write console log to: $txtPath" -ForegroundColor Yellow
}

Write-HostLog ""
Write-HostLog "  Application Insights connectivity test complete." -ForegroundColor White
Write-HostLog ""

# ============================================================================
# Exit code (for automation and batch use)
# ============================================================================
# 0 = No issues found (all checks passed, no diagnosis findings)
# 1 = INFO findings only (informational items, no action required)
# 2 = WARNING detected (telemetry at risk but may still work)
# 3 = BLOCKING issue detected (telemetry is broken)
$hasBlocking = @($script:diagnosisItems | Where-Object { $_.Severity -eq "BLOCKING" }).Count -gt 0
$hasWarning  = @($script:diagnosisItems | Where-Object { $_.Severity -eq "WARNING" }).Count -gt 0
$hasInfo     = @($script:diagnosisItems | Where-Object { $_.Severity -eq "INFO" }).Count -gt 0
if ($hasBlocking) { exit 3 }
elseif ($hasWarning) { exit 2 }
elseif ($hasInfo) { exit 1 }
else { exit 0 }
#endregion Main Execution