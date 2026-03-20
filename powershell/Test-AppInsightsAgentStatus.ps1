<#PSScriptInfo
.VERSION 0.2.0
.GUID c8d3f1a2-6b4e-4f7a-9c5d-2e1a0b3f8d7c
.AUTHOR Todd Foust (Microsoft)
.COMPANYNAME Microsoft
.COPYRIGHT (c) Microsoft Corporation. All rights reserved.
.TAGS ApplicationInsights AzureMonitor Diagnostics Troubleshooting Agent StatusMonitor Redfield IIS
.PROJECTURI https://github.com/microsoft/appinsights-telemetry-flow
.LICENSEURI https://github.com/microsoft/appinsights-telemetry-flow/blob/main/LICENSE
.RELEASENOTES
  v0.2.0 - Preview release. Checks IIS services, applicationHost.config module
           registration, GAC assembly, registry environment variables (Classic AI and
           OpenTelemetry modes), app pool pipeline mode, performance counter permissions,
           Redfield configuration files, PowerShell module, ASP.NET Core startup hooks,
           and optional Instrumentation Engine (CLR profiler) configuration. Structured
           diagnosis with prioritized remediation steps and docs links.
#>

<#
.SYNOPSIS
    Diagnoses whether Application Insights Agent (Status Monitor V2 / Redfield) is
    properly installed, configured, and actively attached on a Windows machine with IIS.

.DESCRIPTION
    Comprehensive diagnostic tool for the Azure Application Insights on-premises agent
    (also known as Status Monitor V2 or Redfield Agent). Validates all installation
    artifacts created during the Enable-ApplicationInsightsMonitoring workflow and
    inspects running processes to determine agent attachment status.

    Currently supports Status Monitor V2 (Redfield) on IIS. Future versions will
    support VM Extensions, App Service, and Functions auto-instrumentation.

    QUICK START:
      .\Test-AppInsightsAgentStatus.ps1
      .\Test-AppInsightsAgentStatus.ps1 -IncludeInstrumentationEngine

    WHAT IT CHECKS:
      - IIS service health (W3SVC and WAS)
      - applicationHost.config module registration (ManagedHttpModuleHelper)
      - GAC assembly registration
      - Registry environment variables (Classic AI and OpenTelemetry modes)
      - IIS application pool pipeline mode (Integrated vs Classic)
      - Application pool identity performance counter permissions
      - Redfield configuration files (ikey.config)
      - PowerShell module installation (Az.ApplicationMonitor)
      - ASP.NET Core startup hook and hosting startup files
      - Instrumentation Engine CLR profiler configuration (auto-detected or -IncludeInstrumentationEngine)

    All checks are READ-ONLY. The script never modifies any configuration.

    OUTPUT MODES:
    - Default:  Full verbose output with educational explanations
    - Compact:  Progress lines only with focused diagnosis at the end

    WHAT TO EXPECT:
    The script runs non-interactively in ~5-15 seconds. Results display as they
    complete. Must be run as Administrator for full accuracy.

    COMPANION TOOL:
    If the agent status looks healthy but telemetry is still missing, run
    Test-AppInsightsTelemetryFlow.ps1 to diagnose network path and backend issues.

.PARAMETER IncludeInstrumentationEngine
    Force Instrumentation Engine (CLR Profiler) checks. These checks run automatically
    when COR_ENABLE_PROFILING is detected in the IIS service registry. Use this switch
    to force the checks even when auto-detection finds no evidence.

.PARAMETER Compact
    Show compact progress-line output instead of full verbose output. Default output
    is verbose with educational explanations for each check. Use -Compact for a quick
    overview or when pasting into a support ticket.

.PARAMETER OutputPath
    Directory to save diagnostic report files. Files are auto-named with hostname and
    UTC timestamp: AppInsights-AgentDiag_{HOSTNAME}_{yyyy-MM-ddTHHmmssZ}.json + .txt
    If not specified, reports are saved to the script's own directory.

.EXAMPLE
    # Full diagnostic (verbose output with educational explanations)
    .\Test-AppInsightsAgentStatus.ps1

.EXAMPLE
    # Compact output for quick checks or support tickets
    .\Test-AppInsightsAgentStatus.ps1 -Compact

.EXAMPLE
    # Force Instrumentation Engine checks (normally auto-detected)
    .\Test-AppInsightsAgentStatus.ps1 -IncludeInstrumentationEngine

.EXAMPLE
    # Save reports to a specific directory
    .\Test-AppInsightsAgentStatus.ps1 -OutputPath "C:\diag"

.NOTES
    Version: 0.2.0
    Author:  Todd Foust (Microsoft) - Azure Monitor App Insights Support
    Source:  https://github.com/microsoft/appinsights-telemetry-flow
    Docs:    https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent
             https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot

    EXIT CODES:
      0 = No blocking issues (all checks passed or only informational findings)
      1 = BLOCKING issue detected (agent is broken or not functional)
      2 = WARNING detected (agent may partially work but has issues)
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '')]
[CmdletBinding()]
param(
    [switch]$IncludeInstrumentationEngine,
    [switch]$Compact,
    [string]$OutputPath
)

# ============================================================================
# CONFIGURATION
# ============================================================================
$ScriptVersion = "0.2.0"
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# --- Output mode ---
# Full verbose output is the default. -Compact reduces to progress lines.
$VerboseOutput = -not $Compact

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-Timestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Write-Header {
    param([string]$Title)
    if (-not $VerboseOutput) { return }
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Write-StepHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Write-Result {
    <#
    .SYNOPSIS
        Writes a single check result line in verbose mode. Matches the connectivity
        script's Write-Result pattern: [symbol] Check / Detail / ACTION.
    #>
    param(
        [string]$Status,  # PASS, FAIL, WARN, INFO, SKIP
        [string]$Check,
        [string]$Detail,
        [string]$Action
    )
    if (-not $VerboseOutput) { return }
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'DarkYellow' }
        'INFO' { 'Gray' }
        'SKIP' { 'DarkGray' }
        default { 'White' }
    }
    $symbol = switch ($Status) {
        'PASS' { [char]0x2713 }  # checkmark
        'FAIL' { [char]0x2717 }  # X mark
        'WARN' { '!' }
        'INFO' { 'i' }
        'SKIP' { '-' }
        default { '?' }
    }
    Write-Host "  [$symbol] " -ForegroundColor $color -NoNewline
    Write-Host "$Check" -ForegroundColor White
    if ($Detail) {
        foreach ($dLine in ($Detail -split "`n")) {
            Write-Host "      $dLine" -ForegroundColor Gray
        }
    }
    if ($Action -and $Status -in @('FAIL','WARN','INFO')) {
        Write-Host "      ACTION: $Action" -ForegroundColor Yellow
    }
}

function Write-DetailHost {
    <# Writes to host only when verbose output is active (not -Compact). #>
    param(
        [string]$Object = "",
        [string]$ForegroundColor = "White",
        [switch]$NoNewline
    )
    if (-not $VerboseOutput) { return }
    if ($NoNewline) {
        Write-Host $Object -ForegroundColor $ForegroundColor -NoNewline
    } else {
        Write-Host $Object -ForegroundColor $ForegroundColor
    }
}

$script:progressStartPending = ""

function Write-ProgressStart {
    <#
    .SYNOPSIS
        Prints the leading portion of a progress line with no newline, giving the user
        visual feedback that a test is running. Only outputs in compact mode.
    #>
    param([string]$Name)

    if ($VerboseOutput) {
        $script:progressStartPending = $Name
        return
    }

    if ($script:progressStartPending) {
        $clearWidth = 80
        Write-Host "`r$(' ' * $clearWidth)`r" -NoNewline
    }

    $totalWidth = 36
    $dots = $totalWidth - $Name.Length
    if ($dots -lt 3) { $dots = 3 }
    $leader = " " + ("." * $dots) + " "

    Write-Host "  $Name" -NoNewline -ForegroundColor White
    Write-Host $leader -NoNewline -ForegroundColor DarkGray

    $script:progressStartPending = $Name
}

function Write-ProgressLine {
    <#
    .SYNOPSIS
        Prints a compact progress line: "  Check Name ............... STATUS  summary"
        Always prints regardless of output mode.
    #>
    param(
        [string]$Name,
        [string]$Status,   # OK, WARN, INFO, FAIL, SKIP
        [string]$Summary
    )

    $statusColor = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'DarkYellow' }
        'INFO' { 'Yellow' }
        'FAIL' { 'Red' }
        'SKIP' { 'DarkGray' }
        default { 'White' }
    }

    $statusWidth = 5
    $displayStatus = $Status.PadRight($statusWidth)

    $totalWidth = 36
    $dots = $totalWidth - $Name.Length
    if ($dots -lt 3) { $dots = 3 }
    $leader = " " + ("." * $dots) + " "

    if ($script:progressStartPending) {
        if ($script:progressStartPending -eq $Name -and -not $VerboseOutput) {
            Write-Host $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-Host "  $Summary" -ForegroundColor Gray
        } elseif (-not $VerboseOutput) {
            $clearWidth = 80
            Write-Host "`r$(' ' * $clearWidth)`r" -NoNewline
            Write-Host "  $Name" -NoNewline -ForegroundColor White
            Write-Host $leader -NoNewline -ForegroundColor DarkGray
            Write-Host $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-Host "  $Summary" -ForegroundColor Gray
        } else {
            Write-Host ''
            Write-Host "  $Name" -NoNewline -ForegroundColor White
            Write-Host $leader -NoNewline -ForegroundColor DarkGray
            Write-Host $displayStatus -NoNewline -ForegroundColor $statusColor
            Write-Host "  $Summary" -ForegroundColor Gray
        }
        $script:progressStartPending = ""
    } else {
        if ($VerboseOutput) { Write-Host '' }
        Write-Host "  $Name" -NoNewline -ForegroundColor White
        Write-Host $leader -NoNewline -ForegroundColor DarkGray
        Write-Host $displayStatus -NoNewline -ForegroundColor $statusColor
        Write-Host "  $Summary" -ForegroundColor Gray
    }
}

# --- Diagnosis collector ---
$script:diagnosisItems = @()

function Add-Diagnosis {
    <#
    .SYNOPSIS
        Adds an issue to the diagnosis collector for display in the final summary.
        Matches the connectivity script's Add-Diagnosis pattern.
    #>
    param(
        [ValidateSet('BLOCKING','WARNING','INFO')]
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

function Get-RegistryEnvironmentValue {
    <#
    .SYNOPSIS
        Reads the REG_MULTI_SZ 'Environment' value from a registry service key
        and returns it as a hashtable of Name=Value pairs.
    #>
    param([string]$ServiceKeyPath)

    $result = @{
        Exists = $false
        Raw    = @()
        Parsed = @{}
    }

    try {
        $key = Get-ItemProperty -Path "HKLM:\$ServiceKeyPath" -Name 'Environment' -ErrorAction Stop
        $values = $key.Environment
        $result.Exists = $true
        $result.Raw = $values

        foreach ($entry in $values) {
            $parts = $entry -split '=', 2
            if ($parts.Count -eq 2) {
                $result.Parsed[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
    }
    catch {
        $null = $_ # Key or value doesn't exist
    }

    $result
}

# ============================================================================
# RESULT COLLECTOR
# ============================================================================
# Collects all check results for summary stats and report output.
$allResults = New-Object System.Collections.Generic.List[PSCustomObject]

function Add-CheckResult {
    <#
    .SYNOPSIS
        Records a check result and writes it to both verbose and compact output.
        Use -Silent to collect the result without writing verbose output (for
        sections that render their own consolidated table).
    #>
    param(
        [string]$CheckName,
        [ValidateSet('PASS','WARN','FAIL','INFO')]
        [string]$Status,
        [string]$Message,
        [string]$Detail = '',
        [string]$Action = '',
        [switch]$Silent
    )

    # Write verbose output (unless Silent)
    if (-not $Silent) {
        $verboseStatus = switch ($Status) {
            'WARN' { 'WARN' }
            default { $Status }
        }
        Write-Result -Status $verboseStatus -Check "$CheckName -- $Message" -Detail $Detail -Action $Action
    }

    # Collect result
    $obj = [PSCustomObject]@{
        Check   = $CheckName
        Status  = $Status
        Message = $Message
        Detail  = $Detail
        Action  = $Action
    }
    $allResults.Add($obj)
}

# ============================================================================
# PREFLIGHT
# ============================================================================

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for full diagnostic accuracy."
    Write-Warning "Some checks `(GAC, registry, IIS config`) may fail without elevation.`n"
}


# ============================================================================
# KNOWN CONSTANTS
# ============================================================================

# Public release public key token
$PublicKeyToken_Public  = '31bf3856ad364e35'
# Internal build public key token
$PublicKeyToken_Internal = 'f23a46de0be5d6f3'

$HttpModuleFQN_Public   = "Microsoft.AppInsights.IIS.ManagedHttpModuleHelper.ManagedHttpModuleHelper, Microsoft.AppInsights.IIS.ManagedHttpModuleHelper, Version=1.0.0.0, Culture=neutral, PublicKeyToken=$PublicKeyToken_Public"
$HttpModuleFQN_Internal = "Microsoft.AppInsights.IIS.ManagedHttpModuleHelper.ManagedHttpModuleHelper, Microsoft.AppInsights.IIS.ManagedHttpModuleHelper, Version=1.0.0.0, Culture=neutral, PublicKeyToken=$PublicKeyToken_Internal"

$RegistryServicePaths = @(
    'SYSTEM\CurrentControlSet\Services\IISADMIN',
    'SYSTEM\CurrentControlSet\Services\W3SVC',
    'SYSTEM\CurrentControlSet\Services\WAS'
)

# Environment variables set during codeless attach (classic AI SDK mode)
$ExpectedEnvVars_ClassicAI = @(
    'MicrosoftAppInsights_ManagedHttpModulePath',
    'MicrosoftAppInsights_ManagedHttpModuleType',
    'ASPNETCORE_HOSTINGSTARTUPASSEMBLIES',
    'DOTNET_STARTUP_HOOKS'
)

# Environment variables set for OpenTelemetry mode
$ExpectedEnvVars_OpenTelemetry = @(
    'ASPNETCORE_HOSTINGSTARTUPASSEMBLIES',
    'DOTNET_ADDITIONAL_DEPS',
    'DOTNET_SHARED_STORE',
    'DOTNET_STARTUP_HOOKS',
    'OTEL_DOTNET_AUTO_HOME',
    'OTEL_DOTNET_AUTO_PLUGINS'
)

# Instrumentation Engine environment variables
$ExpectedEnvVars_InstrumentationEngine = @(
    'COR_ENABLE_PROFILING',
    'COR_PROFILER',
    'COR_PROFILER_PATH_32',
    'COR_PROFILER_PATH_64',
    'MicrosoftInstrumentationEngine_Host',
    'MicrosoftInstrumentationEngine_HostPath_32',
    'MicrosoftInstrumentationEngine_HostPath_64',
    'MicrosoftInstrumentationEngine_ConfigPath32_Private',
    'MicrosoftInstrumentationEngine_ConfigPath64_Private'
)

$COR_PROFILER_CLSID = '{324F817A-7420-4E6D-B3C1-143FBED6D855}'

# ============================================================================
# BANNER
# ============================================================================

Write-Host ''
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host '   Application Insights Agent -- Status Diagnostic' -ForegroundColor Cyan
Write-Host '   (Status Monitor V2 / Redfield Agent)' -ForegroundColor Cyan
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Machine    : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Date       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor Gray
Write-Host "  User       : $env:USERDOMAIN\$env:USERNAME `(Admin: $isAdmin`)" -ForegroundColor Gray
Write-Host "  PowerShell : $($PSVersionTable.PSVersion) `($($PSVersionTable.PSEdition)`)" -ForegroundColor Gray
Write-Host "  Script     : v$ScriptVersion" -ForegroundColor Gray

# --- Pre-scan: detect agent mode and module version for the banner summary ---
$bannerMode = 'Not detected'
$bannerModuleVersion = $null
$bannerIisSiteCount = $null

# Quick mode detection from IISADMIN registry
$quickEnv = Get-RegistryEnvironmentValue -ServiceKeyPath $RegistryServicePaths[0]
if ($quickEnv.Exists) {
    if ($quickEnv.Parsed.ContainsKey('OTEL_DOTNET_AUTO_HOME')) {
        $bannerMode = 'OpenTelemetry'
    } elseif ($quickEnv.Parsed.ContainsKey('MicrosoftAppInsights_ManagedHttpModulePath')) {
        $bannerMode = 'Classic Application Insights SDK'
    } else {
        $bannerMode = 'Unknown (registry exists but mode markers not found)'
    }
} else {
    $bannerMode = 'Not configured (no registry environment variables)'
}

# Auto-detect Instrumentation Engine from registry evidence
$ieDetected = $quickEnv.Exists -and $quickEnv.Parsed.ContainsKey('COR_ENABLE_PROFILING')

# Quick module version check
$quickModule = Get-Module -Name 'Az.ApplicationMonitor' -ListAvailable -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $quickModule) {
    $quickModule = Get-Module -Name 'ApplicationInsightsAgent' -ListAvailable -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($quickModule) {
    $bannerModuleVersion = $quickModule.Version.ToString()
}

# Quick IIS site count
try {
    Import-Module WebAdministration -ErrorAction Stop
    $bannerIisSiteCount = @(Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue).Count
} catch {
    $null = $_ # WebAdministration not available
}

Write-Host ''
Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host "  Agent Mode:   " -ForegroundColor Gray -NoNewline
if ($bannerMode -match 'Not configured|Not detected') {
    Write-Host $bannerMode -ForegroundColor Yellow
} else {
    Write-Host $bannerMode -ForegroundColor White
}
if ($bannerModuleVersion) {
    Write-Host "  Module:       " -ForegroundColor Gray -NoNewline
    Write-Host "Az.ApplicationMonitor v$bannerModuleVersion" -ForegroundColor White
} else {
    Write-Host "  Module:       " -ForegroundColor Gray -NoNewline
    Write-Host "(not found)" -ForegroundColor DarkGray
}
if ($null -ne $bannerIisSiteCount) {
    Write-Host "  IIS Sites:    " -ForegroundColor Gray -NoNewline
    Write-Host "$bannerIisSiteCount" -ForegroundColor White
}
Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

if (-not $VerboseOutput) {
    Write-Host '  Running diagnostics...' -ForegroundColor Gray
    Write-Host ''
}

# ============================================================================
# STEP 1: IIS Service Status
# ============================================================================

$stepNumber = 1
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: IIS Service Status"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The Application Insights Agent works by injecting an HTTP module into IIS.' -ForegroundColor Gray
    Write-Host '  IIS must be installed and running for the agent to intercept requests and' -ForegroundColor Gray
    Write-Host '  collect telemetry from your ASP.NET and ASP.NET Core applications.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - W3SVC (World Wide Web Publishing Service) -- the core IIS web server service' -ForegroundColor Gray
    Write-Host '  - WAS (Windows Process Activation Service) -- manages IIS worker processes' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - Both W3SVC and WAS services are installed and running' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'IIS Services'

$iisInstalled = $false
try {
    $w3svc = Get-Service -Name 'W3SVC' -ErrorAction Stop
    $iisInstalled = $true

    if ($w3svc.Status -eq 'Running') {
        Add-CheckResult 'W3SVC Service' 'PASS' 'World Wide Web Publishing Service is running.'
    }
    else {
        Add-CheckResult 'W3SVC Service' 'FAIL' "W3SVC service exists but is NOT running `(Status: $($w3svc.Status)`). The agent requires IIS to be running."
        Add-Diagnosis -Severity 'BLOCKING' -Title 'IIS (W3SVC) is not running' `
            -Summary 'W3SVC service is stopped -- agent cannot function' `
            -Description "The W3SVC service exists but has status '$($w3svc.Status)'. The agent needs IIS running to inject its HTTP module." `
            -Fix 'Start the service: Start-Service W3SVC' `
            -Docs 'https://learn.microsoft.com/iis/get-started/whats-new-in-iis-10/running-iis-on-nano-server'
    }
}
catch {
    Add-CheckResult 'W3SVC Service' 'FAIL' 'IIS (W3SVC) is not installed on this machine. The Application Insights Agent requires IIS.'
    Add-Diagnosis -Severity 'BLOCKING' -Title 'IIS is not installed' `
        -Summary 'IIS not found -- agent cannot function without it' `
        -Description 'The W3SVC service was not found. The Application Insights Agent only works with IIS-hosted applications.' `
        -Fix 'Install IIS: Install-WindowsFeature Web-Server, Web-Mgmt-Tools' `
        -Docs 'https://learn.microsoft.com/iis/get-started/whats-new-in-iis-10/running-iis-on-nano-server'
}

# Check WAS service
try {
    $was = Get-Service -Name 'WAS' -ErrorAction Stop
    if ($was.Status -eq 'Running') {
        Add-CheckResult 'WAS Service' 'PASS' 'Windows Process Activation Service is running.'
    }
    else {
        Add-CheckResult 'WAS Service' 'WARN' "WAS service exists but is NOT running `(Status: $($was.Status)`)."
        Add-Diagnosis -Severity 'WARNING' -Title 'WAS service is not running' `
            -Summary 'Windows Process Activation Service is stopped' `
            -Description "WAS manages IIS worker processes. Without it, app pools cannot start." `
            -Fix 'Start the service: Start-Service WAS'
    }
}
catch {
    Add-CheckResult 'WAS Service' 'WARN' 'WAS service not found.'
    Add-Diagnosis -Severity 'WARNING' -Title 'WAS service not found' `
        -Summary 'Windows Process Activation Service is not installed' `
        -Description 'WAS manages IIS worker processes. It is normally installed alongside IIS.' `
        -Fix 'Verify IIS installation: Install-WindowsFeature Web-Server, Web-Mgmt-Tools'
}

# Progress line for compact mode
$w3Pass = @($allResults | Where-Object { $_.Check -match 'W3SVC' -and $_.Status -eq 'PASS' }).Count
$wasPass = @($allResults | Where-Object { $_.Check -match 'WAS' -and $_.Status -eq 'PASS' }).Count
if ($w3Pass -gt 0 -and $wasPass -gt 0) {
    Write-ProgressLine -Name 'IIS Services' -Status 'OK' -Summary 'W3SVC and WAS running'
} elseif ($w3Pass -gt 0) {
    Write-ProgressLine -Name 'IIS Services' -Status 'WARN' -Summary 'W3SVC running, WAS issue'
} else {
    Write-ProgressLine -Name 'IIS Services' -Status 'FAIL' -Summary 'IIS not installed or not running'
}

# ============================================================================
# STEP 2: applicationHost.config -- ManagedHttpModuleHelper
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: applicationHost.config -- HTTP Module Registration"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The agent registers a managed HTTP module (ManagedHttpModuleHelper) in the IIS' -ForegroundColor Gray
    Write-Host '  global configuration. This module intercepts incoming HTTP requests to collect' -ForegroundColor Gray
    Write-Host '  telemetry from ASP.NET (Full Framework) applications. Without this registration,' -ForegroundColor Gray
    Write-Host '  IIS won''t load the agent''s module and no telemetry will be collected.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - applicationHost.config file exists in the IIS config directory' -ForegroundColor Gray
    Write-Host '  - ManagedHttpModuleHelper <add> element in the <modules> section matches expected' -ForegroundColor Gray
    Write-Host '    assembly identity, preCondition (managedHandler), and runtime version (v4.0)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - Config file found and the ManagedHttpModuleHelper element matches expected values' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'applicationHost.config'

$appHostConfigPath = [System.Environment]::ExpandEnvironmentVariables('%SYSTEMROOT%\System32\inetsrv\config\applicationHost.config')
$appHostModuleOk = $false

if (Test-Path $appHostConfigPath) {
    Add-CheckResult 'applicationHost.config exists' 'PASS' $appHostConfigPath

    try {
        # SDL: Use XmlDocument with DtdProcessing disabled to prevent XXE attacks
        $appHostXml = New-Object System.Xml.XmlDocument
        $appHostXml.XmlResolver = $null
        $appHostXml.LoadXml((Get-Content -Path $appHostConfigPath -Raw -ErrorAction Stop))
        $moduleFound = $false

        # Check both possible locations
        $locationModules = $appHostXml.SelectNodes("//configuration/location[@path='']/system.webServer/modules/add[@name='ManagedHttpModuleHelper']")
        $globalModules   = $appHostXml.SelectNodes("//configuration/system.webServer/modules/add[@name='ManagedHttpModuleHelper']")

        $allModuleNodes = @()
        if ($locationModules) { $allModuleNodes += $locationModules }
        if ($globalModules)   { $allModuleNodes += $globalModules   }

        foreach ($node in $allModuleNodes) {
            $moduleFound = $true
            $typeName    = $node.type
            $preCond     = $node.preCondition

            # Validate all attributes in one pass
            $typeIsValid    = ($typeName -eq $HttpModuleFQN_Public) -or ($typeName -eq $HttpModuleFQN_Internal)
            $hasManaged     = $preCond -and $preCond -match 'managedHandler'
            $hasRuntime     = $preCond -and $preCond -match 'runtimeVersionv4\.0'
            $allGood        = $typeIsValid -and $hasManaged -and $hasRuntime

            if ($allGood) {
                # Single consolidated PASS -- show the actual XML element
                $xmlSnippet = "<add name=`"ManagedHttpModuleHelper`" type=`"$typeName`" preCondition=`"$preCond`" />"
                Add-CheckResult 'ManagedHttpModuleHelper' 'PASS' 'Registered with expected values.' -Detail $xmlSnippet
            }
            else {
                # Report each specific issue
                if (-not $typeIsValid) {
                    Add-CheckResult 'ManagedHttpModuleHelper type' 'WARN' "Registered but type string does not match expected assembly identity." -Detail "Found:    $typeName`nExpected: $HttpModuleFQN_Public"
                    Add-Diagnosis -Severity 'WARNING' -Title 'Unexpected HTTP module type string' `
                        -Summary 'ManagedHttpModuleHelper has non-standard type identity' `
                        -Description "The module is registered but the type string doesn't match the expected public-key token '$PublicKeyToken_Public' or '$PublicKeyToken_Internal'." `
                        -Fix 'Re-run Enable-ApplicationInsightsMonitoring to re-register the module with the correct type.' `
                        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
                }
                if (-not $hasManaged) {
                    Add-CheckResult 'ManagedHttpModuleHelper preCondition' 'WARN' "preCondition missing 'managedHandler' -- module may load in Classic pipeline mode." -Detail "Found: $preCond"
                    Add-Diagnosis -Severity 'WARNING' -Title 'Missing managedHandler preCondition' `
                        -Description "The ManagedHttpModuleHelper preCondition should include 'managedHandler' to ensure it loads only in Integrated pipeline mode." `
                        -Fix 'Re-run Enable-ApplicationInsightsMonitoring to fix the preCondition.' `
                        -Docs 'https://learn.microsoft.com/iis/configuration/system.webserver/modules/add'
                }
                if (-not $hasRuntime) {
                    Add-CheckResult 'ManagedHttpModuleHelper runtime' 'WARN' "preCondition missing 'runtimeVersionv4.0' -- module works only with .NET Framework 4.x." -Detail "Found: $preCond"
                    Add-Diagnosis -Severity 'WARNING' -Title 'Missing runtimeVersionv4.0 preCondition' `
                        -Description "The ManagedHttpModuleHelper preCondition should include 'runtimeVersionv4.0' to target the .NET Framework 4.x CLR." `
                        -Fix 'Re-run Enable-ApplicationInsightsMonitoring to fix the preCondition.' `
                        -Docs 'https://learn.microsoft.com/iis/configuration/system.webserver/modules/add'
                }
                # Still record the overall registration as a partial pass
                $xmlSnippet = "<add name=`"ManagedHttpModuleHelper`" type=`"$typeName`" preCondition=`"$preCond`" />"
                Add-CheckResult 'ManagedHttpModuleHelper' 'WARN' 'Registered but with unexpected attributes (see warnings above).' -Detail $xmlSnippet
            }
        }

        if (-not $moduleFound) {
            Add-CheckResult 'ManagedHttpModuleHelper' 'FAIL' "Not registered in applicationHost.config. The agent's IIS HTTP module will not load for ASP.NET (.NET Framework) applications. ASP.NET Core apps use the startup hook instead and are not affected."
            Add-Diagnosis -Severity 'BLOCKING' -Title 'HTTP module not registered in applicationHost.config' `
                -Summary 'ManagedHttpModuleHelper missing -- ASP.NET (.NET Framework) telemetry will not be collected' `
                -Description "The 'ManagedHttpModuleHelper' module must be registered in applicationHost.config for the agent to intercept requests from ASP.NET (.NET Framework) applications. ASP.NET Core apps use DOTNET_STARTUP_HOOKS instead and are not affected by this." `
                -Fix "Re-run Enable-ApplicationInsightsMonitoring:`nImport-Module Az.ApplicationMonitor`nEnable-ApplicationInsightsMonitoring -ConnectionString ""your-connection-string""" `
                -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
        }
        elseif ($allGood) {
            $appHostModuleOk = $true
        }
    }
    catch {
        Add-CheckResult 'applicationHost.config parse' 'FAIL' "Failed to parse applicationHost.config: $_"
        Add-Diagnosis -Severity 'BLOCKING' -Title 'Cannot parse applicationHost.config' `
            -Description "The IIS configuration file could not be parsed: $_" `
            -Fix 'Check the file for XML corruption. Consider restoring from backup or reinstalling IIS.'
    }
}
else {
    Add-CheckResult 'applicationHost.config exists' 'FAIL' "Not found at '$appHostConfigPath'. Is IIS installed?"
    Add-Diagnosis -Severity 'BLOCKING' -Title 'applicationHost.config not found' `
        -Summary 'IIS configuration file missing' `
        -Description "Expected at $appHostConfigPath. This indicates IIS may not be installed." `
        -Fix 'Install IIS: Install-WindowsFeature Web-Server, Web-Mgmt-Tools'
}

if ($appHostModuleOk) {
    Write-ProgressLine -Name 'applicationHost.config' -Status 'OK' -Summary 'ManagedHttpModuleHelper registered'
} elseif (@($allResults | Where-Object { $_.Check -match 'applicationHost|ManagedHttp|Module' -and $_.Status -eq 'FAIL' }).Count -gt 0) {
    Write-ProgressLine -Name 'applicationHost.config' -Status 'FAIL' -Summary 'HTTP module not registered'
} else {
    Write-ProgressLine -Name 'applicationHost.config' -Status 'WARN' -Summary 'Module registered with warnings'
}

# ============================================================================
# STEP 3: GAC Registration
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: GAC -- ManagedHttpModuleHelper Assembly"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The ManagedHttpModuleHelper DLL must be installed in the Global Assembly Cache (GAC)' -ForegroundColor Gray
    Write-Host '  for IIS to load it. The applicationHost.config entry (Step 2) references this assembly' -ForegroundColor Gray
    Write-Host '  by its strong name -- if it''s not in the GAC, IIS cannot find it and the module fails' -ForegroundColor Gray
    Write-Host '  to load silently.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - GAC directories for the ManagedHttpModuleHelper assembly' -ForegroundColor Gray
    Write-Host '  - .NET type resolution (same technique the agent itself uses)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - Assembly found in GAC with a valid DLL file and version info' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'GAC Registration'

$gacFound = $false
$gacDetails = @()

$gacPaths = @(
    "$env:SystemRoot\Microsoft.NET\assembly\GAC_MSIL\Microsoft.AppInsights.IIS.ManagedHttpModuleHelper",
    "$env:SystemRoot\assembly\GAC_MSIL\Microsoft.AppInsights.IIS.ManagedHttpModuleHelper"
)

foreach ($gacPath in $gacPaths) {
    if (Test-Path $gacPath) {
        $gacFound = $true
        $versions = Get-ChildItem -Path $gacPath -Directory -ErrorAction SilentlyContinue
        foreach ($ver in $versions) {
            $dllPath = Join-Path $ver.FullName 'Microsoft.AppInsights.IIS.ManagedHttpModuleHelper.dll'
            if (Test-Path $dllPath) {
                $fileVersion = (Get-Item $dllPath).VersionInfo.FileVersion
                $gacDetails += "Found: $dllPath `(FileVersion: $fileVersion`)"
            }
            else {
                $gacDetails += "Directory exists but DLL missing: $($ver.FullName)"
            }
        }
    }
}

# Type resolution check (same approach the product uses)
try {
    $typeCheck_Public   = [System.Type]::GetType($HttpModuleFQN_Public, $false)
    $typeCheck_Internal = [System.Type]::GetType($HttpModuleFQN_Internal, $false)

    if ($typeCheck_Public -or $typeCheck_Internal) {
        $gacFound = $true
        $which = if ($typeCheck_Public) { 'Public' } else { 'Internal' }
        $gacDetails += "Type.GetType resolved successfully `($($which) build`)"
    }
}
catch {
    $null = $_ # Type resolution failed -- expected if not GAC'd
}

if ($gacFound) {
    Add-CheckResult 'GAC Registration' 'PASS' 'Microsoft.AppInsights.IIS.ManagedHttpModuleHelper is registered in the GAC.' -Detail ($gacDetails -join "`n")
    Write-ProgressLine -Name 'GAC Registration' -Status 'OK' -Summary 'Assembly found in GAC'
}
else {
    Add-CheckResult 'GAC Registration' 'FAIL' 'Microsoft.AppInsights.IIS.ManagedHttpModuleHelper is NOT found in the GAC.' `
        -Detail "Searched:`n  $($gacPaths -join "`n  ")"
    Add-Diagnosis -Severity 'BLOCKING' -Title 'GAC assembly not registered' `
        -Summary 'ManagedHttpModuleHelper DLL not in GAC -- IIS cannot load the agent module' `
        -Description 'IIS loads the agent module by strong name from the GAC. Without GAC registration, the module entry in applicationHost.config has no effect.' `
        -Fix "Re-run Enable-ApplicationInsightsMonitoring to re-register the GAC assembly:`nImport-Module Az.ApplicationMonitor`nEnable-ApplicationInsightsMonitoring -ConnectionString ""your-connection-string""" `
        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
    Write-ProgressLine -Name 'GAC Registration' -Status 'FAIL' -Summary 'Assembly not found in GAC'
}

# ============================================================================
# STEP 4: Registry Environment Variables
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Registry -- IIS Service Environment Variables"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The agent configures IIS by setting environment variables on three Windows services' -ForegroundColor Gray
    Write-Host '  (IISADMIN, W3SVC, WAS). These variables tell the .NET runtime to load the agent''s' -ForegroundColor Gray
    Write-Host '  HTTP module (for ASP.NET Full Framework) and startup hooks (for ASP.NET Core).' -ForegroundColor Gray
    Write-Host '  The variables are stored as REG_MULTI_SZ "Environment" values in the registry.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Environment registry values exist on IISADMIN, W3SVC, and WAS services' -ForegroundColor Gray
    Write-Host '  - Agent mode detection (Classic AI SDK vs OpenTelemetry)' -ForegroundColor Gray
    Write-Host '  - All expected variables for the detected mode are present' -ForegroundColor Gray
    Write-Host '  - Path-based variables point to files/directories that exist' -ForegroundColor Gray
    Write-Host '  - All three services have identical environment variable values' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - All expected variables present with valid values' -ForegroundColor Gray
    Write-Host '  - All referenced file paths exist on disk' -ForegroundColor Gray
    Write-Host '  - All three services are in sync' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'Registry Env Vars'

$detectedMode = 'None'
$registryFailures = 0

# --- Phase 1: Collect data from all services silently ---
$serviceNames      = @()
$serviceEnvData    = @{}
$serviceVarStatus  = @{}
$registryWarnings  = @()
$blankEntries      = @{}

foreach ($svcPath in $RegistryServicePaths) {
    $svcName = $svcPath -replace '.*\\', ''
    $serviceNames += $svcName
    $envData = Get-RegistryEnvironmentValue -ServiceKeyPath $svcPath
    $serviceEnvData[$svcName] = $envData
    $serviceVarStatus[$svcName] = [ordered]@{}

    if (-not $envData.Exists) {
        Add-CheckResult "Registry [$svcName] Environment" 'FAIL' "No 'Environment' value found under HKLM:\$svcPath. The agent's environment variables are missing for this service." -Silent
        $registryFailures++
        continue
    }

    # Detect blank or whitespace-only entries in the raw REG_MULTI_SZ value
    $blanks = @($envData.Raw | Where-Object { [string]::IsNullOrWhiteSpace($_) })
    if ($blanks.Count -gt 0) {
        $blankEntries[$svcName] = $blanks.Count
        Add-CheckResult "Registry [$svcName] blank entries" 'WARN' "$($blanks.Count) blank or whitespace-only entry found in the Environment value. This can prevent the agent from attaching to .NET applications." -Silent
    }

    Add-CheckResult "Registry [$svcName] Environment exists" 'PASS' "Found 'Environment' REG_MULTI_SZ with $($envData.Raw.Count) entries." -Detail ($envData.Raw -join "`n") -Silent

    # Detect which mode is configured
    $hasAIModulePath = $envData.Parsed.ContainsKey('MicrosoftAppInsights_ManagedHttpModulePath')
    $hasOtelHome     = $envData.Parsed.ContainsKey('OTEL_DOTNET_AUTO_HOME')

    if ($hasOtelHome) {
        $detectedMode = 'OpenTelemetry'
        Add-CheckResult "Registry [$svcName] Mode" 'INFO' 'OpenTelemetry mode detected (OTEL_DOTNET_AUTO_HOME is set).' -Silent
    }
    elseif ($hasAIModulePath) {
        $detectedMode = 'ClassicAI'
        Add-CheckResult "Registry [$svcName] Mode" 'INFO' 'Classic Application Insights SDK mode detected (MicrosoftAppInsights_ManagedHttpModulePath is set).' -Silent
    }

    # Check for expected variables based on detected mode
    $expectedVars = if ($detectedMode -eq 'OpenTelemetry') { $ExpectedEnvVars_OpenTelemetry }
                    elseif ($detectedMode -eq 'ClassicAI') { $ExpectedEnvVars_ClassicAI }
                    else { @() }

    foreach ($varName in $expectedVars) {
        $vs = @{ Present = $false; Value = ''; PathOK = $null }

        if ($envData.Parsed.ContainsKey($varName)) {
            $val = $envData.Parsed[$varName]
            $vs.Present = $true
            $vs.Value   = $val
            Add-CheckResult "Registry [$svcName] $varName" 'PASS' 'Present.' -Detail $val -Silent

            # For path-based variables, verify the file exists
            if ($varName -match 'Path$|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_SHARED_STORE|OTEL_DOTNET_AUTO_HOME') {
                $vs.PathOK = $true
                $paths = $val -split ';'
                foreach ($p in $paths) {
                    $p = $p.Trim()
                    if ($p -and -not (Test-Path $p)) {
                        $vs.PathOK = $false
                        Add-CheckResult "Registry [$svcName] $varName target" 'FAIL' "Path does not exist: '$p'" -Silent
                        $registryFailures++
                    }
                    elseif ($p) {
                        Add-CheckResult "Registry [$svcName] $varName target" 'PASS' "Path exists: '$p'" -Silent
                    }
                }
            }
        }
        else {
            Add-CheckResult "Registry [$svcName] $varName" 'FAIL' "Missing. This environment variable should be set for $detectedMode mode." -Silent
            $registryFailures++
        }

        $serviceVarStatus[$svcName][$varName] = $vs
    }

    # Check ASPNETCORE_HOSTINGSTARTUPASSEMBLIES value
    if ($envData.Parsed.ContainsKey('ASPNETCORE_HOSTINGSTARTUPASSEMBLIES')) {
        $hsaValue = $envData.Parsed['ASPNETCORE_HOSTINGSTARTUPASSEMBLIES']
        if ($detectedMode -eq 'OpenTelemetry' -and $hsaValue -ne 'OpenTelemetry.AutoInstrumentation.AspNetCoreBootstrapper') {
            Add-CheckResult "Registry [$svcName] HostingStartup value" 'WARN' "Expected 'OpenTelemetry.AutoInstrumentation.AspNetCoreBootstrapper' but found '$hsaValue'." -Silent
            $registryWarnings += "[$svcName] HostingStartup: Expected 'OpenTelemetry.AutoInstrumentation.AspNetCoreBootstrapper' but found '$hsaValue'."
        }
        elseif ($detectedMode -eq 'ClassicAI' -and $hsaValue -ne 'Microsoft.ApplicationInsights.StartupBootstrapper') {
            Add-CheckResult "Registry [$svcName] HostingStartup value" 'WARN' "Expected 'Microsoft.ApplicationInsights.StartupBootstrapper' but found '$hsaValue'." -Silent
            $registryWarnings += "[$svcName] HostingStartup: Expected 'Microsoft.ApplicationInsights.StartupBootstrapper' but found '$hsaValue'."
        }
    }

    # Classic AI: Check MicrosoftAppInsights_ManagedHttpModuleType
    if ($detectedMode -eq 'ClassicAI' -and $envData.Parsed.ContainsKey('MicrosoftAppInsights_ManagedHttpModuleType')) {
        $moduleType = $envData.Parsed['MicrosoftAppInsights_ManagedHttpModuleType']
        $expectedType = 'Microsoft.ApplicationInsights.RedfieldIISModule.RedfieldIISModule'
        if ($moduleType -ne $expectedType) {
            Add-CheckResult "Registry [$svcName] ModuleType value" 'WARN' "Expected '$expectedType' but found '$moduleType'." -Silent
            $registryWarnings += "[$svcName] ModuleType: Expected '$expectedType' but found '$moduleType'."
        }
        else {
            Add-CheckResult "Registry [$svcName] ModuleType value" 'PASS' 'Matches expected RedfieldIISModule type.' -Silent
        }
    }
}

# --- Phase 1.5: Compute consistency across services (needed before table) ---
$consistencyIssues = @()
$allConsistent     = $true

if ($RegistryServicePaths.Count -gt 1) {
    $refName = $serviceNames[0]
    $refRaw  = $serviceEnvData[$refName].Raw

    for ($i = 1; $i -lt $serviceNames.Count; $i++) {
        $otherName = $serviceNames[$i]
        $otherRaw  = $serviceEnvData[$otherName].Raw

        $refSorted   = ($refRaw | Sort-Object) -join '|'
        $otherSorted = ($otherRaw | Sort-Object) -join '|'

        if ($refSorted -ne $otherSorted) {
            $allConsistent = $false
            $onlyInRef   = @($refRaw | Where-Object { $_ -notin $otherRaw })
            $onlyInOther = @($otherRaw | Where-Object { $_ -notin $refRaw })
            $consistencyIssues += [PSCustomObject]@{
                Service     = $otherName
                RefName     = $refName
                OnlyInRef   = $onlyInRef
                OnlyInOther = $onlyInOther
            }
        }
    }
}

# --- Phase 2: Render consolidated output (verbose mode) ---
if ($VerboseOutput) {
    $chk = [string][char]0x2713
    $xmk = [string][char]0x2717

    # Show exactly which registry keys we are checking
    Write-Host '  Registry keys checked:' -ForegroundColor DarkCyan
    foreach ($svcPath in $RegistryServicePaths) {
        Write-Host "    HKLM:\$svcPath  (Environment value)" -ForegroundColor Gray
    }
    Write-Host ''

    # Blank / whitespace entry warnings
    if ($blankEntries.Count -gt 0) {
        foreach ($sn in $serviceNames) {
            if ($blankEntries.ContainsKey($sn)) {
                $count = $blankEntries[$sn]
                Write-Host "  [!] $sn`: $count blank/whitespace-only entry found in Environment value." -ForegroundColor DarkYellow
                Write-Host '      Blank entries in the REG_MULTI_SZ can prevent the agent from attaching' -ForegroundColor DarkYellow
                Write-Host '      to .NET Framework applications. Open regedit, navigate to the key above,' -ForegroundColor DarkYellow
                Write-Host '      double-click the ''Environment'' multi-string value, and delete any empty lines.' -ForegroundColor DarkYellow
            }
        }
        Write-Host ''
    }

    if ($detectedMode -ne 'None') {
        $modeLabel = if ($detectedMode -eq 'ClassicAI') { 'Classic Application Insights SDK' } else { 'OpenTelemetry Auto-Instrumentation' }
        Write-Host "  Detected Mode: $modeLabel" -ForegroundColor White
        Write-Host ''

        $expectedVars = if ($detectedMode -eq 'OpenTelemetry') { $ExpectedEnvVars_OpenTelemetry }
                        else { $ExpectedEnvVars_ClassicAI }

        # Column widths
        $varCol = ($expectedVars | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 4
        $svcCol = 10

        # Header
        Write-Host ('  ' + 'Variable'.PadRight($varCol)) -NoNewline -ForegroundColor DarkCyan
        foreach ($sn in $serviceNames) { Write-Host $sn.PadRight($svcCol) -NoNewline -ForegroundColor DarkCyan }
        Write-Host 'Path' -ForegroundColor DarkCyan

        # Separator
        Write-Host ('  ' + ('-' * ($varCol - 2)).PadRight($varCol)) -NoNewline -ForegroundColor DarkGray
        foreach ($sn in $serviceNames) { Write-Host ('-' * $sn.Length).PadRight($svcCol) -NoNewline -ForegroundColor DarkGray }
        Write-Host '----' -ForegroundColor DarkGray

        # Data rows
        foreach ($varName in $expectedVars) {
            $isPathVar = $varName -match 'Path$|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_SHARED_STORE|OTEL_DOTNET_AUTO_HOME'
            Write-Host ('  ' + $varName.PadRight($varCol)) -NoNewline -ForegroundColor White

            foreach ($sn in $serviceNames) {
                $ed = $serviceEnvData[$sn]
                if (-not $ed.Exists) {
                    Write-Host $xmk.PadRight($svcCol) -NoNewline -ForegroundColor Red
                }
                elseif ($serviceVarStatus[$sn].Contains($varName) -and $serviceVarStatus[$sn][$varName].Present) {
                    Write-Host $chk.PadRight($svcCol) -NoNewline -ForegroundColor Green
                }
                else {
                    Write-Host $xmk.PadRight($svcCol) -NoNewline -ForegroundColor Red
                }
            }

            if (-not $isPathVar) {
                Write-Host '-' -ForegroundColor DarkGray
            }
            else {
                $pathOK = $null
                foreach ($sn in $serviceNames) {
                    if ($serviceVarStatus[$sn].Contains($varName) -and $null -ne $serviceVarStatus[$sn][$varName].PathOK) {
                        $pathOK = $serviceVarStatus[$sn][$varName].PathOK; break
                    }
                }
                if ($pathOK -eq $true)  { Write-Host $chk -ForegroundColor Green }
                elseif ($pathOK -eq $false) { Write-Host $xmk -ForegroundColor Red }
                else { Write-Host '-' -ForegroundColor DarkGray }
            }
        }

        # Sync row -- shows whether each service matches the reference
        Write-Host ('  ' + 'Sync'.PadRight($varCol)) -NoNewline -ForegroundColor White
        Write-Host $chk.PadRight($svcCol) -NoNewline -ForegroundColor Green   # reference service always matches itself
        for ($i = 1; $i -lt $serviceNames.Count; $i++) {
            $sn = $serviceNames[$i]
            $hasMismatch = $consistencyIssues | Where-Object { $_.Service -eq $sn }
            if ($hasMismatch) {
                Write-Host $xmk.PadRight($svcCol) -NoNewline -ForegroundColor Red
            } else {
                Write-Host $chk.PadRight($svcCol) -NoNewline -ForegroundColor Green
            }
        }
        Write-Host ''

        # Values section -- show once from the first service that has data
        $refSvc = $serviceNames | Where-Object { $serviceEnvData[$_].Exists } | Select-Object -First 1
        if ($refSvc) {
            Write-Host '  Values:' -ForegroundColor DarkCyan
            foreach ($varName in $expectedVars) {
                if ($serviceVarStatus[$refSvc].Contains($varName) -and $serviceVarStatus[$refSvc][$varName].Present) {
                    $val = $serviceVarStatus[$refSvc][$varName].Value
                    Write-Host "    $varName" -NoNewline -ForegroundColor Gray
                    Write-Host ' = ' -NoNewline -ForegroundColor DarkGray
                    Write-Host $val -ForegroundColor Gray
                }
            }
            Write-Host ''
        }

        # Value warnings (HostingStartup / ModuleType mismatches)
        if ($registryWarnings.Count -gt 0) {
            foreach ($w in $registryWarnings) {
                Write-Host "  [!] $w" -ForegroundColor DarkYellow
            }
            Write-Host ''
        }

        # Consistency diff details
        if ($consistencyIssues.Count -gt 0) {
            Write-Host '  Service Sync Details:' -ForegroundColor DarkCyan
            Write-Host '  All three services must have identical Environment values. Differences shown below.' -ForegroundColor Gray
            Write-Host ''
            foreach ($issue in $consistencyIssues) {
                Write-Host "    $($issue.RefName) vs $($issue.Service):" -ForegroundColor White
                foreach ($entry in $issue.OnlyInRef) {
                    $label = if ([string]::IsNullOrWhiteSpace($entry)) { '(blank line)' } else { $entry }
                    Write-Host "      Only in $($issue.RefName)`: " -NoNewline -ForegroundColor Gray
                    Write-Host $label -ForegroundColor DarkYellow
                }
                foreach ($entry in $issue.OnlyInOther) {
                    $label = if ([string]::IsNullOrWhiteSpace($entry)) { '(blank line)' } else { $entry }
                    Write-Host "      Only in $($issue.Service)`: " -NoNewline -ForegroundColor Gray
                    Write-Host $label -ForegroundColor DarkYellow
                }
            }
            Write-Host ''
            Write-Host '  ACTION: Open regedit and make the Environment values match across all three' -ForegroundColor Yellow
            Write-Host '  service keys, or re-run Enable-ApplicationInsightsMonitoring to reset them.' -ForegroundColor Yellow
            Write-Host ''
        }
    }
    else {
        # No agent mode detected -- show per-service summary
        foreach ($sn in $serviceNames) {
            $ed = $serviceEnvData[$sn]
            if ($ed.Exists) {
                Write-Host "  [!] $sn -- Environment key found but no recognized agent mode detected." -ForegroundColor DarkYellow
            }
            else {
                Write-Host "  [$xmk] $sn -- No 'Environment' value found." -ForegroundColor Red
            }
        }
        Write-Host ''
    }
}

# --- Phase 3: Record consistency results and diagnosis ---
if ($consistencyIssues.Count -gt 0) {
    foreach ($issue in $consistencyIssues) {
        $diffLines = @()
        foreach ($entry in $issue.OnlyInRef) {
            $label = if ([string]::IsNullOrWhiteSpace($entry)) { '(blank line)' } else { $entry }
            $diffLines += "Only in $($issue.RefName): $label"
        }
        foreach ($entry in $issue.OnlyInOther) {
            $label = if ([string]::IsNullOrWhiteSpace($entry)) { '(blank line)' } else { $entry }
            $diffLines += "Only in $($issue.Service): $label"
        }
        Add-CheckResult "Registry consistency ($($issue.Service))" 'WARN' `
            "Environment values differ between $($issue.RefName) and $($issue.Service). They should be identical." `
            -Detail ($diffLines -join "`n") -Silent
        Add-Diagnosis -Severity 'WARNING' -Title "Registry inconsistency: $($issue.RefName) vs $($issue.Service)" `
            -Summary "Environment variables differ between IIS services -- may cause unpredictable behavior" `
            -Description ("The $($issue.RefName) and $($issue.Service) registry keys have different Environment values. " + `
                "All three services should be identical.`n`nDifferences:`n" + ($diffLines -join "`n")) `
            -Fix 'Re-run Enable-ApplicationInsightsMonitoring to reset all three service keys, or manually edit the Environment values in regedit to match.'
    }
} elseif ($allConsistent -and $serviceEnvData[$serviceNames[0]].Exists) {
    Add-CheckResult 'Registry consistency' 'PASS' 'All three service keys (IISADMIN, W3SVC, WAS) have identical Environment values.' -Silent
}

# Diagnosis for blank entries
foreach ($sn in $serviceNames) {
    if ($blankEntries.ContainsKey($sn)) {
        Add-Diagnosis -Severity 'WARNING' -Title "Blank entry in $sn Environment registry value" `
            -Summary "Blank entries in REG_MULTI_SZ can prevent agent from attaching to .NET Framework apps" `
            -Description "The 'Environment' multi-string value under HKLM:\SYSTEM\CurrentControlSet\Services\$sn contains $($blankEntries[$sn]) blank or whitespace-only entry. This is a known issue that can cause the Status Monitor V2 agent to fail to attach." `
            -Fix "Open regedit, navigate to HKLM:\SYSTEM\CurrentControlSet\Services\$sn, double-click the 'Environment' multi-string value, and remove any empty lines."
    }
}

# Add diagnosis for missing registry
if ($registryFailures -gt 0 -and $detectedMode -eq 'None') {
    Add-Diagnosis -Severity 'BLOCKING' -Title 'Agent registry environment variables not configured' `
        -Summary 'No agent environment variables found -- agent was never enabled or was removed' `
        -Description "The Environment registry values on IISADMIN/W3SVC/WAS are missing. These are set by Enable-ApplicationInsightsMonitoring during agent installation." `
        -Fix "Run Enable-ApplicationInsightsMonitoring:`nImport-Module Az.ApplicationMonitor`nEnable-ApplicationInsightsMonitoring -ConnectionString ""your-connection-string""" `
        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
} elseif ($registryFailures -gt 0) {
    Add-Diagnosis -Severity 'BLOCKING' -Title 'Missing or broken registry environment variables' `
        -Summary "$registryFailures registry issue(s) found -- agent may not function correctly" `
        -Description "Some expected environment variables are missing or reference paths that don't exist. Mode detected: $detectedMode." `
        -Fix "Re-run Enable-ApplicationInsightsMonitoring to fix registry entries." `
        -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot'
}

$hasRegistryWarnings = ($consistencyIssues.Count -gt 0) -or ($blankEntries.Count -gt 0) -or ($registryWarnings.Count -gt 0)

if ($registryFailures -eq 0 -and $detectedMode -ne 'None' -and -not $hasRegistryWarnings) {
    Write-ProgressLine -Name 'Registry Env Vars' -Status 'OK' -Summary "$detectedMode mode, all variables present"
} elseif ($registryFailures -eq 0 -and $detectedMode -ne 'None' -and $hasRegistryWarnings) {
    $warnParts = @()
    if ($consistencyIssues.Count -gt 0) { $warnParts += 'services out of sync' }
    if ($blankEntries.Count -gt 0) { $warnParts += 'blank entries found' }
    if ($registryWarnings.Count -gt 0) { $warnParts += 'value warnings' }
    Write-ProgressLine -Name 'Registry Env Vars' -Status 'WARN' -Summary "$detectedMode mode -- $($warnParts -join ', ')"
} elseif ($registryFailures -gt 0) {
    Write-ProgressLine -Name 'Registry Env Vars' -Status 'FAIL' -Summary "$registryFailures issue(s) found"
} else {
    Write-ProgressLine -Name 'Registry Env Vars' -Status 'WARN' -Summary 'No agent mode detected'
}

# ============================================================================
# STEP 5: IIS Application Pool Pipeline Mode
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: IIS Application Pool Pipeline Mode"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The ManagedHttpModuleHelper has a preCondition of "managedHandler" which means it' -ForegroundColor Gray
    Write-Host '  only loads in Integrated pipeline mode. Applications running in Classic pipeline' -ForegroundColor Gray
    Write-Host '  mode will NOT be instrumented by the agent.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Pipeline mode of each application pool (Integrated vs Classic)' -ForegroundColor Gray
    Write-Host '  - .NET runtime version configured on each pool' -ForegroundColor Gray
    Write-Host '  - Pools with no managed runtime (ASP.NET Core out-of-process)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - All relevant app pools are in Integrated pipeline mode' -ForegroundColor Gray
    Write-Host '  - No pools are in Classic mode (or they are intentionally configured that way)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-classic-pipeline-mode' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'App Pool Pipeline'

if ($iisInstalled) {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $appPools = Get-ChildItem IIS:\AppPools -ErrorAction Stop

        $classicPools = @()
        $integratedPools = @()

        foreach ($pool in $appPools) {
            $mode = $pool.managedPipelineMode
            $runtime = $pool.managedRuntimeVersion
            $state = $pool.state

            if ($mode -eq 'Classic') {
                $classicPools += "$($pool.Name) `(runtime: $runtime, state: $state`)"
            }
            else {
                $integratedPools += "$($pool.Name) `(runtime: $runtime, state: $state`)"
            }
        }

        if ($integratedPools.Count -gt 0) {
            Add-CheckResult 'Integrated Pipeline Pools' 'PASS' "$($integratedPools.Count) app pool(s) in Integrated mode (compatible with the agent)." `
                -Detail ($integratedPools -join "`n")
        }
        else {
            Add-CheckResult 'Integrated Pipeline Pools' 'FAIL' 'No app pools are in Integrated pipeline mode. The ManagedHttpModuleHelper requires Integrated mode.'
            Add-Diagnosis -Severity 'BLOCKING' -Title 'No Integrated pipeline app pools' `
                -Summary 'All app pools are in Classic mode -- agent HTTP module will not load' `
                -Description "The agent's ManagedHttpModuleHelper has preCondition=managedHandler which requires Integrated pipeline mode." `
                -Fix "Switch pools to Integrated mode in IIS Manager or via:`nSet-ItemProperty IIS:\AppPools\<PoolName> -Name managedPipelineMode -Value Integrated" `
                -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-classic-pipeline-mode'
        }

        if ($classicPools.Count -gt 0) {
            Add-CheckResult 'Classic Pipeline Pools' 'WARN' "$($classicPools.Count) app pool(s) in Classic mode -- the agent HTTP module will NOT load in these pools." `
                -Detail ($classicPools -join "`n")
            Add-Diagnosis -Severity 'WARNING' -Title "$($classicPools.Count) app pool(s) in Classic pipeline mode" `
                -Summary "Classic mode pools will not be instrumented by the agent" `
                -Description "These pools use Classic pipeline mode: $($classicPools -join ', '). The agent's HTTP module only loads in Integrated mode." `
                -Fix "Switch to Integrated mode: Set-ItemProperty IIS:\AppPools\<PoolName> -Name managedPipelineMode -Value Integrated" `
                -Portal 'IIS Manager > Application Pools > [pool] > Advanced Settings > Managed Pipeline Mode' `
                -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-classic-pipeline-mode'
        }

        # Check for pools with no managed runtime
        $noRuntimePools = $appPools | Where-Object { [string]::IsNullOrEmpty($_.managedRuntimeVersion) }
        if ($noRuntimePools) {
            $names = ($noRuntimePools | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult 'App Pool .NET Runtime' 'INFO' "Pool(s) with no managed runtime: $names. These likely host ASP.NET Core out-of-process apps which use DOTNET_STARTUP_HOOKS instead."
        }

        if ($classicPools.Count -gt 0 -and $integratedPools.Count -gt 0) {
            Write-ProgressLine -Name 'App Pool Pipeline' -Status 'WARN' -Summary "$($integratedPools.Count) Integrated, $($classicPools.Count) Classic"
        } elseif ($integratedPools.Count -gt 0) {
            Write-ProgressLine -Name 'App Pool Pipeline' -Status 'OK' -Summary "All $($integratedPools.Count) pool(s) Integrated"
        } else {
            Write-ProgressLine -Name 'App Pool Pipeline' -Status 'FAIL' -Summary 'No Integrated mode pools'
        }
    }
    catch {
        $errMsg = "$_"
        if ($errMsg -match "drive.*'IIS'|name 'IIS' does not exist") {
            # The WebAdministration module exposes IIS config as a PowerShell PSDrive
            # named "IIS:\".  This is a virtual provider drive, not a disk volume.
            # The drive fails to register when the session lacks admin rights or when
            # the IIS Management Scripts and Tools role feature is not installed.
            $summary   = 'The IIS PowerShell provider drive (IIS:\) could not be created.'
            $detail    = "The WebAdministration module uses a virtual PSDrive named IIS:\ to " +
                         "expose IIS configuration.  This is NOT a disk drive -- it is a " +
                         "PowerShell provider that maps app pools, sites, and settings as a " +
                         "navigable path.`n`n" +
                         "Likely causes:`n" +
                         "  1. PowerShell is not running as Administrator`n" +
                         "  2. The 'IIS Management Scripts and Tools' role feature is not installed`n" +
                         "     (Install via: Install-WindowsFeature Web-Scripting-Tools)`n`n" +
                         "Raw error: $errMsg"
            $progressSummary = 'IIS:\ provider unavailable'
        }
        else {
            $summary   = "Could not enumerate app pools: $errMsg"
            $detail    = $null
            $progressSummary = 'Could not enumerate pools'
        }

        Add-CheckResult 'App Pool Check' 'WARN' $summary -Detail $detail
        Add-Diagnosis -Severity 'WARNING' -Title 'Could not enumerate IIS application pools' `
            -Summary $summary `
            -Description $detail `
            -Fix 'Re-run this script as Administrator. If the issue persists, verify the IIS Management Scripts and Tools role feature is installed: Install-WindowsFeature Web-Scripting-Tools'
        Write-ProgressLine -Name 'App Pool Pipeline' -Status 'WARN' -Summary $progressSummary
    }
}
else {
    Add-CheckResult 'App Pool Check' 'FAIL' 'IIS is not installed -- cannot check app pool pipeline modes.'
    Write-ProgressLine -Name 'App Pool Pipeline' -Status 'FAIL' -Summary 'IIS not installed'
}

# ============================================================================
# STEP 6: Application Pool Identity Permissions
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Application Pool Identity Permissions"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The agent collects performance counter telemetry (CPU, memory, request rates).' -ForegroundColor Gray
    Write-Host '  The IIS worker process (w3wp.exe) runs under the app pool identity, which needs' -ForegroundColor Gray
    Write-Host '  membership in the "Performance Monitor Users" local group to read these counters.' -ForegroundColor Gray
    Write-Host '  The agent adds identities to this group during Enable, but custom pools may be missed.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Members of the "Performance Monitor Users" local group' -ForegroundColor Gray
    Write-Host '  - Each app pool identity''s membership in that group' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - All app pool identities are members of "Performance Monitor Users"' -ForegroundColor Gray
    Write-Host '  - Or pools run as LocalSystem (which always has permissions)' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'Pool Identity Perms'

if ($iisInstalled) {
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        $perfMonGroup = 'Performance Monitor Users'
        $perfMonMembers = @()
        $permIssueCount = 0

        try {
            $group = [ADSI]"WinNT://./$perfMonGroup,group"
            $perfMonMembers = @($group.Invoke('Members') | ForEach-Object {
                $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
            })
            Add-CheckResult "'$perfMonGroup' group" 'INFO' "Members: $($perfMonMembers -join ', ')" -Detail ($perfMonMembers -join "`n")
        }
        catch {
            Add-CheckResult "'$perfMonGroup' group" 'WARN' "Could not enumerate group members: $_"
            Add-Diagnosis -Severity 'WARNING' -Title 'Could not enumerate Performance Monitor Users group' `
                -Summary "Could not read members of the '$perfMonGroup' local group" `
                -Description "Error: $_. This is usually a permissions issue." `
                -Fix 'Re-run this script as Administrator.'
        }

        # Check each app pool identity
        $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
        foreach ($pool in $appPools) {
            $identityType = $pool.processModel.identityType
            $userName     = $pool.processModel.userName

            if ($identityType -eq 'LocalSystem') {
                Add-CheckResult "Pool '$($pool.Name)' identity" 'PASS' 'Runs as LocalSystem -- always has performance counter permissions.'
                continue
            }

            $accountName = switch ($identityType) {
                'NetworkService'         { 'NETWORK SERVICE' }
                'LocalService'           { 'LOCAL SERVICE' }
                'ApplicationPoolIdentity' { "IIS AppPool\$($pool.Name)" }
                'SpecificUser'           { $userName }
                default                  { $null }
            }

            if ($accountName -and $perfMonMembers.Count -gt 0) {
                $isMember = $perfMonMembers | Where-Object { $_ -like "*$($accountName.Split('\')[-1])*" }
                if ($isMember) {
                    Add-CheckResult "Pool '$($pool.Name)' perms" 'PASS' "'$accountName' is in '$perfMonGroup'."
                }
                else {
                    $permIssueCount++
                    Add-CheckResult "Pool '$($pool.Name)' perms" 'WARN' "'$accountName' `($identityType`) is NOT in '$perfMonGroup'."
                }
            }
        }

        if ($permIssueCount -gt 0) {
            Add-Diagnosis -Severity 'WARNING' -Title "$permIssueCount app pool identity(s) missing Performance Monitor Users membership" `
                -Summary 'Some pool identities may not be able to read performance counters' `
                -Description "Performance counter collection may fail for pools whose identity is not in the Performance Monitor Users group." `
                -Fix "Add identities to the group: net localgroup ""Performance Monitor Users"" ""IIS AppPool\YourPoolName"" /add" `
                -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
            Write-ProgressLine -Name 'Pool Identity Perms' -Status 'WARN' -Summary "$permIssueCount pool(s) missing Performance Monitor Users"
        } else {
            Write-ProgressLine -Name 'Pool Identity Perms' -Status 'OK' -Summary 'All pool identities have permissions'
        }
    }
    catch {
        Add-CheckResult 'Permissions check' 'WARN' "Could not check permissions: $_"
        Add-Diagnosis -Severity 'WARNING' -Title 'Could not check app pool identity permissions' `
            -Summary "Error during permissions check: $_" `
            -Description 'The IIS PowerShell provider may not be available. This is usually a permissions or IIS Management Tools issue.' `
            -Fix 'Re-run this script as Administrator.'
        Write-ProgressLine -Name 'Pool Identity Perms' -Status 'WARN' -Summary 'Could not check permissions'
    }
}
else {
    Write-ProgressLine -Name 'Pool Identity Perms' -Status 'SKIP' -Summary 'IIS not installed'
}

# ============================================================================
# STEP 7: Redfield Configuration File
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Redfield Configuration File"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  When you run Enable-ApplicationInsightsMonitoring, the agent writes a configuration' -ForegroundColor Gray
    Write-Host '  file (applicationInsights.ikey.config) containing the instrumentation key and other' -ForegroundColor Gray
    Write-Host '  settings. This file tells the agent which Application Insights resource to send' -ForegroundColor Gray
    Write-Host '  telemetry to.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Known directories for agent configuration files (.ikey.config)' -ForegroundColor Gray
    Write-Host '  - Redfield configuration XML files' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - At least one configuration file found with valid content' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'Config Files'

$configSearchPaths = @(
    "$env:ProgramData\Microsoft\ApplicationInsights\",
    "$env:ALLUSERSPROFILE\Microsoft\ApplicationInsights\",
    "C:\Program Files\WindowsPowerShell\Modules\Az.ApplicationMonitor\",
    "C:\Program Files\Microsoft Application Insights\"
)

$configFound = $false
$configFileCount = 0
$configSeenPaths = @{}
$script:foundConfigFiles = @()

foreach ($searchPath in $configSearchPaths) {
    if (Test-Path $searchPath) {
        $configs = Get-ChildItem -Path $searchPath -Recurse -Filter '*.ikey.config' -ErrorAction SilentlyContinue
        if ($configs) {
            foreach ($cfg in $configs) {
                if (-not $configSeenPaths.ContainsKey($cfg.FullName)) {
                    $configSeenPaths[$cfg.FullName] = $true
                    $configFound = $true
                    $configFileCount++
                    $script:foundConfigFiles += $cfg.FullName
                    Add-CheckResult 'Config file found' 'PASS' $cfg.FullName

                    if ($VerboseOutput) {
                        try {
                            $content = Get-Content $cfg.FullName -Raw -ErrorAction Stop
                            # SDL: Mask ikey GUIDs in raw config content before writing to report
                            $safeContent = $content -replace '([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})', '$1-****-****-****-$5'
                            Add-CheckResult 'Config file content' 'INFO' 'See detail.' -Detail $safeContent
                        }
                        catch {
                            Add-CheckResult 'Config file read' 'WARN' "Could not read: $_"
                            Add-Diagnosis -Severity 'WARNING' -Title 'Could not read agent config file' `
                                -Summary "Config file exists but could not be read: $_" `
                                -Fix 'Check file permissions on the agent config directory.'
                        }
                    }
                }
            }
        }
    }
}

# Also check for RedfieldConfiguration XML files
foreach ($searchPath in $configSearchPaths) {
    if (Test-Path $searchPath) {
        $xmlConfigs = Get-ChildItem -Path $searchPath -Recurse -Filter 'applicationInsights.*.config' -ErrorAction SilentlyContinue
        if ($xmlConfigs) {
            foreach ($cfg in $xmlConfigs) {
                if (-not $configSeenPaths.ContainsKey($cfg.FullName)) {
                    $configSeenPaths[$cfg.FullName] = $true
                    $configFound = $true
                    $configFileCount++
                    $script:foundConfigFiles += $cfg.FullName
                    Add-CheckResult 'Redfield config file' 'PASS' $cfg.FullName
                }
            }
        }
    }
}

if (-not $configFound) {
    Add-CheckResult 'Config file' 'WARN' "No Redfield/AI Agent config files found in common locations." `
        -Detail ("Searched:`n  " + ($configSearchPaths -join "`n  "))
    Add-Diagnosis -Severity 'WARNING' -Title 'No agent configuration files found' `
        -Summary 'Agent config files not found -- agent may not have been enabled successfully' `
        -Description "The agent writes applicationInsights.ikey.config during Enable-ApplicationInsightsMonitoring. No config files were found in standard locations." `
        -Fix "Re-run Enable-ApplicationInsightsMonitoring with your connection string." `
        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
    Write-ProgressLine -Name 'Config Files' -Status 'WARN' -Summary 'No config files found'
}
else {
    Write-ProgressLine -Name 'Config Files' -Status 'OK' -Summary "$configFileCount config file(s) found"
}

# ============================================================================
# STEP 8: PowerShell Module
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Application Insights Agent PowerShell Module"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The Az.ApplicationMonitor PowerShell module provides the cmdlets used to install,' -ForegroundColor Gray
    Write-Host '  configure, and manage the agent (Enable-ApplicationInsightsMonitoring, etc.).' -ForegroundColor Gray
    Write-Host '  While the module isn''t required at runtime (the agent runs independently after' -ForegroundColor Gray
    Write-Host '  setup), it''s needed for management operations and troubleshooting.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Az.ApplicationMonitor module availability' -ForegroundColor Gray
    Write-Host '  - ApplicationInsightsAgent module (alternate name)' -ForegroundColor Gray
    Write-Host '  - Module version and install location' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - Module found with a version number and valid path' -ForegroundColor Gray
    Write-Host '  - Or module not found (acceptable if agent was installed via Azure VM Extension)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=api-reference' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'PS Module'

$moduleNames = @('Az.ApplicationMonitor', 'ApplicationInsightsAgent')
$moduleFound = $false

foreach ($modName in $moduleNames) {
    $mod = Get-Module -Name $modName -ListAvailable -ErrorAction SilentlyContinue
    if ($mod) {
        $moduleFound = $true
        foreach ($m in $mod) {
            Add-CheckResult "PowerShell Module '$modName'" 'PASS' "Version $($m.Version) at $($m.ModuleBase)"
        }
    }
}

if (-not $moduleFound) {
    Add-CheckResult 'PowerShell Module' 'INFO' "No Application Insights Agent PowerShell module found. This is expected if the agent was installed via Azure VM Extension."
    Write-ProgressLine -Name 'PS Module' -Status 'INFO' -Summary 'Not found (may be expected)'
}
else {
    Write-ProgressLine -Name 'PS Module' -Status 'OK' -Summary "Found `(v$($quickModule.Version)`)"
}

# ============================================================================
# STEP 9: PowerShell Version Validation
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: PowerShell Version Validation"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The Az.ApplicationMonitor module and its cmdlets (Enable-ApplicationInsightsMonitoring,' -ForegroundColor Gray
    Write-Host '  Get-ApplicationInsightsMonitoringStatus, etc.) were built for Windows PowerShell 5.1.' -ForegroundColor Gray
    Write-Host '  Running under PowerShell 6 (Core) or 7+ can cause cmdlets to fail silently or' -ForegroundColor Gray
    Write-Host '  produce unexpected behavior because the module depends on .NET Framework APIs' -ForegroundColor Gray
    Write-Host '  that are not available in .NET Core.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - PowerShell major version (must be 5.x for full compatibility)' -ForegroundColor Gray
    Write-Host '  - PowerShell edition (Desktop vs Core)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - PowerShell 5.1 (Desktop edition) detected' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#powershell-versions' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'PowerShell Version'

$psVersion = $PSVersionTable.PSVersion
$psEditionStr = $PSVersionTable.PSEdition

if ($psVersion.Major -eq 5) {
    Add-CheckResult 'PowerShell Version' 'PASS' "PowerShell $psVersion `($psEditionStr`) -- fully compatible with Az.ApplicationMonitor."
    Write-ProgressLine -Name 'PowerShell Version' -Status 'OK' -Summary "PS $psVersion `($psEditionStr`)"
}
elseif ($psVersion.Major -ge 6) {
    Add-CheckResult 'PowerShell Version' 'WARN' "PowerShell $psVersion `($psEditionStr`) detected. Az.ApplicationMonitor requires Windows PowerShell 5.1." `
        -Detail "The agent cmdlets depend on .NET Framework APIs not available in PowerShell Core/.NET Core."
    Add-Diagnosis -Severity 'WARNING' -Title 'Running under PowerShell Core instead of Windows PowerShell 5.1' `
        -Summary "PowerShell $psVersion `($psEditionStr`) -- agent cmdlets may not work correctly" `
        -Description "Az.ApplicationMonitor was built for Windows PowerShell 5.1 `(Desktop edition`). Running under PS $psVersion may cause Enable-ApplicationInsightsMonitoring and other cmdlets to fail silently." `
        -Fix "Run this script and agent cmdlets from Windows PowerShell 5.1:`n  powershell.exe -File .\Test-AppInsightsAgentStatus.ps1" `
        -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#powershell-versions'
    Write-ProgressLine -Name 'PowerShell Version' -Status 'WARN' -Summary "PS $psVersion -- agent requires 5.1"
}
else {
    Add-CheckResult 'PowerShell Version' 'WARN' "PowerShell $psVersion detected. This is an older version; 5.1 is recommended."
    Add-Diagnosis -Severity 'WARNING' -Title 'Outdated PowerShell version detected' `
        -Summary "PowerShell $psVersion is older than the recommended 5.1" `
        -Description "The Az.ApplicationMonitor module was built for Windows PowerShell 5.1. Older versions may be missing APIs the agent depends on." `
        -Fix 'Update to Windows PowerShell 5.1 via Windows Management Framework 5.1: https://www.microsoft.com/en-us/download/details.aspx?id=54616'
    Write-ProgressLine -Name 'PowerShell Version' -Status 'WARN' -Summary "PS $psVersion -- upgrade to 5.1 recommended"
}

# ============================================================================
# STEP 10: IIS Shared Configuration
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: IIS Shared Configuration Detection"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  When IIS is configured to use a shared configuration (applicationHost.config stored' -ForegroundColor Gray
    Write-Host '  on a network share and used by multiple web servers), the Application Insights Agent' -ForegroundColor Gray
    Write-Host '  installation requires special steps. The agent modifies applicationHost.config to' -ForegroundColor Gray
    Write-Host '  register its HTTP module, and in shared config mode this must be done carefully to' -ForegroundColor Gray
    Write-Host '  avoid breaking all servers that share the configuration.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  The recommended approach is:' -ForegroundColor Gray
    Write-Host '    1. Temporarily disable shared configuration' -ForegroundColor Gray
    Write-Host '    2. Run Enable-ApplicationInsightsMonitoring on each server individually' -ForegroundColor Gray
    Write-Host '    3. Re-enable shared configuration' -ForegroundColor Gray
    Write-Host '    4. Ensure the shared applicationHost.config includes the module registration' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - IIS shared configuration enabled/disabled state' -ForegroundColor Gray
    Write-Host '  - Shared config physical path (if enabled)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - Shared config disabled (standard single-server setup), or' -ForegroundColor Gray
    Write-Host '  - Shared config enabled with an informational note about special requirements' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-shared-configuration' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'IIS Shared Config'

$sharedConfigDetected = $false

try {
    # Method 1: Check the redirection.config file directly
    $redirectionConfigPath = [System.Environment]::ExpandEnvironmentVariables('%SYSTEMROOT%\System32\inetsrv\config\redirection.config')
    if (Test-Path $redirectionConfigPath) {
        try {
            [xml]$redirectionXml = Get-Content -Path $redirectionConfigPath -Raw -ErrorAction Stop
            $configRedirection = $redirectionXml.SelectSingleNode('//configuration/configurationRedirection')

            if ($configRedirection) {
                $enabledAttr = $configRedirection.GetAttribute('enabled')
                if ($enabledAttr -eq 'true') {
                    $sharedConfigDetected = $true
                    $sharedPath = $configRedirection.GetAttribute('path')
                    $sharedUser = $configRedirection.GetAttribute('userName')

                    $detailLines = @("Shared config path: $sharedPath")
                    if ($sharedUser) { $detailLines += "Config user: $sharedUser" }

                    Add-CheckResult 'IIS Shared Configuration' 'WARN' "IIS shared configuration is ENABLED. Special steps required for agent installation." `
                        -Detail ($detailLines -join "`n")
                    Add-Diagnosis -Severity 'WARNING' -Title 'IIS shared configuration is enabled' `
                        -Summary 'Shared config detected -- agent installation requires special steps' `
                        -Description "IIS is using a shared applicationHost.config from '$sharedPath'. The agent modifies this file to register its HTTP module. In shared config environments, you must temporarily disable shared config, run Enable-ApplicationInsightsMonitoring on each server, then re-enable shared config." `
                        -Fix "1. Disable shared config temporarily`n2. Run Enable-ApplicationInsightsMonitoring on this server`n3. Re-enable shared config`n4. Verify module registration in the shared applicationHost.config" `
                        -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-shared-configuration'
                }
            }
        }
        catch {
            # Parse error is expected on some IIS versions where redirection.config
            # doesn't have the 'enabled' attribute. Fallback (Method 2) will handle it.
            if ($VerboseOutput) {
                Add-CheckResult 'IIS Shared Config (redirection.config)' 'INFO' "Could not parse redirection.config: $_"
            }
        }
    }

    # Method 2: Check via IIS Administration COM object (backup approach)
    if (-not $sharedConfigDetected) {
        try {
            $iisSection = Get-WebConfigurationProperty -Filter '/system.webServer/management' -PSPath 'MACHINE/WEBROOT' -Name 'enableSharedConfiguration' -ErrorAction SilentlyContinue
            if ($iisSection -and $iisSection.Value -eq $true) {
                $sharedConfigDetected = $true
                Add-CheckResult 'IIS Shared Configuration' 'WARN' 'IIS shared configuration is ENABLED (detected via WebAdministration).'
                Add-Diagnosis -Severity 'WARNING' -Title 'IIS shared configuration is enabled' `
                    -Summary 'Shared config detected -- agent installation requires special steps' `
                    -Description 'IIS is using shared configuration. See docs for agent installation steps in shared config environments.' `
                    -Fix 'Temporarily disable shared config, run Enable-ApplicationInsightsMonitoring, then re-enable.' `
                    -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#iis-shared-configuration'
            }
        }
        catch {
            $null = $_ # WebAdministration may not support this query -- that's fine
        }
    }
}
catch {
    Add-CheckResult 'IIS Shared Config' 'INFO' "Could not check shared configuration: $_"
}

if (-not $sharedConfigDetected) {
    Add-CheckResult 'IIS Shared Configuration' 'PASS' 'IIS is using local configuration (shared configuration is not enabled).'
    Write-ProgressLine -Name 'IIS Shared Config' -Status 'OK' -Summary 'Local config (not shared)'
}
else {
    Write-ProgressLine -Name 'IIS Shared Config' -Status 'WARN' -Summary 'Shared configuration enabled'
}

# ============================================================================
# STEP 11: Conflicting DLLs in Application bin Folders
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Conflicting DLLs in Application bin Folders"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The Application Insights Agent performs "codeless attach" by injecting its own' -ForegroundColor Gray
    Write-Host '  version of the Application Insights SDK into your applications at runtime. If your' -ForegroundColor Gray
    Write-Host '  application already ships its own copy of certain DLLs in its bin folder, version' -ForegroundColor Gray
    Write-Host '  conflicts can occur. This causes exceptions like "method not found", duplicate' -ForegroundColor Gray
    Write-Host '  telemetry, or silently missing data.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  The most common conflicting DLLs are:' -ForegroundColor Gray
    Write-Host '  - Microsoft.ApplicationInsights.dll (the core AI SDK)' -ForegroundColor Gray
    Write-Host '  - System.Diagnostics.DiagnosticSource.dll (activity/correlation)' -ForegroundColor Gray
    Write-Host '  - Microsoft.AspNet.TelemetryCorrelation.dll (request correlation)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  This is NOT necessarily a problem -- many apps intentionally use the SDK alongside' -ForegroundColor Gray
    Write-Host '  the agent. But if telemetry is missing or duplicated, version conflicts here are the' -ForegroundColor Gray
    Write-Host '  most likely cause.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Each IIS site''s physical path for bin\*.dll matching known conflicting filenames' -ForegroundColor Gray
    Write-Host '  - DLL version numbers to help identify mismatches' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - No conflicting DLLs found (pure codeless attach), or' -ForegroundColor Gray
    Write-Host '  - Conflicting DLLs found with an informational note (may be intentional SDK usage)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#conflicting-dlls-in-an-apps-bin-directory' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'Conflicting DLLs'

# Known DLLs that conflict with codeless attach
$conflictingDllNames = @(
    'Microsoft.ApplicationInsights.dll',
    'System.Diagnostics.DiagnosticSource.dll',
    'Microsoft.AspNet.TelemetryCorrelation.dll'
)

$sitesWithConflicts = @()
$totalConflictingFiles = 0

if ($iisInstalled) {
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $iisSites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue

        foreach ($site in $iisSites) {
            $siteName = $site.Name
            $physicalPath = $null

            try {
                $physicalPath = $site.physicalPath
                # Expand environment variables in the path
                if ($physicalPath -match '%') {
                    $physicalPath = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
                }
            }
            catch {
                # Can't get physical path for this site
                continue
            }

            if (-not $physicalPath -or -not (Test-Path $physicalPath)) {
                continue
            }

            $binPath = Join-Path $physicalPath 'bin'
            if (-not (Test-Path $binPath)) {
                # No bin folder -- no conflict possible for this site
                Add-CheckResult "Site '$siteName' bin folder" 'INFO' "No bin folder found -- pure codeless attach `(no SDK in app`)."
                continue
            }

            $siteConflicts = @()
            foreach ($dllName in $conflictingDllNames) {
                $dllPath = Join-Path $binPath $dllName
                if (Test-Path $dllPath) {
                    $totalConflictingFiles++
                    $fileVersion = ''
                    try {
                        $versionInfo = (Get-Item $dllPath).VersionInfo
                        $fileVersion = $versionInfo.FileVersion
                    }
                    catch { $null = $_ }

                    $versionDetail = if ($fileVersion) { "v$fileVersion" } else { 'unknown version' }
                    $siteConflicts += "  $dllName `($versionDetail`)"

                    Add-CheckResult "Site '$siteName' $dllName" 'INFO' "Found in bin folder `($versionDetail`)." `
                        -Detail "Path: $dllPath"
                }
            }

            if ($siteConflicts.Count -gt 0) {
                $sitesWithConflicts += @{
                    SiteName = $siteName
                    PhysicalPath = $physicalPath
                    Conflicts = $siteConflicts
                }
            }
            else {
                Add-CheckResult "Site '$siteName' bin folder" 'PASS' 'No known conflicting DLLs in bin folder.'
            }
        }
    }
    catch {
        Add-CheckResult 'Conflicting DLLs scan' 'WARN' "Could not enumerate IIS sites: $_"
        Add-Diagnosis -Severity 'WARNING' -Title 'Could not scan IIS sites for conflicting DLLs' `
            -Summary "Could not enumerate IIS sites: $_" `
            -Description 'The IIS PowerShell provider may not be available. Conflicting DLL detection was skipped.' `
            -Fix 'Re-run this script as Administrator.'
    }
}
else {
    Add-CheckResult 'Conflicting DLLs scan' 'SKIP' 'IIS is not installed -- cannot check for conflicting DLLs.'
}

if ($sitesWithConflicts.Count -gt 0) {
    # Build a summary of which sites have which DLLs
    $conflictSummaryLines = @()
    foreach ($sc in $sitesWithConflicts) {
        $conflictSummaryLines += "$($sc.SiteName) `($($sc.PhysicalPath)`)"
        $conflictSummaryLines += $sc.Conflicts
    }

    Add-Diagnosis -Severity 'INFO' -Title "Conflicting Application Insights DLLs found in $($sitesWithConflicts.Count) site(s)" `
        -Summary "$totalConflictingFiles conflicting DLL(s) across $($sitesWithConflicts.Count) site(s) -- may cause version conflicts" `
        -Description ("The following sites have Application Insights SDK DLLs in their bin folders that may conflict with the agent's codeless attach:`n" + ($conflictSummaryLines -join "`n")) `
        -Fix "If telemetry is missing or duplicated: remove the conflicting DLLs from the bin folder and rely on the agent's codeless attach, OR remove the agent and use the SDK directly. Do not mix SDK + agent unless you have verified version compatibility." `
        -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#conflicting-dlls-in-an-apps-bin-directory'
    Write-ProgressLine -Name 'Conflicting DLLs' -Status 'INFO' -Summary "$totalConflictingFiles DLL(s) in $($sitesWithConflicts.Count) site(s)"
}
elseif ($iisInstalled) {
    Write-ProgressLine -Name 'Conflicting DLLs' -Status 'OK' -Summary 'No conflicting DLLs found'
}
else {
    Write-ProgressLine -Name 'Conflicting DLLs' -Status 'SKIP' -Summary 'IIS not installed'
}

# ============================================================================
# STEP 12: Connection String / Instrumentation Key Extraction
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Connection String / Instrumentation Key Extraction"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  The agent sends telemetry to a specific Application Insights resource identified by' -ForegroundColor Gray
    Write-Host '  a connection string or instrumentation key. If the connection string is missing,' -ForegroundColor Gray
    Write-Host '  incorrect, or points to the wrong resource, telemetry will be lost or sent to the' -ForegroundColor Gray
    Write-Host '  wrong place.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Connection strings are the modern approach and contain the ingestion endpoint, ikey,' -ForegroundColor Gray
    Write-Host '  and optional live metrics / profiler endpoints. Instrumentation keys (ikeys) are the' -ForegroundColor Gray
    Write-Host '  legacy approach -- still functional but being deprecated.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Agent config files discovered in Step 7 for embedded ikey and connection string' -ForegroundColor Gray
    Write-Host '  - Registry environment variables for connection string settings' -ForegroundColor Gray
    Write-Host '  - Validation that the ikey is a valid GUID format' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - A valid connection string or instrumentation key is configured' -ForegroundColor Gray
    Write-Host '  - The ikey is a valid GUID (not all zeros or a placeholder)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'Connection String'

# Script-level storage for extracted values (used by footer for cross-tool command)
$script:extractedIKey = $null
$script:extractedConnectionString = $null

$ikeyGuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$allZerosGuid = '00000000-0000-0000-0000-000000000000'

function Protect-IKey {
    param([string]$ikey)
    if ($ikey.Length -ge 12) {
        return $ikey.Substring(0,8) + '-****-****-****-' + $ikey.Substring($ikey.Length - 4)
    }
    return '****'
}

function Protect-ConnectionString {
    param([string]$cs)
    # Mask the InstrumentationKey value within the connection string
    if ($cs -match 'InstrumentationKey=([0-9a-fA-F-]+)') {
        $fullKey = $Matches[1]
        $masked = Protect-IKey $fullKey
        return $cs -replace [regex]::Escape($fullKey), $masked
    }
    return $cs
}

$configParsed = $false
$ikeyFound = $false
$connStringFound = $false
$extractedValues = @()

# 1) Parse config files found in Step 7
foreach ($cfgPath in $script:foundConfigFiles) {
    try {
        $content = Get-Content -Path $cfgPath -Raw -ErrorAction Stop

        # Try XML parsing first (XXE-safe: XmlResolver = $null prevents external entity resolution)
        $parsedXml = $null
        try {
            $parsedXml = New-Object System.Xml.XmlDocument
            $parsedXml.XmlResolver = $null
            $parsedXml.LoadXml($content)
        }
        catch {
            $parsedXml = $null  # Not valid XML, try regex extraction
        }

        $fileIKey = $null
        $fileConnString = $null

        if ($parsedXml) {
            # Look for InstrumentationKey element
            $ikeyNode = $parsedXml.SelectSingleNode('//*[local-name()="InstrumentationKey"]')
            if ($ikeyNode -and $ikeyNode.InnerText) {
                $fileIKey = $ikeyNode.InnerText.Trim()
            }

            # Look for ConnectionString element
            $csNode = $parsedXml.SelectSingleNode('//*[local-name()="ConnectionString"]')
            if ($csNode -and $csNode.InnerText) {
                $fileConnString = $csNode.InnerText.Trim()
            }
        }

        # Fallback: regex for ikey GUID pattern
        if (-not $fileIKey -and $content -match 'InstrumentationKey[">= ]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
            $fileIKey = $Matches[1]
        }

        # Fallback: regex for connection string
        if (-not $fileConnString -and $content -match '(InstrumentationKey=[0-9a-fA-F-]+;IngestionEndpoint=[^"<\s]+)') {
            $fileConnString = $Matches[1]
        }

        $fileName = [System.IO.Path]::GetFileName($cfgPath)

        # Clean up JSON-style escaped slashes (common in XML config files)
        if ($fileConnString) { $fileConnString = $fileConnString -replace '\\/', '/' }
        if ($fileIKey) { $fileIKey = $fileIKey.Trim() }

        if ($fileConnString) {
            $connStringFound = $true
            $configParsed = $true
            $maskedCS = Protect-ConnectionString $fileConnString
            $extractedValues += "Connection string from $fileName"
            Add-CheckResult "Config '$fileName' connection string" 'PASS' "Connection string found." `
                -Detail "Masked: $maskedCS"

            # Extract ikey from connection string if not found separately
            if (-not $fileIKey -and $fileConnString -match 'InstrumentationKey=([0-9a-fA-F-]+)') {
                $fileIKey = $Matches[1]
            }

            if (-not $script:extractedConnectionString) {
                $script:extractedConnectionString = $fileConnString
            }
        }

        if ($fileIKey) {
            $ikeyFound = $true
            $configParsed = $true
            $maskedKey = Protect-IKey $fileIKey

            if ($fileIKey -eq $allZerosGuid) {
                Add-CheckResult "Config '$fileName' ikey" 'WARN' "Instrumentation key is all zeros -- this is a placeholder, not a real resource." `
                    -Detail "IKey: $fileIKey"
                Add-Diagnosis -Severity 'WARNING' -Title 'Instrumentation key is a placeholder (all zeros)' `
                    -Summary 'Config file contains 00000000-0000-0000-0000-000000000000 -- telemetry will not be ingested' `
                    -Description "The agent config file '$fileName' has an all-zeros instrumentation key. This typically means Enable-ApplicationInsightsMonitoring was run without a valid connection string." `
                    -Fix "Re-run Enable-ApplicationInsightsMonitoring -ConnectionString 'your-connection-string'" `
                    -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string'
            }
            elseif ($fileIKey -notmatch $ikeyGuidPattern) {
                Add-CheckResult "Config '$fileName' ikey" 'WARN' "Instrumentation key is not a valid GUID format." `
                    -Detail "IKey: $maskedKey"
                Add-Diagnosis -Severity 'WARNING' -Title 'Instrumentation key has invalid format' `
                    -Summary 'IKey in config is not a valid GUID -- telemetry will not be ingested' `
                    -Description "The agent config file '$fileName' contains an instrumentation key that is not a valid GUID: $maskedKey" `
                    -Fix "Re-run Enable-ApplicationInsightsMonitoring with a valid connection string from the Azure portal." `
                    -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string'
            }
            else {
                $extractedValues += "IKey: $maskedKey"
                Add-CheckResult "Config '$fileName' ikey" 'PASS' "Valid instrumentation key found: $maskedKey"
            }

            if (-not $script:extractedIKey) {
                $script:extractedIKey = $fileIKey
            }
        }

        if (-not $fileIKey -and -not $fileConnString) {
            Add-CheckResult "Config '$fileName' parse" 'INFO' "No instrumentation key or connection string found in this file."
        }
    }
    catch {
        Add-CheckResult "Config file parse" 'WARN' "Could not read config file '$cfgPath': $_"
        Add-Diagnosis -Severity 'WARNING' -Title 'Could not parse agent config for connection string' `
            -Summary "Error reading '$cfgPath': $_" `
            -Fix 'Check file permissions or re-run as Administrator.'
    }
}

# 2) Check registry for connection string in environment variables (already parsed in Step 4)
if (-not $connStringFound) {
    # Check if APPLICATIONINSIGHTS_CONNECTION_STRING is set in registry env vars
    foreach ($svcName in @('IISADMIN', 'W3SVC', 'WAS')) {
        $svcKey = "SYSTEM\CurrentControlSet\Services\$svcName"
        $regData = Get-RegistryEnvironmentValue -ServiceKeyPath $svcKey
        if ($regData.Exists) {
            foreach ($entry in $regData.Raw) {
                if ($entry -match '^APPLICATIONINSIGHTS_CONNECTION_STRING=(.+)$') {
                    $regCS = $Matches[1].Trim()
                    $connStringFound = $true
                    $configParsed = $true
                    $maskedCS = Protect-ConnectionString $regCS
                    Add-CheckResult "Registry [$svcName] connection string" 'PASS' "Connection string found in service environment." `
                        -Detail "Masked: $maskedCS"
                    if (-not $script:extractedConnectionString) {
                        $script:extractedConnectionString = $regCS
                    }
                    break
                }
            }
            if ($connStringFound) { break }
        }
    }
}

# Summary
if ($script:foundConfigFiles.Count -eq 0) {
    Add-CheckResult 'Connection String' 'INFO' 'No config files were found to parse (see Step 7).'
    Write-ProgressLine -Name 'Connection String' -Status 'INFO' -Summary 'No config files to parse'
}
elseif (-not $configParsed) {
    Add-CheckResult 'Connection String' 'WARN' 'Config files found but no instrumentation key or connection string could be extracted.'
    Add-Diagnosis -Severity 'WARNING' -Title 'No instrumentation key or connection string found in agent config' `
        -Summary 'Could not extract ikey or connection string from any config file' `
        -Description 'The agent config files were found but do not appear to contain a valid instrumentation key or connection string. The agent will not know where to send telemetry.' `
        -Fix "Re-run Enable-ApplicationInsightsMonitoring -ConnectionString 'your-connection-string'" `
        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string'
    Write-ProgressLine -Name 'Connection String' -Status 'WARN' -Summary 'No ikey or connection string found'
}
elseif ($connStringFound) {
    Write-ProgressLine -Name 'Connection String' -Status 'OK' -Summary "Connection string configured"
}
elseif ($ikeyFound) {
    Add-CheckResult 'Connection String note' 'INFO' 'Only instrumentation key found (no connection string). Consider migrating to connection strings.' `
        -Detail 'Connection strings are the modern approach and support custom endpoints for private link, sovereign clouds, etc.'
    Write-ProgressLine -Name 'Connection String' -Status 'OK' -Summary "IKey found (consider migrating to connection string)"
}

# ============================================================================
# STEP (auto-detected or manual): Instrumentation Engine (CLR Profiler)
# ============================================================================

if ($IncludeInstrumentationEngine -or $ieDetected) {
    $stepNumber++
    if ($VerboseOutput) {
        $ieSource = if ($ieDetected -and -not $IncludeInstrumentationEngine) { ' (auto-detected from registry)' } else { '' }
        Write-StepHeader "STEP $stepNumber`: Instrumentation Engine (CLR Profiler) Configuration$ieSource"
        Write-Host ''
        Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
        Write-Host '  The Instrumentation Engine is an optional component that provides deeper telemetry' -ForegroundColor Gray
        Write-Host '  collection using the .NET CLR Profiler API. It enables features like SQL dependency' -ForegroundColor Gray
        Write-Host '  tracking without code changes. This is only installed when -EnableInstrumentationEngine' -ForegroundColor Gray
        Write-Host '  was passed to Enable-ApplicationInsightsMonitoring.' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
        Write-Host '  - CLR Profiler CLSID registration in HKCR (COM class registration)' -ForegroundColor Gray
        Write-Host '  - Profiler DLL file existence' -ForegroundColor Gray
        Write-Host '  - COR_ENABLE_PROFILING and COR_PROFILER environment variables' -ForegroundColor Gray
        Write-Host '  - All Instrumentation Engine environment variables in registry' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
        Write-Host '  - CLSID registered and InprocServer32 DLL exists' -ForegroundColor Gray
        Write-Host '  - All COR_* and MicrosoftInstrumentationEngine_* variables set correctly' -ForegroundColor Gray
        Write-Host ''
    }

    Write-ProgressStart -Name 'Instrumentation Engine'

    $clsidPaths = @(
        "HKCR:\CLSID\$COR_PROFILER_CLSID",
        "Registry::HKEY_CLASSES_ROOT\CLSID\$COR_PROFILER_CLSID",
        "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\$COR_PROFILER_CLSID"
    )

    $profilerRegistered = $false
    $ieFailures = 0
    foreach ($clsidPath in $clsidPaths) {
        try {
            if (Test-Path $clsidPath) {
                $profilerRegistered = $true
                $inprocServer = Get-ItemProperty -Path "$clsidPath\InprocServer32" -Name '(Default)' -ErrorAction SilentlyContinue
                $dllPath = if ($inprocServer) { $inprocServer.'(Default)' } else { 'unknown' }

                Add-CheckResult "CLSID $COR_PROFILER_CLSID" 'PASS' 'Instrumentation Engine CLSID registered.' -Detail $dllPath

                if ($dllPath -and $dllPath -ne 'unknown' -and -not (Test-Path $dllPath)) {
                    Add-CheckResult 'Profiler DLL exists' 'FAIL' "InprocServer32 DLL not found at '$dllPath'."
                    Add-Diagnosis -Severity 'BLOCKING' -Title 'Instrumentation Engine profiler DLL is missing' `
                        -Summary "CLR Profiler CLSID is registered but the DLL does not exist at '$dllPath'" `
                        -Description 'The COM registration points to a file that is not on disk. The Instrumentation Engine will fail to load.' `
                        -Fix 'Re-run Enable-InstrumentationEngine to reinstall the profiler DLL.' `
                        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=api-reference'
                    $ieFailures++
                }
            }
        }
        catch {
            $null = $_ # Path not found -- try next
        }
    }

    if (-not $profilerRegistered) {
        Add-CheckResult 'Instrumentation Engine CLSID' 'WARN' "CLR Profiler CLSID $COR_PROFILER_CLSID not registered."
        Add-Diagnosis -Severity 'WARNING' -Title 'Instrumentation Engine CLSID not registered' `
            -Summary 'CLR Profiler COM registration missing -- advanced profiling unavailable' `
            -Description "The Instrumentation Engine CLSID was not found in HKCR. This is only required when -EnableInstrumentationEngine was used." `
            -Fix 'Re-run Enable-InstrumentationEngine to register the CLR profiler.' `
            -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=api-reference'
    }

    # Check COR_* environment variables
    $firstSvcEnv = Get-RegistryEnvironmentValue -ServiceKeyPath $RegistryServicePaths[0]
    if ($firstSvcEnv.Exists) {
        foreach ($varName in $ExpectedEnvVars_InstrumentationEngine) {
            if ($firstSvcEnv.Parsed.ContainsKey($varName)) {
                $val = $firstSvcEnv.Parsed[$varName]
                Add-CheckResult "IE env var $varName" 'PASS' 'Present.' -Detail $val
            }
            else {
                Add-CheckResult "IE env var $varName" 'FAIL' 'Missing from IISADMIN Environment.'
                $ieFailures++
            }
        }

        # Validate COR_PROFILER value
        if ($firstSvcEnv.Parsed.ContainsKey('COR_PROFILER')) {
            $profilerVal = $firstSvcEnv.Parsed['COR_PROFILER']
            if ($profilerVal -ne $COR_PROFILER_CLSID) {
                Add-CheckResult 'COR_PROFILER value' 'FAIL' "Expected '$COR_PROFILER_CLSID' but found '$profilerVal'."
                $ieFailures++
            }
        }
    }

    if ($ieFailures -eq 0) {
        Write-ProgressLine -Name 'Instrumentation Engine' -Status 'OK' -Summary 'CLSID registered, all env vars present'
    } else {
        Write-ProgressLine -Name 'Instrumentation Engine' -Status 'FAIL' -Summary "$ieFailures issue(s) found"
    }
}

# ============================================================================
# STEP 13: ASP.NET Core Startup Hook & Hosting Startup Files
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: ASP.NET Core Startup Hook & Hosting Startup Files"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  ASP.NET Core applications are instrumented differently than Full Framework apps.' -ForegroundColor Gray
    Write-Host '  Instead of an IIS HTTP module, the agent uses .NET startup hooks' -ForegroundColor Gray
    Write-Host '  (DOTNET_STARTUP_HOOKS) and hosting startup assemblies to inject telemetry at' -ForegroundColor Gray
    Write-Host '  application startup. The DLLs referenced by these variables must exist on disk.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - DOTNET_STARTUP_HOOKS target DLL exists' -ForegroundColor Gray
    Write-Host '  - DOTNET_ADDITIONAL_DEPS path exists (if set)' -ForegroundColor Gray
    Write-Host '  - DOTNET_SHARED_STORE path exists (if set)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - All referenced DLLs and paths exist on disk' -ForegroundColor Gray
    Write-Host '  - Or these variables are not set (acceptable for Full Framework-only environments)' -ForegroundColor Gray
    Write-Host ''
}

Write-ProgressStart -Name 'Startup Hook Files'

$firstSvcEnv = Get-RegistryEnvironmentValue -ServiceKeyPath $RegistryServicePaths[0]
$hookCheckCount = 0
$hookFailCount = 0

if ($firstSvcEnv.Exists -and $firstSvcEnv.Parsed.ContainsKey('DOTNET_STARTUP_HOOKS')) {
    $hookPath = $firstSvcEnv.Parsed['DOTNET_STARTUP_HOOKS']
    $hookCheckCount++
    if (Test-Path $hookPath) {
        Add-CheckResult 'DOTNET_STARTUP_HOOKS target' 'PASS' "Startup hook DLL exists: $hookPath"
    }
    else {
        Add-CheckResult 'DOTNET_STARTUP_HOOKS target' 'FAIL' "Startup hook DLL NOT found: $hookPath"
        $hookFailCount++
    }
}

if ($firstSvcEnv.Exists -and $firstSvcEnv.Parsed.ContainsKey('DOTNET_ADDITIONAL_DEPS')) {
    $depsPath = $firstSvcEnv.Parsed['DOTNET_ADDITIONAL_DEPS']
    $hookCheckCount++
    if (Test-Path $depsPath) {
        Add-CheckResult 'DOTNET_ADDITIONAL_DEPS target' 'PASS' "Additional deps path exists: $depsPath"
    }
    else {
        Add-CheckResult 'DOTNET_ADDITIONAL_DEPS target' 'FAIL' "Additional deps path NOT found: $depsPath"
        $hookFailCount++
    }
}

if ($firstSvcEnv.Exists -and $firstSvcEnv.Parsed.ContainsKey('DOTNET_SHARED_STORE')) {
    $storePath = $firstSvcEnv.Parsed['DOTNET_SHARED_STORE']
    $hookCheckCount++
    if (Test-Path $storePath) {
        Add-CheckResult 'DOTNET_SHARED_STORE target' 'PASS' "Shared store path exists: $storePath"
    }
    else {
        Add-CheckResult 'DOTNET_SHARED_STORE target' 'FAIL' "Shared store path NOT found: $storePath"
        $hookFailCount++
    }
}

if ($hookFailCount -gt 0) {
    Add-Diagnosis -Severity 'BLOCKING' -Title 'Missing ASP.NET Core startup hook files' `
        -Summary "$hookFailCount startup hook file(s) missing -- ASP.NET Core apps will not be instrumented" `
        -Description 'One or more DLLs or paths referenced by DOTNET_STARTUP_HOOKS, DOTNET_ADDITIONAL_DEPS, or DOTNET_SHARED_STORE do not exist. The agent installation may be corrupted.' `
        -Fix "Reinstall the Az.ApplicationMonitor module and re-run Enable-ApplicationInsightsMonitoring." `
        -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions'
    Write-ProgressLine -Name 'Startup Hook Files' -Status 'FAIL' -Summary "$hookFailCount file(s) missing"
} elseif ($hookCheckCount -gt 0) {
    Write-ProgressLine -Name 'Startup Hook Files' -Status 'OK' -Summary "All $hookCheckCount file(s) verified"
} else {
    Add-CheckResult 'Startup Hook Files' 'INFO' 'No ASP.NET Core startup hook variables found in registry. This is normal for environments that only host ASP.NET Full Framework apps.'
    Write-ProgressLine -Name 'Startup Hook Files' -Status 'INFO' -Summary 'No hooks configured (Full Framework only?)'
}

# ============================================================================
# STEP (last): Running w3wp / dotnet.exe Process & Module Inspection
# ============================================================================

$stepNumber++
if ($VerboseOutput) {
    Write-StepHeader "STEP $stepNumber`: Running w3wp / dotnet.exe Process & Module Inspection"
    Write-Host ''
    Write-Host '  WHY THIS MATTERS:' -ForegroundColor Cyan
    Write-Host '  Even if the agent is installed correctly, it only takes effect when IIS worker' -ForegroundColor Gray
    Write-Host '  processes (w3wp.exe) or ASP.NET Core host processes (dotnet.exe) load the agent' -ForegroundColor Gray
    Write-Host '  DLLs. After enabling the agent, IIS must be restarted (iisreset) for the' -ForegroundColor Gray
    Write-Host '  environment variables to take effect.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Critically, when the agent detects that an application already ships its own copy' -ForegroundColor Gray
    Write-Host '  of the Application Insights SDK (e.g., Microsoft.ApplicationInsights.dll in the' -ForegroundColor Gray
    Write-Host '  app''s bin folder), the agent "backs off" to avoid version conflicts. This check' -ForegroundColor Gray
    Write-Host '  inspects which DLLs are actually loaded in memory and WHERE they were loaded from' -ForegroundColor Gray
    Write-Host '  to determine whether the agent is active, backed off, or not loaded at all.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT WE''RE CHECKING:' -ForegroundColor Cyan
    Write-Host '  - Running w3wp.exe processes, mapped to their IIS application pool' -ForegroundColor Gray
    Write-Host '  - Running dotnet.exe processes that may host ASP.NET Core apps' -ForegroundColor Gray
    Write-Host '  - Agent-specific DLLs (RedfieldIISModule, StartupHook, StartupBootstrapper)' -ForegroundColor Gray
    Write-Host '  - Instrumentation Engine DLLs (MicrosoftInstrumentationEngine)' -ForegroundColor Gray
    Write-Host '  - Shared SDK DLLs and whether they loaded from the agent or the app''s bin folder' -ForegroundColor Gray
    Write-Host '  - OpenTelemetry auto-instrumentation DLLs (when OTel mode is detected)' -ForegroundColor Gray
    Write-Host '  - .NET runtime detection (clr.dll = Framework, coreclr.dll = Core)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  WHAT SUCCESS LOOKS LIKE:' -ForegroundColor Cyan
    Write-Host '  - w3wp processes running with agent DLLs loaded from the agent install path' -ForegroundColor Gray
    Write-Host '  - If no w3wp processes are running, that just means no sites have received' -ForegroundColor Gray
    Write-Host '    requests yet -- browse to a site, wait a moment, then re-run this script' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  NOTE: Module inspection requires Administrator privileges. Without elevation,' -ForegroundColor Gray
    Write-Host '  process discovery still works but loaded DLLs cannot be examined. If 32-bit' -ForegroundColor Gray
    Write-Host '  app pools are in use, a matching-bitness PowerShell session is also required.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Docs: https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=get-status' -ForegroundColor DarkGray
    Write-Host ''
}

Write-ProgressStart -Name 'Process Inspection'

# Agent-specific modules -- these ONLY come from the agent, never from an app's own SDK
$agentOnlyPatterns = @(
    'Microsoft.ApplicationInsights.RedfieldIISModule',
    'Microsoft.AppInsights.IIS.ManagedHttpModuleHelper',
    'Microsoft.ApplicationInsights.StartupHook',
    'Microsoft.ApplicationInsights.StartupBootstrapper'
)

# Instrumentation Engine DLLs
$iePatterns = @(
    'MicrosoftInstrumentationEngine_x64',
    'MicrosoftInstrumentationEngine_x86'
)

# OpenTelemetry auto-instrumentation DLLs (relevant when $detectedMode is 'OpenTelemetry')
$otelPatterns = @(
    'OpenTelemetry.AutoInstrumentation',
    'OpenTelemetry.Api'
)

# DLLs that both the agent and apps may ship -- the load path tells us who "won"
$sharedDllNames = @(
    'Microsoft.ApplicationInsights.dll',
    'System.Diagnostics.DiagnosticSource.dll',
    'Microsoft.AspNet.TelemetryCorrelation.dll'
)

# Build a list of known agent install directories for path matching
$agentInstallPaths = @()
$azMonModule = Get-Module -Name 'Az.ApplicationMonitor' -ListAvailable -ErrorAction SilentlyContinue | Select-Object -First 1
if ($azMonModule) {
    $agentInstallPaths += $azMonModule.ModuleBase.ToLower()
}
$agentInstallPaths += (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\Az.ApplicationMonitor').ToLower()
$agentInstallPaths += (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\ApplicationInsightsAgent').ToLower()
$agentInstallPaths = $agentInstallPaths | Select-Object -Unique

# --- Determine this PowerShell process's bitness ---
$scriptIs64Bit = [Environment]::Is64BitProcess

# --- Build app pool 32-bit setting map from IIS config ---
$poolIs32Bit = @{}
try {
    $iisAppPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
    foreach ($pool in $iisAppPools) {
        $poolIs32Bit[$pool.Name] = [bool]$pool.enable32BitAppOnWin64
    }
}
catch {
    $null = $_ # WebAdministration not available or IIS not installed
}

# --- Build PID-to-app-pool map via CIM command line parsing ---
$pidToAppPool = @{}
try {
    $w3wpCimProcs = @(Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -ErrorAction SilentlyContinue)
    foreach ($cimProc in $w3wpCimProcs) {
        $cmdLine = $cimProc.CommandLine
        if ($cmdLine -match '-ap\s+"([^"]+)"') {
            $pidToAppPool[$cimProc.ProcessId] = $Matches[1]
        }
        elseif ($cmdLine -match '-ap\s+(\S+)') {
            $pidToAppPool[$cimProc.ProcessId] = $Matches[1]
        }
    }
}
catch {
    $null = $_ # CIM query failed -- app pool names will be unavailable
}

# --- Gather target processes ---
$w3wpProcesses = @()
$dotnetProcesses = @()
try { $w3wpProcesses = @(Get-Process -Name 'w3wp' -ErrorAction SilentlyContinue) } catch { $null = $_ }
try { $dotnetProcesses = @(Get-Process -Name 'dotnet' -ErrorAction SilentlyContinue) } catch { $null = $_ }

$allTargetProcesses = @()
foreach ($p in $w3wpProcesses) {
    $poolName = if ($pidToAppPool.ContainsKey($p.Id)) { $pidToAppPool[$p.Id] } else { $null }
    $is32 = if ($poolName -and $poolIs32Bit.ContainsKey($poolName)) { $poolIs32Bit[$poolName] } else { $null }
    $label = if ($poolName) { "w3wp PID $($p.Id) ($poolName)" } else { "w3wp PID $($p.Id)" }
    $allTargetProcesses += @{ Process = $p; Type = 'w3wp'; AppPool = $poolName; Is32Bit = $is32; Label = $label }
}
foreach ($p in $dotnetProcesses) {
    $allTargetProcesses += @{ Process = $p; Type = 'dotnet'; AppPool = $null; Is32Bit = $null; Label = "dotnet PID $($p.Id)" }
}

$agentActiveCount = 0
$agentBackedOffCount = 0
$noAgentCount = 0
$accessDeniedCount = 0
$bitnessMismatchCount = 0
$processSummaryRows = @()

if ($allTargetProcesses.Count -eq 0) {
    Add-CheckResult 'Target Processes' 'INFO' 'No w3wp.exe or dotnet.exe processes are currently running.' `
        -Detail 'IIS starts worker processes on demand. Browse to a site in the browser, wait a few seconds, then re-run this script.'
    Write-ProgressLine -Name 'Process Inspection' -Status 'INFO' -Summary 'No w3wp / dotnet processes running'
}
else {
    $procCountParts = @()
    if ($w3wpProcesses.Count -gt 0) { $procCountParts += "$($w3wpProcesses.Count) w3wp" }
    if ($dotnetProcesses.Count -gt 0) { $procCountParts += "$($dotnetProcesses.Count) dotnet" }
    Add-CheckResult 'Target Processes' 'INFO' "Found $($allTargetProcesses.Count) process(es): $($procCountParts -join ', ')." -Silent

    foreach ($entry in $allTargetProcesses) {
        $proc = $entry.Process
        $procLabel = $entry.Label
        $agentOnlyModulesFound = @()
        $ieModulesFound = @()
        $otelModulesFound = @()
        $sharedDllAnalysis = @()
        $hasAgentOnlyModules = $false
        $hasIEModules = $false
        $hasOtelModules = $false
        $hasBackedOff = $false
        $moduleAccessOk = $true
        $classification = 'Unknown'

        # Detect bitness mismatch before attempting module inspection
        $hasBitnessMismatch = $false
        if ($entry.Type -eq 'w3wp' -and $null -ne $entry.Is32Bit) {
            # Pool configured for 32-bit but we're 64-bit PowerShell (or vice versa)
            if ($entry.Is32Bit -and $scriptIs64Bit) {
                $hasBitnessMismatch = $true
            }
            elseif (-not $entry.Is32Bit -and -not $scriptIs64Bit) {
                $hasBitnessMismatch = $true
            }
        }

        $runtimeLabel = '?'

        try {
            $allModules = @($proc.Modules)

            # 0) Detect .NET runtime(s) loaded in this process
            $hasClr     = $false
            $hasCoreClr = $false
            foreach ($mod in $allModules) {
                $fn = [System.IO.Path]::GetFileName($mod.FileName)
                if ($fn -eq 'clr.dll')     { $hasClr     = $true }
                if ($fn -eq 'coreclr.dll') { $hasCoreClr = $true }
            }
            $runtimeLabel = if ($hasClr -and $hasCoreClr) { 'FX+Core' }
                            elseif ($hasClr)     { 'FX' }
                            elseif ($hasCoreClr) { 'Core' }
                            else                 { '-' }

            # 1) Check for agent-only modules
            foreach ($mod in $allModules) {
                $modFile = $mod.FileName
                foreach ($pattern in $agentOnlyPatterns) {
                    if ($modFile -like "*$pattern*") {
                        $agentOnlyModulesFound += [System.IO.Path]::GetFileName($modFile)
                        break
                    }
                }
            }
            if ($agentOnlyModulesFound.Count -gt 0) { $hasAgentOnlyModules = $true }

            # 2) Check for Instrumentation Engine DLLs
            foreach ($mod in $allModules) {
                $modFile = $mod.FileName
                foreach ($pattern in $iePatterns) {
                    if ($modFile -like "*$pattern*") {
                        $ieModulesFound += [System.IO.Path]::GetFileName($modFile)
                        break
                    }
                }
            }
            if ($ieModulesFound.Count -gt 0) { $hasIEModules = $true }

            # 3) Check for OpenTelemetry auto-instrumentation DLLs
            foreach ($mod in $allModules) {
                $modFile = $mod.FileName
                foreach ($pattern in $otelPatterns) {
                    if ($modFile -like "*$pattern*") {
                        $otelModulesFound += [System.IO.Path]::GetFileName($modFile)
                        break
                    }
                }
            }
            if ($otelModulesFound.Count -gt 0) { $hasOtelModules = $true }

            # 4) For shared/conflicting DLLs, determine WHERE they loaded from
            foreach ($dllName in $sharedDllNames) {
                $loadedMod = $allModules | Where-Object {
                    [System.IO.Path]::GetFileName($_.FileName) -eq $dllName
                } | Select-Object -First 1

                if ($loadedMod) {
                    $loadedPath = $loadedMod.FileName
                    $loadedPathLower = $loadedPath.ToLower()
                    $loadedVersion = ''
                    try { $loadedVersion = $loadedMod.FileVersionInfo.FileVersion } catch { $null = $_ }
                    $vStr = if ($loadedVersion) { "v$loadedVersion" } else { 'unknown version' }

                    $origin = 'Unknown'
                    $isFromAgent = $false
                    foreach ($agentPath in $agentInstallPaths) {
                        if ($loadedPathLower.StartsWith($agentPath)) {
                            $origin = 'Agent install'
                            $isFromAgent = $true
                            break
                        }
                    }
                    if (-not $isFromAgent) {
                        if ($loadedPathLower -like '*\bin\*' -or $loadedPathLower -like '*\bin') {
                            $origin = 'App bin folder'
                            $hasBackedOff = $true
                        }
                        elseif ($loadedPathLower -like '*\assembly\gac*') {
                            $origin = 'GAC'
                        }
                        elseif ($loadedPathLower -like '*\windows\microsoft.net\*') {
                            $origin = '.NET Framework'
                        }
                    }

                    $sharedDllAnalysis += "$dllName ($vStr) -- $origin"
                    if ($VerboseOutput) {
                        $sharedDllAnalysis += "    Path: $loadedPath"
                    }
                }
            }
        }
        catch {
            $moduleAccessOk = $false
            $accessDeniedCount++

            # Provide a specific message depending on probable cause
            if ($hasBitnessMismatch) {
                $bitnessMismatchCount++
                $psBits = if ($scriptIs64Bit) { '64-bit' } else { '32-bit' }
                $w3wpBits = if ($entry.Is32Bit) { '32-bit' } else { '64-bit' }
                Add-CheckResult $procLabel 'WARN' "Cannot inspect modules -- $psBits PowerShell cannot read modules from $w3wpBits w3wp.exe process." `
                    -Detail "App pool '$($entry.AppPool)' has enable32BitAppOnWin64=$($entry.Is32Bit). Run this script from a matching $w3wpBits PowerShell to inspect this process." `
                    -Action "Launch $w3wpBits PowerShell and re-run, or disable 32-bit mode on the app pool if not needed."
            }
            elseif (-not $isAdmin) {
                Add-CheckResult $procLabel 'WARN' "Could not inspect loaded modules -- not running as Administrator." `
                    -Detail 'Process is running but module inspection requires elevation.' `
                    -Action 'Re-run this script as Administrator to inspect loaded DLLs in this process.'
            }
            else {
                Add-CheckResult $procLabel 'WARN' "Could not inspect loaded modules (access denied)."
            }
        }

        if ($moduleAccessOk) {
            # Build detail string
            $detailLines = @()
            if ($agentOnlyModulesFound.Count -gt 0) {
                $detailLines += "Agent modules: $($agentOnlyModulesFound -join ', ')"
            }
            if ($ieModulesFound.Count -gt 0) {
                $detailLines += "IE modules:    $($ieModulesFound -join ', ')"
            }
            if ($otelModulesFound.Count -gt 0) {
                $detailLines += "OTel modules:  $($otelModulesFound -join ', ')"
            }
            if ($sharedDllAnalysis.Count -gt 0) {
                $detailLines += $sharedDllAnalysis
            }
            $detailText = if ($detailLines.Count -gt 0) { $detailLines -join "`n" } else { '' }

            # Classify the process
            if ($hasOtelModules) {
                $agentActiveCount++
                $classification = 'OTel auto-instrumented'
                Add-CheckResult $procLabel 'PASS' "OpenTelemetry auto-instrumentation ACTIVE." `
                    -Detail $detailText
            }
            elseif ($hasAgentOnlyModules -and -not $hasBackedOff) {
                $agentActiveCount++
                $classification = 'Agent ACTIVE'
                Add-CheckResult $procLabel 'PASS' 'Agent is ACTIVE -- agent modules loaded, SDK provided by agent.' `
                    -Detail $detailText
            }
            elseif ($hasAgentOnlyModules -and $hasBackedOff) {
                $agentActiveCount++
                $classification = 'Agent ACTIVE (mixed)'
                Add-CheckResult $procLabel 'INFO' 'Agent attached but some SDK DLLs loaded from app bin folder -- possible mixed instrumentation.' `
                    -Detail $detailText
            }
            elseif ($hasBackedOff) {
                $agentBackedOffCount++
                $classification = 'Agent BACKED OFF'
                Add-CheckResult $procLabel 'INFO' 'Agent appears to have BACKED OFF -- SDK DLLs loaded from app bin folder, not from agent.' `
                    -Detail $detailText
            }
            elseif ($sharedDllAnalysis.Count -eq 0 -and $agentOnlyModulesFound.Count -eq 0 -and -not $hasOtelModules) {
                $noAgentCount++
                $classification = 'Not instrumented'
                Add-CheckResult $procLabel 'WARN' 'No Application Insights agent or SDK modules detected in this process.' `
                    -Detail 'The agent may not have taken effect. Run "iisreset" to restart IIS after enabling the agent.'
            }
            else {
                $noAgentCount++
                $classification = 'Unknown (partial)'
                Add-CheckResult $procLabel 'WARN' 'Agent modules not detected, but some AI-related DLLs are loaded.' `
                    -Detail $detailText
            }

            # Track for summary table
            $ieLabel = if ($hasIEModules) { 'Yes' } else { 'No' }
            $processSummaryRows += @{
                PID = $proc.Id
                Identity = if ($entry.AppPool) { $entry.AppPool } elseif ($entry.Type -eq 'dotnet') { '(dotnet.exe)' } else { '(unknown pool)' }
                Classification = $classification
                IE = $ieLabel
                Is32Bit = $entry.Is32Bit
                Runtime = $runtimeLabel
            }
        }
        else {
            # Even when module inspection fails, we still track the process
            $failReason = if ($hasBitnessMismatch) { '(32/64-bit mismatch)' } elseif (-not $isAdmin) { '(not admin)' } else { '(access denied)' }
            $processSummaryRows += @{
                PID = $proc.Id
                Identity = if ($entry.AppPool) { $entry.AppPool } elseif ($entry.Type -eq 'dotnet') { '(dotnet.exe)' } else { '(unknown pool)' }
                Classification = $failReason
                IE = '?'
                Is32Bit = $entry.Is32Bit
                Runtime = $runtimeLabel
            }
        }
    }

    # --- Render summary table (verbose only) ---
    if ($VerboseOutput -and $processSummaryRows.Count -gt 0) {
        Write-Host ''
        Write-Host '  Process Summary:' -ForegroundColor White

        # Determine if 32-bit column is relevant (any w3wp with known setting)
        $show32BitCol = ($processSummaryRows | Where-Object { $null -ne $_.Is32Bit }).Count -gt 0

        # Column widths
        $pidW = 7
        $idW  = ($processSummaryRows | ForEach-Object { $_.Identity.Length } | Measure-Object -Maximum).Maximum
        if ($idW -lt 8) { $idW = 8 }
        if ($idW -gt 30) { $idW = 30 }
        $clW  = ($processSummaryRows | ForEach-Object { $_.Classification.Length } | Measure-Object -Maximum).Maximum
        if ($clW -lt 14) { $clW = 14 }
        $ieW  = 4

        $rtW  = 8
        $hdrPid = 'PID'.PadRight($pidW)
        $hdrId  = 'Identity'.PadRight($idW)
        $hdrRt  = 'Runtime'.PadRight($rtW)
        $hdrCl  = 'Classification'.PadRight($clW)
        $hdrIe  = 'IE'

        if ($show32BitCol) {
            $bitW = 5
            $hdrBit = '32b'
            Write-Host "    $hdrPid  $hdrId  $($hdrBit.PadRight($bitW))$hdrRt$hdrCl  $hdrIe" -ForegroundColor DarkGray
            $rule = '    ' + ('-' * $pidW) + '  ' + ('-' * $idW) + '  ' + ('-' * $bitW) + ('-' * $rtW) + ('-' * $clW) + '  ' + ('-' * $ieW)
        }
        else {
            Write-Host "    $hdrPid  $hdrId  $hdrRt$hdrCl  $hdrIe" -ForegroundColor DarkGray
            $rule = '    ' + ('-' * $pidW) + '  ' + ('-' * $idW) + '  ' + ('-' * $rtW) + ('-' * $clW) + '  ' + ('-' * $ieW)
        }
        Write-Host $rule -ForegroundColor DarkGray

        foreach ($row in $processSummaryRows) {
            $pidStr = "$($row.PID)".PadRight($pidW)
            $idStr  = $row.Identity.PadRight($idW).Substring(0, $idW)
            $clStr  = $row.Classification.PadRight($clW)

            $clColor = switch -Wildcard ($row.Classification) {
                'Agent ACTIVE*'        { 'Green' }
                'OTel auto*'           { 'Green' }
                'Agent BACKED OFF'     { 'DarkYellow' }
                'Not instrumented'     { 'DarkYellow' }
                '(32/64-bit mismatch)' { 'DarkYellow' }
                '(not admin)'          { 'DarkGray' }
                '(access denied)'      { 'DarkGray' }
                default                { 'Gray' }
            }

            $rtStr = $row.Runtime.PadRight($rtW)
            $rtColor = switch ($row.Runtime) {
                'FX+Core' { 'Cyan' }
                'FX'      { 'Gray' }
                'Core'    { 'Gray' }
                default   { 'DarkGray' }
            }

            Write-Host "    $pidStr  $idStr  " -NoNewline -ForegroundColor Gray
            if ($show32BitCol) {
                $bitStr = if ($null -eq $row.Is32Bit) { '  -  ' } elseif ($row.Is32Bit) { ' Yes ' } else { '  No ' }
                $bitColor = if ($row.Is32Bit -eq $true) { 'DarkYellow' } else { 'Gray' }
                Write-Host $bitStr -NoNewline -ForegroundColor $bitColor
            }
            Write-Host $rtStr -NoNewline -ForegroundColor $rtColor
            Write-Host $clStr -NoNewline -ForegroundColor $clColor
            Write-Host "  $($row.IE)" -ForegroundColor Gray
        }

        if ($show32BitCol -and $bitnessMismatchCount -gt 0) {
            $psBits = if ($scriptIs64Bit) { '64-bit' } else { '32-bit' }
            Write-Host ''
            Write-Host "  Note: This script is running as $psBits PowerShell. Module inspection" -ForegroundColor DarkGray
            Write-Host "  cannot cross the 32/64-bit boundary. Processes marked '32b=Yes' are" -ForegroundColor DarkGray
            Write-Host '  32-bit w3wp.exe (enable32BitAppOnWin64=True on the app pool).' -ForegroundColor DarkGray
        }

        Write-Host ''
    }

    # --- Diagnosis ---
    $summaryParts = @()
    if ($agentActiveCount -gt 0) { $summaryParts += "$agentActiveCount active" }
    if ($agentBackedOffCount -gt 0) { $summaryParts += "$agentBackedOffCount backed-off" }
    if ($noAgentCount -gt 0) { $summaryParts += "$noAgentCount not loaded" }
    if ($accessDeniedCount -gt 0) { $summaryParts += "$accessDeniedCount inaccessible" }

    if ($bitnessMismatchCount -gt 0) {
        $psBits = if ($scriptIs64Bit) { '64-bit' } else { '32-bit' }
        $targetBits = if ($scriptIs64Bit) { '32-bit' } else { '64-bit' }
        Add-Diagnosis -Severity 'INFO' -Title "$bitnessMismatchCount process(es) skipped due to 32/64-bit mismatch" `
            -Summary "This $psBits PowerShell cannot inspect $targetBits w3wp.exe processes" `
            -Description "The .NET Process.Modules API cannot enumerate modules across the 32/64-bit boundary. $bitnessMismatchCount w3wp process(es) are running as $targetBits (enable32BitAppOnWin64 is set on their app pool) but this PowerShell session is $psBits." `
            -Fix "Either launch $targetBits PowerShell to re-run this script, or disable 'Enable 32-Bit Applications' on the affected app pool(s) in IIS Manager if 32-bit mode is not required."
    }

    if (-not $isAdmin -and $accessDeniedCount -gt 0 -and $bitnessMismatchCount -lt $accessDeniedCount) {
        Add-Diagnosis -Severity 'WARNING' -Title 'Process module inspection requires Administrator privileges' `
            -Summary "$($accessDeniedCount - $bitnessMismatchCount) process(es) could not be inspected due to insufficient privileges" `
            -Description 'The script detected running w3wp/dotnet processes but could not read their loaded modules without elevation. Process discovery still works, but DLL-level classification requires Administrator.' `
            -Fix 'Re-run this script as Administrator (right-click PowerShell -> Run as Administrator).'
    }

    if ($noAgentCount -gt 0 -and $agentActiveCount -eq 0 -and $agentBackedOffCount -eq 0) {
        Add-Diagnosis -Severity 'WARNING' -Title 'Agent DLLs not loaded in any running process' `
            -Summary "$($allTargetProcesses.Count) process(es) running but none have agent modules loaded" `
            -Description "The agent appears to be installed, but no running worker processes have loaded the agent DLLs. This usually means IIS has not been restarted since the agent was enabled." `
            -Fix "Restart IIS to force worker processes to pick up the agent environment variables:`n  iisreset" `
            -Docs 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=get-status'
        Write-ProgressLine -Name 'Process Inspection' -Status 'WARN' -Summary "$($allTargetProcesses.Count) process(es): $($summaryParts -join ', ')"
    }
    elseif ($agentBackedOffCount -gt 0) {
        Add-Diagnosis -Severity 'INFO' -Title "Agent backed off in $agentBackedOffCount process(es)" `
            -Summary "Agent detected app-bundled SDK DLLs and backed off to avoid conflicts" `
            -Description "In $agentBackedOffCount worker process(es), the Application Insights SDK DLLs were loaded from the application's bin folder instead of from the agent's install directory. This means the agent detected the app already has the SDK and backed off. This is expected behavior when apps bundle the SDK, but means those apps get telemetry from their own SDK, not from the agent." `
            -Fix "If you want the agent to instrument these apps: remove Microsoft.ApplicationInsights.dll and related DLLs from the app's bin folder, then run iisreset. If the app intentionally uses the SDK, no action needed." `
            -Docs 'https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot#conflicting-dlls-in-an-apps-bin-directory'
        Write-ProgressLine -Name 'Process Inspection' -Status 'INFO' -Summary "$($allTargetProcesses.Count) process(es): $($summaryParts -join ', ')"
    }
    elseif ($agentActiveCount -gt 0) {
        Write-ProgressLine -Name 'Process Inspection' -Status 'OK' -Summary "$($allTargetProcesses.Count) process(es): $($summaryParts -join ', ')"
    }
    elseif ($accessDeniedCount -gt 0 -and $noAgentCount -eq 0) {
        # All processes were inaccessible but we still found them running
        Write-ProgressLine -Name 'Process Inspection' -Status 'WARN' -Summary "$($allTargetProcesses.Count) process(es): $($summaryParts -join ', ')"
    }
    else {
        Write-ProgressLine -Name 'Process Inspection' -Status 'WARN' -Summary "$($allTargetProcesses.Count) process(es): $($summaryParts -join ', ')"
    }
}

# ============================================================================
# DIAGNOSIS & SUMMARY
# ============================================================================

$passes   = @($allResults | Where-Object Status -eq 'PASS').Count
$warnings = @($allResults | Where-Object Status -eq 'WARN').Count
$failures = @($allResults | Where-Object Status -eq 'FAIL').Count
$infos    = @($allResults | Where-Object Status -eq 'INFO').Count
$totalChecks = $allResults.Count

# --- Diagnosis Block ---
# --- Consolidate "agent not installed" when all three core components are missing ---
# When the HTTP module, GAC assembly, and registry env vars are ALL absent, the agent
# simply isn't installed. Replace three individual BLOCKING entries with one clear finding.
$agentNotInstalled = (-not $appHostModuleOk) -and (-not $gacFound) -and ($detectedMode -eq 'None')

if ($agentNotInstalled) {
    $notInstalledTitles = @(
        'HTTP module not registered in applicationHost.config',
        'GAC assembly not registered',
        'Agent registry environment variables not configured'
    )
    $consolidated = @{
        Severity    = 'BLOCKING'
        Title       = 'Application Insights Agent for .NET (IIS auto-instrumentation) is not installed'
        Summary     = 'Agent not installed -- HTTP module, GAC assembly, and registry environment variables are all missing'
        Description = "No Application Insights Agent components were detected on this machine.`n" +
            "     This agent provides codeless auto-instrumentation for ASP.NET and ASP.NET Core`n" +
            "     applications running in IIS. It is separate from the Application Insights SDK`n" +
            "     (added via NuGet) and from agents for other languages (Java, Node.js, Python).`n" +
            "     `n" +
            "     Missing components:`n" +
            "       - ManagedHttpModuleHelper not registered in applicationHost.config`n" +
            "       - ManagedHttpModuleHelper assembly not in the Global Assembly Cache (GAC)`n" +
            "       - No agent environment variables on IISADMIN / W3SVC / WAS registry keys"
        Fix         = "Install and enable the agent:`nImport-Module Az.ApplicationMonitor`nEnable-ApplicationInsightsMonitoring -ConnectionString ""your-connection-string"""
        Portal      = $null
        Docs        = 'https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent?tabs=detailed-instructions#deploy-the-application-insights-agent-for-on-premises-servers'
    }
    # Remove the three individual entries and insert the consolidated one
    $script:diagnosisItems = @($script:diagnosisItems | Where-Object { $_.Title -notin $notInstalledTitles })
    $script:diagnosisItems = @($consolidated) + $script:diagnosisItems
}

$blockingItems = @($script:diagnosisItems | Where-Object { $_.Severity -eq 'BLOCKING' })
$warningItems  = @($script:diagnosisItems | Where-Object { $_.Severity -eq 'WARNING' })
$infoItems     = @($script:diagnosisItems | Where-Object { $_.Severity -eq 'INFO' })
$totalIssues   = $blockingItems.Count + $warningItems.Count + $infoItems.Count

# Also count as "has issues" if WARN/FAIL check results exist without diagnosis entries
$hasUncoveredIssues = ($totalIssues -eq 0) -and ($failures -gt 0 -or $warnings -gt 0)

# Build ordered list: BLOCKING first, then WARNING, then INFO
$orderedItems = @()
$orderedItems += $blockingItems
$orderedItems += $warningItems
$orderedItems += $infoItems

Write-Host ''

if ($totalIssues -eq 0 -and -not $hasUncoveredIssues) {
    # ---- No issues found ----
    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host '  DIAGNOSIS: ' -ForegroundColor Green -NoNewline
    Write-Host "All checks passed `($($totalChecks) checks, no issues`)" -ForegroundColor Green
    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host ''

    if ($allTargetProcesses.Count -eq 0) {
        # Installation artifacts look correct but no processes were running to confirm agent is loading
        Write-Host '  Agent installation and configuration look correct -- no issues found.' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  IMPORTANT: ' -ForegroundColor Yellow -NoNewline
        Write-Host 'No w3wp.exe or dotnet.exe processes were running during this scan.' -ForegroundColor Gray
        Write-Host '  We verified registry, config files, GAC, and file paths, but could not confirm' -ForegroundColor Gray
        Write-Host '  that the agent DLLs are actually loading into a live process.' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  Next step:' -ForegroundColor Cyan
        Write-Host '    1. Browse to your application in a web browser to trigger IIS worker startup' -ForegroundColor Gray
        Write-Host '    2. Wait a few seconds for the process to initialize' -ForegroundColor Gray
        Write-Host '    3. Re-run this script to inspect loaded modules and confirm agent attachment' -ForegroundColor Gray
        Write-Host ''
    }
    else {
        Write-Host '  The Application Insights Agent appears to be properly installed and configured.' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  If telemetry is still missing, the issue may be:' -ForegroundColor Gray
        Write-Host '    - Network connectivity (run Test-AppInsightsTelemetryFlow.ps1 to check)' -ForegroundColor Gray
        Write-Host '    - Connection string configuration in the agent config files' -ForegroundColor Gray
        Write-Host '    - Backend issues (daily cap, deleted workspace, ingestion sampling)' -ForegroundColor Gray
        Write-Host ''
    }
}
elseif ($hasUncoveredIssues) {
    # ---- Safety net: WARN/FAIL results exist but no Add-Diagnosis was called ----
    $issueLabel = @()
    if ($failures -gt 0) { $issueLabel += "$failures FAIL" }
    if ($warnings -gt 0) { $issueLabel += "$warnings WARN" }
    $issueSummary = $issueLabel -join ', '
    $headerColor = if ($failures -gt 0) { 'Red' } else { 'Yellow' }

    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host '  DIAGNOSIS: ' -ForegroundColor $headerColor -NoNewline
    Write-Host "$issueSummary detected `($($totalChecks) checks`)" -ForegroundColor $headerColor
    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host ''
    Write-Host '  Review the check results above for details on the warnings/failures.' -ForegroundColor Gray
    Write-Host ''
}
else {
    # ---- Issues found: Two-tier display ----

    # === TIER 1: DIAGNOSIS SUMMARY TABLE (verbose only) ===
    if ($VerboseOutput) {
        $findingsLabel = if ($totalIssues -eq 1) { '1 finding' } else { "$totalIssues findings" }
        $headerColor = if ($blockingItems.Count -gt 0) { 'Red' }
                       elseif ($warningItems.Count -gt 0) { 'DarkYellow' }
                       else { 'Yellow' }
        Write-Host '  ================================================================' -ForegroundColor White
        Write-Host '  DIAGNOSIS SUMMARY' -ForegroundColor $headerColor -NoNewline
        Write-Host ("$findingsLabel".PadLeft(64 - '  DIAGNOSIS SUMMARY'.Length)) -ForegroundColor DarkGray
        Write-Host '  ================================================================' -ForegroundColor White
        Write-Host ''

        $itemNum = 0
        foreach ($item in $orderedItems) {
            $itemNum++
            $numStr = "#$itemNum".PadRight(4)
            $sevLabel = $item.Severity.PadRight(10)

            switch ($item.Severity) {
                'BLOCKING' {
                    Write-Host '  ' -NoNewline
                    Write-Host $sevLabel -ForegroundColor Red -NoNewline
                    Write-Host "$numStr" -ForegroundColor Red -NoNewline
                    Write-Host $item.Summary -ForegroundColor White
                }
                'WARNING' {
                    Write-Host '  ' -NoNewline
                    Write-Host $sevLabel -ForegroundColor DarkYellow -NoNewline
                    Write-Host "$numStr" -ForegroundColor DarkYellow -NoNewline
                    Write-Host $item.Summary -ForegroundColor Gray
                }
                'INFO' {
                    Write-Host '  ' -NoNewline
                    Write-Host $sevLabel -ForegroundColor Yellow -NoNewline
                    Write-Host "$numStr" -ForegroundColor Yellow -NoNewline
                    Write-Host $item.Summary -ForegroundColor Gray
                }
            }
        }
    }

    # === TIER 2: WHAT TO DO (in priority order) ===
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host '  WHAT TO DO (in priority order)' -ForegroundColor White
    Write-Host '  ================================================================' -ForegroundColor White
    Write-Host ''

    # Show context
    Write-Host '  Agent Mode:  ' -ForegroundColor DarkGray -NoNewline
    Write-Host $bannerMode -ForegroundColor White
    Write-Host ''

    $itemNum = 0
    foreach ($item in $orderedItems) {
        $itemNum++

        # Header:  #1 [BLOCKING] Title
        $sevColor = switch ($item.Severity) {
            'BLOCKING' { 'Red' }
            'WARNING'  { 'DarkYellow' }
            'INFO'     { 'Yellow' }
        }
        Write-Host "  #$itemNum " -ForegroundColor White -NoNewline
        Write-Host "[$($item.Severity)]" -ForegroundColor $sevColor -NoNewline
        Write-Host " $($item.Title)" -ForegroundColor White

        # Description
        if ($item.Description) {
            Write-Host "     $($item.Description)" -ForegroundColor Gray
        }

        # Fix
        if ($item.Fix) {
            Write-Host '     ' -NoNewline
            Write-Host '->' -ForegroundColor Cyan -NoNewline
            Write-Host ' Fix: ' -ForegroundColor Cyan -NoNewline
            Write-Host $item.Fix -ForegroundColor Gray
        }

        # Portal navigation
        if ($item.Portal) {
            Write-Host '     ' -NoNewline
            Write-Host '->' -ForegroundColor Cyan -NoNewline
            Write-Host ' Portal: ' -ForegroundColor Cyan -NoNewline
            Write-Host $item.Portal -ForegroundColor Gray
        }

        # Docs link
        if ($item.Docs) {
            Write-Host '     ' -NoNewline
            Write-Host '->' -ForegroundColor Cyan -NoNewline
            Write-Host ' Docs: ' -ForegroundColor Cyan -NoNewline
            Write-Host $item.Docs -ForegroundColor DarkGray
        }

        Write-Host ''
    }
}

# --- Footer ---
Write-Host '  ================================================================' -ForegroundColor White
if ($Compact) {
    Write-Host '  Tip: Run without ' -ForegroundColor DarkGray -NoNewline
    Write-Host '-Compact' -ForegroundColor White -NoNewline
    Write-Host ' for verbose output with full explanations.' -ForegroundColor DarkGray
}
if (-not $IncludeInstrumentationEngine -and -not $ieDetected) {
    Write-Host '  Tip: Add ' -ForegroundColor DarkGray -NoNewline
    Write-Host '-IncludeInstrumentationEngine' -ForegroundColor White -NoNewline
    Write-Host ' to check CLR Profiler configuration.' -ForegroundColor DarkGray
}
Write-Host '  Companion: Run ' -ForegroundColor DarkGray -NoNewline
Write-Host 'Test-AppInsightsTelemetryFlow.ps1' -ForegroundColor White -NoNewline
Write-Host ' to diagnose network path and backend issues.' -ForegroundColor DarkGray
if ($script:extractedConnectionString) {
    $maskedCmdCS = Protect-ConnectionString $script:extractedConnectionString
    Write-Host "  Quick-run: " -ForegroundColor DarkGray -NoNewline
    Write-Host ".\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString '$maskedCmdCS'" -ForegroundColor Yellow
    Write-Host "             (replace masked ikey with actual value, or copy from Azure portal)" -ForegroundColor DarkGray
}
Write-Host '  Docs: https://learn.microsoft.com/azure/azure-monitor/app/application-insights-asp-net-agent' -ForegroundColor DarkGray
Write-Host '  Troubleshoot: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/agent/status-monitor-v2-troubleshoot' -ForegroundColor DarkGray
Write-Host '  Source: https://github.com/microsoft/appinsights-telemetry-flow' -ForegroundColor DarkGray
Write-Host '  ================================================================' -ForegroundColor White
Write-Host ''

# ============================================================================
# SAVE REPORT
# ============================================================================

$utcTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmmss") + "Z"
$hostName = $env:COMPUTERNAME -replace '[\\/:*?"<>|\s\(\)]', '_'
$autoName = "AppInsights-AgentDiag_${hostName}_${utcTimestamp}"

# Determine output directory
$reportDir = $null
if ($OutputPath) {
    # SDL: Block UNC paths -- reports may contain partial iKeys and internal hostnames
    if ($OutputPath -match '^\\\\') {
        Write-Host '  [ERROR] -OutputPath cannot be a UNC path (network share).' -ForegroundColor Red
        Write-Host '  Specify a local filesystem path instead.' -ForegroundColor Yellow
        $OutputPath = $null
    }
    else {
        # SDL: Resolve to absolute path and neutralise path traversal
        $resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
        if ($resolvedOutput -ne $OutputPath -and $OutputPath -match '\.\.') {
            Write-Host "  [WARN] -OutputPath contained path traversal ('..'), resolved to: $resolvedOutput" -ForegroundColor Yellow
        }
        $OutputPath = $resolvedOutput
    }

    if ($OutputPath) {
        $isDirectory = (Test-Path -Path $OutputPath -PathType Container)
        $looksLikeDir = (-not $OutputPath.EndsWith('.json')) -and (-not $OutputPath.EndsWith('.txt'))

        if ($isDirectory -or $looksLikeDir) {
            if (-not (Test-Path $OutputPath)) {
                try {
                    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                } catch {
                    Write-Host "  [!] Cannot create directory: $OutputPath -- falling back to script directory" -ForegroundColor Yellow
                    $OutputPath = $null
                }
            }
            if ($OutputPath) { $reportDir = $OutputPath }
        }
    }
}

if (-not $reportDir) {
    $reportDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

$jsonPath = Join-Path $reportDir "$autoName.json"
$txtPath = Join-Path $reportDir "$autoName.txt"

# Build report object
$report = @{
    ToolVersion = $ScriptVersion
    Timestamp = Get-Timestamp
    Environment = @{
        ComputerName = $env:COMPUTERNAME
        UserName = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin = $isAdmin
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
    }
    AgentInfo = @{
        DetectedMode = $detectedMode
        ModuleVersion = if ($bannerModuleVersion) { $bannerModuleVersion } else { $null }
        IisSiteCount = $bannerIisSiteCount
        IncludeInstrumentationEngine = $IncludeInstrumentationEngine.IsPresent
        InstrumentationEngineAutoDetected = $ieDetected
    }
    Summary = @{
        TotalChecks = $totalChecks
        Pass = $passes
        Warn = $warnings
        Fail = $failures
        Info = $infos
    }
    Diagnosis = @($orderedItems | ForEach-Object {
        @{
            Severity = $_.Severity
            Title = $_.Title
            Summary = $_.Summary
            Description = $_.Description
            Fix = $_.Fix
            Portal = $_.Portal
            Docs = $_.Docs
        }
    })
    CheckResults = @($allResults | ForEach-Object {
        @{
            Check = $_.Check
            Status = $_.Status
            Message = $_.Message
            Detail = $_.Detail
        }
    })
}

# Save JSON
try {
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  Report (JSON): $jsonPath" -ForegroundColor DarkGray
}
catch {
    Write-Host "  [!] Could not save JSON report: $_" -ForegroundColor Yellow
}

# Save TXT summary
try {
    $txt = @()
    $txt += "Application Insights Agent -- Status Diagnostic Report"
    $txt += "Generated: $(Get-Timestamp)  |  Script: v$ScriptVersion"
    $txt += "Machine: $env:COMPUTERNAME  |  User: $env:USERDOMAIN\$env:USERNAME `(Admin: $isAdmin`)"
    $txt += "Agent Mode: $detectedMode"
    $txt += ""
    $txt += "SUMMARY: $($totalChecks) checks | $passes PASS | $warnings WARN | $failures FAIL | $infos INFO"
    $txt += ""

    if ($orderedItems.Count -gt 0) {
        $txt += "DIAGNOSIS (priority order):"
        $txt += ("-" * 60)
        $diagNum = 0
        foreach ($item in $orderedItems) {
            $diagNum++
            $txt += "#$diagNum [$($item.Severity)] $($item.Title)"
            if ($item.Description) { $txt += "   $($item.Description)" }
            if ($item.Fix) { $txt += "   -> Fix: $($item.Fix)" }
            if ($item.Portal) { $txt += "   -> Portal: $($item.Portal)" }
            if ($item.Docs) { $txt += "   -> Docs: $($item.Docs)" }
            $txt += ""
        }
    } elseif ($hasUncoveredIssues) {
        $txt += "Issues detected ($warnings WARN, $failures FAIL) -- review detailed results below."
    } else {
        $txt += "No issues found. Agent appears properly installed."
    }

    $txt += ""
    $txt += "DETAILED CHECK RESULTS:"
    $txt += ("-" * 60)
    foreach ($r in $allResults) {
        $txt += "[$($r.Status)] $($r.Check) -- $($r.Message)"
        if ($r.Detail) { $txt += "       $($r.Detail)" }
    }

    $txt -join "`n" | Out-File -FilePath $txtPath -Encoding UTF8
    Write-Host "  Report (TXT):  $txtPath" -ForegroundColor DarkGray
}
catch {
    Write-Host "  [!] Could not save TXT report: $_" -ForegroundColor Yellow
}

Write-Host ''

# ============================================================================
# EXIT CODE
# ============================================================================

if ($blockingItems.Count -gt 0) {
    exit 1
}
elseif ($warningItems.Count -gt 0) {
    exit 2
}
else {
    exit 0
}
