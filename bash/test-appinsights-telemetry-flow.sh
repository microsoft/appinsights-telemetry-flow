#!/usr/bin/env bash
# ============================================================================
# test-appinsights-telemetry-flow.sh
# Application Insights Telemetry Flow Diagnostics (Bash/Linux)
# ============================================================================
# Version: 1.0.0
# Author:  Todd Foust (Microsoft)
# Source:  https://github.com/microsoft/appinsights-telemetry-flow
#
# Requires: Bash 5.0+, curl, openssl
# Optional: dig (fallback: nslookup), az CLI, jq, bc
#
# DISCLAIMER:
# This script is provided as a sample for diagnostic and troubleshooting
# purposes. It is not an official Microsoft product and is not supported
# under any Microsoft standard support program or service.
#
# This script is provided AS IS without warranty of any kind. Microsoft
# further disclaims all implied warranties including, without limitation,
# any implied warranties of merchantability or of fitness for a particular
# purpose. The entire risk arising out of the use or performance of this
# script and its documentation remains with you.
#
# In no event shall Microsoft, its authors, or anyone else involved in the
# creation, production, or delivery of this script be liable for any damages
# whatsoever (including, without limitation, damages for loss of business
# profits, business interruption, loss of business information, or other
# pecuniary loss) arising out of the use of or inability to use this script
# or its documentation, even if Microsoft has been advised of the possibility
# of such damages.
#
# EXIT CODES:
#   0 = No issues found (all checks passed, no diagnosis findings)
#   1 = INFO findings only (informational items, no action required)
#   2 = WARNING detected (telemetry at risk but may still work)
#   3 = BLOCKING issue detected (telemetry is broken)
# ============================================================================

set -o pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

# --- Parameter defaults ---
CONNECTION_STRING=""
SKIP_INGESTION_TEST=false
NETWORK_ONLY=false
COMPACT=false
TENANT_ID=""
OUTPUT_PATH=""
AUTO_APPROVE=false
LOOKUP_AMPLS_IP=""

# AMPLS manual IP comparison (associative array: fqdn -> expected_ip)
declare -A AMPLS_EXPECTED_IPS

# Resolved IP registry: every IP resolved during execution (DNS + AMPLS PE validation)
# Used to validate --lookup-ampls-ip: the supplied IP must appear in this list.
RESOLVED_IP_REGISTRY=()

# --- Debug output truncation ---
# Maximum characters shown for request/response bodies in debug output.
# Set to 0 to disable truncation (dump full bodies).
DEBUG_TRUNCATE_LENGTH=500

# --- Runtime flags ---
VERBOSE_OUTPUT=true
DEBUG_MODE=false
CHECK_AZURE=false
AZ_LOGGED_IN=false
AZ_CLI_FOUND=false
PIPELINE_BROKEN=false
INGESTION_BLOCKED_PREFLIGHT=false
INGESTION_TCP_BLOCKED=false
DIAG_SETTINGS_LA_COUNT=0  # Count of Diagnostic Settings exporting logs to LA (set by Known Issue #6)

# --- Tool availability ---
HAS_DIG=false
HAS_JQ=false
HAS_BC=false
HAS_OPENSSL=false
HAS_CURL=false
HAS_NSLOOKUP=false

# --- Timing strategy ---
# Bash 5.0+ provides $EPOCHREALTIME for sub-millisecond timestamps without forking.
# On older bash (4.4/RHEL 8) we fall back to date +%s%3N which forks per call.
HAS_EPOCHREALTIME=false
if [[ -n "${EPOCHREALTIME:-}" ]]; then
    HAS_EPOCHREALTIME=true
fi

# --- Step counter ---
STEP_NUMBER=0
DNS_STEP_NUMBER=0

# ============================================================================
# Usage / Help
# ============================================================================

show_help() {
    cat <<'HELPEOF'
Application Insights Telemetry Flow Diagnostics (Bash/Linux)
Version 1.0.0

SYNOPSIS
    test-appinsights-telemetry-flow.sh [OPTIONS]

QUICK START
    # From the machine where telemetry isn't flowing:
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=...;IngestionEndpoint=...;..."

    # Or if APPLICATIONINSIGHTS_CONNECTION_STRING is already set (e.g., App Service):
    ./test-appinsights-telemetry-flow.sh

DESCRIPTION
    Comprehensive diagnostic tool for Azure Monitor Application Insights.
    Tests network connectivity (DNS, TCP, TLS), validates AMPLS/Private Link
    configurations, checks for known issues that cause silent data loss, and
    sends a test telemetry record to confirm end-to-end pipeline health.

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
    If the Azure CLI (az) is installed and you have an active login, the
    script automatically performs AMPLS validation, known issue checks, and
    E2E data plane verification. No extra flags needed.
    Use --network-only to skip all Azure calls (pure network checks only).

    OUTPUT MODES:
    - Default:  Full verbose output with educational explanations
    - Compact:  Progress lines only with focused diagnosis at the end

    WHAT TO EXPECT:
    The script runs non-interactively in ~10-30 seconds for network checks.
    With Azure checks enabled, total time is ~30-90 seconds (includes ~60s
    of polling for E2E verification). Results display as they complete.
    Two report files (JSON + TXT) are saved automatically to --output-path.

    CONSENT PROMPTS:
    Before querying Azure resources or sending test telemetry, the script
    prompts for interactive Y/N consent. Use --auto-approve to bypass prompts
    in CI/CD, cron jobs, or other non-interactive environments.
    Use --network-only or --skip-ingestion-test to skip gated operations entirely.

    Designed to run from: Azure App Service (Linux), Function Apps,
    Container Apps, AKS pods, Azure VMs, on-premises Linux servers,
    Cloud Shell, and WSL.

PREREQUISITES
    Required:
      curl            HTTP requests (ingestion test, data plane query)
      openssl         TLS handshake validation
      dig or nslookup DNS resolution
      nc or ncat      TCP connectivity testing

    Optional (for Azure resource checks):
      az (Azure CLI)  AMPLS validation, known issues, E2E verification
      jq              Richer JSON parsing (falls back to grep/sed without it)

    All required tools are pre-installed on Azure App Service, Cloud Shell,
    and most Linux distributions. The script detects available tools at
    startup and gracefully skips checks when tools are missing.

OPTIONS
    --connection-string <CS>    Application Insights connection string.
                                If omitted, reads from environment variables:
                                  APPLICATIONINSIGHTS_CONNECTION_STRING
                                  APPINSIGHTS_INSTRUMENTATIONKEY
                                  ApplicationInsights__ConnectionString

    --skip-ingestion-test       Skip the sample telemetry send test.

    --network-only              Skip all Azure-authenticated checks. Run only
                                pure network tests (DNS, TCP, TLS, ingestion).

    --compact                   Show compact progress lines instead of full
                                verbose output with educational explanations.

    --tenant-id <GUID>          Entra ID tenant for multi-tenant auth.

    --output-path <DIR>         Directory for report files. Defaults to
                                current directory. Files are auto-named:
                                AppInsights-Diag_{HOST}_{RESOURCE}_{TIMESTAMP}.json + .txt
                                When the App Insights resource name is not
                                available the {RESOURCE} segment is omitted.

    --ampls-expected-ips <MAP>  Comma-separated FQDN=IP pairs for manual AMPLS
                                validation without Azure login. Copy these from
                                Azure Portal > AMPLS > Private Endpoint > DNS.
                                Format: "fqdn1=ip1,fqdn2=ip2"

    --lookup-ampls-ip <IP>       A private IPv4 address to reverse-lookup through
                                Azure Resource Graph to find the AMPLS resource
                                and private endpoint that owns it. Use when DNS
                                resolves an Azure Monitor endpoint to an unexpected
                                private IP. The IP must be a valid private IPv4
                                address that was resolved during this script run.
                                Requires Azure login (incompatible with --network-only).

    --auto-approve               Bypass interactive consent prompts for operations
                                that query Azure resources or send test telemetry.
                                Without this flag, the script prompts for Y/N
                                confirmation before Azure login/queries and
                                before sending a test telemetry record. Use in
                                non-interactive or automated environments (CI/CD,
                                containers) where no operator is available.
                                Equivalent to answering "Y" to every consent prompt.

    --debug                     Show all outbound HTTP requests and responses.
                                Logs every API call the script makes (URL, method,
                                request body, response status, response body) so
                                you can see exactly what data is sent and received.

    --help                      Show this help text and exit.

AZURE API CALLS (read-only)
    When Azure CLI is available and logged in, the script makes these calls:

    With authentication (az login required):
      POST management.azure.com  ARG query to find App Insights resource
      POST management.azure.com  ARG query to find AMPLS/private link scopes
      POST management.azure.com  ARG query to find workspace transform DCRs
      GET  management.azure.com  ARM: Read AMPLS scoped resources, access modes
      GET  management.azure.com  ARM: Read private endpoint DNS configurations
      GET  management.azure.com  ARM: Read daily cap (PricingPlans API)
      GET  management.azure.com  ARM: Read diagnostic settings
      POST api.applicationinsights.io  Data plane: KQL query for E2E verify

    Without authentication (always runs):
      DNS  Resolve each endpoint hostname via dig/nslookup
      TCP  Connect to port 443 via nc/ncat
      TLS  Handshake validation via openssl s_client
      POST {ingestion-endpoint}/v2.1/track  Send one test availability record

    Use --debug to see every request/response in real time.

EXIT CODES
    0  No issues found (all checks passed, no diagnosis findings)
    1  INFO findings only (informational items, no action required)
    2  WARNING detected (telemetry at risk but may still work)
    3  BLOCKING issue detected (telemetry is broken)

EXAMPLES
    # Full diagnostic (verbose output, Azure checks auto-detected)
    ./test-appinsights-telemetry-flow.sh \
      --connection-string "InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..."

    # Compact output for quick checks
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --compact

    # Network checks only (no Azure login required)
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --network-only

    # Multi-tenant: target a specific Entra ID tenant
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." \
      --tenant-id "contoso.onmicrosoft.com"

    # Auto-detect connection string from environment variables (App Service)
    ./test-appinsights-telemetry-flow.sh

    # Manual AMPLS IP comparison (no Azure login needed)
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." \
      --ampls-expected-ips "{region}.in.applicationinsights.azure.com=10.0.1.5,{region}.livediagnostics.monitor.azure.com=10.0.1.6"

    # Show all HTTP traffic for security review
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --debug

    # Save reports to a specific directory
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." \
      --output-path /tmp/diag

    # Non-interactive / CI: bypass consent prompts
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." --auto-approve

    # Reverse-lookup a private IP to find the AMPLS resource that owns it
    ./test-appinsights-telemetry-flow.sh --connection-string "InstrumentationKey=xxx;..." \
      --lookup-ampls-ip "10.0.1.5"

INPUTS
    None. This script does not read from stdin (except for interactive Y/N consent prompts).

OUTPUTS
    Exit code: 0 (clean), 1 (INFO), 2 (WARNING), or 3 (BLOCKING).

    The script writes two report files to --output-path (default: current directory):
      AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{yyyy-MM-ddTHHmmssZ}.json
      AppInsights-Diag_{HOSTNAME}_{RESOURCE}_{yyyy-MM-ddTHHmmssZ}.txt
          When the App Insights resource name is discovered via Azure checks it is
          included in the filename; otherwise the {RESOURCE} segment is omitted.
          JSON is machine-parseable with all check results; TXT is a human-readable
          console output mirror.

NOTES
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

    Author:  Todd Foust - Azure Monitor App Insights Supportability Engineer
    Source:  https://github.com/microsoft/appinsights-telemetry-flow
    Docs:    https://github.com/microsoft/appinsights-telemetry-flow

HELPEOF
    exit 0
}

# ============================================================================
# Parameter Parsing
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --connection-string)
                [[ -z "${2:-}" ]] && { echo "Error: --connection-string requires a value" >&2; exit 1; }
                if (( ${#2} > 1024 )); then
                    echo "Error: --connection-string exceeds maximum length (1024 chars)" >&2; exit 1
                fi
                CONNECTION_STRING="$2"; shift 2 ;;
            --skip-ingestion-test)
                SKIP_INGESTION_TEST=true; shift ;;
            --network-only)
                NETWORK_ONLY=true; shift ;;
            --compact)
                COMPACT=true; shift ;;
            --tenant-id)
                [[ -z "${2:-}" ]] && { echo "Error: --tenant-id requires a value" >&2; exit 1; }
                local tenant_guid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                local tenant_domain_re='^[a-zA-Z0-9][a-zA-Z0-9.-]+\.onmicrosoft\.com$'
                if [[ ! "$2" =~ $tenant_guid_re ]] && [[ ! "$2" =~ $tenant_domain_re ]]; then
                    echo "Error: --tenant-id must be a GUID or a *.onmicrosoft.com domain" >&2; exit 1
                fi
                TENANT_ID="$2"; shift 2 ;;
            --output-path)
                [[ -z "${2:-}" ]] && { echo "Error: --output-path requires a value" >&2; exit 1; }
                # SDL: Block path traversal sequences
                if [[ "$2" == *..* ]]; then
                    echo "Error: --output-path must not contain '..' path traversal sequences" >&2; exit 1
                fi
                # Resolve to absolute path to prevent symlink escapes
                if command -v realpath &>/dev/null; then
                    OUTPUT_PATH="$(realpath -m -- "$2" 2>/dev/null || echo "$2")"
                else
                    OUTPUT_PATH="$2"
                fi
                shift 2 ;;
            --ampls-expected-ips)
                [[ -z "${2:-}" ]] && { echo "Error: --ampls-expected-ips requires a value" >&2; exit 1; }
                # Parse comma-separated "fqdn=ip" pairs into associative array
                local IFS=','
                local -a pairs
                read -ra pairs <<< "$2"
                for pair in "${pairs[@]}"; do
                    pair="${pair#"${pair%%[![:space:]]*}"}"
                    pair="${pair%"${pair##*[![:space:]]}"}"
                    if [[ "$pair" =~ ^([^=]+)=([^=]+)$ ]]; then
                        local fqdn="${BASH_REMATCH[1]}"
                        local ip="${BASH_REMATCH[2]}"
                        fqdn="${fqdn#"${fqdn%%[![:space:]]*}"}"
                        fqdn="${fqdn%"${fqdn##*[![:space:]]}"}"
                        ip="${ip#"${ip%%[![:space:]]*}"}"
                        ip="${ip%"${ip##*[![:space:]]}"}"
                        AMPLS_EXPECTED_IPS["$fqdn"]="$ip"
                    else
                        echo "Error: Invalid --ampls-expected-ips pair: '$pair'" >&2
                        echo "Expected format: \"fqdn1=10.0.1.5,fqdn2=10.0.1.6\"" >&2
                        exit 1
                    fi
                done
                shift 2 ;;
            --help|-h)
                show_help ;;
            --lookup-ampls-ip)
                [[ -z "${2:-}" ]] && { echo "Error: --lookup-ampls-ip requires a value" >&2; exit 1; }
                LOOKUP_AMPLS_IP="$2"; shift 2 ;;
            --auto-approve)
                AUTO_APPROVE=true; shift ;;
            --debug)
                DEBUG_MODE=true; shift ;;
            *)
                echo "Unknown option: $1" >&2
                echo "Run with --help for usage information." >&2
                exit 1 ;;
        esac
    done

    # Compact mode disables verbose output
    if $COMPACT; then
        VERBOSE_OUTPUT=false
    fi

    # Validate --lookup-ampls-ip / --network-only mutual exclusion
    if [[ -n "$LOOKUP_AMPLS_IP" ]] && $NETWORK_ONLY; then
        echo "Error: --lookup-ampls-ip requires Azure resource access and cannot be used with --network-only." >&2
        echo "Remove --network-only to enable AMPLS reverse-lookup, or omit --lookup-ampls-ip for network-only checks." >&2
        exit 1
    fi
}

# ============================================================================
# Bash Version Check
# ============================================================================

check_bash_version() {
    local major="${BASH_VERSINFO[0]:-0}"
    local minor="${BASH_VERSINFO[1]:-0}"

    if (( major < 4 || (major == 4 && minor < 4) )); then
        echo "ERROR: This script requires bash 4.4+ (5.0+ recommended)." >&2
        echo "Current version: $BASH_VERSION" >&2
        echo "Upgrade bash or run from a system with bash 5.0+." >&2
        exit 1
    fi

    if (( major == 4 )); then
        # Bash 4.4 works but lacks $EPOCHREALTIME for precise timing
        echo "[!] WARN: bash $BASH_VERSION detected. Bash 5.0+ recommended for precision timing." >&2
        echo "    Timing measurements will use date fallback (slightly less precise)." >&2
        echo "" >&2
    fi
}


# ============================================================================
# CONSOLE COLOR DETECTION & OUTPUT HELPERS
# ============================================================================

# --- Console output capture ---
# All output is appended to this buffer for the .txt report, matching the PS1's
# StringBuilder approach. We don't use tee/process substitution so we can handle
# partial-line writes (-NoNewline equivalent) correctly.
CONSOLE_LOG=""

# --- Color detection ---
USE_COLOR=true

detect_color_support() {
    # Not a terminal (piped or redirected)
    if [[ ! -t 1 ]]; then
        USE_COLOR=false
        return
    fi
    # Dumb terminal or empty TERM
    case "${TERM:-dumb}" in
        dumb|"") USE_COLOR=false; return ;;
    esac
    # Try tput -- if it can't report colors, disable
    if command -v tput &>/dev/null; then
        local colors
        colors="$(tput colors 2>/dev/null || echo 0)"
        if (( colors < 8 )); then
            USE_COLOR=false
        fi
    fi
}

# --- ANSI escape constants ---
setup_colors() {
    if $USE_COLOR; then
        C_RED='\033[0;91m'
        C_DARK_RED='\033[0;31m'
        C_GREEN='\033[0;32m'
        C_YELLOW='\033[0;93m'
        C_DARK_YELLOW='\033[0;33m'   
        C_CYAN='\033[0;96m'
        C_DARK_CYAN='\033[0;36m'
        C_WHITE='\033[1;37m'
        C_GRAY='\033[0;37m'
        C_DARK_GRAY='\033[0;90m'
        C_RESET='\033[0m'
    else
        C_RED='' C_GREEN='' C_YELLOW='' C_CYAN='' C_WHITE=''
        C_GRAY='' C_DARK_GRAY='' C_DARK_YELLOW='' C_RESET=''
        C_DARK_CYAN='' C_DARK_YELLOW='' C_DARK_RED=''
    fi
}

# ============================================================================
# Core Output Functions
# ============================================================================
#
# These mirror the PS1's Write-Host override, Write-Result, Write-Header,
# Write-ProgressLine, and Write-DetailHost. Every function that writes to
# the console also appends to CONSOLE_LOG for the .txt report.

# _print [-n] [-c COLOR] "text"
#   -n  : no newline (like Write-Host -NoNewline)
#   -c  : color escape (ignored when USE_COLOR is false)
_print() {
    local no_newline=false
    local color=""
    local text=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n) no_newline=true; shift ;;
            -c) color="$2"; shift 2 ;;
            *)  text="$1"; shift ;;
        esac
    done

    if $no_newline; then
        printf '%b%s%b' "$color" "$text" "$C_RESET"
    else
        printf '%b%s%b\n' "$color" "$text" "$C_RESET"
    fi

    # Capture for .txt report (plain text, no ANSI)
    if $no_newline; then
        CONSOLE_LOG+="$text"
    else
        CONSOLE_LOG+="${text}"$'\n'
    fi
}

# write_result STATUS "Check text" ["Detail text"] ["Action text"]
# Prints [+]/[X]/[!]/[i]/[-] prefixed lines. Verbose mode only.
write_result() {
    $VERBOSE_OUTPUT || return 0

    local status="$1"
    local check="$2"
    local detail="${3:-}"
    local action="${4:-}"

    local color symbol
    case "$status" in
        PASS) color="$C_GREEN";       symbol="+" ;;
        FAIL) color="$C_RED";         symbol="X" ;;
        WARN) color="$C_DARK_YELLOW"; symbol="!" ;;
        INFO) color="$C_GRAY";        symbol="i" ;;
        SKIP) color="$C_DARK_GRAY";   symbol="-" ;;
        *)    color="$C_WHITE";       symbol="?" ;;
    esac

    _print -n -c "$color" "  [$symbol] "
    _print -c "$C_WHITE" "$check"

    [[ -n "$detail" ]] && _print -c "$C_GRAY" "      $detail"
    if [[ -n "$action" ]] && [[ "$status" =~ ^(FAIL|WARN|INFO)$ ]]; then
        _print -c "$C_YELLOW" "      ACTION: $action"
    fi
}

# _get_console_width
#   Returns usable console width for word-wrapping, capped at 120 to keep
#   diagnostic text readable even on ultra-wide consoles. Falls back to 119.
_get_console_width() {
    local w
    w="$(tput cols 2>/dev/null)" || w=120
    (( w <= 0 )) && w=120
    (( w > 120 )) && w=120
    echo $(( w - 1 ))
}

# _write_wrapped TEXT INDENT_WIDTH COLOR
#   Word-wraps TEXT to console width with INDENT_WIDTH spaces on every line.
_write_wrapped() {
    local text="$1" indent_width="${2:-5}" color="${3:-$C_GRAY}"
    local indent
    indent="$(printf '%*s' "$indent_width" '')"
    local max_width
    max_width="$(_get_console_width)"
    local available=$(( max_width - indent_width ))
    if (( available < 30 )); then
        _print -c "$color" "${indent}${text}"
        return
    fi
    local line="" word
    for word in $text; do
        if [[ -z "$line" ]]; then
            line="$word"
        elif (( ${#line} + 1 + ${#word} <= available )); then
            line+=" $word"
        else
            _print -c "$color" "${indent}${line}"
            line="$word"
        fi
    done
    [[ -n "$line" ]] && _print -c "$color" "${indent}${line}"
}

# _write_wrapped_prefixed PREFIX CONT_INDENT_WIDTH TEXT COLOR
#   First chunk of TEXT goes on same line as PREFIX (already printed with -n).
#   Continuation lines get CONT_INDENT_WIDTH spaces.
_write_wrapped_prefixed() {
    local cont_width="$1" text="$2" color="${3:-$C_GRAY}"
    local cont_indent
    cont_indent="$(printf '%*s' "$cont_width" '')"
    local max_width
    max_width="$(_get_console_width)"
    local available=$(( max_width - cont_width ))
    if (( available < 30 )); then
        _print -c "$color" "$text"
        return
    fi
    local line="" word is_first=true
    for word in $text; do
        if [[ -z "$line" ]]; then
            line="$word"
        elif (( ${#line} + 1 + ${#word} <= available )); then
            line+=" $word"
        else
            if $is_first; then
                _print -c "$color" "$line"
                is_first=false
            else
                _print -c "$color" "${cont_indent}${line}"
            fi
            line="$word"
        fi
    done
    if [[ -n "$line" ]]; then
        if $is_first; then
            _print -c "$color" "$line"
        else
            _print -c "$color" "${cont_indent}${line}"
        fi
    fi
}

# write_header "Title" -- verbose only
write_header() {
    $VERBOSE_OUTPUT || return 0
    local line
    line="$(printf '=%.0s' {1..72})"
    _print ""
    _print -c "$C_CYAN" " $line"
    _print -c "$C_CYAN" " $1"
    _print -c "$C_CYAN" " $line"
}

# write_header_always "Title" -- prints in both verbose and compact mode
write_header_always() {
    local line
    line="$(printf '=%.0s' {1..72})"
    _print ""
    _print -c "$C_CYAN" " $line"
    _print -c "$C_CYAN" " $1"
    _print -c "$C_CYAN" " $line"
}


# --- Progress line split: start/complete mechanism ---
# In compact non-debug mode, write_progress_start prints the leading label+dots
# with no newline, giving visual feedback that a test is running. write_progress_line
# then completes the line with status and summary. In verbose/debug modes, the start
# is recorded but not printed (enough output already streams to indicate progress).
PROGRESS_START_PENDING=""

# write_progress_start "Check Name"
# Prints "  Check Name .................. " with no newline in compact non-debug mode.
# If a previous start is still pending (test had nothing to report), the old partial
# line is silently overwritten before printing the new start.
write_progress_start() {
    local name="$1"

    # Only emit in compact mode without debug
    if $VERBOSE_OUTPUT || $DEBUG_MODE; then
        PROGRESS_START_PENDING="$name"
        return
    fi

    # If there's already a pending start on the line, clear it first
    if [[ -n "$PROGRESS_START_PENDING" ]]; then
        printf "\r%-80s\r" ""
    fi

    PROGRESS_START_PENDING="$name"

    local total_width=36
    local dot_count=$(( total_width - ${#name} ))
    (( dot_count < 3 )) && dot_count=3
    local leader=" $(printf '%*s' "$dot_count" '' | tr ' ' '.') "

    _print -n -c "$C_WHITE" "  $name"
    _print -n -c "$C_DARK_GRAY" "$leader"
}

# write_progress_line "Check Name" "STATUS" "summary text"
# Always prints. Produces the dot-leader format:
#   Check Name .................. STATUS  summary
# If write_progress_start was called earlier with the same name (compact non-debug),
# appends just the status and summary. If name differs, clears and reprints.
write_progress_line() {
    local name="$1"
    local status="$2"
    local summary="$3"

    local total_width=36
    local dot_count=$(( total_width - ${#name} ))
    (( dot_count < 3 )) && dot_count=3
    local leader=" $(printf '%*s' "$dot_count" '' | tr ' ' '.') "

    local status_color
    case "$status" in
        OK)   status_color="$C_GREEN" ;;
        WARN) status_color="$C_DARK_YELLOW" ;;
        INFO) status_color="$C_YELLOW" ;;
        FAIL) status_color="$C_RED" ;;
        SKIP) status_color="$C_DARK_GRAY" ;;
        *)    status_color="$C_WHITE" ;;
    esac

    local padded_status
    padded_status="$(printf '%-5s' "$status")"

    if [[ -n "$PROGRESS_START_PENDING" ]]; then
        if [[ "$PROGRESS_START_PENDING" == "$name" ]] && ! $VERBOSE_OUTPUT && ! $DEBUG_MODE; then
            # Same name, compact non-debug: just append status + summary
            _print -n -c "$status_color" "$padded_status"
            _print -c "$C_GRAY" "  $summary"
        elif ! $VERBOSE_OUTPUT && ! $DEBUG_MODE; then
            # Different name, compact non-debug: clear line then print new full line
            printf "\r%-80s\r" ""
            _print -n -c "$C_WHITE" "  $name"
            _print -n -c "$C_DARK_GRAY" "$leader"
            _print -n -c "$status_color" "$padded_status"
            _print -c "$C_GRAY" "  $summary"
        else
            # Verbose or debug: start wasn't printed, print full line
            _print -n -c "$C_WHITE" "  $name"
            _print -n -c "$C_DARK_GRAY" "$leader"
            _print -n -c "$status_color" "$padded_status"
            _print -c "$C_GRAY" "  $summary"
        fi
        PROGRESS_START_PENDING=""
    else
        # No pending start: print full line normally
        _print -n -c "$C_WHITE" "  $name"
        _print -n -c "$C_DARK_GRAY" "$leader"
        _print -n -c "$status_color" "$padded_status"
        _print -c "$C_GRAY" "  $summary"
    fi
}

# write_detail "text" -- verbose only, for educational/explanatory prose
write_detail() {
    $VERBOSE_OUTPUT || return 0
    _print -c "$C_GRAY" "$1"
}


# ============================================================================
# DIAGNOSIS ENGINE
# ============================================================================
#
# Accumulates issues found during checks, then renders a prioritized summary.
# Items stored as pipe-delimited strings: "SEVERITY|TITLE|SUMMARY|DESC|FIX|PORTAL|DOCS"

declare -a DIAGNOSIS_ITEMS=()

# add_diagnosis SEVERITY TITLE SUMMARY DESCRIPTION FIX PORTAL DOCS
add_diagnosis() {
    local severity="${1:-INFO}"
    local title="${2:-}"
    local summary="${3:-$title}"
    local description="${4:-}"
    local fix="${5:-}"
    local portal="${6:-}"
    local docs="${7:-}"
    DIAGNOSIS_ITEMS+=("${severity}|${title}|${summary}|${description}|${fix}|${portal}|${docs}")
}

# _diag_field "ITEM_STRING" FIELD_INDEX
_diag_field() {
    local item="$1"
    local idx="$2"
    local IFS='|'
    local -a fields
    read -ra fields <<< "$item"
    echo "${fields[$idx]:-}"
}

# render_diagnosis_summary
# Two-tier output matching the PS1:
#   Tier 1: DIAGNOSIS SUMMARY table (verbose only)
#   Tier 2: WHAT TO DO (always, priority-ordered)
render_diagnosis_summary() {
    # Sort: BLOCKING -> WARNING -> INFO
    local -a blocking_items=() warning_items=() info_items=()
    for item in "${DIAGNOSIS_ITEMS[@]}"; do
        case "$(_diag_field "$item" 0)" in
            BLOCKING) blocking_items+=("$item") ;;
            WARNING)  warning_items+=("$item") ;;
            INFO)     info_items+=("$item") ;;
        esac
    done

    local -a ordered_items=()
    ordered_items+=("${blocking_items[@]}")
    ordered_items+=("${warning_items[@]}")
    ordered_items+=("${info_items[@]}")

    local total_issues=${#ordered_items[@]}

    # Did the ingestion test actually run and pass?
    local ingestion_confirmed=false
    [[ "$INGEST_RESULT_STATUS" == "PASS" ]] && ingestion_confirmed=true

    _print ""

    if (( total_issues == 0 )); then
        # ---- No issues found ----

        if $CHECK_AZURE && ! $AZ_LOGGED_IN; then
            _print -c "$C_WHITE" " ========================================================================"
            _print -c "$C_DARK_YELLOW" " DIAGNOSIS SUMMARY"
            _print -c "$C_WHITE" " ========================================================================"
            _print ""
            if [[ -n "$AI_RESOURCE_NAME" ]]; then
                _print -n -c "$C_DARK_GRAY" "  App Insights:    "
                _print -c "$C_WHITE" "$AI_RESOURCE_NAME"
            fi
            if [[ -n "$WS_NAME" && "$WS_NAME" != "(unknown)" ]]; then
                _print -n -c "$C_DARK_GRAY" "  Log Analytics:   "
                _print -c "$C_WHITE" "$WS_NAME"
            fi
            if [[ -n "$AI_RESOURCE_NAME" || ( -n "$WS_NAME" && "$WS_NAME" != "(unknown)" ) ]]; then
                _print ""
            fi
            if $ingestion_confirmed; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS, ingestion)."
            elif $SKIP_INGESTION_TEST; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (--skip-ingestion-test)."
            elif $ingestion_consent_declined; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (consent not granted)."
            else
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
            fi
            _print -c "$C_GRAY" "  Resource configuration checks were not performed."
            if $ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP; then
                _print -c "$C_GRAY" "  To include resource checks, run this script from Azure Cloud Shell or a machine with az CLI."
            else
                _print -c "$C_GRAY" "  Install az CLI and run 'az login' to enable these checks."
            fi
        elif $CHECK_AZURE && $AZ_LOGGED_IN; then
            _print -c "$C_WHITE" " ======================================================================="
            _print -c "$C_GREEN" " DIAGNOSIS SUMMARY"
            _print -c "$C_WHITE" " ========================================================================"
            _print ""
            if [[ -n "$AI_RESOURCE_NAME" ]]; then
                _print -n -c "$C_DARK_GRAY" "  App Insights:    "
                _print -c "$C_WHITE" "$AI_RESOURCE_NAME"
            fi
            if [[ -n "$WS_NAME" && "$WS_NAME" != "(unknown)" ]]; then
                _print -n -c "$C_DARK_GRAY" "  Log Analytics:   "
                _print -c "$C_WHITE" "$WS_NAME"
            fi
            if [[ -n "$AI_RESOURCE_NAME" || ( -n "$WS_NAME" && "$WS_NAME" != "(unknown)" ) ]]; then
                _print ""
            fi
            if $ingestion_confirmed; then
                _print -c "$C_GRAY" "  All connectivity and resource configuration checks passed."
                _print -c "$C_GRAY" "  If telemetry from your application is still missing, the issue is likely"
                _print -c "$C_GRAY" "  in SDK/agent configuration, not network connectivity."
            elif $SKIP_INGESTION_TEST; then
                _print -c "$C_GRAY" "  Network connectivity and Azure resource configuration checks all passed."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (--skip-ingestion-test)."
            elif $ingestion_consent_declined; then
                _print -c "$C_GRAY" "  Network connectivity and Azure resource configuration checks all passed."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (consent not granted)."
            else
                _print -c "$C_GRAY" "  All connectivity and resource configuration checks passed."
                _print -c "$C_GRAY" "  If telemetry from your application is still missing, the issue is likely"
                _print -c "$C_GRAY" "  in SDK/agent configuration, not network connectivity."
            fi
        else
            _print -c "$C_WHITE" " ========================================================================"
            _print -c "$C_GREEN" " DIAGNOSIS SUMMARY"
            _print -c "$C_WHITE" " ========================================================================"
            _print ""
            if $ingestion_confirmed; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS, ingestion)."
            elif $SKIP_INGESTION_TEST; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (--skip-ingestion-test)."
            elif $ingestion_consent_declined; then
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
                _print -c "$C_GRAY" "  The telemetry ingestion test was not performed (consent not granted)."
            else
                _print -c "$C_GRAY" "  Network connectivity to Azure Monitor is healthy (DNS, TCP, TLS)."
            fi
            if $NETWORK_ONLY; then
                _print -c "$C_GRAY" "  Resource configuration checks were skipped (--network-only)."
            else
                _print -c "$C_GRAY" "  Resource configuration checks were not performed."
                if $ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP; then
                    _print -c "$C_GRAY" "  To include resource checks, run this script from Azure Cloud Shell or a machine with az CLI."
                else
                    _print -c "$C_GRAY" "  Install az CLI and run 'az login' to enable these checks."
                fi
            fi
        fi
        return
    fi

    # ---- Issues found ----

    # === TIER 1: DIAGNOSIS SUMMARY TABLE (verbose only) ===
    if $VERBOSE_OUTPUT; then
        local findings_label
        (( total_issues == 1 )) && findings_label="1 finding" || findings_label="$total_issues findings"

        # Header color: red if any BLOCKING, yellow otherwise
        local header_color="$C_DARK_YELLOW"
        if (( ${#blocking_items[@]} > 0 )); then
            header_color="$C_RED"
        fi

        _print -c "$C_WHITE" " ========================================================================"
        local title_text=" DIAGNOSIS SUMMARY"
        local pad_len=$(( 73 - ${#title_text} ))
        local padded_label
        padded_label="$(printf '%*s' "$pad_len" "$findings_label")"
        _print -n -c "$header_color" "$title_text"
        _print -c "$C_DARK_GRAY" "$padded_label"
        _print -c "$C_WHITE" " ========================================================================"
        _print ""

        local item_num=0
        for item in "${ordered_items[@]}"; do
            (( item_num++ ))
            local sev summary_text
            sev="$(_diag_field "$item" 0)"
            summary_text="$(_diag_field "$item" 2)"
            local num_str sev_label sev_color summary_color

            num_str="$(printf '#%-3d' "$item_num")"
            sev_label="$(printf '%-10s' "$sev")"

            case "$sev" in
                BLOCKING) sev_color="$C_RED" ;;
                WARNING)  sev_color="$C_DARK_YELLOW" ;;
                INFO)     sev_color="$C_YELLOW" ;;
                *)        sev_color="$C_WHITE" ;;
            esac
            summary_color="$C_GRAY"
            [[ "$sev" == "BLOCKING" ]] && summary_color="$C_WHITE"

            _print -n "  "
            _print -n -c "$sev_color" "$sev_label"
            _print -n -c "$sev_color" "$num_str"
            _print -c "$summary_color" "$summary_text"
        done
        _print ""
    fi

    # === TIER 2: WHAT TO DO (in priority order) -- always prints ===

    # Show detected resources (always -- in Compact mode the Diagnosis Summary is skipped,
    # so this is the only place the user sees which resources were evaluated).
    if [[ -n "$AI_RESOURCE_NAME" ]]; then
        _print -n -c "$C_DARK_GRAY" "  App Insights:    "
        _print -c "$C_WHITE" "$AI_RESOURCE_NAME"
    fi
    if [[ -n "$WS_NAME" && "$WS_NAME" != "(unknown)" ]]; then
        _print -n -c "$C_DARK_GRAY" "  Log Analytics:   "
        _print -c "$C_WHITE" "$WS_NAME"
    fi

    _print ""
    _print -c "$C_WHITE" "  ================================================================"
    _print -c "$C_WHITE" "  WHAT TO DO (in priority order)"
    _print -c "$C_WHITE" "  ================================================================"
    _print ""

    local item_num=0
    for item in "${ordered_items[@]}"; do
        (( item_num++ ))
        local sev title_text desc fix portal docs
        sev="$(_diag_field "$item" 0)"
        title_text="$(_diag_field "$item" 1)"
        desc="$(_diag_field "$item" 3)"
        fix="$(_diag_field "$item" 4)"
        portal="$(_diag_field "$item" 5)"
        docs="$(_diag_field "$item" 6)"

        local sev_color
        case "$sev" in
            BLOCKING) sev_color="$C_RED" ;;
            WARNING)  sev_color="$C_DARK_YELLOW" ;;
            INFO)     sev_color="$C_YELLOW" ;;
            *)        sev_color="$C_WHITE" ;;
        esac

        _print -n -c "$C_WHITE" "  #$item_num "
        _print -n -c "$sev_color" "[$sev]"
        _print -c "$C_WHITE" " $title_text"

        # Description (word-wrapped with 5-space indent)
        [[ -n "$desc" ]] && _write_wrapped "$desc" 5 "$C_GRAY"

        # Fix (word-wrapped; colored prefix then aligned continuation)
        if [[ -n "$fix" ]]; then
            _print -n "     "
            _print -n -c "$C_CYAN" "-> Fix: "
            _write_wrapped_prefixed 13 "$fix" "$C_GRAY"   # "     -> Fix: " = 13 chars
        fi
        # Portal (word-wrapped)
        if [[ -n "$portal" ]]; then
            _print -n "     "
            _print -n -c "$C_CYAN" "-> Portal: "
            _write_wrapped_prefixed 16 "$portal" "$C_GRAY"  # "     -> Portal: " = 16 chars
        fi
        # Docs (word-wrapped)
        if [[ -n "$docs" ]]; then
            _print -n "     "
            _print -n -c "$C_CYAN" "-> Docs: "
            _write_wrapped_prefixed 14 "$docs" "$C_DARK_GRAY"  # "     -> Docs: " = 14 chars
        fi
        _print ""
    done
}


# ============================================================================
# DEBUG HELPERS (--debug mode)
# ============================================================================
# When --debug is enabled, these functions log outbound HTTP requests and
# responses so customers can see exactly what API calls the script makes.
# All output goes to stderr to avoid interfering with captured command output.

# _debug MSG...
#   Prints a debug message when DEBUG_MODE is true.
_debug() {
    $DEBUG_MODE || return 0
    local msg="$*"
    echo -e "\033[93m  [DEBUG] $msg\033[0m" >&2
}

# _debug_request METHOD URL [BODY_PREVIEW]
#   Logs an outbound HTTP request in debug mode.
_debug_request() {
    $DEBUG_MODE || return 0
    local method="$1" url="$2" body="${3:-}"
    echo -e "\033[93m  [DEBUG] >>> $method $url\033[0m" >&2
    if [[ -n "$body" ]]; then
        local preview="$body"
        if (( DEBUG_TRUNCATE_LENGTH > 0 && ${#preview} > DEBUG_TRUNCATE_LENGTH )); then
            preview="${preview:0:$DEBUG_TRUNCATE_LENGTH}... (${#body} bytes total)"
        fi
        echo -e "\033[93m  [DEBUG] >>> Body: $preview\033[0m" >&2
    fi
}

# _debug_response STATUS [BODY_PREVIEW]
#   Logs an HTTP response in debug mode.
_debug_response() {
    $DEBUG_MODE || return 0
    local status="$1" body="${2:-}"
    echo -e "\033[93m  [DEBUG] <<< $status\033[0m" >&2
    if [[ -n "$body" ]]; then
        local preview="$body"
        if (( DEBUG_TRUNCATE_LENGTH > 0 && ${#preview} > DEBUG_TRUNCATE_LENGTH )); then
            preview="${preview:0:$DEBUG_TRUNCATE_LENGTH}... (${#body} bytes total)"
        fi
        echo -e "\033[93m  [DEBUG] <<< Body: $preview\033[0m" >&2
    fi
}

# _debug_az_graph QUERY [EXTRA_ARGS...]
#   Logs an Azure Resource Graph query in debug mode.
_debug_az_graph() {
    $DEBUG_MODE || return 0
    local query="$1"
    echo -e "\033[93m  [DEBUG] >>> POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01\033[0m" >&2
    echo -e "\033[93m  [DEBUG] >>> ARG Query: $query\033[0m" >&2
}

# _debug_az_rest METHOD URL
#   Logs an Azure REST API call in debug mode.
_debug_az_rest() {
    $DEBUG_MODE || return 0
    local method="$1" url="$2"
    echo -e "\033[93m  [DEBUG] >>> $method $url\033[0m" >&2
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# --- Timestamps ---

get_timestamp() {
    date -u "+%Y-%m-%dT%H:%M:%S.000Z"
}

# High-precision ms timestamp for latency measurement.
# Bash 5.0+: $EPOCHREALTIME (no fork). Older: date +%s%3N fallback.
get_ms_timestamp() {
    if $HAS_EPOCHREALTIME; then
        local epoch="$EPOCHREALTIME"
        local secs="${epoch%%.*}"
        local frac="${epoch#*.}"
        frac="${frac:0:3}"
        echo "$(( secs * 1000 + 10#$frac ))"
    else
        date +%s%3N
    fi
}

calc_elapsed_ms() {
    echo $(( $2 - $1 ))
}

# --- String masking ---

mask_ikey() {
    local key="$1"
    (( ${#key} < 13 )) && { echo "$key"; return; }
    echo "${key:0:8}...${key: -4}"
}

mask_email() {
    local email="$1"
    [[ -z "$email" ]] && { echo "<unknown>"; return; }
    if [[ "$email" != *@* ]]; then
        echo "${email:0:2}***"
        return
    fi
    local local_part="${email%%@*}"
    local domain="${email#*@}"
    local visible=${#local_part}
    (( visible > 2 )) && visible=2
    echo "${local_part:0:$visible}***@${domain}"
}

# --- SDL: Input validation helpers ---

# validate_ikey_format IKEY
#   Validates that the iKey is a well-formed GUID (8-4-4-4-12 hex).
#   Returns 0 if valid, 1 if not.
validate_ikey_format() {
    local ikey="$1"
    local guid_regex='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    [[ "$ikey" =~ $guid_regex ]]
}

# validate_azure_monitor_endpoint URL
#   SSRF allowlist: only permits HTTPS URLs whose hostname ends with a
#   known Azure Monitor domain. Blocks IPs, localhost, non-Azure hosts.
#   Returns 0 if safe, 1 if blocked.
validate_azure_monitor_endpoint() {
    local url="$1"

    # Must start with https://
    if [[ ! "$url" =~ ^https:// ]]; then
        echo "Blocked: endpoint must use HTTPS: $url" >&2
        return 1
    fi

    # Extract hostname from URL (strip scheme and path)
    local host
    host="${url#https://}"
    host="${host%%/*}"
    host="${host%%:*}"   # strip port if present
    host="$(echo "$host" | tr '[:upper:]' '[:lower:]')"

    # Block raw IP addresses (IPv4 and IPv6)
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$host" =~ ^\[?[0-9a-f:]+\]?$ ]]; then
        echo "Blocked: raw IP address not allowed in endpoint: $url" >&2
        return 1
    fi

    # Block localhost variants
    if [[ "$host" == "localhost" ]] || [[ "$host" == "localhost."* ]]; then
        echo "Blocked: localhost not allowed in endpoint: $url" >&2
        return 1
    fi

    # Azure Monitor domain allowlist
    local -a allowed=(
        ".applicationinsights.azure.com"
        ".applicationinsights.azure.us"
        ".applicationinsights.azure.cn"
        ".monitor.azure.com"
        ".monitor.azure.us"
        ".monitor.azure.cn"
        ".services.visualstudio.com"
        ".in.ai.monitor.azure.com"
        ".livediagnostics.monitor.azure.com"
        ".livediagnostics.monitor.azure.us"
        ".livediagnostics.monitor.azure.cn"
    )

    local suffix
    for suffix in "${allowed[@]}"; do
        if [[ "$host" == *"$suffix" ]]; then
            return 0
        fi
    done

    echo "Blocked: hostname '$host' is not a recognised Azure Monitor domain: $url" >&2
    return 1
}

# sanitize_single_quotes STRING
#   Escapes single quotes for safe interpolation into KQL/ARG query strings.
#   Replaces ' with '' (KQL escape convention).
sanitize_single_quotes() {
    echo "${1//\'/\'\'}" 
}

# --- UUID ---

generate_uuid() {
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x\n' \
            $((RANDOM)) $((RANDOM)) $((RANDOM)) \
            $(( (RANDOM & 0x0fff) | 0x4000 )) \
            $(( (RANDOM & 0x3fff) | 0x8000 )) \
            $((RANDOM)) $((RANDOM)) $((RANDOM))
    fi
}

# --- IP classification ---

is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^10\. ]] || \
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || \
    [[ "$ip" =~ ^192\.168\. ]] || \
    [[ "$ip" =~ ^169\.254\. ]] || \
    [[ "$ip" =~ ^127\. ]]
}

# --- URL helpers ---

extract_host_from_url() {
    local url="$1"
    url="${url#https://}"
    url="${url#http://}"
    url="${url%%/*}"
    url="${url%%:*}"
    echo "$url"
}

# --- Consent gate ---

request_user_consent() {
    # Optional leading flag: --requires-azure-login
    # When set, the PaaS non-interactive check applies (can't az login from Kudu).
    # When absent, only the TTY check applies (so ingestion consent still prompts in Kudu SSH).
    local requires_azure_login=false
    if [[ "${1:-}" == "--requires-azure-login" ]]; then
        requires_azure_login=true
        shift
    fi

    local prompt_title="$1"
    shift
    local skip_hint="$1"
    shift
    local prompt_question="${1:-Proceed? [Y/N]}"
    shift
    local -a prompt_lines=("$@")

    # --auto-approve: automatic YES (no prompt shown)
    if $AUTO_APPROVE; then return 0; fi

    # Non-interactive PaaS check (only for Azure login-dependent operations)
    # Kudu SSH is interactive for ingestion tests but can't az login.
    if $requires_azure_login && $is_non_interactive; then
        _print ""
        _print -c "$C_YELLOW" "  CONSENT REQUIRED: $prompt_title"
        _print -c "$C_GRAY" "  Skipped -- non-interactive environment detected (Azure login unavailable)."
        _print -c "$C_GRAY" "  Use --auto-approve to enable in automated environments."
        _print ""
        return 1
    fi

    # Not a terminal (piped stdin) without --auto-approve: fail closed
    if [[ ! -t 0 ]]; then
        _print ""
        _print -c "$C_YELLOW" "  CONSENT REQUIRED: $prompt_title"
        _print -c "$C_GRAY" "  Skipped -- stdin is not a terminal (piped/redirected)."
        _print -c "$C_GRAY" "  Use --auto-approve to enable in non-interactive environments."
        _print ""
        return 1
    fi

    # Interactive: show consent box and prompt Y/N
    _print ""
    _print -c "$C_DARK_CYAN" "  ================================================================"        
    _print -c "$C_CYAN" "  $prompt_title"
    _print -c "$C_DARK_CYAN" "  ================================================================"        
    local line
    for line in "${prompt_lines[@]}"; do
        _print -c "$C_GRAY" "  $line"
    done
    _print ""
    _print -c "$C_DARK_GRAY" "  $skip_hint"
    _print -c "$C_DARK_CYAN" "  ================================================================"        
    _print ""
    local response
    read -r -p "  $prompt_question " response
    _print ""
    [[ "$response" =~ ^[Yy] ]]
}


# ****************************************************************************
# SETUP & INITIALIZATION FUNCTIONS
# ****************************************************************************
# Environment detection, connection string parsing, tool/CLI availability.
# These run once at startup before any diagnostic steps begin.
# ****************************************************************************

# ============================================================================
# ENVIRONMENT DETECTION FUNCTION
# ============================================================================
# Sets global ENV_* variables. Mirrors the PS1's Get-EnvironmentInfo.

ENV_COMPUTER_NAME=""
ENV_OS=""
ENV_BASH_VERSION=""
ENV_IS_APP_SERVICE=false
ENV_IS_FUNCTION_APP=false
ENV_IS_CONTAINER_APP=false
ENV_IS_KUBERNETES=false
ENV_IS_CLOUD_SHELL=false
ENV_IS_CONTAINER=false
ENV_IS_KUDU=false
ENV_AZURE_HOST_TYPE=""
ENV_AZURE_HOST_DETAIL=""
ENV_DETECTED_CONN_STRING=""
ENV_TIMESTAMP=""

get_environment_info() {
    ENV_COMPUTER_NAME="${HOSTNAME:-$(hostname 2>/dev/null || echo "unknown")}"

    # OS detection
    ENV_OS="Linux"
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release 2>/dev/null
        ENV_OS="${PRETTY_NAME:-Linux}"
    fi

    ENV_BASH_VERSION="${BASH_VERSION:-unknown}"
    ENV_TIMESTAMP="$(get_timestamp)"

    # ---- Azure host detection (order matters -- same as PS1) ----

    # Function App FIRST (Functions run on App Service, so WEBSITE_* also present)
    if [[ -n "${FUNCTIONS_WORKER_RUNTIME:-}" ]]; then
        ENV_IS_FUNCTION_APP=true
        ENV_IS_APP_SERVICE=true
        ENV_AZURE_HOST_TYPE="Azure Function App"
        local -a detail_parts=()
        [[ -n "${FUNCTIONS_EXTENSION_VERSION:-}" ]] && detail_parts+=("v${FUNCTIONS_EXTENSION_VERSION}")
        detail_parts+=("Runtime: ${FUNCTIONS_WORKER_RUNTIME}")
        [[ -n "${WEBSITE_SKU:-}" ]] && detail_parts+=("SKU: ${WEBSITE_SKU}")
        local _joined=""
        for _p in "${detail_parts[@]}"; do [[ -n "$_joined" ]] && _joined+=" | "; _joined+="$_p"; done
        ENV_AZURE_HOST_DETAIL="$_joined"
        local worker="${COMPUTERNAME:-${HOSTNAME:-worker}}"
        ENV_COMPUTER_NAME="${WEBSITE_SITE_NAME:-FunctionApp} ($worker)"

    # App Service (not a Function App)
    elif [[ -n "${WEBSITE_SITE_NAME:-}" ]]; then
        ENV_IS_APP_SERVICE=true
        ENV_AZURE_HOST_TYPE="Azure App Service"
        local -a detail_parts=()
        [[ -n "${WEBSITE_SKU:-}" ]] && detail_parts+=("SKU: ${WEBSITE_SKU}")
        [[ -n "${REGION_NAME:-}" ]] && detail_parts+=("Region: ${REGION_NAME}")
        local _joined=""
        for _p in "${detail_parts[@]}"; do [[ -n "$_joined" ]] && _joined+=" | "; _joined+="$_p"; done
        ENV_AZURE_HOST_DETAIL="$_joined"
        local worker="${COMPUTERNAME:-${HOSTNAME:-worker}}"
        ENV_COMPUTER_NAME="${WEBSITE_SITE_NAME} ($worker)"

    # Azure Container Apps
    elif [[ -n "${CONTAINER_APP_NAME:-}" ]]; then
        ENV_IS_CONTAINER_APP=true
        ENV_IS_CONTAINER=true
        ENV_AZURE_HOST_TYPE="Azure Container App"
        [[ -n "${CONTAINER_APP_REVISION:-}" ]] && ENV_AZURE_HOST_DETAIL="Revision: ${CONTAINER_APP_REVISION}"
        ENV_COMPUTER_NAME="${CONTAINER_APP_NAME}"

    # Kubernetes (AKS or other)
    elif [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
        ENV_IS_KUBERNETES=true
        ENV_IS_CONTAINER=true
        ENV_AZURE_HOST_TYPE="Kubernetes"
        ENV_AZURE_HOST_DETAIL="API: ${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT:-443}"

    # Azure Cloud Shell
    elif [[ -n "${ACC_CLOUD:-}" ]]; then
        ENV_IS_CLOUD_SHELL=true
        ENV_AZURE_HOST_TYPE="Azure Cloud Shell"
    fi

    # Kudu/SCM detection (supplemental)
    [[ -n "${KUDU_APPPATH:-}" ]] && ENV_IS_KUDU=true

    # Container detection (supplemental)
    if ! $ENV_IS_CONTAINER && [[ -f /.dockerenv ]]; then
        ENV_IS_CONTAINER=true
    fi

    # ---- Connection string auto-detection ----
    local env_vars=(
        "APPLICATIONINSIGHTS_CONNECTION_STRING"
        "APPINSIGHTS_INSTRUMENTATIONKEY"
        "ApplicationInsights__ConnectionString"
        "APPLICATIONINSIGHTS_CONNECTIONSTRING"
    )
    for var in "${env_vars[@]}"; do
        local val="${!var:-}"
        if [[ -n "$val" ]]; then
            ENV_DETECTED_CONN_STRING="$val"
            break
        fi
    done
}

# ============================================================================
# PARSE CONNECTION STRING
# ============================================================================
# Sets CS_* globals. Mirrors the PS1's Parse-ConnectionString.

CS_IKEY=""
CS_INGESTION_ENDPOINT=""
CS_LIVE_ENDPOINT=""
CS_APPLICATION_ID=""

parse_connection_string() {
    local conn_str="$1"
    CS_IKEY="" CS_INGESTION_ENDPOINT="" CS_LIVE_ENDPOINT="" CS_APPLICATION_ID="" CS_ENDPOINT_SUFFIX=""

    local IFS=';'
    local -a segments
    read -ra segments <<< "$conn_str"

    for segment in "${segments[@]}"; do
        # Trim whitespace
        segment="${segment#"${segment%%[![:space:]]*}"}"
        segment="${segment%"${segment##*[![:space:]]}"}"

        if [[ "$segment" =~ ^([^=]+)=(.+)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local val="${BASH_REMATCH[2]}"
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            val="${val#"${val%%[![:space:]]*}"}"
            val="${val%"${val##*[![:space:]]}"}"

            case "$key" in
                InstrumentationKey)  CS_IKEY="$val" ;;
                IngestionEndpoint)   CS_INGESTION_ENDPOINT="$val" ;;
                LiveEndpoint)        CS_LIVE_ENDPOINT="$val" ;;
                ApplicationId)       CS_APPLICATION_ID="$val" ;;
                EndpointSuffix)      CS_ENDPOINT_SUFFIX="$val" ;;
            esac
        fi
    done
}

# ============================================================================
# TOOL AVAILABILITY CHECKS
# ============================================================================

check_tool_availability() {
    # Required tools
    if command -v curl &>/dev/null; then
        HAS_CURL=true
    else
        _print -c "$C_RED" "  [ERROR] curl is required but not found."
        _print -c "$C_YELLOW" "  Install curl: apt-get install curl / yum install curl"
        exit 1
    fi

    if command -v openssl &>/dev/null; then
        HAS_OPENSSL=true
    else
        _print -c "$C_RED" "  [ERROR] openssl is required but not found."
        _print -c "$C_YELLOW" "  Install openssl: apt-get install openssl / yum install openssl"
        exit 1
    fi

    # Optional tools
    command -v dig &>/dev/null        && HAS_DIG=true
    command -v nslookup &>/dev/null   && HAS_NSLOOKUP=true
    command -v jq &>/dev/null         && HAS_JQ=true
    command -v bc &>/dev/null         && HAS_BC=true

    if ! $HAS_DIG && ! $HAS_NSLOOKUP; then
        _print -c "$C_YELLOW" "  [!] Neither dig nor nslookup found. DNS resolution tests will be skipped."
        _print -c "$C_GRAY" "      Install: apt-get install dnsutils / yum install bind-utils"
    fi

    if ! $HAS_JQ; then
        write_result "INFO" "jq not found -- JSON output will use basic formatting" \
            "Install jq for formatted JSON: apt-get install jq"
    fi
}

# ============================================================================
# AZURE CLI CHECKS
# ============================================================================

check_azure_cli() {
    if $NETWORK_ONLY; then
        CHECK_AZURE=false
        return
    fi

    if ! command -v az &>/dev/null; then
        AZ_CLI_FOUND=false
        CHECK_AZURE=false
        return
    fi

    AZ_CLI_FOUND=true
    CHECK_AZURE=true

    if az account show &>/dev/null; then
        AZ_LOGGED_IN=true
    fi
}


# ============================================================================
# MAIN DIAGNOSTIC FUNCTIONS
# ============================================================================
# DNS Resolution, TCP Connectivity, TLS Handshake, Telemetry Ingestion
# ============================================================================

# --- DNS Resolution ---

get_dns_servers() {
    if [[ -f /etc/resolv.conf ]]; then
        grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' '
    fi
}

# Sets DNS_RESULT_* globals for a single hostname lookup
DNS_RESULT_STATUS=""
DNS_RESULT_IP=""
DNS_RESULT_PRIVATE=false
DNS_RESULT_DURATION=0
DNS_RESULT_DETAIL=""
DNS_RESULT_FAILURE_LABEL=""

# classify_dig_failure -- called when dig +short returned no IP
#   Runs a lightweight follow-up dig to extract the DNS status code.
#   Sets DNS_RESULT_FAILURE_LABEL and DNS_RESULT_DETAIL.
classify_dig_failure() {
    local hostname="$1"
    # Capture dig output including stderr for error detection
    local dig_raw
    dig_raw="$(dig +short +time=3 +tries=1 "$hostname" 2>&1)"
    # Also get the full status line (lightweight: +noall +comments only prints header)
    local dig_status
    dig_status="$(dig +time=2 +tries=1 +noall +comments "$hostname" 2>/dev/null \
        | grep -i 'status:' | head -1 | sed 's/.*status: *\([A-Z]*\).*/\1/')"

    if echo "$dig_raw" | grep -qi "connection timed out"; then
        DNS_RESULT_FAILURE_LABEL="(DNS timeout)"
        DNS_RESULT_DETAIL="DNS timeout: no response from DNS server for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$dig_raw" | grep -qi "connection refused"; then
        DNS_RESULT_FAILURE_LABEL="(DNS refused)"
        DNS_RESULT_DETAIL="DNS connection refused for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$dig_raw" | grep -qi "network unreachable\|network is unreachable"; then
        DNS_RESULT_FAILURE_LABEL="(DNS no route)"
        DNS_RESULT_DETAIL="DNS server unreachable for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif [[ "$dig_status" == "NXDOMAIN" ]]; then
        DNS_RESULT_FAILURE_LABEL="(NXDOMAIN)"
        DNS_RESULT_DETAIL="DNS NXDOMAIN: '$hostname' -- the DNS server could not find this domain [${DNS_RESULT_DURATION}ms]"
    elif [[ "$dig_status" == "SERVFAIL" ]]; then
        DNS_RESULT_FAILURE_LABEL="(DNS SERVFAIL)"
        DNS_RESULT_DETAIL="DNS SERVFAIL: temporary server failure resolving '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif [[ "$dig_status" == "REFUSED" ]]; then
        DNS_RESULT_FAILURE_LABEL="(DNS REFUSED)"
        DNS_RESULT_DETAIL="DNS query refused by server for '$hostname' [${DNS_RESULT_DURATION}ms]"
    else
        DNS_RESULT_FAILURE_LABEL="(DNS error)"
        DNS_RESULT_DETAIL="DNS resolution failed for '$hostname' [${DNS_RESULT_DURATION}ms]"
    fi
}

# classify_nslookup_failure -- called when nslookup returned no IP
#   Inspects nslookup output to determine the failure reason.
#   Sets DNS_RESULT_FAILURE_LABEL and DNS_RESULT_DETAIL.
classify_nslookup_failure() {
    local hostname="$1"
    local ns_output="$2"

    if echo "$ns_output" | grep -qi "connection timed out"; then
        DNS_RESULT_FAILURE_LABEL="(DNS timeout)"
        DNS_RESULT_DETAIL="DNS timeout: no response from DNS server for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$ns_output" | grep -qi "connection refused"; then
        DNS_RESULT_FAILURE_LABEL="(DNS refused)"
        DNS_RESULT_DETAIL="DNS connection refused for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$ns_output" | grep -qi "server can't find\|NXDOMAIN"; then
        DNS_RESULT_FAILURE_LABEL="(NXDOMAIN)"
        DNS_RESULT_DETAIL="DNS NXDOMAIN: '$hostname' -- the DNS server could not find this domain [${DNS_RESULT_DURATION}ms]"
    elif echo "$ns_output" | grep -qi "SERVFAIL\|server failure"; then
        DNS_RESULT_FAILURE_LABEL="(DNS SERVFAIL)"
        DNS_RESULT_DETAIL="DNS SERVFAIL: temporary server failure resolving '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$ns_output" | grep -qi "REFUSED"; then
        DNS_RESULT_FAILURE_LABEL="(DNS REFUSED)"
        DNS_RESULT_DETAIL="DNS query refused by server for '$hostname' [${DNS_RESULT_DURATION}ms]"
    elif echo "$ns_output" | grep -qi "network is unreachable\|no route"; then
        DNS_RESULT_FAILURE_LABEL="(DNS no route)"
        DNS_RESULT_DETAIL="DNS server unreachable for '$hostname' [${DNS_RESULT_DURATION}ms]"
    else
        DNS_RESULT_FAILURE_LABEL="(DNS error)"
        DNS_RESULT_DETAIL="DNS resolution failed for '$hostname' [${DNS_RESULT_DURATION}ms]"
    fi
}

test_dns_resolution() {
    local hostname="$1"
    DNS_RESULT_STATUS="FAIL"
    DNS_RESULT_IP=""
    DNS_RESULT_PRIVATE=false
    DNS_RESULT_DURATION=0
    DNS_RESULT_DETAIL=""
    DNS_RESULT_FAILURE_LABEL=""

    if $HAS_DIG; then
        local start_ms end_ms ip_line
        start_ms="$(get_ms_timestamp)"
        ip_line="$(dig +short +time=5 +tries=2 "$hostname" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
        end_ms="$(get_ms_timestamp)"
        DNS_RESULT_DURATION=$(( end_ms - start_ms ))

        if [[ -n "$ip_line" ]]; then
            DNS_RESULT_STATUS="PASS"
            DNS_RESULT_IP="$ip_line"
            if is_private_ip "$ip_line"; then
                DNS_RESULT_PRIVATE=true
                DNS_RESULT_DETAIL="$hostname -> $ip_line (Private IP) [${DNS_RESULT_DURATION}ms]"
            else
                DNS_RESULT_DETAIL="$hostname -> $ip_line (Public IP) [${DNS_RESULT_DURATION}ms]"
            fi
        else
            classify_dig_failure "$hostname"
        fi

    elif $HAS_NSLOOKUP; then
        local start_ms end_ms ns_output ip_line
        start_ms="$(get_ms_timestamp)"
        ns_output="$(nslookup "$hostname" 2>&1)"
        end_ms="$(get_ms_timestamp)"
        DNS_RESULT_DURATION=$(( end_ms - start_ms ))

        # Parse nslookup output: skip the server's own address, grab first result
        ip_line="$(echo "$ns_output" | awk '/^Address:/ && !/#/ {print $2}' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
        if [[ -z "$ip_line" ]]; then
            ip_line="$(echo "$ns_output" | awk '/Address:/{a=$2} END{print a}' \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
        fi

        if [[ -n "$ip_line" ]]; then
            DNS_RESULT_STATUS="PASS"
            DNS_RESULT_IP="$ip_line"
            if is_private_ip "$ip_line"; then
                DNS_RESULT_PRIVATE=true
                DNS_RESULT_DETAIL="$hostname -> $ip_line (Private IP) [${DNS_RESULT_DURATION}ms]"
            else
                DNS_RESULT_DETAIL="$hostname -> $ip_line (Public IP) [${DNS_RESULT_DURATION}ms]"
            fi
        else
            classify_nslookup_failure "$hostname" "$ns_output"
        fi
    else
        DNS_RESULT_FAILURE_LABEL="(no DNS tool)"
        DNS_RESULT_DETAIL="No DNS tool available (install dig or nslookup)"
    fi
}

# render_dns_table -- verbose tabular output matching PS1 format
# Reads from the DNS_R_* arrays populated during DNS checks in main()
render_dns_table() {
    # Column widths matching PS1
    local cat_w=24 host_w=48 ip_w=18 type_w=10 stat_w=6

    _print -c "$C_CYAN" "  DNS Resolution Results:"
    _print ""

    # Header
    local hdr
    hdr="$(printf "  %-${cat_w}s %-${host_w}s %-${ip_w}s %-${type_w}s %-${stat_w}s" \
        "Category" "Endpoint" "Resolved IP" "Type" "Status")"
    _print -c "$C_WHITE" "$hdr"

    # Separator
    local sep="  $(printf '%0.s-' $(seq 1 $cat_w)) $(printf '%0.s-' $(seq 1 $host_w)) $(printf '%0.s-' $(seq 1 $ip_w)) $(printf '%0.s-' $(seq 1 $type_w)) $(printf '%0.s-' $(seq 1 $stat_w))"
    _print -c "$C_DARK_GRAY" "$sep"

    local pass_count=0 fail_count=0
    for i in "${!DNS_R_HOSTNAME[@]}"; do
        local cat="${DNS_R_CATEGORY[$i]}"
        local host="${DNS_R_HOSTNAME[$i]}"
        local ip="${DNS_R_IP[$i]}"
        if [[ -z "$ip" ]]; then
            ip="${DNS_R_FAILURE_LABEL[$i]:-"(failed)"}"
        fi
        local ip_type="Public"
        local status="${DNS_R_STATUS[$i]}"

        # Truncate long values
        (( ${#cat} > cat_w )) && cat="${cat:0:$((cat_w-2))}.."
        (( ${#host} > host_w )) && host="${host:0:$((host_w-2))}.."
        (( ${#ip} > ip_w )) && ip="${ip:0:$((ip_w-2))}.."

        if [[ "$status" == "FAIL" ]]; then
            ip_type="-"
            (( fail_count++ ))
        elif [[ "${DNS_R_PRIVATE[$i]}" == "true" ]]; then
            ip_type="Private"
            (( pass_count++ ))
        else
            (( pass_count++ ))
        fi

        local row
        row="$(printf "  %-${cat_w}s %-${host_w}s %-${ip_w}s %-${type_w}s " \
            "$cat" "$host" "$ip" "$ip_type")"

        _print -n "$row"
        case "$status" in
            PASS) _print -c "$C_GREEN" "PASS" ;;
            FAIL) _print -c "$C_RED" "FAIL" ;;
            INFO) _print -c "$C_YELLOW" "INFO" ;;
            SKIP) _print -c "$C_DARK_GRAY" "SKIP" ;;
            *)    _print -c "$C_GRAY" "$status" ;;
        esac
    done

    _print -c "$C_DARK_GRAY" "$sep"
    _print ""

    # Summary line
    local total=${#DNS_R_HOSTNAME[@]}
    _print -n -c "$C_GRAY" "  Resolved: "
    _print -n -c "$C_GREEN" "$pass_count"
    _print -n -c "$C_GRAY" " / $total"
    if (( fail_count > 0 )); then
        _print -n -c "$C_GRAY" "  |  Failed: "
        _print -c "$C_RED" "$fail_count"
    else
        _print ""
    fi

    _print ""
    _print -n -c "$C_DARK_GRAY" "  NOTE: "
    _print -c "$C_DARK_GRAY" "PASS means this machine resolved the hostname to an IP address. It does NOT"
    _print -c "$C_DARK_GRAY" "  yet confirm whether the returned IP is the correct one for healthy telemetry flow."
    if $CHECK_AZURE || [[ ${#AMPLS_EXPECTED_IPS[@]} -gt 0 ]]; then
        _print -c "$C_DARK_GRAY" "  The AMPLS validation step will compare these IPs against any expected private endpoint IPs."
    elif ! $NETWORK_ONLY; then
        _print -c "$C_DARK_GRAY" "  To fully validate resolved IPs (including AMPLS/Private Link), run this script from an"
        _print -c "$C_DARK_GRAY" "  environment with the Azure CLI installed and an active Azure login."
    fi
    _print ""
}


# --- TCP Connectivity ---

TCP_RESULT_STATUS=""
TCP_RESULT_DURATION=0
TCP_RESULT_DETAIL=""

test_tcp_connectivity() {
    local hostname="$1"
    local port="${2:-443}"
    local timeout_sec="${3:-5}"

    TCP_RESULT_STATUS="FAIL"
    TCP_RESULT_DURATION=0
    TCP_RESULT_DETAIL=""

    local start_ms end_ms
    start_ms="$(get_ms_timestamp)"

    if (timeout "$timeout_sec" bash -c "echo >/dev/tcp/$hostname/$port" 2>/dev/null); then
        end_ms="$(get_ms_timestamp)"
        TCP_RESULT_DURATION=$(( end_ms - start_ms ))
        TCP_RESULT_STATUS="PASS"
        TCP_RESULT_DETAIL="TCP ${hostname}:${port} OK [${TCP_RESULT_DURATION}ms]"
        if (( TCP_RESULT_DURATION > 3000 )); then
            TCP_RESULT_STATUS="INFO"
            TCP_RESULT_DETAIL+=" (HIGH LATENCY)"
        fi
    else
        end_ms="$(get_ms_timestamp)"
        TCP_RESULT_DURATION=$(( end_ms - start_ms ))
        TCP_RESULT_DETAIL="TCP ${hostname}:${port} failed (timeout after ${timeout_sec}s)"
    fi
}

# render_tcp_table -- verbose tabular output matching PS1 format
# Uses TCP_R_* arrays populated during TCP checks in main()
render_tcp_table() {
    local cat_w=24 host_w=44 ip_w=16 lat_w=10 stat_w=6

    _print -c "$C_CYAN" "  TCP Connectivity Results:"
    _print ""

    local hdr
    hdr="$(printf "  %-${cat_w}s %-${host_w}s %-${ip_w}s %${lat_w}s %-${stat_w}s" \
        "Category" "Endpoint" "Resolved IP" "Latency" "Status")"
    _print -c "$C_WHITE" "$hdr"

    local sep="  $(printf '%0.s-' $(seq 1 $cat_w)) $(printf '%0.s-' $(seq 1 $host_w)) $(printf '%0.s-' $(seq 1 $ip_w)) $(printf '%0.s-' $(seq 1 $lat_w)) $(printf '%0.s-' $(seq 1 $stat_w))"
    _print -c "$C_DARK_GRAY" "$sep"

    local pass_count=0 fail_count=0
    local -a latencies=()
    for i in "${!TCP_R_HOSTNAME[@]}"; do
        local cat="${TCP_R_CATEGORY[$i]}"
        local host="${TCP_R_HOSTNAME[$i]}"
        local ip="${TCP_R_IP[$i]:---}"
        local duration="${TCP_R_DURATION[$i]}"
        local status="${TCP_R_STATUS[$i]}"

        (( ${#cat} > cat_w )) && cat="${cat:0:$((cat_w-2))}.."
        (( ${#host} > host_w )) && host="${host:0:$((host_w-2))}.."

        local latency="-"
        if [[ "$status" != "FAIL" ]]; then
            latency="${duration}ms"
            latencies+=("$duration")
            (( pass_count++ ))
        else
            (( fail_count++ ))
        fi

        local row
        row="$(printf "  %-${cat_w}s %-${host_w}s %-${ip_w}s %${lat_w}s " \
            "$cat" "$host" "$ip" "$latency")"

        _print -n "$row"
        case "$status" in
            PASS) _print -c "$C_GREEN" "PASS" ;;
            INFO) _print -c "$C_YELLOW" "INFO" ;;
            FAIL) _print -c "$C_RED" "FAIL" ;;
            *)    _print -c "$C_GRAY" "$status" ;;
        esac
    done

    _print -c "$C_DARK_GRAY" "$sep"
    _print ""

    # Summary line
    local total=${#TCP_R_HOSTNAME[@]}
    _print -n -c "$C_GRAY" "  Reachable: "
    _print -n -c "$C_GREEN" "$pass_count"
    _print -n -c "$C_GRAY" " / $total"
    if (( fail_count > 0 )); then
        _print -n -c "$C_GRAY" "  |  Blocked: "
        _print -c "$C_RED" "$fail_count"
    elif (( ${#latencies[@]} > 0 )); then
        # Compute latency range (pure bash, no bc needed)
        local min_lat=999999 max_lat=0 sum_lat=0
        for lat in "${latencies[@]}"; do
            (( lat < min_lat )) && min_lat=$lat
            (( lat > max_lat )) && max_lat=$lat
            (( sum_lat += lat ))
        done
        local avg_lat=$(( sum_lat / ${#latencies[@]} ))
        _print -c "$C_GRAY" "  |  Latency: ${min_lat}-${max_lat}ms (avg: ${avg_lat}ms)"
    else
        _print ""
    fi
    _print ""
}


# --- TLS Handshake Validation ---

# TLS result globals (per-call)
TLS_RESULT_STATUS=""
TLS_RESULT_DETAIL=""
TLS_RESULT_ACTION=""
TLS_RESULT_CERT_ISSUER=""
TLS_RESULT_CERT_SUBJECT=""
TLS_RESULT_TLS_INSPECTION=false
TLS_RESULT_PROXY_PRODUCT=""
TLS_RESULT_DEPRECATED_AZURE_EDGE=false
TLS_RESULT_SUPPORTED=()
TLS_RESULT_FAILED=()
TLS_RESULT_DEPRECATED_ACCEPTED=()

test_tls_handshake() {
    local hostname="$1"
    local port="${2:-443}"
    local timeout_current="${3:-10}"     # 10s for TLS 1.2/1.3
    local timeout_deprecated="${4:-3}"   # 3s for TLS 1.0/1.1 (MITM probe)

    TLS_RESULT_STATUS="FAIL"
    TLS_RESULT_DETAIL=""
    TLS_RESULT_ACTION=""
    TLS_RESULT_CERT_ISSUER=""
    TLS_RESULT_CERT_SUBJECT=""
    TLS_RESULT_TLS_INSPECTION=false
    TLS_RESULT_PROXY_PRODUCT=""
    TLS_RESULT_DEPRECATED_AZURE_EDGE=false
    TLS_RESULT_SUPPORTED=()
    TLS_RESULT_FAILED=()
    TLS_RESULT_DEPRECATED_ACCEPTED=()

    local has_tls12=false has_tls13=false has_tls10=false has_tls11=false
    local cert_captured=false

    # --- TLS version test matrix ---
    # Format: "version_name|openssl_flag|deprecated|timeout"
    local -a tls_tests=(
        "TLS 1.0|-tls1|true|$timeout_deprecated"
        "TLS 1.1|-tls1_1|true|$timeout_deprecated"
        "TLS 1.2|-tls1_2|false|$timeout_current"
        "TLS 1.3|-tls1_3|false|$timeout_current"
    )

    for test_spec in "${tls_tests[@]}"; do
        local IFS='|'
        local -a parts
        read -ra parts <<< "$test_spec"
        local ver_name="${parts[0]}"
        local ssl_flag="${parts[1]}"
        local is_deprecated="${parts[2]}"
        local tls_timeout="${parts[3]}"

        # Check if openssl supports this flag
        # TLS 1.3 requires OpenSSL 1.1.1+; some builds lack -tls1 or -tls1_1
        if ! openssl s_client -help 2>&1 | grep -q -- "$ssl_flag"; then
            TLS_RESULT_FAILED+=("$ver_name")
            continue
        fi

        local ssl_output
        ssl_output="$(echo "" | timeout "$tls_timeout" openssl s_client \
            -connect "${hostname}:${port}" "$ssl_flag" \
            -servername "$hostname" 2>&1)" || true

        if echo "$ssl_output" | grep -qi "Protocol.*:.*TLS\|BEGIN CERTIFICATE\|Verify return code"; then
            # Check for actual successful negotiation (not just cert dump)
            local negotiated_proto
            negotiated_proto="$(echo "$ssl_output" | grep -i '^\s*Protocol\s*:' | awk '{print $NF}')"

            if [[ -z "$negotiated_proto" ]] || echo "$negotiated_proto" | grep -qi "error\|none"; then
                TLS_RESULT_FAILED+=("$ver_name")
                continue
            fi

            # Guard against false positives: OpenSSL echoes the requested protocol even
            # when the server RSTs the connection (errno=104). Detect this by checking
            # for a null cipher (0000 / (NONE)) or zero bytes read -- both indicate the
            # handshake never actually completed.
            local negotiated_cipher
            negotiated_cipher="$(echo "$ssl_output" | grep -i '^\s*Cipher\s*:' | tail -1 | awk '{print $NF}')"
            local handshake_bytes_read
            handshake_bytes_read="$(echo "$ssl_output" | sed -n 's/.*handshake has read \([0-9]\{1,\}\).*/\1/p')"

            if [[ "$negotiated_cipher" == "0000" || "$negotiated_cipher" == "(NONE)" \
               || "$handshake_bytes_read" == "0" ]]; then
                TLS_RESULT_FAILED+=("$ver_name")
                continue
            fi

            TLS_RESULT_SUPPORTED+=("$ver_name")

            case "$ver_name" in
                "TLS 1.0") has_tls10=true; TLS_RESULT_DEPRECATED_ACCEPTED+=("TLS 1.0") ;;
                "TLS 1.1") has_tls11=true; TLS_RESULT_DEPRECATED_ACCEPTED+=("TLS 1.1") ;;
                "TLS 1.2") has_tls12=true ;;
                "TLS 1.3") has_tls13=true ;;
            esac

            # Capture certificate info from first successful connection
            if ! $cert_captured; then
                # OpenSSL output format varies by version:
                #   OpenSSL 3.x (Ubuntu 24): "issuer=CN = Microsoft..." (equals sign)
                #   OpenSSL 1.x (older):     "   issuer : CN=Microsoft..." (colon)
                TLS_RESULT_CERT_ISSUER="$(echo "$ssl_output" | grep -iE '^\s*issuer\s*[=:]' | head -1 | sed 's/^[^=:]*[=:]\s*//')"
                TLS_RESULT_CERT_SUBJECT="$(echo "$ssl_output" | grep -iE '^\s*subject\s*[=:]' | head -1 | sed 's/^[^=:]*[=:]\s*//')"
                [[ -n "$TLS_RESULT_CERT_ISSUER" || -n "$TLS_RESULT_CERT_SUBJECT" ]] && cert_captured=true
            fi
        else
            TLS_RESULT_FAILED+=("$ver_name")
        fi
    done

    # --- Determine overall status ---
    local current_supported=""
    $has_tls12 && current_supported+="TLS 1.2"
    $has_tls13 && { [[ -n "$current_supported" ]] && current_supported+=", "; current_supported+="TLS 1.3"; }

    if $has_tls12 || $has_tls13; then
        TLS_RESULT_STATUS="PASS"
        TLS_RESULT_DETAIL="Supported: $current_supported"

        if [[ -n "$TLS_RESULT_CERT_SUBJECT" ]]; then
            # Extract short CN from subject
            local short_cert
            short_cert="$(echo "$TLS_RESULT_CERT_SUBJECT" | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]\{1,\}\).*/\1/p')"
            [[ -z "$short_cert" ]] && short_cert="$TLS_RESULT_CERT_SUBJECT"
            TLS_RESULT_DETAIL+=" | Cert: $short_cert"
        fi

        # Flag if deprecated protocols were accepted (MITM indicator)
        if $has_tls10 || $has_tls11; then
            local dep_list
            dep_list="$(printf '%s, ' "${TLS_RESULT_DEPRECATED_ACCEPTED[@]}")"
            dep_list="${dep_list%, }"
            TLS_RESULT_STATUS="INFO"
            TLS_RESULT_DETAIL+=" | [SECURITY] Deprecated accepted: $dep_list"
            # Action text is set after the TLS inspection check below (cert-aware)
        fi
    elif $has_tls10 || $has_tls11; then
        local dep_list
        dep_list="$(printf '%s, ' "${TLS_RESULT_DEPRECATED_ACCEPTED[@]}")"
        dep_list="${dep_list%, }"
        TLS_RESULT_STATUS="INFO"
        TLS_RESULT_DETAIL="Only deprecated TLS versions negotiated: $dep_list"
        TLS_RESULT_ACTION="This client could only negotiate deprecated TLS. Azure Monitor requires TLS 1.2+. Likely a proxy/firewall is downgrading the connection."
    else
        local failed_list
        failed_list="$(printf '%s, ' "${TLS_RESULT_FAILED[@]}")"
        failed_list="${failed_list%, }"
        TLS_RESULT_STATUS="FAIL"
        TLS_RESULT_DETAIL="Could not negotiate any TLS version ($failed_list)"
        TLS_RESULT_ACTION="TLS handshake failed for all protocol versions. Common causes: (1) Firewall/proxy blocking TLS traffic, (2) Untrusted CA certificate, (3) Network appliance terminating TLS."
    fi

    # --- TLS inspection detection ---
    local cert_to_check="${TLS_RESULT_CERT_ISSUER:-$TLS_RESULT_CERT_SUBJECT}"
    if [[ -n "$cert_to_check" ]] && ! echo "$cert_to_check" | grep -qiE "microsoft|azure|visualstudio|msedge|digicert|Baltimore|windows\.net"; then
        TLS_RESULT_TLS_INSPECTION=true
        [[ "$TLS_RESULT_STATUS" == "PASS" ]] && TLS_RESULT_STATUS="INFO"

        # Identify specific proxy/firewall product
        TLS_RESULT_PROXY_PRODUCT="Unknown proxy/firewall"
        if echo "$cert_to_check" | grep -qi "Zscaler";                        then TLS_RESULT_PROXY_PRODUCT="Zscaler"
        elif echo "$cert_to_check" | grep -qi "Palo Alto";                    then TLS_RESULT_PROXY_PRODUCT="Palo Alto Networks"
        elif echo "$cert_to_check" | grep -qiE "Fortinet|FortiGate";          then TLS_RESULT_PROXY_PRODUCT="Fortinet/FortiGate"
        elif echo "$cert_to_check" | grep -qiE "Blue Coat|Symantec.*Proxy";   then TLS_RESULT_PROXY_PRODUCT="Blue Coat/Symantec"
        elif echo "$cert_to_check" | grep -qi "Netskope";                     then TLS_RESULT_PROXY_PRODUCT="Netskope"
        elif echo "$cert_to_check" | grep -qiE "McAfee|Skyhigh";              then TLS_RESULT_PROXY_PRODUCT="McAfee/Skyhigh"
        elif echo "$cert_to_check" | grep -qi "Barracuda";                    then TLS_RESULT_PROXY_PRODUCT="Barracuda"
        elif echo "$cert_to_check" | grep -qi "Sophos";                       then TLS_RESULT_PROXY_PRODUCT="Sophos"
        elif echo "$cert_to_check" | grep -qi "Check Point";                  then TLS_RESULT_PROXY_PRODUCT="Check Point"
        elif echo "$cert_to_check" | grep -qiE "Cisco|Umbrella";              then TLS_RESULT_PROXY_PRODUCT="Cisco/Umbrella"
        fi

        TLS_RESULT_DETAIL+=" | [TLS INSPECTION: ${TLS_RESULT_PROXY_PRODUCT}]"
        TLS_RESULT_ACTION="Certificate NOT issued by Microsoft/DigiCert. Issuer: ${TLS_RESULT_CERT_ISSUER}. A TLS-inspecting proxy (${TLS_RESULT_PROXY_PRODUCT}) is re-signing certificates. Configure bypass for Azure Monitor endpoints."
    fi

    # --- Deprecated protocol action text (cert-aware) ---
    # Set after TLS inspection check so we know whether the cert is Microsoft-issued.
    if (( ${#TLS_RESULT_DEPRECATED_ACCEPTED[@]} > 0 )); then
        if $TLS_RESULT_TLS_INSPECTION; then
            # Middlebox (non-Microsoft cert) + deprecated = real MITM concern
            # Action already set by TLS inspection block above
            :
        else
            # Microsoft cert + deprecated = unexpected; Azure Monitor should reject TLS < 1.2
            TLS_RESULT_DEPRECATED_AZURE_EDGE=true
            local dep_list_str
            dep_list_str="$(printf '%s, ' "${TLS_RESULT_DEPRECATED_ACCEPTED[@]}")"
            dep_list_str="${dep_list_str%, }"
            # Replace the SECURITY/MITM detail text with unexpected-scenario text
            TLS_RESULT_DETAIL="${TLS_RESULT_DETAIL/ | \[SECURITY\] Deprecated accepted: $dep_list_str/ | [UNEXPECTED] Deprecated accepted ($dep_list_str) with Microsoft cert}"
            TLS_RESULT_ACTION="Deprecated TLS ($dep_list_str) was accepted and a Microsoft-issued certificate was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1. This is not a third-party proxy (the certificate is legitimate), but the behavior is unexpected. If this persists, contact Microsoft support."
        fi
    fi
}


# --- Telemetry Ingestion Test ---

# Ingestion result globals
INGEST_RESULT_STATUS=""
INGEST_RESULT_HTTP_STATUS=""
INGEST_RESULT_DETAIL=""
INGEST_RESULT_ACTION=""
INGEST_RESULT_DURATION=0
INGEST_RESULT_RESPONSE_BODY=""
INGEST_RESULT_TEST_RECORD_ID=""
INGEST_RESULT_TEST_TIMESTAMP=""
INGEST_RESULT_ENDPOINT=""

test_ingestion_endpoint() {
    local ingestion_url="${1%/}"    # trim trailing slash
    local ikey="$2"

    INGEST_RESULT_STATUS="FAIL"
    INGEST_RESULT_HTTP_STATUS=""
    INGEST_RESULT_DETAIL=""
    INGEST_RESULT_ACTION=""
    INGEST_RESULT_DURATION=0
    INGEST_RESULT_RESPONSE_BODY=""
    INGEST_RESULT_TEST_RECORD_ID=""
    INGEST_RESULT_TEST_TIMESTAMP=""
    INGEST_RESULT_ENDPOINT="${ingestion_url}/v2.1/track"

    # Generate unique test record ID and timestamp
    local test_id
    test_id="$(generate_uuid)"
    INGEST_RESULT_TEST_RECORD_ID="$test_id"

    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%S.%6NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
    INGEST_RESULT_TEST_TIMESTAMP="$timestamp"

    local run_location="${ENV_COMPUTER_NAME:-unknown}"

    # Build the availabilityResults JSON payload
    # Using availabilityResults because it is NEVER sampled out by SDK or service
    local payload
    payload="$(cat <<ENDJSON
[{
  "ver": 1,
  "name": "Microsoft.ApplicationInsights.Message",
  "time": "$timestamp",
  "sampleRate": 100,
  "iKey": "$ikey",
  "tags": {
    "ai.cloud.roleInstance": "Telemetry-Flow-Diag",
    "ai.internal.sdkVersion": "telemetry-flow-diag:$SCRIPT_VERSION"
  },
  "data": {
    "baseType": "AvailabilityData",
    "baseData": {
      "ver": 2,
      "id": "$test_id",
      "name": "Telemetry-Flow-Diag Ingestion Validation",
      "duration": "00:00:00.001",
      "success": true,
      "runLocation": "telemetry-flow-script",
      "message": "[$run_location] Telemetry flow diagnostic test record - safe to ignore",
      "properties": {
        "diagnosticRunId": "$test_id",
        "scriptVersion": "$SCRIPT_VERSION"
      }
    }
  }
}]
ENDJSON
)"

    local post_url="${ingestion_url}/v2.1/track"

    # POST with curl -- capture response body and HTTP status code
    local start_ms end_ms
    start_ms="$(get_ms_timestamp)"

    _debug_request "POST" "$post_url" "$payload"

    local curl_output http_code response_body
    curl_output="$(curl -s -w "\n%{http_code}" \
        --tlsv1.2 \
        -X POST "$post_url" \
        -H "Content-Type: application/json" \
        --connect-timeout 10 \
        --max-time 30 \
        -d "$payload" 2>&1)" || true

    end_ms="$(get_ms_timestamp)"
    INGEST_RESULT_DURATION=$(( end_ms - start_ms ))

    # Last line is the HTTP status code; everything before is the response body
    http_code="$(echo "$curl_output" | tail -1)"
    response_body="$(echo "$curl_output" | sed '$d')"
    INGEST_RESULT_HTTP_STATUS="$http_code"
    INGEST_RESULT_RESPONSE_BODY="$response_body"

    _debug_response "HTTP $http_code (${INGEST_RESULT_DURATION}ms)" "$response_body"

    # Check if curl itself failed (no HTTP code)
    if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
        INGEST_RESULT_STATUS="FAIL"
        INGEST_RESULT_DETAIL="curl failed: $curl_output"
        INGEST_RESULT_ACTION="Network error connecting to ingestion endpoint. Check DNS, firewall, and proxy settings."
        return
    fi

    # Parse response JSON for itemsReceived/Accepted
    local items_received="?" items_accepted="?" errors=""
    if $HAS_JQ && [[ -n "$response_body" ]]; then
        items_received="$(echo "$response_body" | jq -r '.itemsReceived // "?"' 2>/dev/null)"
        items_accepted="$(echo "$response_body" | jq -r '.itemsAccepted // "?"' 2>/dev/null)"
        errors="$(echo "$response_body" | jq -r '.errors[]? | "\(.index): \(.statusCode) - \(.message)"' 2>/dev/null)"
    elif [[ -n "$response_body" ]]; then
        # Basic regex parsing without jq
        items_received="$(echo "$response_body" | sed -n 's/.*"itemsReceived"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p')"
        [[ -z "$items_received" ]] && items_received="?"
        items_accepted="$(echo "$response_body" | sed -n 's/.*"itemsAccepted"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p')"
        [[ -z "$items_accepted" ]] && items_accepted="?"
        errors="$(echo "$response_body" | sed -n 's/.*"message"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    fi

    case "$http_code" in
        200)
            INGEST_RESULT_STATUS="PASS"
            INGEST_RESULT_DETAIL="HTTP 200 | Items sent: 1, received: $items_received, accepted: $items_accepted [${INGEST_RESULT_DURATION}ms]"

            if [[ "$items_accepted" == "0" ]]; then
                INGEST_RESULT_STATUS="INFO"
                [[ -n "$errors" ]] && INGEST_RESULT_DETAIL+=" | Errors: $errors"
                INGEST_RESULT_ACTION="Ingestion endpoint accepted the request but rejected the telemetry item. Check the error details above."
            fi
            ;;
        400)
            INGEST_RESULT_DETAIL="HTTP 400 Bad Request"
            INGEST_RESULT_ACTION="The ingestion API rejected the payload. This typically means the instrumentation key is invalid or doesn't match any App Insights resource. Verify your connection string."
            ;;
        401)
            INGEST_RESULT_DETAIL="HTTP 401 Unauthorized"
            INGEST_RESULT_ACTION="Authentication required. Local authentication is likely disabled on this resource. SDKs must use Entra ID (Managed Identity or Service Principal) bearer tokens."
            ;;
        403)
            INGEST_RESULT_DETAIL="HTTP 403 Forbidden"
            INGEST_RESULT_ACTION="Access denied. The ingestion API blocked this request. Common causes: (1) Public ingestion is disabled and you are sending from outside the private link scope, (2) Local authentication is disabled and no Entra ID bearer token was provided."
            ;;
        404)
            INGEST_RESULT_DETAIL="HTTP 404 Not Found"
            INGEST_RESULT_ACTION="The ingestion endpoint path was not found. Verify the IngestionEndpoint in your connection string is correct and includes the regional prefix."
            ;;
        408)
            INGEST_RESULT_DETAIL="HTTP 408 Request Timeout"
            INGEST_RESULT_ACTION="The request timed out. Check network latency, proxy timeout settings, and firewall rules."
            ;;
        429)
            INGEST_RESULT_DETAIL="HTTP 429 Too Many Requests (Throttled)"
            INGEST_RESULT_ACTION="You are being rate-limited. This typically occurs when ingestion volume is extremely high or the daily cap has been reached."
            ;;
        439)
            INGEST_RESULT_DETAIL="HTTP 439 Too Many Requests (Client)"
            INGEST_RESULT_ACTION="Client-side rate limiting triggered. Too many items sent in a short period."
            ;;
        500)
            INGEST_RESULT_DETAIL="HTTP 500 Internal Server Error"
            INGEST_RESULT_ACTION="Azure Monitor ingestion service error. This is usually transient -- retry after a few minutes."
            ;;
        503)
            INGEST_RESULT_DETAIL="HTTP 503 Service Unavailable"
            INGEST_RESULT_ACTION="Azure Monitor ingestion service temporarily unavailable. This can occur during service updates or during region outages. Check Azure status page."
            ;;
        *)
            INGEST_RESULT_DETAIL="HTTP $http_code (unexpected)"
            INGEST_RESULT_ACTION="Unexpected HTTP status code from ingestion endpoint."
            ;;
    esac
}


# ============================================================================
# AMPLS (AZURE MONITOR PRIVATE LINK SCOPE) FUNCTIONS
# ============================================================================
# These functions are used when Azure checks are active (auto-detected or
# not --network-only). They discover the App Insights resource via iKey,
# find linked AMPLS resources, retrieve private endpoint IPs, and compare
# them against DNS results. All operations are READ-ONLY.
# ============================================================================

# validate_ampls_ip_parameter
#   Validates the --lookup-ampls-ip parameter value.
#   Checks: (1) valid IPv4, (2) private RFC1918 range, (3) present in RESOLVED_IP_REGISTRY.
#   Sets AMPLS_IP_VALID=true/false and AMPLS_IP_REASON to an explanation string.
validate_ampls_ip_parameter() {
    local ip="$1"
    AMPLS_IP_VALID=false
    AMPLS_IP_REASON=""

    # (1) Valid IPv4 format
    if ! [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        AMPLS_IP_REASON="'$ip' is not a valid IPv4 address."
        return
    fi
    local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}"
    if (( o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255 )); then
        AMPLS_IP_REASON="'$ip' is not a valid IPv4 address (octet value > 255)."
        return
    fi

    # (2) Private RFC1918 range
    if ! [[ "$ip" =~ ^10\. ]] && ! [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && ! [[ "$ip" =~ ^192\.168\. ]]; then
        AMPLS_IP_REASON="'$ip' is not a private IP address (RFC1918: 10.x, 172.16-31.x, 192.168.x). Only private IPs from AMPLS private endpoints can be looked up."
        return
    fi

    # (3) Present in resolved IP registry
    local found=false
    for reg_ip in "${RESOLVED_IP_REGISTRY[@]}"; do
        if [[ "$reg_ip" == "$ip" ]]; then
            found=true
            break
        fi
    done
    if ! $found; then
        AMPLS_IP_REASON="'$ip' was not resolved by any Azure Monitor endpoint during this script's execution. We can only look up private endpoints for IPs that were actually returned by DNS for the Azure Monitor endpoints tested above. Re-run with verbose output to see which IPs were resolved, then supply one of those private IPs."
        return
    fi

    AMPLS_IP_VALID=true
}

# find_ampls_by_private_ip TARGET_IP
#   Reverse-lookups a private IP to find the owning AMPLS resource.
#   3-step chain: IP -> NIC (ARG) -> PE (ARG) -> AMPLS (ARM REST).
#   Sets GHOST_AMPLS_* globals with results.
#   Returns 0 if AMPLS found, 1 otherwise.
GHOST_AMPLS_FOUND=false
GHOST_AMPLS_NAME=""
GHOST_AMPLS_RG=""
GHOST_AMPLS_SUB=""
GHOST_AMPLS_ID=""
GHOST_AMPLS_PE_NAME=""
GHOST_AMPLS_PE_RG=""
GHOST_AMPLS_ING_MODE=""
GHOST_AMPLS_Q_MODE=""

find_ampls_by_private_ip() {
    local target_ip="$1"

    # Reset globals
    GHOST_AMPLS_FOUND=false
    GHOST_AMPLS_NAME=""
    GHOST_AMPLS_RG=""
    GHOST_AMPLS_SUB=""
    GHOST_AMPLS_ID=""
    GHOST_AMPLS_PE_NAME=""
    GHOST_AMPLS_PE_RG=""
    GHOST_AMPLS_ING_MODE=""
    GHOST_AMPLS_Q_MODE=""

    local safe_ip
    safe_ip="$(sanitize_single_quotes "$target_ip")"

    # -- Step 1: Find NIC by private IP via Resource Graph --
    local nic_query="resources | where type =~ 'microsoft.network/networkinterfaces' | mv-expand ipconfig = properties.ipConfigurations | where ipconfig.properties.privateIPAddress == '${safe_ip}' | project nicId=id, nicName=name, subscriptionId, resourceGroup, subnetId=tostring(ipconfig.properties.subnet.id)"

    local nic_json=""
    _debug_az_graph "$nic_query"
    nic_json="$(az graph query -q "$nic_query" --query "data[0]" -o json 2>/dev/null | tr -d '\r')"
    _debug_response "NIC lookup" "$nic_json"

    if [[ -z "$nic_json" || "$nic_json" == "null" ]]; then
        _debug_response "No NIC found for IP $target_ip"
        return 1
    fi

    local nic_id=""
    if $HAS_JQ; then
        nic_id="$(echo "$nic_json" | jq -r '.nicId // empty')"
    else
        nic_id="$(echo "$nic_json" | grep -o '"nicId"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"nicId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
    fi

    if [[ -z "$nic_id" ]]; then
        _debug_response "NIC ID extraction failed for IP $target_ip"
        return 1
    fi

    # -- Step 2: Find Private Endpoint by NIC via Resource Graph --
    local safe_nic_id
    safe_nic_id="$(echo "$nic_id" | tr '[:upper:]' '[:lower:]')"
    safe_nic_id="$(sanitize_single_quotes "$safe_nic_id")"
    local pe_query="resources | where type =~ 'microsoft.network/privateendpoints' | mv-expand nic = properties.networkInterfaces | where tolower(tostring(nic.id)) == '${safe_nic_id}' | project peId=id, peName=name, subscriptionId, resourceGroup, privateLinkServiceConnections=properties.privateLinkServiceConnections, manualConnections=properties.manualPrivateLinkServiceConnections"

    local pe_json=""
    _debug_az_graph "$pe_query"
    pe_json="$(az graph query -q "$pe_query" --query "data[0]" -o json 2>/dev/null | tr -d '\r')"
    _debug_response "PE lookup" "$pe_json"

    if [[ -z "$pe_json" || "$pe_json" == "null" ]]; then
        _debug_response "No Private Endpoint found for NIC $nic_id"
        return 1
    fi

    local pe_id="" pe_name="" pe_rg=""
    if $HAS_JQ; then
        pe_id="$(echo "$pe_json" | jq -r '.peId // empty')"
        pe_name="$(echo "$pe_json" | jq -r '.peName // empty')"
        pe_rg="$(echo "$pe_json" | jq -r '.resourceGroup // empty')"
    else
        pe_id="$(echo "$pe_json" | grep -o '"peId"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
        pe_name="$(echo "$pe_json" | grep -o '"peName"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
        pe_rg="$(echo "$pe_json" | grep -o '"resourceGroup"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
    fi

    if [[ -z "$pe_id" ]]; then
        return 1
    fi

    GHOST_AMPLS_PE_NAME="$pe_name"
    GHOST_AMPLS_PE_RG="$pe_rg"

    # -- Step 3: Extract AMPLS resource ID from PE connections + fetch via ARM --
    local ampls_resource_id=""
    if $HAS_JQ; then
        # Check both automatic and manual connections for an AMPLS link
        ampls_resource_id="$(echo "$pe_json" | jq -r '
            ([.privateLinkServiceConnections // []
              | .[]?
              | .properties.privateLinkServiceId // empty] +
             [.manualConnections // []
              | .[]?
              | .properties.privateLinkServiceId // empty])
            | map(select(test("microsoft.insights/privatelinkscopes"; "i")))
            | first // empty
        ' 2>/dev/null)"
    else
        # Grep approach: find privateLinkServiceId containing privatelinkscopes
        ampls_resource_id="$(echo "$pe_json" | grep -oi '"privateLinkServiceId"[[:space:]]*:[[:space:]]*"[^"]*microsoft\.insights/privatelinkscopes[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
    fi

    if [[ -z "$ampls_resource_id" ]]; then
        _debug_response "PE $pe_name is not connected to an AMPLS resource"
        return 1
    fi

    GHOST_AMPLS_ID="$ampls_resource_id"

    # Fetch AMPLS details via ARM REST
    local api_url="https://management.azure.com${ampls_resource_id}?api-version=2021-07-01-preview"
    _debug_az_rest "GET" "$api_url"

    local ampls_json
    ampls_json="$(az rest --method GET --url "$api_url" 2>/dev/null | tr -d '\r')"
    _debug_response "AMPLS detail" "$ampls_json"

    if [[ -z "$ampls_json" || "$ampls_json" == "null" ]]; then
        # ARM call failed -- possibly insufficient permissions
        return 1
    fi

    if $HAS_JQ; then
        GHOST_AMPLS_NAME="$(echo "$ampls_json" | jq -r '.name // empty')"
        GHOST_AMPLS_ID="$(echo "$ampls_json" | jq -r '.id // empty')"
        GHOST_AMPLS_SUB="$(echo "$GHOST_AMPLS_ID" | sed -n 's|.*/subscriptions/\([^/]*\)/.*|\1|p')"
        GHOST_AMPLS_RG="$(echo "$GHOST_AMPLS_ID" | sed -n 's|.*/resourceGroups/\([^/]*\)/.*|\1|p')"
        GHOST_AMPLS_ING_MODE="$(echo "$ampls_json" | jq -r '.properties.accessModeSettings.ingestionAccessMode // "Unknown"')"
        GHOST_AMPLS_Q_MODE="$(echo "$ampls_json" | jq -r '.properties.accessModeSettings.queryAccessMode // "Unknown"')"
    else
        GHOST_AMPLS_NAME="$(echo "$ampls_json" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
        local full_id
        full_id="$(echo "$ampls_json" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
        [[ -n "$full_id" ]] && GHOST_AMPLS_ID="$full_id"
        GHOST_AMPLS_SUB="$(echo "$GHOST_AMPLS_ID" | sed -n 's|.*/subscriptions/\([^/]*\)/.*|\1|p')"
        GHOST_AMPLS_RG="$(echo "$GHOST_AMPLS_ID" | sed -n 's|.*/resourceGroups/\([^/]*\)/.*|\1|p')"
        GHOST_AMPLS_ING_MODE="$(echo "$ampls_json" | grep -o '"ingestionAccessMode"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')"
        GHOST_AMPLS_Q_MODE="$(echo "$ampls_json" | grep -o '"queryAccessMode"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')"
        [[ -z "$GHOST_AMPLS_ING_MODE" ]] && GHOST_AMPLS_ING_MODE="Unknown"
        [[ -z "$GHOST_AMPLS_Q_MODE" ]] && GHOST_AMPLS_Q_MODE="Unknown"
    fi

    if [[ -n "$GHOST_AMPLS_NAME" ]]; then
        GHOST_AMPLS_FOUND=true
        return 0
    fi

    return 1
}

# get_ingestion_endpoint_prefix INGESTION_HOST
#   Extracts the region/endpoint prefix from an ingestion hostname for CNAME matching.
#   E.g., "{region}.in.applicationinsights.azure.com" -> "{region}.in"
#         "dc.services.visualstudio.com" -> "dc"
#   Prints the prefix to stdout. Returns 1 if it cannot be determined.
get_ingestion_endpoint_prefix() {
    local host_lower
    host_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"

    # Regional pattern: {region}.in.applicationinsights.{suffix}
    if [[ "$host_lower" =~ ^([a-z0-9-]+\.in)\.applicationinsights\. ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # Global/legacy pattern: dc.services.visualstudio.com
    if [[ "$host_lower" =~ ^(dc)\.services\.visualstudio\. ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # Global pattern: dc.applicationinsights.{suffix}
    if [[ "$host_lower" =~ ^(dc)\.applicationinsights\. ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # Fallback: take everything before first known domain suffix
    if [[ "$host_lower" =~ ^([a-z0-9-]+(\.[a-z]+)?)\.(applicationinsights|ai\.monitor|ai\.privatelink\.monitor)\. ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    return 1
}

# find_ingestion_endpoint_in_ampls_results INGESTION_HOST RESULTS_LINES...
#   Finds the AMPLS validation table entry that corresponds to the IngestionEndpoint.
#   RESULTS_LINES are "FQDN|EXPECTED_IP|ACTUAL_IP|STATUS" strings.
#   Sets INGESTION_AMPLS_MATCH_FQDN, INGESTION_AMPLS_MATCH_ACTUAL_IP, INGESTION_AMPLS_MATCH_STATUS.
#   Returns 0 if match found, 1 otherwise.
INGESTION_AMPLS_MATCH_FQDN=""
INGESTION_AMPLS_MATCH_ACTUAL_IP=""
INGESTION_AMPLS_MATCH_EXPECTED_IP=""
INGESTION_AMPLS_MATCH_STATUS=""

find_ingestion_endpoint_in_ampls_results() {
    local ingestion_host="$1"
    shift
    local -a result_lines=("$@")

    # Reset globals
    INGESTION_AMPLS_MATCH_FQDN=""
    INGESTION_AMPLS_MATCH_ACTUAL_IP=""
    INGESTION_AMPLS_MATCH_EXPECTED_IP=""
    INGESTION_AMPLS_MATCH_STATUS=""

    local prefix
    prefix="$(get_ingestion_endpoint_prefix "$ingestion_host")" || return 1
    [[ -z "$prefix" ]] && return 1

    local prefix_lower
    prefix_lower="$(echo "$prefix" | tr '[:upper:]' '[:lower:]')"

    for line in "${result_lines[@]}"; do
        local fqdn expected_ip actual_ip status
        IFS='|' read -r fqdn expected_ip actual_ip status <<< "$line"
        local fqdn_lower
        fqdn_lower="$(echo "$fqdn" | tr '[:upper:]' '[:lower:]')"

        # PE FQDNs: {prefix}.ai.privatelink.monitor.{suffix} or {prefix}.ai.monitor.{suffix}
        if [[ "$fqdn_lower" =~ ^${prefix_lower}\.ai\.(privatelink\.)?monitor\. ]]; then
            INGESTION_AMPLS_MATCH_FQDN="$fqdn"
            INGESTION_AMPLS_MATCH_EXPECTED_IP="$expected_ip"
            INGESTION_AMPLS_MATCH_ACTUAL_IP="$actual_ip"
            INGESTION_AMPLS_MATCH_STATUS="$status"
            return 0
        fi
    done

    # Fallback for "dc" prefix
    if [[ "$prefix_lower" == "dc" ]]; then
        for line in "${result_lines[@]}"; do
            local fqdn expected_ip actual_ip status
            IFS='|' read -r fqdn expected_ip actual_ip status <<< "$line"
            local fqdn_lower
            fqdn_lower="$(echo "$fqdn" | tr '[:upper:]' '[:lower:]')"
            if [[ "$fqdn_lower" == dc.* ]]; then
                INGESTION_AMPLS_MATCH_FQDN="$fqdn"
                INGESTION_AMPLS_MATCH_EXPECTED_IP="$expected_ip"
                INGESTION_AMPLS_MATCH_ACTUAL_IP="$actual_ip"
                INGESTION_AMPLS_MATCH_STATUS="$status"
                return 0
            fi
        done
    fi

    return 1
}

# --- AMPLS result globals ---
AI_RESOURCE_ID=""
AI_RESOURCE_NAME=""
AI_RESOURCE_RG=""
AI_RESOURCE_SUB=""
AI_RESOURCE_LOCATION=""
AI_PUBLIC_INGESTION="Enabled"
AI_PUBLIC_QUERY="Enabled"
AI_RESOURCE_PROPERTIES_JSON=""

# Check if az resource-graph extension is available.
# Installs it automatically if possible (silent, no prompt).
check_az_graph_extension() {
    # Check if extension is already installed
    local installed
    installed="$(az extension list --query "[?name=='resource-graph'].name" -o tsv 2>/dev/null)"
    if [[ -n "$installed" ]]; then
        return 0
    fi

    # Try to install it silently
    if $VERBOSE_OUTPUT; then
        _print -c "$C_GRAY" "    Installing az resource-graph extension..."
    fi
    if az extension add --name resource-graph --only-show-errors 2>/dev/null; then
        return 0
    fi

    return 1
}

# find_appinsights_resource IKEY
#   Searches Azure Resource Graph for the App Insights resource matching the given iKey.
#   Sets AI_RESOURCE_* globals on success.
#   Returns 0 if found, 1 if not found.
find_appinsights_resource() {
    local ikey="$1"

    local safe_ikey
    safe_ikey="$(sanitize_single_quotes "$ikey")"
    local query="resources | where type =~ 'microsoft.insights/components' | where properties.InstrumentationKey =~ '${safe_ikey}' | project id, name, resourceGroup, subscriptionId, location, properties"

    local result_json=""

    # Strategy 1: Simple az graph query (searches current tenant by default)
    if $VERBOSE_OUTPUT; then
        _print -c "$C_GRAY" "    Searching tenant for App Insights resource by iKey..."
    fi
    _debug_az_graph "$query"
    result_json="$(az graph query -q "$query" --query "data[0]" -o json 2>/dev/null | tr -d '\r')"
    _debug_response "ARG result" "$result_json"

    # Check if we got a result (not null/empty)
    if [[ -z "$result_json" || "$result_json" == "null" ]]; then
        # Strategy 2: Try with explicit first subscription batching
        local sub_list
        sub_list="$(az account list --query "[].id" -o tsv 2>/dev/null)"
        if [[ -n "$sub_list" ]]; then
            local -a subs=()
            while IFS= read -r sub; do
                sub="${sub//$'\r'/}"
                [[ -n "$sub" ]] && subs+=("$sub")
            done <<< "$sub_list"

            if (( ${#subs[@]} > 0 )); then
                if $VERBOSE_OUTPUT; then
                    _print -c "$C_GRAY" "    Searching ${#subs[@]} subscription(s)..."
                fi
                # az graph query supports --subscriptions as space-separated list
                _debug_az_graph "$query (with ${#subs[@]} subscriptions)"
                result_json="$(az graph query -q "$query" --subscriptions "${subs[@]}" --query "data[0]" -o json 2>/dev/null | tr -d '\r')"
                _debug_response "ARG result" "$result_json"
            fi
        fi
    fi

    if [[ -z "$result_json" || "$result_json" == "null" ]]; then
        return 1
    fi

    # Parse resource fields
    AI_RESOURCE_PROPERTIES_JSON="$result_json"

    if $HAS_JQ; then
        AI_RESOURCE_ID="$(echo "$result_json" | jq -r '.id // empty')"
        AI_RESOURCE_NAME="$(echo "$result_json" | jq -r '.name // empty')"
        AI_RESOURCE_RG="$(echo "$result_json" | jq -r '.resourceGroup // empty')"
        AI_RESOURCE_SUB="$(echo "$result_json" | jq -r '.subscriptionId // empty')"
        AI_RESOURCE_LOCATION="$(echo "$result_json" | jq -r '.location // empty')"

        # Extract network isolation settings
        local pub_ing pub_q
        pub_ing="$(echo "$result_json" | jq -r '.properties.publicNetworkAccessForIngestion // "Enabled"')"
        pub_q="$(echo "$result_json" | jq -r '.properties.publicNetworkAccessForQuery // "Enabled"')"
        AI_PUBLIC_INGESTION="${pub_ing:-Enabled}"
        AI_PUBLIC_QUERY="${pub_q:-Enabled}"
    else
        # Fallback (no jq): extract resource ID from ARG, then derive name/RG/sub
        # from the ID path and get location via a single ARM call.
        # This replaces 7 individual ARG queries with 1 ARG + 1 ARM call.
        _debug "Extracting AI resource ID from ARG, deriving other fields (jq not available)"
        AI_RESOURCE_ID="$(az graph query -q "$query" --query "data[0].id" -o tsv 2>/dev/null)"
        AI_RESOURCE_ID="${AI_RESOURCE_ID//$'\r'/}"

        if [[ -n "$AI_RESOURCE_ID" ]]; then
            # Parse name, resource group, and subscription from the resource ID path
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/.../components/{name}
            AI_RESOURCE_NAME="${AI_RESOURCE_ID##*/}"
            AI_RESOURCE_SUB="$(echo "$AI_RESOURCE_ID" | cut -d'/' -f3)"
            AI_RESOURCE_RG="$(echo "$AI_RESOURCE_ID" | cut -d'/' -f5)"

            # Get location from ARM (the one field not derivable from the resource ID)
            local arm_loc_url="https://management.azure.com${AI_RESOURCE_ID}?api-version=2020-02-02"
            _debug_az_rest "GET" "$arm_loc_url (--query location)"
            AI_RESOURCE_LOCATION="$(az rest --method GET --url "$arm_loc_url" --query "location" -o tsv 2>/dev/null | tr -d '\r')"
            [[ -z "$AI_RESOURCE_LOCATION" || "$AI_RESOURCE_LOCATION" == "null" || "$AI_RESOURCE_LOCATION" == "None" ]] && AI_RESOURCE_LOCATION=""
        fi

        # Default network settings -- ARM refresh (downstream) will override with live values
        AI_PUBLIC_INGESTION="Enabled"
        AI_PUBLIC_QUERY="Enabled"
    fi

    [[ -n "$AI_RESOURCE_ID" ]] && return 0 || return 1
}

# find_ampls_for_resource AI_RESOURCE_ID
#   Discovers AMPLS (Private Link Scope) resources linked to a given App Insights resource.
#   Extracts AMPLS IDs from the AI resource's PrivateLinkScopedResources property
#   (refreshed via ARM), then fetches each AMPLS resource directly via ARM.
#   Outputs AMPLS info as lines: "ID|NAME|RG|SUB|ING_MODE|Q_MODE" to stdout.
#   Returns 0 if any AMPLS found, 1 if none.
find_ampls_for_resource() {
    local ai_resource_id="$1"

    local -a found_ampls_lines=()

    # -----------------------------------------------------------------------
    # Extract AMPLS IDs from AI resource PrivateLinkScopedResources property
    # -----------------------------------------------------------------------
    local plsr_json=""
    if $HAS_JQ && [[ -n "$AI_RESOURCE_PROPERTIES_JSON" ]]; then
        plsr_json="$(echo "$AI_RESOURCE_PROPERTIES_JSON" | jq -r '.properties.PrivateLinkScopedResources // [] | .[].ResourceId // empty' 2>/dev/null)"
    else
        # No jq: use az rest --query (JMESPath) against the AI ARM URL to extract PLSR IDs
        # This avoids an ARG query and reads live data from ARM instead
        local arm_plsr_url="https://management.azure.com${ai_resource_id}?api-version=2020-02-02"
        _debug_az_rest "GET" "$arm_plsr_url (--query PLSR ResourceIds)"
        plsr_json="$(az rest --method GET --url "$arm_plsr_url" --query "properties.PrivateLinkScopedResources[].ResourceId" -o tsv 2>/dev/null | tr -d '\r')"
        _debug_response "Private Link Scope Resource IDs" "$plsr_json"
    fi

    local -a ampls_ids=()
    if [[ -n "$plsr_json" ]]; then
        while IFS= read -r scoped_id; do
            [[ -z "$scoped_id" ]] && continue
            # Extract AMPLS ID: everything before /scopedresources/
            local lower_id
            lower_id="$(echo "$scoped_id" | tr '[:upper:]' '[:lower:]')"
            local ampls_id="${lower_id%%/scopedresources/*}"
            if [[ "$ampls_id" != "$lower_id" ]]; then
                # Deduplicate
                local already=false
                for existing in "${ampls_ids[@]}"; do
                    [[ "$existing" == "$ampls_id" ]] && already=true && break
                done
                $already || ampls_ids+=("$ampls_id")
            fi
        done <<< "$plsr_json"
    fi

    if (( ${#ampls_ids[@]} == 0 )); then
        if $VERBOSE_OUTPUT; then
            _print -c "$C_GRAY" "    No AMPLS links found in App Insights resource properties." >&2
        fi
        return 1
    fi

    if $VERBOSE_OUTPUT; then
        _print -c "$C_GRAY" "    Found ${#ampls_ids[@]} AMPLS link(s) in App Insights resource properties." >&2
    fi

    # -----------------------------------------------------------------------
    # Fetch each linked AMPLS resource directly via ARM for fresh details
    # -----------------------------------------------------------------------
    for ampls_id in "${ampls_ids[@]}"; do
        local api_url="https://management.azure.com${ampls_id}?api-version=2021-07-01-preview"
        _debug_az_rest "GET" "$api_url"

        local ampls_json
        ampls_json="$(az rest --method GET --url "$api_url" 2>/dev/null | tr -d '\r')"
        _debug_response "AMPLS detail" "$ampls_json"

        if [[ -z "$ampls_json" || "$ampls_json" == "null" ]]; then
            if $VERBOSE_OUTPUT; then
                _print -c "$C_DARK_GRAY" "    [SKIP] AMPLS $ampls_id -- HTTP error (insufficient permissions?)" >&2
            fi
            continue
        fi

        local a_id="" a_name="" a_rg="" a_sub="" a_ing_mode="Unknown" a_q_mode="Unknown"
        if $HAS_JQ; then
            a_id="$(echo "$ampls_json" | jq -r '.id // empty')"
            a_name="$(echo "$ampls_json" | jq -r '.name // empty')"
            # Parse resourceGroup and subscriptionId from the ARM resource ID path
            a_sub="$(echo "$ampls_json" | jq -r '.id // empty' | sed -n 's|.*/subscriptions/\([^/]*\)/.*|\1|p')"
            a_rg="$(echo "$ampls_json" | jq -r '.id // empty' | sed -n 's|.*/resourceGroups/\([^/]*\)/.*|\1|p')"
            # Extract access modes directly from the same ARM response
            a_ing_mode="$(echo "$ampls_json" | jq -r '.properties.accessModeSettings.ingestionAccessMode // "Unknown"')"
            a_q_mode="$(echo "$ampls_json" | jq -r '.properties.accessModeSettings.queryAccessMode // "Unknown"')"
        else
            a_id="$(echo "$ampls_json" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
            a_name="$(echo "$ampls_json" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
            a_sub="$(echo "$a_id" | sed -n 's|.*/subscriptions/\([^/]*\)/.*|\1|p')"
            a_rg="$(echo "$a_id" | sed -n 's|.*/resourceGroups/\([^/]*\)/.*|\1|p')"
            # Extract access modes via grep/sed
            a_ing_mode="$(echo "$ampls_json" | grep -o '"ingestionAccessMode"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')"
            a_q_mode="$(echo "$ampls_json" | grep -o '"queryAccessMode"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')"
            [[ -z "$a_ing_mode" ]] && a_ing_mode="Unknown"
            [[ -z "$a_q_mode" ]] && a_q_mode="Unknown"
        fi

        if [[ -n "$a_id" ]]; then
            found_ampls_lines+=("${a_id}|${a_name}|${a_rg}|${a_sub}|${a_ing_mode}|${a_q_mode}")
            if $VERBOSE_OUTPUT; then
                _print -n -c "$C_GREEN" "    [MATCH] " >&2
                _print -c "$C_GRAY" "$a_name -- linked to this App Insights resource" >&2
            fi
        fi
    done

    # Output results (ONLY data lines go to stdout)
    for line in "${found_ampls_lines[@]}"; do
        echo "$line"
    done
    (( ${#found_ampls_lines[@]} > 0 )) && return 0 || return 1
}

# get_ampls_private_endpoints AMPLS_RESOURCE_ID
#   Finds private endpoints connected to an AMPLS and retrieves their DNS/IP configs.
#   Outputs lines: "PE_NAME|PE_RG|FQDN|IP_ADDRESS"
#   Returns 0 if any PE DNS configs found, 1 otherwise.
get_ampls_private_endpoints() {
    local ampls_id="$1"

    # Find private endpoints linked to this AMPLS via Resource Graph
    local query
    local safe_ampls_id
    safe_ampls_id="$(sanitize_single_quotes "$ampls_id")"
    query="resources | where type =~ 'microsoft.network/privateendpoints' | mv-expand conn = properties.privateLinkServiceConnections | where tolower(tostring(conn.properties.privateLinkServiceId)) == tolower('${safe_ampls_id}') | project id, name, resourceGroup, subscriptionId"

    local pe_json
    _debug_az_graph "$query"
    pe_json="$(az graph query -q "$query" --query "data" -o json 2>/dev/null | tr -d '\r')"
    _debug_response "Private endpoints" "$pe_json"

    if [[ -z "$pe_json" || "$pe_json" == "null" || "$pe_json" == "[]" ]]; then
        return 1
    fi

    local -a pe_ids=() pe_names=() pe_rgs=()
    if $HAS_JQ; then
        while IFS=$'\t' read -r p_id p_name p_rg; do
            [[ -z "$p_id" ]] && continue
            pe_ids+=("$p_id")
            pe_names+=("$p_name")
            pe_rgs+=("$p_rg")
        done < <(echo "$pe_json" | jq -r '.[] | [.id, .name, .resourceGroup] | @tsv' 2>/dev/null)
    else
        while IFS=$'\t' read -r p_id p_name p_rg; do
            p_id="${p_id//$'\r'/}"; p_name="${p_name//$'\r'/}"; p_rg="${p_rg//$'\r'/}"
            [[ -z "$p_id" ]] && continue
            pe_ids+=("$p_id")
            pe_names+=("$p_name")
            pe_rgs+=("$p_rg")
        done < <(az graph query -q "$query" --query "data[].[id, name, resourceGroup]" -o tsv 2>/dev/null)
    fi

    local has_output=false

    for i in "${!pe_ids[@]}"; do
        local pe_id="${pe_ids[$i]}"
        local pe_name="${pe_names[$i]}"
        local pe_rg="${pe_rgs[$i]}"

        # Get full PE resource via ARM REST to get customDnsConfigurations
        local api_url="https://management.azure.com${pe_id}?api-version=2023-11-01"
        _debug_az_rest "GET" "$api_url"
        local pe_response
        pe_response="$(az rest --method GET --url "$api_url" 2>/dev/null | tr -d '\r')" || continue
        [[ -z "$pe_response" ]] && continue

        # Extract FQDN-to-IP mappings from customDnsConfigurations
        local dns_configs_found=false
        if $HAS_JQ; then
            while IFS=$'\t' read -r fqdn ip_addr; do
                [[ -z "$fqdn" || -z "$ip_addr" ]] && continue
                echo "${pe_name}|${pe_rg}|${fqdn}|${ip_addr}"
                has_output=true
                dns_configs_found=true
            done < <(echo "$pe_response" | jq -r '.properties.customDnsConfigurations[]? | [.fqdn, (.ipAddresses[0] // "")] | @tsv' 2>/dev/null)
        else
            # Use JMESPath on az rest to extract customDnsConfigurations
            while IFS=$'\t' read -r fqdn ip_addr; do
                fqdn="${fqdn//$'\r'/}"; ip_addr="${ip_addr//$'\r'/}"
                [[ -z "$fqdn" || -z "$ip_addr" ]] && continue
                echo "${pe_name}|${pe_rg}|${fqdn}|${ip_addr}"
                has_output=true
                dns_configs_found=true
            done < <(az rest --method GET --url "$api_url" \
                --query "properties.customDnsConfigurations[].[fqdn, ipAddresses[0]]" \
                -o tsv 2>/dev/null | tr -d '\r')
        fi

        # Fallback: if customDnsConfigurations is empty, try the NIC approach
        if ! $dns_configs_found; then
            local nic_ids=""
            if $HAS_JQ; then
                nic_ids="$(echo "$pe_response" | jq -r '.properties.networkInterfaces[]?.id // empty' 2>/dev/null)"
            else
                nic_ids="$(az rest --method GET --url "$api_url" \
                    --query "properties.networkInterfaces[].id" -o tsv 2>/dev/null | tr -d '\r')"
            fi
            while IFS= read -r nic_id; do
                [[ -z "$nic_id" ]] && continue
                local nic_url="https://management.azure.com${nic_id}?api-version=2023-11-01"
                if $HAS_JQ; then
                    local nic_response
                    nic_response="$(az rest --method GET --url "$nic_url" 2>/dev/null | tr -d '\r')" || continue
                    [[ -z "$nic_response" ]] && continue
                    while IFS=$'\t' read -r ip fqdn; do
                        [[ -z "$ip" || -z "$fqdn" ]] && continue
                        echo "${pe_name}|${pe_rg}|${fqdn}|${ip}"
                        has_output=true
                    done < <(echo "$nic_response" | jq -r '.properties.ipConfigurations[]? | [.properties.privateIPAddress, (.properties.privateLinkConnectionProperties.fqdns[]? // empty)] | @tsv' 2>/dev/null)
                else
                    # NIC fallback via JMESPath - extract IP configs
                    while IFS=$'\t' read -r ip fqdn; do
                        ip="${ip//$'\r'/}"; fqdn="${fqdn//$'\r'/}"
                        [[ -z "$ip" || -z "$fqdn" ]] && continue
                        echo "${pe_name}|${pe_rg}|${fqdn}|${ip}"
                        has_output=true
                    done < <(az rest --method GET --url "$nic_url" \
                        --query "properties.ipConfigurations[].[properties.privateIPAddress, properties.privateLinkConnectionProperties.fqdns[0]]" \
                        -o tsv 2>/dev/null | tr -d '\r')
                fi
            done <<< "$nic_ids"
        fi
    done

    $has_output && return 0 || return 1
}

# show_ampls_validation_table
#   Compares Expected (AMPLS) vs Actual (DNS) IPs.
#   Reads expected mappings from stdin as lines: "FQDN|EXPECTED_IP|PE_NAME|PE_RG"
#   Uses DNS_R_* arrays as a fallback cache; also resolves FQDNs directly.
#   Outputs comparison results as lines: "FQDN|EXPECTED_IP|ACTUAL_IP|STATUS"
#   Returns 0 if no mismatches, 1 if any mismatches.
show_ampls_validation_table() {
    local -a mappings=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && mappings+=("$line")
    done

    # Build DNS cache from earlier results
    local -A dns_cache=()
    for i in "${!DNS_R_HOSTNAME[@]}"; do
        local h="${DNS_R_HOSTNAME[$i]}"
        local ip="${DNS_R_IP[$i]}"
        if [[ -n "$ip" && "${DNS_R_STATUS[$i]}" == "PASS" ]]; then
            dns_cache["${h,,}"]="$ip"
        fi
    done

    local match_count=0 mismatch_count=0 fail_count=0

    # Table header (verbose only) -- send to stderr so stdout stays clean for data
    if $VERBOSE_OUTPUT; then
        local hdr
        printf -v hdr "  %-50s %-18s %-18s %-8s" "Endpoint (FQDN)" "Expected (AMPLS)" "Actual (DNS)" "Match?"
        _print -c "$C_WHITE" "$hdr" >&2
        local sep="  $(printf '%.0s-' {1..50}) $(printf '%.0s-' {1..18}) $(printf '%.0s-' {1..18}) $(printf '%.0s-' {1..8})"
        _print -c "$C_DARK_GRAY" "$sep" >&2
    fi

    local has_mismatches=false

    for mapping in "${mappings[@]}"; do
        local IFS='|'
        local -a fields
        read -ra fields <<< "$mapping"
        local fqdn="${fields[0]}"
        local expected_ip="${fields[1]}"
        local actual_ip=""

        # Check DNS cache first (exact match)
        if [[ -n "${dns_cache[${fqdn,,}]:-}" ]]; then
            actual_ip="${dns_cache[${fqdn,,}]}"
        else
            # Resolve directly from this machine and classify failures
            local ampls_dig_raw=""
            if $HAS_DIG; then
                actual_ip="$(dig +short "$fqdn" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)"
                if [[ -z "$actual_ip" ]]; then
                    # Classify the failure
                    ampls_dig_raw="$(dig +short +time=3 +tries=1 "$fqdn" 2>&1)"
                    local ampls_dig_status
                    ampls_dig_status="$(dig +time=2 +tries=1 +noall +comments "$fqdn" 2>/dev/null \
                        | grep -i 'status:' | head -1 | sed 's/.*status: *\([A-Z]*\).*/\1/')"
                    if echo "$ampls_dig_raw" | grep -qi "connection timed out"; then
                        actual_ip="(DNS timeout)"
                    elif echo "$ampls_dig_raw" | grep -qi "connection refused"; then
                        actual_ip="(DNS refused)"
                    elif echo "$ampls_dig_raw" | grep -qi "network unreachable\|network is unreachable"; then
                        actual_ip="(DNS no route)"
                    elif [[ "$ampls_dig_status" == "NXDOMAIN" ]]; then
                        actual_ip="(NXDOMAIN)"
                    elif [[ "$ampls_dig_status" == "SERVFAIL" ]]; then
                        actual_ip="(DNS SERVFAIL)"
                    elif [[ "$ampls_dig_status" == "REFUSED" ]]; then
                        actual_ip="(DNS REFUSED)"
                    else
                        actual_ip="(DNS error)"
                    fi
                fi
            elif $HAS_NSLOOKUP; then
                local ampls_ns_output
                ampls_ns_output="$(nslookup "$fqdn" 2>&1)"
                actual_ip="$(echo "$ampls_ns_output" | awk '/^Address:/{a=$2} END{print a}' \
                    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
                if [[ -z "$actual_ip" ]]; then
                    if echo "$ampls_ns_output" | grep -qi "connection timed out"; then
                        actual_ip="(DNS timeout)"
                    elif echo "$ampls_ns_output" | grep -qi "connection refused"; then
                        actual_ip="(DNS refused)"
                    elif echo "$ampls_ns_output" | grep -qi "server can't find\|NXDOMAIN"; then
                        actual_ip="(NXDOMAIN)"
                    elif echo "$ampls_ns_output" | grep -qi "SERVFAIL\|server failure"; then
                        actual_ip="(DNS SERVFAIL)"
                    elif echo "$ampls_ns_output" | grep -qi "REFUSED"; then
                        actual_ip="(DNS REFUSED)"
                    else
                        actual_ip="(DNS error)"
                    fi
                fi
            fi
            # Clean up
            actual_ip="${actual_ip//$'\r'/}"
            actual_ip="${actual_ip%%[[:space:]]}"
        fi

        local match_status=""
        local match_color=""

        if [[ -z "$actual_ip" ]]; then
            actual_ip="(no result)"
            match_status="FAIL"
            match_color="$C_RED"
            (( fail_count++ ))
        elif [[ "$actual_ip" =~ ^\(DNS\ |^\(NXDOMAIN\)$ ]]; then
            match_status="FAIL"
            match_color="$C_RED"
            (( fail_count++ ))
        elif [[ "$actual_ip" == "$expected_ip" ]]; then
            match_status="MATCH"
            match_color="$C_GREEN"
            (( match_count++ ))
        else
            match_status="MISMATCH"
            match_color="$C_RED"
            (( mismatch_count++ ))
            has_mismatches=true
        fi

        # Display row (verbose) -- send to stderr
        if $VERBOSE_OUTPUT; then
            local d_fqdn="$fqdn" d_exp="$expected_ip" d_act="$actual_ip"
            (( ${#d_fqdn} > 50 )) && d_fqdn="${d_fqdn:0:48}.."
            (( ${#d_exp} > 18 )) && d_exp="${d_exp:0:16}.."
            (( ${#d_act} > 18 )) && d_act="${d_act:0:16}.."

            local row
            printf -v row "  %-50s %-18s %-18s " "$d_fqdn" "$d_exp" "$d_act"
            _print -n "$row" >&2
            _print -c "$match_color" "$match_status" >&2
        fi

        # Output result (data goes to stdout)
        echo "${fqdn}|${expected_ip}|${actual_ip}|${match_status}"
    done

    if $VERBOSE_OUTPUT; then
        local sep="  $(printf '%.0s-' {1..50}) $(printf '%.0s-' {1..18}) $(printf '%.0s-' {1..18}) $(printf '%.0s-' {1..8})"
        _print -c "$C_DARK_GRAY" "$sep" >&2
    fi

    $has_mismatches && return 1 || return 0
}


# ============================================================================
# KNOWN ISSUE CHECKS
# ============================================================================
# 7 sub-checks using az rest / az graph query (all read-only):
# 1. Local authentication disabled (Entra ID required)
# 2. Ingestion sampling percentage
# 3. Backend workspace health (deleted/suspended)
# 4. Log Analytics daily cap (OverQuota)
# 5. AI daily cap vs LA daily cap mismatch
# 6. Diagnostic settings duplicating telemetry
# 7. DCR workspace transforms on AI tables
# ============================================================================

# State variables set by known issue checks, consumed by ingestion/E2E steps
LOCAL_AUTH_DISABLED=false
WS_RESOURCE_ID=""
WS_NAME="(unknown)"
WS_CAP_QUOTA_GB=""
WS_CAP_OFF=true
AI_CAP_GB=""
AI_CAP_OFF=false

# AI properties extracted from ARM refresh (single source of truth after ARM call)
AI_DISABLE_LOCAL_AUTH=""
AI_SAMPLING_PCT=""
AI_APP_ID=""
AI_WORKSPACE_RESOURCE_ID=""


# ============================================================================
# DATA PLANE QUERY FUNCTIONS (E2E VERIFICATION)
# ============================================================================
# These functions query the App Insights data plane API to verify telemetry
# arrived and to run diagnostic KQL queries. They require an active az CLI
# session and Reader access to the App Insights resource.
# All operations are READ-ONLY queries against logged telemetry data.
# ============================================================================

# get_data_plane_token [RESOURCE_URL]
#   Acquires a bearer token for the App Insights data plane API.
#   RESOURCE_URL defaults to https://api.applicationinsights.io (Public).
#   Gov: https://api.applicationinsights.us  |  China: https://api.applicationinsights.azure.cn
#   Outputs the token string on stdout, or empty on failure.
get_data_plane_token() {
    local resource_url="${1:-https://api.applicationinsights.io}"
    _debug "az account get-access-token --resource \"$resource_url\""
    local token
    token="$(az account get-access-token --resource "$resource_url" --query accessToken -o tsv 2>/dev/null | tr -d '\r')"
    if [[ -n "$token" ]]; then
        _debug "<<< Token acquired (${#token} chars)"
    else
        _debug "<<< Token acquisition failed"
    fi
    echo "$token"
}

# invoke_data_plane_query APP_ID TOKEN KQL [POLL_ATTEMPT] [API_HOST]
#   Executes a KQL query against the App Insights data plane API.
#   API_HOST defaults to api.applicationinsights.io (Public).
#   Sets global E2E_QUERY_* variables with results.
#   Returns 0 on success, 1 on transient error, 2 on non-transient error.
E2E_QUERY_SUCCESS=false
E2E_QUERY_ROWS=""
E2E_QUERY_ERROR=""
E2E_QUERY_HTTP_STATUS=0
E2E_QUERY_ROW_COUNT=0

invoke_data_plane_query() {
    local app_id="$1"
    local token="$2"
    local kql="$3"
    local poll_attempt="${4:-0}"
    local api_host="${5:-api.applicationinsights.io}"

    E2E_QUERY_SUCCESS=false
    E2E_QUERY_ROWS=""
    E2E_QUERY_ERROR=""
    E2E_QUERY_HTTP_STATUS=0
    E2E_QUERY_ROW_COUNT=0

    local api_url="https://${api_host}/v1/apps/${app_id}/query"

    # Cache-bust: append unique KQL comment per poll attempt
    local effective_kql="$kql"
    if (( poll_attempt > 0 )); then
        local ts_comment
        ts_comment="$(date -u '+%H%M%S')"
        effective_kql="${kql}
// poll-${poll_attempt}-${ts_comment}"
    fi

    # Build JSON body -- escape any double quotes in KQL
    local escaped_kql="${effective_kql//\"/\\\"}"
    # Also escape newlines for JSON
    escaped_kql="${escaped_kql//$'\n'/\\n}"
    local body="{\"query\":\"${escaped_kql}\"}"

    _debug_request "POST" "$api_url" "$effective_kql"

    local response_file
    response_file="$(mktemp /tmp/e2e_resp_XXXXXX)"

    local http_code
    http_code="$(curl -s -w "%{http_code}" -o "$response_file" \
        --tlsv1.2 \
        -X POST "$api_url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -H "Cache-Control: no-cache" \
        -H "Pragma: no-cache" \
        --connect-timeout 10 \
        --max-time 30 \
        -d "$body" 2>/dev/null)"

    E2E_QUERY_HTTP_STATUS="$http_code"

    local response_body=""
    [[ -f "$response_file" ]] && response_body="$(cat "$response_file" 2>/dev/null)"
    rm -f "$response_file" 2>/dev/null

    _debug_response "HTTP $http_code" "$response_body"

    if [[ "$http_code" == "200" ]]; then
        E2E_QUERY_SUCCESS=true
        # Extract rows from the response
        if $HAS_JQ; then
            E2E_QUERY_ROWS="$(echo "$response_body" | jq -r '.tables[0].rows // [] | .[] | @tsv' 2>/dev/null)"
            E2E_QUERY_ROW_COUNT="$(echo "$response_body" | jq -r '.tables[0].rows // [] | length' 2>/dev/null)"
            [[ "$E2E_QUERY_ROW_COUNT" == "null" || -z "$E2E_QUERY_ROW_COUNT" ]] && E2E_QUERY_ROW_COUNT=0
        else
            # Without jq: extract row data using grep/sed
            # API response format: {"tables":[{"columns":[...],"rows":[["ts1","ts2","ts3"]]}]}
            # Check if rows array has data (not empty)
            if echo "$response_body" | grep -q '"rows"' 2>/dev/null; then
                # Extract the first row's values
                # Look for pattern: "rows":[["val1","val2","val3"]]
                local row_data
                row_data="$(echo "$response_body" | sed -n 's/.*"rows":\[\["\([^]]*\)\]\].*/\1/p' 2>/dev/null)"
                if [[ -n "$row_data" ]]; then
                    # Convert "ts1","ts2","ts3" to tab-separated
                    E2E_QUERY_ROWS="$(echo "$row_data" | sed 's/","/'$'\t''/g; s/"//g')"
                fi
                # If sed couldn't extract but rows exist and aren't empty
                if [[ -z "$E2E_QUERY_ROWS" ]]; then
                    # Check if rows is non-empty (not "rows":[] or "rows":[[]])
                    if echo "$response_body" | grep -qE '"rows":\[\[' 2>/dev/null; then
                        E2E_QUERY_ROWS="has_data"
                    fi
                fi
                # Estimate row count without jq: count "],[ separators in the rows array
                if [[ -n "$E2E_QUERY_ROWS" ]]; then
                    local sep_count
                    sep_count="$(echo "$response_body" | grep -o '\],\[' 2>/dev/null | wc -l | tr -d ' ')"
                    E2E_QUERY_ROW_COUNT=$(( sep_count + 1 ))
                fi
            fi
        fi
        return 0
    else
        # Extract error message
        if $HAS_JQ && [[ -n "$response_body" ]]; then
            local api_error
            api_error="$(echo "$response_body" | jq -r '.error.message // .error.code // empty' 2>/dev/null)"
            [[ -n "$api_error" ]] && E2E_QUERY_ERROR="$api_error" || E2E_QUERY_ERROR="HTTP $http_code"
        else
            E2E_QUERY_ERROR="HTTP $http_code"
        fi

        # Classify: non-transient errors should NOT be retried
        case "$http_code" in
            400|401|403|404)
                return 2  # non-transient
                ;;
            *)
                return 1  # transient (throttling, server errors, timeouts)
                ;;
        esac
    fi
}

# test_e2e_verification APP_ID TOKEN TEST_RECORD_ID [MAX_WAIT_SEC] [POLL_INTERVAL_SEC] [API_HOST]
#   Polls the data plane API to verify the test record arrived.
#   Sets global E2E_* result variables.
E2E_STATUS=""                  # PASS, TIMEOUT, SKIPPED, ERROR (empty = not run)
E2E_RECORD_FOUND=false
E2E_POLL_ATTEMPTS=0
E2E_WAITED_SECONDS=0
E2E_ERROR=""
E2E_DUPLICATE_COUNT=0
# Latency breakdown (populated on PASS)
E2E_LATENCY_SENT=""
E2E_LATENCY_RECEIVED=""
E2E_LATENCY_INGESTED=""
E2E_LATENCY_CLIENT_TO_PIPELINE=""
E2E_LATENCY_PIPELINE_TO_STORE=""
E2E_LATENCY_E2E=""

test_e2e_verification() {
    local app_id="$1"
    local token="$2"
    local test_record_id="$3"
    local max_wait="${4:-60}"
    local poll_interval="${5:-10}"
    local api_host="${6:-api.applicationinsights.io}"
    local show_polling="${7:-true}"  # Show poll progress lines (false in compact mode)

    E2E_STATUS="ERROR"
    E2E_RECORD_FOUND=false
    E2E_DUPLICATE_COUNT=0
    E2E_POLL_ATTEMPTS=0
    E2E_WAITED_SECONDS=0
    E2E_ERROR=""
    E2E_LATENCY_SENT=""
    E2E_LATENCY_RECEIVED=""
    E2E_LATENCY_INGESTED=""
    E2E_LATENCY_CLIENT_TO_PIPELINE=""
    E2E_LATENCY_PIPELINE_TO_STORE=""
    E2E_LATENCY_E2E=""

    # KQL to find the exact test record with latency columns
    # No 'take 1' -- we return all copies so we can detect duplicates
    # caused by Diagnostic Settings exporting to Log Analytics.
    local kql="availabilityResults
| where customDimensions.diagnosticRunId == '${test_record_id}'
| project timestamp, _TimeReceived, ingestion_time()"

    local total_max_checks=$(( (max_wait + poll_interval - 1) / poll_interval ))
    local start_epoch
    start_epoch="$(get_ms_timestamp)"

    # --- Parse latency from a TSV row ---
    _parse_e2e_latency() {
        local row="$1"
        [[ -z "$row" || "$row" == "has_data" ]] && return 1

        # Row format (tab-separated): timestamp \t _TimeReceived \t ingestion_time()
        local ts_str tr_str ig_str
        IFS=$'\t' read -r ts_str tr_str ig_str <<< "$row"

        [[ -z "$ts_str" || -z "$tr_str" || -z "$ig_str" ]] && return 1

        # Normalize Azure ISO timestamps for GNU date:
        # Azure returns e.g. "2026-02-22T05:20:06.1234567Z"
        # GNU date handles up to 6 fractional digits but chokes on 7+.
        # Truncate to 3 fractional digits (milliseconds) for safe parsing.
        _normalize_ts() {
            local ts="$1"
            # Strip trailing Z, split on dot, truncate frac to 3 chars, reassemble
            ts="${ts%Z}"
            if [[ "$ts" == *"."* ]]; then
                local base="${ts%%.*}"
                local frac="${ts#*.}"
                frac="${frac:0:3}"
                echo "${base}.${frac}Z"
            else
                echo "${ts}Z"
            fi
        }

        local ts_norm tr_norm ig_norm
        ts_norm="$(_normalize_ts "$ts_str")"
        tr_norm="$(_normalize_ts "$tr_str")"
        ig_norm="$(_normalize_ts "$ig_str")"

        # Convert ISO timestamps to epoch seconds
        local ts_epoch tr_epoch ig_epoch
        ts_epoch="$(date -d "$ts_norm" '+%s' 2>/dev/null || date -d "$ts_str" '+%s' 2>/dev/null || echo "")"
        tr_epoch="$(date -d "$tr_norm" '+%s' 2>/dev/null || date -d "$tr_str" '+%s' 2>/dev/null || echo "")"
        ig_epoch="$(date -d "$ig_norm" '+%s' 2>/dev/null || date -d "$ig_str" '+%s' 2>/dev/null || echo "")"

        # macOS fallback (BSD date)
        if [[ -z "$ts_epoch" ]]; then
            local ts_base="${ts_str%%.*}"
            ts_base="${ts_base%Z}"
            ts_epoch="$(date -j -f '%Y-%m-%dT%H:%M:%S' "$ts_base" '+%s' 2>/dev/null || echo "")"
        fi
        if [[ -z "$tr_epoch" ]]; then
            local tr_base="${tr_str%%.*}"
            tr_base="${tr_base%Z}"
            tr_epoch="$(date -j -f '%Y-%m-%dT%H:%M:%S' "$tr_base" '+%s' 2>/dev/null || echo "")"
        fi
        if [[ -z "$ig_epoch" ]]; then
            local ig_base="${ig_str%%.*}"
            ig_base="${ig_base%Z}"
            ig_epoch="$(date -j -f '%Y-%m-%dT%H:%M:%S' "$ig_base" '+%s' 2>/dev/null || echo "")"
        fi

        if [[ -n "$ts_epoch" && -n "$tr_epoch" && -n "$ig_epoch" ]]; then
            E2E_LATENCY_SENT="$ts_str"
            E2E_LATENCY_RECEIVED="$tr_str"
            E2E_LATENCY_INGESTED="$ig_str"
            E2E_LATENCY_CLIENT_TO_PIPELINE="$(( tr_epoch - ts_epoch ))"
            E2E_LATENCY_PIPELINE_TO_STORE="$(( ig_epoch - tr_epoch ))"
            E2E_LATENCY_E2E="$(( ig_epoch - ts_epoch ))"
        fi
    }

    # --- Immediate first attempt (no wait) ---
    E2E_POLL_ATTEMPTS=1
    [[ "$show_polling" == "true" ]] && _print -n -c "$C_DARK_GRAY" "  [0s] Querying... "

    invoke_data_plane_query "$app_id" "$token" "$kql" 1 "$api_host"
    local rc=$?

    if (( rc == 0 )) && [[ -n "$E2E_QUERY_ROWS" ]]; then
        # Record found on first try!
        E2E_DUPLICATE_COUNT=$E2E_QUERY_ROW_COUNT
        local found_label="found!"
        (( E2E_DUPLICATE_COUNT > 1 )) && found_label="found (${E2E_DUPLICATE_COUNT} copies)!"
        [[ "$show_polling" == "true" ]] && _print -c "$C_GREEN" "$found_label"
        E2E_STATUS="PASS"
        E2E_RECORD_FOUND=true
        local now_epoch
        now_epoch="$(get_ms_timestamp)"
        E2E_WAITED_SECONDS="$(( (now_epoch - start_epoch) / 1000 ))"

        # Parse latency from first row
        local first_row
        first_row="$(echo "$E2E_QUERY_ROWS" | head -1)"
        _parse_e2e_latency "$first_row"
        return 0
    elif (( rc == 0 )); then
        [[ "$show_polling" == "true" ]] && _print -c "$C_DARK_GRAY" "not yet available"
    elif (( rc == 2 )); then
        # Non-transient error -- bail immediately
        [[ "$show_polling" == "true" ]] && _print -c "$C_RED" "query error"
        [[ "$show_polling" == "true" ]] && $VERBOSE_OUTPUT && _print -c "$C_DARK_GRAY" "      Error: $E2E_QUERY_ERROR"
        E2E_STATUS="ERROR"
        E2E_ERROR="$E2E_QUERY_ERROR"
        local now_epoch
        now_epoch="$(get_ms_timestamp)"
        E2E_WAITED_SECONDS="$(( (now_epoch - start_epoch) / 1000 ))"
        return 1
    else
        [[ "$show_polling" == "true" ]] && _print -c "$C_DARK_GRAY" "query error (will retry)"
        E2E_ERROR="$E2E_QUERY_ERROR"
    fi

    # --- Polling loop ---
    local attempt
    for (( attempt = 2; attempt <= total_max_checks; attempt++ )); do
        # Wait interval
        sleep "$poll_interval"

        E2E_POLL_ATTEMPTS="$attempt"
        local now_epoch
        now_epoch="$(get_ms_timestamp)"
        local elapsed_s=$(( (now_epoch - start_epoch) / 1000 ))

        [[ "$show_polling" == "true" ]] && _print -n -c "$C_DARK_GRAY" "  [${elapsed_s}s] Querying... "

        invoke_data_plane_query "$app_id" "$token" "$kql" "$attempt" "$api_host"
        local rc=$?

        if (( rc != 0 )); then
            [[ "$show_polling" == "true" ]] && _print -c "$C_RED" "query error"
            [[ "$show_polling" == "true" ]] && $VERBOSE_OUTPUT && _print -c "$C_DARK_GRAY" "      Error: $E2E_QUERY_ERROR"
            E2E_ERROR="$E2E_QUERY_ERROR"

            if (( rc == 2 )); then
                # Non-transient -- stop polling
                E2E_STATUS="ERROR"
                now_epoch="$(get_ms_timestamp)"
                E2E_WAITED_SECONDS="$(( (now_epoch - start_epoch) / 1000 ))"
                [[ "$show_polling" == "true" ]] && _print -c "$C_YELLOW" "  [!] Non-transient error -- skipping remaining poll attempts."
                return 1
            fi
            continue  # Transient -- keep trying
        fi

        if [[ -n "$E2E_QUERY_ROWS" ]]; then
            # Record found!
            E2E_DUPLICATE_COUNT=$E2E_QUERY_ROW_COUNT
            local found_label="FOUND"
            (( E2E_DUPLICATE_COUNT > 1 )) && found_label="FOUND (${E2E_DUPLICATE_COUNT} copies)"
            [[ "$show_polling" == "true" ]] && _print -c "$C_GREEN" "$found_label"
            E2E_STATUS="PASS"
            E2E_RECORD_FOUND=true
            now_epoch="$(get_ms_timestamp)"
            E2E_WAITED_SECONDS="$(( (now_epoch - start_epoch) / 1000 ))"

            local first_row
            first_row="$(echo "$E2E_QUERY_ROWS" | head -1)"
            _parse_e2e_latency "$first_row"
            return 0
        else
            [[ "$show_polling" == "true" ]] && _print -c "$C_DARK_GRAY" "not yet available"
        fi
    done

    # Exhausted all attempts
    E2E_STATUS="TIMEOUT"
    local now_epoch
    now_epoch="$(get_ms_timestamp)"
    E2E_WAITED_SECONDS="$(( (now_epoch - start_epoch) / 1000 ))"
    return 1
}


# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"
    check_bash_version
    detect_color_support
    setup_colors

    # --- Environment detection (needed by banner) ---
    get_environment_info

    local is_non_interactive=false
    if ($ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP || $ENV_IS_KUBERNETES) && ! $ENV_IS_CLOUD_SHELL; then
        is_non_interactive=true
    fi

    # ---- Consent gate infrastructure ----
    local azure_consent_declined=false
    local ingestion_consent_declined=false

    # --- Tool availability ---
    check_tool_availability
    check_azure_cli

    # ================================================================
    # BANNER (always)
    # ================================================================
    _print ""
    _print -c "$C_WHITE" "  ======================================================================"
    _print -c "$C_WHITE" "   Application Insights Telemetry Flow Diagnostics  v${SCRIPT_VERSION}  (bash)"
    if $COMPACT; then
        _print -c "$C_GRAY" "   Output: Compact (progress lines only)"
    fi
    if $NETWORK_ONLY; then
        _print -c "$C_GRAY" "   Azure: Resource checks skipped (--network-only)"
    elif $CHECK_AZURE && $AZ_LOGGED_IN; then
        local acct
        acct="$(az account show --query 'user.name' -o tsv 2>/dev/null || echo unknown)"
        acct="${acct//$'\r'/}"   # Strip \r from WSL/Windows az CLI output
        acct="$(mask_email "$acct")"
        _print -c "$C_GRAY" "   Azure: Active (logged in as $acct)"
    elif $CHECK_AZURE && ! $AZ_LOGGED_IN && $is_non_interactive; then
        local host_type="Azure PaaS"
        $ENV_IS_APP_SERVICE  && host_type="App Service"
        $ENV_IS_FUNCTION_APP && host_type="Function App"
        $ENV_IS_CONTAINER_APP && host_type="Container Apps"
        $ENV_IS_KUBERNETES   && host_type="AKS"
        _print -c "$C_YELLOW" "   Azure: Not logged in ($host_type -- run from local machine for Azure checks)"
    elif $CHECK_AZURE && ! $AZ_LOGGED_IN; then
        _print -c "$C_YELLOW" "   Azure: Not logged in (run 'az login' first, or use --network-only)"
    else
        _print -c "$C_GRAY" "   Azure: Resource checks skipped (az CLI not found)"
    fi
    if ! $USE_COLOR; then
        _print "   Console: Plain text mode (no color support detected)"
    fi
    if $AUTO_APPROVE; then
        _print -c "$C_GRAY" "   Consent: Auto-approved (--auto-approve)"
    elif $is_non_interactive; then
        _print -c "$C_YELLOW" "   Consent: Non-interactive (Azure login operations will be skipped)"
    else
        _print -c "$C_GRAY" "   Consent: Y/N prompts ahead (use --auto-approve to bypass)"
    fi
    _print -c "$C_WHITE" "  ======================================================================"

    # ================================================================
    # STEP 1: ENVIRONMENT DETECTION
    # ================================================================
    (( STEP_NUMBER++ ))

    if $VERBOSE_OUTPUT; then
        write_header_always "STEP $STEP_NUMBER: Environment Detection"
        _print ""
        _print -c "$C_CYAN" "  WHY THIS MATTERS:"
        _print -c "$C_GRAY" "  Understanding where this script is running helps interpret network behavior."
        _print -c "$C_GRAY" "  Azure PaaS services (App Service, Functions) have different networking than VMs or containers."
        _print ""
        _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
        _print -c "$C_GRAY" "  - Host machine identity and OS type"
        _print -c "$C_GRAY" "  - Azure PaaS environment (App Service, Function App, AKS)"
        _print -c "$C_GRAY" "  - Container runtime detection"
        _print -c "$C_GRAY" "  - Proxy configuration (environment variables)"
        _print -c "$C_GRAY" "  - Presence of connection string in environment variables"
        _print ""

        write_result "INFO" "Host: $ENV_COMPUTER_NAME" "OS: $ENV_OS | Bash: $ENV_BASH_VERSION"
        if [[ -n "$ENV_AZURE_HOST_TYPE" ]]; then
            local az_detail="$ENV_AZURE_HOST_TYPE"
            [[ -n "$ENV_AZURE_HOST_DETAIL" ]] && az_detail+=" | $ENV_AZURE_HOST_DETAIL"
            write_result "INFO" "Azure host detected" "$az_detail"
        fi
        if $ENV_IS_CONTAINER && ! $ENV_IS_CONTAINER_APP; then
            write_result "INFO" "Container environment detected"
        fi
    fi

    # --- Proxy detection ---
    local proxy_detected=false
    local -a proxy_details=()

    local proxy_env_vars=("HTTP_PROXY" "HTTPS_PROXY" "http_proxy" "https_proxy" "NO_PROXY" "no_proxy")
    for pvar in "${proxy_env_vars[@]}"; do
        local pval="${!pvar:-}"
        if [[ -n "$pval" ]]; then
            proxy_detected=true
            proxy_details+=("  Env: $pvar = $pval")
        fi
    done

    if $proxy_detected; then
        write_progress_line "Proxy Detection" "INFO" "Proxy configuration detected (see details)"
        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_YELLOW" "  PROXY CONFIGURATION DETECTED:"
            for pd in "${proxy_details[@]}"; do
                _print -c "$C_GRAY" "  $pd"
            done
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "    Proxies can intercept, modify, or block telemetry traffic to Azure Monitor."
            _print ""
            _print -c "$C_CYAN" "  IF YOU SEE CONNECTIVITY FAILURES BELOW:"
            _print -c "$C_GRAY" "    Verify your proxy allows traffic to these domains:"
            _print -c "$C_WHITE" "      *.applicationinsights.azure.com"
            _print -c "$C_WHITE" "      *.monitor.azure.com"
            _print -c "$C_WHITE" "      *.services.visualstudio.com"
            _print -c "$C_WHITE" "      *.in.applicationinsights.azure.com"
            _print ""
            _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"
        fi
    else
        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_DARK_GRAY" "  [i] No proxy configuration detected."
        fi
    fi

    # ================================================================
    # STEP 2: CONNECTION STRING VALIDATION
    # ================================================================
    (( STEP_NUMBER++ ))

    if $VERBOSE_OUTPUT; then
        write_header_always "STEP $STEP_NUMBER: Connection String Validation"
        _print ""
        _print -c "$C_CYAN" "  WHY THIS MATTERS:"
        _print -c "$C_GRAY" "  The connection string tells your SDK where to send telemetry. It contains:"
        _print -c "$C_GRAY" "    - InstrumentationKey: Unique identifier for your App Insights resource"
        _print -c "$C_GRAY" "    - IngestionEndpoint: Regional URL where telemetry is sent"
        _print -c "$C_GRAY" "    - LiveEndpoint: URL for real-time Live Metrics streaming"
        _print ""
        _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
        _print -c "$C_GRAY" "  - Connection string is present (provided or in environment variable)"
        _print -c "$C_GRAY" "  - Required components can be parsed"
        _print -c "$C_GRAY" "  - Regional endpoints are identified for targeted testing"
        _print ""
    fi

    # Resolve connection string: parameter > environment variable
    if [[ -z "$CONNECTION_STRING" ]]; then
        if [[ -n "$ENV_DETECTED_CONN_STRING" ]]; then
            CONNECTION_STRING="$ENV_DETECTED_CONN_STRING"
            write_result "PASS" "Connection string found in environment variable"
        else
            _print ""
            _print -c "$C_RED" "  [ERROR] No connection string found."
            _print -c "$C_YELLOW" "  Provide --connection-string parameter or set APPLICATIONINSIGHTS_CONNECTION_STRING env variable."
            _print ""
            exit 1
        fi
    else
        write_result "PASS" "Connection string provided via parameter"
    fi

    parse_connection_string "$CONNECTION_STRING"

    if [[ -z "$CS_IKEY" ]]; then
        _print -c "$C_RED" "  [ERROR] InstrumentationKey not found in connection string."
        _print -c "$C_YELLOW" "  Get it from Azure Portal > App Insights > Overview > Connection String."
        exit 1
    fi

    # SDL: Validate iKey is a well-formed GUID
    if ! validate_ikey_format "$CS_IKEY"; then
        _print -c "$C_RED" "  [ERROR] InstrumentationKey is not a valid GUID format."
        _print -c "$C_YELLOW" "  Expected format: 00000000-0000-0000-0000-000000000000"
        _print -c "$C_YELLOW" "  Get it from Azure Portal > App Insights > Overview > Connection String."
        exit 1
    fi

    local masked_key
    masked_key="$(mask_ikey "$CS_IKEY")"
    write_result "PASS" "InstrumentationKey: $masked_key"

    local ingestion_endpoint="$CS_INGESTION_ENDPOINT"
    local live_endpoint="$CS_LIVE_ENDPOINT"

    # SDL: Validate endpoints against Azure Monitor SSRF allowlist
    local _ep _ep_label
    for _ep_label in "IngestionEndpoint" "LiveEndpoint"; do
        if [[ "$_ep_label" == "IngestionEndpoint" ]]; then
            _ep="$ingestion_endpoint"
        else
            _ep="$live_endpoint"
        fi
        if [[ -n "$_ep" ]]; then
            if ! validate_azure_monitor_endpoint "$_ep"; then
                _print -c "$C_RED" "  [ERROR] $_ep_label failed SSRF validation: $_ep"
                _print -c "$C_YELLOW" "  Only HTTPS Azure Monitor endpoints are permitted."
                exit 1
            fi
        fi
    done

    # ---- Cloud detection ----
    # Derive which Azure cloud we're targeting from the IngestionEndpoint domain.
    # This drives endpoint construction for DNS/TCP checks, data plane API, and troubleshooting guidance.
    local cloud_suffix="com"   # Default: Public cloud
    local cloud_label="Public"
    if [[ "$ingestion_endpoint" =~ \.azure\.us ]]; then
        cloud_suffix="us"
        cloud_label="US Government"
    elif [[ "$ingestion_endpoint" =~ \.azure\.cn ]]; then
        cloud_suffix="cn"
        cloud_label="China (21Vianet)"
    elif [[ -n "$CS_ENDPOINT_SUFFIX" ]]; then
        # Fallback: check EndpointSuffix if IngestionEndpoint didn't reveal the cloud
        if [[ "$CS_ENDPOINT_SUFFIX" =~ \.us$|\.azure\.us ]]; then
            cloud_suffix="us"
            cloud_label="US Government"
        elif [[ "$CS_ENDPOINT_SUFFIX" =~ \.cn$|\.azure\.cn ]]; then
            cloud_suffix="cn"
            cloud_label="China (21Vianet)"
        fi
    fi

    # Cloud-specific service domains
    local domain_appinsights="applicationinsights.azure.${cloud_suffix}"   # e.g. applicationinsights.azure.com
    local domain_monitor="monitor.azure.${cloud_suffix}"                   # e.g. monitor.azure.com
    local domain_privatelink="privatelink.monitor.azure.${cloud_suffix}"   # e.g. privatelink.monitor.azure.com

    # Data plane API (E2E verification)
    local data_plane_host
    local data_plane_resource
    case "$cloud_suffix" in
        us) data_plane_host="api.applicationinsights.us" ;;
        cn) data_plane_host="api.applicationinsights.azure.cn" ;;
        *)  data_plane_host="api.applicationinsights.io" ;;
    esac
    data_plane_resource="https://${data_plane_host}"

    if [[ -z "$ingestion_endpoint" ]]; then
        if [[ "$cloud_suffix" == "com" ]]; then
            write_result "INFO" "No IngestionEndpoint in connection string -- using global default" \
                "This may indicate an older instrumentation key format without regional endpoints." \
                "Update to a full connection string from App Insights > Overview."
            ingestion_endpoint="https://dc.services.visualstudio.com"
        else
            write_result "INFO" "No IngestionEndpoint in connection string -- using global default for ${cloud_label} cloud" \
                "Using the global ingestion endpoint for the ${cloud_label} cloud." \
                "Consider updating to a full connection string from App Insights > Overview for best reliability."
            ingestion_endpoint="https://dc.${domain_appinsights}"
        fi
    fi

    # Detect global/legacy endpoint
    local is_global_endpoint=false
    if [[ "$ingestion_endpoint" =~ dc\.services\.visualstudio\.com|dc\.applicationinsights\.azure\.(com|us|cn) ]]; then
        is_global_endpoint=true
    fi

    write_result "INFO" "Ingestion Endpoint: $ingestion_endpoint"
    [[ -n "$live_endpoint" ]] && write_result "INFO" "Live Metrics Endpoint: $live_endpoint"
    [[ "$cloud_suffix" != "com" ]] && write_result "INFO" "Azure Cloud: $cloud_label (endpoint suffix: .$cloud_suffix)"

    # Flag global endpoint usage
    if $is_global_endpoint; then
        write_progress_line "Endpoint Type" "INFO" "Global/legacy endpoint (regional recommended)"
        add_diagnosis "INFO" "Using Global/Legacy Ingestion Endpoint" \
            "Using global endpoint instead of regional (adds latency)" \
            "Your connection string routes telemetry through the global endpoint ($ingestion_endpoint) instead of a regional endpoint. Global endpoints relay to regional, adding latency." \
            "Update to a regional connection string from Azure Portal." \
            "App Insights > Overview > Connection String" \
            "https://learn.microsoft.com/azure/azure-monitor/app/sdk-connection-string"

        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_YELLOW" "  [!] GLOBAL/LEGACY ENDPOINT DETECTED"
            _print -c "$C_GRAY" "  Your ingestion endpoint ($ingestion_endpoint) is the global/legacy endpoint."
            _print -c "$C_GRAY" "  This is NOT recommended for production workloads:"
            _print -c "$C_GRAY" "    - Global endpoints relay to regional, adding network hops and latency"
            _print -c "$C_GRAY" "    - Regional endpoints are required for full support from Microsoft"
            _print -c "$C_GRAY" "    - Connection strings with regional endpoints are the modern standard"
            _print ""
            _print -c "$C_CYAN" "  UPDATE: Get the full connection string from Azure Portal > App Insights > Overview"
            _print -c "$C_DARK_GRAY" "  It will look like: InstrumentationKey=xxx;IngestionEndpoint=https://{region}.in.applicationinsights.azure.com/;..."
            _print ""
        fi
    fi

    # Extract hostname from ingestion endpoint
    local ingestion_host
    ingestion_host="$(extract_host_from_url "$ingestion_endpoint")"

    # ---- Resource Header (always) ----
    _print ""
    _print -c "$C_DARK_GRAY" "  ----------------------------------------------------------------"
    _print -n -c "$C_GRAY" "  iKey:     "
    _print -n -c "$C_WHITE" "$masked_key"
    if [[ "$cloud_suffix" != "com" ]]; then
        _print -n -c "$C_GRAY" " | Cloud: "
        _print -c "$C_CYAN" "$cloud_label"
    else
        _print ""
    fi
    _print -n -c "$C_GRAY" "  Endpoint: "
    _print -c "$C_WHITE" "$ingestion_host"
    _print -n -c "$C_GRAY" "  Host:     "
    _print -c "$C_WHITE" "$ENV_COMPUTER_NAME ($ENV_OS)"
    if [[ -n "$ENV_AZURE_HOST_TYPE" ]]; then
        _print -n -c "$C_GRAY" "  Azure:    "
        _print -n -c "$C_CYAN" "$ENV_AZURE_HOST_TYPE"
        if [[ -n "$ENV_AZURE_HOST_DETAIL" ]]; then
            _print -c "$C_DARK_GRAY" " | $ENV_AZURE_HOST_DETAIL"
        else
            _print ""
        fi
    fi
    _print -c "$C_DARK_GRAY" "  ----------------------------------------------------------------"
    _print ""

    if ! $VERBOSE_OUTPUT; then
        # Compact mode: consent prompts appear before the clean progress table
        if $CHECK_AZURE && ! $NETWORK_ONLY; then
            if ! request_user_consent \
                --requires-azure-login \
                "AZURE RESOURCE CHECKS -- YOUR CONSENT IS REQUIRED" \
                "To skip Azure resource checks entirely, press N or re-run with --network-only." \
                "Proceed with Azure resource checks? [Y/N]" \
                "" \
                "Some of the checks in this script require access to your Azure resources." \
                "You will be asked to sign in to Azure if you are not already" \
                "authenticated -- all queries run as YOU, using your own account" \
                "and permissions. No resources will be modified." \
                "" \
                "What your account will be used to query:" \
                "" \
                "  * Azure Resource Graph -- locate your App Insights resource and" \
                "    any AMPLS private link scope linked to it. Discover any workspace" \
                "    transform data collection rules that may impact App Insights telemetry" \
                "" \
                "  * ARM REST API (read-only) -- inspect AMPLS access modes, private" \
                "    endpoint DNS config, daily cap settings, diagnostic settings," \
                "    and Log Analytics workspace state" \
                "" \
                "  * Data plane (conditional) -- if a test telemetry record is sent and" \
                "    successfully accepted by the ingestion endpoint, a single KQL" \
                "    query will confirm whether the record arrived in your workspace"; then
                CHECK_AZURE=false
                azure_consent_declined=true
            fi
        fi
        if ! $SKIP_INGESTION_TEST; then
            if ! request_user_consent \
                "TELEMETRY INGESTION TEST -- YOUR CONSENT IS REQUIRED" \
                "To skip this test, press N or re-run with --skip-ingestion-test." \
                "Send test telemetry record? [Y/N]" \
                "" \
                "To verify end-to-end ingestion, this test will send ONE small" \
                "availability record directly to your Application Insights resource." \
                "" \
                "What will be sent:" \
                "" \
                "  - Record type:  AvailabilityResult" \
                "  - Record name:  'Telemetry-Flow-Diag Ingestion Validation'" \
                "  - Payload size: ~0.5 KB" \
                "  - Sent from:    this machine ($ENV_COMPUTER_NAME) -> your ingestion endpoint" \
                "  - Sent as:      anonymous telemetry -- no sign-in required" \
                "" \
                "Cost: Standard ingestion and data retention rates apply." \
                "For a single telemetry record this is negligible."; then
                ingestion_consent_declined=true
            fi
        fi
        _print -c "$C_GRAY" "  Running diagnostics..."
        _print ""
    fi

    # ================================================================
    # BUILD ENDPOINT LIST (shared by DNS, TCP, TLS steps)
    # ================================================================
    local -a EP_CATEGORIES=()
    local -a EP_HOSTNAMES=()
    local -a EP_CRITICAL=()

    add_endpoint() {
        EP_CATEGORIES+=("$1")
        EP_HOSTNAMES+=("$2")
        EP_CRITICAL+=("$3")
    }

    # Ingestion
    add_endpoint "Ingestion (Regional)" "$ingestion_host" "true"
    add_endpoint "Ingestion (Global/Legacy)" "dc.${domain_appinsights}" "false"
    if [[ "$cloud_suffix" == "com" ]]; then
        add_endpoint "Ingestion (Global/Legacy)" "dc.services.visualstudio.com" "false"
    fi

    # Live Metrics
    if [[ -n "$live_endpoint" ]]; then
        local live_host
        live_host="$(extract_host_from_url "$live_endpoint")"
        add_endpoint "Live Metrics" "$live_host" "false"
    fi
    add_endpoint "Live Metrics (Global/Legacy)" "live.${domain_appinsights}" "false"
    if [[ "$cloud_suffix" == "com" ]]; then
        add_endpoint "Live Metrics (Global/Legacy)" "rt.services.visualstudio.com" "false"
    fi

    # Profiler, Snapshot, Query API, CDN
    if [[ "$cloud_suffix" == "com" ]]; then
        add_endpoint "Profiler" "agent.azureserviceprofiler.net" "false"
    fi
    add_endpoint "Profiler" "profiler.${domain_monitor}" "false"
    add_endpoint "Snapshot Debugger" "snapshot.${domain_monitor}" "false"
    if [[ "$cloud_suffix" == "com" ]]; then
        add_endpoint "Query API" "api.applicationinsights.io" "false"
    fi
    add_endpoint "Query API" "api.${domain_appinsights}" "false"
    if [[ "$cloud_suffix" == "com" ]]; then
        add_endpoint "JS SDK CDN" "js.monitor.azure.com" "false"
    fi

    # Deduplicate by hostname
    local -A seen_hosts=()
    local -a UNIQ_IDX=()
    for i in "${!EP_HOSTNAMES[@]}"; do
        local h="${EP_HOSTNAMES[$i]}"
        if [[ -z "${seen_hosts[$h]:-}" ]]; then
            seen_hosts["$h"]=1
            UNIQ_IDX+=("$i")
        fi
    done
    local endpoint_count=${#UNIQ_IDX[@]}

    # ================================================================
    # STEP 3: DNS RESOLUTION
    # ================================================================
    (( STEP_NUMBER++ ))
    DNS_STEP_NUMBER=$STEP_NUMBER

    if $VERBOSE_OUTPUT; then
        write_header_always "STEP $STEP_NUMBER: DNS Resolution"
        _print ""
        _print -c "$C_CYAN" "  WHY THIS MATTERS:"
        _print -c "$C_GRAY" "  Before sending telemetry, your app must resolve Azure Monitor hostnames to IP addresses."
        _print -c "$C_GRAY" "  DNS failures are a common cause of missing telemetry, especially in:"
        _print -c "$C_GRAY" "    - Private networks with custom DNS servers"
        _print -c "$C_GRAY" "    - Azure Private Link (AMPLS) configurations"
        _print -c "$C_GRAY" "    - Hybrid cloud environments with on-premises DNS"
        _print ""
        _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
        _print -c "$C_GRAY" "  - Ingestion endpoints (where telemetry is sent)"
        _print -c "$C_GRAY" "  - Live Metrics endpoints (real-time monitoring)"
        _print -c "$C_GRAY" "  - Profiler and Snapshot Debugger endpoints"
        _print -c "$C_GRAY" "  - Query API endpoints (for data retrieval)"
        _print -c "$C_GRAY" "  - JavaScript SDK CDN (for browser-based apps)"
        _print ""
        _print -c "$C_CYAN" "  WHAT SUCCESS LOOKS LIKE:"
        _print -c "$C_GRAY" "  - All endpoints resolve to IP addresses"
        _print -c "$C_GRAY" "  - If using AMPLS: All endpoints resolve to PRIVATE IPs consistently"
        _print -c "$C_GRAY" "  - If NOT using AMPLS: All endpoints resolve to PUBLIC Microsoft IPs"
        _print -c "$C_GRAY" "  - No mixed public/private results (indicates incomplete AMPLS setup)"
        _print ""

        local dns_servers
        dns_servers="$(get_dns_servers)"
        if [[ -n "$dns_servers" ]]; then
            _print -n -c "$C_GRAY" "  DNS Server(s): "
            _print -c "$C_WHITE" "$dns_servers"
        else
            _print -n -c "$C_GRAY" "  DNS Server(s): "
            _print -c "$C_YELLOW" "(unable to determine)"
        fi
        _print ""
        _print -c "$C_GRAY" "  Testing $endpoint_count endpoints..."
        _print ""
    fi

    write_progress_start "DNS Resolution"

    # --- Run DNS checks ---
    local -a DNS_R_HOSTNAME=() DNS_R_STATUS=() DNS_R_IP=() DNS_R_PRIVATE=()
    local -a DNS_R_CATEGORY=() DNS_R_CRITICAL=() DNS_R_DETAIL=() DNS_R_DURATION=()
    local -a DNS_R_FAILURE_LABEL=()
    local has_ampls_signals=false
    local has_public_ips=false
    local dns_fail_count=0
    local dns_pass_count=0
    local dns_skipped_no_tool=false

    if ! $HAS_DIG && ! $HAS_NSLOOKUP; then
        # No DNS tools at all -- skip gracefully, don't report as BLOCKING
        dns_skipped_no_tool=true
        if $VERBOSE_OUTPUT; then
            _print -c "$C_YELLOW" "  [!] Neither dig nor nslookup is installed."
            _print -c "$C_GRAY" "      DNS resolution cannot be tested without a DNS lookup tool."
            _print -c "$C_GRAY" "      Install: sudo apt-get install dnsutils  (provides dig)"
            _print -c "$C_GRAY" "               sudo yum install bind-utils    (RHEL/CentOS)"
            _print ""
        fi
        write_progress_line "DNS Resolution" "SKIP" "No DNS tool (install dnsutils)"

        # Still populate hostname arrays so TCP can attempt direct connections
        for idx in "${UNIQ_IDX[@]}"; do
            DNS_R_HOSTNAME+=("${EP_HOSTNAMES[$idx]}")
            DNS_R_STATUS+=("SKIP")
            DNS_R_IP+=("")
            DNS_R_PRIVATE+=(false)
            DNS_R_CATEGORY+=("${EP_CATEGORIES[$idx]}")
            DNS_R_CRITICAL+=("${EP_CRITICAL[$idx]}")
            DNS_R_DETAIL+=("Skipped (no DNS tool)")
            DNS_R_DURATION+=(0)
            DNS_R_FAILURE_LABEL+=("")
        done
    else
        for idx in "${UNIQ_IDX[@]}"; do
        local ep_host="${EP_HOSTNAMES[$idx]}"
        local ep_cat="${EP_CATEGORIES[$idx]}"
        local ep_crit="${EP_CRITICAL[$idx]}"

        test_dns_resolution "$ep_host"

        DNS_R_HOSTNAME+=("$ep_host")
        DNS_R_STATUS+=("$DNS_RESULT_STATUS")
        DNS_R_IP+=("$DNS_RESULT_IP")
        DNS_R_PRIVATE+=("$DNS_RESULT_PRIVATE")
        DNS_R_CATEGORY+=("$ep_cat")
        DNS_R_CRITICAL+=("$ep_crit")
        DNS_R_DETAIL+=("$DNS_RESULT_DETAIL")
        DNS_R_DURATION+=("$DNS_RESULT_DURATION")
        DNS_R_FAILURE_LABEL+=("$DNS_RESULT_FAILURE_LABEL")

        if [[ "$DNS_RESULT_STATUS" == "PASS" ]]; then
            (( dns_pass_count++ ))
            if [[ "$DNS_RESULT_PRIVATE" == "true" ]]; then
                has_ampls_signals=true
            else
                has_public_ips=true
            fi
        else
            (( dns_fail_count++ ))
        fi
    done

    # --- Populate resolved IP registry from DNS results ---
    for i in "${!DNS_R_IP[@]}"; do
        local rip="${DNS_R_IP[$i]}"
        if [[ -n "$rip" && "${DNS_R_STATUS[$i]}" == "PASS" ]]; then
            local already=false
            for existing in "${RESOLVED_IP_REGISTRY[@]}"; do
                [[ "$existing" == "$rip" ]] && { already=true; break; }
            done
            $already || RESOLVED_IP_REGISTRY+=("$rip")
        fi
    done

    # --- DNS progress line ---
    if (( dns_fail_count == 0 )); then
        local ip_type="all public IPs"
        if $has_ampls_signals && ! $has_public_ips; then
            ip_type="all private IPs (AMPLS detected)"
        elif $has_ampls_signals && $has_public_ips; then
            ip_type="mixed public/private IPs"
        fi
        write_progress_line "DNS Resolution" "OK" "$dns_pass_count/$endpoint_count resolved ($ip_type)"
    elif (( dns_pass_count > 0 )); then
        write_progress_line "DNS Resolution" "WARN" "$dns_pass_count/$endpoint_count resolved, $dns_fail_count failed"
    else
        write_progress_line "DNS Resolution" "FAIL" "0/$endpoint_count resolved"
    fi

    if (( dns_fail_count > 0 )); then
        add_diagnosis "BLOCKING" "DNS Resolution Failures" \
            "$dns_fail_count endpoint(s) failed DNS resolution" \
            "$dns_fail_count of $endpoint_count endpoints could not be resolved." \
            "Check DNS configuration. If using AMPLS, verify private DNS zones exist." \
            "" \
            "https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"
    fi
    if $has_ampls_signals && $has_public_ips; then
        add_diagnosis "WARNING" "Mixed Public/Private DNS Results" \
            "Some endpoints resolve to private IPs, others to public (broken AMPLS)" \
            "Mixed DNS results suggest an incomplete AMPLS/Private Link configuration." \
            "Ensure all Azure Monitor private DNS zones are created and linked to your VNet." \
            "" \
            "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
    fi
    fi  # end of DNS tool available check

    # --- DNS verbose table (after progress line) ---
    if $VERBOSE_OUTPUT && ! $dns_skipped_no_tool; then
        render_dns_table
    fi

    # ================================================================
    # STEP 4: TCP CONNECTIVITY
    # ================================================================
    (( STEP_NUMBER++ ))

    write_progress_start "TCP Connectivity"

    if (( dns_pass_count == 0 )) && ! $dns_skipped_no_tool; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: TCP Connectivity (Port 443) [SKIPPED]"
            _print ""
            _print -c "$C_YELLOW" "  Skipping TCP tests -- all DNS resolution failed."
            _print -c "$C_GRAY" "  Resolve DNS issues first (Step $DNS_STEP_NUMBER), then re-run."
            _print ""
        fi
        write_progress_line "TCP Connectivity" "SKIP" "Skipped (DNS failed)"
    else
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: TCP Connectivity (Port 443)"
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "  After DNS resolves, your app must establish a TCP connection on port 443."
            _print -c "$C_GRAY" "  TCP failures indicate firewall rules, NSGs, or network appliances blocking outbound traffic."
            _print ""
            _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
            _print -c "$C_GRAY" "  - Can we open a TCP socket to each endpoint on port 443?"
            _print -c "$C_GRAY" "  - How long does the connection take? (latency indicator)"
            _print ""
            _print -c "$C_CYAN" "  WHAT SUCCESS LOOKS LIKE:"
            _print -c "$C_GRAY" "  - All endpoints accept TCP connections"
            _print -c "$C_GRAY" "  - Connection times are reasonable (under 500ms typically)"
            _print ""
            _print -c "$C_YELLOW" "  IF THIS FAILS, CHECK:"
            _print -c "$C_GRAY" "  - NSG (Network Security Group) outbound rules for port 443"
            _print -c "$C_GRAY" "  - Azure Firewall or third-party firewall appliance rules"
            _print -c "$C_GRAY" "  - UDR (User Defined Routes) that might redirect traffic"
            _print -c "$C_GRAY" "  - On-premises firewall if traffic routes through VPN/ExpressRoute"
            _print ""
        fi

        local tcp_fail_count=0
        local tcp_pass_count=0

        # TCP result arrays for table rendering
        local -a TCP_R_HOSTNAME=() TCP_R_STATUS=() TCP_R_IP=()
        local -a TCP_R_CATEGORY=() TCP_R_DURATION=() TCP_R_DETAIL=()

        for i in "${!DNS_R_HOSTNAME[@]}"; do
            # Skip only endpoints that actively FAILED dns (not SKIP)
            [[ "${DNS_R_STATUS[$i]}" == "FAIL" ]] && continue

            local tcp_host="${DNS_R_HOSTNAME[$i]}"
            test_tcp_connectivity "$tcp_host"

            TCP_R_HOSTNAME+=("$tcp_host")
            TCP_R_STATUS+=("$TCP_RESULT_STATUS")
            TCP_R_IP+=("${DNS_R_IP[$i]}")
            TCP_R_CATEGORY+=("${DNS_R_CATEGORY[$i]}")
            TCP_R_DURATION+=("$TCP_RESULT_DURATION")
            TCP_R_DETAIL+=("$TCP_RESULT_DETAIL")

            if [[ "$TCP_RESULT_STATUS" == "PASS" || "$TCP_RESULT_STATUS" == "INFO" ]]; then
                (( tcp_pass_count++ ))
            else
                (( tcp_fail_count++ ))
            fi

            # Track if the primary ingestion endpoint TCP failed
            if [[ "$tcp_host" == "$ingestion_host" && "$TCP_RESULT_STATUS" == "FAIL" ]]; then
                INGESTION_TCP_BLOCKED=true
            fi
        done

        local total_tcp=$(( tcp_pass_count + tcp_fail_count ))
        if (( tcp_fail_count == 0 )); then
            write_progress_line "TCP Connectivity" "OK" "$tcp_pass_count/$total_tcp reachable on :443"
        else
            write_progress_line "TCP Connectivity" "FAIL" "$tcp_fail_count/$total_tcp blocked on :443"
            add_diagnosis "BLOCKING" "TCP Connection Failures (Port 443)" \
                "$tcp_fail_count endpoint(s) blocked on port 443 (firewall or NSG)" \
                "$tcp_fail_count endpoints are not reachable on port 443." \
                "Check NSG outbound rules, Azure Firewall, UDRs, and proxy settings." \
                "" \
                "https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"
        fi

        # --- TCP verbose table + blocked/high-latency sections ---
        if $VERBOSE_OUTPUT && (( total_tcp > 0 )); then
            render_tcp_table

            # Blocked endpoints summary (grouped by category)
            if (( tcp_fail_count > 0 )); then
                _print -c "$C_RED" "  BLOCKED ENDPOINTS:"
                local prev_cat=""
                for i in "${!TCP_R_HOSTNAME[@]}"; do
                    [[ "${TCP_R_STATUS[$i]}" != "FAIL" ]] && continue
                    local f_cat="${TCP_R_CATEGORY[$i]}"
                    if [[ "$f_cat" != "$prev_cat" ]]; then
                        _print -c "$C_YELLOW" "    $f_cat"
                        prev_cat="$f_cat"
                    fi
                    local ip_note=""
                    [[ -n "${TCP_R_IP[$i]}" ]] && ip_note=" (${TCP_R_IP[$i]})"
                    _print -c "$C_GRAY" "      ${TCP_R_HOSTNAME[$i]}:443${ip_note}"
                done
                _print ""
                _print -c "$C_YELLOW" "  ACTION:"
                _print -c "$C_GRAY" "    Verify outbound port 443 is open in NSG, firewall, and proxy rules for"
                _print -c "$C_GRAY" "    the IPs listed above. If using AMPLS, verify private endpoints are healthy"
                _print -c "$C_GRAY" "    with approved connection status."
                _print ""
            fi

            # High latency warnings
            local has_high_lat=false
            for i in "${!TCP_R_STATUS[@]}"; do
                [[ "${TCP_R_STATUS[$i]}" == "INFO" ]] && has_high_lat=true && break
            done
            if $has_high_lat; then
                _print ""
                _print -c "$C_YELLOW" "  HIGH LATENCY DETECTED:"
                for i in "${!TCP_R_STATUS[@]}"; do
                    [[ "${TCP_R_STATUS[$i]}" != "INFO" ]] && continue
                    local ip_note=""
                    [[ -n "${TCP_R_IP[$i]}" ]] && ip_note=" (${TCP_R_IP[$i]})"
                    _print -c "$C_GRAY" "    - ${TCP_R_HOSTNAME[$i]}${ip_note}: ${TCP_R_DURATION[$i]}ms"
                done
                _print ""
            fi
        fi
    fi

    # ================================================================
    # STEP 5: TLS HANDSHAKE VALIDATION
    # ================================================================
    (( STEP_NUMBER++ ))

    write_progress_start "TLS Handshake"

    if $INGESTION_TCP_BLOCKED || { (( dns_pass_count == 0 )) && ! $dns_skipped_no_tool; }; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: TLS Handshake Validation [SKIPPED]"
            _print ""
            _print -c "$C_YELLOW" "  Skipping TLS tests -- ingestion endpoint is not reachable."
            _print -c "$C_GRAY" "  Resolve TCP/DNS issues first, then re-run."
            _print ""
        fi
        write_progress_line "TLS Handshake" "SKIP" "Skipped (ingestion endpoint not reachable)"
    else
        # --- Full TLS Handshake Validation ---
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: TLS Handshake Validation"
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "  Azure Monitor requires TLS 1.2 or higher. TLS failures can occur when:"
            _print -c "$C_GRAY" "    - Your OS/runtime defaults to older TLS versions (1.0 or 1.1)"
            _print -c "$C_GRAY" "    - A TLS-inspecting proxy/firewall intercepts and re-signs traffic"
            _print -c "$C_GRAY" "    - Certificate trust chain issues exist"
            _print ""
            _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
            _print -c "$C_GRAY" "  - Can THIS machine negotiate TLS 1.2+ with Azure Monitor endpoints?"
            _print -c "$C_GRAY" "  - Certificate issuer (Microsoft/DigiCert = direct, other = TLS inspection)"
            _print -c "$C_GRAY" "  - Protocol versions this client can negotiate (1.2, 1.3)"
            _print -c "$C_GRAY" "  - MITM/downgrade detection: deprecated protocols (1.0, 1.1) are also probed"
            _print -c "$C_GRAY" "    with a short timeout -- a successful 1.0/1.1 handshake indicates a network"
            _print -c "$C_GRAY" "    device is intercepting TLS before it reaches Azure Monitor"
            _print ""
            _print -c "$C_CYAN" "  WHAT SUCCESS LOOKS LIKE:"
            _print -c "$C_GRAY" "  - TLS 1.2 negotiated successfully (minimum required by Azure Monitor)"
            _print -c "$C_GRAY" "  - Certificate issued by Microsoft/DigiCert (not a proxy CA)"
            _print ""
            _print -c "$C_YELLOW" "  IF TLS 1.2 FAILS, CHECK:"
            _print -c "$C_GRAY" "  - Proxy/firewall TLS inspection bypass rules for Azure Monitor"
            _print -c "$C_GRAY" "  - Root CA certificates are up to date (DigiCert Global Root G2)"
            _print -c "$C_GRAY" "  - OpenSSL configuration on this machine"
            _print ""
        fi

        # Check openssl availability
        if ! command -v openssl &>/dev/null; then
            write_progress_line "TLS Handshake" "SKIP" "openssl not available (install openssl)"
        else
            # Select TLS test targets: primary ingestion + live metrics (non-legacy), max 3
            local -a tls_targets_idx=()
            for i in "${!TCP_R_HOSTNAME[@]}"; do
                [[ "${TCP_R_STATUS[$i]}" == "FAIL" ]] && continue
                local cat="${TCP_R_CATEGORY[$i]}"
                if [[ "$cat" =~ Ingestion.*Regional|Live\ Metrics ]] && [[ ! "$cat" =~ Legacy ]]; then
                    tls_targets_idx+=("$i")
                fi
            done
            # If no non-legacy targets, fall back to first 2 passing TCP endpoints
            if (( ${#tls_targets_idx[@]} == 0 )); then
                for i in "${!TCP_R_HOSTNAME[@]}"; do
                    [[ "${TCP_R_STATUS[$i]}" == "FAIL" ]] && continue
                    tls_targets_idx+=("$i")
                    (( ${#tls_targets_idx[@]} >= 2 )) && break
                done
            fi
            # Cap at 3 targets
            (( ${#tls_targets_idx[@]} > 3 )) && tls_targets_idx=("${tls_targets_idx[@]:0:3}")

            # TLS result arrays
            local -a TLS_R_HOSTNAME=() TLS_R_STATUS=() TLS_R_CATEGORY=()
            local -a TLS_R_DETAIL=() TLS_R_ACTION=()
            local -a TLS_R_CERT_ISSUER=() TLS_R_INSPECTION=() TLS_R_PROXY=()
            local -a TLS_R_DEPRECATED=()

            local tls_fail_count=0 tls_info_count=0
            local first_tls_inspection=false first_proxy_product="" first_cert_issuer=""
            local first_deprecated_list=""
            local first_deprecated_azure_edge=false
            local first_supported=""

            for idx in "${tls_targets_idx[@]}"; do
                local tls_host="${TCP_R_HOSTNAME[$idx]}"
                local tls_cat="${TCP_R_CATEGORY[$idx]}"

                test_tls_handshake "$tls_host"

                TLS_R_HOSTNAME+=("$tls_host")
                TLS_R_STATUS+=("$TLS_RESULT_STATUS")
                TLS_R_CATEGORY+=("$tls_cat")
                TLS_R_DETAIL+=("$TLS_RESULT_DETAIL")
                TLS_R_ACTION+=("$TLS_RESULT_ACTION")
                TLS_R_CERT_ISSUER+=("$TLS_RESULT_CERT_ISSUER")
                TLS_R_INSPECTION+=("$TLS_RESULT_TLS_INSPECTION")
                TLS_R_PROXY+=("$TLS_RESULT_PROXY_PRODUCT")

                local dep_list=""
                if (( ${#TLS_RESULT_DEPRECATED_ACCEPTED[@]} > 0 )); then
                    dep_list="$(printf '%s, ' "${TLS_RESULT_DEPRECATED_ACCEPTED[@]}")"
                    dep_list="${dep_list%, }"
                fi
                TLS_R_DEPRECATED+=("$dep_list")

                [[ "$TLS_RESULT_STATUS" == "FAIL" ]] && (( tls_fail_count++ ))
                [[ "$TLS_RESULT_STATUS" == "INFO" ]] && (( tls_info_count++ ))

                # Capture first result for progress line summary
                if [[ -z "$first_supported" ]] && (( ${#TLS_RESULT_SUPPORTED[@]} > 0 )); then
                    first_supported="$(printf '%s, ' "${TLS_RESULT_SUPPORTED[@]}")"
                    first_supported="${first_supported%, }"
                fi
                if [[ "$TLS_RESULT_TLS_INSPECTION" == "true" ]] && ! $first_tls_inspection; then
                    first_tls_inspection=true
                    first_proxy_product="$TLS_RESULT_PROXY_PRODUCT"
                    first_cert_issuer="$TLS_RESULT_CERT_ISSUER"
                fi
                if [[ -z "$first_deprecated_list" && -n "$dep_list" ]]; then
                    first_deprecated_list="$dep_list"
                    first_deprecated_azure_edge=$TLS_RESULT_DEPRECATED_AZURE_EDGE
                fi

                # Verbose per-endpoint output
                if $VERBOSE_OUTPUT; then
                    write_result "$TLS_RESULT_STATUS" "$tls_cat: $tls_host" "$TLS_RESULT_DETAIL" "$TLS_RESULT_ACTION"

                    # Show deprecated protocol detection (cert-aware messaging)
                    if [[ -n "$dep_list" ]]; then
                        if $TLS_RESULT_DEPRECATED_AZURE_EDGE; then
                            _print -c "$C_YELLOW" "      [?] UNEXPECTED: Deprecated protocol(s) accepted: $dep_list (Microsoft cert)"
                            _print -c "$C_GRAY" "          Azure Monitor should reject TLS 1.0/1.1. The certificate is Microsoft-issued"
                            _print -c "$C_GRAY" "          (not a third-party proxy). If this persists, contact Microsoft support."
                        else
                            _print -c "$C_RED" "      [!] SECURITY: Deprecated protocol(s) ACCEPTED: $dep_list"
                            _print -c "$C_YELLOW" "          Azure Monitor rejects TLS < 1.2. A successful handshake means a"
                            _print -c "$C_YELLOW" "          network device is terminating TLS before traffic reaches Azure."
                        fi
                    fi
                fi
            done

            # Extra spacing before progress line in verbose mode
            $VERBOSE_OUTPUT && _print ""

            # --- TLS progress line ---
            if (( ${#TLS_R_HOSTNAME[@]} == 0 )); then
                write_progress_line "TLS Handshake" "SKIP" "No eligible endpoints to test"
            elif (( tls_fail_count > 0 )); then
                write_progress_line "TLS Handshake" "FAIL" "TLS handshake failed"
                add_diagnosis "BLOCKING" "TLS Handshake Failure" \
                    "TLS connection failed (possible TLS inspection or cert issue)" \
                    "Could not establish TLS connection. Possible TLS inspection or certificate issue." \
                    "Check for TLS-inspecting proxy/firewall, verify TLS 1.2 is enabled, update root CAs." \
                    "" \
                    "https://learn.microsoft.com/azure/azure-monitor/fundamentals/azure-monitor-network-access"
            elif (( tls_info_count > 0 )); then
                # Determine summary: TLS inspection, deprecated, or both
                local tls_summary=""
                if $first_tls_inspection; then
                    tls_summary="TLS inspection detected ($first_proxy_product)"
                    if [[ -n "$first_deprecated_list" ]]; then
                        tls_summary+=" + deprecated protocol(s) accepted ($first_deprecated_list)"
                    fi
                    add_diagnosis "INFO" "TLS Inspection Detected ($first_proxy_product)" \
                        "TLS proxy re-signing traffic ($first_proxy_product)" \
                        "Certificate issuer ($first_cert_issuer) is not Microsoft/DigiCert. A TLS-inspecting proxy is re-signing HTTPS traffic. This can cause SDK cert validation failures, telemetry drops, and increased latency." \
                        "Configure a TLS inspection bypass for Azure Monitor endpoints: *.${domain_appinsights}, *.${domain_monitor}, *.in.${domain_appinsights}" \
                        "" \
                        "https://learn.microsoft.com/azure/azure-monitor/app/ip-addresses"
                elif [[ -n "$first_deprecated_list" ]]; then
                    if $first_deprecated_azure_edge; then
                        tls_summary="Deprecated protocol(s) accepted: $first_deprecated_list (unexpected -- Microsoft cert)"
                        add_diagnosis "INFO" "Unexpected: Deprecated TLS Accepted with Microsoft Certificate ($first_deprecated_list)" \
                            "Deprecated TLS accepted with Microsoft-issued certificate ($first_deprecated_list)" \
                            "A deprecated TLS handshake ($first_deprecated_list) succeeded and a Microsoft-issued certificate was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1. This is not a third-party proxy or MITM -- the certificate is legitimate -- but the behavior is unexpected." \
                            "If this persists, contact Microsoft support and reference this diagnostic output." \
                            "" \
                            "https://learn.microsoft.com/azure/azure-monitor/best-practices-security"
                    else
                        tls_summary="Deprecated protocol(s) accepted: $first_deprecated_list -- possible MITM"
                        add_diagnosis "INFO" "Deprecated TLS Protocol Accepted ($first_deprecated_list)" \
                            "Middlebox accepting deprecated TLS ($first_deprecated_list)" \
                            "Azure Monitor rejects TLS < 1.2. A successful deprecated handshake means a network device (proxy, firewall, or MITM appliance) is terminating TLS before traffic reaches Azure." \
                            "Investigate the network path for transparent proxies, firewall TLS inspection, or other devices intercepting HTTPS traffic." \
                            "" \
                            "https://learn.microsoft.com/azure/azure-monitor/best-practices-security"
                    fi
                else
                    tls_summary="${TLS_R_DETAIL[0]}"
                fi
                write_progress_line "TLS Handshake" "INFO" "$tls_summary"
            else
                # All passed -- build friendly summary
                local tls_ver=""
                # Filter to only current TLS versions for summary
                if [[ "$first_supported" == *"1.3"* && "$first_supported" == *"1.2"* ]]; then
                    tls_ver="TLS 1.2, TLS 1.3"
                elif [[ "$first_supported" == *"1.3"* ]]; then
                    tls_ver="TLS 1.3"
                elif [[ "$first_supported" == *"1.2"* ]]; then
                    tls_ver="TLS 1.2"
                else
                    tls_ver="connected"
                fi
                local cert_info=""
                if [[ -n "${TLS_R_CERT_ISSUER[0]}" ]]; then
                    if echo "${TLS_R_CERT_ISSUER[0]}" | grep -qiE "Microsoft|DigiCert"; then
                        cert_info=", Microsoft cert"
                    else
                        cert_info=", cert: ${TLS_R_CERT_ISSUER[0]}"
                    fi
                fi
                write_progress_line "TLS Handshake" "OK" "$tls_ver$cert_info"
            fi

            # --- TLS Verbose: Inspection warning block ---
            if $VERBOSE_OUTPUT && $first_tls_inspection; then
                _print ""
                _print -c "$C_YELLOW" "  TLS INSPECTION WARNING:"
                _print -c "$C_WHITE" "    Detected proxy: $first_proxy_product"
                _print -c "$C_GRAY" "    Certificate issuer: $first_cert_issuer"
                _print ""
                _print -c "$C_GRAY" "    A TLS-inspecting proxy is intercepting and re-signing HTTPS traffic"
                _print -c "$C_GRAY" "    between this machine and Azure Monitor. This can cause:"
                _print -c "$C_GRAY" "      - SDK certificate validation failures (if proxy CA not trusted)"
                _print -c "$C_GRAY" "      - Silent telemetry drops (if proxy modifies or blocks payloads)"
                _print -c "$C_GRAY" "      - Increased latency (extra TLS handshake through proxy)"
                _print -c "$C_GRAY" "      - Live Metrics disconnections (proxy timeouts on long-lived connections)"
                _print ""
                _print -c "$C_CYAN" "    RECOMMENDED: Add a TLS inspection bypass for Azure Monitor domains:"
                _print -c "$C_WHITE" "      *.${domain_appinsights}"
                _print -c "$C_WHITE" "      *.${domain_monitor}"
                if [[ "$cloud_suffix" == "com" ]]; then
                    _print -c "$C_WHITE" "      *.services.visualstudio.com"
                fi
                _print -c "$C_WHITE" "      *.in.${domain_appinsights}"
                _print ""
            fi

            # --- TLS Verbose: Deprecated protocol warning block ---
            if $VERBOSE_OUTPUT && [[ -n "$first_deprecated_list" ]] && ! $first_tls_inspection; then
                _print ""
                if $first_deprecated_azure_edge; then
                    _print -c "$C_YELLOW" "  UNEXPECTED: DEPRECATED PROTOCOL ACCEPTED WITH MICROSOFT CERTIFICATE:"
                    _print -c "$C_WHITE" "    Accepted: $first_deprecated_list"
                    _print ""
                    _print -c "$C_GRAY" "    A deprecated TLS handshake succeeded and a Microsoft-issued certificate"
                    _print -c "$C_GRAY" "    was returned. Azure Monitor endpoints are expected to reject TLS 1.0/1.1."
                    _print -c "$C_GRAY" "    This is NOT a third-party proxy or MITM -- the certificate is legitimate --"
                    _print -c "$C_GRAY" "    but the behavior is unexpected."
                    _print ""
                    _print -c "$C_CYAN" "    If this persists, contact Microsoft support and reference this output."
                    _print ""
                else
                    _print -c "$C_YELLOW" "  DEPRECATED PROTOCOL ACCEPTANCE WARNING:"
                    _print -c "$C_RED" "    Accepted: $first_deprecated_list"
                    _print ""
                    _print -c "$C_GRAY" "    Azure Monitor rejects TLS 1.0 and 1.1. A successful handshake at these"
                    _print -c "$C_GRAY" "    versions means a device in the network path is terminating TLS before"
                    _print -c "$C_GRAY" "    traffic reaches Azure. This could be:"
                    _print -c "$C_GRAY" "      - A transparent proxy not visible in browser proxy settings"
                    _print -c "$C_GRAY" "      - A firewall performing TLS inspection/decryption"
                    _print -c "$C_GRAY" "      - A load balancer or network virtual appliance"
                    _print ""
                    _print -c "$C_CYAN" "    SECURITY IMPACT:"
                    _print -c "$C_GRAY" "      Telemetry data is being decrypted and re-encrypted in transit."
                    _print -c "$C_GRAY" "      The middlebox could be dropping, modifying, or logging telemetry."
                    _print ""
                fi
            fi
        fi
    fi

    # ================================================================
    # STEP 6: AMPLS VALIDATION (requires Azure login)
    # ================================================================
    # This step authenticates to Azure and discovers whether the App Insights
    # resource is linked to an Azure Monitor Private Link Scope (AMPLS).
    # Mirrors the PS1's full AMPLS validation flow.
    # ================================================================

    local ampls_checked=false
    local ampls_resource_found=false
    local ampls_linked=false
    local -a ampls_access_modes=()        # "AMPLS_NAME|ING_MODE|Q_MODE"
    local -a ampls_comparison_results=()   # "FQDN|EXPECTED|ACTUAL|STATUS"
    local -a ampls_detail_blocks=()        # "AMPLS_NAME|PE_NAMES|MAPPING_COUNT"

    # ---- Azure consent gate (verbose mode) ----
    # Compact mode: consent was already handled before the progress table.
    # Verbose mode: ask just-in-time, right before Azure resource queries begin.
    if $VERBOSE_OUTPUT && $CHECK_AZURE && ! $NETWORK_ONLY; then
        if ! request_user_consent \
            --requires-azure-login \
            "AZURE RESOURCE CHECKS -- YOUR CONSENT IS REQUIRED" \
            "To skip Azure resource checks entirely, press N or re-run with --network-only." \
            "Proceed with Azure resource checks? [Y/N]" \
            "" \
            "The next set of checks require access to your Azure resources." \
            "You will be asked to sign in to Azure if you are not already" \
            "authenticated -- all queries run as YOU, using your own account" \
            "and permissions. No resources will be modified." \
            "" \
            "What your account will be used to query:" \
            "" \
            "  * Azure Resource Graph -- locate your App Insights resource and" \
            "    any AMPLS private link scope linked to it. Discover any workspace" \
            "    transform data collection rules that may impact App Insights telemetry" \
            "" \
            "  * ARM REST API (read-only) -- inspect AMPLS access modes, private" \
            "    endpoint DNS config, daily cap settings, diagnostic settings," \
            "    and Log Analytics workspace state" \
            "" \
            "  * Data plane (conditional) -- if a test telemetry record is sent and" \
            "    successfully accepted by the ingestion endpoint, a single KQL" \
            "    query will confirm whether the record arrived in your workspace"; then
            CHECK_AZURE=false
            azure_consent_declined=true
        fi
    fi

    # Case 1: Manual AMPLS IP comparison (user provided --ampls-expected-ips)
    if [[ ${#AMPLS_EXPECTED_IPS[@]} -gt 0 ]]; then
        (( STEP_NUMBER++ ))
        ampls_checked=true

        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: AMPLS Validation (Manual IP Comparison)"
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "  You provided expected private endpoint IPs for your AMPLS configuration."
            _print -c "$C_GRAY" "  We'll compare them against what DNS actually resolved on this machine."
            _print -c "$C_GRAY" "  Mismatches mean this machine's DNS is not pointing to the correct private endpoints."
            _print ""
        fi

        # Build manual mappings in the format show_ampls_validation_table expects: "FQDN|EXPECTED_IP|PE_NAME|PE_RG"
        local -a manual_mappings=()
        for fqdn in "${!AMPLS_EXPECTED_IPS[@]}"; do
            manual_mappings+=("${fqdn}|${AMPLS_EXPECTED_IPS[$fqdn]}|(manual)|(manual)")
        done

        if $VERBOSE_OUTPUT; then
            _print -c "$C_GRAY" "  Comparing ${#manual_mappings[@]} FQDN(s) against DNS results..."
            _print ""
        fi

        # Run comparison through the shared validation table function
        local -a table_results=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && table_results+=("$line")
        done < <(printf '%s\n' "${manual_mappings[@]}" | show_ampls_validation_table)
        ampls_comparison_results+=("${table_results[@]}")

        # Populate resolved IP registry from manual AMPLS validation results
        for cr in "${table_results[@]}"; do
            local IFS='|'; local -a cr_fields; read -ra cr_fields <<< "$cr"
            local cr_exp="${cr_fields[1]}" cr_act="${cr_fields[2]}"
            if [[ -n "$cr_exp" ]]; then
                local dup=false; for e in "${RESOLVED_IP_REGISTRY[@]}"; do [[ "$e" == "$cr_exp" ]] && { dup=true; break; }; done
                $dup || RESOLVED_IP_REGISTRY+=("$cr_exp")
            fi
            if [[ -n "$cr_act" && ! "$cr_act" =~ ^\( ]]; then
                local dup=false; for e in "${RESOLVED_IP_REGISTRY[@]}"; do [[ "$e" == "$cr_act" ]] && { dup=true; break; }; done
                $dup || RESOLVED_IP_REGISTRY+=("$cr_act")
            fi
        done

        # Count results
        local manual_mismatches=0
        local manual_matches=0
        for cr in "${ampls_comparison_results[@]}"; do
            local cr_status="${cr##*|}"
            [[ "$cr_status" == "MISMATCH" || "$cr_status" == "FAIL" ]] && (( manual_mismatches++ ))
            [[ "$cr_status" == "MATCH" ]] && (( manual_matches++ ))
        done

        if (( manual_mismatches > 0 )); then
            write_progress_line "AMPLS IP Comparison" "WARN" "$manual_mismatches mismatched, $manual_matches matched"
            add_diagnosis "WARNING" "AMPLS DNS Mismatches ($manual_mismatches of ${#ampls_comparison_results[@]} endpoints)" \
                "AMPLS DNS mismatches ($manual_mismatches of ${#ampls_comparison_results[@]} endpoints resolve to wrong IPs)" \
                "This machine's DNS does not resolve to the expected AMPLS private endpoint IPs." \
                "Verify private DNS zones (${domain_privatelink}) are linked to your VNet. Flush DNS cache." \
                "" \
                "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"

            # Auto-trigger ghost AMPLS reverse lookup for IngestionEndpoint mismatch (manual mapping path)
            if find_ingestion_endpoint_in_ampls_results "$ingestion_host" "${ampls_comparison_results[@]}"; then
                if [[ "$INGESTION_AMPLS_MATCH_STATUS" == "MISMATCH" && -n "$INGESTION_AMPLS_MATCH_ACTUAL_IP" && ! "$INGESTION_AMPLS_MATCH_ACTUAL_IP" =~ ^\( ]]; then
                    if [[ "$INGESTION_AMPLS_MATCH_ACTUAL_IP" =~ ^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\. ]]; then
                        if find_ampls_by_private_ip "$INGESTION_AMPLS_MATCH_ACTUAL_IP"; then
                            _print ""
                            _print -c "$C_CYAN" "      INGESTION ENDPOINT MISMATCH -- AMPLS IDENTIFIED:"
                            _print -c "$C_WHITE" "        AMPLS Name:       $GHOST_AMPLS_NAME"
                            _print -c "$C_GRAY" "        Resource Group:   $GHOST_AMPLS_RG"
                            _print -c "$C_GRAY" "        Subscription:     $GHOST_AMPLS_SUB"
                            _print -c "$C_GRAY" "        Private Endpoint: $GHOST_AMPLS_PE_NAME ($GHOST_AMPLS_PE_RG)"
                            _print -c "$C_GRAY" "        Access Modes:     Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE"
                            _print -c "$C_DARK_GRAY" "        PE Expected IP:   $INGESTION_AMPLS_MATCH_EXPECTED_IP  |  Actual DNS: $INGESTION_AMPLS_MATCH_ACTUAL_IP"

                            add_diagnosis "WARNING" "Ghost AMPLS Overriding Ingestion Endpoint: $GHOST_AMPLS_NAME" \
                                "Ingestion endpoint resolves to IP $INGESTION_AMPLS_MATCH_ACTUAL_IP owned by AMPLS '$GHOST_AMPLS_NAME'" \
                                "The ingestion FQDN ($INGESTION_AMPLS_MATCH_FQDN) resolves to $INGESTION_AMPLS_MATCH_ACTUAL_IP which belongs to PE '$GHOST_AMPLS_PE_NAME' connected to AMPLS '$GHOST_AMPLS_NAME' (Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE)." \
                                "Add your App Insights resource to AMPLS '$GHOST_AMPLS_NAME' or set its ingestion access mode to 'Open'." \
                                "" \
                                "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                        else
                            _print ""
                            _print -c "$C_DARK_GRAY" "      The ingestion endpoint resolves to private IP $INGESTION_AMPLS_MATCH_ACTUAL_IP"
                            _print -c "$C_DARK_GRAY" "      but the owning private endpoint could not be identified."
                        fi
                    fi
                fi
            fi
        else
            write_progress_line "AMPLS IP Comparison" "OK" "$manual_matches/${#ampls_comparison_results[@]} matched"
        fi

    # Case 2: Automated AMPLS check via Azure login
    elif $CHECK_AZURE && ! $NETWORK_ONLY; then
        (( STEP_NUMBER++ ))
        ampls_checked=true

        write_progress_start "AMPLS Configuration"

        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: AMPLS Validation (Requires Login For Azure Resource Discovery)"
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "  This check authenticates to Azure and discovers whether your App Insights resource"
            _print -c "$C_GRAY" "  is linked to an Azure Monitor Private Link Scope (AMPLS). If it is, we'll retrieve"
            _print -c "$C_GRAY" "  the expected private endpoint IPs and compare them against DNS results from this machine."
            _print ""
            _print -c "$C_CYAN" "  WHAT WE'LL DO (all read-only, no modifications):"
            _print -c "$C_GRAY" "    1. Verify Azure CLI login and resource-graph extension"
            _print -c "$C_GRAY" "    2. Search Azure Resource Graph for your App Insights resource (by iKey)"
            _print -c "$C_GRAY" "    3. Find any AMPLS resources linked to it"
            _print -c "$C_GRAY" "    4. Retrieve private endpoint IP configurations"
            _print -c "$C_GRAY" "    5. Compare expected IPs against DNS results from Step $DNS_STEP_NUMBER"
            _print -c "$C_GRAY" "    6. Report AMPLS access mode settings (Private Only vs Open)"
            _print ""
        fi

        # ---- Prerequisite: Azure login check ----
        if ! $AZ_LOGGED_IN; then
            local is_non_interactive_env=false
            if ($ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP || $ENV_IS_KUBERNETES) && ! $ENV_IS_CLOUD_SHELL; then
                is_non_interactive_env=true
            fi

            if $is_non_interactive_env; then
                local host_type="Azure PaaS"
                $ENV_IS_APP_SERVICE  && host_type="App Service"
                $ENV_IS_FUNCTION_APP && host_type="Function App"
                $ENV_IS_CONTAINER_APP && host_type="Container Apps"
                $ENV_IS_KUBERNETES   && host_type="AKS"
                write_progress_line "AMPLS Validation" "SKIP" "$host_type detected -- interactive login not available"
                if $VERBOSE_OUTPUT; then
                    write_result "INFO" "Skipping Azure login ($host_type environment)" \
                        "Interactive login is not available in this environment. Azure resource checks require an active login context." \
                        "Run this script from your local machine with 'az login', or use --network-only to skip Azure checks."
                fi
            else
                write_progress_line "AMPLS Validation" "SKIP" "Not logged in (run 'az login' first)"
                if $VERBOSE_OUTPUT; then
                    write_result "INFO" "Azure CLI not logged in" \
                        "Run 'az login' to enable AMPLS validation, known issue checks, and E2E verification." \
                        "az login"
                fi
            fi
        else
            # ---- Prerequisite: resource-graph extension ----
            if ! check_az_graph_extension; then
                write_progress_line "AMPLS Validation" "SKIP" "az resource-graph extension not available"
                if $VERBOSE_OUTPUT; then
                    write_result "INFO" "Azure resource-graph extension not found" \
                        "This extension is needed for Resource Graph queries." \
                        "Install with: az extension add --name resource-graph"
                fi
            else
                if $VERBOSE_OUTPUT; then
                    # Show detailed Azure CLI prereq info
                    _print -c "$C_GRAY" "  Checking prerequisites..."
                    local az_ver
                    az_ver="$(az version --query '"azure-cli"' -o tsv 2>/dev/null | tr -d '\r')"
                    [[ -z "$az_ver" ]] && az_ver="unknown"
                    write_result "PASS" "Azure CLI found (v${az_ver})"

                    local acct_email acct_tenant acct_sub_name acct_sub_id
                    acct_email="$(az account show --query 'user.name' -o tsv 2>/dev/null | tr -d '\r')"
                    acct_email="$(mask_email "$acct_email")"
                    acct_tenant="$(az account show --query 'tenantId' -o tsv 2>/dev/null | tr -d '\r')"
                    acct_sub_name="$(az account show --query 'name' -o tsv 2>/dev/null | tr -d '\r')"
                    acct_sub_id="$(az account show --query 'id' -o tsv 2>/dev/null | tr -d '\r')"
                    write_result "PASS" "Logged into Azure CLI as ${acct_email}"
                    _print -c "$C_GRAY" "      Tenant: ${acct_tenant} | Subscription: ${acct_sub_name} (${acct_sub_id})"
                fi

                # ---- Find the App Insights resource ----
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_GRAY" "  Searching for App Insights resource by InstrumentationKey..."
                fi

                if find_appinsights_resource "$CS_IKEY"; then
                    ampls_resource_found=true
                    local ai_name="$AI_RESOURCE_NAME"
                    local ai_rg="$AI_RESOURCE_RG"
                    local ai_sub="$AI_RESOURCE_SUB"
                    local ai_id="$AI_RESOURCE_ID"
                    local ai_public_ingestion="$AI_PUBLIC_INGESTION"
                    local ai_public_query="$AI_PUBLIC_QUERY"

                    write_result "PASS" "Found: $ai_name" \
                        "Resource Group: $ai_rg | Subscription: $ai_sub | Location: $AI_RESOURCE_LOCATION"

                    # ---- Refresh properties via direct ARM call (ARG cache may be stale) ----
                    local arm_url="https://management.azure.com${ai_id}?api-version=2020-02-02"
                    _debug_az_rest "GET" "$arm_url"
                    local arm_refresh_json
                    arm_refresh_json="$(az rest --method GET --url "$arm_url" 2>/dev/null | tr -d '\r')"
                    _debug_response "ARM refresh" "$arm_refresh_json"

                    if [[ -n "$arm_refresh_json" && "$arm_refresh_json" != "null" ]]; then
                        AI_RESOURCE_PROPERTIES_JSON="$arm_refresh_json"

                        # Extract ALL needed properties from the single ARM response
                        # This is the single source of truth for all downstream Known Issue checks
                        if $HAS_JQ; then
                            local fresh_ing fresh_q
                            fresh_ing="$(echo "$arm_refresh_json" | jq -r '.properties.publicNetworkAccessForIngestion // "Enabled"')"
                            fresh_q="$(echo "$arm_refresh_json" | jq -r '.properties.publicNetworkAccessForQuery // "Enabled"')"
                            ai_public_ingestion="${fresh_ing:-Enabled}"
                            ai_public_query="${fresh_q:-Enabled}"
                            AI_PUBLIC_INGESTION="$ai_public_ingestion"
                            AI_PUBLIC_QUERY="$ai_public_query"

                            AI_DISABLE_LOCAL_AUTH="$(echo "$arm_refresh_json" | jq -r '.properties.DisableLocalAuth // empty' 2>/dev/null)"
                            AI_SAMPLING_PCT="$(echo "$arm_refresh_json" | jq -r '.properties.SamplingPercentage // empty' 2>/dev/null)"
                            AI_WORKSPACE_RESOURCE_ID="$(echo "$arm_refresh_json" | jq -r '.properties.WorkspaceResourceId // empty' 2>/dev/null)"
                            AI_APP_ID="$(echo "$arm_refresh_json" | jq -r '.properties.AppId // empty' 2>/dev/null)"
                        else
                            # No jq: use az rest --query (JMESPath) against the ARM URL
                            # to extract all needed properties from live ARM data
                            _debug "Extracting AI resource properties via ARM --query (jq not available)"
                            local fresh_ing fresh_q
                            fresh_ing="$(az rest --method GET --url "$arm_url" --query "properties.publicNetworkAccessForIngestion" -o tsv 2>/dev/null | tr -d '\r')"
                            fresh_q="$(az rest --method GET --url "$arm_url" --query "properties.publicNetworkAccessForQuery" -o tsv 2>/dev/null | tr -d '\r')"
                            ai_public_ingestion="${fresh_ing:-Enabled}"
                            ai_public_query="${fresh_q:-Enabled}"
                            [[ -z "$ai_public_ingestion" || "$ai_public_ingestion" == "None" || "$ai_public_ingestion" == "null" ]] && ai_public_ingestion="Enabled"
                            [[ -z "$ai_public_query" || "$ai_public_query" == "None" || "$ai_public_query" == "null" ]] && ai_public_query="Enabled"
                            AI_PUBLIC_INGESTION="$ai_public_ingestion"
                            AI_PUBLIC_QUERY="$ai_public_query"

                            AI_DISABLE_LOCAL_AUTH="$(az rest --method GET --url "$arm_url" --query "properties.DisableLocalAuth" -o tsv 2>/dev/null | tr -d '\r')"
                            [[ "$AI_DISABLE_LOCAL_AUTH" == "null" ]] && AI_DISABLE_LOCAL_AUTH=""
                            AI_SAMPLING_PCT="$(az rest --method GET --url "$arm_url" --query "properties.SamplingPercentage" -o tsv 2>/dev/null | tr -d '\r')"
                            [[ "$AI_SAMPLING_PCT" == "null" ]] && AI_SAMPLING_PCT=""
                            AI_WORKSPACE_RESOURCE_ID="$(az rest --method GET --url "$arm_url" --query "properties.WorkspaceResourceId" -o tsv 2>/dev/null | tr -d '\r')"
                            [[ "$AI_WORKSPACE_RESOURCE_ID" == "null" ]] && AI_WORKSPACE_RESOURCE_ID=""
                            AI_APP_ID="$(az rest --method GET --url "$arm_url" --query "properties.AppId" -o tsv 2>/dev/null | tr -d '\r')"
                            [[ "$AI_APP_ID" == "null" ]] && AI_APP_ID=""
                        fi
                        _debug "ARM extracted: DisableLocalAuth=$AI_DISABLE_LOCAL_AUTH, SamplingPct=$AI_SAMPLING_PCT, WsResId=${AI_WORKSPACE_RESOURCE_ID:+(set)}, AppId=${AI_APP_ID:+(set)}"
                    else
                        if $VERBOSE_OUTPUT; then
                            _print -c "$C_DARK_GRAY" "    Note: ARM refresh failed, using ARG-cached properties"
                        fi
                        # ARM refresh failed -- fall back to extracting from ARG-cached JSON if jq available
                        if $HAS_JQ && [[ -n "$AI_RESOURCE_PROPERTIES_JSON" ]]; then
                            AI_DISABLE_LOCAL_AUTH="$(echo "$AI_RESOURCE_PROPERTIES_JSON" | jq -r '.properties.DisableLocalAuth // empty' 2>/dev/null)"
                            AI_SAMPLING_PCT="$(echo "$AI_RESOURCE_PROPERTIES_JSON" | jq -r '.properties.SamplingPercentage // empty' 2>/dev/null)"
                            AI_WORKSPACE_RESOURCE_ID="$(echo "$AI_RESOURCE_PROPERTIES_JSON" | jq -r '.properties.WorkspaceResourceId // empty' 2>/dev/null)"
                            AI_APP_ID="$(echo "$AI_RESOURCE_PROPERTIES_JSON" | jq -r '.properties.AppId // empty' 2>/dev/null)"
                        fi
                    fi

                    # ---- Find AMPLS associations ----
                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_GRAY" "  Searching for linked AMPLS resources..."
                    fi

                    local -a ampls_lines=()
                    while IFS= read -r line; do
                        # Only accept pipe-delimited data lines (ID|NAME|RG|SUB|ING_MODE|Q_MODE)
                        [[ "$line" == *"|"*"|"*"|"* ]] && ampls_lines+=("$line")
                    done < <(find_ampls_for_resource "$ai_id")

                    if (( ${#ampls_lines[@]} == 0 )); then
                        # No AMPLS linked
                        write_result "INFO" "No AMPLS found linked to this App Insights resource" \
                            "This resource expects telemetry over public endpoints."

                        if $VERBOSE_OUTPUT; then
                            _print ""
                            _print -c "$C_CYAN" "  WHAT THIS MEANS:"
                            _print -c "$C_GRAY" "  Your App Insights resource is NOT behind a Private Link Scope."
                            _print -c "$C_GRAY" "  Telemetry should flow over public Microsoft IPs."

                            if $has_ampls_signals; then
                                _print ""
                                _print -n -c "$C_YELLOW" "  [!] "
                                _print -c "$C_YELLOW" "WARNING: DNS resolved some endpoints to PRIVATE IPs in Step $DNS_STEP_NUMBER,"
                                _print -c "$C_YELLOW" "      but this App Insights resource is NOT linked to any AMPLS."
                                _print -c "$C_YELLOW" "      This means another AMPLS on this VNet is overriding DNS for Azure Monitor endpoints."
                                _print -c "$C_YELLOW" "      Telemetry may be routing to the wrong private endpoint and getting rejected."
                                _print ""
                                _print -c "$C_YELLOW" "      ACTION: Find the AMPLS that owns the private endpoint on this VNet and either:"
                                _print -c "$C_YELLOW" "        (a) Add this App Insights resource to that AMPLS scope, or"
                                _print -c "$C_YELLOW" "        (b) Set the AMPLS ingestion access mode to 'Open' to allow public fallback"
                            fi
                        fi

                        if $has_ampls_signals; then
                            add_diagnosis "WARNING" "Ghost AMPLS: Private IPs but Resource Not in AMPLS" \
                                "Private IPs detected but resource not linked to any AMPLS" \
                                "DNS resolves to private IPs, but $ai_name is NOT linked to any AMPLS. Another AMPLS is overriding DNS." \
                                "Add this App Insights resource to the AMPLS that owns the private endpoint on this VNet." \
                                "" \
                                "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"

                            # Auto-trigger ghost AMPLS reverse lookup for ingestion endpoint IP
                            local auto_lookup_ip=""
                            for di in "${!DNS_R_HOSTNAME[@]}"; do
                                if [[ "${DNS_R_HOSTNAME[$di]}" == "$ingestion_host" && "${DNS_R_STATUS[$di]}" == "PASS" && "${DNS_R_PRIVATE[$di]}" == "true" ]]; then
                                    auto_lookup_ip="${DNS_R_IP[$di]}"
                                    break
                                fi
                            done
                            if [[ -n "$auto_lookup_ip" ]]; then
                                if find_ampls_by_private_ip "$auto_lookup_ip"; then
                                    _print ""
                                    _print -n -c "$C_CYAN" "      AMPLS IDENTIFIED: "
                                    _print -c "$C_WHITE" "$GHOST_AMPLS_NAME"
                                    _print -c "$C_GRAY" "        Resource Group:   $GHOST_AMPLS_RG"
                                    _print -c "$C_GRAY" "        Subscription:     $GHOST_AMPLS_SUB"
                                    _print -c "$C_GRAY" "        Private Endpoint: $GHOST_AMPLS_PE_NAME ($GHOST_AMPLS_PE_RG)"
                                    _print -c "$C_GRAY" "        Access Modes:     Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE"
                                    _print -c "$C_DARK_GRAY" "        Looked up IP:     $auto_lookup_ip (resolved for $ingestion_host)"
                                    _print ""
                                    _print -c "$C_YELLOW" "      This AMPLS owns the private endpoint that is overriding DNS for your ingestion endpoint."
                                    _print -c "$C_YELLOW" "      Add $ai_name to this AMPLS, or set its ingestion access mode to 'Open'."

                                    add_diagnosis "WARNING" "Ghost AMPLS Identified: $GHOST_AMPLS_NAME" \
                                        "AMPLS '$GHOST_AMPLS_NAME' in RG '$GHOST_AMPLS_RG' owns the PE overriding ingestion DNS" \
                                        "The private IP $auto_lookup_ip (resolved for $ingestion_host) belongs to PE '$GHOST_AMPLS_PE_NAME' connected to AMPLS '$GHOST_AMPLS_NAME' (Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE). This AMPLS is not linked to $ai_name but its PE overrides DNS." \
                                        "Add $ai_name to AMPLS '$GHOST_AMPLS_NAME' or set its ingestion access mode to 'Open'." \
                                        "" \
                                        "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                                else
                                    _print ""
                                    _print -c "$C_DARK_GRAY" "      The private endpoint for IP $auto_lookup_ip could not be identified."
                                    _print -c "$C_DARK_GRAY" "      It may be in a subscription your account cannot access, or the private"
                                    _print -c "$C_DARK_GRAY" "      DNS zone may have been configured manually."
                                fi
                            fi
                        fi
                    else
                        # AMPLS linked -- process each one
                        ampls_linked=true
                        write_result "PASS" "Found ${#ampls_lines[@]} linked AMPLS resource(s)"

                        local ampls_index=0
                        local any_mismatches=false
                        local any_private_only=false

                        for ampls_entry in "${ampls_lines[@]}"; do
                            (( ampls_index++ ))
                            local IFS='|'
                            local -a a_fields
                            read -ra a_fields <<< "$ampls_entry"
                            local a_id="${a_fields[0]}"
                            local a_name="${a_fields[1]}"
                            local a_rg="${a_fields[2]}"
                            local a_sub="${a_fields[3]}"
                            local ing_mode="${a_fields[4]:-Unknown}"
                            local q_mode="${a_fields[5]:-Unknown}"

                            ampls_access_modes+=("${a_name}|${ing_mode}|${q_mode}")

                            [[ "$ing_mode" == "PrivateOnly" || "$q_mode" == "PrivateOnly" ]] && any_private_only=true

                            # Build mode summary
                            local mode_summary=""
                            if [[ "$ing_mode" == "$q_mode" ]]; then
                                mode_summary="$ing_mode (ingestion + query)"
                            else
                                mode_summary="Ingestion: $ing_mode | Query: $q_mode"
                            fi

                            if $VERBOSE_OUTPUT; then
                                _print ""
                                _print -n -c "$C_CYAN" "  AMPLS [$ampls_index/${#ampls_lines[@]}]: "
                                _print -n -c "$C_WHITE" "$a_name "
                                _print -c "$C_DARK_GRAY" "($a_rg)"

                                local mode_color="$C_GREEN"
                                [[ "$ing_mode" == "PrivateOnly" || "$q_mode" == "PrivateOnly" ]] && mode_color="$C_YELLOW"
                                _print -n -c "$C_GRAY" "    Access Mode: "
                                _print -c "$mode_color" "$mode_summary"

                                # Access mode explanation
                                if [[ "$ing_mode" == "PrivateOnly" && "$q_mode" == "PrivateOnly" ]]; then
                                    _print -c "$C_YELLOW" "    ==> Clients on this VNet can ONLY reach Azure Monitor resources scoped to this AMPLS."
                                    _print -c "$C_YELLOW" "        Unscoped/public resources are blocked from this network, even if they accept public traffic."
                                elif [[ "$ing_mode" == "PrivateOnly" || "$q_mode" == "PrivateOnly" ]]; then
                                    [[ "$ing_mode" == "PrivateOnly" ]] && _print -c "$C_YELLOW" "    ==> Ingestion: Clients on this VNet can ONLY send telemetry to AMPLS-scoped resources."
                                    [[ "$q_mode" == "PrivateOnly" ]] && _print -c "$C_YELLOW" "    ==> Query: Clients on this VNet can ONLY query AMPLS-scoped resources."
                                    [[ "$ing_mode" == "Open" ]] && _print -c "$C_GREEN" "    ==> Ingestion: Clients on this VNet can send telemetry to both scoped and public resources."
                                    [[ "$q_mode" == "Open" ]] && _print -c "$C_GREEN" "    ==> Query: Clients on this VNet can query both scoped and public resources."
                                else
                                    _print -c "$C_GREEN" "    ==> Clients on this VNet can reach both AMPLS-scoped and public Azure Monitor resources."
                                fi
                            fi

                            # Get private endpoint IPs
                            local -a pe_mappings=()
                            local -a pe_names_seen=()
                            while IFS='|' read -r pe_name pe_rg_val pe_fqdn pe_ip; do
                                [[ -z "$pe_fqdn" ]] && continue
                                pe_mappings+=("${pe_fqdn}|${pe_ip}|${pe_name}|${pe_rg_val}")

                                # Track unique PE names
                                local pe_seen=false
                                for pn in "${pe_names_seen[@]}"; do
                                    [[ "$pn" == "$pe_name" ]] && pe_seen=true && break
                                done
                                $pe_seen || pe_names_seen+=("$pe_name")
                            done < <(get_ampls_private_endpoints "$a_id")

                            if (( ${#pe_mappings[@]} > 0 )); then
                                if $VERBOSE_OUTPUT; then
                                    local pe_names_str
                                    pe_names_str="$(printf '%s, ' "${pe_names_seen[@]}")"
                                    pe_names_str="${pe_names_str%, }"
                                    _print -n -c "$C_GRAY" "    Private Endpoint: "
                                    _print -n -c "$C_WHITE" "$pe_names_str "
                                    _print -c "$C_DARK_GRAY" "(${#pe_mappings[@]} DNS mappings)"
                                    _print ""
                                fi

                                ampls_detail_blocks+=("${a_name}|${pe_names_str}|${#pe_mappings[@]}")

                                # Run the validation table comparison
                                local -a table_results=()
                                while IFS= read -r cmp_line; do
                                    # Only accept pipe-delimited data lines (FQDN|EXPECTED|ACTUAL|STATUS)
                                    [[ "$cmp_line" == *"|"*"|"*"|"* ]] && table_results+=("$cmp_line")
                                done < <(printf '%s\n' "${pe_mappings[@]}" | show_ampls_validation_table)

                                # Add to cumulative results
                                ampls_comparison_results+=("${table_results[@]}")

                                # Populate resolved IP registry from AMPLS PE validation results
                                for cr in "${table_results[@]}"; do
                                    local IFS='|'; local -a cr_fields; read -ra cr_fields <<< "$cr"
                                    local cr_exp="${cr_fields[1]}" cr_act="${cr_fields[2]}"
                                    if [[ -n "$cr_exp" ]]; then
                                        local dup=false; for e in "${RESOLVED_IP_REGISTRY[@]}"; do [[ "$e" == "$cr_exp" ]] && { dup=true; break; }; done
                                        $dup || RESOLVED_IP_REGISTRY+=("$cr_exp")
                                    fi
                                    if [[ -n "$cr_act" && ! "$cr_act" =~ ^\( ]]; then
                                        local dup=false; for e in "${RESOLVED_IP_REGISTRY[@]}"; do [[ "$e" == "$cr_act" ]] && { dup=true; break; }; done
                                        $dup || RESOLVED_IP_REGISTRY+=("$cr_act")
                                    fi
                                done

                                # Check for mismatches in this AMPLS
                                local this_mismatch=0 this_match=0
                                for cr in "${table_results[@]}"; do
                                    local cr_status="${cr##*|}"
                                    [[ "$cr_status" == "MISMATCH" || "$cr_status" == "FAIL" ]] && (( this_mismatch++ ))
                                    [[ "$cr_status" == "MATCH" ]] && (( this_match++ ))
                                done

                                if (( this_mismatch > 0 )); then
                                    any_mismatches=true
                                    if $VERBOSE_OUTPUT; then
                                        _print -n -c "$C_RED" "    ==> "
                                        _print -n -c "$C_RED" "$this_mismatch mismatched"
                                        _print -c "$C_GRAY" ", $this_match matched"
                                    fi

                                    # Auto-trigger ghost AMPLS reverse lookup for IngestionEndpoint mismatch
                                    if find_ingestion_endpoint_in_ampls_results "$ingestion_host" "${table_results[@]}"; then
                                        if [[ "$INGESTION_AMPLS_MATCH_STATUS" == "MISMATCH" && -n "$INGESTION_AMPLS_MATCH_ACTUAL_IP" && ! "$INGESTION_AMPLS_MATCH_ACTUAL_IP" =~ ^\( ]]; then
                                            if find_ampls_by_private_ip "$INGESTION_AMPLS_MATCH_ACTUAL_IP"; then
                                                _print ""
                                                _print -c "$C_CYAN" "      INGESTION ENDPOINT MISMATCH -- AMPLS IDENTIFIED:"
                                                _print -c "$C_WHITE" "        AMPLS Name:       $GHOST_AMPLS_NAME"
                                                _print -c "$C_GRAY" "        Resource Group:   $GHOST_AMPLS_RG"
                                                _print -c "$C_GRAY" "        Subscription:     $GHOST_AMPLS_SUB"
                                                _print -c "$C_GRAY" "        Private Endpoint: $GHOST_AMPLS_PE_NAME ($GHOST_AMPLS_PE_RG)"
                                                _print -c "$C_GRAY" "        Access Modes:     Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE"
                                                _print -c "$C_DARK_GRAY" "        PE Expected IP:   $INGESTION_AMPLS_MATCH_EXPECTED_IP  |  Actual DNS: $INGESTION_AMPLS_MATCH_ACTUAL_IP"
                                                _print ""
                                                _print -c "$C_YELLOW" "      The ingestion endpoint ($ingestion_host) resolves to $INGESTION_AMPLS_MATCH_ACTUAL_IP"
                                                _print -c "$C_YELLOW" "      instead of the expected $INGESTION_AMPLS_MATCH_EXPECTED_IP from AMPLS '$a_name'."
                                                _print -c "$C_YELLOW" "      A different AMPLS ('$GHOST_AMPLS_NAME') owns the private endpoint at that IP."

                                                add_diagnosis "WARNING" "Ghost AMPLS Overriding Ingestion Endpoint: $GHOST_AMPLS_NAME" \
                                                    "Ingestion endpoint resolves to IP $INGESTION_AMPLS_MATCH_ACTUAL_IP owned by AMPLS '$GHOST_AMPLS_NAME' instead of '$a_name'" \
                                                    "The ingestion FQDN ($INGESTION_AMPLS_MATCH_FQDN) resolves to $INGESTION_AMPLS_MATCH_ACTUAL_IP which belongs to PE '$GHOST_AMPLS_PE_NAME' connected to AMPLS '$GHOST_AMPLS_NAME' (Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE). Expected IP was $INGESTION_AMPLS_MATCH_EXPECTED_IP from '$a_name'." \
                                                    "Ensure only one AMPLS private endpoint is authoritative for ingestion DNS, or add $ai_name to AMPLS '$GHOST_AMPLS_NAME'." \
                                                    "" \
                                                    "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                                            elif [[ "$INGESTION_AMPLS_MATCH_ACTUAL_IP" =~ ^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\. ]]; then
                                                _print ""
                                                _print -c "$C_DARK_GRAY" "      The ingestion endpoint ($ingestion_host) resolves to private IP $INGESTION_AMPLS_MATCH_ACTUAL_IP"
                                                _print -c "$C_DARK_GRAY" "      but the owning private endpoint could not be identified. It may be in a"
                                                _print -c "$C_DARK_GRAY" "      subscription your account cannot access."
                                            fi
                                        fi
                                    fi
                                else
                                    if $VERBOSE_OUTPUT && (( this_match > 0 )); then
                                        _print -n -c "$C_GREEN" "    ==> "
                                        _print -c "$C_GREEN" "All $this_match DNS entries match. Private link is correctly configured."
                                    fi
                                fi
                            else
                                if $VERBOSE_OUTPUT; then
                                    _print -n -c "$C_GRAY" "    Private Endpoint: "
                                    _print -c "$C_DARK_GRAY" "(no private endpoints found)"
                                    _print ""
                                    _print -c "$C_DARK_GRAY" "    This AMPLS resource exists but has not been connected to a Private Endpoint"
                                    _print -c "$C_DARK_GRAY" "    or VNet. Without a Private Endpoint, no private DNS zones are created and"
                                    _print -c "$C_DARK_GRAY" "    no traffic will route through this AMPLS. To complete the setup, create a"
                                    _print -c "$C_DARK_GRAY" "    Private Endpoint and link it to a VNet."
                                    _print -c "$C_DARK_GRAY" "    Docs: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                                fi
                            fi
                        done

                        # DNS mismatch troubleshooting block (verbose, after all AMPLS)
                        if $VERBOSE_OUTPUT && $any_mismatches; then
                            _print ""
                            _print -c "$C_DARK_GRAY" "  ========================================================================="
                            _print -c "$C_RED" "  DNS MISMATCH TROUBLESHOOTING"
                            _print -c "$C_DARK_GRAY" "  ========================================================================="
                            _print ""
                            _print -c "$C_GRAY" "  This machine's DNS is NOT resolving to the expected AMPLS private IPs."
                            if $any_private_only; then
                                _print -c "$C_YELLOW" "  At least one AMPLS uses 'PrivateOnly' mode -- clients on that VNet"
                                _print -c "$C_YELLOW" "  will be BLOCKED from reaching unscoped Azure Monitor resources."
                            fi
                            _print ""
                            _print -c "$C_CYAN" "  COMMON CAUSES:"
                            _print -c "$C_GRAY" "    1. Private DNS zones (${domain_privatelink}) not linked to this VNet"
                            _print -c "$C_GRAY" "    2. Custom DNS server not forwarding to Azure DNS (168.63.129.16)"
                            _print -c "$C_GRAY" "    3. Another AMPLS private endpoint is overriding DNS for this VNet"
                            _print -c "$C_GRAY" "    4. Stale DNS cache on this machine"
                            _print -c "$C_GRAY" "    5. Private DNS zone A records are missing or incorrect"
                            _print ""
                            _print -c "$C_CYAN" "  RESOLUTION STEPS:"
                            _print -c "$C_GRAY" "    1. Azure Portal > Private DNS zones > ${domain_privatelink}"
                            _print -c "$C_GRAY" "    2. Verify A records exist for each mismatched FQDN above"
                            _print -c "$C_GRAY" "    3. Verify the zone is linked to the VNet this machine is connected to"
                            _print -c "$C_GRAY" "    4. If using custom DNS: verify conditional forwarder for ${domain_monitor}"
                            _print -c "$C_GRAY" "       points to Azure DNS (168.63.129.16)"
                            _print -c "$C_GRAY" "    5. Flush DNS on this machine and re-run this script"
                            _print -c "$C_GRAY" "    6. If DNS records are still stale, remove and re-add the Azure Monitor resource"
                            _print -c "$C_GRAY" "       in the AMPLS to force a Private DNS zone refresh."
                            _print -c "$C_GRAY" "       Docs: https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure#connect-resources-to-the-ampls"
                            _print ""
                        elif $VERBOSE_OUTPUT && ! $any_mismatches; then
                            _print ""
                        fi
                    fi

                    # =====================================================================
                    # NETWORK ACCESS ASSESSMENT
                    # =====================================================================

                    # Determine this machine's network position
                    local client_net_type="Public"
                    local client_ingestion_ip="(unknown)"
                    local client_dns_matches_ampls=false

                    # Find DNS result for the ingestion host
                    for di in "${!DNS_R_HOSTNAME[@]}"; do
                        if [[ "${DNS_R_HOSTNAME[$di]}" == "$ingestion_host" && "${DNS_R_STATUS[$di]}" == "PASS" ]]; then
                            client_ingestion_ip="${DNS_R_IP[$di]}"
                            if [[ "${DNS_R_PRIVATE[$di]}" == "true" ]]; then
                                client_net_type="Private"
                                # Check if any comparison result matched
                                for cr in "${ampls_comparison_results[@]}"; do
                                    local cr_status="${cr##*|}"
                                    [[ "$cr_status" == "MATCH" ]] && client_dns_matches_ampls=true && break
                                done
                            fi
                            break
                        fi
                    done

                    # If DNS failed entirely
                    local dns_failed_for_ingestion=false
                    if [[ "$client_ingestion_ip" == "(unknown)" ]]; then
                        # Check if DNS failed
                        for di in "${!DNS_R_HOSTNAME[@]}"; do
                            if [[ "${DNS_R_HOSTNAME[$di]}" == "$ingestion_host" && "${DNS_R_STATUS[$di]}" == "FAIL" ]]; then
                                client_net_type="Unknown (DNS failed)"
                                dns_failed_for_ingestion=true
                                break
                            fi
                        done
                    fi

                    # Gather first AMPLS access mode for display
                    local ampls_ing_mode="(no AMPLS)"
                    local ampls_q_mode="(no AMPLS)"
                    local ampls_display_name="None linked"
                    if (( ${#ampls_access_modes[@]} > 0 )); then
                        local IFS='|'
                        local -a am_fields
                        read -ra am_fields <<< "${ampls_access_modes[0]}"
                        ampls_display_name="${am_fields[0]}"
                        ampls_ing_mode="${am_fields[1]}"
                        ampls_q_mode="${am_fields[2]}"
                    fi

                    # Compute verdicts
                    local ingestion_verdict="UNKNOWN" ingestion_reason="" query_verdict="UNKNOWN" query_reason=""
                    local -a ingestion_fix=() query_fix=()

                    if [[ "$client_net_type" == "Unknown (DNS failed)" ]]; then
                        ingestion_verdict="BLOCKED"
                        ingestion_reason="DNS resolution failed for the ingestion endpoint."
                        ingestion_fix=("Fix DNS resolution first. See the DNS failures above.")
                        query_verdict="BLOCKED"
                        query_reason="DNS resolution failed."
                        query_fix=("Fix DNS resolution first.")

                    elif ! $ampls_linked; then
                        if [[ "$client_net_type" == "Private" ]]; then
                            ingestion_verdict="BLOCKED"
                            ingestion_reason="DNS resolves to private IPs, but this App Insights resource is NOT in any AMPLS. Another AMPLS is overriding DNS."
                            ingestion_fix=("Add this App Insights resource to the AMPLS that owns the private endpoint on this VNet." "Or change that AMPLS ingestion access mode to 'Open'.")
                            query_verdict="BLOCKED"
                            query_reason="$ingestion_reason"
                            query_fix=("${ingestion_fix[@]}")
                        else
                            if [[ "$ai_public_ingestion" == "Enabled" ]]; then
                                ingestion_verdict="ALLOWED"
                                ingestion_reason="No AMPLS configured. App Insights accepts ingestion from all networks."
                            else
                                ingestion_verdict="BLOCKED"
                                ingestion_reason="Ingestion restricted to private networks, but no AMPLS configured."
                                ingestion_fix=("Enable public ingestion, or configure AMPLS with a private endpoint.")
                            fi
                            if [[ "$ai_public_query" == "Enabled" ]]; then
                                query_verdict="ALLOWED"
                                query_reason="No AMPLS configured. App Insights accepts queries from all networks."
                            else
                                query_verdict="BLOCKED"
                                query_reason="Query access restricted to private networks, but no AMPLS configured."
                                query_fix=("Enable public query access, or configure AMPLS with a private endpoint.")
                            fi
                        fi

                    elif [[ "$client_net_type" == "Private" ]] && $client_dns_matches_ampls; then
                        ingestion_verdict="ALLOWED"
                        ingestion_reason="On AMPLS-connected private network. DNS matches private endpoint."
                        query_verdict="ALLOWED"
                        query_reason="On AMPLS-connected private network. Queries flow through private link."

                    elif [[ "$client_net_type" == "Private" ]] && ! $client_dns_matches_ampls; then
                        ingestion_verdict="BLOCKED"
                        ingestion_reason="Private IPs don't match AMPLS. Traffic going to wrong private endpoint or DNS is stale."
                        ingestion_fix=("Verify private DNS zones are linked to VNet. Flush DNS cache.")
                        query_verdict="BLOCKED"
                        query_reason="$ingestion_reason"
                        query_fix=("${ingestion_fix[@]}")

                    else
                        # Public client with AMPLS linked
                        if [[ "$ai_public_ingestion" == "Enabled" ]]; then
                            ingestion_verdict="ALLOWED"
                            ingestion_reason="Public network. App Insights accepts ingestion from all networks."
                        else
                            ingestion_verdict="BLOCKED"
                            ingestion_reason="Public network, but App Insights has public ingestion disabled (HTTP 403)."
                            ingestion_fix=("Run from AMPLS-connected VNet, or enable public ingestion.")
                        fi
                        if [[ "$ai_public_query" == "Enabled" ]]; then
                            query_verdict="ALLOWED"
                            query_reason="Public network. App Insights accepts queries from all networks."
                        else
                            query_verdict="BLOCKED"
                            query_reason="Public network, but App Insights has public query access disabled."
                            query_fix=("Access Portal from AMPLS-connected VNet, or enable public queries.")
                        fi
                    fi

                    # --- AMPLS progress lines (always, BEFORE verbose display) ---
                    if $ampls_linked; then
                        local amp_mismatches=0 amp_matches=0
                        for cr in "${ampls_comparison_results[@]}"; do
                            local cr_status="${cr##*|}"
                            [[ "$cr_status" == "MISMATCH" || "$cr_status" == "FAIL" ]] && (( amp_mismatches++ ))
                            [[ "$cr_status" == "MATCH" ]] && (( amp_matches++ ))
                        done
                        local mode_note=""
                        $any_private_only && mode_note=" (PrivateOnly mode)"

                        if (( amp_mismatches > 0 )); then
                            write_progress_line "AMPLS Configuration" "WARN" "$amp_mismatches DNS mismatches$mode_note"
                            add_diagnosis "WARNING" "AMPLS DNS Mismatches ($amp_mismatches of ${#ampls_comparison_results[@]} endpoints)" \
                                "AMPLS DNS mismatches ($amp_mismatches of ${#ampls_comparison_results[@]} endpoints resolve to wrong IPs)" \
                                "This machine's DNS does not resolve to the expected AMPLS private endpoint IPs." \
                                "Verify private DNS zones (${domain_privatelink}) are linked to your VNet. Flush DNS cache." \
                                "" \
                                "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                        elif (( amp_matches > 0 )); then
                            write_progress_line "AMPLS Configuration" "OK" "$amp_matches IPs matched ($ampls_display_name)$mode_note"
                        else
                            write_progress_line "AMPLS Configuration" "OK" "Linked to $ampls_display_name$mode_note"
                        fi
                    else
                        if $has_ampls_signals; then
                            write_progress_line "AMPLS Configuration" "WARN" "No AMPLS linked, but private IPs detected"
                        else
                            write_progress_line "AMPLS Configuration" "OK" "No AMPLS (telemetry accepted at public endpoints)"
                        fi
                    fi

                    # App Insights Network Access progress line
                    local ingestion_access_label="All networks"
                    [[ "$ai_public_ingestion" != "Enabled" ]] && ingestion_access_label="Private only"
                    local query_access_label="All networks"
                    [[ "$ai_public_query" != "Enabled" ]] && query_access_label="Private only"
                    local network_access_summary="Ingestion: $ingestion_access_label | Query: $query_access_label"
                    if [[ "$ai_public_ingestion" != "Enabled" || "$ai_public_query" != "Enabled" ]]; then
                        write_progress_line "App Insights Network Access" "INFO" "$network_access_summary"
                    else
                        write_progress_line "App Insights Network Access" "OK" "$network_access_summary"
                    fi

                    # Diagnosis items for blocked verdicts
                    if [[ "$ingestion_verdict" == "BLOCKED" ]]; then
                        INGESTION_BLOCKED_PREFLIGHT=true
                        local fix_text=""
                        for f in "${ingestion_fix[@]}"; do fix_text+="$f "; done
                        add_diagnosis "BLOCKING" "Ingestion BLOCKED From This Machine" \
                            "Ingestion blocked ($ingestion_reason)" \
                            "$ingestion_reason" \
                            "$fix_text" \
                            "App Insights ($ai_name) > Network Isolation > 'Enabled from all networks'" \
                            "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                    fi
                    if [[ "$query_verdict" == "BLOCKED" ]]; then
                        local fix_text=""
                        for f in "${query_fix[@]}"; do fix_text+="$f "; done
                        add_diagnosis "WARNING" "Query Access BLOCKED From This Machine" \
                            "Query access blocked (Portal charts will show empty)" \
                            "$query_reason If you see empty charts in the Azure Portal, this is likely why." \
                            "$fix_text" \
                            "App Insights ($ai_name) > Network Isolation > 'Enabled from all networks'" \
                            "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design"
                    fi

                    # Verbose Access Assessment display
                    if $VERBOSE_OUTPUT; then
                        _print ""
                        write_header_always "NETWORK ACCESS ASSESSMENT FOR THIS MACHINE"
                        _print ""
                        _print -c "$C_GRAY" "  This combines your App Insights resource settings, AMPLS configuration,"
                        _print -c "$C_GRAY" "  and the DNS results from this machine to determine whether telemetry"
                        _print -c "$C_GRAY" "  ingestion and data queries will work from HERE."
                        _print ""

                        local ai_ing_display="Enabled from all networks"
                        [[ "$ai_public_ingestion" != "Enabled" ]] && ai_ing_display="Disabled (private only)"
                        local ai_q_display="Enabled from all networks"
                        [[ "$ai_public_query" != "Enabled" ]] && ai_q_display="Disabled (private only)"
                        local client_net_display="$client_net_type"
                        if [[ "$client_net_type" == "Private" ]] && $client_dns_matches_ampls; then
                            client_net_display="Private (DNS matches AMPLS private endpoint)"
                        elif [[ "$client_net_type" == "Private" ]]; then
                            client_net_display="Private (DNS resolves to private IP, but does NOT match AMPLS)"
                        fi

                        _print -c "$C_CYAN" "  YOUR CONFIGURATION:"
                        _print ""
                        _print -c "$C_WHITE" "    App Insights ($ai_name):"
                        _print -c "$C_GRAY" "      Ingestion access:  $ai_ing_display"
                        _print -c "$C_GRAY" "      Query access:      $ai_q_display"
                        _print ""

                        if $ampls_linked; then
                            for am_entry in "${ampls_access_modes[@]}"; do
                                local IFS='|'
                                local -a am_f
                                read -ra am_f <<< "$am_entry"
                                _print -c "$C_WHITE" "    AMPLS (${am_f[0]}):"
                                local ing_label="Open (VNet clients can reach scoped + public resources)"
                                [[ "${am_f[1]}" == "PrivateOnly" ]] && ing_label="PrivateOnly (VNet clients can only reach scoped resources)"
                                local q_label="Open (VNet clients can query scoped + public resources)"
                                [[ "${am_f[2]}" == "PrivateOnly" ]] && q_label="PrivateOnly (VNet clients can only query scoped resources)"
                                _print -c "$C_GRAY" "      Ingestion mode:    $ing_label"
                                _print -c "$C_GRAY" "      Query mode:        $q_label"
                                _print ""
                            done
                        else
                            _print -n -c "$C_WHITE" "    AMPLS: "
                            _print -c "$C_GRAY" "None linked to this App Insights resource"
                        fi
                        _print ""
                        _print -c "$C_WHITE" "    This machine:"
                        _print -c "$C_GRAY" "      Ingestion endpoint: $ingestion_host"
                        _print -c "$C_GRAY" "      Resolved to:        $client_ingestion_ip"
                        _print -c "$C_GRAY" "      Network position:   $client_net_display"
                        _print ""

                        _print -c "$C_CYAN" "  FROM THIS MACHINE:"
                        _print ""

                        # Ingestion verdict
                        local ing_color="$C_GREEN" ing_symbol="+"
                        [[ "$ingestion_verdict" != "ALLOWED" ]] && ing_color="$C_RED" && ing_symbol="X"
                        _print -c "$C_WHITE" "    Ingestion (sending telemetry TO App Insights):"
                        _print -c "$ing_color" "    [$ing_symbol] $ingestion_verdict"
                        _print -c "$C_GRAY" "    $ingestion_reason"
                        if (( ${#ingestion_fix[@]} > 0 )); then
                            _print ""
                            _print -c "$C_YELLOW" "    TO FIX:"
                            for fix in "${ingestion_fix[@]}"; do
                                _print -c "$C_GRAY" "      $fix"
                            done
                        fi
                        _print ""

                        # Query verdict
                        local q_color="$C_GREEN" q_symbol="+"
                        [[ "$query_verdict" != "ALLOWED" ]] && q_color="$C_RED" && q_symbol="X"
                        _print -c "$C_WHITE" "    Query (reading data FROM App Insights, e.g. Azure Portal, API):"
                        _print -c "$q_color" "    [$q_symbol] $query_verdict"
                        _print -c "$C_GRAY" "    $query_reason"
                        if (( ${#query_fix[@]} > 0 )); then
                            _print ""
                            _print -c "$C_YELLOW" "    TO FIX:"
                            for fix in "${query_fix[@]}"; do
                                _print -c "$C_GRAY" "      $fix"
                            done
                        fi

                        if [[ "$query_verdict" == "BLOCKED" ]]; then
                            _print ""
                            _print -c "$C_YELLOW" "    IMPORTANT -- this affects the Azure Portal too:"
                            _print -c "$C_GRAY" "      If you see 'no data' or empty charts in App Insights, it may be because"
                            _print -c "$C_GRAY" "      your browser is on a public network but query access is restricted."
                            _print -c "$C_GRAY" "      The telemetry may actually be there -- you just can't see it from here."
                        fi

                        _print ""
                        _print -c "$C_DARK_GRAY" "  For more information on these settings:"
                        _print -c "$C_DARK_GRAY" "    AMPLS access modes:      https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design#select-an-access-mode"
                        _print -c "$C_DARK_GRAY" "    Network isolation:        https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design#control-network-access-to-ampls-resources"
                        _print -c "$C_DARK_GRAY" "    Configure private link:   https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                    fi

                else
                    # App Insights resource not found
                    write_progress_line "AMPLS Validation" "INFO" "App Insights resource not found for this iKey"
                    local not_found_detail="The resource may be in a different tenant or a subscription your account cannot access."
                    local not_found_action="Ensure you have Reader access to the subscription containing this App Insights resource."
                    if [[ -z "$TENANT_ID" ]]; then
                        not_found_action+=" If your account spans multiple tenants, specify --tenant-id to target the correct one."
                    fi
                    write_result "INFO" "App Insights resource not found for iKey: $masked_key" \
                        "$not_found_detail" "$not_found_action"
                    if [[ -z "$TENANT_ID" ]]; then
                        local az_tenant_id
                        az_tenant_id="$(az account show --query 'tenantId' -o tsv 2>/dev/null)"
                        az_tenant_id="${az_tenant_id//$'\r'/}"
                        add_diagnosis "INFO" "App Insights Resource Not Found" \
                            "Cannot find AI resource in tenant (wrong tenant?)" \
                            "Could not find the AI resource in tenant ${az_tenant_id:-unknown}. If your account has access to multiple Entra ID tenants, re-run with --tenant-id to target the correct tenant." \
                            "Re-run with --tenant-id 'your-tenant-id-or-domain.onmicrosoft.com'" \
                            "" \
                            "https://learn.microsoft.com/cli/azure/authenticate-azure-cli"
                    fi
                fi
            fi
        fi
    fi

    # If Azure consent was declined, show skip progress line
    if $azure_consent_declined; then
        write_progress_line "Azure Resource Checks" "SKIP" "Consent declined (use --auto-approve to bypass)"
        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_YELLOW" "  Azure resource checks skipped (consent declined)."
            _print -c "$C_GRAY" "  Use --auto-approve to bypass consent prompts, or --network-only to skip Azure checks."
            _print ""
        fi
    # If AMPLS wasn't checked but we detected private IPs, hint about it
    elif $has_ampls_signals && ! $ampls_checked; then
        write_progress_line "AMPLS Configuration" "INFO" "Private IPs detected. Run 'az login' or use --ampls-expected-ips to validate."
        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
            _print -c "$C_DARK_GRAY" "  TIP: Private IPs were detected in DNS results. To validate they match your"
            if $ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP; then
                _print -c "$C_DARK_GRAY" "  AMPLS configuration, run this script from Azure Cloud Shell or a machine with az CLI."
            else
                _print -c "$C_DARK_GRAY" "  AMPLS configuration, install the az CLI and log in:"
                _print -c "$C_WHITE" "    az login && az extension add --name resource-graph"
            fi
            _print ""
            _print -c "$C_DARK_GRAY" "  Or provide expected IPs manually:"
            _print -n -c "$C_DARK_GRAY" "    --ampls-expected-ips "
            _print -c "$C_WHITE" "\"your-endpoint.azure.com=10.0.x.x\""
            _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
        fi
    fi

    # ================================================================
    # Manual --lookup-ampls-ip: user-requested reverse lookup
    # ================================================================
    if [[ -n "$LOOKUP_AMPLS_IP" ]]; then
        (( STEP_NUMBER++ ))
        write_header_always "STEP $STEP_NUMBER: AMPLS Reverse-Lookup (Manual)"
        _print ""
        _print -c "$C_GRAY" "  Validating IP: $LOOKUP_AMPLS_IP"

        validate_ampls_ip_parameter "$LOOKUP_AMPLS_IP"
        if ! $AMPLS_IP_VALID; then
            write_result "FAIL" "IP validation failed"
            _print ""
            _print -c "$C_YELLOW" "  $AMPLS_IP_REASON"
            _print ""
        else
            write_result "PASS" "IP validated -- running reverse lookup"
            if find_ampls_by_private_ip "$LOOKUP_AMPLS_IP"; then
                _print ""
                _print -n -c "$C_CYAN" "  AMPLS IDENTIFIED: "
                _print -c "$C_WHITE" "$GHOST_AMPLS_NAME"
                _print -c "$C_GRAY" "    Resource Group:   $GHOST_AMPLS_RG"
                _print -c "$C_GRAY" "    Subscription:     $GHOST_AMPLS_SUB"
                _print -c "$C_GRAY" "    Private Endpoint: $GHOST_AMPLS_PE_NAME ($GHOST_AMPLS_PE_RG)"
                _print -c "$C_GRAY" "    Access Modes:     Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE"
                _print -c "$C_DARK_GRAY" "    Looked up IP:     $LOOKUP_AMPLS_IP"
                _print ""
                _print -c "$C_YELLOW" "  This AMPLS owns the private endpoint associated with IP $LOOKUP_AMPLS_IP."
                _print -c "$C_YELLOW" "  If this is not your expected AMPLS, add your resource to this AMPLS or set its access mode to 'Open'."
                _print ""

                add_diagnosis "INFO" "Manual Lookup: AMPLS '$GHOST_AMPLS_NAME' owns IP $LOOKUP_AMPLS_IP" \
                    "AMPLS '$GHOST_AMPLS_NAME' in RG '$GHOST_AMPLS_RG' owns the private endpoint for IP $LOOKUP_AMPLS_IP" \
                    "Reverse lookup of IP $LOOKUP_AMPLS_IP found NIC -> PE '$GHOST_AMPLS_PE_NAME' -> AMPLS '$GHOST_AMPLS_NAME' (Ingestion=$GHOST_AMPLS_ING_MODE, Query=$GHOST_AMPLS_Q_MODE)." \
                    "If this AMPLS is unexpected, add your Azure Monitor resource to it or set its ingestion access mode to 'Open'." \
                    "" \
                    "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
            else
                _print ""
                _print -c "$C_YELLOW" "  The private endpoint for IP $LOOKUP_AMPLS_IP could not be identified."
                _print -c "$C_GRAY" "  It may be in a subscription your account cannot access, or the private"
                _print -c "$C_GRAY" "  DNS zone may have been configured manually."
                _print ""

                add_diagnosis "INFO" "Manual Lookup: No AMPLS found for IP $LOOKUP_AMPLS_IP" \
                    "Reverse lookup of $LOOKUP_AMPLS_IP did not find an AMPLS resource in accessible subscriptions" \
                    "The IP $LOOKUP_AMPLS_IP could not be traced to an AMPLS-connected private endpoint. The PE may be in an inaccessible subscription or the DNS record may have been configured manually." \
                    "Check private DNS zones for manual A records, or ask the network/subscription owner to investigate." \
                    "" \
                    "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
            fi
        fi
    fi

    # ================================================================
    # STEP 7: KNOWN ISSUE CHECKS (requires Azure login)
    # ================================================================
    if $CHECK_AZURE && ! $NETWORK_ONLY && [[ -n "$AI_RESOURCE_ID" ]]; then
        (( STEP_NUMBER++ ))


        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Known Issue Checks"
            _print ""
            _print -c "$C_CYAN" "  WHY THIS MATTERS:"
            _print -c "$C_GRAY" "  These checks inspect your App Insights and Log Analytics resource configurations"
            _print -c "$C_GRAY" "  for common misconfigurations that cause silent data loss, duplication, or unexpected"
            _print -c "$C_GRAY" "  telemetry behavior -- even when network connectivity is perfectly healthy."
            _print ""
            _print -c "$C_CYAN" "  WHAT WE'RE CHECKING:"
            _print -c "$C_GRAY" "  - Authentication mode (local auth vs Entra ID)"
            _print -c "$C_GRAY" "  - Ingestion sampling (server-side data reduction)"
            _print -c "$C_GRAY" "  - Backend Log Analytics workspace health (exists, not over quota, access mode)"
            _print -c "$C_GRAY" "  - Daily cap settings (App Insights cap vs Log Analytics cap)"
            _print -c "$C_GRAY" "  - Diagnostic Settings (duplicate telemetry exported to LA)"
            _print -c "$C_GRAY" "  - Workspace transforms / DCRs (silent data alteration)"
        fi

        local ai_id="$AI_RESOURCE_ID"
        local ai_name="$AI_RESOURCE_NAME"

        # ==============================================================
        # Known Issue #1: Local Auth Disabled (Entra ID Required)
        # ==============================================================
        write_progress_start "Authentication"
        local disable_local_auth="$AI_DISABLE_LOCAL_AUTH"
        _debug "Known Issue #1: DisableLocalAuth='$disable_local_auth' (from ARM refresh)"

        if [[ "$disable_local_auth" == "true" ]]; then
            LOCAL_AUTH_DISABLED=true
            add_diagnosis "INFO" "Local Authentication Disabled (Entra ID Required)" \
                "Local auth disabled -- SDKs must use Entra ID tokens (iKey returns 401)" \
                "This App Insights resource requires Entra ID (Azure AD) authentication. Standard iKey local auth is rejected with HTTP 401." \
                "Configure SDK for Entra ID auth (Managed Identity or Service Principal), or re-enable local auth if unintentional." \
                "App Insights > Properties > Local Authentication" \
                "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"

            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Authentication Settings"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -n -c "$C_GRAY" "  Local Authentication: "
                _print -c "$C_YELLOW" "DISABLED"
                _print ""
                _print -c "$C_GRAY" "  This App Insights resource requires Entra ID (Azure AD) authentication."
                _print -c "$C_GRAY" "  Standard iKey-based local auth ingestion is rejected with HTTP 401."
                _print ""
                _print -c "$C_CYAN" "  WHAT THIS MEANS FOR YOUR APPLICATION:"
                _print -c "$C_GRAY" "    Your SDKs MUST send an Entra ID bearer token with each telemetry request."
                _print -c "$C_GRAY" "    Without it, ingestion fails silently -- SDKs receive 401 but typically"
                _print -c "$C_GRAY" "    do not surface this to application logs unless SDK diagnostic logging"
                _print -c "$C_GRAY" "    is explicitly enabled."
                _print ""
                _print -c "$C_CYAN" "  IF YOU ARE NOT SEEING TELEMETRY:"
                _print -c "$C_GRAY" "    This is a likely root cause. Verify:"
                _print -c "$C_GRAY" "    1. Your SDK is configured for Entra ID auth (Managed Identity or Service Principal)"
                _print -c "$C_GRAY" "    2. The identity has 'Monitoring Metrics Publisher' role on this resource"
                _print -c "$C_GRAY" "    3. Check SDK diagnostic logs for 401 responses"
                _print -c "$C_GRAY" "    4. Enable SDK Stats for visibility into why telemetry is rejected."
                _print -c "$C_DARK_GRAY" "       https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats"
                _print ""
                _print -c "$C_CYAN" "  TO RE-ENABLE LOCAL AUTH (if this was unintentional):"
                _print -c "$C_GRAY" "    Azure Portal > App Insights > Properties > Local Authentication > Enabled"
                _print ""
                _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
                _print ""
            fi
            write_progress_line "Authentication" "INFO" "Local auth DISABLED (Entra ID required for ingestion)"
        else
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Authentication Settings"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -n -c "$C_GRAY" "  Local Authentication: "
                _print -c "$C_GREEN" "ENABLED"
                _print -c "$C_GRAY" "  Telemetry can be sent using the instrumentation key (standard iKey auth)."
                _print -c "$C_GRAY" "  Entra ID authentication is also accepted but not required."
                _print ""
            fi
            write_progress_line "Authentication" "OK" "Local auth enabled (iKey accepted)"
        fi

        # ==============================================================
        # Known Issue #2: Ingestion Sampling Configured
        # ==============================================================
        write_progress_start "Ingestion Sampling"
        local sampling_pct="100"
        if [[ -n "$AI_SAMPLING_PCT" && "$AI_SAMPLING_PCT" != "null" ]]; then
            sampling_pct="$AI_SAMPLING_PCT"
        fi
        _debug "Known Issue #2: SamplingPercentage='$sampling_pct' (from ARM refresh)"

        # Compare: is sampling_pct < 100?
        local sampling_active=false
        if $HAS_BC; then
            (( $(echo "$sampling_pct < 100" | bc -l 2>/dev/null) )) && sampling_active=true
        else
            # Integer comparison fallback
            local sp_int="${sampling_pct%%.*}"
            [[ -n "$sp_int" ]] && (( sp_int < 100 )) && sampling_active=true
        fi

        if $sampling_active; then
            local drop_pct
            if $HAS_BC; then
                drop_pct="$(echo "100 - $sampling_pct" | bc -l 2>/dev/null)"
            else
                local sp_int="${sampling_pct%%.*}"
                drop_pct="$(( 100 - sp_int ))"
            fi

            add_diagnosis "INFO" "Ingestion Sampling Enabled (${sampling_pct}%)" \
                "Ingestion sampling at ${sampling_pct}% (dropping ${drop_pct}% of accepted telemetry)" \
                "${drop_pct}% of incoming telemetry is dropped during ingestion, AFTER your SDKs have successfully sent it." \
                "Increase to 100% to retain all ingested data (increases cost), or verify this was intentionally configured." \
                "App Insights > Usage and estimated costs > Data Sampling" \
                "https://learn.microsoft.com/azure/azure-monitor/app/sampling-classic-api#ingestion-sampling"

            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Ingestion Sampling"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -n -c "$C_GRAY" "  SamplingPercentage: "
                _print -c "$C_YELLOW" "${sampling_pct}%"
                _print -n -c "$C_GRAY" "  Data dropped at ingestion: "
                _print -c "$C_YELLOW" "${drop_pct}%"
                _print ""
                _print -c "$C_CYAN" "  WHAT THIS MEANS:"
                _print -c "$C_GRAY" "    Your SDKs send telemetry to App Insights and receive HTTP 206 (partial accept)"
                _print -c "$C_GRAY" "    for items that are sampled out. Before the data reaches your Log Analytics"
                _print -c "$C_GRAY" "    workspace, App Insights randomly drops ${drop_pct}% of the telemetry items."
                _print ""
                _print -c "$C_GRAY" "    Ingestion sampling only applies to telemetry that was NOT already sampled by"
                _print -c "$C_GRAY" "    the SDK. Pre-sampled records pass through ingestion sampling untouched."
                _print ""
                _print -c "$C_CYAN" "  IMPACT:"
                _print -c "$C_GRAY" "    - Queries may return fewer results than expected"
                _print -c "$C_GRAY" "    - Specific traces, requests, or exceptions may be missing entirely"
                _print -c "$C_GRAY" "    - itemCount field does NOT compensate for ingestion sampling"
                _print -c "$C_GRAY" "    - End-to-end transaction views may show gaps"
                _print ""
                _print -c "$C_YELLOW" "  NOTE: Microsoft does not recommend ingestion sampling. Prefer SDK-side"
                _print -c "$C_YELLOW" "  adaptive sampling which preserves correlated telemetry items together."
                _print ""
                _print -c "$C_CYAN" "  TO CHANGE:"
                _print -c "$C_GRAY" "    Azure Portal > App Insights > Configure > Usage and estimated costs > Data Sampling"
                _print -c "$C_GRAY" "    Set to 100% to retain all ingested telemetry (increases cost)."
                _print ""
                _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-sampling#ingestion-sampling-not-recommended"
                _print ""
            fi
            write_progress_line "Ingestion Sampling" "INFO" "Sampling at ${sampling_pct}% (dropping ${drop_pct}% of telemetry)"
        else
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Ingestion Sampling"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -n -c "$C_GRAY" "  SamplingPercentage: "
                _print -c "$C_GREEN" "100% (no ingestion sampling)"
                _print -c "$C_GRAY" "  All telemetry accepted by the ingestion API is retained."
                _print ""
            fi
            write_progress_line "Ingestion Sampling" "OK" "100% (all ingested telemetry retained)"
        fi

        # ==============================================================
        # Known Issues #3, #4: Backend LA Workspace Health + Daily Cap
        # ==============================================================
        write_progress_start "Backend LA Workspace"
        WS_RESOURCE_ID="$AI_WORKSPACE_RESOURCE_ID"
        _debug "Known Issue #3/#4: WorkspaceResourceId='${WS_RESOURCE_ID:-(empty)}' (from ARM refresh)"

        local cap_status="Unknown"
        local cap_quota_gb=""
        local cap_reset_time=""

        if [[ -z "$WS_RESOURCE_ID" || "$WS_RESOURCE_ID" == "null" ]]; then
            WS_RESOURCE_ID=""
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Backend Log Analytics Workspace"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -c "$C_YELLOW" "  Could not find WorkspaceResourceId in App Insights resource properties."
                _print -c "$C_GRAY" "  This may indicate a classic (non-workspace-based) App Insights resource."
                _print ""
            fi
            write_progress_line "Backend LA Workspace" "INFO" "No WorkspaceResourceId found in AI resource properties"
        else
            # Extract workspace name from resource ID
            WS_NAME="${WS_RESOURCE_ID##*/}"

            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Backend Log Analytics Workspace"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -c "$C_GRAY" "  App Insights sends telemetry to this backend LA workspace:"
                _print -c "$C_WHITE" "    Name: $WS_NAME"
                _print -c "$C_DARK_GRAY" "    URI:  $WS_RESOURCE_ID"
                _print ""
                _print -c "$C_GRAY" "  Querying workspace resource via ARM..."
            fi

            # Query ARM directly for the workspace (avoids ARG staleness, matches PS1 approach)
            local ws_arm_url="https://management.azure.com${WS_RESOURCE_ID}?api-version=2023-09-01"

            local ws_found=false
            local ws_customer_id="(unknown)"
            local ws_json=""
            local ws_http_code=""

            _debug_az_rest "GET" "$ws_arm_url"

            # Use az rest with --resource to get proper ARM authentication
            # Capture HTTP status via a temp file for stderr, and parse response
            ws_json="$(az rest --method GET --url "$ws_arm_url" 2>/tmp/ws_arm_err_$$.tmp | tr -d '\r')"
            local ws_arm_err
            ws_arm_err="$(cat /tmp/ws_arm_err_$$.tmp 2>/dev/null)"
            rm -f /tmp/ws_arm_err_$$.tmp

            # Determine the effective HTTP status from the response/error
            # az rest returns non-zero exit code on 4xx/5xx and writes error to stderr
            if [[ -n "$ws_json" && "$ws_json" != "null" && "$ws_json" == "{"* ]]; then
                ws_http_code="200"
            elif [[ "$ws_arm_err" == *"(ResourceNotFound)"* || "$ws_arm_err" == *"(ResourceGroupNotFound)"* || "$ws_arm_err" == *"404"* || "$ws_arm_err" == *"Not Found"* ]]; then
                ws_http_code="404"
            elif [[ "$ws_arm_err" == *"AuthorizationFailed"* || "$ws_arm_err" == *"(AuthorizationFailed)"* || "$ws_arm_err" == *"403"* || "$ws_arm_err" == *"Authorization"*"denied"* || "$ws_arm_err" == *"does not have authorization"* ]]; then
                ws_http_code="403"
            elif [[ "$ws_arm_err" == *"401"* || "$ws_arm_err" == *"Unauthorized"* ]]; then
                ws_http_code="401"
            else
                ws_http_code="unknown"
            fi
            _debug_response "HTTP $ws_http_code (ARM workspace)" "$ws_json"

            if [[ "$ws_http_code" == "200" ]]; then
                ws_found=true
                local ws_location=""
                local ws_access_resource_permissions=""
                if $HAS_JQ; then
                    ws_customer_id="$(echo "$ws_json" | jq -r '.properties.customerId // "(unknown)"' 2>/dev/null)"
                    ws_location="$(echo "$ws_json" | jq -r '.location // empty' 2>/dev/null)"
                    cap_status="$(echo "$ws_json" | jq -r '.properties.workspaceCapping.dataIngestionStatus // "Unknown"' 2>/dev/null)"
                    cap_quota_gb="$(echo "$ws_json" | jq -r '.properties.workspaceCapping.dailyQuotaGb // empty' 2>/dev/null)"
                    cap_reset_time="$(echo "$ws_json" | jq -r '.properties.workspaceCapping.quotaNextResetTime // empty' 2>/dev/null)"
                    ws_access_resource_permissions="$(echo "$ws_json" | jq -r '.properties.features.enableLogAccessUsingOnlyResourcePermissions // empty' 2>/dev/null)"
                else
                    # No jq: use az rest --query (JMESPath) against the same ARM endpoint
                    # to extract individual fields from a live ARM response (no ARG staleness)
                    _debug "Extracting workspace fields via individual ARM queries (jq not available)"
                    ws_customer_id="$(az rest --method GET --url "$ws_arm_url" --query "properties.customerId" -o tsv 2>/dev/null | tr -d '\r')"
                    ws_location="$(az rest --method GET --url "$ws_arm_url" --query "location" -o tsv 2>/dev/null | tr -d '\r')"
                    cap_status="$(az rest --method GET --url "$ws_arm_url" --query "properties.workspaceCapping.dataIngestionStatus" -o tsv 2>/dev/null | tr -d '\r')"
                    cap_quota_gb="$(az rest --method GET --url "$ws_arm_url" --query "properties.workspaceCapping.dailyQuotaGb" -o tsv 2>/dev/null | tr -d '\r')"
                    cap_reset_time="$(az rest --method GET --url "$ws_arm_url" --query "properties.workspaceCapping.quotaNextResetTime" -o tsv 2>/dev/null | tr -d '\r')"
                    ws_access_resource_permissions="$(az rest --method GET --url "$ws_arm_url" --query "properties.features.enableLogAccessUsingOnlyResourcePermissions" -o tsv 2>/dev/null | tr -d '\r')"
                fi
                [[ "$ws_customer_id" == "null" || -z "$ws_customer_id" ]] && ws_customer_id="(unknown)"
                [[ "$ws_location" == "null" ]] && ws_location=""
                [[ "$cap_status" == "null" || -z "$cap_status" ]] && cap_status="Unknown"
                [[ "$cap_quota_gb" == "null" ]] && cap_quota_gb=""
                [[ "$cap_reset_time" == "null" ]] && cap_reset_time=""
                [[ "$ws_access_resource_permissions" == "null" ]] && ws_access_resource_permissions=""

                # Determine if LA cap is off
                if [[ -z "$cap_quota_gb" || "$cap_quota_gb" == "-1" ]]; then
                    WS_CAP_OFF=true
                    WS_CAP_QUOTA_GB=""
                else
                    WS_CAP_OFF=false
                    WS_CAP_QUOTA_GB="$cap_quota_gb"
                fi

                if $VERBOSE_OUTPUT; then
                    _print -c "$C_GREEN" "  [OK] Workspace exists"
                    _print -c "$C_GRAY" "    Workspace ID (customerId): $ws_customer_id"
                    [[ -n "$ws_location" ]] && _print -c "$C_GRAY" "    Location: $ws_location"
                fi

                # --- Workspace Access Control Mode check ---
                # enableLogAccessUsingOnlyResourcePermissions:
                #   true  = "Use resource or workspace permissions" (default for workspaces created after March 2019)
                #   false/absent = "Require workspace permissions" (legacy default)
                # When set to "Require workspace permissions", users who have Reader on the
                # App Insights resource but NO role on the LA workspace will get HTTP 200
                # with empty results from data plane queries -- the API silently returns nothing.
                local ws_access_mode_label=""
                local ws_require_workspace_perms=false
                if [[ "$ws_access_resource_permissions" == "true" ]]; then
                    ws_access_mode_label="Use resource or workspace permissions"
                elif [[ "$ws_access_resource_permissions" == "false" || -z "$ws_access_resource_permissions" ]]; then
                    ws_access_mode_label="Require workspace permissions"
                    ws_require_workspace_perms=true
                else
                    ws_access_mode_label="Unknown ($ws_access_resource_permissions)"
                fi

                if $ws_require_workspace_perms; then
                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -n -c "$C_YELLOW" "  [i] "
                        _print -c "$C_YELLOW" "Workspace Access Control Mode: Require workspace permissions"
                        _print ""
                        _print -c "$C_CYAN" "  WHAT THIS MEANS:"
                        _print -c "$C_GRAY" "  This workspace requires EXPLICIT workspace-level RBAC to query data."
                        _print -c "$C_GRAY" "  Users who have Reader on the App Insights resource but NO role on the"
                        _print -c "$C_GRAY" "  Log Analytics workspace will get HTTP 200 with EMPTY results from"
                        _print -c "$C_GRAY" "  data plane queries. The API does not return 403 -- it silently returns"
                        _print -c "$C_GRAY" "  no data, which makes this very hard to diagnose."
                        _print ""
                        _print -c "$C_CYAN" "  WHO IS AFFECTED:"
                        _print -c "$C_GRAY" "  - Users querying App Insights > Logs in the Azure Portal"
                        _print -c "$C_GRAY" "  - SDKs or tools calling the Application Insights data plane API"
                        _print -c "$C_GRAY" "  - This diagnostic script's E2E verification step"
                        _print ""
                        _print -c "$C_CYAN" "  REQUIRED PERMISSIONS:"
                        _print -c "$C_GRAY" "  Ensure the querying user has one of these on the workspace:"
                        _print -c "$C_WHITE" "    - Log Analytics Reader"
                        _print -c "$C_WHITE" "    - Monitoring Reader"
                        _print -c "$C_WHITE" "    - A custom role with Microsoft.OperationalInsights/workspaces/query/*/read"
                        _print ""
                        _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/manage-access"
                        _print ""
                    fi
                    add_diagnosis "INFO" "Workspace Access: Require Workspace Permissions" \
                        "LA workspace requires explicit workspace RBAC -- queries may return empty results" \
                        "The backend workspace ($WS_NAME) access control mode is set to 'Require workspace permissions'. Users who have Reader on App Insights but no role on the workspace will get empty query results (HTTP 200, zero rows). The API does not return 403." \
                        "Ensure querying users have Log Analytics Reader (or equivalent) on the workspace, or change the workspace to 'Use resource or workspace permissions'." \
                        "Log Analytics workspace ($WS_NAME) > Properties > Access control mode" \
                        "https://learn.microsoft.com/azure/azure-monitor/logs/manage-access"
                else
                    if $VERBOSE_OUTPUT; then
                        _print -c "$C_GRAY" "    Access Control Mode: $ws_access_mode_label"
                    fi
                fi

                # --- Known Issue #4: Log Analytics reached Daily Cap (OverQuota) ---
                if [[ "$cap_status" == "OverQuota" ]]; then
                    local reset_note=""
                    # Parse reset time if available
                    if [[ -n "$cap_reset_time" ]]; then
                        # Handle /Date(epoch)/ format or ISO format
                        local epoch_ms=""
                        if [[ "$cap_reset_time" =~ /Date\(([0-9]+)\)/ ]]; then
                            epoch_ms="${BASH_REMATCH[1]}"
                        elif [[ "$cap_reset_time" =~ ^[0-9]+$ ]]; then
                            epoch_ms="$cap_reset_time"
                        fi
                        if [[ -n "$epoch_ms" ]]; then
                            local epoch_s=$(( epoch_ms / 1000 ))
                            local now_s
                            now_s="$(date +%s)"
                            local diff_s=$(( epoch_s - now_s ))
                            if (( diff_s > 0 )); then
                                local hours=$(( diff_s / 3600 ))
                                local mins=$(( (diff_s % 3600) / 60 ))
                                local reset_utc
                                reset_utc="$(date -u -d "@$epoch_s" '+%H:%M' 2>/dev/null || date -u -r "$epoch_s" '+%H:%M' 2>/dev/null || echo "")"
                                reset_note=" (resets in ~${hours}h ${mins}m${reset_utc:+ at $reset_utc UTC})"
                            else
                                reset_note=" (reset time has passed, may take a few minutes to resume)"
                            fi
                        fi
                    fi

                    add_diagnosis "BLOCKING" "Log Analytics Daily Cap Reached (OverQuota)" \
                        "Workspace over quota (${cap_quota_gb} GB cap) -- all ingestion stopped" \
                        "The backend workspace ($WS_NAME) has reached its daily cap of ${cap_quota_gb} GB. All ingestion is stopped. The ingestion API still returns HTTP 200, but data is dropped at the LA layer.${reset_note}" \
                        "Increase or remove the daily cap. The cap resets automatically at the configured reset hour (UTC)." \
                        "Log Analytics > Usage and estimated costs > Daily Cap" \
                        "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_RED" "  [!] DAILY CAP REACHED"
                        _print ""
                        _print -n -c "$C_GRAY" "  dataIngestionStatus: "
                        _print -c "$C_RED" "OverQuota"
                        _print -c "$C_GRAY" "  dailyQuotaGb:        ${cap_quota_gb} GB"
                        _print ""
                        _print -c "$C_CYAN" "  IMPACT:"
                        _print -c "$C_GRAY" "    ALL data ingestion to this workspace is currently stopped."
                        _print -c "$C_GRAY" "    This affects not just this App Insights resource, but any other"
                        _print -c "$C_GRAY" "    data sources sending to the same workspace."
                        _print ""
                        _print -c "$C_GRAY" "    The App Insights ingestion API still returns HTTP 200 to SDKs,"
                        _print -c "$C_GRAY" "    so your applications believe data is being accepted. It is NOT."
                        _print ""
                        _print -c "$C_CYAN" "  FIX:"
                        _print -c "$C_GRAY" "    Azure Portal > Log Analytics workspace ($WS_NAME)"
                        _print -c "$C_GRAY" "    > Settings > Usage and estimated costs > Daily Cap"
                        _print -c "$C_GRAY" "    Increase the limit or remove the cap entirely."
                        _print ""
                        _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"
                        _print ""
                    fi
                    write_progress_line "Backend LA Workspace" "FAIL" "$WS_NAME exists but OVER DAILY CAP${reset_note}"
                    write_progress_line "Daily Cap" "FAIL" "OverQuota -- cap: ${cap_quota_gb}GB/day${reset_note}"
                elif [[ "$cap_status" == "SubscriptionSuspended" ]]; then
                    add_diagnosis "BLOCKING" "Azure Subscription Suspended" \
                        "Subscription suspended -- all ingestion blocked" \
                        "The subscription containing the Log Analytics workspace ($WS_NAME) is suspended. All data ingestion is blocked." \
                        "Resolve the subscription status. Common causes: expired trial, payment issues, or admin action." \
                        "Azure Portal > Subscriptions" \
                        "https://learn.microsoft.com/azure/cost-management-billing/manage/subscription-disabled"
                    PIPELINE_BROKEN=true

                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_RED" "  [!] SUBSCRIPTION SUSPENDED"
                        _print -c "$C_GRAY" "  The Azure subscription for this workspace is suspended."
                        _print -c "$C_GRAY" "  No data ingestion or queries will work until the subscription is reactivated."
                        _print ""
                    fi
                    write_progress_line "Backend Workspace" "FAIL" "$WS_NAME exists but SUBSCRIPTION SUSPENDED"
                    write_progress_line "Daily Cap" "FAIL" "SubscriptionSuspended"
                else
                    # RespectQuota or other normal status
                    local cap_summary="under quota"
                    [[ -n "$cap_quota_gb" && "$cap_quota_gb" != "-1" ]] && cap_summary="cap: ${cap_quota_gb} GB/day"

                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_GRAY" "  Daily Cap Status:"
                        _print -n -c "$C_GRAY" "    dataIngestionStatus: "
                        _print -c "$C_GREEN" "$cap_status"
                        [[ -n "$cap_quota_gb" && "$cap_quota_gb" != "-1" ]] && _print -c "$C_GRAY" "    dailyQuotaGb:        ${cap_quota_gb} GB"
                        _print ""
                    fi
                    if $ws_require_workspace_perms; then
                        write_progress_line "Backend LA Workspace" "INFO" "$WS_NAME exists, $cap_summary, access mode = require workspace permissions"
                    else
                        write_progress_line "Backend LA Workspace" "OK" "$WS_NAME exists, $cap_summary"
                    fi
                    write_progress_line "Daily Cap" "OK" "RespectQuota ($cap_summary)"
                fi

            elif [[ "$ws_http_code" == "404" ]]; then
                # --- Known Issue #3: Backend LA workspace is DELETED ---
                add_diagnosis "BLOCKING" "Backend Log Analytics Workspace Not Found" \
                    "LA workspace deleted -- accepted telemetry silently dropped" \
                    "The Log Analytics workspace ($WS_NAME) linked to this App Insights resource does not exist. Telemetry accepted by the ingestion API (HTTP 200) is silently dropped because the backend workspace is gone." \
                    "Recreate the workspace, or link App Insights to a different workspace. After relinking, verify data flows within a few minutes." \
                    "App Insights > Properties > Change Workspace" \
                    "https://learn.microsoft.com/azure/azure-monitor/app/create-workspace-resource?#modify-the-associated-workspace"
                PIPELINE_BROKEN=true

                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_RED" "  [!] WORKSPACE NOT FOUND"
                    _print ""
                    _print -c "$C_GRAY" "  The Log Analytics workspace linked to this App Insights resource"
                    _print -c "$C_GRAY" "  does not exist (ARM returned HTTP 404)."
                    _print ""
                    _print -c "$C_CYAN" "  IMPACT:"
                    _print -c "$C_GRAY" "    The App Insights ingestion API will return HTTP 200 to your SDKs,"
                    _print -c "$C_GRAY" "    telling them 'data received successfully.' However, the data is"
                    _print -c "$C_GRAY" "    silently dropped in the pipeline when it tries to reach the"
                    _print -c "$C_GRAY" "    non-existent workspace. You will see ZERO data in App Insights."
                    _print ""
                    _print -c "$C_CYAN" "  FIX OPTIONS:"
                    _print -c "$C_GRAY" "    1. Recreate the workspace with the same resource URI:"
                    _print -c "$C_WHITE" "       $WS_RESOURCE_ID"
                    _print -c "$C_YELLOW" "       NOTE: A recreated workspace gets a new Workspace ID (GUID)."
                    _print -c "$C_YELLOW" "       After recreating, you must re-associate App Insights to pick up the new ID:"
                    _print -c "$C_YELLOW" "       Azure Portal > App Insights > Properties > Change Workspace to a different"
                    _print -c "$C_YELLOW" "       workspace, Save, then change it back to the recreated workspace and Save again."
                    _print ""
                    _print -c "$C_GRAY" "    2. Link App Insights to a different (existing) workspace:"
                    _print -c "$C_GRAY" "       Azure Portal > App Insights > Properties > Change Workspace"
                    _print -c "$C_GRAY" "    3. If recently deleted (< 14 days), recover it:"
                    _print -c "$C_DARK_GRAY" "       https://learn.microsoft.com/azure/azure-monitor/logs/delete-workspace#recover-a-workspace"
                    _print ""
                fi
                write_progress_line "Backend LA Workspace" "FAIL" "$WS_NAME NOT FOUND (deleted?)"

            elif [[ "$ws_http_code" == "403" || "$ws_http_code" == "401" ]]; then
                # --- Insufficient permissions ---
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_YELLOW" "  [!] INSUFFICIENT PERMISSIONS"
                    _print ""
                    _print -c "$C_GRAY" "  Could not query the backend Log Analytics workspace via ARM (HTTP $ws_http_code)."
                    _print -c "$C_GRAY" "  Your account may not have Reader access to the subscription containing"
                    _print -c "$C_GRAY" "  the workspace, or the workspace is in a different tenant."
                    _print ""
                    _print -c "$C_GRAY" "  Workspace: $WS_NAME"
                    _print -c "$C_DARK_GRAY" "  URI: $WS_RESOURCE_ID"
                    _print ""
                    _print -c "$C_CYAN" "  TO RESOLVE:"
                    _print -c "$C_GRAY" "  - Ensure your account has Reader on the workspace's subscription"
                    _print -c "$C_GRAY" "  - If the workspace is in a different tenant, use --tenant-id"
                    _print ""
                fi
                write_progress_line "Backend LA Workspace" "INFO" "Insufficient permissions to query $WS_NAME (HTTP $ws_http_code)"
                add_diagnosis "INFO" "Cannot Query Backend LA Workspace (Permissions)" \
                    "Insufficient permissions to read backend LA workspace" \
                    "Could not query the Log Analytics workspace ($WS_NAME) via ARM (HTTP $ws_http_code). Your account may not have Reader access to the workspace subscription. Workspace health, daily cap, and access mode checks are skipped." \
                    "Ensure your account has Reader access to the subscription containing the workspace. If the workspace is in a different tenant, specify --tenant-id." \
                    "" \
                    "https://learn.microsoft.com/azure/azure-monitor/logs/manage-access"

            else
                # --- Unexpected response ---
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_YELLOW" "  [WARN] Unexpected response querying Log Analytics workspace (HTTP $ws_http_code)."
                    _print -c "$C_GRAY" "  Ensure your account has Reader access to the workspace subscription."
                    _print ""
                fi
                write_progress_line "Backend LA Workspace" "INFO" "Could not query workspace (HTTP $ws_http_code)"
            fi
        fi

        # ==============================================================
        # Known Issue #5: AI Daily Cap vs LA Daily Cap Misconfigurations
        # ==============================================================
        if [[ -n "$WS_RESOURCE_ID" ]]; then
            write_progress_start "Daily Cap Settings"
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Daily Cap Settings (App Insights vs Log Analytics)"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -c "$C_GRAY" "  Comparing daily cap settings between App Insights and the backend"
                _print -c "$C_GRAY" "  Log Analytics workspace to detect silent data drop scenarios..."
            fi

            # Fetch AI daily cap from PricingPlans API
            local ai_cap_response
            _debug_az_rest "GET" "https://management.azure.com${ai_id}/PricingPlans/current?api-version=2017-10-01"
            ai_cap_response="$(az rest --method GET --url "https://management.azure.com${ai_id}/PricingPlans/current?api-version=2017-10-01" 2>/dev/null | tr -d '\r')"

            if [[ -n "$ai_cap_response" ]]; then
                if $HAS_JQ; then
                    AI_CAP_GB="$(echo "$ai_cap_response" | jq -r '.properties.cap // empty' 2>/dev/null)"
                    [[ -z "$AI_CAP_GB" ]] && AI_CAP_GB="$(echo "$ai_cap_response" | jq -r '.properties.Cap // empty' 2>/dev/null)"
                else
                    # Use regex to extract cap value
                    if [[ "$ai_cap_response" =~ \"cap\"[[:space:]]*:[[:space:]]*([0-9.]+) ]]; then
                        AI_CAP_GB="${BASH_REMATCH[1]}"
                    elif [[ "$ai_cap_response" =~ \"Cap\"[[:space:]]*:[[:space:]]*([0-9.]+) ]]; then
                        AI_CAP_GB="${BASH_REMATCH[1]}"
                    fi
                fi
            fi

            # Determine if AI cap is effectively off
            if [[ -z "$AI_CAP_GB" ]]; then
                AI_CAP_OFF=true
            else
                # Cap >= 9999 means effectively unlimited
                local ai_cap_int="${AI_CAP_GB%%.*}"
                if [[ -n "$ai_cap_int" ]] && (( ai_cap_int >= 9999 )); then
                    AI_CAP_OFF=true
                fi
            fi

            # --- Comparison Logic ---
            local ai_cap_display la_cap_display
            if $AI_CAP_OFF; then
                ai_cap_display="OFF (no limit)"
            else
                ai_cap_display="${AI_CAP_GB} GB/day"
            fi
            if $WS_CAP_OFF; then
                la_cap_display="OFF (no limit)"
            else
                la_cap_display="${WS_CAP_QUOTA_GB} GB/day"
            fi

            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_WHITE" "  App Insights daily cap:    $ai_cap_display"
                _print -c "$C_WHITE" "  Log Analytics daily cap:   $la_cap_display"
                _print ""
            fi

            if ! $WS_CAP_OFF && ! $AI_CAP_OFF; then
                # Both have caps -- compare them
                local la_lt_ai=false
                if $HAS_BC; then
                    (( $(echo "$WS_CAP_QUOTA_GB < $AI_CAP_GB" | bc -l 2>/dev/null) )) && la_lt_ai=true
                else
                    local la_int="${WS_CAP_QUOTA_GB%%.*}"
                    local ai_int="${AI_CAP_GB%%.*}"
                    [[ -n "$la_int" && -n "$ai_int" ]] && (( la_int < ai_int )) && la_lt_ai=true
                fi

                if $la_lt_ai; then
                    # THE KEY SCENARIO: LA cap < AI cap = silent data drop
                    add_diagnosis "WARNING" "Daily Cap Mismatch: LA Cap (${WS_CAP_QUOTA_GB} GB) < AI Cap (${AI_CAP_GB} GB)" \
                        "Daily cap mismatch: LA ${WS_CAP_QUOTA_GB} GB < AI ${AI_CAP_GB} GB (silent data drop risk)" \
                        "LA workspace hits cap first, silently drops data while SDKs get HTTP 200." \
                        "Align caps: increase LA to >= ${AI_CAP_GB} GB, or decrease AI to <= ${WS_CAP_QUOTA_GB} GB." \
                        "Log Analytics > Usage and estimated costs > Daily Cap" \
                        "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

                    if $VERBOSE_OUTPUT; then
                        _print -c "$C_RED" "  [!] DAILY CAP MISCONFIGURATION DETECTED"
                        _print ""
                        _print -c "$C_CYAN" "  WHAT HAPPENS:"
                        _print -c "$C_GRAY" "    1. Your SDK sends telemetry to App Insights ingestion API"
                        _print -c "$C_GRAY" "    2. App Insights returns HTTP 200 (accepted) -- AI cap not yet reached"
                        _print -c "$C_GRAY" "    3. Data enters the pipeline toward Log Analytics workspace"
                        _print -c "$C_GRAY" "    4. LA workspace has already hit its ${WS_CAP_QUOTA_GB} GB daily cap"
                        _print -c "$C_GRAY" "    5. Data is SILENTLY DROPPED -- no error is returned to the SDK"
                        _print ""
                        _print -c "$C_CYAN" "  SCENARIO:"
                        _print -c "$C_GRAY" "    When daily ingestion is between ${WS_CAP_QUOTA_GB} GB and ${AI_CAP_GB} GB,"
                        _print -c "$C_GRAY" "    the LA workspace stops accepting data while App Insights keeps"
                        _print -c "$C_GRAY" "    telling your SDKs everything is fine."
                        _print ""
                        _print -c "$C_CYAN" "  FIX:"
                        _print -c "$C_GRAY" "    Option 1: Increase LA daily cap to >= ${AI_CAP_GB} GB"
                        _print -c "$C_GRAY" "    Option 2: Decrease AI daily cap to <= ${WS_CAP_QUOTA_GB} GB"
                        _print -c "$C_GRAY" "    Option 3: Remove both caps and use Azure Cost Management alerts"
                        _print ""
                        _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"
                        _print ""
                    fi
                    write_progress_line "Daily Cap Settings" "WARN" "LA cap (${WS_CAP_QUOTA_GB} GB) < AI cap (${AI_CAP_GB} GB) -- silent data drop risk"
                else
                    # Both have caps, LA >= AI -- properly aligned
                    if $VERBOSE_OUTPUT; then
                        _print -c "$C_GREEN" "  Daily caps are properly aligned (LA cap >= AI cap)."
                        _print -c "$C_GRAY" "  The App Insights cap will trigger first, giving SDKs"
                        _print -c "$C_GRAY" "  visibility into throttling before the LA cap is reached."
                        _print ""
                    fi
                    write_progress_line "Daily Cap Settings" "OK" "Aligned -- AI cap ${AI_CAP_GB} GB, LA cap ${WS_CAP_QUOTA_GB} GB"
                fi
            elif ! $WS_CAP_OFF && $AI_CAP_OFF; then
                # AI cap off but LA has a cap -- LA is the effective limit
                add_diagnosis "INFO" "Log Analytics Daily Cap is the Effective Limit (${WS_CAP_QUOTA_GB} GB)" \
                    "LA cap (${WS_CAP_QUOTA_GB} GB) is the effective limit (AI cap is off)" \
                    "App Insights daily cap is OFF, but the LA workspace has a ${WS_CAP_QUOTA_GB} GB cap. Data will be silently dropped at the LA layer if you approach this limit." \
                    "Consider setting the AI daily cap to ${WS_CAP_QUOTA_GB} GB so the ingestion API stops accepting data before the LA cap is hit." \
                    "App Insights > Usage and estimated costs > Daily Cap" \
                    "https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"

                if $VERBOSE_OUTPUT; then
                    _print -c "$C_YELLOW" "  [!] LOG ANALYTICS CAP IS THE EFFECTIVE LIMIT"
                    _print ""
                    _print -c "$C_GRAY" "  App Insights has no daily cap, but the backend LA workspace"
                    _print -c "$C_GRAY" "  limits ingestion to ${WS_CAP_QUOTA_GB} GB/day. Consider also setting"
                    _print -c "$C_GRAY" "  the AI daily cap so the ingestion API rejects data before"
                    _print -c "$C_GRAY" "  the LA cap is hit."
                    _print ""
                fi
                write_progress_line "Daily Cap Settings" "INFO" "AI cap OFF, LA cap ${WS_CAP_QUOTA_GB} GB/day -- LA is effective limit"
            elif $WS_CAP_OFF && $AI_CAP_OFF; then
                # Both off -- no caps
                if $VERBOSE_OUTPUT; then
                    _print -c "$C_GREEN" "  Both daily caps are off. No daily ingestion limit is enforced."
                    _print -c "$C_GRAY" "  Consider using Azure Cost Management alerts for budget control."
                    _print ""
                fi
                write_progress_line "Daily Cap Settings" "OK" "Both caps OFF (no daily limit)"
            else
                # AI has cap, LA unlimited -- fine
                if $VERBOSE_OUTPUT; then
                    _print -c "$C_GREEN" "  AI daily cap limits ingestion to ${AI_CAP_GB} GB/day."
                    _print -c "$C_GRAY" "  LA workspace has no daily cap -- no silent drops risk."
                    _print ""
                fi
                write_progress_line "Daily Cap Settings" "OK" "AI cap ${AI_CAP_GB} GB/day, LA unlimited"
            fi
        fi

        # ==============================================================
        # Known Issue #6: Diagnostic Settings Causing Duplicate Telemetry
        # ==============================================================
        write_progress_start "Diagnostic Settings"
        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_DARK_GRAY" "  ========================================================================"
            _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Diagnostic Settings (Duplicate Telemetry)"
            _print -c "$C_DARK_GRAY" "  ========================================================================"
            _print ""
            _print -c "$C_GRAY" "  Checking if Diagnostic Settings on this App Insights resource export"
            _print -c "$C_GRAY" "  logs to ANY Log Analytics workspace (which causes duplicate telemetry)..."
        fi

        local ds_api_url="https://management.azure.com${ai_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        local ds_response
        _debug_az_rest "GET" "$ds_api_url"
        ds_response="$(az rest --method GET --url "$ds_api_url" 2>/dev/null | tr -d '\r')"

        if [[ -n "$ds_response" ]]; then
            local ds_with_la_count=0
            local ds_same_ws_count=0
            local ds_diff_ws_count=0
            local ds_total_count=0
            local -a ds_detail_lines=()

            local lower_ws_id=""
            [[ -n "$WS_RESOURCE_ID" ]] && lower_ws_id="$(echo "$WS_RESOURCE_ID" | tr '[:upper:]' '[:lower:]')"

            if $HAS_JQ; then
                ds_total_count="$(echo "$ds_response" | jq -r '.value | length' 2>/dev/null)"
                [[ "$ds_total_count" == "null" ]] && ds_total_count=0

                # Find diagnostic settings that have workspaceId AND enabled log categories
                local ds_la_json
                ds_la_json="$(echo "$ds_response" | jq -r '
                    [.value[] |
                     select(.properties.workspaceId != null and .properties.workspaceId != "") |
                     select(.properties.logs != null) |
                     select([.properties.logs[] | select(.enabled == true)] | length > 0) |
                     {
                       name: .name,
                       workspaceId: .properties.workspaceId,
                       categories: [.properties.logs[] | select(.enabled == true) | (.category // .categoryGroup)]
                     }
                    ]' 2>/dev/null)"

                ds_with_la_count="$(echo "$ds_la_json" | jq 'length' 2>/dev/null)"
                [[ "$ds_with_la_count" == "null" ]] && ds_with_la_count=0

                if (( ds_with_la_count > 0 )); then
                    while IFS= read -r ds_entry; do
                        local ds_ws_id
                        ds_ws_id="$(echo "$ds_entry" | jq -r '.workspaceId' 2>/dev/null | tr '[:upper:]' '[:lower:]')"
                        local ds_name_val
                        ds_name_val="$(echo "$ds_entry" | jq -r '.name' 2>/dev/null)"
                        local ds_target_name="${ds_ws_id##*/}"
                        local ds_cats
                        ds_cats="$(echo "$ds_entry" | jq -r '.categories | join(", ")' 2>/dev/null)"

                        local is_same=false
                        [[ -n "$lower_ws_id" && "$ds_ws_id" == "$lower_ws_id" ]] && is_same=true

                        if $is_same; then
                            (( ds_same_ws_count++ ))
                            ds_detail_lines+=("SAME|${ds_name_val}|${ds_target_name}|${ds_cats}")
                        else
                            (( ds_diff_ws_count++ ))
                            ds_detail_lines+=("DIFF|${ds_name_val}|${ds_target_name}|${ds_cats}")
                        fi
                    done < <(echo "$ds_la_json" | jq -c '.[]' 2>/dev/null)
                fi
            else
                # Non-jq: use az rest with JMESPath to get structured data
                ds_total_count="$(az rest --method GET --url "$ds_api_url" \
                    --query "length(value)" -o tsv 2>/dev/null | tr -d '\r')"
                [[ -z "$ds_total_count" || "$ds_total_count" == "None" ]] && ds_total_count=0

                # Get settings with workspaceId AND at least one enabled log category.
                # This JMESPath filter excludes metrics-only exports (which don't cause duplicates).
                # JMESPath backtick literals need single-quoting in bash.
                local ds_ws_list
                ds_ws_list="$(az rest --method GET --url "$ds_api_url" \
                    --query 'value[?properties.workspaceId && length(properties.logs[?enabled==`true`]) > `0`].{n:name, w:properties.workspaceId}' \
                    -o tsv 2>/dev/null | tr -d '\r')"

                if [[ -n "$ds_ws_list" ]]; then
                    while IFS=$'\t' read -r ds_name_val ds_ws_id_val; do
                        [[ -z "$ds_name_val" ]] && continue
                        (( ds_with_la_count++ ))
                        local ds_target_name="${ds_ws_id_val##*/}"
                        local lower_ds_ws
                        lower_ds_ws="$(echo "$ds_ws_id_val" | tr '[:upper:]' '[:lower:]')"

                        # Get enabled log category names for this specific setting.
                        # Query the individual setting endpoint for cleaner JMESPath.
                        # Uses category||categoryGroup to handle both allLogs (categoryGroup)
                        # and individual table categories (category).
                        local ds_single_url="https://management.azure.com${ai_id}/providers/Microsoft.Insights/diagnosticSettings/${ds_name_val}?api-version=2021-05-01-preview"
                        local ds_cats_val=""
                        ds_cats_val="$(az rest --method GET --url "$ds_single_url" \
                            --query 'properties.logs[?enabled==`true`].[category || categoryGroup][]' \
                            -o tsv 2>/dev/null | tr -d '\r' | tr '\t' '\n' | paste -sd, | sed 's/,/, /g')"
                        [[ -z "$ds_cats_val" ]] && ds_cats_val="(log categories detected)"

                        if [[ -n "$lower_ws_id" && "$lower_ds_ws" == "$lower_ws_id" ]]; then
                            (( ds_same_ws_count++ ))
                            ds_detail_lines+=("SAME|${ds_name_val}|${ds_target_name}|${ds_cats_val}")
                        else
                            (( ds_diff_ws_count++ ))
                            ds_detail_lines+=("DIFF|${ds_name_val}|${ds_target_name}|${ds_cats_val}")
                        fi
                    done <<< "$ds_ws_list"
                fi
            fi

            if (( ds_with_la_count > 0 )); then
                DIAG_SETTINGS_LA_COUNT=$ds_with_la_count
                local ds_summary="${ds_with_la_count} setting(s) export to Log Analytics"
                (( ds_same_ws_count > 0 )) && ds_summary+=" (${ds_same_ws_count} to SAME workspace = duplicates)"

                # Build diagnosis description dynamically based on same/different workspace counts
                local diag_desc="${ds_with_la_count} Diagnostic Setting(s) on this App Insights resource export log data to a Log Analytics workspace. "
                if (( ds_same_ws_count > 0 )); then
                    diag_desc+="Of these, ${ds_same_ws_count} export to the SAME workspace that App Insights already writes to, causing duplicate records in both App Insights queries AND direct LA table queries. "
                fi
                if (( ds_diff_ws_count > 0 )); then
                    diag_desc+="${ds_diff_ws_count} export to a DIFFERENT workspace. When querying from App Insights, it stitches data across workspaces, so you will still see duplicates in App Insights query results (Transaction Search, Log queries, end-to-end views)."
                fi

                add_diagnosis "INFO" "Diagnostic Settings Exporting to LA (Duplicate Telemetry Risk)" \
                    "Diagnostic settings exporting to LA (duplicate telemetry in queries)" \
                    "$diag_desc" \
                    "Delete export to LA, or keep it and de-duplicate with KQL distinct operator, or query LA tables directly." \
                    "App Insights > Monitoring > Diagnostic settings" \
                    "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"

                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_YELLOW" "  [!] DIAGNOSTIC SETTINGS EXPORTING TO LOG ANALYTICS"
                    _print ""
                    _print -c "$C_GRAY" "  Found ${ds_total_count} diagnostic setting(s), ${ds_with_la_count} export logs to LA:"
                    _print ""

                    # Show per-setting details
                    for ds_line in "${ds_detail_lines[@]}"; do
                        local IFS='|'
                        local -a ds_parts
                        read -ra ds_parts <<< "$ds_line"
                        local ds_type="${ds_parts[0]}"
                        local ds_nm="${ds_parts[1]}"
                        local ds_tgt="${ds_parts[2]}"
                        local ds_cat="${ds_parts[3]}"

                        _print -n -c "$C_GRAY" "    Setting: "
                        _print -c "$C_WHITE" "$ds_nm"
                        _print -n -c "$C_GRAY" "    Target:  "
                        if [[ "$ds_type" == "SAME" ]]; then
                            _print -n -c "$C_WHITE" "$ds_tgt"
                            _print -c "$C_RED" " <-- SAME as AI backend"
                        else
                            _print -n -c "$C_WHITE" "$ds_tgt"
                            _print -c "$C_YELLOW" " (different workspace)"
                        fi
                        _print -c "$C_DARK_GRAY" "    Categories: ${ds_cat}"
                        _print ""
                    done

                    _print -c "$C_CYAN" "  WHY THIS CAUSES DUPLICATES:"
                    _print -c "$C_GRAY" "    App Insights already sends all telemetry to its backend LA workspace."
                    _print -c "$C_GRAY" "    Diagnostic Settings create a SECOND copy of the same data in LA."
                    _print ""
                    if (( ds_same_ws_count > 0 )); then
                        _print -c "$C_GRAY" "    When exported to the SAME workspace:"
                        _print -c "$C_GRAY" "      Two copies of every record in the same LA tables (AppRequests, etc.)"
                        _print -c "$C_GRAY" "      Duplicates visible in BOTH App Insights and LA direct queries."
                        _print ""
                    fi
                    if (( ds_diff_ws_count > 0 )); then
                        _print -c "$C_GRAY" "    When exported to a DIFFERENT workspace:"
                        _print -c "$C_GRAY" "      App Insights stitches data from all accessible workspaces,"
                        _print -c "$C_GRAY" "      so Transaction Search, end-to-end views, and log queries from"
                        _print -c "$C_GRAY" "      App Insights will show duplicate results."
                        _print ""
                    fi
                    _print -c "$C_CYAN" "  FIX OPTIONS:"
                    _print -c "$C_GRAY" "    1. Remove the LA export: Azure Portal > App Insights > Monitoring > Diagnostic settings"
                    _print -c "$C_GRAY" "       Delete or edit the setting(s) that export log categories to a LA workspace."
                    _print -c "$C_GRAY" "       You can still export to Blob Storage or Event Hubs without causing duplicates."
                    _print ""
                    _print -c "$C_GRAY" "    2. Keep the export but de-duplicate in queries:"
                    _print -c "$C_DARK_GRAY" "       https://learn.microsoft.com/azure/data-explorer/kusto/query/distinct-operator"
                    _print ""
                    if (( ds_diff_ws_count > 0 )); then
                        _print -c "$C_GRAY" "    3. Query from the individual LA workspace(s) directly instead of through"
                        _print -c "$C_GRAY" "       App Insights, so you only see a single copy of each record."
                        _print ""
                    fi
                    _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings#application-insights"
                    _print ""
                fi
                write_progress_line "Diagnostic Settings" "INFO" "$ds_summary"
            else
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -n -c "$C_GRAY" "  Diagnostic Settings: "
                    if (( ds_total_count == 0 )); then
                        _print -c "$C_GREEN" "None configured"
                    else
                        _print -c "$C_GREEN" "${ds_total_count} found, none export App Insights logs to LA"
                    fi
                    _print -c "$C_GRAY" "  No duplicate telemetry risk from Diagnostic Settings."
                    _print ""
                fi
                if (( ds_total_count > 0 )); then
                    write_progress_line "Diagnostic Settings" "OK" "${ds_total_count} setting(s) found, none export logs to LA"
                else
                    write_progress_line "Diagnostic Settings" "OK" "None configured"
                fi
            fi
        else
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_YELLOW" "  [WARN] Could not query Diagnostic Settings."
                _print ""
            fi
            write_progress_line "Diagnostic Settings" "INFO" "Could not query"
        fi

        # ==============================================================
        # Known Issue #7: Workspace Transforms (DCRs) on AI Tables
        # ==============================================================
        if [[ -n "$WS_RESOURCE_ID" ]]; then
            write_progress_start "Workspace Transforms"
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print -c "$C_CYAN" "  KNOWN ISSUE CHECK: Workspace Transforms (Data Collection Rules)"
                _print -c "$C_DARK_GRAY" "  ========================================================================"
                _print ""
                _print -c "$C_GRAY" "  Checking for Data Collection Rules with workspace transforms that"
                _print -c "$C_GRAY" "  target App Insights tables. These transforms can silently drop or"
                _print -c "$C_GRAY" "  alter telemetry before it lands in the Log Analytics workspace."
            fi

            # App Insights table names
            local -a ai_tables=("AppRequests" "AppTraces" "AppExceptions" "AppDependencies" "AppEvents" "AppMetrics" "AppPageViews" "AppPerformanceCounters" "AppAvailabilityResults" "AppBrowserTimings" "AppSystemEvents")

            # Parallel arrays avoid delimiter conflicts (KQL contains pipes & tabs)
            local -a at_dcr_names=()    # DCR name for each active transform
            local -a at_table_names=()  # Table name (e.g. AppRequests)
            local -a at_kql_values=()   # Full KQL text (may contain newlines, pipes)
            local -a passthrough_transforms=()
            local active_transform_count=0

            # Use Azure Resource Graph to search the ENTIRE TENANT for WorkspaceTransforms
            # DCRs targeting our workspace. DCRs can be created in ANY subscription (not just
            # the workspace's subscription), so ARG cross-subscription search is required.
            local lower_ws_id
            lower_ws_id="$(echo "$WS_RESOURCE_ID" | tr '[:upper:]' '[:lower:]')"

            local safe_ws_id
            safe_ws_id="$(sanitize_single_quotes "$WS_RESOURCE_ID")"
            local dcr_arg_query="resources | where type =~ 'microsoft.insights/datacollectionrules' | where kind =~ 'WorkspaceTransforms' | mv-expand dest = properties.destinations.logAnalytics | where tolower(tostring(dest.workspaceResourceId)) == tolower('${safe_ws_id}') | mv-expand flow = properties.dataFlows | mv-expand stream = flow.streams | where tostring(stream) startswith 'Microsoft-Table-App' | project name, id, tableName=replace_string(tostring(stream), 'Microsoft-Table-', ''), transformKql=replace_string(replace_string(tostring(flow.transformKql), '\n', ' '), '\r', '')"

            _debug_az_graph "$dcr_arg_query"

            if $HAS_JQ; then
                # jq path: single ARG query, parse JSON response
                local dcr_arg_response
                dcr_arg_response="$(az graph query -q "$dcr_arg_query" --query "data" -o json 2>/dev/null | tr -d '\r')"
                _debug_response "DCR ARG result" "$dcr_arg_response"

                if [[ -n "$dcr_arg_response" && "$dcr_arg_response" != "null" && "$dcr_arg_response" != "[]" ]]; then
                    while IFS=$'\t' read -r dcr_name table_name transform_kql; do
                        [[ -z "$dcr_name" ]] && continue
                        transform_kql="${transform_kql:-"(none)"}"
                        [[ -z "$transform_kql" ]] && transform_kql="(none)"
                        local is_passthrough=false
                        [[ "$transform_kql" == "source" || "$transform_kql" == "(none)" ]] && is_passthrough=true

                        if $is_passthrough; then
                            passthrough_transforms+=("${table_name}")
                        else
                            at_dcr_names+=("$dcr_name")
                            at_table_names+=("$table_name")
                            at_kql_values+=("$transform_kql")
                            (( active_transform_count++ ))
                        fi
                    done < <(echo "$dcr_arg_response" | jq -r '.[]? | [.name, .tableName, (.transformKql // "(none)")] | @tsv' 2>/dev/null)
                fi
            else
                # No-jq path: single ARG query with JMESPath, parse TSV output
                # ARG --query with -o tsv gives us tab-separated columns per row
                local dcr_arg_tsv
                dcr_arg_tsv="$(az graph query -q "$dcr_arg_query" \
                    --query "data[].{n:name, t:tableName, k:transformKql}" -o tsv 2>/dev/null | tr -d '\r')"
                _debug_response "DCR ARG result (tsv)" "$dcr_arg_tsv"

                if [[ -n "$dcr_arg_tsv" ]]; then
                    while IFS=$'\t' read -r dcr_name table_name transform_kql; do
                        [[ -z "$dcr_name" ]] && continue
                        [[ -z "$transform_kql" || "$transform_kql" == "None" ]] && transform_kql="(none)"
                        local is_passthrough=false
                        [[ "$transform_kql" == "source" || "$transform_kql" == "(none)" ]] && is_passthrough=true

                        if $is_passthrough; then
                            passthrough_transforms+=("$table_name")
                        else
                            at_dcr_names+=("$dcr_name")
                            at_table_names+=("$table_name")
                            at_kql_values+=("$transform_kql")
                            (( active_transform_count++ ))
                        fi
                    done <<< "$dcr_arg_tsv"
                fi
            fi

            if (( active_transform_count > 0 )); then
                # Collect unique affected tables
                local -a affected_tables=()
                for (( ati=0; ati<active_transform_count; ati++ )); do
                    local tname="${at_table_names[$ati]}"
                    local found_t=false
                    for existing_t in "${affected_tables[@]}"; do
                        [[ "$existing_t" == "$tname" ]] && found_t=true && break
                    done
                    $found_t || affected_tables+=("$tname")
                done
                local affected_tables_str
                affected_tables_str="$(printf '%s, ' "${affected_tables[@]}")"
                affected_tables_str="${affected_tables_str%, }"

                add_diagnosis "INFO" "Workspace Transforms Detected on App Insights Tables" \
                    "Workspace transforms on ${affected_tables_str} (may drop/modify telemetry)" \
                    "${active_transform_count} Data Collection Rule transform(s) modify App Insights data before it reaches Log Analytics. Affected tables: ${affected_tables_str}." \
                    "Review the transform KQL for each affected table, or set to 'source' for passthrough." \
                    "Log Analytics > Tables > select table > Create transformation" \
                    "https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations"

                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_RED" "  [!] WORKSPACE TRANSFORMS FOUND ON APP INSIGHTS TABLES"
                    _print ""
                    _print -c "$C_GRAY" "  These Data Collection Rules apply KQL transforms to App Insights"
                    _print -c "$C_GRAY" "  telemetry BEFORE it lands in the Log Analytics workspace."
                    _print -c "$C_GRAY" "  Transforms can silently drop rows or remove columns."
                    _print ""

                    for (( ati=0; ati<active_transform_count; ati++ )); do
                        local at_dcr="${at_dcr_names[$ati]}"
                        local at_table="${at_table_names[$ati]}"
                        local at_kql="${at_kql_values[$ati]}"

                        _print -c "$C_DARK_GRAY" "  -----------------------------------------------------------------------"
                        _print -n -c "$C_GRAY" "  Table: "
                        _print -c "$C_YELLOW" "$at_table"
                        _print -c "$C_GRAY" "  DCR:   $at_dcr"
                        _print -c "$C_GRAY" "  Transform KQL:"
                        # Display KQL line-by-line (at_kql already has real newlines)
                        while IFS= read -r kql_line; do
                            local trimmed="${kql_line#"${kql_line%%[![:space:]]*}"}"
                            [[ -n "$trimmed" ]] && _print -c "$C_WHITE" "    $trimmed"
                        done <<< "$at_kql"
                        _print ""

                        # Analyze the transform for common patterns
                        local -a kql_warnings=()
                        [[ "$at_kql" =~ \|[[:space:]]*where ]] && kql_warnings+=("Contains 'where' clause -- may be DROPPING rows that don't match the filter")
                        [[ "$at_kql" =~ \|[[:space:]]*project[^-] ]] && kql_warnings+=("Contains 'project' clause -- may be REMOVING columns from telemetry records")
                        [[ "$at_kql" =~ \|[[:space:]]*project-away ]] && kql_warnings+=("Contains 'project-away' clause -- explicitly removes specific columns")
                        [[ "$at_kql" =~ \|[[:space:]]*extend ]] && kql_warnings+=("Contains 'extend' clause -- adds or modifies columns")
                        [[ "$at_kql" =~ \|[[:space:]]*summarize ]] && kql_warnings+=("Contains 'summarize' clause -- AGGREGATES rows (individual records may be lost)")
                        [[ "$at_kql" =~ \|[[:space:]]*(take|limit) ]] && kql_warnings+=("Contains 'take/limit' clause -- only a subset of rows will be retained")

                        if (( ${#kql_warnings[@]} > 0 )); then
                            _print -c "$C_CYAN" "  ANALYSIS:"
                            for w in "${kql_warnings[@]}"; do
                                _print -c "$C_YELLOW" "    [!] $w"
                            done
                            _print ""
                        fi
                    done

                    _print -c "$C_CYAN" "  HOW TO FIX:"
                    _print -c "$C_GRAY" "    To remove a transform: Log Analytics > Tables > select table >"
                    _print -c "$C_GRAY" "    ... (ellipsis) > Create transformation > set KQL to just 'source'"
                    _print -c "$C_GRAY" "    Or delete the DCR directly via Azure Portal > Data Collection Rules."
                    _print ""
                    _print -c "$C_DARK_GRAY" "  NOTE: Setting transformKql to 'source' makes the transform a passthrough"
                    _print -c "$C_DARK_GRAY" "  (all data flows through unchanged). This is equivalent to no transform."
                    _print ""
                    _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-transformations"
                    _print ""
                fi
                write_progress_line "Workspace Transforms" "INFO" "${active_transform_count} transform(s) on App Insights tables: ${affected_tables_str}"
            elif (( ${#passthrough_transforms[@]} > 0 )); then
                # Only passthrough transforms found
                local pt_tables_str
                pt_tables_str="$(printf '%s, ' "${passthrough_transforms[@]}")"
                pt_tables_str="${pt_tables_str%, }"
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_GREEN" "  Workspace transforms exist on: ${pt_tables_str}"
                    _print -c "$C_GRAY" "  All are passthrough ('source' only) -- no data modification."
                    _print ""
                fi
                write_progress_line "Workspace Transforms" "OK" "Passthrough only (${pt_tables_str})"
            else
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_GREEN" "  No workspace transforms found targeting App Insights tables."
                    _print -c "$C_GRAY" "  Telemetry flows through to Log Analytics unmodified."
                    _print ""
                fi
                write_progress_line "Workspace Transforms" "OK" "None targeting App Insights tables"
            fi
        fi

    elif $CHECK_AZURE && ! $NETWORK_ONLY; then
        (( STEP_NUMBER++ ))
        write_progress_line "Known Issue Checks" "SKIP" "App Insights resource not found"
    fi

    # ================================================================
    # STEP 8: TELEMETRY INGESTION TEST
    # ================================================================
    (( STEP_NUMBER++ ))

    write_progress_start "Telemetry Ingestion"

    # ---- Ingestion consent gate (verbose mode) ----
    # Compact mode: consent was already handled before the progress table.
    # Verbose mode: ask just-in-time, right before the ingestion test.
    if $VERBOSE_OUTPUT && ! $SKIP_INGESTION_TEST && ! $PIPELINE_BROKEN && ! $INGESTION_BLOCKED_PREFLIGHT && ! $INGESTION_TCP_BLOCKED && ! $ingestion_consent_declined; then
        if ! request_user_consent \
            "TELEMETRY INGESTION TEST -- YOUR CONSENT IS REQUIRED" \
            "To skip this test, press N or re-run with --skip-ingestion-test." \
            "Send test telemetry record? [Y/N]" \
            "" \
            "To verify end-to-end ingestion, this test will send ONE small" \
            "availability record directly to your Application Insights resource." \
            "" \
            "What will be sent:" \
            "" \
            "  - Record type:  AvailabilityResult" \
            "  - Record name:  'Telemetry-Flow-Diag Ingestion Validation'" \
            "  - Payload size: ~0.5 KB" \
            "  - Sent from:    this machine ($ENV_COMPUTER_NAME) -> your ingestion endpoint" \
            "  - Sent as:      anonymous telemetry -- no sign-in required" \
            "" \
            "Cost: Standard ingestion and data retention rates apply." \
            "For a single telemetry record this is negligible."; then
            ingestion_consent_declined=true
        fi
    fi

    if $SKIP_INGESTION_TEST; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test [SKIPPED]"
            write_result "SKIP" "Ingestion test skipped (--skip-ingestion-test)"
            _print ""
        fi
        write_progress_line "Telemetry Ingestion" "SKIP" "Skipped (--skip-ingestion-test)"
    elif $ingestion_consent_declined; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test [SKIPPED]"
            write_result "SKIP" "Ingestion test skipped (consent declined)"
            _print ""
        fi
        write_progress_line "Telemetry Ingestion" "SKIP" "Consent declined (use --auto-approve to bypass)"
        write_progress_line "End-to-End Verification" "SKIP" "Skipped (ingestion test did not run)"
    elif $PIPELINE_BROKEN; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test [SKIPPED]"
            _print ""
            _print -c "$C_YELLOW" "  Skipping telemetry ingestion test and end-to-end verification."
            _print -c "$C_GRAY" "  The backend Log Analytics workspace is deleted or the subscription is suspended."
            _print -c "$C_GRAY" "  The ingestion API will return HTTP 200, but data is silently dropped in the pipeline."
            _print -c "$C_GRAY" "  Resolve the backend issue above first, then re-run this script to validate end-to-end."
            _print ""
        fi
        write_progress_line "Telemetry Ingestion" "SKIP" "Skipped (backend pipeline broken -- see diagnosis)"
    elif $INGESTION_BLOCKED_PREFLIGHT; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test [SKIPPED]"
            _print ""
            _print -c "$C_YELLOW" "  Skipping telemetry ingestion test."
            _print -c "$C_GRAY" "  The network access assessment determined ingestion is BLOCKED from this machine."
            _print -c "$C_GRAY" "  Resolve the network/AMPLS configuration issue first, then re-run."
            _print ""
        fi
        write_progress_line "Telemetry Ingestion" "SKIP" "Skipped (ingestion blocked at network level)"
    elif $INGESTION_TCP_BLOCKED; then
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test [SKIPPED]"
            _print ""
            _print -c "$C_YELLOW" "  Skipping telemetry ingestion test."
            _print -c "$C_GRAY" "  The ingestion endpoint ($ingestion_host) failed TCP connectivity."
            _print -c "$C_GRAY" "  An HTTP POST cannot succeed without an open TCP connection."
            _print -c "$C_GRAY" "  Resolve the TCP/firewall issue first, then re-run."
            _print ""
        fi
        write_progress_line "Telemetry Ingestion" "SKIP" "Skipped (ingestion endpoint TCP blocked)"
    else
        # --- Full Telemetry Ingestion Test ---
        if $VERBOSE_OUTPUT; then
            write_header_always "STEP $STEP_NUMBER: Telemetry Ingestion Test"
            _print ""
            _print -c "$C_GRAY" "  This test bypasses your app and its Application Insights SDK entirely and"
            _print -c "$C_GRAY" "  sends a raw telemetry record directly to your Application Insights resource."
            _print -c "$C_GRAY" "  Think of this test as asking the question:"
            _print ""
            _print -c "$C_YELLOW" "  Can ANY application running on this machine talk to your App Insights resource?"
            _print ""
            _print -c "$C_CYAN" "  WHAT WE TEST:"
            _print -c "$C_GRAY" "    Step 1: POST a unique availabilityResults record to your ingestion endpoint"
            _print -c "$C_GRAY" "    Step 2: Query App Insights data plane API to confirm the record arrived at your resource"
            _print ""
            _print -c "$C_GRAY" "  The test record will appear in your resource's Availability blade as a custom"
            _print -c "$C_GRAY" "  test named \"Telemetry-Flow-Diag Ingestion Validation\"."
            _print ""
            _print -c "$C_GRAY" "  If BOTH steps succeed, the entire telemetry pipeline is confirmed working:"
            _print -c "$C_GRAY" "    This machine -> Network -> Ingestion API -> Processing Pipeline -> Log Analytics -> Queryable"
            _print ""
            _print -c "$C_CYAN" "  WHAT SUCCESS PROVES (from this machine):"
            _print -c "$C_GRAY" "    - Network: DNS resolves, port 443 open, TLS works, no firewall blocks"
            _print -c "$C_GRAY" "    - Auth: Your instrumentation key is accepted by your resource's ingestion endpoint"
            _print -c "$C_GRAY" "    - Service: Azure Monitor is accepting data from this machine's network location"
            _print ""
            _print -c "$C_CYAN" "  SENDING TEST TELEMETRY RECORD..."
            _print ""
        fi

        # Check curl availability
        if ! command -v curl &>/dev/null; then
            write_progress_line "Telemetry Ingestion" "SKIP" "curl not available (install curl)"
        else
            test_ingestion_endpoint "$ingestion_endpoint" "$CS_IKEY"

            # Per-endpoint result (verbose)
            write_result "$INGEST_RESULT_STATUS" "POST $INGEST_RESULT_ENDPOINT" \
                "$INGEST_RESULT_DETAIL" "$INGEST_RESULT_ACTION"

            if $VERBOSE_OUTPUT; then
                _print -n -c "$C_GRAY" "      InstrumentationKey: "
                _print -c "$C_WHITE" "$masked_key"

                # Show API response JSON
                if [[ -n "$INGEST_RESULT_RESPONSE_BODY" ]]; then
                    _print ""
                    _print -c "$C_CYAN" "      API Response:"
                    if $HAS_JQ; then
                        local pretty_json
                        pretty_json="$(echo "$INGEST_RESULT_RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$INGEST_RESULT_RESPONSE_BODY")"
                        while IFS= read -r line; do
                            _print -c "$C_GRAY" "      $line"
                        done <<< "$pretty_json"
                    else
                        _print -c "$C_GRAY" "      $INGEST_RESULT_RESPONSE_BODY"
                    fi
                    _print ""
                fi
            fi

            # --- Ingestion progress line ---
            if [[ "$INGEST_RESULT_STATUS" == "PASS" ]]; then
                local duration_note=""
                local latency_warning=""
                if (( INGEST_RESULT_DURATION > 0 )); then
                    duration_note=" [${INGEST_RESULT_DURATION}ms]"
                    if (( INGEST_RESULT_DURATION > 3000 )); then
                        latency_warning=" (high latency)"
                    fi
                fi
                write_progress_line "Telemetry Ingestion" "OK" "HTTP 200, accepted${duration_note}${latency_warning}"

                # BOTTOM LINE for --network-only: ingestion passed but no E2E verification available
                if $NETWORK_ONLY && $VERBOSE_OUTPUT; then
                    _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
                    _print -n -c "$C_GREEN" "  BOTTOM LINE: "
                    _print -c "$C_WHITE" "Network connectivity validated. Ingestion API accepted test telemetry record."
                    _print ""
                    _print -c "$C_GRAY" "  E2E verification was not performed (--network-only skips Azure resource checks)."
                    _print -c "$C_GRAY" "  Use the KQL query below to manually confirm the record arrived in logs."
                    _print ""
                    _print -c "$C_GRAY" "  If telemetry from your application is still missing, focus on:"
                    _print -c "$C_GRAY" "    1. SDK/Agent configuration and initialization issues"
                    _print -c "$C_GRAY" "    2. Connection string - Does your app use this same connection string?"
                    _print -c "$C_GRAY" "    3. Sampling - Is adaptive sampling dropping data?"
                    _print -c "$C_GRAY" "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing"
                    _print -c "$C_GRAY" "    5. Process state - Is your app process (w3wp.exe, dotnet, node) healthy?"
                    _print -c "$C_GRAY" "    6. Review any other WARN or INFO messages reported by this tool"
                    _print ""
                    _print -c "$C_DARK_GRAY" "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics"
                    _print -c "$C_DARK_GRAY" "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats"
                    _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
                    _print ""
                fi

                # KQL verification query (network-only: E2E won't run, give manual query)
                if $NETWORK_ONLY; then
                    _print ""
                    _print -c "$C_CYAN" "  MANUAL VERIFICATION QUERY:"
                    _print -c "$C_DARK_GRAY" "  The ingestion API accepted the test record (HTTP 200), but --network-only skips"
                    _print -c "$C_DARK_GRAY" "  automated verification. Run the following query in App Insights > Logs to confirm arrival:"
                    _print ""
                    _print -c "$C_WHITE" "  availabilityResults | where customDimensions.diagnosticRunId == '$INGEST_RESULT_TEST_RECORD_ID'"
                    _print ""
                fi

                # High latency note
                if (( INGEST_RESULT_DURATION > 3000 )); then
                    _print -n -c "$C_YELLOW" "  NOTE: "
                    _print -c "$C_YELLOW" "Round-trip API response time was ${INGEST_RESULT_DURATION}ms (higher than typical <1000ms)."
                    _print -c "$C_DARK_GRAY" "  This measures client-to-ingestion-API round-trip only, NOT full pipeline latency."
                    _print -c "$C_DARK_GRAY" "  Possible causes: proxy routing, geographic distance, or network congestion."
                    _print ""
                fi
            elif [[ "$INGEST_RESULT_STATUS" == "INFO" ]]; then
                # 401 with local auth disabled is INFO, not blocking
                write_progress_line "Telemetry Ingestion" "INFO" "$INGEST_RESULT_DETAIL"
            else
                # Correlate: if 401 and local auth is disabled, this is expected, not blocking
                if [[ "$INGEST_RESULT_DETAIL" == *"401"* ]] && $LOCAL_AUTH_DISABLED; then
                    write_progress_line "Telemetry Ingestion" "INFO" "HTTP 401 (expected -- Entra ID auth required, test uses iKey)"
                    add_diagnosis "INFO" "Ingestion Returned 401 (Entra ID Auth Required)" \
                        "HTTP 401 expected -- script uses iKey but resource requires Entra ID" \
                        "This script sends telemetry using iKey/local auth, but local auth is disabled. Only Entra ID bearer tokens are accepted. This 401 is expected for our test." \
                        "If your apps use Entra ID tokens, this is expected. If not seeing telemetry, verify SDK Entra ID config and Monitoring Metrics Publisher role." \
                        "" \
                        "https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
                else
                    write_progress_line "Telemetry Ingestion" "FAIL" "$INGEST_RESULT_DETAIL"

                    # Select Portal path and Docs based on HTTP response code
                    local ing_fail_portal=""
                    local ing_fail_docs="https://learn.microsoft.com/troubleshoot/azure/azure-monitor/welcome-azure-monitor"
                    case "$INGEST_RESULT_HTTP_STATUS" in
                        400)
                            ing_fail_portal="App Insights > Overview > Connection String (verify iKey)"
                            ;;
                        401)
                            ing_fail_portal="App Insights > Properties > Local Authentication"
                            ing_fail_docs="https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication"
                            ;;
                        403)
                            ing_fail_portal="App Insights > Network Isolation > 'Enabled from all networks'"
                            ing_fail_docs="https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure"
                            ;;
                        429|439)
                            ing_fail_portal="App Insights > Usage and estimated costs > Daily Cap"
                            ing_fail_docs="https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap"
                            ;;
                    esac

                    if $INGESTION_BLOCKED_PREFLIGHT; then
                        add_diagnosis "INFO" "Ingestion Block Confirmed by Test" \
                            "Confirmed: sample telemetry test returned HTTP $INGEST_RESULT_HTTP_STATUS (see blocking issue above)" \
                            "The sample telemetry test confirmed the ingestion block detected earlier. $INGEST_RESULT_DETAIL" \
                            "Resolve the blocking issue above first, then re-run to verify." \
                            "$ing_fail_portal" \
                            "$ing_fail_docs"
                    else
                        add_diagnosis "BLOCKING" "Telemetry Ingestion Failed" \
                            "Telemetry ingestion failed ($INGEST_RESULT_DETAIL)" \
                            "Could not send test telemetry to App Insights. $INGEST_RESULT_DETAIL" \
                            "${INGEST_RESULT_ACTION}" \
                            "$ing_fail_portal" \
                            "$ing_fail_docs"
                    fi
                fi
            fi
        fi
    fi

    # ================================================================
    # STEP 9: E2E VERIFICATION (requires Azure login + successful ingestion)
    # ================================================================
    # Gate: Azure checks active, AI resource found, ingestion passed.
    # This queries the App Insights data plane API to confirm the test
    # record actually arrived and is queryable in logs.
    # ================================================================
    if $CHECK_AZURE && ! $NETWORK_ONLY && [[ -n "$AI_RESOURCE_ID" ]] && [[ "$INGEST_RESULT_STATUS" == "PASS" ]]; then

        write_progress_start "End-to-End Verification"

        # Resolve the Application ID needed for the data plane API
        # Priority: 1) connection string ApplicationId, 2) AI resource properties
        local app_id_for_query=""
        if [[ -n "$CS_APPLICATION_ID" ]]; then
            app_id_for_query="$CS_APPLICATION_ID"
        elif [[ -n "$AI_APP_ID" ]]; then
            app_id_for_query="$AI_APP_ID"
        fi
        _debug "E2E: AppId='${app_id_for_query:-(empty)}' (source: ${CS_APPLICATION_ID:+connection string}${CS_APPLICATION_ID:-ARM refresh})"

        if [[ -z "$app_id_for_query" || "$app_id_for_query" == "null" ]]; then
            # No AppId available
            if $VERBOSE_OUTPUT; then
                _print ""
                _print -c "$C_DARK_GRAY" "  [i] Application ID not found -- skipping end-to-end verification."
                _print -c "$C_DARK_GRAY" "      The AppId was not in the connection string or resource properties."
                _print -c "$C_DARK_GRAY" "      Use the KQL above to verify manually in App Insights > Logs."
                _print ""
            fi
            write_progress_line "End-to-End Verification" "SKIP" "No Application ID available"
        else
            # Acquire data plane token
            local data_plane_token
            data_plane_token="$(get_data_plane_token "$data_plane_resource")"

            if [[ -z "$data_plane_token" ]]; then
                # Token acquisition failed
                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_DARK_GRAY" "  [i] Could not acquire data plane API token -- skipping end-to-end verification."
                    _print -c "$C_DARK_GRAY" "      Your account may not have Reader access, or the token endpoint is unreachable."
                    _print -c "$C_DARK_GRAY" "      Use the KQL above to verify manually in App Insights > Logs."
                    _print ""
                fi
                write_progress_line "End-to-End Verification" "SKIP" "No data plane token (verify manually with KQL above)"
            else
                # Token acquired -- proceed with E2E verification
                if $VERBOSE_OUTPUT; then
                    local dash_line
                    dash_line="$(printf -- '-%.0s' {1..71})"
                    _print ""
                    _print -c "$C_CYAN" "  $dash_line"
                    _print -c "$C_CYAN" "  END-TO-END VERIFICATION"
                    _print -c "$C_CYAN" "  $dash_line"
                    _print ""
                    _print -c "$C_GRAY" "  The ingestion API accepted the test record. Now we can verify it actually"
                    _print -c "$C_GRAY" "  arrived in the backend logs by querying your Application Insights resource."
                    _print -c "$C_GRAY" "  This closes the loop on the entire telemetry pipeline:"
                    _print -c "$C_GRAY" "    This machine -> Ingestion API -> Processing Pipeline -> Log Analytics -> Queryable"
                    _print ""
                    _print -c "$C_DARK_GRAY" "  NOTE ON INGESTION LATENCY:"
                    _print -c "$C_DARK_GRAY" "  Data typically appears in a few seconds to a few minutes, but longer pipeline"
                    _print -c "$C_DARK_GRAY" "  ingestion delays can randomly occur. A slow but successful pipeline is normal."
                    _print -c "$C_DARK_GRAY" "  https://www.microsoft.com/licensing/docs/view/Service-Level-Agreements-SLA-for-Online-Services"
                fi

                if $VERBOSE_OUTPUT; then
                    _print ""
                    _print -c "$C_WHITE" "  Verifying record arrived in App Insights logs..."
                    _print -c "$C_GRAY" "  Querying your App Insights resource for the test record, polling every 10 seconds for up to 60 seconds."
                    _print ""
                fi

                # Run the poll/verify loop (show polling output only in verbose mode)
                local show_poll="true"
                ! $VERBOSE_OUTPUT && show_poll="false"
                test_e2e_verification "$app_id_for_query" "$data_plane_token" "$INGEST_RESULT_TEST_RECORD_ID" 60 10 "$data_plane_host" "$show_poll"

                # --- Display results ---
                if [[ "$E2E_STATUS" == "PASS" ]]; then
                    local e2e_summary="Record arrived"
                    if (( E2E_DUPLICATE_COUNT > 1 )); then
                        e2e_summary+=" (${E2E_DUPLICATE_COUNT} copies -- duplicates detected)"
                    fi
                    [[ -n "$E2E_LATENCY_E2E" ]] && e2e_summary+=" (E2E: ${E2E_LATENCY_E2E}s)"
                    $VERBOSE_OUTPUT && _print ""
                    write_progress_line "End-to-End Verification" "OK" "$e2e_summary"

                    if $VERBOSE_OUTPUT && [[ -n "$E2E_LATENCY_SENT" ]]; then
                        _print ""
                        _print -c "$C_CYAN" "  LATENCY BREAKDOWN:"
                        _print ""
                        _print -n -c "$C_GRAY" "  Sent (client):       "
                        _print -c "$C_WHITE" "$E2E_LATENCY_SENT"
                        _print -n -c "$C_GRAY" "  Received (pipeline): "
                        _print -n -c "$C_WHITE" "$E2E_LATENCY_RECEIVED"
                        _print -c "$C_DARK_GRAY" "   (client -> pipeline: ${E2E_LATENCY_CLIENT_TO_PIPELINE}s)"
                        _print -n -c "$C_GRAY" "  Stored (queryable):  "
                        _print -n -c "$C_WHITE" "$E2E_LATENCY_INGESTED"
                        _print -c "$C_DARK_GRAY" "   (pipeline -> storage: ${E2E_LATENCY_PIPELINE_TO_STORE}s)"
                        _print -n -c "$C_GRAY" "  End-to-end:          "
                        _print -c "$C_GREEN" "${E2E_LATENCY_E2E}s"
                        _print ""
                        _print -c "$C_DARK_GRAY" "  Note: Negative client->pipeline time indicates clock skew between this"
                        _print -c "$C_DARK_GRAY" "  machine and Azure. This is normal and does not affect telemetry delivery."
                        _print -c "$C_DARK_GRAY" "  Azure Monitor rejects records timestamped more than 2 hours in the future."
                        _print ""
                        _print -c "$C_CYAN" "  WHAT THIS MEANS:"
                        _print -c "$C_GRAY" "  Client -> Pipeline measures network transit from this machine to Azure Monitor."
                        _print -c "$C_GRAY" "  Pipeline -> Storage measures Azure's internal processing (parsing, indexing)."
                        _print -c "$C_GRAY" "  E2E latency varies by region and load. A result within a few minutes is typical."
                        _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time"
                        _print ""
                    elif $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_DARK_GRAY" "  (Latency breakdown not available -- timestamp parsing failed)"
                        _print ""
                    fi

                    # --- Duplicate detection messaging ---
                    if $VERBOSE_OUTPUT && (( E2E_DUPLICATE_COUNT > 1 )); then
                        _print -c "$C_YELLOW" "  [!] DUPLICATE TELEMETRY DETECTED"
                        _print ""
                        _print -c "$C_YELLOW" "  We sent 1 unique test record but received ${E2E_DUPLICATE_COUNT} copies in the query results."
                        _print -c "$C_YELLOW" "  This confirms duplicate telemetry is being written to your workspace."
                        _print ""
                        if (( DIAG_SETTINGS_LA_COUNT > 0 )); then
                            _print -c "$C_CYAN" "  ROOT CAUSE IDENTIFIED:"
                            _print -c "$C_GRAY" "  Earlier in this report we detected ${DIAG_SETTINGS_LA_COUNT} Diagnostic Setting(s) exporting"
                            _print -c "$C_GRAY" "  App Insights log data to a Log Analytics workspace. This is the source of the"
                            _print -c "$C_GRAY" "  duplicate records. Each Diagnostic Setting creates an additional copy of every"
                            _print -c "$C_GRAY" "  telemetry record in the target workspace."
                            _print ""
                            _print -c "$C_GRAY" "  See the 'Diagnostic Settings Exporting to LA' finding above for fix options."
                        else
                            _print -c "$C_CYAN" "  POSSIBLE CAUSES:"
                            _print -c "$C_GRAY" "  1. Diagnostic Settings that were recently removed may still have in-flight data"
                            _print -c "$C_GRAY" "  2. Multiple SDKs or agents sending from the same application"
                            _print -c "$C_GRAY" "  3. Data Collection Rules with transformations that fork telemetry"
                        fi
                        _print ""

                        local dup_desc="The E2E verification query returned ${E2E_DUPLICATE_COUNT} copies of the single unique test record sent by this tool. This confirms duplicate telemetry is being written."
                        if (( DIAG_SETTINGS_LA_COUNT > 0 )); then
                            dup_desc+=" The ${DIAG_SETTINGS_LA_COUNT} Diagnostic Setting(s) exporting to Log Analytics (detected earlier) are the likely root cause."
                        else
                            dup_desc+=" Check for Diagnostic Settings, multiple SDKs, or DCR transforms."
                        fi
                        add_diagnosis "INFO" "Duplicate Telemetry Confirmed (E2E Verification)" \
                            "Sent 1 test record, received ${E2E_DUPLICATE_COUNT} copies -- duplicates confirmed" \
                            "$dup_desc" \
                            "Remove Diagnostic Settings that export to LA, or de-duplicate with KQL distinct operator." \
                            "App Insights > Monitoring > Diagnostic settings" \
                            "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
                    fi

                    if $VERBOSE_OUTPUT; then
                        _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
                        _print -n -c "$C_GREEN" "  BOTTOM LINE: "
                        _print -c "$C_WHITE" "Environment validated. Network, auth, and ingestion are working."
                        _print ""
                        _print -c "$C_GRAY" "  If telemetry from your application is still missing, focus on:"
                        _print -c "$C_GRAY" "    1. SDK/Agent configuration and initialization issues"
                        _print -c "$C_GRAY" "    2. Connection string - Does your app use this same connection string?"
                        _print -c "$C_GRAY" "    3. Sampling - Is adaptive sampling dropping data?"
                        _print -c "$C_GRAY" "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing"
                        _print -c "$C_GRAY" "    5. Process state - Is your app process (w3wp, dotnet, node) healthy?"
                        _print -c "$C_GRAY" "    6. Review any other WARN or INFO messages reported by this tool"
                        _print ""
                        _print -c "$C_DARK_GRAY" "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics"
                        _print -c "$C_DARK_GRAY" "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats"
                        _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
                        _print ""
                    fi

                elif [[ "$E2E_STATUS" == "TIMEOUT" ]]; then
                    $VERBOSE_OUTPUT && _print ""
                    write_progress_line "End-to-End Verification" "INFO" "Not found after ${E2E_WAITED_SECONDS}s (pipeline may still be processing)"
                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_GRAY" "  The test record was accepted by the ingestion API but hasn't appeared in"
                        _print -c "$C_GRAY" "  query results yet. This is not necessarily an error -- pipeline processing"
                        _print -c "$C_GRAY" "  can take a few minutes under normal conditions. Use the KQL above to check later."
                        _print ""
                    fi

                elif [[ "$E2E_STATUS" == "ERROR" ]]; then
                    local is_auth_error=false
                    [[ "$E2E_ERROR" =~ Authorization|Unauthorized|Forbidden|Authentication|403|401 ]] && is_auth_error=true

                    local error_summary="Query failed"
                    $is_auth_error && error_summary="Auth failed"

                    $VERBOSE_OUTPUT && _print ""
                    write_progress_line "End-to-End Verification" "INFO" "$error_summary -- verify manually with KQL above"
                    if $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_YELLOW" "  Error: $E2E_ERROR"
                    fi

                    if $is_auth_error && $VERBOSE_OUTPUT; then
                        _print ""
                        _print -c "$C_CYAN" "  DATA PLANE AUTH TROUBLESHOOTING:"
                        _print -c "$C_GRAY" "  The token was acquired but the API rejected it. Common causes:"
                        _print -c "$C_GRAY" "    1. Missing RBAC: Your account needs 'Reader' on the App Insights resource"
                        _print -c "$C_DARK_GRAY" "       (specifically the 'Microsoft.Insights/components/*/read' permission)"
                        _print -c "$C_GRAY" "    2. Wrong audience: The token must target '${data_plane_resource}'"
                        _print -c "$C_GRAY" "    3. Workspace-based query restrictions: If public query access is disabled,"
                        _print -c "$C_GRAY" "       queries must come from within the AMPLS/private link scope"
                        _print ""
                    elif $VERBOSE_OUTPUT; then
                        _print -c "$C_GRAY" "  This does not mean ingestion failed -- use the KQL above to verify manually."
                    fi
                    $VERBOSE_OUTPUT && _print ""
                fi
            fi
        fi
    elif $CHECK_AZURE && ! $NETWORK_ONLY && [[ "$INGEST_RESULT_STATUS" != "PASS" ]]; then
        # Ingestion didn't pass -- skip E2E
        (( STEP_NUMBER++ ))
        write_progress_line "End-to-End Verification" "SKIP" "Skipped (ingestion test did not pass)"
    elif $CHECK_AZURE && ! $NETWORK_ONLY; then
        (( STEP_NUMBER++ ))
        write_progress_line "End-to-End Verification" "SKIP" "App Insights resource not found"
    elif ! $CHECK_AZURE && ! $NETWORK_ONLY && [[ "$INGEST_RESULT_STATUS" == "PASS" ]]; then
        # No Azure login -- can't do automated E2E verification.
        # Show manual verification guidance with KQL query.
        write_progress_line "End-to-End Verification" "SKIP" "Azure login not available (verify manually with KQL below)"

        local verify_kql="availabilityResults | where customDimensions.diagnosticRunId == '$INGEST_RESULT_TEST_RECORD_ID'"

        if $VERBOSE_OUTPUT; then
            _print ""
            _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
            _print -n -c "$C_GREEN" "  BOTTOM LINE: "
            _print -c "$C_WHITE" "Network connectivity validated. Ingestion API accepted test telemetry record."
            _print ""
            _print -c "$C_GRAY" "  Automated end-to-end verification requires an Azure login (az CLI)."
            _print -c "$C_GRAY" "  The ingestion API accepted the test record (HTTP 200). To confirm it arrived"
            _print -c "$C_GRAY" "  in your App Insights resource, run the KQL query below manually."
            _print ""
            _print -c "$C_GRAY" "  If telemetry from your application is still missing, focus on:"
            _print -c "$C_GRAY" "    1. SDK/Agent configuration and initialization issues"
            _print -c "$C_GRAY" "    2. Connection string - Does your app use this same connection string?"
            _print -c "$C_GRAY" "    3. Sampling - Is adaptive sampling dropping data?"
            _print -c "$C_GRAY" "    4. SDK logs - Enable verbose SDK logging to see what the SDK is doing"
            _print -c "$C_GRAY" "    5. Process state - Is your app process (w3wp, dotnet, node) healthy?"
            _print -c "$C_GRAY" "    6. Review any other WARN or INFO messages reported by this tool"
            _print ""
            _print -c "$C_DARK_GRAY" "  Docs: (SDK Logging) https://learn.microsoft.com/troubleshoot/azure/azure-monitor/app-insights/telemetry/enable-self-diagnostics"
            _print -c "$C_DARK_GRAY" "  Docs: (SDK Stats) https://learn.microsoft.com/azure/azure-monitor/app/sdk-stats"
            _print -c "$C_DARK_GRAY" "  -------------------------------------------------------------------------"
            _print ""
        fi

        _print ""
        _print -c "$C_CYAN" "  MANUAL VERIFICATION QUERY:"
        _print -c "$C_DARK_GRAY" "  The ingestion API accepted the test record (HTTP 200) but automated verification"
        _print -c "$C_DARK_GRAY" "  is not available without an Azure login. Open Azure Portal > App Insights > Logs"
        _print -c "$C_DARK_GRAY" "  and run this query to confirm the record arrived:"
        _print ""
        _print -c "$C_WHITE" "  $verify_kql"
        _print ""
    fi

    # Safety net: if a progress start is still pending (shouldn't happen, but defensive),
    # close the partial line so the diagnosis section starts clean.
    if [[ -n "$PROGRESS_START_PENDING" ]] && ! $VERBOSE_OUTPUT && ! $DEBUG_MODE; then
        echo ""
        PROGRESS_START_PENDING=""
    fi

    # ================================================================
    # DIAGNOSIS SUMMARY
    # ================================================================
    render_diagnosis_summary

    # ---- Footer ----
    _print ""
    _print -c "$C_WHITE" "  ================================================================"
    if $COMPACT; then
        _print -n -c "$C_DARK_GRAY" "  Tip: Run without "
        _print -n -c "$C_WHITE" "--compact"
        _print -c "$C_DARK_GRAY" " for verbose output with full explanations."
    fi
    if $NETWORK_ONLY; then
        _print -n -c "$C_DARK_GRAY" "  Tip: Run without "
        _print -n -c "$C_WHITE" "--network-only"
        _print -c "$C_DARK_GRAY" " to include Azure resource checks."
    fi
    if ! $CHECK_AZURE && ! $NETWORK_ONLY && [[ ${#AMPLS_EXPECTED_IPS[@]} -eq 0 ]]; then
        if $azure_consent_declined; then
            _print -c "$C_DARK_GRAY" "  Note: Azure resource checks were skipped. User consent was not granted."
        else
            _print -c "$C_DARK_GRAY" "  Note: Azure resource checks were skipped (az CLI not found or not logged in)."
            if $ENV_IS_APP_SERVICE || $ENV_IS_FUNCTION_APP || $ENV_IS_CONTAINER_APP; then
                _print -c "$C_DARK_GRAY" "  To include resource checks, run this script from Azure Cloud Shell or a machine with az CLI."
            else
                _print -n -c "$C_DARK_GRAY" "  Install az CLI and run "
                _print -n -c "$C_WHITE" "az login"
                _print -c "$C_DARK_GRAY" " to enable AMPLS, workspace health, and E2E checks."
            fi
        fi
    fi
    if ! $AUTO_APPROVE; then
        _print -n -c "$C_DARK_GRAY" "  Tip: Run with "
        _print -n -c "$C_WHITE" "--auto-approve"
        _print -c "$C_DARK_GRAY" " to skip consent prompts on repeat runs."
    fi
    _print -c "$C_DARK_GRAY" "  Docs: https://learn.microsoft.com/troubleshoot/azure/azure-monitor/welcome-azure-monitor"
    _print -c "$C_DARK_GRAY" "  Source: https://github.com/microsoft/appinsights-telemetry-flow"
    _print -c "$C_WHITE" "  ================================================================"
    _print ""

    # ================================================================
    # SAVE REPORT FILES
    # ================================================================
    local report_dir="${OUTPUT_PATH:-.}"
    mkdir -p "$report_dir" 2>/dev/null || report_dir="."

    local utc_timestamp
    utc_timestamp="$(date -u '+%Y-%m-%dT%H%M%SZ')"
    local safe_hostname
    safe_hostname="$(echo "$ENV_COMPUTER_NAME" | tr ' ()/:*?"<>|\\' '_')"
    local safe_ai_name=""
    [[ -n "$AI_RESOURCE_NAME" ]] && safe_ai_name="$(echo "$AI_RESOURCE_NAME" | tr ' ()/:*?"<>|\\' '_')"
    local auto_name
    if [[ -n "$safe_ai_name" ]]; then
        auto_name="AppInsights-Diag_${safe_hostname}_${safe_ai_name}_${utc_timestamp}"
    else
        auto_name="AppInsights-Diag_${safe_hostname}_${utc_timestamp}"
    fi

    local json_path="${report_dir}/${auto_name}.json"
    local txt_path="${report_dir}/${auto_name}.txt"

    # --- Build JSON report ---
    local json_diag_items="[]"
    if (( ${#DIAGNOSIS_ITEMS[@]} > 0 )); then
        json_diag_items="["
        local first=true
        for item in "${DIAGNOSIS_ITEMS[@]}"; do
            $first || json_diag_items+=","
            first=false
            local sev title summ desc fix portal docs
            sev="$(_diag_field "$item" 0)"
            title="$(_diag_field "$item" 1)"
            summ="$(_diag_field "$item" 2)"
            desc="$(_diag_field "$item" 3)"
            fix="$(_diag_field "$item" 4)"
            portal="$(_diag_field "$item" 5)"
            docs="$(_diag_field "$item" 6)"
            # Escape double quotes for valid JSON
            sev="${sev//\"/\\\"}"
            title="${title//\"/\\\"}"
            summ="${summ//\"/\\\"}"
            desc="${desc//\"/\\\"}"
            fix="${fix//\"/\\\"}"
            portal="${portal//\"/\\\"}"
            docs="${docs//\"/\\\"}"
            json_diag_items+="{\"Severity\":\"$sev\",\"Title\":\"$title\",\"Summary\":\"$summ\",\"Description\":\"$desc\",\"Fix\":\"$fix\",\"Portal\":\"$portal\",\"Docs\":\"$docs\"}"
        done
        json_diag_items+="]"
    fi

    # --- Compute summary counters (mirrors PS1 $allResults aggregation) ---
    local total_checks=0 pass_count=0 fail_count=0 warn_count=0
    for s in "${DNS_R_STATUS[@]}"; do
        (( total_checks++ ))
        case "$s" in PASS) (( pass_count++ )) ;; FAIL) (( fail_count++ )) ;; WARN) (( warn_count++ )) ;; esac
    done
    for s in "${TCP_R_STATUS[@]}"; do
        (( total_checks++ ))
        case "$s" in PASS) (( pass_count++ )) ;; FAIL) (( fail_count++ )) ;; WARN) (( warn_count++ )) ;; INFO) ;; esac
    done
    for s in "${TLS_R_STATUS[@]}"; do
        (( total_checks++ ))
        case "$s" in PASS) (( pass_count++ )) ;; FAIL) (( fail_count++ )) ;; WARN) (( warn_count++ )) ;; esac
    done
    if [[ -n "$INGEST_RESULT_STATUS" ]]; then
        (( total_checks++ ))
        case "$INGEST_RESULT_STATUS" in PASS) (( pass_count++ )) ;; FAIL) (( fail_count++ )) ;; WARN) (( warn_count++ )) ;; esac
    fi
    for entry in "${ampls_comparison_results[@]}"; do
        (( total_checks++ ))
        local ampls_s="${entry##*|}"
        case "$ampls_s" in PASS) (( pass_count++ )) ;; MISMATCH|FAIL) (( fail_count++ )) ;; esac
    done

    cat > "$json_path" 2>/dev/null <<JSONEOF
{
  "ToolVersion": "$SCRIPT_VERSION",
  "Timestamp": "$(get_timestamp)",
  "Environment": {
    "ComputerName": "$ENV_COMPUTER_NAME",
    "OS": "$ENV_OS",
    "BashVersion": "$ENV_BASH_VERSION",
    "AzureHostType": "${ENV_AZURE_HOST_TYPE:-}",
    "AzureHostDetail": "${ENV_AZURE_HOST_DETAIL:-}",
    "IsAppService": $ENV_IS_APP_SERVICE,
    "IsFunctionApp": $ENV_IS_FUNCTION_APP,
    "IsContainerApp": $ENV_IS_CONTAINER_APP,
    "IsKubernetes": $ENV_IS_KUBERNETES,
    "IsCloudShell": $ENV_IS_CLOUD_SHELL,
    "IsContainer": $ENV_IS_CONTAINER,
    "ProxyDetected": $proxy_detected
  },
  "ConnectionString": {
    "InstrumentationKey": "$masked_key",
    "IngestionEndpoint": "$ingestion_endpoint",
    "LiveEndpoint": "${live_endpoint:-}",
    "IsGlobalEndpoint": $is_global_endpoint,
    "Cloud": "$cloud_label",
    "CloudSuffix": "$cloud_suffix"
  },
  "KnownIssues": {
    "LocalAuthDisabled": $LOCAL_AUTH_DISABLED,
    "IngestionSamplingPct": ${sampling_pct:-null},
    "BackendWorkspace": "${WS_NAME}",
    "DailyCapStatus": "${cap_status:-null}",
    "AiDailyCapGb": $(if $AI_CAP_OFF; then echo '"OFF"'; elif [[ -n "$AI_CAP_GB" ]]; then echo "$AI_CAP_GB"; else echo "null"; fi),
    "LaDailyCapGb": $(if $WS_CAP_OFF; then echo '"OFF"'; elif [[ -n "$WS_CAP_QUOTA_GB" ]]; then echo "$WS_CAP_QUOTA_GB"; else echo "null"; fi)
  },
  "EndToEndVerification": {
    "Status": $(if [[ -n "$E2E_STATUS" ]]; then echo "\"$E2E_STATUS\""; else echo "null"; fi),
    "RecordFound": $E2E_RECORD_FOUND,
    "PollAttempts": ${E2E_POLL_ATTEMPTS:-0},
    "WaitedSeconds": ${E2E_WAITED_SECONDS:-0},
    "LatencyE2ESec": ${E2E_LATENCY_E2E:-null},
    "LatencyClientToPipelineSec": ${E2E_LATENCY_CLIENT_TO_PIPELINE:-null},
    "LatencyPipelineToStoreSec": ${E2E_LATENCY_PIPELINE_TO_STORE:-null}
  },
  "Diagnosis": $json_diag_items,
  "Summary": {
    "TotalChecks": $total_checks,
    "Passed": $pass_count,
    "Warnings": $warn_count,
    "Failed": $fail_count,
    "AmplsDetected": $has_ampls_signals,
    "AmplsValidated": $ampls_checked,
    "AzureChecksRequested": $CHECK_AZURE,
    "AzureChecksCompleted": $(if $CHECK_AZURE && [[ -n "$AI_RESOURCE_ID" ]]; then echo "true"; else echo "false"; fi),
    "DetectedAppInsights": $(if [[ -n "$AI_RESOURCE_ID" ]]; then echo "\"$AI_RESOURCE_ID\""; else echo "null"; fi),
    "DetectedLogAnalytics": $(if [[ -n "$WS_RESOURCE_ID" ]]; then echo "\"$WS_RESOURCE_ID\""; else echo "null"; fi)
  }
}
JSONEOF

    if [[ $? -eq 0 ]]; then
        _print -c "$C_GREEN" "  Report saved: $json_path"
    else
        _print -c "$C_YELLOW" "  [!] Could not write report to: $json_path"
    fi

    # --- Save TXT report ---
    {
        echo "============================================================"
        echo "Application Insights Telemetry Flow Diagnostics v$SCRIPT_VERSION"
        echo "============================================================"
        echo "Generated:      $(get_timestamp)"
        echo "Host:           $ENV_COMPUTER_NAME ($ENV_OS)"
        [[ -n "$ENV_AZURE_HOST_TYPE" ]] && echo "Azure:          $ENV_AZURE_HOST_TYPE"
        echo "iKey:           $masked_key"
        echo "Endpoint:       $ingestion_endpoint"
        [[ "$cloud_suffix" != "com" ]] && echo "Cloud:          $cloud_label"
        echo ""
        echo "============================================================"
        echo "CONSOLE OUTPUT"
        echo "============================================================"
        echo ""
        echo "$CONSOLE_LOG" | sed 's/\x1B\[[0-9;]*[mGKHJ]//g'
    } > "$txt_path" 2>/dev/null

    if [[ $? -eq 0 ]]; then
        _print -c "$C_GREEN" "  Console log saved: $txt_path"
    else
        _print -c "$C_YELLOW" "  [!] Could not write console log to: $txt_path"
    fi

    _print ""
    _print -c "$C_WHITE" "  Application Insights connectivity test complete."
    _print ""

    # ================================================================
    # EXIT CODE
    # ================================================================
    local has_blocking=false has_warning=false has_info=false
    for item in "${DIAGNOSIS_ITEMS[@]}"; do
        local sev
        sev="$(_diag_field "$item" 0)"
        [[ "$sev" == "BLOCKING" ]] && has_blocking=true
        [[ "$sev" == "WARNING" ]] && has_warning=true
        [[ "$sev" == "INFO" ]] && has_info=true
    done

    if $has_blocking; then exit 3
    elif $has_warning; then exit 2
    elif $has_info; then exit 1
    else exit 0
    fi
}

# ============================================================================
# ENTRY POINT
# ============================================================================
main "$@"