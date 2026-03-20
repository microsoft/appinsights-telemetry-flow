# AMPLS & Private Link Deep Dive

> A methodical approach to troubleshooting Azure Monitor Private Link Scope
> (AMPLS) issues with Application Insights — starting from what the resource
> allows, then checking what the network delivers.

---

## Table of Contents

- [Why AMPLS Troubleshooting Is Challenging](#why-ampls-troubleshooting-is-hard)
- [The Troubleshooting Framework](#the-troubleshooting-framework)
  - [Step 1 — Where Does App Insights Want Traffic to Come From?](#step-1--where-does-app-insights-want-traffic-to-come-from)
  - [Step 2 — Which Private Networks Does App Insights Trust?](#step-2--which-private-networks-does-app-insights-trust)
  - [Step 3 — What Do the AMPLS Access Modes Allow?](#step-3--what-do-the-ampls-access-modes-allow)
  - [Step 4 — Where Does Your DNS Actually Send Traffic?](#step-4--where-does-your-dns-actually-send-traffic)
- [Putting It All Together: The Decision Matrix](#putting-it-all-together-the-decision-matrix)
- [The Four AMPLS Scenarios You Will See](#the-four-ampls-scenarios-you-will-see)
  - [Scenario A — No AMPLS, Public Access](#scenario-a--no-ampls-public-access)
  - [Scenario B — AMPLS, Open Mode, Correctly Configured](#scenario-b--ampls-open-mode-correctly-configured)
  - [Scenario C — Ghost AMPLS (The "Somebody Else Added AMPLS" Problem)](#scenario-c--ghost-ampls-the-somebody-else-added-ampls-problem)
  - [Scenario D — Competing AMPLS Across Teams](#scenario-d--competing-ampls-across-teams)
- [How DNS Works in AMPLS](#how-dns-works-in-ampls)
  - [The CNAME Chain](#the-cname-chain)
  - [Private DNS Zones](#private-dns-zones)
  - [What "VNet-wide Impact" Really Means](#what-vnet-wide-impact-really-means)
  - [The Peered Network Problem](#the-peered-network-problem)
- [Access Modes Explained](#access-modes-explained)
  - [Open vs Private Only](#open-vs-private-only)
  - [How Access Modes Interact with Network Isolation](#how-access-modes-interact-with-network-isolation)
  - [Common Access Mode Mistakes](#common-access-mode-mistakes)
- [Network Isolation on the App Insights Resource](#network-isolation-on-the-app-insights-resource)
- [What the Script Checks](#what-the-script-checks)
  - [Automated AMPLS Discovery](#automated-ampls-discovery)
  - [IP Comparison Table](#ip-comparison-table)
  - [Network Access Assessment](#network-access-assessment)
  - [Ghost AMPLS Detection](#ghost-ampls-detection)
  - [Ghost AMPLS Reverse Lookup](#ghost-ampls-reverse-lookup)
  - [Manual Mode (-AmplsExpectedIps)](#manual-mode--amplsexpectedips)
- [DNS Mismatch Troubleshooting Checklist](#dns-mismatch-troubleshooting-checklist)
- [End-to-End Diagnostic Walkthrough](#end-to-end-diagnostic-walkthrough)
- [Multi-Cloud AMPLS](#multi-cloud-ampls)
- [Further Reading](#further-reading)

---

## Why AMPLS Troubleshooting Is Challenging

AMPLS consistently produces the most complex and confusing failures. 
There are three reasons:

1. **DNS is a VNet-wide side-effect.** Adding a single AMPLS + Private
   Endpoint to a VNet rewrites DNS for *every* Azure Monitor endpoint on
   that VNet — and potentially peered networks. Developers who did not
   configure the AMPLS are affected by it.

2. **Three independent configuration layers interact.** The App Insights
   resource has network isolation settings. The AMPLS has access mode
   settings. The VNet has DNS resolution behaviour. All three must agree
   or traffic gets dropped.

3. **Failures are silent.** When AMPLS blocks ingestion, the ingestion
   endpoint often returns HTTP 403, or worse, the request never reaches 
   any endpoint at all because DNS points to the wrong private IP, or
   DNS is unable to resolve the Azure Monitor endpoints at all. 

The mental model that cuts through this complexity is simple:
**treat it like a DNS problem.** Find out where App Insights *wants*
clients to connect, then check whether DNS on the your network
delivers traffic to that expected destination.

---

## The Troubleshooting Framework

The approach below is the same methodology the script automates. When
troubleshooting manually, follow these four steps in order.

### Step 1 — Where Does App Insights Want Traffic to Come From?

Before looking at the network, look at the **App Insights resource itself**.

**Portal path:** App Insights → Configure → Network Isolation

Two settings control who can send data and who can read it:

| Setting | Values | Effect |
|---------|--------|--------|
| **Ingestion access** | Enabled / Restricted | Whether apps on the public internet can POST telemetry |
| **Query access** | Enabled / Restricted | Whether Portal users / API callers on the public internet can read data |

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  App Insights Resource: "contoso-prod-ai"                       │
  │                                                                 │
  │  Ingestion:  Enabled from all networks    ←← public + private   │
  │  Query:      Enabled from all networks    ←← public + private   │
  │                                                                 │
  │  OR                                                             │
  │                                                                 │
  │  Ingestion:  Restricted (private only)      ←← AMPLS required   │
  │  Query:      Restricted (private only)      ←← AMPLS required   │
  └─────────────────────────────────────────────────────────────────┘
```

**What this tells you:**

- If **ingestion = Enabled**, apps on any network (public or private) can
  send telemetry. AMPLS is optional.
- If **ingestion = Restricted**, *only* clients coming through an AMPLS
  private endpoint can send telemetry. Public apps will get HTTP 403.
- The same logic applies to **query** — with the additional symptom that
  disabling public query makes the Azure Portal show empty charts when
  accessed from a public network (the telemetry may be there, you just
  cannot query it).

**Start here every time.** If public access is enabled and no private IPs
are appearing in DNS, AMPLS is not in play and you can skip the rest of
this article.

### Step 2 — Which Private Networks Does App Insights Trust?

If App Insights has `Restricted... (private only)` for ingestion or query — or
if you see private IPs in DNS resolution — you need to find out which
AMPLS resources are linked to this App Insights resource.

**Portal path:** App Insights → Configure → Network Isolation → Private
access → Azure Monitor Private Link Scopes (or use the Resource Graph query below)

Each linked AMPLS represents a "trusted private network." The AMPLS is
attached to a Private Endpoint, which lives on a specific VNet subnet.
Clients on that VNet (or peered VNets) can reach App Insights through
that Private Endpoint.

```
  ┌──────────────────────────┐
  │  App Insights resource   │
  │  "contoso-prod-ai"       │
  │                          │
  │  Linked AMPLS:           │
  │    ├── ampls-team-alpha  │──▶ PE on VNet-A (10.1.0.0/16)
  │    └── ampls-team-beta   │──▶ PE on VNet-B (10.2.0.0/16)
  └──────────────────────────┘
```

**Key questions to answer:**

- How many AMPLS resources are linked? (Often more than you expect.)
- Which VNet/subnet does each AMPLS's Private Endpoint sit on?
- Is your app running on one of those VNets?

### Step 3 — What Do the AMPLS Access Modes Allow?

Every AMPLS resource has two access mode settings that control what
clients on its VNet can reach.

**Portal path:** AMPLS resource → Configure -> Access modes

| Setting | Values | Effect |
|---------|--------|--------|
| **Ingestion access mode** | Open / Private Only | What Azure Monitor resources this VNet's apps can *send telemetry to* |
| **Query access mode** | Open / Private Only | What Azure Monitor resources this VNet's apps can *query* |

   >**Key Point: This is NOT about inbound — it is about outbound from the VNet's perspective:**

| Mode | Meaning |
|------|---------|
| **Open** | Clients on this VNet can reach *all* Azure Monitor resources — both the private ones scoped to this AMPLS and public ones that are not in the AMPLS. |
| **Private Only** | Clients on this VNet can *only* reach Azure Monitor resources that are added to this AMPLS. Attempts to reach unscoped/public resources are blocked. |

```
  AMPLS: ampls-team-alpha
  ┌────────────────────────────────────────────────────────────┐
  │  Ingestion mode:  Open                                     │
  │    → Apps on VNet-A can send telemetry to ANY App Insights │
  │      (both scoped to this AMPLS and public resources)      │
  │                                                            │
  │  Query mode:  Private Only                                 │
  │    → Apps/users on VNet-A can ONLY query resources that    │
  │      are added to this AMPLS scope                         │
  └────────────────────────────────────────────────────────────┘
```

**The critical insight:** Private Only mode on the AMPLS is an *exit
control*. It restricts what the VNet's clients can talk to — it does not
restrict who can talk *to* the App Insights resource. That inbound control
lives on the App Insights resource's Network Isolation settings (Step 1).

### Step 4 — Where Does Your DNS Actually Send Traffic?

Now you know:
1. Where App Insights *wants* traffic to come from (public, private, or both)
2. Which private networks it trusts (the AMPLS-linked VNets)
3. What the AMPLS access modes allow from those VNets

The final step is the DNS reality check. From your actual machine
or app environment/network, resolve the regional ingestion endpoint and compare:

```powershell
# PowerShell
Resolve-DnsName "{region}.in.applicationinsights.azure.com"

# Or use nslookup
nslookup {region}.in.applicationinsights.azure.com
```

| DNS Resolves To | What It Means |
|-----------------|---------------|
| **Public IP** (e.g. `20.x.x.x`) | Traffic will go out to Azure's public endpoints. If App Insights allows public ingestion → works. If not → HTTP 403. |
| **Private IP** matching the AMPLS PE (e.g. `10.1.0.5`) | Traffic routes through the correct Private Endpoint. AMPLS access modes apply. |
| **Private IP NOT matching any known AMPLS PE** | A different AMPLS on this VNet (or a peered VNet) is overriding DNS. Traffic routes to the wrong Private Endpoint. This is the "Ghost AMPLS" scenario. |
| **DNS failure** | Private DNS zone missing A records, zone not linked to VNet, or custom DNS server not forwarding to Azure DNS (168.63.129.16). |

**This is the step that reveals most AMPLS problems.** Steps 1–3 are about
configuration intent. Step 4 is about network reality.

---

## Putting It All Together: The Decision Matrix

This matrix shows the ingestion verdict for every combination of
resource settings, AMPLS state, and DNS resolution. The script computes
exactly this assessment in its "NETWORK ACCESS ASSESSMENT" section.

| App Insights Ingestion | AMPLS Linked? | Client DNS Resolves To | Verdict | Why |
|------------------------|---------------|------------------------|---------|-----|
| Enabled (all networks) | No | Public IP | **ALLOWED** | Public access, public path |
| Enabled (all networks) | Yes | Public IP | **ALLOWED** | Public access still works even with AMPLS |
| Enabled (all networks) | Yes, Open mode | Private IP (matches) | **ALLOWED** | Private path, Open mode allows everything |
| Enabled (all networks) | Yes, Private Only | Private IP (matches) | **ALLOWED** | Private path, resource is scoped to this AMPLS |
| Enabled (all networks) | No | Private IP (ghost) | **BLOCKED** | DNS entries ovwerwritten by another AMPLS; resource not scoped to it |
| Restricted (private only) | No | Public IP | **BLOCKED** | No private path configured; 403 |
| Restricted (private only) | Yes | Public IP | **BLOCKED** | Client is on public network; resource requires private |
| Restricted (private only) | Yes | Private IP (matches) | **ALLOWED** | Correct private path |
| Restricted (private only) | Yes | Private IP (mismatch) | **BLOCKED** | Wrong private endpoint; DNS stale or another AMPLS |

The same logic applies to query access, with the additional wrinkle that
"BLOCKED" for query means the Azure Portal shows empty charts even though
telemetry may have been successfully ingested.

---

## The Four AMPLS Scenarios You Will See

### Scenario A — No AMPLS, Public Access

```
  ┌─────────┐        Public DNS          ┌─────────────────┐
  │ App     │ ──── 20.42.x.x ─────────▶ │ App Insights    │
  │ (VNet)  │                            │ Ingestion: ✅  │
  └─────────┘                            │ Query:     ✅  │
                                         └─────────────────┘
```

**Configuration:**
- App Insights → Ingestion: Enabled from all networks
- App Insights → Query: Enabled from all networks
- No AMPLS linked

**Result:** Everything works over public IPs. This is the default and
most common configuration. Nothing to troubleshoot unless DNS cannot
resolve the public endpoints at all.

**Script output:** "No AMPLS (telemetry accepted at public endpoints)"

### Scenario B — AMPLS, Open Mode, Correctly Configured

```
  ┌─────────┐     Private DNS        ┌─────────────┐        ┌─────────────────┐
  │ App     │ ── 10.1.0.5 ────────▶ │ Private     │──────▶ │ App Insights    │
  │ (VNet-A)│                        │ Endpoint    │        │ Ingestion: ✅   │
  └─────────┘                        │ (VNet-A)    │        │ Query:     ✅   │
                                     └─────────────┘        └─────────────────┘
                                           ▲
                                     AMPLS: ampls-prod
                                     Mode: Open / Open
```

**Configuration:**
- App Insights → Network Isolation → may be Enabled or Restricted
- AMPLS `ampls-prod` linked to App Insights
- AMPLS access modes: Open / Open
- Private Endpoint on VNet-A with private DNS zone configured
- DNS resolves ingestion endpoint to `10.1.0.5` (matches Private Endpoint (PE) ingestion API IP)

**Result:** Traffic flows through the private endpoint, all IPs match,
access modes allow everything. Perfect.

**Script output:** "All # DNS entries match. Private link is correctly
configured."

### Scenario C — Ghost AMPLS (The "Somebody Else Added AMPLS" Problem)

This is the most common and most confusing AMPLS failure. It happens
when:

1. **Developer A** has an app on VNet-X sending telemetry to a public
   App Insights resource. Everything is working fine.
2. **Developer B** — on the same VNet or a peered VNet — adds an AMPLS
   + Private Endpoint because they want private telemetry for *their*
   App Insights resource.
3. Developer B's Private Endpoint **rewrites DNS for the entire VNet**.
   All Azure Monitor endpoints (global and specific regional endpoints)
   now resolve to Developer B's private IPs.
4. Developer A's app now sends telemetry to Developer B's Private
   Endpoint, but Developer A's App Insights resource is **not** scoped
   to Developer B's AMPLS.
5. If Developer B's AMPLS has **Private Only** ingestion access mode, the AMPLS
   rejects Developer A's telemetry intended for a public resource. 
   If Developer B's AMPLS has **Open** ingestion access mode, the
   telemetry might flow — but only if Developer A's App Insights
   resource has public ingestion enabled.

```
  Developer A's app (VNet-X)
  ┌─────────┐
  │ App A   │─── DNS: 10.2.0.7 ───▶ ⛔  Developer B's PE
  │         │    (should be 20.x.x.x)     │
  └─────────┘                              ▼
                                     AMPLS-B (PrivateOnly)
                                     Scoped resources:
                                       └── App Insights B ✅
                                       └── App Insights A ❌ ← NOT scoped
                                     ▼
                                     Result: HTTP 403 / telemetry silently dropped
```

**How to identify:** The script detects this as **"Ghost AMPLS: Private
IPs but Resource Not in AMPLS"** — DNS resolves to private IPs, but the
App Insights resource under test is not linked to any AMPLS.

**How to fix (choose one):**
1. **Add** Developer A's App Insights resource to Developer B's AMPLS
   scope (so AMPLS trusts it)
2. **Change** Developer B's AMPLS ingestion mode from `Private Only` to
   `Open` (so unscoped resources can still receive public traffic)
3. **Remove and re-add** Developer B's AMPLS + PE to isolate DNS impact
   to only the subnets that need it (requires careful planning)

### Scenario D — Competing AMPLS Across Teams

A variation of the Ghost AMPLS problem at enterprise scale:

1. Team Alpha has an AMPLS (`ampls-alpha`) with a PE on VNet-A,
   configured correctly. DNS resolves to `10.1.0.5`.
2. Team Beta creates a *second* AMPLS (`ampls-beta`) with a PE on
   VNet-B (which is peered to VNet-A). This updates the shared private
   DNS zone with new A records pointing to `10.2.0.10`.
3. **All apps on both VNets now resolve to `10.2.0.10`** — Team Beta's PE.
4. Team Alpha's apps break because their DNS no longer points to their
   PE (`10.1.0.5`).

```
  VNet-A (10.1.0.0/16)                  VNet-B (10.2.0.0/16)
  ┌──────────────────┐                  ┌──────────────────┐
  │ Team Alpha apps  │                  │ Team Beta apps   │
  │ DNS: 10.2.0.10 ❌│                 │ DNS: 10.2.0.10 ✅│
  │ (should be       │                  │                  │
  │  10.1.0.5)       │                  │                  │
  └──────────────────┘                  └──────────────────┘
         │                                       │
    ── PEERED ──────────────────────────────── ──
         │                                       │
    PE-alpha: 10.1.0.5                     PE-beta: 10.2.0.10
    AMPLS-alpha                             AMPLS-beta
```

**Root cause:** A single Azure Private DNS zone (e.g.,
`privatelink.monitor.azure.com`) is shared across linked VNets. When
Team Beta's PE writes A records, those records override Team Alpha's.

**How to fix:**

| Option | Approach |
|--------|----------|
| **Consolidate** | Use a single AMPLS for both teams. Add both App Insights resources to it. One PE, one set of DNS records. |
| **Accept second AMPLS** | On each team's App Insights resource, add BOTH AMPLS resources (so either PE is trusted). |
| **Isolate DNS** | Use separate private DNS zones with VNet-specific links. This prevents cross-contamination but requires custom DNS architecture. |
| **Re-create PE** | Remove and re-create the PE for Team Alpha's AMPLS. This rewrites the DNS zone A records back to Team Alpha's IPs — but then Team Beta breaks. Only useful if you consolidate at the same time. |

### Additional Behavior: Multiple AMPLS Attachments (Why DNS Checks Only Succeed for One Network)

When an Application Insights resource is linked to **two or more AMPLS resources**, it is effectively reachable from **multiple private networks**. The diagnostic script enumerates *all* AMPLS resources attached to the App Insights instance so it can validate DNS resolution for each one.

However, the script itself runs from **one specific network** — the network where the you execute it. Because private DNS resolution is always scoped to the caller’s network, the results will look like this:

- For the AMPLS resource associated with **your current VNet**, all ingestion and query endpoint hostnames resolve to the expected private IPs.
- For **every other AMPLS resource** attached to the same App Insights instance, DNS resolution will *not* match the expected private IPs. Endpoints may resolve to public IPs or fail to resolve entirely.

This behavior is **expected**. DNS validation can only reflect the network the script is running from; it cannot simulate DNS behavior from other private networks.

**How to interpret:**  
If you see one AMPLS showing correct private IP resolution and the others showing mismatches, this does *not* indicate a misconfiguration. It simply means the App Insights resource is reachable from multiple private networks, but the script is observing DNS from only one of them.

---

## How DNS Works in AMPLS

### The CNAME Chain

When a Private Endpoint is created for an AMPLS, Azure sets up a CNAME
chain in public DNS that redirects resolution to a `privatelink.*` zone:

```
  {region}.in.applicationinsights.azure.com
    CNAME → {region}.in.applicationinsights.azure.com.privatelink.monitor.azure.com
              │
              ├── If private DNS zone exists and is linked to VNet:
              │     A record → 10.1.0.5  (private endpoint IP)
              │
              └── If NO private DNS zone exists:
                    Falls through to public resolution → 20.42.x.x
```

**Azure Monitor domains that get CNAME-redirected:**

| Domain | Purpose |
|--------|---------|
| `*.in.applicationinsights.azure.com` | Regional ingestion |
| `*.livediagnostics.monitor.azure.com` | Live Metrics |
| `*.applicationinsights.azure.com` | App Insights services |
| `*.monitor.azure.com` | Azure Monitor services |
| `*.ods.opinsights.azure.com` | Log Analytics data collection |
| `*.oms.opinsights.azure.com` | Log Analytics management |

All redirect to `privatelink.monitor.azure.com` (or the gov/china
equivalents).

### Private DNS Zones

When you create a Private Endpoint for an AMPLS, Azure creates (or
updates) the following private DNS zone:

```
  privatelink.monitor.azure.com     (Public cloud)
  privatelink.monitor.azure.us      (Azure Government)
  privatelink.monitor.azure.cn      (Azure China / 21Vianet)
```

Inside that zone, Azure creates A records for every Azure Monitor
endpoint FQDN that the AMPLS needs to route privately. A single AMPLS
can generate **dozens** of A records.

**Critical requirement:** The private DNS zone must be **linked** to
every VNet that should resolve those FQDNs to private IPs. If the link
is missing, DNS falls through to public resolution and the private
endpoint is bypassed.

### What "VNet-wide Impact" Really Means

A private DNS zone linked to a VNet affects **every resource on that
VNet** — not just the subnet where the Private Endpoint lives. This
includes:

- All VMs on any subnet
- All App Services with VNet integration
- All Container Apps on the VNet
- All AKS nodes on the VNet
- All Azure Functions with VNet integration

There is no way to scope private DNS resolution to a single subnet.
If the DNS zone is linked to the VNet, every resource on that VNet
gets the private IP when resolving Azure Monitor endpoints.

This is why a single AMPLS + PE deployment can break telemetry for
every application on the VNet that is not scoped to that AMPLS.

### The Peered Network Problem

VNet peering shares DNS resolution. If VNet-A is peered with VNet-B,
and VNet-B has a private DNS zone linked, then resources on VNet-A
*may also* resolve to the private IPs — depending on the DNS
configuration:

| DNS Setup | Cross-VNet Impact |
|-----------|-------------------|
| **Azure-provided DNS** on both VNets + private DNS zone linked to both | Both VNets resolve to private IPs |
| **Custom DNS** on VNet-A forwarding to Azure DNS | VNet-A resolves to private IPs if the zone is linked to VNet-A |
| **Custom DNS** on VNet-A NOT forwarding to Azure DNS | VNet-A resolves to public IPs (bypasses private DNS zone) |
| **Private DNS zone** linked only to VNet-B (not VNet-A) | VNet-A resolves to public IPs |

The script cannot detect peered networks directly, but it *can* detect
the symptom: DNS resolving to private IPs that do not match the AMPLS
private endpoints linked to the App Insights resource under test.

---

## Access Modes Explained

### Open vs Private Only

Access modes are set on the **AMPLS resource**, not on the App Insights
resource. They control what clients on the AMPLS-linked VNet can reach via outbound connections.

```
                                  ┌──────────────────────────────────────┐
                                  │  AMPLS Access Mode: OPEN             │
                                  │                                      │
  Client on VNet ──── PE ───────▶│  ✅ Scoped resources (in this AMPLS) │
                                  │  ✅ Unscoped resources (public)      │
                                  └──────────────────────────────────────┘

                                  ┌──────────────────────────────────────┐
                                  │  AMPLS Access Mode: PRIVATE ONLY     │
                                  │                                      │
  Client on VNet ──── PE ───────▶│  ✅ Scoped resources (in this AMPLS) │
                                  │  ❌ Unscoped resources (BLOCKED)     │
                                  └──────────────────────────────────────┘
```

**"Open" is the safer default.** It allows the private path for scoped
resources while still permitting public fallback for everything else.

**"Private Only" is the secure choice.** It ensures no Azure Monitor
traffic leaves the VNet over the public internet — but it also means
every Azure Monitor resource the VNet needs MUST be added to the AMPLS.

### How Access Modes Interact with Network Isolation

The App Insights resource's Network Isolation settings and the AMPLS
access modes are **independent controls that both must allow the traffic.**

| App Insights Network Isolation | AMPLS Ingestion Mode | Client on VNet | Client on Public | 
|-------------------------------|---------------------|----------------|-----------------|
| Enabled (all networks) | Open | ✅ Private path | ✅ Public path |
| Enabled (all networks) | Private Only | ✅ If scoped to AMPLS | ✅ Public path (bypasses AMPLS) |
| Restricted (private only) | Open | ✅ Private path | ❌ 403 |
| Restricted (private only) | Private Only | ✅ If scoped to AMPLS | ❌ 403 |

**The subtlety:** A public client accessing an App Insights resource
with "Enabled from all networks" is not affected by any AMPLS access
mode. Access modes only govern traffic flowing *through* the AMPLS
Private Endpoint. A public client goes around the AMPLS entirely.

### Common Access Mode Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Set Private Only but forgot to scope a resource to the AMPLS | That resource returns 403 or is unreachable from the VNet | Add the resource to the AMPLS scope |
| Set Private Only for ingestion but Open for query (or vice versa) | Telemetry flows but Portal shows empty charts (or charts work but telemetry is blocked) | Align both modes to the same setting |
| Assumed Open mode = no security | Open mode still routes traffic privately for scoped resources; it just does not *block* public resources | Understand that Open is "allow all" not "disable AMPLS" |
| Changed to Private Only without coordinating with other teams on the VNet | Other teams' Azure Monitor traffic gets blocked | Communicate with VNet stakeholders before changing modes |

---

## Network Isolation on the App Insights Resource

The App Insights resource has its own inbound network controls,
independent from the AMPLS:

**Portal path:** App Insights → Configure → Network Isolation

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Network Isolation Settings                                         │
  │                                                                     │
  │  Accept data ingestion from:                                        │
  │    (●) All networks                    ← public + private OK        │
  │    ( ) Only from private link scope    ← AMPLS required             │
  │                                                                     │
  │  Accept queries from:                                               │
  │    (●) All networks                    ← Portal works everywhere    │
  │    ( ) Only from private link scope    ← Portal needs private path  │
  │                                                                     │
  │  Private endpoint connections:                                      │
  │    ├── ampls-prod    (Approved)                                     │
  │    └── ampls-staging (Approved)                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

**The linked AMPLS list here is how you answer Step 2.** Any AMPLS shown
in this list represents a trusted private network.

When "Restricted public inbound..." is selected for ingestion:
- Apps MUST send telemetry through a Private Endpoint connected to one
  of the linked AMPLS resources
- Public API calls receive HTTP 403
- The SDK error message is typically:
  `"Access denied. The ingestion API blocked this request."`

---

## What the Script Checks

The script automates the four-step troubleshooting framework described
above. Here is exactly what it does and what to look for in the output.

### Automated AMPLS Discovery

When Azure checks are enabled (Az modules available, user consents), the
script:

1. **Finds the App Insights resource** via Resource Graph query (by iKey)
2. **Reads network isolation settings** from the ARM properties
   (`publicNetworkAccessForIngestion`, `publicNetworkAccessForQuery`)
3. **Extracts AMPLS links** from the resource's
   `PrivateLinkScopedResources` array
4. **Fetches each AMPLS resource** via ARM GET to read access modes
5. **Finds Private Endpoints** for each AMPLS via Resource Graph
6. **Retrieves DNS/IP configurations** from the PE's
   `customDnsConfigurations` (or falls back to reading the PE's NIC)

All operations are read-only ARM GETs and Resource Graph queries.

### IP Comparison Table

For each AMPLS Private Endpoint, the script builds a table comparing
**expected** IPs (from Azure) against **actual** IPs (from DNS on this
machine):

```
  Endpoint (FQDN)                                    Expected (AMPLS)   Actual (DNS)        Match?
  -------------------------------------------------- ------------------ ------------------  --------
  {region}.in.applicationinsights.azure.com            10.1.0.5           10.1.0.5           MATCH
  {region}.livediagnostics.monitor.azure.com           10.1.0.6           10.1.0.6           MATCH
  rt.services.visualstudio.com                         10.1.0.7           20.42.12.34        MISMATCH
```

**MATCH** means DNS is correctly routing to the AMPLS private endpoint.
**MISMATCH** means DNS is returning a different IP — either a public IP
or another private endpoint's IP.

### Network Access Assessment

After comparing IPs, the script combines all three configuration layers
into a single verdict:

```
  YOUR CONFIGURATION:

    App Insights (contoso-prod-ai):
      Ingestion access:  Enabled from all networks
      Query access:      Disabled (private only)

    AMPLS (ampls-prod):
      Ingestion mode:    Open (VNet clients can reach scoped + public resources)
      Query mode:        PrivateOnly (VNet clients can only query scoped resources)

    This machine:
      Ingestion endpoint: westus2.in.applicationinsights.azure.com
      Resolved to:        10.1.0.5
      Network position:   Private (DNS matches AMPLS private endpoint)

  FROM THIS MACHINE:

    Ingestion (sending telemetry TO App Insights):
    [✓] ALLOWED
    On AMPLS-connected private network. DNS matches private endpoint.

    Query (reading data FROM App Insights, e.g. Azure Portal, API):
    [✓] ALLOWED
    On AMPLS-connected private network. Queries flow through private link.
```

If either verdict is **BLOCKED**, the script adds a BLOCKING or WARNING
diagnosis with specific fix instructions.

### Ghost AMPLS Detection

The script specifically detects the scenario where DNS resolves to
private IPs but the App Insights resource is not linked to any AMPLS:

```
  WARNING: DNS resolved some endpoints to PRIVATE IPs in Step 3,
  but this App Insights resource is NOT linked to any AMPLS.
  This means another AMPLS on this VNet is overriding DNS for Azure Monitor endpoints.
  Telemetry may be routing to the wrong private endpoint and getting rejected.

  ACTION: Find the AMPLS that owns the private endpoint on this VNet and either:
    (a) Add this App Insights resource to that AMPLS scope, or
    (b) Set the AMPLS ingestion access mode to 'Open' to allow public fallback
```

This maps directly to [Scenario C](#scenario-c--ghost-ampls-the-somebody-else-added-ampls-problem).

### Ghost AMPLS Reverse Lookup

When the script detects a ghost AMPLS scenario (private IPs but resource not linked to
any AMPLS) or an ingestion endpoint IP mismatch within a linked AMPLS, it automatically
performs a **reverse IP lookup** to identify the AMPLS resource responsible:

1. **IP → NIC**: Azure Resource Graph query finds the network interface with the private IP.
2. **NIC → Private Endpoint**: Second ARG query traces the NIC to its parent private endpoint.
3. **PE → AMPLS**: ARM REST call reads the private endpoint's connections to find the
   linked `Microsoft.Insights/privateLinkScopes` resource and its access modes.

If found, the script displays the AMPLS name, resource group, subscription, private
endpoint name, and access modes — giving you immediate visibility into which AMPLS is
overriding your DNS.

You can also trigger this lookup manually for any private IP observed during script execution. For example, if DNS resolution returns an unexpected private IP for the Live Metrics endpoint, you can use the lookup to identify which AMPLS and Private Endpoint are responsible:

```powershell
# PowerShell
.\Test-AppInsightsTelemetryFlow.ps1 -ConnectionString "..." -LookupAmplsIp "10.0.1.5"
```

```bash
# Bash
./test-appinsights-telemetry-flow.sh --connection-string "..." --lookup-ampls-ip "10.0.1.5"
```

The supplied IP must be a private (RFC1918) address that was resolved during the
current script execution. This prevents probing arbitrary private IPs.

### Manual Mode (-AmplsExpectedIps)

If you cannot use Azure login (e.g., running from a Kudu console where
`Connect-AzAccount` is unavailable), you can provide the expected AMPLS
IPs manually:

```powershell
.\Test-AppInsightsTelemetryFlow.ps1 `
    -ConnectionString "InstrumentationKey=..." `
    -AmplsExpectedIps @{
        "{region}.in.applicationinsights.azure.com" = "10.1.0.5"
        "{region}.livediagnostics.monitor.azure.com" = "10.1.0.6"
    }
```

Copy the expected FQDNs and IPs from:
**Azure Portal → AMPLS → Private Endpoint → DNS Configuration**

The script runs the same DNS comparison table but skips the Azure
discovery steps.

---

## DNS Mismatch Troubleshooting Checklist

When the script reports DNS mismatches, work through this checklist:

| # | Check | How | What to Look For |
|---|-------|-----|------------------|
| 1 | **Private DNS zone exists** | Portal → Private DNS zones → search for `privatelink.monitor.azure.com` | Zone must exist in the same subscription or a connected subscription |
| 2 | **A records present** | Open the zone → check for A records matching the mismatched FQDNs | Each FQDN from the comparison table should have an A record pointing to the PE's IP |
| 3 | **Zone linked to VNet** | Zone → Virtual network links | The VNet where the client runs must be listed and show status "Completed" |
| 4 | **Custom DNS forwarding** | If using custom DNS server (not Azure-provided): check conditional forwarder | Must forward `monitor.azure.com` queries to Azure DNS (`168.63.129.16`) |
| 5 | **Stale DNS cache** | Flush on the client machine | `ipconfig /flushdns` (Windows) or restart DNS resolver (Linux) |
| 6 | **A records stale** | Compare A record IPs in the zone to the PE's actual NIC IP | If they differ, the AMPLS may have been re-created without updating DNS. Remove and re-add the Azure Monitor resource in the AMPLS to force a refresh. |
| 7 | **Multiple PEs updating the same zone** | Check if other PEs in other VNets are linked to the same DNS zone | Another PE may have overwritten the A records ([Scenario D](#scenario-d--competing-ampls-across-teams)) |

---

## End-to-End Diagnostic Walkthrough

Here is the complete sequence the script follows for an AMPLS-enabled
resource, mapped to the troubleshooting framework:

```
  Phase 1: Environment Detection
    └─ Detect Azure host type, capture machine identity
  
  Phase 2: Connection String Parsing
    └─ Extract iKey, regional ingestion endpoint, live endpoint
  
  Phase 3: DNS Resolution  ← Framework Step 4 data collection
    └─ Resolve all endpoints
    └─ Flag any private IPs (sets hasAmplsSignals)
    └─ Report "MIXED public/private" if some are private, some public

  Phase 4: TCP Connectivity
    └─ Verify port 443 reachable for each endpoint

  Phase 5: TLS Handshake
    └─ Verify TLS negotiation, certificate chain

  Phase 6: AMPLS Validation  ← Framework Steps 1, 2, 3
    └─ Consent gate (Azure resource checks)
    └─ Login to Azure (Connect-AzAccount)
    └─ Find App Insights resource (Resource Graph)
    └─ Read network isolation settings (Step 1)
    └─ Find linked AMPLS resources (Step 2)
    └─ Read access modes for each AMPLS (Step 3)
    └─ Find Private Endpoints for each AMPLS
    └─ Retrieve expected IPs from PE DNS configs
    └─ Compare expected vs actual IPs (Step 4 validation)
    └─ Auto-trigger ghost AMPLS reverse lookup if ingestion IP mismatches
    └─ NETWORK ACCESS ASSESSMENT (combine all layers into verdict)

  Phase 7: Known Issues
    └─ Local auth, daily cap, workspace health, etc.

  Phase 8: Ingestion Test (skipped if blocked by assessment)
    └─ POST one availability record

  Phase 9: E2E Verification (skipped if ingestion blocked/skipped)
    └─ KQL query to confirm record arrived

  Phase 10: Diagnosis Summary
    └─ Report all findings in priority order
```

Notice that the AMPLS assessment comes *before* the ingestion test. If
the assessment determines ingestion is BLOCKED, the script skips the
ingestion test entirely — there is no point sending a record that will
be rejected.

---

## Multi-Cloud AMPLS

AMPLS works across Azure Public, Azure Government, and Azure China. The
script adapts automatically based on the connection string endpoint
domain:

| Cloud | Ingestion Domain | Private DNS Zone |
|-------|-----------------|------------------|
| Public | `*.in.applicationinsights.azure.com` | `privatelink.monitor.azure.com` |
| Government | `*.in.applicationinsights.azure.us` | `privatelink.monitor.azure.us` |
| China | `*.in.applicationinsights.azure.cn` | `privatelink.monitor.azure.cn` |

The same troubleshooting framework applies regardless of cloud — only
the domain suffixes change.

---

## Further Reading

**Microsoft documentation:**
- [Azure Monitor Private Link overview](https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security)
- [Design your Private Link setup](https://learn.microsoft.com/azure/azure-monitor/logs/private-link-design)
- [Configure Private Link](https://learn.microsoft.com/azure/azure-monitor/logs/private-link-configure)

**Other docs in this repo:**
- [architecture.md](architecture.md) — Telemetry flow overview, including
  public vs private path diagrams
- [diagnostic-flow.md](diagnostic-flow.md) — Complete phase-by-phase
  walkthrough including AMPLS skip logic
- [interpreting-results.md](interpreting-results.md) — Finding-by-finding
  reference for Ghost AMPLS, DNS mismatches, and access mode findings
- [security-model.md](security-model.md) — The script's read-only guarantees
  and consent model
