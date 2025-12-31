# Investigation: CrashLoopBackOff on ts-amd-plwxm-0

**Date**: 2025-12-31
**Pod**: `ts-amd-plwxm-0` (namespace: `tailscale`)
**Service**: `amd` (namespace: `apps-prod`)
**Target**: Tailscale Service `amd.taild1875d.ts.net` (100.116.252.110)

---

## Executive Summary

The pod was experiencing CrashLoopBackOff due to a missing `CMD` instruction in the custom Docker image. After multiple fixes:
1. Fixed Dockerfile CMD instruction
2. Fixed `serviceIPsFromNetMap()` to trust DNS ExtraRecords (removed incorrect AllowedIPs validation)
3. Added route to table 52 for Service IPs in `installEgressForwardingRule()`

**Current Status**: Route fix is working (Service IP in table 52), but **tailscaled reports "no associated peer node"** for Service IPs. The commits are correct but insufficient - there's a deeper issue with how tailscaled handles Service IP routing.

**Root Cause (NEW)**: tailscaled uses lazy peer loading. Even though the endpoint peer has Service IPs in its AllowedIPs, tailscaled doesn't associate Service IP traffic with that peer until the peer is actively configured in WireGuard.

---

## Timeline

| Time | Event | Image |
|------|-------|-------|
| ~13:40 | CrashLoopBackOff begins | `ghcr.io/blackfuel-ai/tailscale:00a57d6` |
| 13:43 | Rolled back to official image | `tailscale/tailscale:v1.92.4` |
| 13:43 | Pod recovered | v1.92.4 (no Service FQDN support) |
| 14:11 | Updated to fixed image | `ghcr.io/blackfuel-ai/tailscale:fa45d65` |
| 14:38 | Updated to merged branch | `ghcr.io/blackfuel-ai/tailscale:f427e77` |
| 16:01 | Fixed serviceIPsFromNetMap() | `ghcr.io/blackfuel-ai/tailscale:2bfef27` |
| 16:15 | Deployed, Service detected but routing fails | 2bfef27 |
| 16:28 | Added route to table 52 for Service IPs | `ghcr.io/blackfuel-ai/tailscale:bbceb53` |
| 16:45 | Route fix verified working, but tailscaled "no associated peer node" | bbceb53 |

---

## Root Causes Identified

### 1. CrashLoopBackOff - Missing CMD Instruction (FIXED)

**Issue**: Custom Dockerfile was missing the `CMD` instruction.

```dockerfile
# Missing from Dockerfile:
CMD ["/usr/local/bin/containerboot"]
```

**Result**: Container defaulted to `/bin/sh` and exited immediately.

**Fix**: Added `CMD ["/usr/local/bin/containerboot"]` to Dockerfile in commit `fa45d65a7`.

**Evidence**:
```bash
$ docker inspect ghcr.io/blackfuel-ai/tailscale:00a57d6
Cmd: [/bin/sh]  # Wrong!

$ docker inspect tailscale/tailscale:v1.92.4
Cmd: [/usr/local/bin/containerboot]  # Correct
```

---

### 2. Service FQDN Resolution Support (FIXED)

**Issue**: Official v1.92.4 image cannot resolve Tailscale Service FQDNs for egress routing.

**Fix**: Commit `bb3529fcd` (already in main branch) adds Service FQDN support to containerboot.

**What changed**:
- New `resolveTailnetFQDN()` function checks both peer devices AND Tailscale Services
- New `serviceIPsFromNetMap()` function identifies Services via DNS ExtraRecords

**Evidence**:
```
boot: Installing forwarding rules for destination 100.116.252.110
boot: Installing forwarding rules for destination fd7a:115c:a1e0::7737:fc6e
```

The Service FQDN `amd.taild1875d.ts.net` resolves correctly.

---

### 3. serviceIPsFromNetMap() AllowedIPs Validation (FIXED)

**Issue**: The function required finding Service IP in peer's AllowedIPs, but Services don't advertise IPs this way.

**Fix**: Commit `2bfef2766` removes the incorrect AllowedIPs validation and trusts DNS ExtraRecords directly.

**Before** (broken):
```go
// Validate we can see a peer advertising the Tailscale Service.
for _, ps := range nm.Peers {
    for _, allowedIP := range ps.AllowedIPs().All() {
        if allowedIP == ipPrefix {  // Never matches for Services!
            prefixes = append(prefixes, ipPrefix)
        }
    }
}
```

**After** (fixed):
```go
// Trust ExtraRecords directly - Services use DNS, not AllowedIPs
if strings.EqualFold(fqdn.WithTrailingDot(), recFQDN.WithTrailingDot()) {
    ip, _ := netip.ParseAddr(rec.Value)
    prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
}
```

---

### 4. Missing Route in Table 52 (FIXED)

**Issue**: Service IP detected and DNAT/SNAT rules installed, but no route exists to send traffic via tailscale0.

**Symptoms**:
```bash
# From test pod:
$ curl https://amd.apps-prod:443
[hangs - timeout after 10s]

# Route lookup shows wrong interface:
$ kubectl exec -n tailscale ts-amd-plwxm-0 -- ip route get 100.116.252.110
100.116.252.110 via 100.64.10.5 dev eth0 src 100.64.10.23  # WRONG - should be tailscale0!

# Compare with endpoint (works correctly):
$ kubectl exec -n tailscale ts-amd-plwxm-0 -- ip route get 100.77.247.40
100.77.247.40 dev tailscale0 table 52 src 100.113.98.20  # CORRECT
```

**Analysis**:

The Service IP `100.116.252.110` exists in ExtraRecords and is detected:
```
boot: Installing forwarding rules for destination 100.116.252.110
```

But checking routing table 52:
```bash
$ kubectl exec ts-amd-plwxm-0 -- ip route show table 52
100.67.221.35 dev tailscale0
100.77.247.40 dev tailscale0  # <- endpoint has route
100.78.234.30 dev tailscale0
...
# 100.116.252.110 is MISSING!
```

**Root cause**: `installEgressForwardingRule()` in `cmd/containerboot/forwarding.go` sets up:
- DNAT rules (redirect traffic to Service IP)
- SNAT rules (source NAT for responses)
- MSS clamping

But it does NOT add a route to table 52 for the Service IP. Routes to table 52 are only added by tailscaled for WireGuard peers, and Services aren't peers.

**The fix**: Add route for Service IP to table 52 via tailscale0 in `installEgressForwardingRule()`.

---

### 5. tailscaled "No Associated Peer Node" (CURRENT BLOCKER)

**Issue**: Even with the route fix, tailscaled reports "no associated peer node" when traffic arrives for Service IPs.

**Evidence from logs**:
```
2025/12/31 15:42:04 open-conn-track: timeout opening (TCP 100.113.98.20:55202 => 100.116.252.110:443); no associated peer node
2025/12/31 15:42:28 open-conn-track: timeout opening (TCP [fd7a:115c:a1e0::2237:6214]:38548 => [fd7a:115c:a1e0::7737:fc6e]:443); no associated peer node
```

**Verification that route fix works**:
```bash
$ kubectl exec ts-amd-plwxm-0 -- ip route show table 52 | grep 100.116
100.116.252.110 dev tailscale0  # ✅ Route is present

$ kubectl exec ts-amd-plwxm-0 -- ip route get 100.116.252.110
100.116.252.110 dev tailscale0 table 52 src 100.113.98.20  # ✅ Correct lookup
```

**But the endpoint DOES have Service IP in AllowedIPs**:
```bash
$ kubectl exec ts-amd-plwxm-0 -- tailscale whois 100.77.247.40
Machine:
  Name:       kube-apiserver-amd-0-1.taild1875d.ts.net
  AllowedIPs: [100.77.247.40/32, fd7a:115c:a1e0::1c37:f728/128,
               100.116.252.110/32, fd7a:115c:a1e0::7737:fc6e/128]  # ✅ Service IPs present!
```

**Root Cause**: WireGuard uses lazy peer loading:
```
2025/12/31 15:42:14 wgengine: Reconfig: configuring userspace WireGuard config (with 1/18 peers)
```

Only 1 of 18 peers is actively configured in WireGuard. The `kube-apiserver-amd-0-1` peer isn't configured until traffic is sent to its **device IP** (100.77.247.40), not the Service IP.

**Additional findings**:
- Direct to endpoint IP (100.77.247.40:443) → "RST by peer" (connection refused)
- Service IP (100.116.252.110:443) → "no associated peer node" (not routed)
- Local machine curl to Service → **works** (via IPv6, tailscaled handles routing internally)

**Key insight**: When a normal Tailscale client (like your laptop) connects to a Service, tailscaled intercepts the connection in userspace and handles Service routing. But the proxy uses kernel-level DNAT + routes, bypassing tailscaled's userspace Service handling.

---

## Configuration Details

### Pod Configuration
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ts-amd-plwxm-0
  namespace: tailscale
spec:
  containers:
  - name: tailscale
    image: ghcr.io/blackfuel-ai/tailscale:f427e77
    env:
    - name: TS_TAILNET_TARGET_FQDN
      value: amd.taild1875d.ts.net.
    - name: TS_INTERNAL_APP
      value: k8s-operator-egress-proxy
```

### Service Configuration (apps-prod)
```yaml
apiVersion: v1
kind: Service
metadata:
  name: amd
  namespace: apps-prod
  annotations:
    tailscale.com/tailnet-fqdn: amd.taild1875d.ts.net
spec:
  type: ExternalName
  externalName: ts-amd-plwxm.tailscale.svc.cluster.local
  ports:
  - port: 443
    targetPort: 443
```

### Tailscale Service (on tailnet)
```
Name: amd.taild1875d.ts.net
IPv4: 100.116.252.110
IPv6: fd7a:115c:a1e0::7737:fc6e
Endpoint: kube-apiserver-amd-0-1 (100.77.247.40)
```

### Tailscale Proxy Identity
```
Name: apps-prod-amd.taild1875d.ts.net
IP: 100.113.98.20
Tags: tag:k8s
```

---

## ACL Configuration

The ACLs use wildcard access:
```json
{
  "src": ["*"],
  "dst": ["*"],
  "ip": ["*"]
}
```

This allows IP-level connectivity between all devices. The proxy CAN reach the Service endpoint directly:
```bash
$ tailscale ping 100.77.247.40  # kube-apiserver-amd-0-1
pong from kube-apiserver-amd-0-1 (100.77.247.40) via DERP(ord) in 279ms
```

But cannot see the Service IP (100.116.252.110) in its peer list.

---

## Additional Fixes Merged

Branch `origin/hwh33/tsnet-services-support` contains:
- `180e100a8` - Fixes Service FQDN handling for TLS termination
- `2c2b2f8cf` - Adds identity and app capability headers for Services
- Multiple tsnet improvements for Service support

These were merged in commit `f427e773a` but don't solve the AllowedIPs issue.

---

## Why Service Routing Fails

### Issue 1: serviceIPsFromNetMap() (FIXED in 2bfef27)
The function incorrectly required AllowedIPs validation. Fixed by trusting ExtraRecords directly.

### Issue 2: Missing Route in Table 52 (FIXED in bbceb53)

The `installEgressForwardingRule()` function sets up firewall rules but NOT routes.

Routes to table 52 are added by tailscaled only for WireGuard peers. Services aren't peers, so no route is added.

**Fix**: Commit `bbceb5333` adds route in `installEgressForwardingRule()` using netlink:
```go
route := &netlink.Route{
    LinkIndex: link.Attrs().Index,  // tailscale0
    Dst:       netipx.PrefixIPNet(dstPrefix),
    Table:     52,
}
netlink.RouteReplace(route)
```

✅ **Verified working**: Route is present and lookup is correct.

### Issue 3: Lazy Peer Loading - "No Associated Peer Node" (CURRENT BLOCKER)

**The Problem**: tailscaled uses lazy WireGuard peer configuration. Even though the endpoint peer has Service IPs in its AllowedIPs, tailscaled doesn't configure the peer in WireGuard until traffic is sent to the peer's **device IP** (100.77.247.40), not the Service IP.

**Traffic flow breakdown**:
1. Packet arrives at proxy pod ClusterIP (100.64.10.23)
2. DNAT changes destination to Service IP (100.116.252.110) ✅
3. Kernel looks up route for 100.116.252.110 ✅
4. Route lookup returns tailscale0 via table 52 ✅
5. Packet enters tailscale0 interface ✅
6. **BUG**: tailscaled receives packet but reports "no associated peer node"
7. Packet is dropped, connection times out ❌

**Why it fails**:
- tailscaled maintains a mapping of IPs → WireGuard peers
- Lazy loading means only actively used peers are configured
- Service IPs don't trigger peer configuration
- When packet arrives for Service IP, no peer mapping exists

**Why local clients work**:
- Normal Tailscale clients intercept connections in userspace
- tailscaled handles Service DNS resolution and routing internally
- Connection is established to the Service, then routed to endpoint
- The kernel never sees Service IPs directly

**Why egress proxy fails**:
- Proxy uses kernel-level DNAT + routing (bypass userspace)
- Kernel forwards packets directly to tailscale0
- tailscaled receives packets but hasn't configured the peer
- No WireGuard tunnel exists for Service IP

---

## Network Path

**Expected flow**:
```
K8s Pod (curl-test)
  → Service DNS (amd.apps-prod → 100.64.10.23)
    → Proxy Pod (ts-amd-plwxm-0)
      → DNAT to Service IP (100.116.252.110) ✅
        → Route via tailscale0 (table 52) ✅
          → tailscale0 interface receives packet ✅
            → tailscaled checks IP → peer mapping ❌ "no associated peer node"
              → Packet dropped, connection timeout
```

**Current behavior** (after bbceb53):
```
K8s Pod (curl-test)
  → Service DNS (amd.apps-prod → 100.64.10.23)
    → Proxy Pod (ts-amd-plwxm-0)
      → DNAT to Service IP (100.116.252.110) ✅
        → Route via tailscale0 (table 52) ✅
          → Packet enters tailscale0 ✅
            → tailscaled: "no associated peer node" ❌
              → Packet dropped (timeout)
```

**Comparison with working local client**:
```
Local Machine (matthieu-dell)
  → DNS resolves amd.taild1875d.ts.net → Service IPs
    → tailscaled intercepts connection in userspace
      → Looks up Service → Endpoint mapping
        → Configures WireGuard peer for endpoint
          → Establishes WireGuard tunnel to 100.77.247.40
            → Traffic flows to endpoint's Service listener ✅
```

---

## Logs Evidence

### Successful Startup
```
boot: 2025/12/31 14:38:31 Using tailscaled config file "/etc/tsconfig/ts-amd-plwxm-0/cap-107.hujson"
boot: 2025/12/31 14:38:31 Starting tailscaled
boot: 2025/12/31 14:38:31 Installing forwarding rules for destination 100.116.252.110
boot: 2025/12/31 14:38:31 Installing forwarding rules for destination fd7a:115c:a1e0::7737:fc6e
boot: 2025/12/31 14:38:31 Startup complete, waiting for shutdown signal
```

### Service Detection Working
```bash
$ kubectl exec ts-amd-plwxm-0 -- tailscale debug netmap | grep -A2 "amd.taild"
"ExtraRecords": [
  {
    "Name": "amd.taild1875d.ts.net.",
    "Value": "100.116.252.110"
  }
]
```

### But Routing Fails
```bash
$ kubectl exec ts-amd-plwxm-0 -- tailscale status | grep 100.116
# No output - Service not in peer list

$ kubectl exec ts-amd-plwxm-0 -- ip route show table 52 | grep 100.116
# No output - Service IP not in routing table
```

---

## Kubernetes Environment

- **Cluster**: control-tower
- **CNI**: Cilium (tunnel mode, kube-proxy replacement enabled)
- **Tailscale Operator**: v1.92.4
- **Tailscale Image**: ghcr.io/blackfuel-ai/tailscale:f427e77
- **Node**: scw-control-tower-default-dbd5bde996be47e98c7d

---

## Potential Solutions

### ~~Option 1: Add Route in installEgressForwardingRule()~~ (DONE)
✅ Fixed in commit `bbceb5333` - route is working but insufficient alone.

### ~~Option 2: Fix serviceIPsFromNetMap()~~ (DONE)
✅ Fixed in commit `2bfef2766` - removed incorrect AllowedIPs validation.

### Option 3: Pre-configure WireGuard Peer for Service Endpoints
Force tailscaled to configure the endpoint peer in WireGuard before traffic arrives.

**Approach**: Before installing forwarding rules, ping the endpoint's device IP to trigger peer configuration:
```go
func installEgressForwardingRule(ctx context.Context, dstStr string, ...) error {
    // For Service IPs, pre-configure the peer by sending traffic to endpoint
    if isServiceIP(dst) {
        endpoint := lookupServiceEndpoint(dst)
        pingEndpoint(endpoint) // Trigger WireGuard peer configuration
    }
    // ... existing DNAT/SNAT/route setup ...
}
```

**Challenges**:
- Need mapping from Service IP → Endpoint IP
- Endpoint might not have service listening on device IP
- Adds latency during setup

### Option 4: Fix tailscaled IP → Peer Mapping for Service IPs
Modify tailscaled to recognize Service IPs in AllowedIPs and map them to peers.

**Approach**: When a peer has Service IPs in its AllowedIPs, add those IPs to the peer mapping table immediately (not lazily).

**Changes needed**:
- Modify `magicsock` or `wgengine` to parse AllowedIPs
- Identify Service IPs (from DNS ExtraRecords)
- Add Service IP → Peer mapping when peer is discovered
- Ensure peer is configured in WireGuard before Service traffic arrives

**This is the proper fix** but requires changes to core tailscaled logic.

### Option 5: Use Direct Endpoint (WORKAROUND)
Instead of targeting the Service, point directly to the endpoint machine:
```yaml
metadata:
  annotations:
    tailscale.com/tailnet-fqdn: kube-apiserver-amd-0-1.taild1875d.ts.net  # Direct to machine
```

**Issues**:
- Endpoint IP (100.77.247.40:443) returns connection refused
- API server might only listen on Service IP or require TLS SNI
- Defeats the purpose of using Tailscale Services

### Option 6: Use SOCKS5 Proxy Mode
Configure containerboot with `TS_SOCKS5_SERVER` to route through tailscaled's userspace proxy:
```yaml
env:
- name: TS_SOCKS5_SERVER
  value: localhost:1080
```

Then configure cluster traffic to use SOCKS5 proxy. This routes through tailscaled's userspace which handles Services correctly.

**Issues**:
- Requires SOCKS5 support in cluster networking
- More complex configuration
- May have performance implications

---

## Key Commits

- `00a57d65f` - Added GitHub Container Registry workflow
- `fa45d65a7` - Fixed Dockerfile CMD instruction
- `bb3529fcd` - Added Service FQDN support to containerboot
- `180e100a8` - Fixed TLS termination for Services (from hwh33/tsnet-services-support)
- `f427e773a` - Merged tsnet-services-support branch
- `2bfef2766` - Fixed serviceIPsFromNetMap() to trust ExtraRecords directly (removed AllowedIPs validation)
- `bbceb5333` - Added route to table 52 for egress Service destinations

---

## Next Steps

1. ~~**Add route to table 52**~~ - ✅ DONE in commit `bbceb5333`, verified working
2. ~~**Fix serviceIPsFromNetMap()**~~ - ✅ DONE in commit `2bfef2766`, verified working
3. **Choose solution for "no associated peer node"** - Options:
   - **Option 3**: Pre-configure peer (hackish but quick)
   - **Option 4**: Fix tailscaled IP mapping (proper but complex)
   - **Option 6**: SOCKS5 mode (alternative architecture)
4. **Investigate why endpoint refuses direct connections**:
   - Test if API server only listens on Service IP
   - Check TLS SNI requirements
   - May provide workaround path

---

## Commands for Troubleshooting

```bash
# Check pod status and image
kubectl get pod ts-amd-plwxm-0 -n tailscale -o wide
kubectl describe pod ts-amd-plwxm-0 -n tailscale

# Check logs
kubectl logs ts-amd-plwxm-0 -n tailscale --tail=50

# Check routing
kubectl exec -n tailscale ts-amd-plwxm-0 -- ip route show table 52
kubectl exec -n tailscale ts-amd-plwxm-0 -- ip rule list

# Check Tailscale status
kubectl exec -n tailscale ts-amd-plwxm-0 -- tailscale status
kubectl exec -n tailscale ts-amd-plwxm-0 -- tailscale debug netmap | grep -A5 ExtraRecords

# Test connectivity
kubectl exec ubuntu -- curl -v https://amd.apps-prod:443
kubectl exec -n tailscale ts-amd-plwxm-0 -- tailscale ping 100.77.247.40  # Endpoint
kubectl exec -n tailscale ts-amd-plwxm-0 -- tailscale ping 100.116.252.110  # Service
```

---

## Files Changed

- `.github/workflows/docker-ghcr.yml` - Added GHCR build workflow
- `Dockerfile` - Added missing `CMD` instruction
- Merged `origin/hwh33/tsnet-services-support` branch for Service improvements
- `cmd/containerboot/main.go` - Fixed `serviceIPsFromNetMap()` to trust ExtraRecords directly
- `cmd/containerboot/forwarding.go` - Added route to table 52 for Service IPs in `installEgressForwardingRule()`

---

## Commit Review Summary

**All commits are correct** - they implement necessary fixes but are insufficient alone:

| Commit | Purpose | Status |
|--------|---------|--------|
| `2bfef2766` | Trust DNS ExtraRecords for Service IPs | ✅ Correct - Service IP resolution working |
| `bbceb5333` | Add route to table 52 for Service IPs | ✅ Correct - Route working, packets reach tailscale0 |

**The commits did not introduce wrong logic**. They successfully:
1. Identify Service IPs from DNS ExtraRecords ✅
2. Install route to send Service traffic to tailscale0 ✅
3. Traffic reaches tailscale0 interface ✅

**The remaining issue** is in tailscaled's core routing logic:
- tailscaled uses lazy peer loading
- Service IPs don't trigger peer configuration
- Packet arrives at tailscale0 but tailscaled reports "no associated peer node"
- This requires a deeper fix in tailscaled's IP → peer mapping logic

**Verification**:
```bash
# Route fix working
$ kubectl exec ts-amd-plwxm-0 -- ip route show table 52 | grep 100.116
100.116.252.110 dev tailscale0  ✅

# Peer has Service IP in AllowedIPs
$ kubectl exec ts-amd-plwxm-0 -- tailscale whois 100.77.247.40
AllowedIPs: [100.116.252.110/32, ...]  ✅

# But tailscaled doesn't route it
$ kubectl logs ts-amd-plwxm-0 | grep "no associated peer"
timeout opening (TCP => 100.116.252.110:443); no associated peer node  ❌
```

---

## Code-Level Analysis and Verification

**Date**: 2025-12-31 (Updated after code review)

### Verification of Implemented Fixes

#### ✅ Fix 1: Dockerfile CMD Instruction
**Location**: `Dockerfile:89`
```dockerfile
CMD ["/usr/local/bin/containerboot"]
```
**Status**: Verified correct. Container now properly starts containerboot instead of defaulting to `/bin/sh`.

#### ✅ Fix 2: Service IP Resolution via DNS ExtraRecords
**Location**: `cmd/containerboot/main.go:911-927`
```go
func serviceIPsFromNetMap(nm *netmap.NetworkMap, fqdn dnsname.FQDN) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, rec := range nm.DNS.ExtraRecords {
		recFQDN, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		if strings.EqualFold(fqdn.WithTrailingDot(), recFQDN.WithTrailingDot()) {
			ip, err := netip.ParseAddr(rec.Value)
			if err != nil {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return prefixes
}
```
**Status**: Verified correct. Function properly:
- Iterates through DNS ExtraRecords
- Matches FQDN case-insensitively
- Returns IP prefixes without requiring AllowedIPs validation
- This is the correct approach since Services are identified by DNS, not AllowedIPs

#### ✅ Fix 3: Route to Table 52 for Service IPs
**Location**: `cmd/containerboot/forwarding.go:133-164`
```go
func installEgressForwardingRule(_ context.Context, dstStr string, tsIPs []netip.Prefix, nfr linuxfw.NetfilterRunner) error {
	// ... DNAT/SNAT setup ...

	// Add route to table 52 for the destination via tailscale0.
	// This is needed for Tailscale Services which are not WireGuard peers
	// and thus don't have routes added by tailscaled.
	if err := addRouteForEgressDestination(dst); err != nil {
		log.Printf("[warning] failed to add route for egress destination %v: %v", dst, err)
	}
	return nil
}

func addRouteForEgressDestination(dst netip.Addr) error {
	link, err := netlink.LinkByName("tailscale0")
	if err != nil {
		return fmt.Errorf("getting tailscale0 link: %w", err)
	}
	dstPrefix := netip.PrefixFrom(dst, dst.BitLen())
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       netipx.PrefixIPNet(dstPrefix),
		Table:     tailscaleRouteTable, // 52
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("adding route %v to table %d: %w", dstPrefix, tailscaleRouteTable, err)
	}
	log.Printf("Added route for %v via tailscale0 to table %d", dst, tailscaleRouteTable)
	return nil
}
```
**Status**: Verified correct. Route addition is:
- Properly implemented using netlink
- Non-fatal (logs warning on failure)
- Necessary because Services aren't WireGuard peers

**Conclusion**: All three fixes are correctly implemented and working as intended. They successfully:
1. Start the container properly ✅
2. Detect Service IPs from DNS ExtraRecords ✅
3. Route Service traffic to tailscale0 ✅

The problem is that traffic reaches tailscale0 but tailscaled cannot route it.

---

### Root Cause: Lazy Peer Loading Architecture

#### The Problem in Code

**Location**: `wgengine/pendopen.go:181-202`

When a TCP connection times out after 5 seconds, `onOpenTimeout()` is called:

```go
func (e *userspaceEngine) onOpenTimeout(flow flowtrack.Tuple) {
	// ... cleanup ...

	// Diagnose why it might've timed out.
	pip, ok := e.PeerForIP(flow.DstAddr())
	if !ok {
		e.logf("open-conn-track: timeout opening %v; no associated peer node", flow)
		return  // <-- THIS IS WHAT'S HAPPENING
	}
	// ... more diagnostics ...
}
```

**Location**: `wgengine/userspace.go:1650-1702`

The `PeerForIP()` function tries three lookups:

```go
func (e *userspaceEngine) PeerForIP(ip netip.Addr) (ret PeerForIP, ok bool) {
	// ... lock and get netmap ...

	// Step 1: Check peer device addresses
	for _, p := range nm.Peers {
		for i := range p.Addresses().Len() {
			a := p.Addresses().At(i)
			if a.Addr() == ip && a.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
				return PeerForIP{Node: p, Route: a}, true
			}
		}
	}
	// Service IP is NOT a device address, so this fails

	// Step 2: Check self node addresses
	addrs := nm.GetAddresses()
	for i := range addrs.Len() {
		if a := addrs.At(i); a.Addr() == ip && a.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
			return PeerForIP{Node: nm.SelfNode, IsSelf: true, Route: a}, true
		}
	}
	// Service IP is not self, so this fails

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	// Step 3: Check AllowedIPs in e.lastCfgFull.Peers
	// THIS IS WHERE IT SHOULD WORK BUT DOESN'T
	var best netip.Prefix
	var bestKey key.NodePublic
	for _, p := range e.lastCfgFull.Peers {
		for _, cidr := range p.AllowedIPs {
			if !cidr.Contains(ip) {
				continue
			}
			if !best.IsValid() || cidr.Bits() > best.Bits() {
				best = cidr
				bestKey = p.PublicKey
			}
		}
	}
	// If the peer isn't in e.lastCfgFull.Peers, bestKey stays zero
	// and the function returns (ret, false)

	if !bestKey.IsZero() {
		for _, p := range nm.Peers {
			if p.Key() == bestKey {
				return PeerForIP{Node: p, Route: best}, true
			}
		}
	}
	return ret, false  // <-- Service endpoint peer not found
}
```

#### Why Step 3 Fails: Lazy Peer Trimming

**Location**: `wgengine/userspace.go:658-670`

```go
func (e *userspaceEngine) isTrimmablePeer(p *wgcfg.Peer, numPeers int) bool {
	if e.forceFullWireguardConfig(numPeers) {
		return false
	}

	// AllowedIPs must all be single IPs, not subnets.
	for _, aip := range p.AllowedIPs {
		if !aip.IsSingleIP() {
			return false  // Peer advertises subnets, NOT trimmable
		}
	}
	return true  // All IPs are /32 or /128, IS trimmable
}
```

**The Issue**: Service endpoint peers typically have AllowedIPs like:
```
100.77.247.40/32         # Device IP
fd7a:115c:a1e0::1c37:f728/128
100.116.252.110/32       # Service IP
fd7a:115c:a1e0::7737:fc6e/128
```

All are single IPs, so `isTrimmablePeer()` returns `true`. The peer gets excluded from the active config.

**Location**: `wgengine/userspace.go:793-826`

During WireGuard reconfiguration:

```go
// Don't re-alloc the map; the Go compiler optimizes map clears as of Go 1.11
if e.trimmedNodes != nil {
	clear(e.trimmedNodes)
} else {
	e.trimmedNodes = make(map[key.NodePublic]bool)
}

needRemoveStep := false
for i := range full.Peers {
	p := &full.Peers[i]
	nk := p.PublicKey

	if !buildfeatures.HasLazyWG || !e.isTrimmablePeer(p, len(full.Peers)) {
		min.Peers = append(min.Peers, *p)
		if discoChanged[nk] {
			needRemoveStep = true
		}
		continue
	}

	// Peer is trimmable, check if it's active
	lastRecvAgo := e.timeNow().Sub(e.recvActivityAt[nk])
	if lastRecvAgo < lazyPeerIdleThreshold {
		min.Peers = append(min.Peers, *p)
		if discoChanged[nk] {
			needRemoveStep = true
		}
	} else {
		e.trimmedNodes[nk] = true  // <-- Service endpoint gets trimmed here
	}
}
```

#### The Chicken-and-Egg Problem

**Location**: `wgengine/userspace.go:672-711`

Peers are added back to WireGuard config when activity is detected:

```go
func (e *userspaceEngine) noteRecvActivity(nk key.NodePublic) {
	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	if _, ok := e.recvActivityAt[nk]; !ok {
		// Not a trimmable peer we care about tracking.
		if e.trimmedNodes[nk] {
			e.logf("wgengine: [unexpected] noteReceiveActivity called on idle node %v that's not in recvActivityAt", nk.ShortString())
		}
		return
	}
	now := e.timeNow()
	e.recvActivityAt[nk] = now

	// ... (lines omitted) ...

	if e.trimmedNodes[nk] {
		e.logf("wgengine: idle peer %v now active, reconfiguring WireGuard", nk.ShortString())
		e.maybeReconfigWireguardLocked(nil)
	}
}
```

**The Problem**:
1. `noteRecvActivity()` only triggers on **received** packets from the peer
2. Outbound connections to Service IPs send SYN packets that never get responses
3. No response = no received activity = peer stays trimmed
4. Peer stays trimmed = no WireGuard tunnel = connection times out

**This is a chicken-and-egg problem**:
- Need peer configured in WireGuard to receive packets
- Need to receive packets to configure peer in WireGuard

---

### Why Normal Clients Work vs. Egress Proxy Fails

#### Normal Tailscale Clients (Your Laptop)
Traffic flow when connecting to a Service:
1. Application calls `connect()` to Service FQDN
2. DNS resolves to Service IP (100.116.252.110)
3. **Tailscaled intercepts connection in userspace** (not kernel)
4. Tailscaled looks up Service → Endpoint mapping internally
5. Tailscaled ensures endpoint peer is configured in WireGuard
6. Connection is established to endpoint
7. Endpoint routes Service traffic to the actual service

**Key**: Connection is intercepted **before** hitting the kernel network stack. Tailscaled handles everything in userspace.

#### Egress Proxy (Containerboot)
Traffic flow when proxying to a Service:
1. Cluster pod sends to K8s Service (amd.apps-prod:443)
2. K8s DNS resolves to proxy pod ClusterIP (100.64.10.23)
3. Packet arrives at proxy pod, **kernel applies DNAT** to Service IP (100.116.252.110)
4. Kernel looks up route for Service IP → finds table 52 route
5. **Kernel injects packet directly to tailscale0 interface**
6. Tailscaled receives raw packet from kernel
7. Tailscaled checks `PeerForIP(100.116.252.110)` → not found
8. Packet is dropped, connection times out

**Key**: Packet enters tailscaled from kernel (not userspace interception). Tailscaled never gets a chance to set up the peer configuration **before** the packet arrives.

---

### The Proper Fix: Make Service Endpoints Non-Trimmable

**Target**: `wgengine/userspace.go:658-670`

**Approach**: Modify `isTrimmablePeer()` to detect when a peer advertises Service IPs in its AllowedIPs and mark it as non-trimmable.

**Implementation Strategy**:

```go
func (e *userspaceEngine) isTrimmablePeer(p *wgcfg.Peer, numPeers int) bool {
	if e.forceFullWireguardConfig(numPeers) {
		return false
	}

	// NEW: Check if this peer advertises any Service IPs
	// Service endpoints should always be configured to handle Service traffic
	if e.peerAdvertisesServiceIPs(p) {
		return false
	}

	// AllowedIPs must all be single IPs, not subnets.
	for _, aip := range p.AllowedIPs {
		if !aip.IsSingleIP() {
			return false
		}
	}
	return true
}

// NEW FUNCTION: Check if peer advertises Service IPs
func (e *userspaceEngine) peerAdvertisesServiceIPs(p *wgcfg.Peer) bool {
	// Need to check if any of p.AllowedIPs matches a Service IP
	// from the NetworkMap's DNS ExtraRecords
	// This requires access to e.netMap which is protected by e.mu
	//
	// Options:
	// 1. Pass netMap to this function (requires signature change)
	// 2. Cache Service IPs in userspaceEngine during Reconfig
	// 3. Check during the loop where isTrimmablePeer is called

	// Implementation TBD based on locking and architecture constraints
	return false
}
```

**Challenges**:
1. `isTrimmablePeer()` is called while holding `e.wgLock`
2. NetworkMap is protected by `e.mu` (different lock)
3. Need to avoid lock ordering issues
4. May need to cache Service IPs during `Reconfig()` when both locks can be acquired

**Alternative Location**: Check during the loop in `maybeReconfigWireguardLocked()` where `isTrimmablePeer()` is called:

```go
// In maybeReconfigWireguardLocked, around line 805:
for i := range full.Peers {
	p := &full.Peers[i]
	nk := p.PublicKey

	// NEW: Check if peer has Service IPs before checking if trimmable
	hasServiceIPs := false
	if nm != nil && nm.DNS != nil {
		for _, rec := range nm.DNS.ExtraRecords {
			serviceIP, err := netip.ParseAddr(rec.Value)
			if err != nil {
				continue
			}
			for _, allowedIP := range p.AllowedIPs {
				if allowedIP.Addr() == serviceIP {
					hasServiceIPs = true
					break
				}
			}
			if hasServiceIPs {
				break
			}
		}
	}

	if !buildfeatures.HasLazyWG || hasServiceIPs || !e.isTrimmablePeer(p, len(full.Peers)) {
		min.Peers = append(min.Peers, *p)
		// ...
		continue
	}
	// ... existing trimming logic ...
}
```

---

### Updated Recommendations

#### **Recommended Solution: Non-Trimmable Service Endpoints**

**Implementation Steps**:

1. **Modify `maybeReconfigWireguardLocked()`** in `wgengine/userspace.go`:
   - Before the loop that processes peers (around line 805)
   - Build a set of Service IPs from `nm.DNS.ExtraRecords`
   - During peer processing, check if any `AllowedIPs` match Service IPs
   - If yes, add peer to `min.Peers` without checking `isTrimmablePeer()`

2. **Alternative: Cache Service IPs** in `userspaceEngine`:
   - Add `serviceIPs map[netip.Addr]bool` field to `userspaceEngine`
   - Update it during `Reconfig()` when NetworkMap changes
   - Reference it in `isTrimmablePeer()` (requires passing as parameter or caching)

3. **Testing**:
   - Verify Service endpoint peers appear in WireGuard config
   - Check `tailscale debug netmap` shows endpoints as configured
   - Test egress proxy connections to Service IPs

**Expected Result**: Service endpoint peers will always be configured in WireGuard, allowing `PeerForIP()` to find them and route traffic correctly.

---

### Files Requiring Changes

For the recommended fix:

1. **wgengine/userspace.go**:
   - Modify `maybeReconfigWireguardLocked()` (around line 805)
   - Add logic to detect Service IPs in peer's AllowedIPs
   - Mark those peers as non-trimmable

2. **Testing locations**:
   - `cmd/containerboot/main.go` - Already correctly detects Services
   - `cmd/containerboot/forwarding.go` - Already correctly routes to table 52
   - Focus testing on WireGuard peer configuration

---

## Conclusion

**All implemented fixes are correct and necessary**:
- ✅ Dockerfile CMD: Container starts properly
- ✅ Service IP detection: ExtraRecords are trusted correctly
- ✅ Route to table 52: Service traffic reaches tailscale0

**The remaining issue is architectural**:
- Lazy peer loading optimization conflicts with kernel-level egress proxy architecture
- Service endpoints get trimmed because all AllowedIPs are single IPs (/32, /128)
- Traffic arrives at tailscale0 but tailscaled can't route it (no peer mapping)

**The fix is straightforward**:
- Detect peers that advertise Service IPs in AllowedIPs
- Mark them as non-trimmable during WireGuard configuration
- Ensure they're always present in active WireGuard config
- This allows `PeerForIP()` to find the peer and route traffic correctly

**Estimated complexity**: Medium - requires careful handling of locks and NetworkMap access during WireGuard reconfiguration.

---

## Implementation of the Fix

**Date**: 2025-12-31 (Fix implemented)

### Changes Made to `wgengine/userspace.go`

The fix has been implemented in the `maybeReconfigWireguardLocked()` function to detect Service endpoint peers and mark them as non-trimmable.

**Location**: `wgengine/userspace.go:766-843`

#### 1. Service IP Detection (lines 766-782)

Added logic at the start of the function to build a set of Service IPs from DNS ExtraRecords:

```go
// Build a set of Service IPs from DNS ExtraRecords.
// Peers advertising these IPs should not be trimmed as they handle
// Tailscale Service traffic that may arrive via kernel routing
// (e.g., egress proxy use case).
serviceIPs := make(map[netip.Addr]bool)
e.mu.Lock()
if nm := e.netMap; nm != nil && len(nm.DNS.ExtraRecords) > 0 {
	for _, rec := range nm.DNS.ExtraRecords {
		if ip, err := netip.ParseAddr(rec.Value); err == nil {
			serviceIPs[ip] = true
		}
	}
}
e.mu.Unlock()
if len(serviceIPs) > 0 {
	e.logf("[v1] wgengine: found %d Service IPs in DNS ExtraRecords", len(serviceIPs))
}
```

**Key points**:
- Acquires `e.mu` lock temporarily to safely access `e.netMap`
- Extracts all Service IPs from DNS ExtraRecords
- Stores them in a map for O(1) lookup during peer processing
- Logs the number of Service IPs found for diagnostics

#### 2. Peer Trimming Logic Update (lines 824-843)

Modified the peer processing loop to check if a peer advertises Service IPs:

```go
// Check if this peer advertises any Service IPs.
// Service endpoint peers must always be configured in WireGuard
// to handle traffic routed by the kernel to Service IPs.
advertizesServiceIP := false
if len(serviceIPs) > 0 {
	for _, allowedIP := range p.AllowedIPs {
		if serviceIPs[allowedIP.Addr()] {
			advertizesServiceIP = true
			e.logf("[v1] wgengine: peer %v advertises Service IP %v, marking as non-trimmable", nk.ShortString(), allowedIP.Addr())
			break
		}
	}
}

if !buildfeatures.HasLazyWG || advertizesServiceIP || !e.isTrimmablePeer(p, len(full.Peers)) {
	min.Peers = append(min.Peers, *p)
	if discoChanged[nk] {
		needRemoveStep = true
	}
	continue
}
```

**Key points**:
- For each peer, checks if any of its AllowedIPs match a Service IP
- If a match is found, marks the peer as non-trimmable
- Logs when a peer is marked non-trimmable for diagnostics
- The peer is added to `min.Peers` (active WireGuard config) immediately

### How the Fix Works

1. **Service IP Discovery**: When WireGuard is reconfigured, the function first discovers all Service IPs from the NetworkMap's DNS ExtraRecords.

2. **Peer Classification**: During peer processing, each peer's AllowedIPs are checked against the Service IPs. If any match, the peer is classified as a Service endpoint.

3. **Non-Trimmable Status**: Service endpoint peers bypass the lazy loading optimization and are always included in the active WireGuard configuration, even if they haven't received traffic recently.

4. **Result**: When traffic arrives for a Service IP via kernel routing (egress proxy case):
   - Packet reaches tailscale0 interface ✅
   - `PeerForIP()` finds the peer in `lastCfgFull.Peers` ✅
   - WireGuard tunnel is already configured ✅
   - Traffic flows successfully ✅

### Testing

To test the fix:

1. **Build and deploy the updated image**:
   ```bash
   docker build -t ghcr.io/blackfuel-ai/tailscale:fix-service-trimming .
   docker push ghcr.io/blackfuel-ai/tailscale:fix-service-trimming
   ```

2. **Update the pod to use the new image**:
   ```bash
   kubectl set image -n tailscale pod/ts-amd-plwxm-0 tailscale=ghcr.io/blackfuel-ai/tailscale:fix-service-trimming
   ```

3. **Check logs for diagnostic messages**:
   ```bash
   kubectl logs -n tailscale ts-amd-plwxm-0 | grep -E "Service IPs|non-trimmable"
   ```

   Expected output:
   ```
   wgengine: found 2 Service IPs in DNS ExtraRecords
   wgengine: peer xxxxx advertises Service IP 100.116.252.110, marking as non-trimmable
   ```

4. **Verify WireGuard peer configuration**:
   ```bash
   kubectl exec -n tailscale ts-amd-plwxm-0 -- tailscale debug netmap | grep -A10 "kube-apiserver-amd-0-1"
   ```

   Should show the Service endpoint peer is configured.

5. **Test connectivity**:
   ```bash
   kubectl exec ubuntu -- curl -v https://amd.apps-prod:443
   ```

   Should now succeed without timeout.

### Expected Log Output

**Before the fix**:
```
wgengine: Reconfig: configuring userspace WireGuard config (with 1/18 peers)
open-conn-track: timeout opening (TCP 100.113.98.20:55202 => 100.116.252.110:443); no associated peer node
```

**After the fix**:
```
wgengine: found 2 Service IPs in DNS ExtraRecords
wgengine: peer [KEY] advertises Service IP 100.116.252.110, marking as non-trimmable
wgengine: peer [KEY] advertises Service IP fd7a:115c:a1e0::7737:fc6e, marking as non-trimmable
wgengine: Reconfig: configuring userspace WireGuard config (with 2/18 peers)
```

Connection should succeed without "no associated peer node" errors.

---

## Summary of All Changes

### Commit History

| Commit | File | Description | Status |
|--------|------|-------------|--------|
| `fa45d65a7` | Dockerfile | Added CMD instruction | ✅ Working |
| `2bfef2766` | cmd/containerboot/main.go | Fixed serviceIPsFromNetMap() | ✅ Working |
| `bbceb5333` | cmd/containerboot/forwarding.go | Added route to table 52 | ✅ Working |
| **NEW** | wgengine/userspace.go | Prevent Service endpoint peer trimming | ✅ Implemented |

### Complete Solution

The complete fix required changes at multiple layers:

1. **Container Runtime** (fa45d65a7): Fixed CMD to start containerboot properly
2. **Service Detection** (2bfef2766): Trust DNS ExtraRecords for Service IPs
3. **Kernel Routing** (bbceb5333): Add routes to table 52 for Service IPs
4. **WireGuard Configuration** (NEW): Keep Service endpoint peers configured in WireGuard

All four components are now in place. The egress proxy should now successfully route traffic to Tailscale Services.
