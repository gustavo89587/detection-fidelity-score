# dfs_core/features/cyber_wall.py
"""
DFS Cyber Wall — Active Defense IPS with Autonomous Response

This extractor implements the "DFS Muro Cibernético" concept:
an aggressive active defense layer that uses DFS scoring to decide
between MONITOR → QUARANTINE → KILL responses in real-time.

The key insight: DFS's multiplicative model naturally solves the
"auto-DoS" problem. A legitimate traffic spike from a known IP
has high T (known context) and high B (consistent behavior),
so even with high S the final DFS stays moderate → no kill.

An unknown IP touching a honey port has:
  S = 1.00 (maximum threat signal)
  T = 0.10 (zero context — we know nothing about this actor)
  B = 0.00 (touching a trap = zero behavioral coherence)
  DFS = 0.00 → KILL immediately

Response tiers (more aggressive than standard DFS):
  DFS ≥ 0.85  → KILL:        terminate connection, ban IP, log forensics
  0.65-0.85   → QUARANTINE:  isolate to sandbox container, deep inspect
  0.40-0.65   → THROTTLE:    rate limit + honeypot redirect
  0.20-0.40   → MONITOR:     heightened logging, no action yet
  < 0.20      → ALLOW:       normal traffic, baseline noise

Threat patterns detected:
  - Honey port touch (instant KILL)
  - Port scan (sequential port probing)
  - Volumetric anomaly (DDoS / flood)
  - Lateral movement (internal pivoting)
  - C2 beaconing (periodic outbound to unknown IP)
  - Data exfiltration (large outbound transfers)
  - Credential stuffing (repeated auth failures)
  - Zero-day exploit pattern (unexpected protocol anomaly)
  - IP spoofing attempt (TTL/header inconsistency)
  - Admin IP impersonation (spoofed trusted source)

Auto-DoS protection:
  - Whitelisted IPs never get KILL regardless of score
  - Score requires BOTH high S AND low T to trigger KILL
  - Velocity of actions from same IP is tracked (circuit breaker layer)
  - Behavioral baseline per IP: first deviation = MONITOR, not KILL
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple
from dfs_core.scoring import DFSInputs


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))


# ---------------------------------------------------------------------------
# Honey ports — touching these = instant maximum signal
# ---------------------------------------------------------------------------
HONEY_PORTS: Set[int] = {
    1,      # tcpmux — nobody should touch this
    11,     # systat
    19,     # chargen — amplification attack vector
    23,     # telnet — dead protocol, scanner bait
    69,     # tftp
    79,     # finger
    111,    # portmapper / rpcbind
    135,    # MS RPC — internal only
    137,    # NetBIOS
    161,    # SNMP
    512,    # rexec
    513,    # rlogin
    514,    # rsh / syslog (if external)
    1080,   # SOCKS proxy — C2 favorite
    1433,   # MSSQL — should never be internet-facing
    1521,   # Oracle DB
    2375,   # Docker daemon (unauthenticated) — critical
    2376,   # Docker TLS
    3306,   # MySQL — should never be internet-facing
    3389,   # RDP — honey if exposed externally
    4444,   # Metasploit default
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis (unauthenticated by default)
    8500,   # Consul
    9200,   # Elasticsearch (unauthenticated)
    27017,  # MongoDB (unauthenticated)
    31337,  # Back Orifice / elite C2
    50070,  # Hadoop NameNode
}

# Known C2 / malicious port patterns
C2_PORTS: Set[int] = {4444, 1337, 31337, 8080, 8443, 50050, 60000, 9999, 6666}

# Lateral movement ports (internal → internal = suspicious)
LATERAL_PORTS: Set[int] = {445, 139, 3389, 5985, 5986, 135, 389, 636, 88}

# Private IP ranges (for lateral movement detection)
def _is_private(ip: str) -> bool:
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(x) for x in parts]
        return (o[0] == 10 or
                (o[0] == 172 and 16 <= o[1] <= 31) or
                (o[0] == 192 and o[1] == 168))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Threat pattern risk scores
# ---------------------------------------------------------------------------
_THREAT_RISK = {
    "honey_port":           1.00,  # touching trap = immediate maximum
    "data_exfiltration":    0.95,  # large outbound transfer
    "c2_beacon":            0.93,  # periodic outbound to unknown IP
    "zero_day_pattern":     0.92,  # unexpected protocol anomaly
    "credential_stuffing":  0.88,  # mass auth failures
    "port_scan":            0.85,  # sequential port probing
    "volumetric_flood":     0.82,  # DDoS / amplification
    "lateral_movement":     0.88,  # internal pivoting
    "ip_spoofing":          0.90,  # TTL/header inconsistency
    "admin_impersonation":  0.95,  # spoofed trusted source
    "exploit_attempt":      0.90,  # known exploit signature
    "reverse_shell":        0.96,  # outbound shell connection
    "dns_tunneling":        0.82,  # data in DNS queries
    "protocol_anomaly":     0.70,  # unexpected protocol usage
    "geo_anomaly":          0.55,  # traffic from unexpected country
    "time_anomaly":         0.45,  # traffic outside business hours
    "unknown_traffic":      0.35,  # no classification
}

# Protocol anomaly risk
_PROTOCOL_RISK = {
    "icmp_flood":       0.75,
    "syn_flood":        0.82,
    "udp_flood":        0.78,
    "http_flood":       0.70,
    "dns_flood":        0.72,
    "ssl_strip":        0.85,
    "arp_poison":       0.88,
    "bgp_hijack":       0.95,
    "normal":           0.05,
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps network/host security event → (DFSInputs, flags).

    The DFS score here maps to autonomous response:
      ≥ 0.85 → KILL
      0.65   → QUARANTINE
      0.40   → THROTTLE
      0.20   → MONITOR
      < 0.20 → ALLOW
    """

    # ── Event identity ────────────────────────────────────────────────────────
    event_id        = _clean(event.get("event_id") or event.get("id"))
    timestamp       = _clean(event.get("timestamp"))
    sensor_id       = _clean(event.get("sensor_id") or event.get("sensor"))
    sensor_type     = _clean(event.get("sensor_type") or "ids")  # ids|firewall|waf|edr

    # ── Network 5-tuple ───────────────────────────────────────────────────────
    src_ip          = _clean(event.get("src_ip") or event.get("source_ip"))
    dst_ip          = _clean(event.get("dst_ip") or event.get("dest_ip"))
    src_port        = int(event.get("src_port") or 0)
    dst_port        = int(event.get("dst_port") or event.get("port") or 0)
    protocol        = _clean(event.get("protocol") or "tcp")
    direction       = _clean(event.get("direction") or "inbound")

    # ── Traffic metrics ───────────────────────────────────────────────────────
    bytes_in        = float(event.get("bytes_in") or event.get("bytes_recv") or 0)
    bytes_out       = float(event.get("bytes_out") or event.get("bytes_sent") or 0)
    packets_in      = int(event.get("packets_in") or 0)
    packet_rate     = float(event.get("packet_rate_pps") or 0)  # packets/sec
    bandwidth_mbps  = float(event.get("bandwidth_mbps") or 0)
    baseline_mbps   = float(event.get("baseline_mbps") or 1.0)  # expected bandwidth
    conn_duration   = float(event.get("connection_duration_sec") or 0)
    retry_count     = int(event.get("retry_count") or 0)

    # ── Threat classification ─────────────────────────────────────────────────
    threat_type     = _clean(event.get("threat_type") or event.get("alert_type") or "unknown_traffic")
    threat_conf     = float(event.get("threat_confidence") or event.get("confidence") or 0.5)
    signature_id    = _clean(event.get("signature_id") or event.get("rule_id"))
    signature_name  = _clean(event.get("signature_name") or event.get("rule_name"))
    cve_reference   = _clean(event.get("cve") or event.get("cve_reference"))
    mitre_technique = _clean(event.get("mitre_technique") or event.get("technique_id"))

    # ── IP reputation / geolocation ───────────────────────────────────────────
    ip_reputation   = float(event.get("ip_reputation_score") or 0.0)  # 0=clean 1=malicious
    threat_intel    = bool(event.get("threat_intel_match") or event.get("in_blocklist") or False)
    country_code    = _clean(event.get("country_code") or event.get("geo_country"))
    is_tor          = bool(event.get("is_tor") or event.get("tor_exit_node") or False)
    is_vpn          = bool(event.get("is_vpn") or False)
    is_datacenter   = bool(event.get("is_datacenter") or event.get("hosting_provider") or False)
    asn             = _clean(event.get("asn") or event.get("autonomous_system"))
    prior_blocks    = int(event.get("prior_blocks") or event.get("block_count") or 0)

    # ── Host context ──────────────────────────────────────────────────────────
    dst_hostname    = _clean(event.get("dst_hostname") or event.get("target_host"))
    dst_service     = _clean(event.get("dst_service") or event.get("service"))
    is_internet_facing = bool(event.get("internet_facing") or True)
    host_criticality = _clean(event.get("host_criticality") or "medium")
    is_whitelisted  = bool(event.get("is_whitelisted") or event.get("trusted_source") or False)
    is_admin_ip     = bool(event.get("is_admin_ip") or event.get("admin_source") or False)

    # ── Process / payload context ─────────────────────────────────────────────
    process_name    = _clean(event.get("process_name") or event.get("process"))
    payload_entropy = float(event.get("payload_entropy") or 0.0)  # 0-8, >7 = encrypted/packed
    has_payload     = bool(event.get("has_payload") or payload_entropy > 0)
    protocol_anomaly = _clean(event.get("protocol_anomaly"))
    ttl_value       = int(event.get("ttl") or 64)
    expected_ttl    = int(event.get("expected_ttl") or 64)

    # ── Auth / credential signals ─────────────────────────────────────────────
    auth_failures   = int(event.get("auth_failures") or event.get("failed_logins") or 0)
    auth_user       = _clean(event.get("auth_user") or event.get("username"))
    is_brute_force  = auth_failures >= 10

    # ── Derived threat signals ────────────────────────────────────────────────

    # Honey port detection — highest priority
    is_honey_port   = dst_port in HONEY_PORTS
    is_c2_port      = dst_port in C2_PORTS and direction == "outbound"
    is_lateral      = (_is_private(src_ip or "") and _is_private(dst_ip or "") and
                       dst_port in LATERAL_PORTS)

    # Volumetric anomaly
    bandwidth_ratio = bandwidth_mbps / max(baseline_mbps, 0.001)
    is_volumetric   = bandwidth_ratio >= 10.0 or packet_rate >= 10000

    # Data exfiltration heuristic
    is_exfil        = (bytes_out > 100_000_000 and direction == "outbound" and
                       not _is_private(dst_ip or ""))  # >100MB outbound to external

    # C2 beaconing: regular small outbound connections
    is_beaconing    = (conn_duration > 300 and bytes_out < 10000 and
                       direction == "outbound" and not _is_private(dst_ip or ""))

    # Port scan: high variety of dst_ports from same src (this event = one probe)
    is_port_scan    = bool(event.get("port_scan_detected") or
                           event.get("scan_type") or
                           (src_port > 1024 and dst_port < 1024 and retry_count > 5))

    # TTL spoofing — IP spoofing indicator
    ttl_delta       = abs(ttl_value - expected_ttl)
    is_ttl_anomaly  = ttl_delta > 20

    # Admin IP impersonation (claimed admin but behavior doesn't match)
    is_admin_spoof  = (is_admin_ip and (is_honey_port or is_volumetric or
                       auth_failures > 5 or is_port_scan))

    # High entropy payload = likely encrypted C2 or exfil
    high_entropy    = payload_entropy >= 7.0

    # Override threat type with derived signals for scoring
    effective_threat = threat_type
    if is_honey_port:           effective_threat = "honey_port"
    elif is_admin_spoof:        effective_threat = "admin_impersonation"
    elif is_exfil:              effective_threat = "data_exfiltration"
    elif is_beaconing:          effective_threat = "c2_beacon"
    elif is_lateral:            effective_threat = "lateral_movement"
    elif is_port_scan:          effective_threat = "port_scan"
    elif is_volumetric:         effective_threat = "volumetric_flood"
    elif is_ttl_anomaly:        effective_threat = "ip_spoofing"

    threat_risk     = _THREAT_RISK.get(effective_threat, 0.35)
    proto_risk      = _PROTOCOL_RISK.get((protocol_anomaly or "normal").lower(), 0.05)

    # Presence / quality flags
    has_src_ip      = _truthy(src_ip)
    has_dst_ip      = _truthy(dst_ip)
    has_dst_port    = dst_port > 0
    has_signature   = signature_id is not None or signature_name is not None
    has_threat_type = _truthy(threat_type) and threat_type != "unknown_traffic"
    has_geo         = country_code is not None
    has_asn         = asn is not None
    has_host_ctx    = dst_hostname is not None or dst_service is not None
    has_process     = process_name is not None
    has_sensor      = sensor_id is not None
    has_timestamp   = timestamp is not None
    has_event_id    = event_id is not None
    has_mitre       = mitre_technique is not None

    # ── T — Telemetry Completeness ────────────────────────────────────────────
    # Without good context, we can't tell legitimate spike from attack
    network_fields  = [has_src_ip, has_dst_ip, has_dst_port, _truthy(protocol)]
    threat_fields   = [has_signature, has_threat_type, has_mitre, threat_conf > 0.5]
    enrichment      = [has_geo, has_asn, ip_reputation > 0, _truthy(direction)]
    sensor_fields   = [has_sensor, has_timestamp, has_event_id, has_host_ctx]

    t = (
        sum(1.0 for x in network_fields if x) / max(len(network_fields), 1) * 0.35 +
        sum(1.0 for x in threat_fields if x) / max(len(threat_fields), 1) * 0.30 +
        sum(1.0 for x in enrichment if x)    / max(len(enrichment), 1)    * 0.20 +
        sum(1.0 for x in sensor_fields if x) / max(len(sensor_fields), 1) * 0.15
    )

    # ── S — Signal Clarity ────────────────────────────────────────────────────
    s = (threat_risk * 0.50) + (threat_conf * 0.25) + (ip_reputation * 0.15) + (proto_risk * 0.10)

    if is_honey_port:       s = _clamp(s + 0.30)  # non-negotiable max
    if threat_intel:        s = _clamp(s + 0.15)
    if is_tor:              s = _clamp(s + 0.12)
    if is_datacenter:       s = _clamp(s + 0.05)
    if prior_blocks >= 3:   s = _clamp(s + 0.10)  # repeat offender
    if high_entropy:        s = _clamp(s + 0.08)
    if cve_reference:       s = _clamp(s + 0.10)
    if is_brute_force:      s = _clamp(s + 0.10)
    if is_admin_spoof:      s = _clamp(s + 0.20)  # most dangerous pattern
    if is_ttl_anomaly:      s = _clamp(s + 0.08)

    # Reduce signal for whitelisted / admin IPs (auto-DoS protection)
    if is_whitelisted:      s = _clamp(s * 0.25)   # strong reduction
    if is_admin_ip and not is_admin_spoof:
                            s = _clamp(s * 0.40)

    s = _clamp(s)

    # ── B — Behavioral Coherence ──────────────────────────────────────────────
    # Coherence = traffic pattern matches expected behavior for this source/dest
    b = 0.35
    if has_signature:       b += 0.12   # known pattern = coherent narrative
    if has_mitre:           b += 0.10
    if has_geo:             b += 0.07
    if has_asn:             b += 0.07
    if has_host_ctx:        b += 0.07
    if has_process:         b += 0.08
    if threat_conf >= 0.80: b += 0.08
    if threat_intel:        b += 0.06

    # Incoherence penalties
    if is_honey_port:       b = _clamp(b - 0.40)  # touching trap = zero coherence
    if is_admin_spoof:      b = _clamp(b - 0.35)  # identity ≠ behavior
    if is_ttl_anomaly:      b = _clamp(b - 0.20)  # spoofed headers
    if is_volumetric and is_whitelisted:
                            b = _clamp(b - 0.05)  # unusual for this source

    b = _clamp(b)

    flags = {
        # Standard DFS
        "has_user":                 _truthy(auth_user),
        "has_host":                 has_dst_ip,
        "has_command_line":         has_process,
        "has_process_path":         has_process,
        "has_parent_process":       False,
        # Network
        "has_src_ip":               has_src_ip,
        "has_dst_port":             has_dst_port,
        "has_signature":            has_signature,
        "has_mitre":                has_mitre,
        "has_geo":                  has_geo,
        "has_threat_intel":         threat_intel,
        # Threat patterns
        "is_honey_port":            is_honey_port,
        "is_c2_port":               is_c2_port,
        "is_lateral_movement":      is_lateral,
        "is_volumetric":            is_volumetric,
        "is_data_exfil":            is_exfil,
        "is_c2_beacon":             is_beaconing,
        "is_port_scan":             is_port_scan,
        "is_brute_force":           is_brute_force,
        "is_ttl_anomaly":           is_ttl_anomaly,
        "is_admin_spoof":           is_admin_spoof,
        "is_tor":                   is_tor,
        "high_entropy_payload":     high_entropy,
        "has_cve":                  _truthy(cve_reference),
        "repeat_offender":          prior_blocks >= 3,
        # Protection
        "is_whitelisted":           is_whitelisted,
        "is_admin_ip":              is_admin_ip,
        "auto_dos_protected":       is_whitelisted or (is_admin_ip and not is_admin_spoof),
    }

    return DFSInputs(_clamp(s), _clamp(t), _clamp(b)), flags


def cyber_wall_to_inputs_and_flags(event):
    return extract(event)
