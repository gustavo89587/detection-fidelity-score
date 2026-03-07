"""
Manual test for DFS Cyber Wall extractor.
Run: python test_cyber_wall_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.cyber_wall import extract

def action(dfs):
    if dfs >= 0.85:   return "KILL"
    if dfs >= 0.65:   return "QUARANTINE"
    if dfs >= 0.40:   return "THROTTLE"
    if dfs >= 0.20:   return "MONITOR"
    return "ALLOW"

CASES = {
    "Honey port touch (port 2375 Docker)": {
        "event_id": "evt-001", "sensor_id": "ids-dmz-01",
        "timestamp": "2026-03-06T02:00:00Z",
        "src_ip": "185.220.101.42", "dst_ip": "10.0.1.5",
        "src_port": 54321, "dst_port": 2375,
        "protocol": "tcp", "direction": "inbound",
        "threat_type": "port_scan", "threat_confidence": 0.95,
        "ip_reputation_score": 0.92, "threat_intel_match": True,
        "country_code": "RU", "asn": "AS396982",
        "is_tor": False, "prior_blocks": 5,
        "bytes_in": 1024, "bandwidth_mbps": 0.1, "baseline_mbps": 1.0,
        "signature_id": "SID-9001", "signature_name": "Docker API Probe",
        "mitre_technique": "T1046",
        "internet_facing": True, "host_criticality": "critical",
    },

    "DDoS volumetric flood (10Gbps vs 1Mbps baseline)": {
        "event_id": "evt-002", "sensor_id": "ids-edge-01",
        "timestamp": "2026-03-06T02:01:00Z",
        "src_ip": "203.0.113.0", "dst_ip": "198.51.100.10",
        "src_port": 0, "dst_port": 80,
        "protocol": "udp", "direction": "inbound",
        "threat_type": "volumetric_flood", "threat_confidence": 0.88,
        "ip_reputation_score": 0.75,
        "bandwidth_mbps": 10000.0, "baseline_mbps": 1.0,
        "packet_rate_pps": 500000,
        "bytes_in": 5_000_000_000, "packets_in": 3000000,
        "country_code": "CN", "asn": "AS4134",
        "protocol_anomaly": "udp_flood",
        "signature_id": "SID-1001",
        "mitre_technique": "T1498",
        "internet_facing": True, "host_criticality": "high",
    },

    "Admin IP spoof (spoofed admin doing port scan)": {
        "event_id": "evt-003", "sensor_id": "ids-internal-01",
        "timestamp": "2026-03-06T02:02:00Z",
        "src_ip": "10.0.0.1",  # claims to be admin IP
        "dst_ip": "10.0.1.100",
        "src_port": 12345, "dst_port": 22,
        "protocol": "tcp", "direction": "inbound",
        "threat_type": "port_scan", "threat_confidence": 0.85,
        "is_admin_ip": True,    # claims admin
        "port_scan_detected": True, "retry_count": 50,
        "ttl": 42, "expected_ttl": 64,  # TTL mismatch → spoofing
        "auth_failures": 15,
        "ip_reputation_score": 0.0,
        "signature_id": "SID-5001", "signature_name": "Internal Port Scan",
        "country_code": "BR", "asn": "AS7162",
        "bytes_in": 512, "bandwidth_mbps": 0.01, "baseline_mbps": 1.0,
        "internet_facing": False, "host_criticality": "critical",
    },

    "C2 beacon — periodic small outbound to unknown IP": {
        "event_id": "evt-004", "sensor_id": "edr-ws-01",
        "timestamp": "2026-03-06T02:03:00Z",
        "src_ip": "10.0.5.22", "dst_ip": "185.220.101.99",
        "src_port": 49152, "dst_port": 8443,
        "protocol": "tcp", "direction": "outbound",
        "threat_type": "c2_beacon", "threat_confidence": 0.82,
        "ip_reputation_score": 0.88, "threat_intel_match": True,
        "connection_duration_sec": 600,
        "bytes_out": 2048, "bytes_in": 512,
        "bandwidth_mbps": 0.01, "baseline_mbps": 1.0,
        "payload_entropy": 7.6,  # high entropy = encrypted C2
        "process_name": "svchost.exe",
        "country_code": "NL", "asn": "AS206728",
        "is_tor": True,
        "signature_id": "SID-7001", "mitre_technique": "T1071",
        "internet_facing": True, "host_criticality": "high",
    },

    "Data exfiltration — 500MB outbound to external": {
        "event_id": "evt-005", "sensor_id": "ids-dmz-02",
        "timestamp": "2026-03-06T02:04:00Z",
        "src_ip": "10.0.2.50", "dst_ip": "104.21.45.67",
        "src_port": 49200, "dst_port": 443,
        "protocol": "tcp", "direction": "outbound",
        "threat_type": "data_exfiltration", "threat_confidence": 0.79,
        "bytes_out": 500_000_000, "bytes_in": 10000,
        "bandwidth_mbps": 50.0, "baseline_mbps": 2.0,
        "payload_entropy": 7.9,
        "process_name": "python.exe",
        "ip_reputation_score": 0.60,
        "country_code": "US", "asn": "AS13335",
        "signature_id": "SID-8001", "mitre_technique": "T1048",
        "internet_facing": True, "host_criticality": "critical",
        "cve": "CVE-2024-12345",
    },

    "Lateral movement — internal SMB pivot": {
        "event_id": "evt-006", "sensor_id": "ids-internal-02",
        "timestamp": "2026-03-06T02:05:00Z",
        "src_ip": "10.0.5.22", "dst_ip": "10.0.1.5",
        "src_port": 49300, "dst_port": 445,
        "protocol": "tcp", "direction": "inbound",
        "threat_type": "lateral_movement", "threat_confidence": 0.77,
        "auth_failures": 3, "auth_user": "CORP\\jdoe",
        "bytes_in": 8192, "bandwidth_mbps": 0.5, "baseline_mbps": 1.0,
        "process_name": "cmd.exe",
        "ip_reputation_score": 0.0,
        "country_code": "BR",
        "signature_id": "SID-6001", "mitre_technique": "T1021.002",
        "internet_facing": False, "host_criticality": "critical",
    },

    "Legit traffic spike — whitelisted CDN (auto-DoS protection)": {
        "event_id": "evt-007", "sensor_id": "ids-edge-02",
        "timestamp": "2026-03-06T14:00:00Z",
        "src_ip": "151.101.1.1",  # Fastly CDN
        "dst_ip": "198.51.100.10",
        "src_port": 443, "dst_port": 80,
        "protocol": "tcp", "direction": "inbound",
        "threat_type": "unknown_traffic", "threat_confidence": 0.20,
        "bandwidth_mbps": 800.0, "baseline_mbps": 100.0,  # spike but expected
        "bytes_in": 2_000_000_000, "packets_in": 1000000,
        "is_whitelisted": True,  # CDN is whitelisted
        "ip_reputation_score": 0.0,
        "country_code": "US", "asn": "AS54113",
        "internet_facing": True, "host_criticality": "high",
    },

    "Credential stuffing — 500 auth failures": {
        "event_id": "evt-008", "sensor_id": "waf-01",
        "timestamp": "2026-03-06T02:07:00Z",
        "src_ip": "198.51.100.99", "dst_ip": "10.0.1.10",
        "src_port": 55000, "dst_port": 443,
        "protocol": "tcp", "direction": "inbound",
        "threat_type": "credential_stuffing", "threat_confidence": 0.91,
        "auth_failures": 500, "auth_user": "admin",
        "bytes_in": 102400, "bandwidth_mbps": 2.0, "baseline_mbps": 1.0,
        "ip_reputation_score": 0.85, "threat_intel_match": True,
        "prior_blocks": 7,
        "is_datacenter": True, "is_vpn": True,
        "country_code": "XX", "asn": "AS12345",
        "signature_id": "SID-2001", "mitre_technique": "T1110",
        "internet_facing": True, "host_criticality": "high",
        "dst_hostname": "login.corp.com", "dst_service": "https",
    },
}

print(f"\n{'='*80}")
print(f"  DFS CYBER WALL — Active Defense IPS")
print(f"{'='*80}")
print(f"{'CASE':<50} {'S':>5} {'T':>5} {'B':>5} {'DFS':>6}  RESPONSE")
print(f"{'-'*80}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    resp = action(dfs)
    prot = " [PROTECTED]" if flags.get("auto_dos_protected") else ""
    print(f"{name:<50} {inputs.signal:>5.3f} {inputs.trust:>5.3f} "
          f"{inputs.overlap:>5.3f} {dfs:>6.4f}  → {resp}{prot}")
    top = [k for k, v in flags.items() if v is True and
           k in ("is_honey_port","is_volumetric","is_admin_spoof","is_c2_beacon",
                 "is_data_exfil","is_lateral_movement","is_brute_force",
                 "is_tor","repeat_offender","high_entropy_payload","is_ttl_anomaly",
                 "auto_dos_protected")]
    if top:
        print(f"  signals: {', '.join(top[:5])}")

print(f"{'='*80}\n")
