"""
Manual test for CVE Context extractor.
Run: python test_cve_manual.py

These cases directly mirror the Zero Day Clock problem space:
  - CVE that's in CISA KEV + ransomware = automate patch
  - CVSS 9.8 but no exploit, no reachability = noise
  - Zero-day exploited before disclosure = critical
  - High CVSS but unreachable = deprioritize
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.cve_context import extract

CASES = {
    "Log4Shell (KEV + ransomware + reachable)": {
        "cve_id": "CVE-2021-44228",
        "cvss_v3": 10.0,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.975,
        "epss_percentile": 99.8,
        "in_cisa_kev": True,
        "known_ransomware_use": True,
        "exploit_maturity": "weaponized",
        "has_metasploit_module": True,
        "has_public_poc": True,
        "exploit_count": 47,
        "description": "Apache Log4j2 JNDI injection RCE",
        "asset": {
            "id": "java-app-prod-01",
            "type": "web_application",
            "criticality": "critical",
            "internet_facing": True,
            "in_production": True,
            "owner": "platform-team",
            "environment": "production",
        },
        "reachability": {
            "is_reachable": True,
            "confidence": 0.97,
            "call_path_exists": True,
            "loaded_in_runtime": True,
        },
        "patch": {"available": True, "version": "2.17.1", "days_available": 14},
    },

    "CVSS 9.8 — no exploit, no reachability (inflation)": {
        "cve_id": "CVE-2024-99999",
        "cvss_v3": 9.8,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.008,
        "epss_percentile": 42.0,
        "in_cisa_kev": False,
        "exploit_maturity": "theoretical",
        "has_public_poc": False,
        "description": "Theoretical buffer overflow in obscure library",
        "asset": {
            "id": "internal-tool-01",
            "criticality": "low",
            "internet_facing": False,
            "in_production": True,
            "owner": "dev-team",
        },
        "reachability": {
            "is_reachable": False,
            "confidence": 0.90,
            "call_path_exists": False,
            "loaded_in_runtime": False,
        },
        "patch": {"available": True, "days_available": 5},
    },

    "Zero-day exploited before disclosure (2026 pattern)": {
        "cve_id": "CVE-2026-00001",
        "cvss_v3": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.940,
        "epss_percentile": 99.5,
        "in_cisa_kev": True,
        "is_zero_day": True,
        "exploited_before_disclosure": True,
        "exploit_maturity": "weaponized",
        "known_ransomware_use": True,
        "description": "Zero-day in VPN appliance exploited before patch",
        "asset": {
            "id": "vpn-gateway-01",
            "type": "network_device",
            "criticality": "critical",
            "internet_facing": True,
            "in_production": True,
            "owner": "network-team",
        },
        "reachability": {
            "is_reachable": True,
            "confidence": 1.0,
            "call_path_exists": True,
            "loaded_in_runtime": True,
        },
        "patch": {"available": False},
    },

    "Metasploit module, medium asset, reachable": {
        "cve_id": "CVE-2023-44487",
        "cvss_v3": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.720,
        "epss_percentile": 97.0,
        "in_cisa_kev": True,
        "exploit_maturity": "metasploit",
        "has_metasploit_module": True,
        "description": "HTTP/2 Rapid Reset DoS (CVSS 7.5 but massively exploited)",
        "asset": {
            "id": "nginx-proxy-01",
            "type": "web_server",
            "criticality": "high",
            "internet_facing": True,
            "in_production": True,
            "owner": "infra-team",
        },
        "reachability": {
            "is_reachable": True,
            "confidence": 0.95,
            "call_path_exists": True,
            "loaded_in_runtime": True,
        },
        "patch": {"available": True, "days_available": 30},
    },

    "High CVSS, internal asset, unreachable (deprioritize)": {
        "cve_id": "CVE-2022-12345",
        "cvss_v3": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
        "epss_score": 0.023,
        "epss_percentile": 68.0,
        "in_cisa_kev": False,
        "exploit_maturity": "poc_private",
        "description": "Complex exploit requiring user interaction on internal tool",
        "asset": {
            "id": "dev-server-07",
            "criticality": "medium",
            "internet_facing": False,
            "in_production": False,
            "owner": "dev-team",
        },
        "reachability": {
            "is_reachable": False,
            "confidence": 0.85,
            "call_path_exists": False,
        },
        "patch": {"available": True, "days_available": 2},
    },

    "No reachability data — CVSS only (blind patching)": {
        "cve_id": "CVE-2023-55555",
        "cvss_v3": 9.1,
        "cvss_severity": "critical",
        "epss_score": 0.0,
        "in_cisa_kev": False,
        "exploit_maturity": "none",
        "description": "Critical vuln, no enrichment data available",
        "asset": {"id": "unknown-host", "owner": "unknown"},
        "patch": {"available": True},
    },
}

print(f"\n{'='*76}")
print(f"  CVE CONTEXT EXTRACTOR — DFS Prioritization")
print(f"{'='*76}")
print(f"{'CASE':<46} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'-'*76}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)

    if dfs >= 0.78:   action = "AUTOMATE"
    elif dfs >= 0.55: action = "ESCALATE"
    elif dfs >= 0.30: action = "TRIAGE"
    else:             action = "BACKLOG"

    print(f"{name:<46} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}  → {action}")
    risk = [k for k, v in flags.items() if v is True and k not in ("has_user","has_host","has_command_line","has_process_path","has_parent_process","has_cvss","has_cve_id","has_asset","has_patch","has_epss","has_exploit_data","has_reachability","has_kev_data")]
    if risk:
        print(f"  signals: {', '.join(risk[:6])}")

print(f"{'='*76}\n")
