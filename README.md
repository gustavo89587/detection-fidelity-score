# Detection Fidelity Score (DFS)

[![DFS Tests](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml/badge.svg)](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

> **Can this alert safely drive automation — or does it need a human?**

DFS is an open-source framework that scores security alerts not just on *what* they detected, but on *how much you should trust the signal* before acting on it.

---

## The Problem

Every SOC team has the same complaint: too many alerts, too little context.

The instinct is to add more rules. But the real problem is **decision confidence**.

When a Falco alert fires saying "shell spawned in container" — should you auto-kill it? Escalate? Log and move on?

The answer depends entirely on how complete your telemetry is. DFS measures exactly that.

---

## How It Works

```
DFS = S × T × B
```

| Dimension | Name | What It Measures |
|-----------|------|-----------------|
| **S** | Signal Clarity | How explicit is the threat intent? |
| **T** | Telemetry Completeness | How much forensic context do you have? |
| **B** | Behavioral Coherence | How consistent is the causal narrative? |

Multiplicative scoring matters: if telemetry is missing (T = 0.2), the score collapses — even if the signal looks high. You can't automate a response you can't explain.

### Decision Tiers

| DFS Score | Action | Meaning |
|-----------|--------|---------|
| ≥ 0.78 | **AUTOMATE** | High trust — automated response allowed |
| 0.55 – 0.78 | **ESCALATE** | Strong signal — senior analyst required |
| 0.30 – 0.55 | **TRIAGE** | Investigate — human review needed |
| < 0.30 | **INVESTIGATE** | Fragile signal — do not automate |

---

## Supported Data Sources

DFS ships with production-grade extractors for **12 security data sources**:

### Windows / Endpoint
| Source | Event | What It Detects |
|--------|-------|----------------|
| Sysmon | Event ID 1 | Process creation, parent-child chains, LOLBins |
| Sysmon | Event ID 3 | Network connections, C2, lateral movement |
| Windows Security | Event ID 4624 | Logon events, RDP, NTLM, cleartext auth |
| Windows Security | Event ID 4688 | Process creation with command-line context |
| PowerShell | Event ID 4104 | Script block logging, AMSI bypass, download cradles |

### Cloud
| Source | What It Detects |
|--------|----------------|
| AWS CloudTrail IAM | Privilege escalation, access key abuse, policy changes |
| AWS GuardDuty | Threat findings with severity + resource context scoring |
| Azure AD Sign-in | Legacy auth, impossible travel, leaked credentials, MFA gaps |
| GCP Cloud Audit Logs | IAM changes, Secret Manager access, org policy violations |
| GCP Security Command Center | ETD/CTD findings, MITRE-mapped threats, reverse shells |

### Infrastructure
| Source | What It Detects |
|--------|----------------|
| Docker / Falco | Container breakout, reverse shells, crypto mining, privileged containers |

### SIEMs
| Source | What It Detects |
|--------|----------------|
| Elastic Security | EQL rules, indicator match, ML anomaly alerts |
| Splunk Enterprise Security | Notable events, Risk Based Alerting (RBA) |
| Wazuh XDR | FIM, brute force, vulnerability CVE scoring, rule level mapping |

---

## Quick Start

```bash
git clone https://github.com/gustavo89587/detection-fidelity-score
cd detection-fidelity-score
pip install -e .
```

### Score an event from the CLI

```bash
python dfs_cli.py score examples/events_4104.jsonl \
  --kind windows-powershell-4104 \
  --policy policies/powershell_4104.policy.json \
  --limit 3
```

### Use the Python API

```python
from dfs_core.pipeline import evaluate_event

event = {
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell -NoProfile -EncodedCommand SQBFAFgA...",
        "parent": {"executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
    },
}

result = evaluate_event(
    event,
    kind="windows-sysmon-1",
    policy_path="policies/sysmon_1.policy.json"
)

print(result.card.score)   # 0.7425
print(result.card.action)  # "ESCALATE"
print(result.card.notes)   # ["missing_command_line"]
```

---

## Real Scores From Real Events

### Sysmon 3 — Network Connections
```
mshta.exe → port 31337 (LOLBin + C2 port)    DFS: 0.9094  → AUTOMATE block
winword.exe → port 4444 (Office macro C2)     DFS: 0.8050  → AUTOMATE block
powershell → DGA domain (C2 beaconing)        DFS: 0.8245  → AUTOMATE block
certutil.exe → external IP (LOLBin C2)        DFS: 0.7500  → ESCALATE
Lateral movement: cmd.exe → SMB internal      DFS: 0.5456  → TRIAGE
chrome.exe → google.com (normal browsing)     DFS: 0.1364  → noise
```

### AWS GuardDuty
```
InstanceCredentialExfiltration (full ctx)     DFS: 1.0000  → AUTOMATE
CryptoCurrency:EC2/BitcoinTool                DFS: 0.4763  → TRIAGE
High severity, missing context (degraded)     DFS: 0.1357  → INVESTIGATE
Policy:S3/BucketPublicAccessGranted           DFS: 0.1084  → noise
```

### Falco / Docker Runtime
```
Reverse shell (full context)                  DFS: 0.9029  → AUTOMATE
Crypto mining detected                        DFS: 0.8164  → AUTOMATE
Shell in privileged container                 DFS: 0.6249  → ESCALATE
Normal app network connection                 DFS: 0.3466  → INVESTIGATE
```

### Splunk Enterprise Security
```
RBA: High risk user (score 95, 47 events)     DFS: 0.9700  → AUTOMATE
Web attack (SQL injection)                    DFS: 0.3706  → TRIAGE
Already closed notable                        DFS: 0.0988  → noise
```

---

## Output Shape

Every evaluation returns a `DecisionCard`:

```json
{
  "kind": "windows-powershell-4104",
  "score": 0.7425,
  "action": "ESCALATE",
  "notes": ["looks_amsi_bypass", "looks_download_cradle"]
}
```

---

## Project Structure

```
dfs_core/
  features/          # 12 extractors (one per data source)
    windows_sysmon_1.py
    windows_sysmon_3.py
    windows_4624.py
    windows_4688.py
    windows_powershell_4104.py
    aws_cloudtrail_iam.py
    aws_guardduty.py
    azure_ad_signin.py
    gcp_audit_log.py
    gcp_scc.py
    docker_runtime.py
    elastic_siem.py
    splunk_notable.py
    wazuh_alert.py
    registry.py        # extractor registry
  scoring.py           # DFSInputs dataclass
  pipeline.py          # evaluate_event() + DecisionCard
  explain.py           # explainability layer
  guardrails.py        # action tiers
  tests/               # pytest test suite (10 tests, CI green)

policies/              # JSON policy files per source
examples/              # sample event datasets
docs/                  # technical specification
```

---

## Running Tests

```bash
pytest dfs_core/tests/ -v
```

CI runs on Python 3.11 and 3.12 via GitHub Actions.

---

## Roadmap

- [ ] CLI installable via `pip install dfs-core`
- [ ] Jupyter notebook for interactive score calibration
- [ ] Okta, CrowdStrike, Microsoft Sentinel extractors
- [ ] Zeek / Suricata network extractors
- [ ] REST API wrapper for SOAR integration
- [ ] Telemetry drift detection (score baseline over time)

---

## Contributing

Pull requests are welcome. If you want to add an extractor for a new data source, the pattern is consistent across all 14 existing ones — each extractor is a single Python file that returns `(DFSInputs, flags)`.

See `dfs_core/features/windows_sysmon_3.py` as the reference implementation.

---

## Author

**Gustavo Okamoto** — Detection Engineering / Signal Reliability Research  
[Okamoto Security Labs](https://github.com/gustavo89587)

---

## License

Apache-2.0
