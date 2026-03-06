<div align="center">

# Detection Fidelity Score (DFS)

**Can this alert — or this AI agent action — safely drive automation?**

[![CI](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/ci.yml/badge.svg)](https://github.com/gustavo89587/detection-fidelity-score/actions)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Extractors](https://img.shields.io/badge/extractors-16-blueviolet)

</div>

---

## The Problem

Security teams and AI systems face two compounding crises:

- **Alert fatigue:** SOCs receive thousands of alerts per day. Most are noise. The ones that aren't look identical to the ones that are.
- **Agent autonomy:** AI agents can now execute code, transfer funds, modify infrastructure, and delete data — without a standard for deciding *when* they should act alone vs. when a human must intervene.

The industry's answer has been: *tune your thresholds* or *add more rules.* Neither scales.

DFS answers a different question:

> **"How much should I trust this event — enough to act on it automatically?"**

---

## How It Works

Every event — whether a security alert, a CVE, or an AI agent action — is scored across three dimensions:

| Dimension | Question | Weight |
|-----------|----------|--------|
| **S** — Signal Clarity | How dangerous or significant is this event? | Context-dependent |
| **T** — Telemetry | How complete and trustworthy is the data behind it? | Context-dependent |
| **B** — Behavioral Coherence | Does the full context hang together, or is something off? | Context-dependent |

```
DFS = S × T × B
```

The multiplicative model is the key insight: **if any dimension collapses to zero, the score collapses.** A perfectly dangerous signal with no telemetry context scores near zero. Noise cannot be misclassified as critical.

### Decision Tiers

| DFS Score | Action | Meaning |
|-----------|--------|---------|
| ≥ 0.78 | **AUTOMATE** | Execute without human review |
| 0.55 – 0.78 | **ESCALATE** | Notify human, proceed with logging |
| 0.30 – 0.55 | **TRIAGE** | Pause, request human approval |
| < 0.30 | **INVESTIGATE / BLOCK** | Hard gate — do not act |

---

## Real Scores From Real Events

```
Event                                          S      T      B     DFS    Decision
─────────────────────────────────────────────────────────────────────────────────────
Log4Shell (KEV + ransomware + reachable)     1.000  1.000  1.000  1.0000  AUTOMATE
Zero-day exploited before disclosure         1.000  1.000  0.900  0.9000  AUTOMATE
Credential stuffing – 500 auth failures      1.000  0.920  1.000  0.9200  KILL
C2 beacon (Tor + encrypted payload)          1.000  0.930  0.962  0.8951  KILL
CVSS 9.8 – no exploit, not reachable         0.198  0.530  0.667  0.0700  BACKLOG ←
Prompt injection: summarize→exfiltrate       1.000  0.170  0.871  0.1480  BLOCK
AI agent: delete prod DB, no approval        1.000  0.570  0.738  0.4204  TRIAGE
Legit CDN traffic spike (whitelisted)        0.057  0.490  0.613  0.0173  ALLOW  ←
Intruder crawling in server room (Wi-Fi CSI) 1.000  0.850  0.900  0.7650  ESCALATE
```

The two `←` rows tell the story:
- **CVSS 9.8 → BACKLOG**: No exploit, no reachability, no real threat. CVSS alone is noise.
- **10Gbps CDN spike → ALLOW**: Known source, whitelisted. The circuit never trips for legitimate traffic.

---

## Supported Data Sources

### Security Alerts & SIEMs
| Source | Extractor | Detects |
|--------|-----------|---------|
| Elastic SIEM | `elastic_siem` | EQL rules, indicator match, ML anomalies, building blocks |
| Splunk Enterprise Security | `splunk_notable` | Notable events, Risk Based Alerting (RBA), urgency scoring |
| Wazuh XDR | `wazuh_alert` | Rule levels, FIM, CVE/CVSS, SCA compliance |

### Windows / Endpoint
| Source | Extractor | Detects |
|--------|-----------|---------|
| Sysmon Event 1 | `windows-sysmon-1` | Process creation, LOLBins, parent anomalies |
| Sysmon Event 3 | `windows-sysmon-3` | Network connections, C2 beaconing |
| Windows Event 4624 | `windows-4624` | Logon events, lateral movement |
| Windows Event 4688 | `windows-4688` | Process creation with command line |
| PowerShell 4104 | `windows-powershell-4104` | Script block logging, obfuscation |

### Cloud
| Source | Extractor | Detects |
|--------|-----------|---------|
| AWS CloudTrail IAM | `aws-cloudtrail-iam` | Privilege escalation, credential abuse |
| AWS GuardDuty | `aws-guardduty` | Threat intelligence findings |
| Azure AD Sign-in | `azure-ad-signin` | Impossible travel, MFA bypass |
| GCP Audit Log | `gcp-audit` | Admin activity, data access |
| GCP Security Command Center | `gcp-scc` | Misconfiguration, vulnerability findings |

### Infrastructure
| Source | Extractor | Detects |
|--------|-----------|---------|
| Docker | `docker` | Container escape, privileged runs |
| Falco | `falco` | Runtime anomalies, syscall violations |

### AI Agent Governance
| Source | Extractor | Detects |
|--------|-----------|---------|
| AI Agent Actions | `agent-action` | Prompt injection, chain depth, irreversible actions |
| CVE Context | `cve-context` | EPSS + CISA KEV + reachability — real exploitability |

### Physical / Network
| Source | Extractor | Detects |
|--------|-----------|---------|
| Wi-Fi CSI | `wifi-csi` | Physical intruders, gait anomaly, evil twin, RF jamming |
| Cyber Wall IPS | `cyber-wall` | Honey ports, C2, volumetric DDoS, lateral movement, exfil |

---

## Agent Infrastructure

Beyond scoring, DFS provides the enforcement layer that makes autonomous decisions safe:

### `dfs_guardrail.py` — Trust Boundary Middleware
```python
from dfs_core.guardrail import evaluate_before_action

decision = evaluate_before_action(action_event, kind="agent-action")

if decision.approved:
    execute()          # DFS ≥ threshold
else:
    request_human(decision.reason)   # Hard gate
```

Or as a decorator:
```python
from dfs_core.guardrail import dfs_guardrail

@dfs_guardrail(kind="agent-action", threshold=0.78)
def deploy_to_production(env, action_event=None):
    ...
```

### `circuit_breaker.py` — Behavioral Anomaly Detection
Automatically cuts agent access on velocity anomalies, error storms, scope creep, or risk escalation — before damage occurs.

### `abac_token.py` — Per-Action Scoped Authorization
```python
token = manager.issue(
    agent_id="agent-deploy-01",
    action_type="deploy_to_production",
    resource="k8s-prod-cluster",
    environment="production",
    authorized_by="jane@corp.com",
    valid_seconds=300,
    single_use=True,
)
```
No master keys. Every action requires a cryptographically signed, time-bounded, single-use token.

### `audit_ledger.py` — Tamper-Evident Hash-Chained Log
Every decision is written to an append-only SHA-256 hash chain. Modifying any entry breaks all subsequent hashes — forensically detectable.

```python
ledger.verify_chain()
# VerificationResult(valid=True, total=47, reason='Chain intact — 47 entries verified')
```

---

## Quick Start

```bash
git clone https://github.com/gustavo89587/detection-fidelity-score
cd detection-fidelity-score
pip install -r requirements.txt
```

**Score an event from the CLI:**
```bash
python -m dfs_core.cli --kind windows-sysmon-1 --file event.json
```

**Use the Python API:**
```python
from dfs_core.scoring import evaluate_event

result = evaluate_event(
    kind="agent-action",
    event={
        "agent_id": "agent-01",
        "action_type": "deploy_to_production",
        "environment": "production",
        "is_reversible": True,
        "initiator_type": "human_approved",
        "approved_by": "jane@corp.com",
        "rollback_plan": "kubectl rollout undo",
    }
)

print(result.dfs_score)   # 0.5743
print(result.action)      # ESCALATE
print(result.reason)      # "DFS 0.5743 — executing with human notification..."
```

---

## Project Structure

```
detection-fidelity-score/
├── dfs_core/
│   ├── scoring.py              # DFSInputs, DecisionCard, evaluate_event()
│   ├── guardrail.py            # Trust boundary middleware + decorator + context manager
│   ├── circuit_breaker.py      # Velocity anomaly + error storm detection
│   ├── abac_token.py           # Per-action signed authorization tokens
│   ├── audit_ledger.py         # SHA-256 hash-chained immutable log
│   └── features/
│       ├── registry.py         # Extractor registry — maps kind → module
│       ├── elastic_siem.py     # Elastic SIEM extractor
│       ├── splunk_notable.py   # Splunk ES extractor
│       ├── wazuh_alert.py      # Wazuh XDR extractor
│       ├── windows_sysmon_1.py # Sysmon process creation
│       ├── windows_sysmon_3.py # Sysmon network connection
│       ├── windows_4624.py     # Windows logon
│       ├── windows_4688.py     # Windows process creation
│       ├── windows_ps_4104.py  # PowerShell script block
│       ├── aws_cloudtrail.py   # AWS CloudTrail IAM
│       ├── aws_guardduty.py    # AWS GuardDuty
│       ├── azure_ad_signin.py  # Azure AD sign-in
│       ├── gcp_audit.py        # GCP Audit Log
│       ├── gcp_scc.py          # GCP Security Command Center
│       ├── docker_event.py     # Docker runtime
│       ├── falco_alert.py      # Falco syscall
│       ├── agent_action.py     # AI agent action (prompt injection, chain depth)
│       ├── cve_context.py      # CVE scoring (EPSS + KEV + reachability)
│       ├── wifi_csi.py         # Wi-Fi CSI physical telemetry
│       └── cyber_wall.py       # Active defense IPS (honey ports, C2, exfil)
├── tests/
│   └── test_extractors.py      # pytest suite — all extractors
└── .github/workflows/ci.yml    # GitHub Actions CI
```

---

## Running Tests

```bash
pytest tests/ -v
```

All extractors have automated tests with real event fixtures. CI runs on every push.

---

## Why S × T × B?

Most scoring systems are additive: `score = a×signal + b×context + c×history`. Additive systems let high scores in one dimension compensate for zero in another.

DFS is multiplicative. A real-world consequence:

- A CVSS 9.8 vulnerability with no reachability, no exploit, and no KEV entry scores **DFS 0.07 → BACKLOG**
- The same asset with Log4Shell (KEV + ransomware use + confirmed reachable) scores **DFS 1.00 → AUTOMATE**

The math enforces what analysts know intuitively: *context that's missing isn't neutral — it's a reason not to act.*

---

## Roadmap

- [ ] `pip install dfs-core` — PyPI package
- [ ] RFC-001: S×T×B as a language-agnostic scoring specification
- [ ] TypeScript SDK
- [ ] Jupyter notebook: interactive scoring playground
- [ ] SIEM native integrations (Splunk SOAR, Microsoft Sentinel)
- [ ] Real-time drift monitor dashboard
- [ ] OASIS CoSAI contribution (Agentic Systems workstream)

---

## Contributing

The reference implementation for a new extractor is [`dfs_core/features/elastic_siem.py`](dfs_core/features/elastic_siem.py). Every extractor follows the same contract:

```python
def extract(event: Dict[str, Any], policy=None) -> Tuple[DFSInputs, Dict[str, bool]]:
    ...
    return DFSInputs(signal, trust, overlap), flags
```

PRs welcome. Open an issue first for new extractor proposals.

---

## Author

Built by **Gustavo** · [github.com/gustavo89587](https://github.com/gustavo89587)

Inspired by the gap identified in:
- Chris Hughes, *"Governing Agentic AI"* — Resilient Cyber, Feb 2026
- Sergej Epp, *"The Zero Day Clock"* — 2026
- Engin & Hand, *"Toward Adaptive Categories: Dimensional Governance for Agentic AI"*

---

## License

Apache 2.0 — free to use, modify, and distribute. Attribution appreciated.
