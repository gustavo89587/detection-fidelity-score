# Detection Fidelity Score (DFS)

![CI](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml/badge.svg)

### Signal Integrity for Detection Engineering

DFS is a practical framework to evaluate whether **detection telemetry deserves trust**.

Instead of asking:
> “Did it alert?”

DFS asks:
> **Can this signal safely drive investigation, escalation, or automation?**

DFS models three failure modes that break detections in the real world:
- **Signal Loss** (missing fields / missing sources)
- **Signal Distortion** (parsing/enrichment changes what the event *means*)
- **Signal Drift** (behavior changes over time; old logic becomes unreliable)

---

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Status](https://img.shields.io/badge/status-research-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

---

## Detection Signal Lifecycle

```text
Telemetry Source
     │
     ▼
Collection Layer
     │
     ▼
Normalization / Parsing
     │
     ▼
Detection Logic
     │
     ▼
DFS Signal Evaluation
     │
     ▼
Trust Boundary Decision
     │
     ▼
SOC Analyst / AI Agent Action

DFS Decision Flow

Telemetry Sources
      │
      ▼
Collection Layer
      │
      ▼
Parsing / Normalization
      │
      ▼
Detection Logic
      │
      ▼
DFS Signal Evaluation
   ├── Loss
   ├── Distortion
   └── Drift
      │
      ▼
Detection Fidelity Score
      │
      ▼
Trust Boundary
   ├── Strong   → Automation Allowed
   ├── Degraded → Assist Analyst
   └── Broken   → Human Only

   Live Demo (5 seconds)

git clone https://github.com/gustavo89587/detection-fidelity-score
cd detection-fidelity-score

Run demo
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1

CLI Usage

Score a JSONL dataset and emit DecisionCards:

python .\dfs_cli.py score .\examples\events_4104.jsonl `
  --kind windows-powershell-4104 `
  --policy .\policies\powershell_4104.policy.json `
  --limit 3

  Project Layout
dfs_core/        # scoring pipeline + evaluation logic
policies/        # scoring policies (thresholds/weights/penalties)
datasets/        # curated datasets (e.g., CloudTrail IAM abuse, 4104)
examples/        # small demo datasets
scripts/         # demo and helper scripts
tests/           # automated tests
docs/            # documentation + diagrams

Output Shape (DecisionCard)

Example output:

{
  "kind": "windows-powershell-4104",
  "score": 0.6325,
  "interpretation": "Low Trust",
  "action": "TRIAGE",
  "action_reason": [
    "looks_amsi_bypass",
    "looks_download_cradle",
    "looks_reflection"
  ]
}

Roadmap

Telemetry adapters (Sysmon / PowerShell / CloudTrail) hardened for real SOC pipelines

Detection quality baselining and drift checks

Governance layer for AI/automation decisions driven by DFS trust boundaries

Author

Gustavo Okamoto
Okamoto Security Labs
Detection Engineering / Signal Reliability Research

License

Apache-2.0


