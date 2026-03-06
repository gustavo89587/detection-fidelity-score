# Detection Fidelity Score (DFS)


![DFS Tests](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml/badge.svg)

**Signal Integrity for Detection Engineering**

[![CI](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml/badge.svg)](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org)
[![Status](https://img.shields.io/badge/status-research-orange)](https://github.com/gustavo89587/detection-fidelity-score)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

> Security teams measure alerts. DFS measures detection signal quality.

---

## The Problem

Detection engineering teams track coverage — how many ATT&CK techniques have rules, how many rules are active, how many alerts fired. What they don't track is whether those signals are actually trustworthy.

The result is **detection debt**: a growing body of rules whose real-world reliability is unknown. This produces:

- Alert fatigue from high-noise detections
- Automation built on low-fidelity signals
- Deployed rules with unknown operational impact
- Telemetry degradation that silently breaks detections
- Adversarial evolution that renders logic stale

DFS treats detection as what it actually is: **a decision system operating under operational cost and telemetry uncertainty.**

---

## How DFS Works

DFS evaluates detection signals before they drive action. It sits between detection logic and operational decisions:

```
Telemetry Source
      │
      ▼
Collection / Normalization
      │
      ▼
Detection Logic
      │
      ▼
DFS Signal Evaluation      ← quality gate
      │
      ▼
Trust Boundary Decision
      │
      ▼
Human Analyst / AI Agent Action
```

---

## Scoring Model

DFS computes a score across three orthogonal dimensions:

```
DFS = Signal_Strength × Telemetry_Stability × Behavioral_Robustness

where each dimension ∈ [0.0, 1.0]
```

### Why multiplicative?

An additive model allows a high score in one dimension to compensate for failure in another. The multiplicative model enforces that **all three conditions must hold**. If any dimension collapses, the score collapses — correctly reflecting that the signal cannot be trusted regardless of other properties.

| Dimension | What it measures |
|---|---|
| **Signal Strength** | How well the detection discriminates true positives from noise |
| **Telemetry Stability** | Reliability and consistency of the underlying telemetry over time |
| **Behavioral Robustness** | Resistance to adversarial evasion and behavioral drift |

### Trust Tiers

| Score | Tier | Action | Implication |
|---|---|---|---|
| > 0.70 | **High Trust** | `AUTOMATE` | Signal is reliable. Automation and autonomous response are appropriate. |
| 0.40 – 0.70 | **Operational** | `TRIAGE` | Signal has value but requires analyst validation before action. |
| < 0.40 | **Fragile** | `HUMAN ONLY` | Cannot drive automation. Flag for detection review. |

---

## Signal Degradation Model

DFS models three failure modes that break detections in production:

| Mode | Cause | Risk |
|---|---|---|
| **Loss** | Missing telemetry fields or collection gaps | Silent — detection runs but produces no alerts |
| **Distortion** | Parsing or enrichment changes alter field semantics | Alerts fire but with incorrect context |
| **Drift** | Adversarial behavior evolves past detection logic | Detection becomes progressively less effective |

---

## Operational Metrics

Beyond individual detection scores, DFS computes system-level metrics:

| Metric | Definition |
|---|---|
| `signal_density` | Fraction of alerts that are High Trust signals |
| `investigation_pressure` | Operational load from triage-tier detections (minutes/day) |
| `escalation_pressure` | Rate at which triage investigations escalate to incidents |
| `automation_coverage` | Fraction of detections eligible for automated response |
| `decision_stability` | Score variance across the detection pack over a rolling window |

These metrics answer questions like: *Is this detection policy generating more noise? Is the system becoming more or less reliable over time?*

---

## Output: DecisionCard

Every evaluation produces a `DecisionCard`:

```json
{
  "kind": "windows-powershell-4104",
  "score": 0.6325,
  "interpretation": "Operational",
  "action": "TRIAGE",
  "action_reason": [
    "looks_amsi_bypass",
    "looks_download_cradle",
    "looks_reflection"
  ],
  "dimensions": {
    "signal_strength": 0.75,
    "telemetry_stability": 0.91,
    "behavioral_robustness": 0.92
  },
  "degradation_flags": [],
  "evaluated_at": "2025-03-05T14:22:00Z"
}
```

---

## Quick Start

```bash
git clone https://github.com/gustavo89587/detection-fidelity-score
cd detection-fidelity-score
```

Score a dataset and emit DecisionCards:

```bash
python dfs_cli.py score ./examples/events_4104.jsonl \
  --kind windows-powershell-4104 \
  --policy ./policies/powershell_4104.policy.json \
  --limit 3
```

Run the full pipeline:

```bash
python pipeline.py \
  --input ./datasets/cloudtrail_iam.jsonl \
  --kind cloudtrail-iam \
  --policy ./policies/cloudtrail_iam.policy.json \
  --output ./reports/
```

---

## Integration with AI Agents

DFS provides a principled trust boundary for AI-driven SOC automation:

```
alert fires
      │
      ▼
DFS signal evaluation
      │
      ├── High Trust  →  agent may act autonomously
      ├── Operational →  agent may assist, human confirms
      └── Fragile     →  human only, agent must not act
```

This prevents a critical failure mode: agents acting on low-fidelity signals at machine speed, compounding noise into operational disruption.

---

## Project Layout

```
dfs_core/        # scoring pipeline and evaluation logic
policies/        # scoring policies (thresholds, weights, behavioral signals)
datasets/        # curated datasets (CloudTrail IAM, PowerShell 4104)
examples/        # small demo datasets
scripts/         # demo and helper scripts
tests/           # automated tests
docs/            # technical specification and diagrams
```

Full technical specification: [`docs/DFS_Technical_Specification_v1.0.md`](docs/DFS_Technical_Specification_v1.0.md)

---

## Roadmap

**Phase 1 — Detection CI/CD**
DFS as a quality gate in the detection engineering workflow. Evaluate impact before deploy.

**Phase 2 — Detection Observability Platform**
Continuous monitoring of signal density, investigation pressure, and decision stability across the detection environment.

**Phase 3 — Open Benchmark**
DFS as an industry benchmark for detection quality — analogous to ATT&CK Evaluations for EDR, but applied to detection signal engineering.

---

## Known Limitations

- Score calibration is based on design intent and empirical tuning; statistical validation against labeled ground truth is in progress
- The multiplicative model is sensitive to low values in any single dimension
- Current telemetry adapters cover CloudTrail and Windows PowerShell 4104; broader support is on the roadmap
- Behavioral Robustness does not yet incorporate time-series data for live drift detection

---

## Author

**Gustavo Okamoto** — Okamoto Security Labs  
Detection Engineering / Signal Reliability Research

---

## License

[Apache-2.0](LICENSE)
