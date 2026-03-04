# Detection Fidelity Score (DFS)

### Signal Integrity for Detection Engineering

DFS is a framework for evaluating the **trustworthiness of detection signals** across security telemetry pipelines.

It measures three critical failure modes in detection systems:

- **Signal Loss**
- **Signal Distortion**
- **Signal Drift**

The result is a **Detection Fidelity Score** that determines whether a signal can safely drive **SOC automation or AI agent decisions**.

---

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Status](https://img.shields.io/badge/status-research-orange)
![License](https://img.shields.io/badge/license-MIT-green)

## Detection Signal Lifecycle

Telemetry flows through multiple layers before reaching a detection.

# Each layer can introduce risk.

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
SOC / AI Agent Action

## Project Architecture

dfs/
 ├── engine.py          # core DFS scoring logic
 ├── evaluate.py        # signal evaluation
 ├── decision.py        # trust boundary decisions
 └── simulate.py        # scenario simulation

datasets/
 └── monte_carlo_scenarios.csv

docs/
 └── dfs_concept.md

## Example Evaluation

{
  "loss": 0.18,
  "distortion": 0.22,
  "drift": 0.09,
  "score": "Degraded",
  "trust_boundary": "Assist Analyst"
}

## Roadmap
Telemetry adapters for SOC pipelines

Elastic and Sigma compatibility

AI agent governance layer

DFS visualization dashboards

Monte Carlo simulation environment

## Author

Gustavo Okamoto  
Detection Engineering Research  
Okamoto Security Labs

## Quick Start

git clone https://github.com/detection-fidelity-score/dfs
cd dfs
python simulate.py
