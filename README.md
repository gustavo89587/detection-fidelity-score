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

Each layer can introduce risk.


## Telemetry Source
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

# Detection Fidelity Score (DFS)

Security teams measure alerts.
DFS measures detection signal quality.

Detection Fidelity Score (DFS) is a framework for evaluating detection systems as decision systems operating under operational cost and telemetry uncertainty.

DFS introduces a structured way to analyze how detections behave in real environments, focusing on signal trust, survivability, and decision reliability rather than alert volume.

# The Problem

Modern security operations generate massive volumes of telemetry and alerts.

However, most detection engineering practices focus on:

rule creation

alert generation

coverage expansion

What is rarely measured is the quality of the signal produced by the detection system.

As a result, many SOC teams experience:

alert fatigue

poor signal-to-noise ratios

fragile detections that degrade silently

automation acting on incomplete context

unclear decision boundaries

Most detections are evaluated in isolation, while in reality they operate as part of a larger decision system.

DFS addresses this gap.

## Core Idea

Detection should not be treated as isolated rules.

Detection systems should be evaluated as decision systems.

Each detection contributes to operational outcomes such as:

ignore
investigate
escalate
automate

Each of these decisions has a real operational cost in analyst time, cognitive load, and automation risk.

DFS evaluates detection systems based on:

signal density

operational pressure

decision distribution

system stability under variation

detection survivability under telemetry degradation

## Conceptual Model
events
   ↓
detections
   ↓
DFS evaluation
   ↓
signal quality
   ↓
human / automated decision

DFS acts as a signal evaluation layer between detection logic and operational decision making.

What DFS Measures

DFS evaluates detection systems using several structural dimensions.

Signal Density

How much meaningful signal exists relative to noise.

signal_density = (investigate + escalate) / total_events
Investigation Pressure

How much workload the detection system creates for analysts.

investigate_rate = investigate_decisions / total_events
Escalation Pressure

How frequently detections trigger incident escalation.

escalate_rate = escalations / total_events
Automation Coverage

How much of the decision flow can safely be automated.

automation_rate = automated_decisions / total_events
Decision Stability

How stable the detection system behaves under variation and degraded telemetry.

DFS models degradation across three domains:

Loss       → missing telemetry
Distortion → altered semantics
Drift      → adversary evolution
Detection Fidelity Score

DFS introduces a lightweight scoring structure to evaluate detection survivability.

## Example model:

DFS = Signal Strength × Telemetry Stability × Behavioral Robustness

Where:

Signal Strength — clarity of behavioral signal

Telemetry Stability — resistance to data loss or distortion

Behavioral Robustness — resistance to adversary drift

# Interpretation:

> 0.70   High Trust
0.40–0.70 Operational
< 0.40   Fragile
Example CLI Usage
dfs compare --events examples/events_4104.jsonl --policies policies/*.policy.json

Example output:

policy ranking

powershell-4104          score: 0.65
windows-4624-soc         score: 0.41

This allows engineers to compare detection policies under the same dataset and operational assumptions.

DFS as Detection Engineering Infrastructure

DFS is designed to function as a CI layer for detection engineering.

Example workflow:

engineer modifies detection rule
        ↓
pull request
        ↓
DFS evaluation
        ↓
impact report
        ↓
approve / revise

DFS helps answer questions such as:

Will this rule increase investigation load?

Does this detection improve signal density?

Does the system become more stable or fragile?

Connection to AI Agents

Autonomous security systems and AI-driven SOC workflows require reliable signal quality.

Raw alerts alone are insufficient for automated decision making.

DFS provides a signal evaluation layer that agents can query before acting.

alert
   ↓
DFS signal evaluation
   ↓
agent decision

This prevents automation of noise.

Who This Project Is For

DFS is designed for:

Detection Engineers

designing production-grade detections

evaluating detection reliability

reducing analyst workload

# SOC Teams

improving signal-to-noise ratio

understanding detection system behavior

validating detections before deployment

Security Researchers

studying detection reliability

analyzing signal degradation patterns

Project Status

DFS is currently under active development and research.

Current focus areas:

detection survivability modeling

decision system evaluation

dataset benchmarking

detection engineering methodology

Long-Term Vision

DFS aims to establish a new discipline:

Detection Quality Engineering

A field focused on:

evaluating detection systems as decision architectures

measuring signal reliability under operational constraints

designing survivable detections

enabling safe automation and AI-assisted SOC workflows

License

Apache License 2.0

## Author

Detection Fidelity Score (DFS)
Originally formulated and maintained by Gustavo Okamoto

DFS was created from practical observation of how detection systems behave under real operational pressure.

The goal is simple:

Engineering detection systems that produce trustworthy decisions.