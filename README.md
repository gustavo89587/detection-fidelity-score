# Detection Fidelity Score (DFS)

Detection engineering is not about writing more rules.
It’s about making decisions under uncertainty.

This repository introduces the idea of a Detection Fidelity Score (DFS):
a way to reason about how much *decision confidence* a detection gives
to an analyst under real SOC conditions.

DFS is not a tool and not a SIEM feature.
It is a mental framework to evaluate trade-offs between
coverage, noise, and analyst cost.

---

## Why this exists

Discussions about privacy and detection are usually opinion-based:

- “Redaction breaks detections”
- “We need raw data for correlation”
- “Privacy makes SOC blind”

Yet very few teams can answer, objectively:

- *How much detection capability was lost?*
- *Which techniques are affected?*
- *Which fields truly matter for detection?*
- *Does correlation still hold under anonymization?*

DFS exists to replace intuition with **measurable, reproducible evidence**.

---

## Core principle

**Same input.  
Same detection logic.  
One variable: the pipeline.**

Detection fidelity is evaluated by running the **same detections** over:
- Raw telemetry (baseline)
- Privacy-preserving telemetry (via OpenTelemetry Collector)

Any change in detection behavior becomes **measurable system behavior**, not speculation.

---

## What DFS measures

- **Detection Recall Delta**  
  How much detection capability changes after anonymization.

- **Detection Survivability**  
  Which detections survive, degrade, or break.

- **Field Dependency**  
  Which fields actually feed detections.

- **Correlation Integrity**  
  Whether kill chains remain correlatable under pseudonymization.

---

## What this is NOT

- ❌ A detection rules pack  
- ❌ A SIEM product  
- ❌ A compliance tool  
- ❌ A promise of “no detection loss”

DFS does not advocate for more or less data.  
It provides a **method to reason about trade-offs**.

---

## Repository structure

