# Detection Fidelity Score (DFS)

Detection Fidelity Score (DFS) is a methodology for objectively measuring the impact of privacy transformations (redaction, pseudonymization, anonymization) on the effectiveness of detections.

DFS is not a SIEM package, nor a set of rules.

It is a method for **measuring and comparing trade-offs** in detection engineering — especially when privacy enters as a system variable.

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

