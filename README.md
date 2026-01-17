# Detection Fidelity Score (DFS)

Detection engineering is not about writing more rules.
It’s about making decisions under uncertainty.

This repository introduces the idea of a Detection Fidelity Score (DFS):
a way to reason about how much *decision confidence*
a detection provides to an analyst under real SOC conditions.


DFS is not a tool and not a SIEM feature.
It is a mental framework to evaluate trade-offs between
coverage, noise, and analyst cost.

---

## Why this exists

## Why this exists

Many detections are technically correct but operationally weak.

They trigger on real attacker behavior,
but also overlap heavily with legitimate admin activity.

This creates a problem:
- Analysts lose trust in alerts
- SOC fatigue increases
- Good signals get ignored

DFS exists to help reason about this problem *before* shipping a detection.

## Example use case

A detection engineer is reviewing a rule change.

The change increases coverage,
but also introduces additional benign matches.

The question is not:
"Does this detect more behavior?"

The real question is:
"Does this improve analyst decision-making?"

DFS frames this as a fidelity problem:
How much confidence does each alert provide
relative to the cost it introduces?


---

## Core concepts

DFS is based on a few high-level dimensions:

- Signal clarity  
  How clearly the alert points to malicious intent

- Noise overlap  
  How often the same behavior appears in benign workflows

- Analyst cost  
  Time and cognitive effort required to validate the alert

DFS does not aim for precision math.
It aims for explicit reasoning.

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

