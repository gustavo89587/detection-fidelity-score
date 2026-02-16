# 🧠 Detection Fidelity Score (DFS)

![License](https://img.shields.io/badge/license-Apache%202.0-blue) ![Status](https://img.shields.io/badge/status-active%20development-green) ![Version](https://img.shields.io/badge/version-v0.1-informational) ![Author](https://img.shields.io/badge/author-Gustavo%20Okamoto-black) ![Focus](https://img.shields.io/badge/focus-detection%20engineering-purple)

> Detection is not about finding activity.  
> It's about making trustworthy decisions under uncertainty.

> Used for research, detection design, and SOC signal evaluation.
> Originally developed from hands-on SOC observation and detection engineering practice.


A practical framework to measure signal quality, noise overlap, and operational trust in detection engineering.

DFS is a framework to measure detection signal trust, design detections as decision systems, and approach detection engineering as an operational discipline.


## Who this is for

- Detection Engineers designing production-grade detections  
- SOC teams struggling with alert trust and signal clarity  
- Security leaders evaluating detection quality at scale  
- Researchers studying detection reliability over time  

## How I use this in practice

I use DFS to review detections before they reach production environments.

It helps identify:

- weak telemetry dependencies
- silent degradation risks
- unclear decision boundaries
- hidden analyst cost

This improves confidence in high-impact alerts and reduces operational noise.

## Project status

DFS is under active development as a long-term detection engineering framework.

Current focus:
- Formalizing detection design standards
- Modeling signal degradation patterns
- Building reference detection packs



## Positioning

DFS is not a detection rule set.

It is a way to think about signal trust, decision confidence, and detection survivability in real environments.

While DFS is primarily a design and governance discipline, it also introduces a lightweight quantitative model to assess detection survivability under degradation conditions.

## 🎯 Why DFS exists

While DFS is primarily a design and governance discipline, it also introduces a lightweight quantitative model to assess detection survivability under degradation conditions.

## Quantitative Model (DFS v1.0)

DFS introduces a minimal scoring structure to evaluate detection survivability across degradation domains.

DFS Score = f(Loss, Distortion, Drift, Confidence Boundary)

The model does not replace engineering judgment.
It structures it.

Each detection can be evaluated across:

- Telemetry dependency exposure
- Degradation sensitivity
- Decision boundary clarity
- Analyst cost amplification


Most detections fail not because they are wrong,
but because they are noisy, fragile, or hard to trust. 

Quantitative Model (DFS v1.0)

Even though DFS is primarily a decision discipline, it also introduces a measurable score to quantify detection survivability under degradation conditions.

Let:

S = Detections surviving intact
D = Detections degraded but operational
B = Detections broken
T = Total detections evaluated

DFS Score:

DFS = (S + 0.5D) / T

Interpretation:

1.0 → No operational degradation
0.8–0.99 → Minor degradation
0.5–0.79 → Operational degradation
<0.5 → High operational risk

DFS allows teams to compare detection reliability before and after telemetry changes, privacy controls, or architectural shifts.

## What DFS is becoming

DFS is evolving into a practical detection engineering discipline focused on:

- Designing detections as decision systems
- Governing signal trust across environments
- Measuring degradation over time
- Supporting high-confidence response automation

The long-term goal is to make detection reliability measurable, reviewable, and enforceable.

## Real-world application (SOC thinking)

I use DFS to evaluate detections before production deployment.

For each rule, I ask:

- What decision does this alert authorize?
- What telemetry does it depend on?
- Where can signal degrade? (Loss / Distortion / Drift)
- What is the expected analyst cost?

If these questions are unclear, the detection is not ready.

DFS turns detections from coverage artifacts into decision systems.


Each rule must declare its Trust Decision Boundary (what action it authorizes), and quantify how the signal degrades across:

- **Loss** (missing telemetry)
- **Distortion** (semantic corruption such as truncation/normalization)
- **Drift** (adversary evolution)

The goal is to ship detections that remain operationally reliable over time, with explicit validation gates and governance tiers — rather than maximizing coverage at the expense of analyst trust.


© 2026 Gustavo Okamoto
Licensed under the Apache License, Version 2.0

Engineering and Governing Trust in Automated Security Decisions
Detection Signal
        │
        ▼
┌─────────────────────────────┐
│     Degradation Domains     │
│                             │
│   • Loss        (missing)   │
│   • Distortion  (altered)   │
│   • Drift       (decayed)   │
└─────────────────────────────┘
        │
        ▼
   Trust Decision Boundary
        │
        ▼
 Human │ Automated │ Contextual


Engineering detection as a decision system — not an alert generator.

## The Problem

Modern detection engineering often prioritizes:

Coverage over clarity

Alerts over decisions

Tool logic over behavioral modeling

Automation before governance

This leads to:

Analyst fatigue

Inflated detection catalogs

Poor signal integrity

Fragile rules that degrade silently

DFS proposes a different approach.

Core Concept: Fidelity-Centric Detection

Detection is not an event.
Detection is a decision boundary.

Every detection must explicitly define:

What behavior is being modeled

What operational decision it enables

How the signal degrades over time

What risks exist in telemetry reliability

Trust Decision Boundary 

---

## 🔬 Practical Example – Windows 4688 Detection

To illustrate how DFS works in practice, below is a simplified applied example.

### Detection Hypothesis

Suspicious parent-child process chain indicating execution staging.

Example:
winword.exe → powershell.exe → encoded command

### Trust Decision Boundary

Action: Escalate to Tier 2 Analyst  
Confidence Required: ≥ 0.75  
Operational Tier: High Impact

---

### Degradation Analysis

| Domain      | Risk Level | Impact Description |
|-------------|-----------|-------------------|
| Loss        | High      | Missing command-line logging removes execution context |
| Distortion  | Medium    | Truncation alters semantic interpretation |
| Drift       | High      | Adversary shifts to LOLBins or indirect execution |

---

### Analyst Cost Estimation

- Context Required: Process tree + command line
- Average Triage Time: 6–12 minutes
- False Positive Surface: Medium

---

### Example DFS Score (Illustrative Model)

DFS = Signal Strength × Telemetry Stability × Behavioral Robustness

Where:

- Signal Strength (0–1)
- Telemetry Stability (0–1)
- Behavioral Robustness (0–1)

Example Evaluation:

Signal Strength: 0.82  
Telemetry Stability: 0.60  
Behavioral Robustness: 0.75  

DFS Score = 0.82 × 0.60 × 0.75 = **0.369**

Interpretation:

< 0.40 → Fragile  
0.40 – 0.70 → Operational  
> 0.70 → High Trust

This detection would require telemetry hardening before automation.

---

DFS is not theoretical.  
It forces detections to declare survivability under stress.


Each detection declares:

What action it authorizes (alert / escalate / block / observe)

Required confidence level

Operational tier

Without an explicit boundary, the rule is incomplete.

Degradation Model

All detections degrade.

DFS models degradation in three dimensions:

Loss

Signal disappears due to missing telemetry.

Distortion

Signal changes semantically (e.g., truncation, normalization).

Drift

Adversary behavior evolves to bypass logic.

Detections are reviewed as dynamic systems — not static rules.

Detection Design Standard (DDS)

All detections must comply with the formal design standard:

See: standards/Detection_Design_Standard_v1.md

This defines:

Hypothesis format

Telemetry requirements

Detection logic structure

False positive surface modeling

Drift modeling

Trust boundary declaration

Validation protocol

Governance metadata

Detection Packs

Structured detection implementations can be found in:

Detection Pack (v0.1)

Each pack:

Follows DDS

Declares Trust Decision Boundary

Includes degradation profile

Defines validation protocol

Future versions will enforce strict PASS/FAIL fidelity gates.

Objective

## Operational mindset

DFS was created from a practical observation:

Most detection failures are not technical failures.  
They are trust failures.

Alerts exist.  
Rules exist.  
Coverage exists.  

But under pressure, analysts still hesitate.

DFS focuses on:

- Signal clarity under real conditions
- Decision confidence during incidents
- Detection survivability over time
- Reducing cognitive load on analysts

This is not about writing more rules.

It's about engineering detections that can be trusted when it matters most.


Build detection engineering as:

A decision architecture

A signal integrity discipline

A governed operational system

Not just a collection of rules.
Attribution
## Author intent

DFS was created from a practical need to understand why some detections are trusted and acted upon, while others are ignored or silently degrade over time.

It reflects a mindset shaped by real-world observation of signal reliability, analyst decision pressure, and detection survivability.



Detection Fidelity Score (DFS)
Originally formulated and maintained by Gustavo Okamoto.

DFS is designed for long-term structural clarity, not trend cycles.

Trust must not be assumed.
It must be engineered.

standards/Detection_Design_Standard_v1.md

Detection Pack (v0.1)/
