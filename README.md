# Detection Fidelity Score (DFS)

DFS (Detection Fidelity Score) treats detections as decision systems, not alert generators.

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

##The Problem

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

Build detection engineering as:

A decision architecture

A signal integrity discipline

A governed operational system

Not just a collection of rules.
Attribution

Detection Fidelity Score (DFS)
Originally formulated and maintained by Gustavo Okamoto.

DFS is designed for long-term structural clarity, not trend cycles.

Trust must not be assumed.
It must be engineered.

standards/Detection_Design_Standard_v1.md

Detection Pack (v0.1)/
