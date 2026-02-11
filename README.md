Detection Fidelity Score (DFS)

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


Detection trust is not binary. It degrades.
DFS makes that degradation explicit, measurable, and governable.

Executive Summary

Detection systems and automated responses increasingly make high-impact decisions:

Account lockouts

Endpoint isolation

Token revocation

Privilege removal

AI-assisted triage

Yet most organizations cannot clearly explain:

Why a signal is trusted

When automation is justified

What degradation invalidates trust

Who revalidates assumptions over time

DFS is a structured model for designing, validating, and governing trust in automated security decision systems.

It transforms implicit confidence into explicit trust boundaries.

Why This Matters Now

Security systems are becoming:

More automated

More AI-assisted

More abstracted

More dependent on complex telemetry pipelines

At the same time:

Telemetry silently degrades

Schemas evolve

Privacy controls alter signal semantics

Risk engines become probabilistic inputs to deterministic automation

Without explicit degradation modeling, automation scales both confidence and error.

DFS exists to ensure automation scales responsibly.

The Core Model

DFS models degradation across three domains:

Loss

Signal missing, delayed, or incomplete.

Distortion

Signal survives but semantic meaning changes.

Drift

Assumptions decay over time as systems and behaviors evolve.

These domains define explicit Trust Decision Boundaries.

If degradation is unbounded, automation eligibility must be restricted.

→ See: docs/core-model.md

Automation Governance Model

DFS introduces governance tiers for automated actions:

Tier 1 — Eligible for Automation

Tier 2 — Human-Assisted Automation

Tier 3 — Contextual Only

Automation is not a capability decision.
It is a trust decision.

→ See: docs/automation-governance-model.md

Testing & Validation

Degradation must be continuously tested.

DFS defines validation strategies for:

Telemetry completeness (Loss)

Schema and semantic stability (Distortion)

Assumption revalidation (Drift)

Trust decays unless actively maintained.

→ See: docs/core-model.md (Domain Testing Strategies)

Applied Examples

DFS includes structured real-world scenarios across:

IAM automation

MFA fatigue detection

OAuth abuse

Impossible travel

EDR auto-isolation

Incident-based drift analysis

Each example models:

Degradation profile

Trust boundary

Governance tier

Validation requirements

→ See: examples/

How to Apply DFS in 30 Minutes

Select one automated detection or response.

Model its Loss, Distortion, and Drift exposure.

Declare the Trust Decision Boundary explicitly.

Assign a Governance Tier.

Define revalidation triggers.

Document assumptions.

If you cannot explain when automation becomes unsafe, trust is implicit.

DFS makes it explicit.

Executive Interpretation

DFS helps security leaders answer:

Where are we over-trusting automation?

Which detections are unsafe to auto-respond?

Where does telemetry loss create blind spots?

Which alerts truly require human judgment?

What decision risk are we carrying invisibly?

DFS does not replace tooling.
It governs how tooling is trusted.

What DFS Is

An engineering model for detection trust

A governance framework for automation eligibility

A shared language between engineers and leadership

A method to make detection debt visible

What DFS Is Not

A SIEM product

A tuning methodology

A scoring gimmick

A replacement for human judgment

DFS clarifies when human judgment is required.

Roadmap

Future development areas include:

Quantitative fidelity modeling

SOC maturity-aligned governance thresholds

MITRE ATT&CK alignment

CI-based trust regression

AI-agent autonomy constraints

DFS evolves deliberately and versioned.

→ See: docs/evolution-and-versioning.md

Attribution

Detection Fidelity Score (DFS)
Originally formulated and maintained by Gustavo Okamoto.

DFS is designed for long-term structural clarity, not trend cycles.

Trust must not be assumed.
It must be engineered.
