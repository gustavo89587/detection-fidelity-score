Detection Design Standard (DDS) v1. 0

All detection must follow this mandatory framework.

1. Hypothesis (Behavioral)

Describe in one sentence:

What behavior is being modeled

What operational risk represents

At what stage of the kill chain does it fit

Format:

An actor performs [behavior] for [adversary objective], generating observable artifacts in [telemetry].

2. Telemetry Requirements

Explicitly state:

Source (Sysmon / Security / EDR / etc.)

Event IDs

Critical fields (without them detection is invalid)

Separate:

Required fields

Optional enrichment fields

3. Detection Logic

Pseudocode or Sigma/KQL / ES|QL

Formal condition

Explicit exclusions

Avoid implicit logic.

4. False Positive Surface

Map:

Legitimate scenarios

Known Softwares

Administrative proceedings

Specific corporate environments

Add:

Mitigation Strategy:

Contextual filter

Parent-child validation

User scope restriction

5. Adversarial Drift Model

Describe:

How the attacker can bypass

What alternative LOLBins

What simple changes would break the rule

Create if necessary:

Detection siblings

6. Trust Decision Boundary

Explicitly state:

What does this detection authorize to do?

Alert?

Stagger?

Block?

Just hunting?

Define Tier:

T0-Observational

T1-Alert Only

T2-Escalation Required

T3-Contextual Investigation

T4-Automated Response Eligible

7. Degradation Profile (Fidelity Risk)
Loss

When can the signal disappear?

Distortion

When can the sign change semantically?

Drift

How does behavior evolve?

8. Validation Protocol

Define:

How to test

What event expected

Which field should exist

PASS criterion

FAIL criterion

No reproducible test → no valid detection.

9. Governance Metadata

Owner

Review cadence (ex: 30 days)

Last validation

Technical dependencies
