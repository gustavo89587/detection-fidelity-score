MFA Fatigue Detection Auto-Account Lock
Context

Detection Name: mfa_fatigue_pattern

Trigger condition:

Multiple MFA push requests sent to a user within a short time window, followed by eventual approval.

Common automated response:

Immediate account lock

Session revocation

Forced credential reset

This detection gained relevance with push-based MFA abuse.

Why It Is Considered High Value

MFA fatigue attacks indicate:

Credential compromise

Social engineering pressure

Real-time adversary presence

High urgency.
High impact.
Strong intuition for automation.

Degradation Profile
Loss

Dependencies:

MFA provider logs

Push request telemetry

Approval metadata

Session correlation data

Loss conditions:

Delayed MFA log ingestion

Missing failed push attempts

Partial logging from mobile client

Push denial events not captured

Implication:

Attack may occur without detection.

Silence cannot be trusted without telemetry completeness validation.

Distortion

Dependencies:

User push behavior baseline

Push retry handling

Mobile device network stability

Distortion conditions:

User accidentally tapping approve

Network retry causing duplicate push

Accessibility tools triggering repeated requests

Legitimate session refresh loops

Signal survives.
Meaning shifts.

Not every repeated push equals adversary coercion.

Drift

Assumptions:

Push-based MFA remains standard

User behavior patterns remain stable

Attack patterns remain repetitive

Drift conditions:

Adoption of number-matching MFA

Transition to passkeys

Changes in MFA UX

Adversary adapting to slower push cadence

Detection effectiveness decays over time.

Trust Decision Boundary

Implicit boundary:

Repeated push → Auto-lock

DFS boundary:

Auto-lock qualifies for Tier 1 only when:

Repeated push + suspicious IP

Repeated push + impossible travel

Repeated push + new device fingerprint

Standalone fatigue pattern:

Tier 2 by default.

Governance Tier Assignment

Default: Tier 2 — Human-Assisted Automation

Eligible for Tier 1 only with multi-signal correlation.

Validation Strategy

Loss:

Monitor MFA event completeness

Validate push logging integrity

Alert on ingestion gaps

Distortion:

Track false-positive rate

Validate UX-related retry patterns

Measure accidental approval frequency

Drift:

Reassess after MFA UX changes

Review after authentication architecture shifts

Key Insight

MFA fatigue is behaviorally strong.

But automation based solely on repetition can punish victims.

DFS prevents coercion signals from becoming deterministic disruption.
