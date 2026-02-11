DFS Core Model
Overview

The Detection Fidelity Score (DFS) models how detection systems degrade under real-world constraints.

Degradation is not accidental.
It follows structural patterns.

DFS formalizes these patterns into three primary failure domains:

Loss

Distortion

Drift

These domains define how detection trust degrades over time and under operational stress.

Formal Definitions
1. Loss

Definition

Loss is degradation caused by the absence, delay, truncation, or incompleteness of required telemetry or signal components.

Loss occurs when the detection no longer receives the data it assumes exists.

Characteristics

Missing events

Delayed ingestion

Field truncation

Pipeline drops under load

Agent disconnection

Structural Property

Loss affects signal presence, not meaning.

The detection logic may remain correct —
but the underlying evidence becomes partially or fully unavailable.

Trust Impact

Absence of alerts becomes unreliable

Negative assertions (“nothing happened”) cannot be trusted

Automation based on silence becomes unsafe

2. Distortion

Definition

Distortion is degradation caused by semantic alteration of telemetry without corresponding adaptation of detection logic.

Distortion occurs when the signal survives —
but its meaning changes.

Characteristics

Field normalization changes

Redaction for privacy

Encoding transformations

Schema remapping

Parsing inconsistencies

Structural Property

Distortion affects signal meaning, not existence.

The detection continues to run —
but interprets altered semantics.

Trust Impact

Increased false positives or false negatives

Higher analyst cognitive burden

Inconsistent triage outcomes

Hidden degradation masked as “noise”

3. Drift

Definition

Drift is degradation caused by evolving environmental, behavioral, or architectural assumptions that are not revalidated over time.

Drift occurs when detection logic remains static while its operating context changes.

Characteristics

Adversary tradecraft evolution

Platform updates

Telemetry schema changes

Default behavior modifications

Infrastructure redesign

Structural Property

Drift affects assumptions, not immediate signal quality.

The detection appears functional —
but its validity decays silently.

Trust Impact

Gradual loss of relevance

Undetected blind spots

False confidence in outdated coverage

Long-term erosion of detection integrity

Interaction Between Domains

These domains are independent but compounding:

Loss can mask Drift.

Distortion can amplify Analyst Cost.

Drift can remain invisible without periodic Loss/Distortion testing.

DFS does not treat degradation as binary failure.

It treats degradation as bounded trust erosion.

Core Principle

Detection systems do not fail at once.
They degrade across Loss, Distortion, and Drift.

DFS exists to:

Identify which domain is active

Make trust boundaries explicit

Enable deliberate engineering response

Engineering Implication

Any detection system claiming robustness should be able to answer:

What forms of Loss are acceptable?

What semantic distortions are tolerated?

How is Drift detected and revalidated?

If these cannot be articulated, trust is assumed — not engineered.
