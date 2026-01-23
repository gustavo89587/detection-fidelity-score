# Detection Fidelity Score (DFS)

## Why this exists

Many of the problems we label as **SOC fatigue**, **brittle detections**, or **insecure automation** are not tooling failures. They are symptoms of the same structural issue: **trust decisions made without explicit, shared criteria**.

At scale, organizations routinely ask humans and systems to act on signals whose **fidelity, intent, and downstream cost** were never clearly assessed. The result is invisible debt — analysts absorb it as fatigue, and organizations absorb it as risk.

This repository introduces the **Detection Fidelity Score (DFS)** as a *lens* for reasoning about trust, attention, and action in detection systems.

> **The issue isn’t control vs innovation — it’s the lack of explicit criteria for trust.**

---

## What this is (and is not)

**DFS is:**

* A conceptual framework to reason about detection quality
* A way to make detection debt visible
* A shared language between engineers, SOC analysts, and leadership

**DFS is not:**

* A SIEM feature or product
* A replacement for threat modeling or analyst judgment
* A silver bullet for alert fatigue

---

## The core problem

Detection systems tend to fail in two opposite but equally damaging ways:

1. **Rigidity** — when innovation challenges existing frameworks, systems become defensive and blind to new approaches.
2. **Subjectivity** — when detections are built and tuned based on intuition, habit, or inherited rules rather than explicit criteria.

Both lead to the same outcome: **unclear trust boundaries**. Alerts are generated without a shared understanding of what truly deserves human attention or automated action.

---

## Detection fidelity as a model

Detection Fidelity is not about volume reduction. It is about **decision quality**.

A high‑fidelity detection:

* Clearly represents adversary behavior
* Minimizes overlap with benign activity
* Improves analyst decision‑making rather than consuming it

A low‑fidelity detection may still trigger often, but it does so at a high **human and organizational cost**.

---

## Core dimensions

DFS evaluates detections across several conceptual dimensions:

* **Signal Clarity** — How clearly does the signal indicate malicious or high‑risk behavior?
* **Noise Overlap** — How often does benign activity resemble this signal?
* **Analyst Cost** — What cognitive, temporal, and emotional effort is required to triage it?
* **Actionability** — Does the alert meaningfully inform a decision or response?

These dimensions are intentionally qualitative first. Precision without understanding only accelerates bad decisions.

---

## How to think with DFS

DFS is meant to guide questions, not enforce answers:

1. What decision is this detection asking a human or system to make?
2. What evidence supports that decision?
3. What is the cost if this signal is wrong — and who pays it?
4. Should this ever page a human, or remain contextual only?

If these questions cannot be answered clearly, fidelity is likely low — regardless of alert volume.

---

## Why this matters beyond the SOC

The same trust failures appear in:

* Automated response pipelines
* Agent‑based AI workflows
* Open‑source ecosystems with implicit trust

When criteria for trust are implicit, systems scale faster than discernment. DFS provides a way to reason about *when* trust is earned — before humans or autonomous systems are forced to act.

---

## A lens, not a solution

DFS does not aim to eliminate alert fatigue or prevent every failure. Its purpose is to:

* Make tradeoffs explicit
* Shift conversations from volume to fidelity
* Re‑center detection engineering around human impact

---

## Open questions

This work is intentionally incomplete. Open areas include:

* How should fidelity be measured quantitatively without losing nuance?
* How do different SOC models change acceptable fidelity thresholds?
* Where should automation stop and human judgment begin?

Thoughtful disagreement and real‑world feedback are encouraged.

---

## Closing thought

Detection systems do not fail because people are careless. They fail because trust is assumed instead of designed.

Making fidelity explicit is the first step toward systems that scale without burning the humans inside them.
