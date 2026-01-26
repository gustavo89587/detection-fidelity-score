# Detection Fidelity Score (DFS)

## Core Model: Loss, Distortion, Drift

DFS positions detection engineering as **both an engineering discipline and an architecture-of-trust problem**. It evaluates how detection systems behave when exposed to real-world constraints, rather than ideal conditions.

The core question DFS asks is:

> *How does this detection degrade — and can we predict, measure, and reason about that degradation before it causes harm?*

DFS models degradation across **three failure domains**: **Loss**, **Distortion**, and **Drift**.

---

## 1. Loss — When the signal disappears or arrives too late

**Loss** describes failures where detection-relevant information is **missing, delayed, or incomplete**.

This includes:

* Telemetry drops
* Parsing failures
* Rate limiting and backpressure
* Queue overflows
* Latency that invalidates detection windows
* Partial enrichment failures

Loss is primarily a **pipeline integrity problem**.

### Why Loss matters

A detection cannot reason about behavior it never sees. Loss failures are dangerous because they often remain **silent** — no alert fires, and no error is raised.

DFS treats Loss as a **measurable engineering risk**, not an operational accident.

---

## 2. Distortion — When the signal survives but loses meaning

**Distortion** occurs when telemetry still flows, but **semantic meaning is altered** enough to weaken or break detections.

This includes:

* Field redaction or truncation
* Pseudonymization altering join behavior
* Schema normalization inconsistencies
* Minor formatting or casing changes
* Field-order assumptions
* Overly brittle pattern matching

Distortion reveals **detection fragility**.

### Why Distortion matters

A distorted signal may still trigger alerts, but at reduced confidence, increased noise, or misleading context. This is where false positives, analyst fatigue, and mis-triage accumulate.

DFS evaluates whether detections are **robust to reasonable variation**, not whether they only work under perfect formatting.

---

## 3. Drift — When the world changes underneath the detection

**Drift** describes failures caused by **environmental or semantic change**, even in the absence of an attacker.

This includes:

* Schema evolution
* Attribute renaming
* Default behavior changes
* Collector / agent upgrades
* Vendor-side telemetry changes
* Implicit assumptions baked into rules

Drift is a **time-based trust failure**.

### Why Drift matters

Detections often fail not because they were wrong, but because their assumptions were never made explicit. Drift exposes detections that rely on **unstated contracts** with upstream systems.

DFS measures how tightly a detection is coupled to unstable semantics.

---

## The DFS Degradation Model

```
        ┌───────────────┐
        │   Telemetry   │
        └───────┬───────┘
                │
        ┌───────▼───────┐
        │   Pipeline    │
        │ (Transforms)  │
        └───────┬───────┘
                │
     ┌──────────▼──────────┐
     │   Detection Engine  │
     └──────────┬──────────┘
                │
        ┌───────▼───────┐
        │    Alerting   │
        └───────────────┘

Loss       → signal never reaches detection
Distortion → signal reaches detection with degraded meaning
Drift      → detection assumptions decay over time
```

Each domain answers a different trust question:

* **Loss:** *Can I trust that the signal exists?*
* **Distortion:** *Can I trust what the signal means?*
* **Drift:** *Can I trust that this meaning will remain stable?*

---

## DFS as Engineering + Trust Architecture

From an **engineering perspective**, DFS:

* Treats detection as a system under load and constraint
* Makes degradation observable and testable
* Encourages resilient, explicit design

From a **trust architecture perspective**, DFS:

* Defines when a signal deserves human or automated action
* Makes hidden assumptions visible
* Prevents silent erosion of confidence

DFS does not judge detections as "good" or "bad". It maps **where trust holds — and where it does not**.

---

## What DFS Produces

Rather than a single score, DFS yields:

* A **degradation profile** across Loss, Distortion, and Drift
* Identified failure modes
* Explicit trust boundaries
* Engineering guidance on where robustness matters most

---

## Closing Principle

> Detection systems should degrade **predictably and measurably**, not silently.

DFS exists to ensure that trust in detection is **designed, not assumed**.
