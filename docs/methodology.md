# Detection Fidelity Score — Methodology

## Objective

To objectively measure how privacy-preserving transformations affect detection effectiveness, correlation, and coverage.

The goal is not to maximize detection or minimize data, but to **understand system behavior under constraint**.

---

## Experimental model

### Fixed elements
- Telemetry source
- Detection engine
- Detection rules
- Evaluation window

### Variable element
- Telemetry pipeline

Two pipelines are evaluated:
1. **Raw baseline pipeline**
2. **Privacy-preserving pipeline** (redaction, pseudonymization, transformation)

Any difference in detection output is attributed to the pipeline.

---

## Assumptions

- Detections depend on **fields, not raw truth**
- Privacy transformations are **deterministic where correlation is required**
- Some loss is acceptable — *unmeasured loss is not*

---

## Measurement approach

### Step 1: Establish baseline
- Run detections over raw telemetry
- Record alerts, timestamps, correlations

### Step 2: Apply privacy transformations
- Redact or pseudonymize selected fields
- Preserve identifiers required for correlation
- Normalize fields consistently

### Step 3: Re-run detections
- Same rules
- Same time window
- Same evaluation criteria

---

## What is measured

- Alert count differences
- Detection recall per ATT&CK technique
- Rule survivability
- Correlation completeness
- Field-level impact

---

## What is explicitly NOT measured

- Incident severity
- Analyst decision quality
- Threat intelligence accuracy
- Business impact

DFS evaluates **detection mechanics**, not SOC outcomes.

---

## Interpretation guidelines

- A detection breaking does not mean privacy failed
- A detection surviving does not mean it is well-designed
- High field dependency indicates **design fragility**
- Stable detections under constraint indicate **robust engineering**

---

## Limitations

- DFS does not model attacker adaptation
- DFS does not replace threat modeling
- Results are environment-specific

DFS is a **lens**, not a verdict.

---

## Design principle

> Detection systems should degrade **predictably and measurably**, not silently.

