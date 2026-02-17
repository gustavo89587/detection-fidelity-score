DFS SOC Implementation Playbook (v1.1)
Purpose

Translate DFS from conceptual framework into repeatable SOC practice.

DFS must not live only in documentation.
It must shape production detection engineering.

1️⃣ Pre-Production Gate (Detection Intake)

Before any detection reaches production:

Declare Trust Decision Boundary (TDB)

Score S, T, B

Document degradation exposure (Loss / Distortion / Drift)

Estimate analyst cost

Assign automation eligibility tier

If any of these are missing → detection is incomplete.

2️⃣ Automation Eligibility Matrix
DFS Score	Automation Policy
≥ 0.80	Eligible for controlled automation
0.60–0.79	Human validation required
0.40–0.59	Investigation-only
< 0.40	Redesign before deployment

Automation is earned, not assumed.

3️⃣ Telemetry Drift Review Cycle

Quarterly review:

Has telemetry changed?

Has normalization been modified?

Has redaction been introduced?

Has adversary behavior shifted?

Recalculate DFS if any dimension shifts.

4️⃣ Incident Review Integration

After major incidents:

Re-evaluate DFS score

Validate survivability assumptions

Adjust T or B if drift observed

Detection governance must be dynamic.

5️⃣ Detection Lifecycle States

Draft

Validated (DFS ≥ 0.60)

Production

Under Review (degradation observed)

Deprecated

DFS becomes lifecycle control, not static metric.
