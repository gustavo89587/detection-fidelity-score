OAuth Application Auto-Revocation Based on Risk Heuristic
Context

Detection Name: suspicious_oauth_grant

Trigger condition:

New OAuth application granted high-privilege scopes combined with heuristic risk score.

Automated action:

Immediate token revocation

App deletion

Admin notification

Why It Is Considered High Value

OAuth abuse enables:

Persistent API access

Data exfiltration

Mailbox scraping

Token replay

Automation appears logical.

Degradation Profile
Loss

Dependencies:

OAuth consent logs

Token issuance telemetry

Scope assignment visibility

App registration events

Loss conditions:

Partial consent logging

Missing token refresh telemetry

App deletion event not captured

Silence invalid if consent telemetry incomplete.

Distortion

Dependencies:

Risk scoring model

Scope classification logic

Third-party app categorization

Distortion conditions:

Legitimate internal integration flagged as suspicious

High-privilege scope misclassified

Newly approved SaaS integration appears anomalous

Signal meaning shifts.

Revocation may break business workflow.

Drift

Assumptions:

Scope risk weighting stable

SaaS ecosystem stable

Integration behavior predictable

Drift conditions:

Rapid SaaS adoption

New internal automation tools

Vendor scope definition changes

Detection slowly over-fires.

Trust Decision Boundary

Implicit boundary:

High-risk OAuth → Immediate revocation

DFS boundary:

Tier 2 default.

Tier 1 only if:

Known malicious app signature

Confirmed token abuse pattern

Privilege escalation evidence

Governance Tier

Default: Tier 2 — Human-Assisted

Key Insight

OAuth automation failures are not security failures.

They are governance failures under Distortion and Drift.

DFS forces proportional revocation logic.
