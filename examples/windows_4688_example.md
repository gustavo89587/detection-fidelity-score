# Windows 4688 – Suspicious Process Creation
Detection Pack v0.1 (DFS-aligned)

---

## 1. Detection Hypothesis

Adversaries often execute suspicious processes using command-line arguments
that indicate credential dumping, encoded payload execution, or LOLBin abuse.

This detection models:

Process creation events (Windows Event ID 4688)
where command-line contains high-risk execution patterns.

---

## 2. Operational Intent

This detection is designed to authorize:

Tier: High-Confidence Escalation  
Action: SOC investigation (not auto-block)

This rule does NOT authorize automatic containment.

---

## 3. Telemetry Dependencies

Required telemetry:

- Windows Security Log
- Event ID 4688
- Full CommandLine field enabled
- ProcessName
- ParentProcessName
- User context

Optional enrichment:

- Host criticality tier
- Known admin tooling baseline
- Process hash intelligence

---

## 4. Detection Logic (Abstracted)

Trigger when:

EventID = 4688  
AND CommandLine contains one or more of:

- " -enc "
- "FromBase64String"
- "mimikatz"
- "rundll32 .* comsvcs.dll"
- "regsvr32 /s /n /u /i:http"

AND ParentProcess not in approved baseline

---

## 5. Trust Decision Boundary (TDB)

This alert authorizes:

Escalation to Tier-2 SOC

It does NOT authorize:

- Host isolation
- Credential reset
- Containment

Confidence Level Required: ≥ Medium-High

If CommandLine telemetry is missing or truncated,
Trust Boundary is automatically downgraded.

---

## 6. Degradation Model (DFS)

All detections degrade.

This detection degrades across three domains:

### 6.1 Loss

Signal disappears if:

- CommandLine logging disabled
- 4688 not forwarded
- Audit policy misconfigured

Impact:
Detection becomes blind to encoded payload execution.

Severity: Critical

---

### 6.2 Distortion

Signal altered if:

- CommandLine truncated
- Encoding normalized
- Unicode obfuscation bypasses string matching

Impact:
False negatives increase silently.

Severity: High

---

### 6.3 Drift

Adversary evolution examples:

- Switching to indirect execution
- Using renamed binaries
- Living-off-the-land variants not in keyword set

Impact:
Detection precision decays over time.

Severity: Medium → High (time dependent)

---

## 7. Analyst Cost Profile

Expected Analyst Effort: Medium

Drivers of cost:

- Admin scripts using encoded PowerShell
- IT automation tasks
- Red team activity overlap

False positive surface must be reviewed quarterly.

---

## 8. Validation Protocol

Before production deployment:

- Simulate encoded PowerShell execution
- Simulate benign admin encoded script
- Test behavior with truncated CommandLine
- Test telemetry drop scenario

Detection must document:

- Survival rate under 10% log loss
- FP rate in admin baseline environment
- Behavior under partial truncation

If not measurable → not production-ready.

---

## 9. Survivability Score (Experimental)

Baseline environment:
Detection Confidence: 0.82

Under 20% CommandLine truncation:
Detection Confidence: 0.54

Under full CommandLine loss:
Detection Confidence: 0.12

This detection is highly dependent on semantic telemetry integrity.

---

## 10. Governance Metadata

Detection Owner: Detection Engineering  
Review Cycle: Quarterly  
Criticality Tier: Tier 2  
Automation Level: Assisted (Human in loop)

---

## 11. Key DFS Observations

This rule demonstrates:

- High Distortion sensitivity
- Medium Drift risk
- High Loss impact

It should not be treated as static coverage.

It must be continuously revalidated.

---

## Final Note

This is not a keyword detection.

It is a decision system with:

- Declared trust boundary
- Explicit degradation model
- Operational cost profile
- Governance lifecycle

Detection reliability must be engineered — not assumed.
