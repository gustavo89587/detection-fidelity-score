# Linux auditd – Suspicious Process Execution
Detection Pack v0.1 (DFS-aligned)

---

## 1. Detection Hypothesis

Adversaries frequently execute suspicious processes using:

- shells spawned from unusual parents
- encoded payload execution
- credential dumping tooling
- LOLBins and living-off-the-land patterns

This detection models:

Linux process execution telemetry (auditd / execve)
where command-line and parent-child lineage indicate high-risk behavior.

---

## 2. Operational Intent

Tier: High-Confidence Escalation  
Action: SOC investigation (not auto-block)

This detection does NOT authorize automatic containment.

---

## 3. Telemetry Dependencies

Required telemetry:

- auditd enabled
- execve events (e.g., SYSCALL + EXECVE args)
- user identity (uid/euid/auid)
- parent process (ppid) and process name (comm/exe)
- full command-line args (a0..aN) where available

Optional enrichment:

- host criticality tier
- baseline for admin tooling
- package manager activity / service accounts
- container context (namespace/cgroup metadata)

---

## 4. Detection Logic (Abstracted)

Trigger when:

- execve occurs
AND one or more of:

- suspicious shell from unusual parent (e.g., nginx/apache/java -> /bin/sh)
- command-line contains high-risk patterns:
  - "curl|wget" piped into "sh|bash"
  - base64 decode + execution
  - "python -c" inline payload
  - "chmod +x" on temp paths followed by execution
- user context is anomalous (service account or unexpected interactive)

AND parent process not in approved baseline

---

## 5. Trust Decision Boundary (TDB)

This alert authorizes:

Escalation to Tier-2 SOC

It does NOT authorize:

- host isolation
- service shutdown
- automated kill signals

Confidence Required: ≥ Medium-High

If args visibility is partial, TDB is downgraded.

---

## 6. Degradation Model (DFS)

### 6.1 Loss

Signal disappears if:

- auditd disabled or not persistent
- execve args not captured
- logs not forwarded from critical hosts

Impact:
Blindness to command-level semantics and parent-child chains.

Severity: Critical

---

### 6.2 Distortion

Signal altered if:

- args truncated (buffer limits)
- escaping/quoting normalization changes meaning
- container boundary hides true parent lineage

Impact:
Silent false negatives and broken intent classification.

Severity: High

---

### 6.3 Drift

Adversary evolution examples:

- using less obvious LOLBins (python/perl/ruby variations)
- shifting to fileless execution methods or indirect loaders
- staging via systemd timers / cron / at jobs

Impact:
Detection precision decays unless behavior model is updated.

Severity: Medium → High (time dependent)

---

## 7. Analyst Cost Profile

Expected Analyst Effort: Medium

Cost drivers:

- legitimate admin automation resembles adversary tradecraft
- service accounts performing updates/deploys
- containerized workloads obscure context

Review FP surface monthly in high-change environments.

---

## 8. Validation Protocol

Before production:

- simulate:
  - curl|sh
  - base64 decode + exec
  - suspicious parent->shell chain
- simulate benign:
  - standard deploy scripts
  - package updates (apt/yum)
- test telemetry failures:
  - missing args
  - truncated args
  - missing parent lineage

If not measurable → not production-ready.

---

## 9. Survivability Score (Experimental)

Baseline environment:
Signal Strength: 0.78  
Telemetry Stability: 0.62  
Behavioral Robustness: 0.70  

DFS = 0.78 × 0.62 × 0.70 = **0.339**

Interpretation: Fragile (telemetry hardening + baseline needed)

---

## 10. Governance Metadata

Detection Owner: Detection Engineering  
Review Cycle: Monthly (high drift environments)  
Criticality Tier: Tier 2  
Automation Level: Assisted (Human in loop)

---

## 11. Key DFS Observations

This detection demonstrates:

- high dependency on semantic args
- moderate drift pressure (fast-changing tradecraft)
- strong operational value when telemetry is stable

Detection reliability must be engineered, not assumed.
