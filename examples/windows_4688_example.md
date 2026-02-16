# Windows Event ID 4688 — Suspicious Process Creation (DFS example)

> DFS mindset: this isn’t “a keyword rule”. It’s a decision boundary + survivability under telemetry degradation.

## 1) Detection hypothesis (what I’m modeling)
Adversaries often run suspicious processes with command-lines that hint at:
- encoded payload execution
- credential dumping tooling
- LOLBin abuse

So I’m modeling **process creation (4688)** where the **CommandLine** carries high-risk patterns.

## 2) Operational intent (what decision this alert authorizes)
- **Tier:** High-confidence escalation
- **Action:** Investigate (human-in-the-loop)
- **This does NOT authorize:** auto-block / isolation / credential reset

If I can’t defend that decision under pressure, the rule isn’t ready.

## 3) Telemetry dependencies (what can break me)
**Required**
- Windows Security Log
- Event ID 4688
- **Full CommandLine enabled**
- ProcessName, ParentProcessName, User

**Nice to have**
- Host criticality
- Admin tooling baseline
- Hash / reputation enrichment

## 4) Detection logic (abstract)
Trigger when:
- EventID = 4688
- AND CommandLine matches one or more:
  - ` -enc `
  - `FromBase64String`
  - `mimikatz`
  - `rundll32 .* comsvcs.dll`
  - `regsvr32 /s /n /u /i:http`
- AND ParentProcess is **not** in an approved baseline

## 5) Trust Decision Boundary (TDB)
This alert authorizes:
- escalate to Tier-2 SOC

This alert does NOT authorize:
- isolate host
- block process
- contain user

**If CommandLine is missing/truncated → downgrade confidence automatically.**

## 6) Degradation model (DFS)
All detections degrade. I track it in 3 buckets:

### 6.1 Loss (signal disappears)
Examples:
- CommandLine logging disabled
- 4688 not forwarded
- audit policy drift

Impact:
- blind to encoded payload execution

Severity:
- **Critical**

### 6.2 Distortion (signal semantics corrupted)
Examples:
- CommandLine truncation
- normalization changes
- unicode/zero-width tricks bypass string matching

Impact:
- false negatives creep in silently

Severity:
- **High**

### 6.3 Drift (attacker changes behavior)
Examples:
- indirect execution (no obvious keywords)
- renamed binaries / alternate LOLBins
- new variants not in the pattern set

Impact:
- precision decays over time

Severity:
- **Medium → High** (time-dependent)

## 7) Analyst cost profile (hidden price)
Expected effort: **Medium**

Main FP sources:
- encoded PowerShell in legit admin scripts
- IT automation overlaps
- red-team activity

So: baseline matters. If I don’t model baseline, I’m guessing.

## 8) Validation protocol (before prod)
I want proof, not vibes:

- simulate encoded PowerShell (malicious)
- simulate benign admin encoded script
- test with truncated CommandLine
- test telemetry drop scenario

I document:
- survival rate under 10% log loss
- FP rate in admin-heavy environment
- behavior under partial truncation

**If it’s not measurable → it’s not production-ready.**

## 9) Survivability (example numbers)
Baseline confidence: **0.82**  
With 20% CommandLine truncation: **0.54**  
With full CommandLine loss: **0.12**

Translation: this rule lives and dies by semantic telemetry integrity.

## 10) Governance metadata
- Owner: Detection Engineering
- Review: Quarterly
- Criticality: Tier 2
- Automation: Assisted (human in loop)

## Final note
This detection is a **decision system**:
- declared trust boundary
- explicit degradation model
- analyst cost awareness
- governance lifecycle

Detection reliability must be engineered — not assumed.
