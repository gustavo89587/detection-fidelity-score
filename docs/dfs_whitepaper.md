
---

## D) Whitepaper curto (estrutura vendável)

Crie `docs/dfs_whitepaper.md`:

```md
# Detection Fidelity Score (DFS) — Short Whitepaper

## 1. Problem
Detection is not finding activity.
Detection is making a **reliable decision under uncertainty**.

Modern SOC automation fails when it treats:
- partial context as complete truth
- correctness as actionability

## 2. Thesis
Observability > smartness.

If telemetry degrades, confidence must degrade — explicitly.

## 3. DFS Model
DFS evaluates three dimensions (S/T/B):
- Signal clarity (S): how visible intent is
- Telemetry completeness (T): how complete the context is
- Behavioral coherence (B): how well behavior supports a hypothesis

## 4. Survivability
DFS is designed for “survivability under redaction”:
- same event, less context → lower confidence
- obfuscation → clarity down, but behavior markers may remain

## 5. Guardrails
DFS recommends bounded action:
- Investigate
- Escalate
- Automate-Lite (low blast radius)
- Automate-Hard (containment)

## 6. Artifact: DecisionCard
DFS emits a portable DecisionCard:
- score
- action
- rationale
- penalties / notes

## 7. Practical cases
- Windows 4688 / Sysmon 1: command-line + parent chain
- PowerShell 4104: AMSI bypass / reflection under obfuscation
- CloudTrail IAM: high-risk identity actions with/without MFA context

## 8. Adoption path
Start as scoring-only (no action).
Then integrate as a policy gate before automation.
