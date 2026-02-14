# Detection Pack (v0.1)

This pack contains structured detection artifacts compliant with the Detection Design Standard (DDS).

---

## Reference Detection (DDS-Compliant)

### DFS-PS-ENC-DL-001  
Suspicious PowerShell Encoded Command with Download Primitive

This detection models adversarial PowerShell execution using encoded payloads combined with network staging behavior.

---

### Artifacts

- Detection Rule → `detection.yml`
- Fidelity Model → `dfs.yml`
- Test Cases → `tests/`

---

## Validation Flow

To validate this detection:

1. Execute atomic simulation (see `tests/atomic.md`)
2. Confirm expected event structure (see `tests/expected.md`)
3. Apply PASS/FAIL gate criteria (see `tests/validation.md`)

---

## Trust Decision Tier

T2 – Escalation Required

This detection models high-risk execution behavior prone to legitimate automation noise.
Escalation requires contextual analysis.

---

## Compliance

This pack follows:

`standards/Detection_Design_Standard_v1.md`

All detections must declare:

- Hypothesis
- Telemetry Requirements
- Trust Decision Boundary
- Degradation Profile
- Validation Protocol
)
