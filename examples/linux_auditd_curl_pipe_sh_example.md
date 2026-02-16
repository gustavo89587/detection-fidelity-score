# Linux auditd — curl | sh style execution (DFS example)

## 1) Detection hypothesis
A surprisingly common “real-world bad day” pattern:
- `curl ... | sh`
- `wget ... -O- | sh`
- or download → pipe → execute

I’m modeling **process execution + network fetch + shell** as a chained decision.

## 2) Operational intent
- **Tier:** Medium-high confidence escalation
- **Action:** Investigate quickly (triage + confirm)
- **Not authorized:** auto-containment (unless host is high criticality + corroborating signals)

## 3) Telemetry dependencies
**Required**
- auditd exec events (`execve`)
- command-line / argv capture (or equivalent)
- parent/child relationship

**Optional**
- DNS/HTTP logs (egress)
- package manager baselines
- known automation tooling allowlist

## 4) Detection logic (abstract)
Trigger when an execution matches any:
- `curl` AND (`| sh` OR `bash -c` OR `sh -c`)
- `wget` AND (`-O-` OR stdout) AND pipe to shell
- `bash -c` where the string contains `curl`/`wget` fetch + execute

Add context gates:
- user is not in a known automation account list
- host is not in CI/CD runner baseline
- executed from unusual directory (eg `/tmp`, `/dev/shm`)

## 5) Trust Decision Boundary (TDB)
This alert authorizes:
- escalation + collection (process tree, command history, recent network)

It does NOT authorize:
- blocking shell globally
- nuking the box

If I don’t have argv fidelity, I **downgrade** to “suspicious behavior” not “confirmed chain”.

## 6) Degradation model (DFS)

### Loss
- auditd not deployed / misconfigured
- exec events sampled or dropped

Impact: blind.

Severity: **Critical**

### Distortion
- argv capture truncated
- wrapper scripts hide the real command
- aliased binaries (curl → busybox)

Impact: silent false negatives.

Severity: **High**

### Drift
- attacker avoids pipes (download to file then execute)
- uses python/perl one-liners instead of curl/wget
- shifts to signed tooling + living off the land

Impact: precision decays.

Severity: **Medium → High**

## 7) Analyst cost
Expected effort: **Medium**
False positives usually come from:
- bootstrap scripts
- devops automation
- internal tooling that “looks sketchy”

So: baseline first, then confidence.

## 8) Validation protocol
- run benign install scripts in a dev host (baseline)
- simulate malicious fetch (test box)
- test without argv (what do we lose?)
- test on CI runner images (FP surface)

If I can’t quantify degradation, I’m not engineering — I’m hoping.

## Final note
This detection is only strong when it can **survive**:
- missing data
- corrupted arguments
- behavior shifts

DFS keeps me honest about that.
