# Windows 4688 Fidelity Case — PowerShell / LOLBin (Full vs Degraded Context)

This is the kind of scenario that keeps showing up in real SOC life:
PowerShell is *not* inherently malicious — but it's one of the fastest paths from "normal activity" to "high-risk decision".

My goal here is simple:
**show that the same technically-correct detection can be decision-safe or decision-fragile depending on context.**

---

## Why 4688 matters

Windows Security Event **4688** (Process Creation) is often the first line of evidence for:
- LOLBins (PowerShell, mshta, rundll32, regsvr32, wmic, etc.)
- initial execution from phishing docs
- hands-on-keyboard activity

But 4688 only supports a *decision* when the context is present.

---

## Case A — Full Context (Decision-Supporting)

Below is a realistic 4688-style payload (simplified/normalized).

### 4688 (Full)
``json
{
  "event": {
    "code": 4688,
    "provider": "Microsoft-Windows-Security-Auditing",
    "action": "process-start",
    "outcome": "success"
  },
  "host": { "name": "WS-0231", "os": { "type": "windows" } },
  "user": { "domain": "CORP", "name": "jdoe" },
  "process": {
    "pid": 5148,
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "name": "powershell.exe",
    "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
    "parent": {
      "pid": 3892,
      "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "name": "WINWORD.EXE",
      "command_line": "\"WINWORD.EXE\" /n \"C:\\Users\\jdoe\\Downloads\\invoice.docm\""
    }
  },
  "winlog": {
    "event_data": {
      "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
      "CreatorProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "TokenElevationType": "%%1938"
    }
  }
}

My decision thinking (why this supports action)

This one is decision-supporting because:

Intent is visible: -EncodedCommand, hidden window, no profile

Causality exists: WINWORD.EXE → powershell.exe

User context exists: I can assess if jdoe is expected, role, baseline

Operational clarity: I can scope quickly (doc path, parent cmdline)

Even if this is a false positive in some edge environment, I can still make a safe call:

isolate host? maybe

kill process? likely

escalate? yes
Because the signal carries enough context to justify a decision.

Case B — Degraded Context (Decision-Fragile)

Now the same "powershell started" event, but with realistic loss:

command-line is missing/redacted

parent relationship is missing (or not trustworthy)

key fields are partially suppressed

4688 (Degraded)
{
  "event": {
    "code": 4688,
    "provider": "Microsoft-Windows-Security-Auditing",
    "action": "process-start",
    "outcome": "success"
  },
  "host": { "name": "WS-0231", "os": { "type": "windows" } },
  "user": { "domain": "CORP", "name": "jdoe" },
  "process": {
    "pid": 5148,
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "name": "powershell.exe",
    "command_line": null,
    "parent": {
      "pid": null,
      "executable": null,
      "name": null,
      "command_line": null
    }
  },
  "winlog": {
    "event_data": {
      "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "[REDACTED_OR_MISSING]",
      "CreatorProcessName": "[MISSING]"
    }
  }
}

My decision thinking (why this is risky)

This is still a correct detection (PowerShell started).
But it becomes decision-fragile because:

I can’t see intent (encoded? download cradle? benign admin script?)

I can’t see causality (what launched it? doc? explorer? service? scheduler?)

I lose the fastest path to scoping (parent chain + arguments)

automation/agents become dangerous here: they’ll “act confident” while the signal isn’t

So the question becomes:

Do I trust this enough to automate response?

In many environments, the honest answer is no.
This is where “confidence” becomes a liability.

Where DFS fits (conceptual)

Both cases can fire the same rule:

process.name: powershell.exe (or LOLBin list)

But the decision-supporting quality is not the same.

What I care about operationally is:

Does the signal sustain action?

Does it survive context loss (redaction/partial telemetry)?

That’s what I mean by fidelity.

Practical outcomes (what I would do)
Full Context

Escalate quickly

Correlate with script block logs (if available), AMSI, network, file writes

Consider containment if the chain looks like phishing → execution

Degraded Context

Do not let automation overreact

Attempt to recover context (EDR telemetry, process tree, Sysmon, PS logs)

Increase evidence requirements before action

Next: turn this into measurable scoring

This doc is intentionally “close to the ground”.
Next steps to make it measurable:

define required context for decision safety (command-line, parent, user, integrity, network)

quantify survivability under redaction

map missing context → decision risk

That becomes the DFS scoring layer.
