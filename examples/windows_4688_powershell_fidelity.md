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
```json
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


