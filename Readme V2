Detection Fidelity Score (DFS)
A framework for engineering trust in detection systems

Detection Fidelity Score (DFS) is a framework for reasoning about how detections behave under real-world constraints.

Instead of asking “does this detection work?”, DFS asks:

Where does this detection degrade — and can we predict, measure, and reason about that degradation before it causes harm?

DFS treats detection as both:

an engineering system (pipelines, schemas, latency, failure modes), and

an architecture of trust (when a signal warrants human escalation or automated action).

DFS is intentionally not a product, a SIEM feature, or a prescriptive scorecard.

The DFS core model

DFS models degradation across three failure domains:

Loss — the signal is missing, delayed, or incomplete

Distortion — the signal survives but loses semantic meaning

Drift — the signal breaks as assumptions decay over time

Together, these domains define explicit trust boundaries in detection systems.

→ Full model: docs/core-model.md

What DFS produces

DFS does not produce a single magic number.

It produces:

A degradation profile across Loss, Distortion, and Drift

Concrete failure modes and their triggers

Explicit trust assumptions

Guidance on where robustness and verification matter most

This helps teams surface detection debt before it becomes alert fatigue, blind spots, or unsafe automation.

What DFS is (and is not)

DFS is:

A conceptual + technical framework

A shared language between detection engineers, SOC analysts, and leadership

A way to make implicit trust decisions explicit

DFS is not:

A SIEM replacement

A false-positive tuning playbook

A metric for analyst performance

DFS evaluates detection trustworthiness under degradation — not SOC effectiveness, which depends on staffing, process, and response design.

Example: one detection, three failure domains

Detection: Suspicious PowerShell execution with encoded commands

Loss

Telemetry dropped under endpoint CPU pressure

Command line truncated due to field length limits

Impact: Entire executions disappear from detection scope
Trust outcome: ❌ You cannot trust the absence of alerts

Distortion

Base64 content partially redacted for privacy

Normalization alters pattern matching

Impact: Inconsistent matches + reduced context
Trust outcome: ⚠️ Alerts demand higher analyst effort to interpret

Drift

Agent update changes field naming

Detection relies on implicit default parsing/normalization behavior

Impact: Detection silently stops matching
Trust outcome: ❌ Trust decays over time without visibility

DFS interpretation

This detection isn’t “bad” — its trustworthiness is conditional:

Unsafe under Loss

Fragile under Distortion

Unstable under Drift

DFS makes those conditions explicit — and therefore actionable.

First technical artifact: DFS result contract (MVP)

DFS starts with a shared result contract, not code.

DFS result (conceptual schema)
{
  "detection": "powershell_encoded_command",
  "environment": "endpoint_windows",
  "dfs": {
    "loss": {
      "risk": "high",
      "signals": ["telemetry_drop", "field_truncation"]
    },
    "distortion": {
      "risk": "medium",
      "signals": ["redaction", "normalization"]
    },
    "drift": {
      "risk": "high",
      "signals": ["schema_change", "implicit_defaults"]
    }
  },
  "trust_boundary": "contextual_only",
  "notes": "Do not page on absence; use for enrichment and correlation."
}


Why this matters:

Forces explicit reasoning

Enables tooling later without locking design early

Keeps trust boundaries visible to humans and automation

Design principle

Detection systems should degrade predictably and measurably — not silently.

DFS exists to ensure trust in detection is designed, tested, and maintained, not assumed.

Status

DFS is currently a framework and methodology, not a finished implementation.

Future work may include:

Automated Loss / Distortion / Drift testing

CI-based trust regression (“does this detection still mean what we think it means?”)

Comparative analysis across telemetry stacks and pipelines

Thoughtful disagreement and real-world feedback are encouraged.
