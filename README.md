<div align="center">

# Detection Fidelity Score (DFS)

![Logo](assets/logo.png)

**Can this alert — or this AI agent action — safely drive automation?**

[![DFS Tests](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/gustavo89587/detection-fidelity-score/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](https://github.com/gustavo89587/detection-fidelity-score/blob/main/LICENSE)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Extractors](https://img.shields.io/badge/extractors-22-blueviolet)

</div>

---

## 🏛 OASIS CoSAI Alignment

The **Detection Fidelity Score (DFS)** is a reference framework designed to support the mission of the **Coalition for Secure AI (CoSAI)** under the OASIS Open consortium. It provides a standardized, interoperable metric for AI Risk Governance and Secure-by-Design Agentic Systems.

### Core Contribution Areas:
* **AI Security Risk Governance:** Standardizing how enterprises evaluate the safety of autonomous agent actions.
* **Secure Design Patterns for Agentic Systems:** Providing real-time guardrails and cryptographic liability proofs for AI tool execution.
* **Supply Chain Security:** Evaluating vulnerability exploitability through multi-dimensional telemetry (S×T×B).

---

## The Problem

Security teams and AI systems face two compounding crises:

- **Alert fatigue:** SOCs receive thousands of alerts per day. Most are noise.
- **Agent autonomy:** AI agents can now execute code and modify infrastructure without a standard for deciding *when* they should act alone vs. when a human must intervene.

DFS answers a critical question for modern governance:
> **"How much should I trust this event — enough to act on it automatically?"**

---

## How It Works: The S × T × B Model

Unlike additive scoring systems, DFS uses a multiplicative model. **If any dimension collapses to zero, the final score collapses**. This prevents "noisy but high-severity" events from triggering false automations.

| Dimension | Question | Core Metric |
|-----------|----------|-------------|
| **S** — Signal Clarity | How dangerous/significant is this event? | Impact & Severity |
| **T** — Telemetry | How complete/trustworthy is the data? | Provenance & Evidence |
| **B** — Behavioral Coherence | Does the full context hang together? | Policy & Logic |

$$
DFS = S \times T \times B
$$

### Decision Tiers (Actionable Outputs)

| DFS Score | Action | Governance Meaning |
|-----------|--------|--------------------|
| ≥ 0.78 | AUTOMATE | Secure-by-design autonomous execution |
| 0.55 – 0.78 | ESCALATE | Human-in-the-loop: Passive notification |
| 0.30 – 0.55 | TRIAGE | Human-in-the-loop: Active approval required |
| < 0.30 | BLOCK | Hard gate — Policy violation or insufficient trust |

---

## Agent Infrastructure & Compliance
DFS provides the enforcement layer required for audit-ready AI deployments:

* **🛡 Agent Firewall (Real-Time I/O Protection):** Application-layer protection that intercepts agent requests and responses. Enforces 6 built-in policies: PII Redaction, Secret Exfiltration, Destructive Commands, Goal Drift, Prompt Injection, and Unauthorized Code Execution.
* **📜 Liability Ledger (Audit-Ready Proofs):** Uses HMAC-SHA256 signatures to provide an immutable record of evaluated policies, telemetry state, and CoSAI mapping.
* **🔐 ABAC Action Tokens:** Zero-trust authorization for agents. Every sensitive tool call requires a cryptographically signed, time-bounded, single-use token.

### Supported Data Sources (Extractors)
DFS is interoperable across SIEMs, Cloud Providers, and AI Ecosystems:
* **SIEM/XDR:** Elastic SIEM, Splunk ES, Wazuh.
* **Endpoint:** Sysmon (1, 3), Windows Event Logs (4624, 4688), PowerShell (4104).
* **Cloud:** AWS (CloudTrail, GuardDuty), Azure (AD Sign-in), GCP (Audit, SCC).
* **AI/App:** Agent Action Protocol (OpenAI/Anthropic), CVE Context (EPSS/KEV/Reachable).
* **Physical:** Wi-Fi CSI (Gait/Intruder detection).

---

## Quick Start
```bash
git clone https://github.com/gustavo89587/detection-fidelity-score
cd detection-fidelity-score
pip install -e .
Run the unified test suite:

Bash
pytest tests/test_extractors.py -v
Roadmap & Community
[ ] RFC-001: S×T×B as a language-agnostic scoring specification.

[ ] Integration with OASIS CoSAI Workstreams.

[ ] SIEM Native Connectors (Sentinel, Splunk SOAR).

[ ] TypeScript/Go SDKs for cross-language guardrails.

Author: Gustavo Okamoto

License: Apache License 2.0 — Standard for OASIS Open projects.