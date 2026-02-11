Detection Fidelity Score (DFS)
© 2026 Gustavo Okamoto
Licensed under Apache 2.0

        
        
        Detection Fidelity Score (DFS)
      Engineering trust in detection systems
                
                Detection Signal
                        │
                        ▼
        ┌─────────────────────────────┐
        │      Degradation Domains    │
        │                             │
        │   • Loss        (missing)   │
        │   • Distortion  (altered)   │
        │   • Drift       (decayed)   │
        └─────────────────────────────┘
                       │
                       ▼
            Trust Decision Boundary
                       │
                       ▼
           Human │ Automated │ Contextual
     Detection trust is not binary. It degrades.
        DFS makes that degradation measurable.



## Why this exists


Many of the problems labeled as SOC fatigue, brittle detections, or unsafe automation are not tooling failures.

They are structural failures of trust.

At scale, organizations ask humans and systems to act on signals whose evidence strength, ambiguity, and downstream cost were never made explicit.

Analysts absorb this as fatigue.
Organizations absorb it as risk.

The Detection Fidelity Score (DFS) introduces a simple but disciplined premise:

Trust in detection systems must be explicit, reasoned, and proportional to impact.

DFS exists to operationalize that premise.

The structural problem

Detection systems fail in two symmetrical ways:

1. Rigidity

When new telemetry, attacker behavior, or architectural change challenges legacy logic, systems become defensive. Rules persist without revalidation. Signal meaning erodes.

2. Subjectivity

Detections are built and tuned on intuition, habit, or inherited playbooks — without explicit decision criteria.

Both produce the same outcome:

Unclear trust boundaries.

Alerts are generated without a shared understanding of:

What decision they demand

Who should make it

What happens if it is wrong

This ambiguity scales faster than discernment.

Detection fidelity as a decision model

Detection Fidelity is not about reducing alert volume.

It is about improving decision quality per signal.

A high-fidelity detection:

Strongly represents adversary behavior

Minimizes benign overlap

Reduces cognitive friction during triage

Supports confident action

A low-fidelity detection may fire frequently —
but it does so by externalizing cost onto analysts and operations.

Volume is a metric.
Fidelity is a property of trust.

Core dimensions

DFS evaluates detections across four primary dimensions:

Signal Clarity — How strongly does the signal indicate malicious or high-risk behavior?

Noise Overlap — How frequently does legitimate activity resemble this signal?

Analyst Cost — What cognitive, temporal, and escalation burden does triage impose?

Actionability — Does this detection meaningfully change a decision or response path?

These dimensions are qualitative by design.

Precision without reasoning simply accelerates bad automation.

The operational question

Before a detection pages a human or triggers automation, DFS asks:

What decision is this detection demanding?

What evidence supports that decision?

What is the cost of being wrong — and who absorbs it?

Is automation justified at this fidelity level?

If these questions cannot be answered clearly, fidelity is likely low — regardless of how advanced the detection appears.

Why this matters now

Detection systems are becoming:

More automated

More abstracted

More AI-assisted

More dependent on complex telemetry pipelines

At the same time:

Telemetry silently degrades

Schemas evolve

Privacy controls alter signal semantics

Regulatory scrutiny increases accountability for automated decisions

When degradation is invisible, organizations either:

Over-trust automation

Or under-trust their own detection systems

DFS exists to make trust boundaries explicit before they fail in production.

Executive interpretation

DFS helps security leaders answer:

Where are we over-trusting automation?

Which detections are unsafe to auto-respond?

Where does telemetry loss create blind spots?

Which alerts truly require human judgment?

What detection risk are we carrying without visibility?

DFS does not replace tooling.

It provides a defensible structure for reasoning about detection trustworthiness — especially when automation and AI increase the cost of being wrong.

What this is (and is not)
DFS is:

A structured lens for evaluating detection trustworthiness

A model for reasoning about justified automation

A shared language between detection engineers, SOC analysts, and leadership

A way to make detection debt visible

DFS is not:

A SIEM feature or product

A replacement for threat modeling

A substitute for analyst judgment

A mathematical formula pretending to eliminate nuance

DFS does not remove human decision-making.
It clarifies when it is truly required.

A lens, not a silver bullet

DFS does not promise to eliminate alert fatigue.

It aims to:

Make tradeoffs explicit

Shift discussions from alert volume to decision integrity

Re-center detection engineering around human sustainability

Enable safer automation

Roadmap

This framework is intentionally evolving.

Future development areas include:

Quantitative scoring models that preserve nuance

Fidelity thresholds by SOC maturity model

Mapping DFS to MITRE ATT&CK techniques

Integration patterns with automation pipelines

CI-based detection trust regression

Real-world feedback is encouraged.

Closing principle

Detection systems rarely fail because people are careless.

They fail because trust was assumed instead of designed.

Making fidelity explicit is how detection systems scale
without burning the humans inside them.

Originally formulated and maintained by Gustavo Okamoto.

