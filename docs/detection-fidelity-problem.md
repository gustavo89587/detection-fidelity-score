The Detection Signal Problem

Security teams operate increasingly complex detection systems.

Every day, thousands or millions of events flow through SIEMs, detection pipelines, and security analytics platforms. Detection rules evaluate those events and produce alerts intended to surface meaningful security signals.

However, modern security operations face a fundamental problem:

they measure alerts, but not signal quality.

Security tooling focuses heavily on detection coverage, alert generation, and rule creation. But very little attention is given to evaluating the behavior of the detection system itself.

As a result, security teams struggle with:

overwhelming alert volume

high noise-to-signal ratios

analyst fatigue and burnout

difficulty understanding the operational impact of detection policies

deploying new detection logic without knowing its systemic consequences

Detection rules are typically evaluated in isolation.
But in practice, they operate as part of a decision system.

Every detection rule contributes to operational outcomes such as:

ignore
investigate
escalate
automate

Each of these outcomes has a real cost in time, attention, and operational capacity.

Yet most security programs lack a systematic way to measure:

how detection policies affect investigation load

how often detections escalate incidents

how stable detection decisions are under changing conditions

how much useful signal is actually produced

Without these measurements, detection engineering becomes guesswork.

Detection as Decision Systems

Security detections should not be treated as isolated rules.

They should be understood as components of a decision system operating under operational constraints.

In this view, the key question becomes:

How does the detection system behave under real conditions?

Important properties of a detection system include:

decision distribution (ignore, investigate, escalate, automate)

operational pressure placed on analysts

stability of decisions under variation

density of meaningful signal relative to noise

Understanding these properties allows security teams to reason about detection systems the same way engineers reason about other complex systems.

Detection Fidelity

The Detection Fidelity Score (DFS) is an attempt to introduce systematic evaluation into detection engineering.

DFS evaluates detection policies by measuring:

signal density

operational cost

decision distribution

system stability under variation

Rather than asking only “does this rule detect?”, DFS asks:

What kind of decisions does this detection system produce, and at what cost?

This perspective allows detection engineering to evolve from rule-writing toward system-level signal engineering.

Toward Detection Observability

If modern security systems are going to rely increasingly on automation and AI-driven agents, then understanding signal quality becomes even more critical.

Autonomous systems cannot rely solely on raw alerts.

They require reliable assessments of signal quality before taking action.

DFS proposes a step in this direction: providing a framework to observe and evaluate detection systems as decision-making systems operating under cost and uncertainty.