# Agents, Automation and Signal Trust

There’s a shift happening in SOC environments.

We’re moving from:

human-driven triage
to

agent-assisted decisions
and in some cases,

agent-driven response.

On paper, this looks like progress.

In practice, it introduces a new kind of risk.

Not because agents are “dumb”.
But because they can act on signals that look strong — and aren’t.

Most automated decisions assume:

the alert is correct

the context is complete

the signal is trustworthy

But in reality:

logs are partial

fields get redacted

telemetry is delayed

relationships are missing

And yet, decisions still happen.

This is where the real problem starts.

Detection finds activity.
But decisions require trust.

## A process start alert, for example, can be technically correct and still not be safe enough to drive an automated action.

If command-line is missing.
If parent context is weak.
If identity is unclear.

The system still sees “activity”.
But the confidence behind that activity is fragile.

This is the gap I keep thinking about.

Not detection accuracy.
Signal fidelity.

Before automation acts, we should be asking:

“Is this signal strong enough to support a decision?”

That question is what led me to start thinking in terms of Detection Fidelity.
