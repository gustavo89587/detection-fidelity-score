# Minimum Context Before Automation

Automation is getting faster.
Agents are getting smarter.
Pipelines are getting more autonomous.

But decisions are still only as strong as the signal behind them.

This document defines a simple principle:

> Not every detection should drive an automated action.

Some signals support a decision.
Some signals still need context.

---

## Example: Process Execution (4688 / PowerShell)

Before an automated response is considered, these questions matter:

- Is the command-line visible?
- Is the parent process known?
- Is the user context clear?
- Is the process chain coherent?
- Is telemetry complete enough to understand intent?

If key context is missing:

- command-line redacted
- parent unknown
- identity unclear
- relationship broken

Then the signal may still be correct…

But the decision confidence becomes fragile.

---

## Operational Principle

Detection finds activity.

But automation should require stronger evidence than detection alone.

A signal that is:

- technically correct
- but context-poor

should not immediately trigger high-impact automated actions.

---

## Why this matters

Humans can pause.
Humans can question.
Humans can investigate.

Automation acts.

And when automation acts on weak context,
the cost of being wrong increases.

---

## DFS perspective

The goal is not to stop automation.

The goal is to ensure that:

> Action is supported by sufficient signal fidelity.

Before automating:
- Check context.
- Check relationships.
- Check clarity.

If fidelity is low,
prefer investigation over reaction.
