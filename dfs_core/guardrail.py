# dfs_core/guardrail.py
"""
DFS Guardrail — Trust Boundary Middleware for AI Agents

This is the runtime enforcement layer that Chris Hughes describes as missing:
  "Runtime behavioral monitoring... detecting when an agent's behavior
   is drifting toward governance boundaries that demand intervention."
  — Resilient Cyber, Feb 2026

Usage as a decorator:

    from dfs_core.guardrail import dfs_guardrail

    @dfs_guardrail(kind="agent-action", threshold=0.78)
    def delete_s3_bucket(bucket_name: str):
        ...

Usage as a context manager:

    from dfs_core.guardrail import DFSGuardrail

    with DFSGuardrail(action_event, kind="agent-action") as guard:
        if guard.approved:
            execute_action()

Usage inline (for SOAR / pipeline integration):

    from dfs_core.guardrail import evaluate_before_action

    decision = evaluate_before_action(action_event, kind="agent-action")
    if decision.approved:
        run_playbook()
    else:
        notify_human(decision.reason)

The 3A Governance Model (Engin & Hand):
  Decision Authority → enforced via threshold tiers
  Process Autonomy   → controlled by DFS score + reversibility flag
  Accountability     → every decision is logged with full trace
"""

from __future__ import annotations

import functools
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

from dfs_core.features.agent_action import extract as agent_extract
from dfs_core.scoring import DFSInputs

logger = logging.getLogger("dfs.guardrail")


# ---------------------------------------------------------------------------
# Decision tiers — map DFS score to action
# ---------------------------------------------------------------------------

TIER_AUTOMATE    = 0.78   # full autonomous execution
TIER_ESCALATE    = 0.55   # execute but notify human
TIER_TRIAGE      = 0.30   # pause, request human approval
# below TRIAGE   → BLOCK  # hard gate, do not execute


@dataclass
class GuardrailDecision:
    """
    Returned by every DFS guardrail evaluation.
    Fully serializable for audit logging.
    """
    approved:       bool
    action:         str          # AUTOMATE | ESCALATE | TRIAGE | BLOCK
    dfs_score:      float
    signal:         float        # S
    trust:          float        # T
    coherence:      float        # B
    flags:          Dict[str, bool] = field(default_factory=dict)
    reason:         str          = ""
    trace_id:       Optional[str] = None
    agent_id:       Optional[str] = None
    action_type:    Optional[str] = None
    environment:    Optional[str] = None
    evaluated_at:   str          = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    policy_version: str          = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @property
    def requires_human(self) -> bool:
        return self.action in ("TRIAGE", "BLOCK")

    @property
    def is_blocked(self) -> bool:
        return self.action == "BLOCK"


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------

def evaluate_before_action(
    action_event: Dict[str, Any],
    kind: str = "agent-action",
    custom_thresholds: Optional[Dict[str, float]] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> GuardrailDecision:
    """
    Evaluate a proposed agent action against DFS trust thresholds.

    Args:
        action_event:       The action dict (see agent_action.py schema)
        kind:               Extractor kind (default: "agent-action")
        custom_thresholds:  Override default tiers, e.g.
                            {"automate": 0.85, "escalate": 0.65, "triage": 0.40}
        policy:             Optional policy overrides passed to extractor

    Returns:
        GuardrailDecision with approved, action, score, flags, and reason
    """
    thresholds = {
        "automate": TIER_AUTOMATE,
        "escalate": TIER_ESCALATE,
        "triage":   TIER_TRIAGE,
    }
    if custom_thresholds:
        thresholds.update(custom_thresholds)

    # Route to correct extractor based on kind
    if kind in ("agent-action", "agent"):
        inputs, flags = agent_extract(action_event, policy=policy)
    else:
        # Fallback: try to import from registry
        try:
            from dfs_core.features.registry import get_extractor
            extractor = get_extractor(kind)
            inputs, flags = extractor(action_event, policy=policy)
        except Exception:
            inputs = DFSInputs(0.5, 0.5, 0.5)
            flags = {}

    dfs_score = round(inputs.signal * inputs.trust * inputs.overlap, 4)

    # Determine action tier
    if dfs_score >= thresholds["automate"]:
        action   = "AUTOMATE"
        approved = True
        reason   = f"DFS {dfs_score:.4f} ≥ {thresholds['automate']} — autonomous execution approved"

    elif dfs_score >= thresholds["escalate"]:
        action   = "ESCALATE"
        approved = True  # execute but notify
        reason   = (
            f"DFS {dfs_score:.4f} — executing with human notification. "
            f"Trust below autonomous threshold ({thresholds['automate']})"
        )

    elif dfs_score >= thresholds["triage"]:
        action   = "TRIAGE"
        approved = False
        reason   = (
            f"DFS {dfs_score:.4f} — execution paused. "
            f"Human approval required before proceeding."
        )

    else:
        action   = "BLOCK"
        approved = False
        reason   = (
            f"DFS {dfs_score:.4f} — action BLOCKED. "
            f"Insufficient trust to proceed. "
            f"S={inputs.signal:.3f} T={inputs.trust:.3f} B={inputs.overlap:.3f}"
        )

    # Build human-readable reason with top risk flags
    risk_flags = [k for k, v in flags.items() if v is True and k.startswith("is_") or
                  k in ("dangerous_args", "possible_injection", "deep_chain_no_human",
                        "financial_impact", "affects_pii")]
    if risk_flags:
        reason += f". Risk signals: {', '.join(risk_flags[:5])}"

    decision = GuardrailDecision(
        approved        = approved,
        action          = action,
        dfs_score       = dfs_score,
        signal          = round(inputs.signal, 4),
        trust           = round(inputs.trust, 4),
        coherence       = round(inputs.overlap, 4),
        flags           = flags,
        reason          = reason,
        trace_id        = action_event.get("trace_id") or action_event.get("session_id"),
        agent_id        = action_event.get("agent_id") or action_event.get("agent"),
        action_type     = action_event.get("action_type") or action_event.get("action"),
        environment     = action_event.get("environment") or action_event.get("target_environment"),
    )

    # Always log — this is the audit trail Chris Hughes requires
    log_decision(decision)

    return decision


def log_decision(decision: GuardrailDecision) -> None:
    """Structured audit log for every guardrail evaluation."""
    level = logging.WARNING if not decision.approved else logging.INFO
    logger.log(level, json.dumps({
        "dfs_guardrail": True,
        "action":        decision.action,
        "approved":      decision.approved,
        "dfs_score":     decision.dfs_score,
        "s":             decision.signal,
        "t":             decision.trust,
        "b":             decision.coherence,
        "agent_id":      decision.agent_id,
        "action_type":   decision.action_type,
        "trace_id":      decision.trace_id,
        "environment":   decision.environment,
        "evaluated_at":  decision.evaluated_at,
        "reason":        decision.reason,
    }))


# ---------------------------------------------------------------------------
# Decorator interface
# ---------------------------------------------------------------------------

def dfs_guardrail(
    kind: str = "agent-action",
    threshold: float = TIER_AUTOMATE,
    event_builder: Optional[Callable] = None,
    on_block: Optional[Callable] = None,
    on_escalate: Optional[Callable] = None,
    dry_run: bool = False,
):
    """
    Decorator that wraps any function with a DFS trust boundary.

    Args:
        kind:           Extractor kind
        threshold:      Minimum DFS score for autonomous execution
        event_builder:  Callable(*args, **kwargs) → action_event dict
                        If None, uses kwargs directly as event
        on_block:       Callback(decision) when action is blocked
        on_escalate:    Callback(decision) when action is escalated
        dry_run:        If True, evaluate but never block

    Example:
        @dfs_guardrail(kind="agent-action", threshold=0.78)
        def delete_s3_bucket(bucket_name, action_event=None):
            s3.delete_bucket(Bucket=bucket_name)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Build the action event
            if event_builder:
                action_event = event_builder(*args, **kwargs)
            else:
                action_event = kwargs.get("action_event") or {}

            # Inject dry_run flag
            if dry_run:
                action_event["dry_run"] = True

            # Evaluate
            custom = {"automate": threshold}
            decision = evaluate_before_action(action_event, kind=kind,
                                               custom_thresholds=custom)

            # Handle tiers
            if decision.action == "BLOCK" and not dry_run:
                if on_block:
                    on_block(decision)
                raise DFSBlockedError(decision)

            if decision.action in ("TRIAGE",) and not dry_run:
                if on_block:
                    on_block(decision)
                raise DFSApprovalRequired(decision)

            if decision.action == "ESCALATE":
                if on_escalate:
                    on_escalate(decision)

            # Execute the wrapped function
            return func(*args, **kwargs)

        wrapper._dfs_guardrail = True
        wrapper._dfs_threshold = threshold
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Context manager interface
# ---------------------------------------------------------------------------

class DFSGuardrail:
    """
    Context manager for DFS trust boundary enforcement.

    with DFSGuardrail(action_event, kind="agent-action") as guard:
        if guard.approved:
            execute_payload()
        else:
            request_human_approval(guard.decision.reason)
    """

    def __init__(
        self,
        action_event: Dict[str, Any],
        kind: str = "agent-action",
        custom_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.action_event = action_event
        self.kind = kind
        self.custom_thresholds = custom_thresholds
        self.decision: Optional[GuardrailDecision] = None

    def __enter__(self) -> "DFSGuardrail":
        self.decision = evaluate_before_action(
            self.action_event,
            kind=self.kind,
            custom_thresholds=self.custom_thresholds,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False  # never suppress exceptions

    @property
    def approved(self) -> bool:
        return self.decision.approved if self.decision else False

    @property
    def score(self) -> float:
        return self.decision.dfs_score if self.decision else 0.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DFSBlockedError(Exception):
    """Raised when DFS score is below triage threshold."""
    def __init__(self, decision: GuardrailDecision):
        self.decision = decision
        super().__init__(f"DFS BLOCKED: {decision.reason}")


class DFSApprovalRequired(Exception):
    """Raised when DFS score requires human approval before proceeding."""
    def __init__(self, decision: GuardrailDecision):
        self.decision = decision
        super().__init__(f"DFS APPROVAL REQUIRED: {decision.reason}")
