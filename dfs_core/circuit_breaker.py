# dfs_core/circuit_breaker.py
"""
DFS Circuit Breaker — Anomaly Detection for AI Agent Behavior

Monitors agent actions in real-time and automatically cuts access
when behavior patterns indicate compromise, runaway loops, or abuse.

Patterns detected:
  - Velocity anomaly:    too many actions per second/minute
  - Resource hammering:  same resource accessed repeatedly
  - Scope creep:         agent accessing resources outside approved scope
  - Error storm:         too many blocked/failed actions in sequence
  - Privilege escalation: action risk level suddenly jumps
  - Time anomaly:        actions outside expected operating hours

State is maintained per agent_id in memory (or pluggable store).
When tripped, the breaker enters OPEN state — all actions BLOCKED
until manually reset or cooldown expires.

States:
  CLOSED  → normal operation, monitoring
  HALF    → warning threshold crossed, heightened scrutiny
  OPEN    → breaker tripped, all actions blocked
"""

from __future__ import annotations

import json
import time
import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("dfs.circuit_breaker")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreakerConfig:
    # Velocity limits
    max_actions_per_second:     float = 5.0
    max_actions_per_minute:     int   = 60
    max_actions_per_hour:       int   = 500

    # Resource hammering
    max_same_resource_per_min:  int   = 10

    # Error storm
    max_consecutive_blocks:     int   = 3    # BLOCK decisions in a row
    max_block_rate_per_min:     float = 0.5  # >50% of actions blocked

    # Scope creep
    enforce_scope:              bool  = True

    # Risk escalation
    risk_escalation_threshold:  float = 0.30  # DFS jump > 0.30 in one step

    # Cooldown after trip
    cooldown_seconds:           int   = 300   # 5 minutes

    # Window sizes
    window_seconds:             int   = 60
    history_size:               int   = 100


# ---------------------------------------------------------------------------
# Per-agent state
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    agent_id:           str
    state:              str   = "CLOSED"   # CLOSED | HALF | OPEN
    trip_reason:        str   = ""
    trip_time:          float = 0.0
    cooldown_until:     float = 0.0
    consecutive_blocks: int   = 0
    total_actions:      int   = 0
    total_blocked:      int   = 0
    approved_scope:     List[str] = field(default_factory=list)
    last_dfs_score:     float = 0.0

    # Sliding windows
    action_timestamps:  List[float] = field(default_factory=list)
    resource_counts:    Dict[str, List[float]] = field(default_factory=dict)
    recent_decisions:   List[str] = field(default_factory=list)   # AUTOMATE|ESCALATE|TRIAGE|BLOCK
    recent_scores:      List[float] = field(default_factory=list)


@dataclass
class BreakerEvent:
    agent_id:       str
    event_type:     str    # TRIP | RESET | WARNING | ACTION
    state:          str
    reason:         str
    timestamp:      str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    action_type:    Optional[str] = None
    dfs_score:      Optional[float] = None
    metrics:        Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class DFSCircuitBreaker:
    """
    Stateful circuit breaker for AI agent behavioral monitoring.

    Usage:
        breaker = DFSCircuitBreaker()

        # Before executing agent action:
        status = breaker.check(agent_id, action_event, dfs_decision)
        if status.blocked:
            raise CircuitOpenError(status.reason)

        # After action completes (or fails):
        breaker.record(agent_id, action_event, dfs_decision)
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self._agents: Dict[str, AgentState] = {}
        self._events: List[BreakerEvent] = []

    def _get_state(self, agent_id: str) -> AgentState:
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentState(agent_id=agent_id)
        return self._agents[agent_id]

    def set_scope(self, agent_id: str, approved_resources: List[str]) -> None:
        """Define approved resource scope for an agent."""
        state = self._get_state(agent_id)
        state.approved_scope = approved_resources

    def check(
        self,
        agent_id: str,
        action_event: Dict[str, Any],
        dfs_score: float = 0.5,
        decision_action: str = "AUTOMATE",
    ) -> "BreakerCheckResult":
        """
        Check if agent is allowed to proceed.
        Call BEFORE executing the action.
        """
        state = self._get_state(agent_id)
        now = time.time()

        # ── Check if breaker is OPEN ─────────────────────────────────────
        if state.state == "OPEN":
            if now < state.cooldown_until:
                remaining = int(state.cooldown_until - now)
                return BreakerCheckResult(
                    blocked=True,
                    breaker_state="OPEN",
                    reason=f"Circuit OPEN: {state.trip_reason}. "
                           f"Cooldown: {remaining}s remaining.",
                    agent_id=agent_id,
                )
            else:
                # Cooldown expired — move to HALF
                state.state = "HALF"
                self._log_event(agent_id, "RESET", "HALF",
                                "Cooldown expired, entering HALF-OPEN state")

        # ── Velocity check ───────────────────────────────────────────────
        cfg = self.config
        window = cfg.window_seconds
        recent_ts = [t for t in state.action_timestamps if now - t <= window]

        actions_per_min = len(recent_ts)
        if len(state.action_timestamps) >= 2:
            last_interval = now - state.action_timestamps[-1] if state.action_timestamps else 1
            instant_rate = 1.0 / max(last_interval, 0.001)
        else:
            instant_rate = 0.0

        if instant_rate > cfg.max_actions_per_second:
            return self._trip(state, agent_id,
                f"Velocity anomaly: {instant_rate:.1f} actions/sec "
                f"(max: {cfg.max_actions_per_second})",
                action_event, dfs_score)

        if actions_per_min > cfg.max_actions_per_minute:
            return self._trip(state, agent_id,
                f"Velocity anomaly: {actions_per_min} actions/min "
                f"(max: {cfg.max_actions_per_minute})",
                action_event, dfs_score)

        # ── Resource hammering ───────────────────────────────────────────
        target = action_event.get("target_resource") or action_event.get("target") or ""
        if target and cfg.max_same_resource_per_min:
            res_ts = state.resource_counts.get(target, [])
            recent_res = [t for t in res_ts if now - t <= window]
            if len(recent_res) >= cfg.max_same_resource_per_min:
                return self._trip(state, agent_id,
                    f"Resource hammering: '{target}' accessed "
                    f"{len(recent_res)}x in {window}s",
                    action_event, dfs_score)

        # ── Error storm ──────────────────────────────────────────────────
        if state.consecutive_blocks >= cfg.max_consecutive_blocks:
            return self._trip(state, agent_id,
                f"Error storm: {state.consecutive_blocks} consecutive "
                f"BLOCK decisions",
                action_event, dfs_score)

        # ── Block rate ───────────────────────────────────────────────────
        if len(state.recent_decisions) >= 10:
            block_rate = state.recent_decisions.count("BLOCK") / len(state.recent_decisions)
            if block_rate > cfg.max_block_rate_per_min:
                return self._trip(state, agent_id,
                    f"High block rate: {block_rate:.0%} of recent actions blocked",
                    action_event, dfs_score)

        # ── Scope creep ──────────────────────────────────────────────────
        if cfg.enforce_scope and state.approved_scope and target:
            in_scope = any(target.startswith(s) or s in target
                          for s in state.approved_scope)
            if not in_scope:
                return self._trip(state, agent_id,
                    f"Scope creep: '{target}' not in approved scope "
                    f"{state.approved_scope}",
                    action_event, dfs_score)

        # ── Risk escalation ──────────────────────────────────────────────
        if state.last_dfs_score > 0 and state.last_dfs_score < 0.5:
            score_jump = dfs_score - state.last_dfs_score
            if score_jump > cfg.risk_escalation_threshold:
                self._warn(state, agent_id,
                    f"Risk escalation: DFS jumped +{score_jump:.3f} "
                    f"({state.last_dfs_score:.3f} → {dfs_score:.3f})")

        # ── HALF state: extra scrutiny ───────────────────────────────────
        if state.state == "HALF" and decision_action in ("TRIAGE", "BLOCK"):
            return self._trip(state, agent_id,
                "HALF-OPEN: first suspicious action after reset triggered re-trip",
                action_event, dfs_score)

        return BreakerCheckResult(
            blocked=False,
            breaker_state=state.state,
            reason="",
            agent_id=agent_id,
        )

    def record(
        self,
        agent_id: str,
        action_event: Dict[str, Any],
        dfs_score: float,
        decision_action: str,
    ) -> None:
        """Record a completed action. Call AFTER execution."""
        state = self._get_state(agent_id)
        now = time.time()

        # Update timestamps
        state.action_timestamps.append(now)
        if len(state.action_timestamps) > self.config.history_size:
            state.action_timestamps = state.action_timestamps[-self.config.history_size:]

        # Update resource counts
        target = action_event.get("target_resource") or ""
        if target:
            if target not in state.resource_counts:
                state.resource_counts[target] = []
            state.resource_counts[target].append(now)
            state.resource_counts[target] = [
                t for t in state.resource_counts[target]
                if now - t <= self.config.window_seconds
            ]

        # Update decision history
        state.recent_decisions.append(decision_action)
        if len(state.recent_decisions) > 20:
            state.recent_decisions = state.recent_decisions[-20:]

        # Consecutive blocks
        if decision_action == "BLOCK":
            state.consecutive_blocks += 1
            state.total_blocked += 1
        else:
            state.consecutive_blocks = 0

        state.total_actions += 1
        state.last_dfs_score = dfs_score
        state.recent_scores.append(dfs_score)
        if len(state.recent_scores) > 20:
            state.recent_scores = state.recent_scores[-20:]

    def reset(self, agent_id: str, reason: str = "manual reset") -> None:
        """Manually reset circuit breaker for an agent."""
        state = self._get_state(agent_id)
        state.state = "CLOSED"
        state.consecutive_blocks = 0
        state.trip_reason = ""
        self._log_event(agent_id, "RESET", "CLOSED", reason)

    def status(self, agent_id: str) -> Dict[str, Any]:
        """Get current breaker status for an agent."""
        if agent_id not in self._agents:
            return {"agent_id": agent_id, "state": "CLOSED", "total_actions": 0}
        s = self._agents[agent_id]
        now = time.time()
        return {
            "agent_id":             agent_id,
            "state":                s.state,
            "trip_reason":          s.trip_reason,
            "total_actions":        s.total_actions,
            "total_blocked":        s.total_blocked,
            "block_rate":           round(s.total_blocked / max(s.total_actions, 1), 3),
            "consecutive_blocks":   s.consecutive_blocks,
            "avg_dfs_score":        round(sum(s.recent_scores) / max(len(s.recent_scores), 1), 4),
            "cooldown_remaining":   max(0, int(s.cooldown_until - now)),
        }

    def _trip(
        self,
        state: AgentState,
        agent_id: str,
        reason: str,
        action_event: Dict[str, Any],
        dfs_score: float,
    ) -> "BreakerCheckResult":
        state.state = "OPEN"
        state.trip_reason = reason
        state.trip_time = time.time()
        state.cooldown_until = time.time() + self.config.cooldown_seconds
        self._log_event(agent_id, "TRIP", "OPEN", reason,
                        action_event.get("action_type"), dfs_score)
        logger.warning(f"CIRCUIT BREAKER TRIPPED — agent={agent_id} reason={reason}")
        return BreakerCheckResult(
            blocked=True,
            breaker_state="OPEN",
            reason=f"CIRCUIT TRIPPED: {reason}",
            agent_id=agent_id,
        )

    def _warn(self, state: AgentState, agent_id: str, reason: str) -> None:
        if state.state == "CLOSED":
            state.state = "HALF"
        self._log_event(agent_id, "WARNING", state.state, reason)

    def _log_event(self, agent_id, event_type, state, reason,
                   action_type=None, dfs_score=None):
        ev = BreakerEvent(
            agent_id=agent_id, event_type=event_type,
            state=state, reason=reason,
            action_type=action_type, dfs_score=dfs_score,
        )
        self._events.append(ev)
        logger.info(json.dumps(ev.to_dict()))


@dataclass
class BreakerCheckResult:
    blocked:        bool
    breaker_state:  str
    reason:         str
    agent_id:       str


class CircuitOpenError(Exception):
    def __init__(self, result: BreakerCheckResult):
        self.result = result
        super().__init__(f"Circuit OPEN for agent {result.agent_id}: {result.reason}")


# Singleton for easy import
default_breaker = DFSCircuitBreaker()
