# dfs_core/agent_firewall.py
"""
DFS Agent Firewall — Real-Time AI Agent I/O Protection

Application-layer firewall for AI agents. Intercepts and scores
every request and response in real-time using DFS scoring.

Unlike cyber_wall.py (network-layer IPS), this firewall operates
at the semantic layer — understanding what the agent is TRYING to do
and whether that aligns with declared policy.

Protection layers:
  1. Input firewall:    score agent requests BEFORE tool execution
  2. Output firewall:   score tool responses BEFORE agent sees them
  3. Policy engine:     built-in rules with regex + keyword matching
  4. Goal coherence:    detect when agent drifts from declared purpose
  5. Leakage detection: catch secrets/PII in tool responses

Response tiers:
  PASS    → forward normally
  AUDIT   → forward + log alert
  REDACT  → forward with sensitive content removed
  BLOCK   → drop + notify + log
"""

from __future__ import annotations

import json
import re
import time
import logging
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("dfs.agent_firewall")


# ---------------------------------------------------------------------------
# Policy definitions
# ---------------------------------------------------------------------------

@dataclass
class FirewallPolicy:
    id:          str
    name:        str
    description: str
    direction:   str
    action:      str
    patterns:    List[str]
    keywords:    List[str]
    scope:       List[str]
    severity:    float
    enabled:     bool = True

    def matches(self, content: str, tool_type: str = "") -> bool:
        if not self.enabled:
            return False
        if self.scope and tool_type not in self.scope:
            return False
        content_lower = content.lower()
        for kw in self.keywords:
            if kw.lower() in content_lower:
                return True
        for pat in self.patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    return True
            except re.error:
                pass
        return False


DEFAULT_POLICIES: List[FirewallPolicy] = [
    FirewallPolicy(
        id="POL-001", name="Secret Exfiltration",
        description="Detects API keys, passwords, tokens in agent requests or responses",
        direction="both", action="BLOCK", severity=0.95,
        patterns=[
            r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}",
            r"bearer\s+[A-Za-z0-9\-_\.]{20,}",
            r"sk-[A-Za-z0-9]{32,}",
            r"[Aa]nthrop[a-z]*[-_]?[Kk]ey",
        ],
        keywords=["api_key", "secret_key", "private_key", "access_key",
                  "password", "credential", "auth_token"],
        scope=[],
    ),
    FirewallPolicy(
        id="POL-002", name="Prompt Injection",
        description="Detects prompt injection attempts in tool responses",
        direction="response", action="BLOCK", severity=0.92,
        patterns=[
            r"ignore previous instructions",
            r"disregard (your|all) (previous|prior|earlier)",
            r"new (system|persona|role|instruction)",
            r"you are now",
            r"jailbreak",
        ],
        keywords=["ignore previous", "forget everything", "new instructions",
                  "system prompt", "override"],
        scope=[],
    ),
    FirewallPolicy(
        id="POL-003", name="PII Leakage",
        description="Detects PII in tool responses before agent processes them",
        direction="response", action="REDACT", severity=0.75,
        patterns=[
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ],
        keywords=["social security", "ssn", "date of birth", "credit card",
                  "cvv", "passport number"],
        scope=[],
    ),
    FirewallPolicy(
        id="POL-004", name="Destructive Command",
        description="Blocks destructive shell commands in action tools",
        direction="request", action="BLOCK", severity=0.98,
        patterns=[
            r"rm\s+-rf",
            r"drop\s+table",
            r"format\s+[c-z]:",
            r"del\s+/[fqs]",
            r"truncate\s+table",
            r"DELETE\s+FROM\s+\w+\s*;?\s*$",
        ],
        keywords=["rm -rf", "drop database", "wipe", "format disk"],
        scope=["action"],
    ),
    FirewallPolicy(
        id="POL-005", name="Goal Drift",
        description="Detects agent requesting tools unrelated to declared purpose",
        direction="request", action="AUDIT", severity=0.60,
        patterns=[],
        keywords=["bitcoin", "crypto wallet", "monero", "tor browser",
                  "vpn", "proxy", "darkweb", "onion"],
        scope=[],
    ),
    FirewallPolicy(
        id="POL-006", name="Code Execution",
        description="Audits all code execution requests",
        direction="request", action="AUDIT", severity=0.78,
        patterns=[
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__",
            r"subprocess\.",
            r"os\.system",
        ],
        keywords=["eval(", "exec(", "subprocess", "shell=True"],
        scope=["action"],
    ),
]


# ---------------------------------------------------------------------------
# Firewall decision
# ---------------------------------------------------------------------------

@dataclass
class FirewallDecision:
    direction:      str
    action:         str
    dfs_score:      float
    signal:         float
    trust:          float
    coherence:      float
    policies_hit:   List[str]
    reason:         str
    agent_id:       Optional[str]
    tool_name:      Optional[str]
    redacted:       bool = False
    content_hash:   str = ""
    timestamp:      str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @property
    def blocked(self) -> bool:
        return self.action == "BLOCK"

    @property
    def passed(self) -> bool:
        return self.action in ("PASS", "AUDIT")


class FirewallBlockedError(Exception):
    def __init__(self, decision: FirewallDecision):
        self.decision = decision
        super().__init__(
            f"Agent Firewall BLOCKED [{decision.direction}]: {decision.reason}"
        )


# ---------------------------------------------------------------------------
# Agent Firewall
# ---------------------------------------------------------------------------

class DFSAgentFirewall:
    """
    Real-time DFS-scored firewall for AI agent I/O.

    Usage:
        firewall = DFSAgentFirewall()

        result = firewall.check_request(
            agent_id="agent-01",
            tool_name="web_search",
            tool_type="data_source",
            method="query",
            params={"query": "Q3 earnings"},
            purpose="Summarize Q3 earnings report",
        )
        if result.blocked:
            raise FirewallBlockedError(result)

        clean, result = firewall.check_response(
            agent_id="agent-01",
            tool_name="database",
            tool_type="data_source",
            content=raw_response,
        )
    """

    def __init__(
        self,
        policies: Optional[List[FirewallPolicy]] = None,
        custom_policies: Optional[List[FirewallPolicy]] = None,
    ):
        self._policies = policies or DEFAULT_POLICIES
        if custom_policies:
            self._policies = self._policies + custom_policies
        self._events: List[FirewallDecision] = []
        self._violation_counts: Dict[str, int] = {}

    def add_policy(self, policy: FirewallPolicy) -> None:
        self._policies.append(policy)

    def check_request(
        self,
        agent_id:       Optional[str],
        tool_name:      Optional[str],
        tool_type:      str,
        method:         str,
        params:         Dict[str, Any],
        purpose:        Optional[str] = None,
        chain_depth:    int = 0,
        is_whitelisted: bool = False,
        human_approved: bool = False,
    ) -> FirewallDecision:
        """Score and evaluate an outbound agent request."""
        content = json.dumps(params)
        return self._evaluate(
            direction="request",
            content=content,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_type=tool_type,
            method=method,
            purpose=purpose,
            chain_depth=chain_depth,
            is_whitelisted=is_whitelisted,
            human_approved=human_approved,
        )

    def check_response(
        self,
        agent_id:  Optional[str],
        tool_name: Optional[str],
        tool_type: str,
        content:   str,
        purpose:   Optional[str] = None,
        is_whitelisted: bool = False,
    ) -> Tuple[str, FirewallDecision]:
        """Score and evaluate an inbound tool response."""
        decision = self._evaluate(
            direction="response",
            content=content,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_type=tool_type,
            method="response",
            purpose=purpose,
            is_whitelisted=is_whitelisted,
        )

        if decision.action == "REDACT":
            clean = self._redact(content)
            decision.redacted = True
            return clean, decision

        return content, decision

    def _evaluate(
        self,
        direction:      str,
        content:        str,
        agent_id:       Optional[str],
        tool_name:      Optional[str],
        tool_type:      str,
        method:         str,
        purpose:        Optional[str] = None,
        chain_depth:    int = 0,
        is_whitelisted: bool = False,
        human_approved: bool = False,
    ) -> FirewallDecision:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        prior = self._violation_counts.get(agent_id or "", 0)

        # Policy matching
        policies_hit = []
        max_severity  = 0.0
        worst_action  = "PASS"
        action_rank   = {"PASS": 0, "AUDIT": 1, "REDACT": 2, "BLOCK": 3}

        for policy in self._policies:
            if policy.direction not in (direction, "both"):
                continue
            if policy.matches(content, tool_type):
                policies_hit.append(policy.id)
                if policy.severity > max_severity:
                    max_severity = policy.severity
                if action_rank.get(policy.action, 0) > action_rank.get(worst_action, 0):
                    worst_action = policy.action

        # DFS scoring
        s = self._compute_signal(
            tool_type, method, max_severity, prior,
            direction, is_whitelisted, human_approved
        )
        t = self._compute_trust(
            agent_id, tool_name, tool_type, purpose,
            chain_depth, is_whitelisted, human_approved
        )
        b = self._compute_coherence(
            policies_hit, purpose, tool_type,
            content, direction, is_whitelisted
        )
        dfs = round(s * t * b, 4)

        # Determine action from DFS when no policy matched
        # Firewall tiers are INVERTED: DFS = risk score, lower = safer
        if not policies_hit:
            if dfs < 0.15:   worst_action = "PASS"
            elif dfs < 0.35: worst_action = "AUDIT"
            elif dfs < 0.60: worst_action = "REDACT"
            else:            worst_action = "BLOCK"

        reason = self._build_reason(worst_action, dfs, policies_hit)

        if worst_action == "BLOCK":
            self._violation_counts[agent_id or ""] = prior + 1

        decision = FirewallDecision(
            direction    = direction,
            action       = worst_action,
            dfs_score    = dfs,
            signal       = round(s, 4),
            trust        = round(t, 4),
            coherence    = round(b, 4),
            policies_hit = policies_hit,
            reason       = reason,
            agent_id     = agent_id,
            tool_name    = tool_name,
            content_hash = content_hash,
        )

        self._events.append(decision)
        logger.info(json.dumps(decision.to_dict()))

        if worst_action == "BLOCK":
            logger.warning(
                f"FIREWALL BLOCK | agent={agent_id} tool={tool_name} "
                f"direction={direction} DFS={dfs:.4f} policies={policies_hit}"
            )

        return decision

    def _compute_signal(
        self, tool_type, method, policy_severity, prior_violations,
        direction, is_whitelisted, human_approved
    ) -> float:
        tool_risk   = {"data_source": 0.15, "analytics": 0.20,
                       "integration": 0.45, "action": 0.70}.get(tool_type, 0.40)
        method_risk = {"query": 0.10, "search": 0.12, "fetch": 0.15,
                       "get": 0.10, "list": 0.08, "analyze": 0.18,
                       "call": 0.45, "execute": 0.75, "delete": 0.90,
                       "run": 0.70, "write": 0.65, "response": 0.10}.get(method, 0.35)

        if policy_severity > 0:
            # Policy hit: severity is primary signal driver
            s = (policy_severity * 0.65) + (tool_risk * 0.20) + (method_risk * 0.15)
        else:
            # No policy hit: S = inherent tool+method risk only (kept low for safe traffic)
            s = (tool_risk * 0.50) + (method_risk * 0.50)

        if prior_violations >= 3:  s = min(1.0, s + 0.15)
        if is_whitelisted:         s = s * 0.25   # strong reduction
        if human_approved:         s = max(0.0, s - 0.20)

        return max(0.0, min(1.0, s))

    def _compute_trust(
        self, agent_id, tool_name, tool_type, purpose,
        chain_depth, is_whitelisted, human_approved
    ) -> float:
        t = 0.50   # higher baseline — we trust identified agents
        if agent_id:        t += 0.15
        if tool_name:       t += 0.10
        if tool_type:       t += 0.08
        if purpose:         t += 0.12
        if is_whitelisted:  t += 0.15
        if human_approved:  t += 0.10
        if chain_depth > 0: t += 0.03
        if chain_depth >= 5 and not human_approved: t -= 0.15
        return max(0.0, min(1.0, t))

    def _compute_coherence(
        self, policies_hit, purpose, tool_type,
        content, direction, is_whitelisted
    ) -> float:
        b = 0.80   # high baseline — coherent until proven otherwise
        if policies_hit:
            b -= 0.20 * len(policies_hit)   # each policy hit reduces coherence
        if not purpose and tool_type == "action":
            b -= 0.20
        if direction == "response" and len(policies_hit) > 1:
            b -= 0.10
        if is_whitelisted:
            b = min(1.0, b + 0.10)
        return max(0.0, min(1.0, b))

    def _build_reason(self, action, dfs, policies_hit) -> str:
        if not policies_hit:
            return (f"DFS {dfs:.4f} — no policy match, "
                    f"{'forwarding' if action in ('PASS','AUDIT') else 'low trust score'}")
        return f"Policies matched: {', '.join(policies_hit)} — DFS {dfs:.4f} → {action}"

    def _redact(self, content: str) -> str:
        redacted = content
        for policy in self._policies:
            if policy.action != "REDACT":
                continue
            for pat in policy.patterns:
                try:
                    redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
                except re.error:
                    pass
            for kw in policy.keywords:
                redacted = re.sub(
                    re.escape(kw), "[REDACTED]",
                    redacted, flags=re.IGNORECASE
                )
        return redacted

    def stats(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        events = self._events
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        actions = [e.action for e in events]
        return {
            "total":      len(events),
            "pass":       actions.count("PASS"),
            "audit":      actions.count("AUDIT"),
            "redact":     actions.count("REDACT"),
            "block":      actions.count("BLOCK"),
            "block_rate": round(actions.count("BLOCK") / max(len(actions), 1), 3),
        }

    def recent_violations(self, limit: int = 20) -> List[FirewallDecision]:
        return [e for e in self._events if e.action == "BLOCK"][-limit:]


default_firewall = DFSAgentFirewall()
