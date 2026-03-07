# dfs_core/features/protocol.py
"""
DFS Protocol Interoperability — Agent↔Tool Communication Layer

Implements a JSON-RPC 2.0 based protocol for standardized communication
between AI agents and external tools, with DFS scoring of every interaction.

Every tool call is scored before execution:
  S = how risky is this tool + method combination?
  T = how complete is the request context?
  B = does this request cohere with the agent's declared purpose?

Tool categories:
  - data_source:  read-only queries (low risk)
  - analytics:    computation + explanation (low-medium risk)
  - action:       side-effecting execution (high risk)
  - integration:  external API calls (medium-high risk)

DFS decision tiers:
  ≥ 0.78 → EXECUTE   (proceed autonomously)
  0.55   → LOG       (execute + notify)
  0.30   → REVIEW    (pause for approval)
  < 0.30 → BLOCK     (hard gate)
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from dfs_core.scoring import DFSInputs

logger = logging.getLogger("dfs.protocol")


# ---------------------------------------------------------------------------
# Tool risk catalogue
# ---------------------------------------------------------------------------

_TOOL_CATEGORY_RISK = {
    "data_source":   0.20,
    "analytics":     0.25,
    "integration":   0.55,
    "action":        0.80,
    "unknown":       0.65,
}

_METHOD_RISK = {
    # Data source
    "query":         0.15,
    "search":        0.18,
    "fetch":         0.20,
    "list":          0.10,
    "get":           0.12,
    # Analytics
    "analyze":       0.22,
    "explain":       0.18,
    "summarize":     0.15,
    "score":         0.20,
    # Integration
    "call":          0.50,
    "request":       0.55,
    "webhook":       0.60,
    "send":          0.65,
    # Action
    "execute":       0.80,
    "run":           0.78,
    "write":         0.72,
    "delete":        0.92,
    "modify":        0.75,
    "deploy":        0.85,
    "transfer":      0.90,
    "create":        0.60,
    "update":        0.65,
}

# Ecosystem vendor risk (calling external LLM APIs)
_VENDOR_RISK = {
    "openai":        0.45,
    "anthropic":     0.45,
    "google":        0.45,
    "cohere":        0.45,
    "huggingface":   0.40,
    "unknown":       0.70,
}

# Dangerous parameter patterns
_DANGEROUS_PARAMS = [
    "api_key", "secret", "password", "token", "credential",
    "private_key", "access_key", "auth", "bearer",
    "drop", "delete", "truncate", "rm -rf", "format",
    "eval", "exec", "import os", "subprocess",
]


def _get(d: Dict, key: str, default=None):
    return d.get(key, default)


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _truthy(v) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown"):
        return False
    return True


# ---------------------------------------------------------------------------
# Protocol message models (pure dataclasses, no pydantic dependency)
# ---------------------------------------------------------------------------

@dataclass
class ToolRequest:
    method:     str
    params:     Dict[str, Any] = field(default_factory=dict)
    id:         str = field(default_factory=lambda: str(uuid.uuid4()))
    jsonrpc:    str = "2.0"
    agent_id:   Optional[str] = None
    tool_name:  Optional[str] = None
    tool_type:  Optional[str] = None   # data_source|analytics|action|integration
    vendor:     Optional[str] = None   # openai|anthropic|etc
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    purpose:    Optional[str] = None   # declared agent purpose for coherence check

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class ToolResponse:
    id:         str
    result:     Any = None
    error:      Optional[Dict[str, Any]] = None
    jsonrpc:    str = "2.0"
    dfs_score:  Optional[float] = None
    decision:   Optional[str] = None
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class ProtocolDecision:
    request_id:   str
    agent_id:     Optional[str]
    tool_name:    Optional[str]
    method:       str
    dfs_score:    float
    signal:       float
    trust:        float
    coherence:    float
    decision:     str        # EXECUTE | LOG | REVIEW | BLOCK
    reason:       str
    flags:        Dict[str, bool]
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @property
    def approved(self) -> bool:
        return self.decision in ("EXECUTE", "LOG")


# ---------------------------------------------------------------------------
# DFS extractor
# ---------------------------------------------------------------------------

def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps an Agent↔Tool protocol event → (DFSInputs, flags).

    event fields:
      agent_id, tool_name, tool_type, method, params,
      vendor, purpose, chain_depth, prior_violations,
      is_whitelisted, response_content (for response scoring)
    """

    # ── Identity ─────────────────────────────────────────────────────────
    agent_id      = _get(event, "agent_id")
    tool_name     = _get(event, "tool_name") or _get(event, "tool")
    tool_type     = (_get(event, "tool_type") or "unknown").lower()
    method        = (_get(event, "method") or "unknown").lower()
    vendor        = (_get(event, "vendor") or "unknown").lower()
    purpose       = _get(event, "purpose") or ""      # declared agent goal
    request_id    = _get(event, "request_id") or _get(event, "id") or ""
    timestamp     = _get(event, "timestamp")

    # ── Request context ───────────────────────────────────────────────────
    params            = _get(event, "params") or {}
    params_str        = json.dumps(params).lower() if params else ""
    chain_depth       = int(_get(event, "chain_depth") or 0)
    prior_violations  = int(_get(event, "prior_violations") or 0)
    is_whitelisted    = bool(_get(event, "is_whitelisted") or False)
    human_approved    = bool(_get(event, "human_approved") or False)
    is_response       = bool(_get(event, "is_response") or False)   # scoring a response
    response_content  = str(_get(event, "response_content") or "")

    # ── Risk calculation ──────────────────────────────────────────────────
    category_risk = _TOOL_CATEGORY_RISK.get(tool_type, 0.65)
    method_risk   = _METHOD_RISK.get(method, 0.50)
    vendor_risk   = _VENDOR_RISK.get(vendor, 0.50) if vendor != "unknown" else 0.50

    # Dangerous parameter detection
    dangerous_params  = any(p in params_str for p in _DANGEROUS_PARAMS)
    param_risk        = 0.85 if dangerous_params else 0.0

    # Response leakage detection (API keys, secrets in response)
    response_lower    = response_content.lower()
    response_leakage  = any(p in response_lower for p in
                            ["api_key", "secret", "password", "private_key",
                             "access_key", "bearer ", "token:"])
    response_risk     = 0.90 if response_leakage else 0.0

    # ── S — Signal ────────────────────────────────────────────────────────
    s = (category_risk * 0.35) + (method_risk * 0.35) + (vendor_risk * 0.15) + (0.15 * 0.5)

    if dangerous_params:      s = _clamp(s + 0.20)
    if response_leakage:      s = _clamp(s + 0.25)
    if prior_violations >= 3: s = _clamp(s + 0.15)
    if chain_depth >= 5:      s = _clamp(s + 0.10)
    if is_whitelisted:        s = _clamp(s * 0.35)
    if human_approved:        s = _clamp(s - 0.15)

    s = _clamp(s)

    # ── T — Telemetry ─────────────────────────────────────────────────────
    has_agent_id   = _truthy(agent_id)
    has_tool_name  = _truthy(tool_name)
    has_tool_type  = tool_type != "unknown"
    has_method     = method != "unknown"
    has_vendor     = vendor != "unknown"
    has_purpose    = _truthy(purpose)
    has_request_id = _truthy(request_id)
    has_timestamp  = _truthy(timestamp)
    has_params     = bool(params)

    identity_fields = [has_agent_id, has_tool_name, has_request_id, has_timestamp]
    tool_fields     = [has_tool_type, has_method, has_vendor, has_params]
    context_fields  = [has_purpose, chain_depth > 0, human_approved or is_whitelisted]

    t = (
        sum(1.0 for x in identity_fields if x) / len(identity_fields) * 0.40 +
        sum(1.0 for x in tool_fields if x)     / len(tool_fields)     * 0.35 +
        sum(1.0 for x in context_fields if x)  / len(context_fields)  * 0.25
    )

    # Penalize for deep chain without human oversight
    if chain_depth >= 5 and not human_approved:
        t = _clamp(t - 0.15)

    t = _clamp(t)

    # ── B — Behavioral Coherence ──────────────────────────────────────────
    b = 0.40

    if has_tool_type and has_method:    b += 0.12
    if has_purpose:                     b += 0.10
    if has_agent_id:                    b += 0.08
    if has_vendor:                      b += 0.07
    if human_approved:                  b += 0.10
    if is_whitelisted:                  b += 0.08
    if prior_violations == 0:           b += 0.08

    # Incoherence: dangerous params in a "safe" tool type
    if dangerous_params and tool_type in ("data_source", "analytics"):
        b = _clamp(b - 0.30)

    # Incoherence: action tool called without declared purpose
    if tool_type == "action" and not has_purpose:
        b = _clamp(b - 0.20)

    # Incoherence: response contains secrets
    if response_leakage:
        b = _clamp(b - 0.35)

    # Incoherence: repeat violations
    if prior_violations >= 3:
        b = _clamp(b - 0.20)

    b = _clamp(b)

    flags = {
        "has_agent_id":        has_agent_id,
        "has_tool_name":       has_tool_name,
        "has_tool_type":       has_tool_type,
        "has_method":          has_method,
        "has_vendor":          has_vendor,
        "has_purpose":         has_purpose,
        "has_params":          has_params,
        "dangerous_params":    dangerous_params,
        "response_leakage":    response_leakage,
        "is_whitelisted":      is_whitelisted,
        "human_approved":      human_approved,
        "deep_chain":          chain_depth >= 5,
        "repeat_violator":     prior_violations >= 3,
        "is_response_event":   is_response,
        "is_action_tool":      tool_type == "action",
        "is_integration":      tool_type == "integration",
        "vendor_call":         vendor not in ("unknown", ""),
    }

    return DFSInputs(_clamp(s), _clamp(t), _clamp(b)), flags


def evaluate_request(request: ToolRequest) -> ProtocolDecision:
    """Evaluate a ToolRequest and return a ProtocolDecision."""
    event = {
        "agent_id":    request.agent_id,
        "tool_name":   request.tool_name,
        "tool_type":   request.tool_type,
        "method":      request.method,
        "vendor":      request.vendor,
        "purpose":     request.purpose,
        "params":      request.params,
        "request_id":  request.id,
        "timestamp":   request.timestamp,
    }
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)

    if dfs >= 0.78:
        decision, reason = "EXECUTE", f"DFS {dfs:.4f} — proceed autonomously"
    elif dfs >= 0.55:
        decision, reason = "LOG", f"DFS {dfs:.4f} — execute with audit notification"
    elif dfs >= 0.30:
        decision, reason = "REVIEW", f"DFS {dfs:.4f} — pause for human approval"
    else:
        decision, reason = "BLOCK", f"DFS {dfs:.4f} — hard gate, action denied"

    pd = ProtocolDecision(
        request_id=request.id,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        method=request.method,
        dfs_score=dfs,
        signal=round(inputs.signal, 4),
        trust=round(inputs.trust, 4),
        coherence=round(inputs.overlap, 4),
        decision=decision,
        reason=reason,
        flags=flags,
    )
    logger.info(json.dumps(pd.to_dict()))
    return pd
