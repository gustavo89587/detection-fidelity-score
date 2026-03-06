# dfs_core/abac_token.py
"""
DFS ABAC Token — Attribute-Based Access Control for AI Agents

Every agent action requires a cryptographically signed token
that specifies EXACTLY what the agent is allowed to do:
  - Which action type
  - Which resource(s)
  - Which environment
  - Time window (not before / not after)
  - Maximum DFS score allowed to auto-execute
  - Who authorized it

No master keys. No ambient authority.
Each token is single-use or time-bounded.

This implements what Chris Hughes calls:
  "Each action requires an authorization token specific
   to that task and time."

Token structure:
  {
    "jti":          "uuid",          # unique token ID
    "agent_id":     "agent-01",
    "action_type":  "deploy_to_production",
    "resource":     "k8s-prod-cluster",
    "environment":  "production",
    "authorized_by": "jane@corp.com",
    "nbf":          1234567890,      # not before (unix)
    "exp":          1234568490,      # expires (unix)
    "max_dfs_auto": 0.78,            # max DFS for auto-execute
    "single_use":   true,
    "sig":          "sha256:..."     # HMAC signature
  }
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("dfs.abac")

# In production: load from environment / KMS
_DEFAULT_SECRET = b"dfs-abac-secret-change-in-production"


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------

@dataclass
class ABACToken:
    jti:            str               # unique token ID
    agent_id:       str
    action_type:    str               # exact action or wildcard "read_*"
    resource:       str               # exact resource or prefix "prod-db-*"
    environment:    str
    authorized_by:  str
    nbf:            float             # not before (unix timestamp)
    exp:            float             # expires (unix timestamp)
    max_dfs_auto:   float = 0.78      # DFS threshold for auto-execute
    single_use:     bool  = True
    scope_tags:     List[str] = field(default_factory=list)
    sig:            str   = ""        # HMAC-SHA256 signature

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.exp

    @property
    def is_valid_time(self) -> bool:
        now = time.time()
        return self.nbf <= now <= self.exp

    @property
    def expires_in(self) -> int:
        return max(0, int(self.exp - time.time()))


# ---------------------------------------------------------------------------
# Token Manager
# ---------------------------------------------------------------------------

class ABACTokenManager:
    """
    Issues, validates, and revokes ABAC tokens for agent actions.

    Usage:
        manager = ABACTokenManager()

        # Issue token for a specific action
        token = manager.issue(
            agent_id="agent-deploy-01",
            action_type="deploy_to_production",
            resource="k8s-prod-cluster",
            environment="production",
            authorized_by="jane@corp.com",
            valid_seconds=600,   # 10 minutes
        )

        # Before executing — validate token
        result = manager.validate(token, action_event)
        if not result.valid:
            raise UnauthorizedActionError(result.reason)

        # After executing — consume single-use token
        manager.consume(token.jti)
    """

    def __init__(self, secret: bytes = _DEFAULT_SECRET):
        self._secret = secret
        self._consumed: Set[str] = set()   # used single-use tokens
        self._revoked:  Set[str] = set()   # manually revoked tokens
        self._issued:   Dict[str, ABACToken] = {}

    def issue(
        self,
        agent_id:       str,
        action_type:    str,
        resource:       str,
        environment:    str,
        authorized_by:  str,
        valid_seconds:  int   = 300,
        max_dfs_auto:   float = 0.78,
        single_use:     bool  = True,
        scope_tags:     Optional[List[str]] = None,
        nbf_offset:     int   = 0,
    ) -> ABACToken:
        """Issue a new ABAC token."""
        now = time.time()
        token = ABACToken(
            jti=str(uuid.uuid4()),
            agent_id=agent_id,
            action_type=action_type,
            resource=resource,
            environment=environment,
            authorized_by=authorized_by,
            nbf=now + nbf_offset,
            exp=now + valid_seconds,
            max_dfs_auto=max_dfs_auto,
            single_use=single_use,
            scope_tags=scope_tags or [],
        )
        token.sig = self._sign(token)
        self._issued[token.jti] = token

        logger.info(json.dumps({
            "dfs_abac": "issued",
            "jti": token.jti,
            "agent_id": agent_id,
            "action_type": action_type,
            "resource": resource,
            "environment": environment,
            "authorized_by": authorized_by,
            "expires_in": valid_seconds,
            "single_use": single_use,
        }))

        return token

    def validate(
        self,
        token: ABACToken,
        action_event: Dict[str, Any],
        dfs_score: Optional[float] = None,
    ) -> "TokenValidationResult":
        """Validate token against the proposed action."""

        # ── Signature ────────────────────────────────────────────────────
        expected_sig = self._sign(token)
        if not hmac.compare_digest(token.sig, expected_sig):
            return TokenValidationResult(False, "Invalid token signature")

        # ── Revocation ───────────────────────────────────────────────────
        if token.jti in self._revoked:
            return TokenValidationResult(False, "Token has been revoked")

        if token.single_use and token.jti in self._consumed:
            return TokenValidationResult(False, "Single-use token already consumed")

        # ── Time window ──────────────────────────────────────────────────
        if not token.is_valid_time:
            if time.time() > token.exp:
                return TokenValidationResult(False,
                    f"Token expired {int(time.time() - token.exp)}s ago")
            return TokenValidationResult(False, "Token not yet valid (nbf)")

        # ── Agent identity ───────────────────────────────────────────────
        event_agent = action_event.get("agent_id") or action_event.get("agent")
        if event_agent and event_agent != token.agent_id:
            return TokenValidationResult(False,
                f"Agent mismatch: token for '{token.agent_id}', "
                f"action from '{event_agent}'")

        # ── Action type ──────────────────────────────────────────────────
        event_action = action_event.get("action_type") or action_event.get("action") or ""
        if not self._matches(event_action, token.action_type):
            return TokenValidationResult(False,
                f"Action mismatch: token allows '{token.action_type}', "
                f"requested '{event_action}'")

        # ── Resource ─────────────────────────────────────────────────────
        event_resource = action_event.get("target_resource") or action_event.get("target") or ""
        if not self._matches(event_resource, token.resource):
            return TokenValidationResult(False,
                f"Resource mismatch: token allows '{token.resource}', "
                f"requested '{event_resource}'")

        # ── Environment ──────────────────────────────────────────────────
        event_env = action_event.get("environment") or action_event.get("target_environment") or ""
        if event_env and not self._matches(event_env, token.environment):
            return TokenValidationResult(False,
                f"Environment mismatch: token allows '{token.environment}', "
                f"requested '{event_env}'")

        # ── DFS score gate ───────────────────────────────────────────────
        if dfs_score is not None and dfs_score > token.max_dfs_auto:
            return TokenValidationResult(False,
                f"DFS score {dfs_score:.4f} exceeds token's max_dfs_auto "
                f"{token.max_dfs_auto} — human approval required")

        return TokenValidationResult(True, "Token valid",
                                     token=token, expires_in=token.expires_in)

    def consume(self, jti: str) -> None:
        """Mark single-use token as consumed."""
        self._consumed.add(jti)
        logger.info(json.dumps({"dfs_abac": "consumed", "jti": jti}))

    def revoke(self, jti: str, reason: str = "") -> None:
        """Permanently revoke a token."""
        self._revoked.add(jti)
        logger.warning(json.dumps({"dfs_abac": "revoked", "jti": jti, "reason": reason}))

    def _sign(self, token: ABACToken) -> str:
        """HMAC-SHA256 signature over token payload (excluding sig field)."""
        payload = json.dumps({
            k: v for k, v in token.to_dict().items() if k != "sig"
        }, sort_keys=True).encode()
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"sha256:{sig}"

    @staticmethod
    def _matches(value: str, pattern: str) -> bool:
        """Simple wildcard matching: 'deploy_*' matches 'deploy_to_production'."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return value.startswith(pattern[:-1])
        if pattern.startswith("*"):
            return value.endswith(pattern[1:])
        return value == pattern


@dataclass
class TokenValidationResult:
    valid:      bool
    reason:     str
    token:      Optional[ABACToken] = None
    expires_in: int = 0


class UnauthorizedActionError(Exception):
    def __init__(self, reason: str):
        super().__init__(f"ABAC UNAUTHORIZED: {reason}")


# Singleton
default_token_manager = ABACTokenManager()
