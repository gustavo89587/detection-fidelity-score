# dfs_core/features/agent_action.py
"""
AI Agent Action → DFS Inputs

This extractor implements the "Guardian Agent" concept described by
Chris Hughes (Resilient Cyber, Feb 2026) and the "critical trust threshold"
from Engin & Hand's dimensional governance model.

The question is NOT "did the agent do something bad?"
The question is: "should this action be allowed to execute autonomously,
or does it require human oversight before proceeding?"

DFS as the trust boundary:
  DFS ≥ 0.78  → AUTOMATE:    execute without human review
  0.55 – 0.78 → ESCALATE:    notify human, proceed with logging
  0.30 – 0.55 → TRIAGE:      pause and request human approval
  < 0.30      → BLOCK:       hard gate — do not execute

DFS Mapping:
  S (Signal Clarity):   Action type risk + tool sensitivity + reversibility
  T (Telemetry):        Context completeness — who asked? what tool? what env?
  B (Behavioral):       Coherence between instruction and action (anti-injection)

The 3A's (Engin & Hand):
  Decision Authority → maps to action_initiator + approval_chain
  Process Autonomy   → maps to action_type + reversibility
  Accountability     → maps to trace_id + tool_call_chain completeness

Key threat patterns:
  - Prompt injection: instruction says X but action is Y
  - Privilege escalation: agent requests more permissions than task requires
  - Data exfiltration: agent reads sensitive data and sends externally
  - Irreversible actions: delete, deploy, financial transactions
  - Tool chain hijacking: unexpected tool invoked mid-chain
  - Shadow actions: agent acts on systems not in scope
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from dfs_core.scoring import DFSInputs


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))


# ---------------------------------------------------------------------------
# Action type risk classification
# ---------------------------------------------------------------------------

_ACTION_TYPE_RISK = {
    # Destructive / irreversible
    "delete_file":              0.90,
    "drop_database":            0.98,
    "terminate_instance":       0.88,
    "delete_secret":            0.92,
    "revoke_credentials":       0.85,
    "wipe_storage":             0.98,
    "remove_user":              0.82,

    # Financial
    "execute_payment":          0.95,
    "transfer_funds":           0.97,
    "create_invoice":           0.70,
    "modify_pricing":           0.75,

    # Infrastructure changes
    "deploy_to_production":     0.85,
    "modify_firewall_rule":     0.88,
    "change_iam_policy":        0.90,
    "create_api_key":           0.80,
    "modify_dns":               0.85,
    "open_port":                0.82,

    # Data access
    "read_pii":                 0.72,
    "export_data":              0.78,
    "send_email":               0.55,
    "send_external_request":    0.60,
    "query_database":           0.35,
    "read_file":                0.25,

    # Code execution
    "execute_code":             0.75,
    "run_shell_command":        0.82,
    "install_package":          0.70,
    "modify_code":              0.65,

    # Low risk
    "read_config":              0.20,
    "search_web":               0.15,
    "summarize_text":           0.10,
    "generate_report":          0.20,
    "send_notification":        0.30,
}

# Tool sensitivity
_TOOL_SENSITIVITY = {
    # Critical tools
    "bash":                     0.85,
    "shell":                    0.85,
    "terminal":                 0.85,
    "python_repl":              0.75,
    "sql_executor":             0.70,
    "iam_manager":              0.90,
    "secret_manager":           0.88,
    "payment_processor":        0.95,
    "kubernetes_kubectl":       0.85,
    "terraform":                0.82,
    "aws_sdk":                  0.72,
    "gcp_sdk":                  0.72,
    "azure_sdk":                0.72,

    # Medium tools
    "file_system":              0.55,
    "email_sender":             0.60,
    "http_client":              0.50,
    "database_client":          0.65,
    "git":                      0.45,
    "slack_api":                0.40,

    # Low risk tools
    "web_search":               0.15,
    "calculator":               0.05,
    "text_summarizer":          0.05,
    "code_reviewer":            0.20,
    "document_reader":          0.15,
}

# Environments — production is highest risk
_ENVIRONMENT_RISK = {
    "production":   1.00,
    "prod":         1.00,
    "staging":      0.60,
    "pre-prod":     0.65,
    "development":  0.30,
    "dev":          0.30,
    "test":         0.20,
    "sandbox":      0.10,
    "local":        0.10,
}

# Initiator types
_INITIATOR_TRUST = {
    "human_approved":       0.95,  # human explicitly approved
    "human_initiated":      0.85,  # human started the chain
    "scheduled_job":        0.70,  # automated but expected
    "agent_chain":          0.50,  # another agent triggered this
    "webhook":              0.45,  # external trigger
    "api_call":             0.40,  # programmatic trigger
    "unknown":              0.20,  # can't trace origin
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps AI agent action event → (DFSInputs, flags).

    Use BEFORE executing an agent action to determine
    whether human oversight is required.
    """

    # ── Action identity ──────────────────────────────────────────────────────
    action_id       = _clean(event.get("action_id") or event.get("id"))
    action_type     = _clean(event.get("action_type") or event.get("action") or "unknown")
    action_desc     = _clean(event.get("description") or event.get("action_description"))
    timestamp       = _clean(event.get("timestamp") or event.get("time"))
    trace_id        = _clean(event.get("trace_id") or event.get("session_id"))

    # ── Agent identity ───────────────────────────────────────────────────────
    agent_id        = _clean(event.get("agent_id") or event.get("agent"))
    agent_name      = _clean(event.get("agent_name"))
    agent_version   = _clean(event.get("agent_version"))
    agent_model     = _clean(event.get("model") or event.get("llm_model"))

    # ── Instruction chain ────────────────────────────────────────────────────
    original_instruction = _clean(event.get("original_instruction") or
                                   event.get("user_instruction") or
                                   event.get("task"))
    immediate_instruction = _clean(event.get("immediate_instruction") or
                                    event.get("current_step") or
                                    event.get("step_instruction"))
    instruction_source = _clean(event.get("instruction_source") or "unknown")
    tool_call_chain = event.get("tool_call_chain") or event.get("prior_steps") or []
    chain_depth     = int(event.get("chain_depth") or len(tool_call_chain) or 0)

    # ── Tool context ─────────────────────────────────────────────────────────
    tool_name       = _clean(event.get("tool_name") or event.get("tool"))
    tool_args       = event.get("tool_args") or event.get("parameters") or {}
    tool_args_str   = str(tool_args).lower()

    # ── Target / scope ───────────────────────────────────────────────────────
    target_resource = _clean(event.get("target_resource") or event.get("target"))
    target_env      = _clean(event.get("environment") or event.get("target_environment") or "unknown")
    target_system   = _clean(event.get("target_system") or event.get("system"))
    is_external     = bool(event.get("is_external") or event.get("external_target") or False)
    scope_defined   = bool(event.get("scope") or event.get("approved_scope"))

    # ── Initiator / approval chain ───────────────────────────────────────────
    initiator_type  = _clean(event.get("initiator_type") or event.get("initiated_by") or "unknown")
    approved_by     = _clean(event.get("approved_by") or event.get("human_approver"))
    approval_time   = _clean(event.get("approval_timestamp"))
    requires_approval = bool(event.get("requires_approval") or False)

    # ── Reversibility ────────────────────────────────────────────────────────
    is_reversible   = bool(event.get("is_reversible") if event.get("is_reversible") is not None else True)
    rollback_plan   = _clean(event.get("rollback_plan") or event.get("undo_action"))
    dry_run         = bool(event.get("dry_run") or event.get("simulation_mode") or False)

    # ── Risk metadata ────────────────────────────────────────────────────────
    data_classification = _clean(event.get("data_classification") or
                                  event.get("data_sensitivity"))
    affects_pii     = bool(event.get("affects_pii") or
                           any(w in tool_args_str for w in ("pii", "personal", "ssn", "passport", "email")))
    financial_impact = bool(event.get("financial_impact") or
                            event.get("monetary_transaction") or False)
    blast_radius    = _clean(event.get("blast_radius") or event.get("impact_scope") or "unknown")

    # ── Derived signals ──────────────────────────────────────────────────────
    action_lower    = (action_type or "").lower()
    action_risk     = _ACTION_TYPE_RISK.get(action_lower, 0.45)

    tool_lower      = (tool_name or "").lower()
    tool_risk       = _TOOL_SENSITIVITY.get(tool_lower, 0.40)

    env_lower       = (target_env or "").lower()
    env_risk        = _ENVIRONMENT_RISK.get(env_lower, 0.50)

    initiator_lower = (initiator_type or "unknown").lower()
    initiator_trust = _INITIATOR_TRUST.get(initiator_lower, 0.30)

    # Prompt injection detection heuristic
    # If original instruction doesn't semantically relate to action type,
    # it may indicate injection in the tool call chain
    injection_risk  = 0.0
    if original_instruction and immediate_instruction:
        orig_words  = set(original_instruction.lower().split())
        imm_words   = set(immediate_instruction.lower().split())
        overlap     = len(orig_words & imm_words) / max(len(orig_words), 1)
        if overlap < 0.10 and chain_depth > 2:
            injection_risk = 0.60  # instructions diverged deep in chain
        elif overlap < 0.20 and chain_depth > 4:
            injection_risk = 0.40

    # Dangerous patterns in tool args
    dangerous_args  = any(w in tool_args_str for w in (
        "rm -rf", "drop table", "delete *", "format", "wipe",
        "; bash", "| bash", "wget http", "curl http",
        "/etc/passwd", "/etc/shadow", "chmod 777",
        "base64 -d", "eval(", "exec(",
    ))

    # High chain depth without human checkpoint
    deep_chain_no_human = chain_depth >= 5 and not _truthy(approved_by)

    # Production + irreversible = maximum risk
    is_prod_irreversible = env_risk >= 0.90 and not is_reversible

    # Presence flags
    has_action_id   = action_id is not None
    has_trace       = trace_id is not None
    has_agent_id    = agent_id is not None
    has_tool        = tool_name is not None
    has_target      = target_resource is not None
    has_instruction = original_instruction is not None
    has_approval    = _truthy(approved_by)
    has_rollback    = rollback_plan is not None
    has_scope       = scope_defined
    has_timestamp   = timestamp is not None
    has_chain       = len(tool_call_chain) > 0

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    # Without full context, we can't make a safe autonomous decision
    identity_fields = [has_agent_id, has_trace, has_action_id, has_timestamp]
    instruction_fields = [has_instruction, _truthy(immediate_instruction),
                          _truthy(initiator_type)]
    action_fields   = [has_tool, has_target, _truthy(target_env), has_scope]
    safety_fields   = [has_rollback or is_reversible, has_approval or not requires_approval,
                       _truthy(blast_radius)]

    t = (
        sum(1.0 for x in identity_fields if x) / max(len(identity_fields), 1) * 0.30 +
        sum(1.0 for x in instruction_fields if x) / max(len(instruction_fields), 1) * 0.25 +
        sum(1.0 for x in action_fields if x) / max(len(action_fields), 1) * 0.25 +
        sum(1.0 for x in safety_fields if x) / max(len(safety_fields), 1) * 0.20
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    # Higher S = more dangerous = more oversight needed
    s = (action_risk * 0.35) + (tool_risk * 0.25) + \
        (env_risk * 0.25) + ((1.0 - initiator_trust) * 0.15)

    if not is_reversible:           s = _clamp(s + 0.15)
    if is_prod_irreversible:        s = _clamp(s + 0.10)
    if is_external:                 s = _clamp(s + 0.08)
    if financial_impact:            s = _clamp(s + 0.10)
    if affects_pii:                 s = _clamp(s + 0.08)
    if dangerous_args:              s = _clamp(s + 0.20)
    if injection_risk > 0:          s = _clamp(s + injection_risk * 0.30)
    if deep_chain_no_human:         s = _clamp(s + 0.10)

    # Dry run = much lower risk
    if dry_run:                     s = _clamp(s * 0.30)
    # Human explicitly approved = reduce signal
    if has_approval:                s = _clamp(s - 0.15)

    s = _clamp(s)

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    # Coherence = action makes sense given instruction + context
    b = 0.35
    if has_instruction:             b += 0.12
    if has_trace:                   b += 0.10
    if has_agent_id:                b += 0.08
    if has_scope:                   b += 0.10
    if has_rollback:                b += 0.08
    if has_approval:                b += 0.10
    if has_chain:                   b += 0.05  # prior steps = auditable chain

    # Incoherence penalties
    if injection_risk > 0.30:       b = _clamp(b - 0.25)  # instructions diverged
    if dangerous_args:              b = _clamp(b - 0.20)  # suspicious parameters
    if deep_chain_no_human:         b = _clamp(b - 0.15)  # lost human context
    if not has_scope:               b = _clamp(b - 0.08)  # undefined boundaries
    if initiator_lower == "unknown": b = _clamp(b - 0.10) # can't trace origin

    b = _clamp(b)

    flags = {
        # Standard DFS
        "has_user":                 has_approval,
        "has_host":                 has_agent_id,
        "has_command_line":         _truthy(immediate_instruction),
        "has_process_path":         has_tool,
        "has_parent_process":       has_instruction,
        # Agent-specific
        "has_trace":                has_trace,
        "has_agent_id":             has_agent_id,
        "has_instruction":          has_instruction,
        "has_tool":                 has_tool,
        "has_scope":                has_scope,
        "has_rollback":             has_rollback,
        "has_approval":             has_approval,
        # Risk signals
        "is_reversible":            is_reversible,
        "is_dry_run":               dry_run,
        "is_external":              is_external,
        "is_production":            env_risk >= 0.90,
        "is_prod_irreversible":     is_prod_irreversible,
        "affects_pii":              affects_pii,
        "financial_impact":         financial_impact,
        "dangerous_args":           dangerous_args,
        "deep_chain_no_human":      deep_chain_no_human,
        "possible_injection":       injection_risk >= 0.40,
        "requires_approval":        requires_approval,
        "initiator_unknown":        initiator_lower == "unknown",
    }

    return DFSInputs(_clamp(s), _clamp(t), _clamp(b)), flags


def agent_action_to_inputs_and_flags(event):
    return extract(event)
