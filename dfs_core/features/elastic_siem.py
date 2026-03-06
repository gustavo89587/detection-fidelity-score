# dfs_core/features/elastic_siem.py
"""
Elastic SIEM / Security Alert → DFS Inputs

Elastic Security generates alerts from:
  - Detection Engine rules (EQL, KQL, ML, threshold, indicator match)
  - Prebuilt rules (Elastic Security Labs)
  - Custom rules
  - ML anomaly detections

Alert schema (signal/kibana.alert.*):
  kibana.alert.rule.name, kibana.alert.rule.category
  kibana.alert.severity, kibana.alert.risk_score
  kibana.alert.rule.type (eql, query, threshold, machine_learning, indicator_match)
  kibana.alert.original_event.* (the triggering event)
  kibana.alert.ancestors (event lineage)

ECS fields underneath:
  host.name, host.os.type
  user.name, user.domain
  process.*, network.*, file.*
  threat.indicator.*, threat.technique.*

DFS Mapping:
  S: Risk score + rule type confidence + threat intel match + ML anomaly score
  T: ECS field completeness across host/user/process/network
  B: Coherence of alert lineage + MITRE coverage + rule specificity
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
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


# Elastic rule type confidence weights
_RULE_TYPE_CONFIDENCE = {
    "eql":               0.88,  # Event Query Language — high precision
    "esql":              0.85,
    "indicator_match":   0.90,  # Threat intel match — very high signal
    "machine_learning":  0.72,  # ML — probabilistic
    "threshold":         0.65,  # Count-based — medium precision
    "query":             0.60,  # KQL/Lucene — variable
    "new_terms":         0.70,  # First-seen — good for baseline deviation
    "threat_match":      0.90,
}

# Elastic severity → normalized risk
_SEVERITY_SCORE = {
    "critical": 0.95,
    "high":     0.78,
    "medium":   0.55,
    "low":      0.28,
    "info":     0.10,
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:

    # ── Alert metadata ───────────────────────────────────────────────────────
    # Support both kibana.alert.* and flattened signal.*
    rule_name       = _clean(
        _get(event, "kibana.alert.rule.name") or
        _get(event, "signal.rule.name") or
        event.get("rule_name")
    )
    rule_type       = _clean(
        _get(event, "kibana.alert.rule.type") or
        _get(event, "signal.rule.type") or
        event.get("rule_type") or "query"
    )
    rule_category   = _clean(
        _get(event, "kibana.alert.rule.category") or
        _get(event, "signal.rule.description")
    )
    severity_raw    = _clean(
        _get(event, "kibana.alert.severity") or
        _get(event, "signal.rule.severity") or
        event.get("severity") or "medium"
    )
    risk_score_raw  = (
        _get(event, "kibana.alert.risk_score") or
        _get(event, "signal.rule.risk_score") or
        event.get("risk_score") or 0
    )
    alert_id        = _clean(
        _get(event, "kibana.alert.uuid") or
        _get(event, "_id") or event.get("id")
    )
    alert_status    = _clean(
        _get(event, "kibana.alert.workflow_status") or
        event.get("status") or "open"
    )
    building_block  = bool(
        _get(event, "kibana.alert.building_block_type") or
        _get(event, "signal.rule.building_block_type")
    )

    # ── MITRE ATT&CK ────────────────────────────────────────────────────────
    threat          = event.get("threat") or []
    mitre_tactics   = []
    mitre_techniques = []
    if isinstance(threat, list):
        for t in threat:
            tactic = _get(t, "tactic.name")
            if tactic:
                mitre_tactics.append(tactic)
            techs = t.get("technique") or []
            for tech in techs:
                tid = tech.get("id") or tech.get("name")
                if tid:
                    mitre_techniques.append(tid)
    has_mitre       = len(mitre_tactics) > 0 or len(mitre_techniques) > 0

    # ── Threat intel indicators ──────────────────────────────────────────────
    indicator       = event.get("threat", {})
    if isinstance(indicator, list):
        indicator = indicator[0] if indicator else {}
    ti_matched      = bool(
        _get(event, "kibana.alert.rule.threat_filters") or
        rule_type in ("indicator_match", "threat_match")
    )

    # ── ECS: Host ────────────────────────────────────────────────────────────
    host_name       = _clean(_get(event, "host.name"))
    host_os         = _clean(_get(event, "host.os.type") or _get(event, "host.os.name"))
    host_id         = _clean(_get(event, "host.id"))
    agent_id        = _clean(_get(event, "agent.id"))

    # ── ECS: User ────────────────────────────────────────────────────────────
    user_name       = _clean(_get(event, "user.name"))
    user_domain     = _clean(_get(event, "user.domain"))
    user_id         = _clean(_get(event, "user.id"))

    # ── ECS: Process ─────────────────────────────────────────────────────────
    proc_name       = _clean(_get(event, "process.name"))
    proc_exe        = _clean(_get(event, "process.executable"))
    proc_cmdline    = _clean(_get(event, "process.command_line"))
    proc_pid        = _clean(_get(event, "process.pid"))
    parent_name     = _clean(_get(event, "process.parent.name"))
    parent_exe      = _clean(_get(event, "process.parent.executable"))

    # ── ECS: Network ─────────────────────────────────────────────────────────
    dst_ip          = _clean(_get(event, "destination.ip"))
    dst_port        = _clean(_get(event, "destination.port"))
    src_ip          = _clean(_get(event, "source.ip"))
    network_proto   = _clean(_get(event, "network.protocol"))
    network_dir     = _clean(_get(event, "network.direction"))

    # ── ECS: File ────────────────────────────────────────────────────────────
    file_path       = _clean(_get(event, "file.path"))
    file_hash       = _clean(_get(event, "file.hash.sha256") or _get(event, "file.hash.md5"))

    # ── ML anomaly ───────────────────────────────────────────────────────────
    ml_score        = _get(event, "kibana.alert.ml.is_interim") or \
                      _get(event, "result_type")
    anomaly_score   = float(_get(event, "record_score") or _get(event, "anomaly_score") or 0)
    is_ml_alert     = rule_type == "machine_learning"

    # ── Ancestors (alert lineage) ────────────────────────────────────────────
    ancestors       = _get(event, "kibana.alert.ancestors") or \
                      _get(event, "signal.ancestors.depth") or []
    ancestor_depth  = len(ancestors) if isinstance(ancestors, list) else 0
    has_lineage     = ancestor_depth > 0

    # ── Derived signals ──────────────────────────────────────────────────────
    severity_score  = _SEVERITY_SCORE.get((severity_raw or "medium").lower(), 0.55)
    rule_confidence = _RULE_TYPE_CONFIDENCE.get((rule_type or "query").lower(), 0.60)
    risk_normalized = min(1.0, float(risk_score_raw) / 100.0) if risk_score_raw else severity_score

    is_closed       = (alert_status or "").lower() in ("closed", "resolved", "acknowledged")
    is_building_block = building_block

    # ML: normalize anomaly score (Elastic uses 0-100)
    if is_ml_alert and anomaly_score > 0:
        ml_normalized = min(1.0, anomaly_score / 100.0)
    else:
        ml_normalized = 0.0

    # Presence flags
    has_rule_name   = rule_name is not None
    has_severity    = _truthy(severity_raw)
    has_risk_score  = float(risk_score_raw) > 0
    has_host        = host_name is not None
    has_user        = user_name is not None
    has_process     = proc_name is not None or proc_exe is not None
    has_cmdline     = proc_cmdline is not None
    has_parent      = parent_name is not None or parent_exe is not None
    has_network     = dst_ip is not None or src_ip is not None
    has_file        = file_path is not None
    has_agent       = agent_id is not None
    has_alert_id    = alert_id is not None
    has_os          = host_os is not None

    # ── T — Telemetry ────────────────────────────────────────────────────────
    alert_fields    = [has_rule_name, has_severity, has_risk_score, has_alert_id]
    host_fields     = [has_host, has_os, has_agent]
    identity_fields = [has_user]
    event_fields    = [has_process, has_cmdline, has_parent, has_network or has_file]
    context_fields  = [has_mitre, has_lineage, ti_matched]

    t = (
        sum(1.0 for x in alert_fields if x) / max(len(alert_fields), 1) * 0.30 +
        sum(1.0 for x in host_fields if x) / max(len(host_fields), 1) * 0.20 +
        sum(1.0 for x in identity_fields if x) / max(len(identity_fields), 1) * 0.15 +
        sum(1.0 for x in event_fields if x) / max(len(event_fields), 1) * 0.25 +
        sum(1.0 for x in context_fields if x) / max(len(context_fields), 1) * 0.10
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = (risk_normalized * 0.40) + (rule_confidence * 0.35) + (severity_score * 0.25)

    if ti_matched:              s = min(1.0, s + 0.10)
    if has_mitre:               s = min(1.0, s + 0.05)
    if is_ml_alert:             s = (s * 0.70) + (ml_normalized * 0.30)
    if is_building_block:       s = max(0.0, s - 0.15)  # building blocks = supporting, not actionable alone
    if is_closed:               s = max(0.0, s - 0.20)

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_host:                b += 0.10
    if has_user:                b += 0.10
    if has_process:             b += 0.10
    if has_cmdline:             b += 0.07
    if has_parent:              b += 0.07
    if has_mitre:               b += 0.08
    if has_lineage:             b += 0.05
    if ti_matched:              b += 0.05
    if has_network:             b += 0.03
    if is_building_block:       b = max(0.0, b - 0.10)

    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_user":             has_user,
        "has_host":             has_host,
        "has_command_line":     has_cmdline,
        "has_process_path":     has_process,
        "has_parent_process":   has_parent,
        "has_rule_name":        has_rule_name,
        "has_severity":         has_severity,
        "has_risk_score":       has_risk_score,
        "has_mitre":            has_mitre,
        "has_lineage":          has_lineage,
        "has_network":          has_network,
        "has_file":             has_file,
        "has_agent":            has_agent,
        "is_eql_rule":          rule_type == "eql",
        "is_ml_rule":           is_ml_alert,
        "is_ti_match":          ti_matched,
        "is_building_block":    is_building_block,
        "is_closed":            is_closed,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def elastic_to_inputs_and_flags(event):
    return extract(event)
