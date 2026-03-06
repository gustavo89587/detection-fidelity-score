# dfs_core/features/splunk_notable.py
"""
Splunk SIEM / Notable Event → DFS Inputs

Splunk Enterprise Security generates "notable events" from:
  - Correlation searches (SPL saved searches)
  - Risk-based alerting (RBA) — risk scores accumulate per entity
  - Adaptive Response actions
  - ESCU (Enterprise Security Content Updates) detections

Notable event fields:
  source, sourcetype, index, splunk_server
  rule_name, rule_description, rule_title
  severity, urgency, priority
  risk_score, risk_object, risk_object_type
  orig_sourcetype, orig_source, orig_index
  search_name, correlation_search_name
  Notable Event fields: event_id, status, owner, comment
  Entity fields: src, dest, user, dvc
  MITRE: mitre_technique_id, mitre_tactic

RBA (Risk Based Alerting):
  risk_score accumulates per entity (user/system)
  risk_object is the entity being scored
  Multiple low-risk events can trigger a notable via risk threshold
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from dfs_core.scoring import DFSInputs


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a", "unspecified"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


# Splunk ES urgency → risk
_URGENCY_SCORE = {
    "critical": 0.95,
    "high":     0.78,
    "medium":   0.55,
    "low":      0.28,
    "info":     0.10,
    "informational": 0.10,
}

# Splunk severity labels
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

    # ── Notable / correlation fields ─────────────────────────────────────────
    rule_name       = _clean(
        event.get("rule_name") or event.get("rule_title") or
        event.get("search_name") or event.get("correlation_search_name")
    )
    rule_desc       = _clean(event.get("rule_description") or event.get("description"))
    urgency         = _clean(event.get("urgency") or event.get("Urgency") or "medium")
    severity        = _clean(event.get("severity") or event.get("Severity") or "medium")
    priority        = _clean(event.get("priority") or event.get("Priority"))
    event_id        = _clean(event.get("event_id") or event.get("notable_id"))
    status          = _clean(event.get("status") or event.get("Status") or "new")
    owner           = _clean(event.get("owner") or event.get("Owner"))
    comment         = _clean(event.get("comment"))

    # ── Risk Based Alerting ──────────────────────────────────────────────────
    risk_score      = float(event.get("risk_score") or event.get("calculated_risk_score") or 0)
    risk_object     = _clean(event.get("risk_object") or event.get("risk_object_name"))
    risk_object_type = _clean(event.get("risk_object_type") or "system")
    contributing_events = int(event.get("contributing_events_count") or event.get("event_count") or 1)
    is_rba          = risk_object is not None and risk_score > 0

    # ── Entity fields (Splunk ES standard) ───────────────────────────────────
    src             = _clean(event.get("src") or event.get("src_ip"))
    dest            = _clean(event.get("dest") or event.get("dest_ip"))
    user            = _clean(event.get("user") or event.get("src_user") or event.get("dest_user"))
    dvc             = _clean(event.get("dvc") or event.get("host"))
    src_host        = _clean(event.get("src_host") or event.get("src_dns"))
    dest_host       = _clean(event.get("dest_host") or event.get("dest_dns"))

    # ── Process fields ───────────────────────────────────────────────────────
    process         = _clean(event.get("process") or event.get("process_name"))
    process_path    = _clean(event.get("process_path") or event.get("process_exec"))
    cmdline         = _clean(event.get("process") or event.get("cmdline") or event.get("CommandLine"))
    parent_process  = _clean(event.get("parent_process") or event.get("parent_process_name"))

    # ── Network fields ───────────────────────────────────────────────────────
    dest_port       = _clean(event.get("dest_port") or event.get("port"))
    transport       = _clean(event.get("transport") or event.get("protocol"))
    bytes_out       = event.get("bytes_out") or event.get("bytes_sent") or 0
    bytes_in        = event.get("bytes_in") or event.get("bytes_recv") or 0

    # ── MITRE ────────────────────────────────────────────────────────────────
    mitre_technique = _clean(event.get("mitre_technique_id") or event.get("annotations.mitre_attack.technique_id"))
    mitre_tactic    = _clean(event.get("mitre_tactic") or event.get("annotations.mitre_attack.tactic"))
    has_mitre       = mitre_technique is not None or mitre_tactic is not None

    # ── Source context ───────────────────────────────────────────────────────
    orig_sourcetype = _clean(event.get("orig_sourcetype") or event.get("sourcetype"))
    orig_source     = _clean(event.get("orig_source") or event.get("source"))
    splunk_server   = _clean(event.get("splunk_server"))

    # ── Derived signals ──────────────────────────────────────────────────────
    urgency_score   = _URGENCY_SCORE.get((urgency or "medium").lower(), 0.55)
    severity_score  = _SEVERITY_SCORE.get((severity or "medium").lower(), 0.55)
    risk_normalized = min(1.0, risk_score / 100.0) if risk_score > 0 else urgency_score

    is_new          = (status or "").lower() in ("new", "unassigned", "")
    is_closed       = (status or "").lower() in ("closed", "resolved", "auto-resolved")
    is_assigned     = _truthy(owner) and (owner or "").lower() not in ("nobody", "unassigned")
    high_contributing = contributing_events >= 5  # multiple events → more coherent

    # Presence flags
    has_rule        = rule_name is not None
    has_urgency     = _truthy(urgency)
    has_src         = src is not None
    has_dest        = dest is not None
    has_user        = user is not None
    has_dvc         = dvc is not None
    has_process     = process is not None or process_path is not None
    has_cmdline     = cmdline is not None
    has_parent      = parent_process is not None
    has_risk_obj    = risk_object is not None
    has_event_id    = event_id is not None
    has_sourcetype  = orig_sourcetype is not None

    # ── T — Telemetry ────────────────────────────────────────────────────────
    alert_fields    = [has_rule, has_urgency, has_event_id, has_sourcetype]
    entity_fields   = [has_src or has_dest, has_user, has_dvc]
    process_fields  = [has_process, has_cmdline, has_parent]
    context_fields  = [has_mitre, is_rba, high_contributing]

    t = (
        sum(1.0 for x in alert_fields if x) / max(len(alert_fields), 1) * 0.30 +
        sum(1.0 for x in entity_fields if x) / max(len(entity_fields), 1) * 0.30 +
        sum(1.0 for x in process_fields if x) / max(len(process_fields), 1) * 0.25 +
        sum(1.0 for x in context_fields if x) / max(len(context_fields), 1) * 0.15
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = (risk_normalized * 0.45) + (urgency_score * 0.35) + (severity_score * 0.20)

    if has_mitre:               s = min(1.0, s + 0.05)
    if high_contributing:       s = min(1.0, s + 0.05)
    if is_rba and risk_score >= 80: s = min(1.0, s + 0.08)
    if is_closed:               s = max(0.0, s - 0.20)

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_user:                b += 0.12
    if has_dvc:                 b += 0.10
    if has_process:             b += 0.10
    if has_cmdline:             b += 0.08
    if has_src and has_dest:    b += 0.07
    if has_mitre:               b += 0.07
    if is_rba:                  b += 0.05
    if high_contributing:       b += 0.03
    if is_closed:               b = max(0.0, b - 0.10)

    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_user":             has_user,
        "has_host":             has_dvc,
        "has_command_line":     has_cmdline,
        "has_process_path":     has_process,
        "has_parent_process":   has_parent,
        "has_rule":             has_rule,
        "has_urgency":          has_urgency,
        "has_src":              has_src,
        "has_dest":             has_dest,
        "has_risk_object":      has_risk_obj,
        "has_mitre":            has_mitre,
        "is_rba":               is_rba,
        "is_new":               is_new,
        "is_closed":            is_closed,
        "is_assigned":          is_assigned,
        "high_contributing":    high_contributing,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def splunk_to_inputs_and_flags(event):
    return extract(event)
