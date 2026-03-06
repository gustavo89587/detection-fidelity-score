# dfs_core/features/wazuh_alert.py
"""
Wazuh Alert → DFS Inputs

Wazuh is an open-source XDR/SIEM that generates alerts from:
  - File integrity monitoring (FIM)
  - Log analysis (decoders + rules)
  - Vulnerability detection
  - Active response
  - SCA (Security Configuration Assessment)
  - AWS/Azure/GCP integrations
  - Docker monitoring
  - Syscall monitoring (via auditd)

Alert JSON schema:
  _id, _index, _source
  _source.rule.id, rule.level, rule.description, rule.groups
  _source.agent.id, agent.name, agent.ip
  _source.manager.name
  _source.data.* (varies by decoder/integration)
  _source.syscheck.* (FIM events)
  _source.vulnerability.* (CVE data)
  _source.timestamp

Rule levels: 0-15
  0-3:   Informational
  4-7:   Low
  8-11:  Medium
  12-14: High
  15:    Critical
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


def _rule_level_to_score(level: Any) -> float:
    try:
        l = int(level)
        if l >= 15:   return 0.95
        if l >= 12:   return 0.82
        if l >= 8:    return 0.62
        if l >= 4:    return 0.38
        return 0.15
    except (TypeError, ValueError):
        return 0.30


# High-risk Wazuh rule groups
_HIGH_RISK_GROUPS = {
    "rootkit", "trojan", "exploit", "web_attack", "sql_injection",
    "shellshock", "attack", "intrusion_detection", "syscheck",
    "authentication_failed", "authentication_failures", "brute_force",
    "invalid_login", "multiple_authentication_failures",
    "privilege_escalation", "pci_dss_10", "gdpr_IV",
    "malware", "virus", "ransomware", "cryptominer",
    "lateral_movement", "c2", "exfiltration", "persistence",
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Wazuh alert JSON → (DFSInputs, flags).
    Accepts both raw _source and unwrapped alert.
    """

    # Support both wrapped (_source) and unwrapped formats
    src = event.get("_source") or event

    # ── Rule context ─────────────────────────────────────────────────────────
    rule            = src.get("rule") or {}
    rule_id         = _clean(rule.get("id"))
    rule_level      = rule.get("level") or 0
    rule_desc       = _clean(rule.get("description"))
    rule_groups     = rule.get("groups") or []
    rule_mitre      = rule.get("mitre") or {}
    rule_firedtimes = int(rule.get("firedtimes") or 1)
    rule_mail       = bool(rule.get("mail"))

    mitre_ids       = rule_mitre.get("id") or []
    mitre_tactics   = rule_mitre.get("tactic") or []
    mitre_techniques = rule_mitre.get("technique") or []
    has_mitre       = len(mitre_ids) > 0 or len(mitre_tactics) > 0

    # ── Agent context ─────────────────────────────────────────────────────────
    agent           = src.get("agent") or {}
    agent_id        = _clean(agent.get("id"))
    agent_name      = _clean(agent.get("name"))
    agent_ip        = _clean(agent.get("ip"))
    agent_labels    = agent.get("labels") or {}

    manager         = src.get("manager") or {}
    manager_name    = _clean(manager.get("name"))

    # ── Timestamp ────────────────────────────────────────────────────────────
    timestamp       = _clean(src.get("timestamp") or src.get("@timestamp"))

    # ── Data fields (varies by decoder) ──────────────────────────────────────
    data            = src.get("data") or {}

    # Common decoded fields
    src_ip          = _clean(data.get("srcip") or data.get("src_ip") or _get(data, "aws.sourceIPAddress"))
    dst_ip          = _clean(data.get("dstip") or data.get("dst_ip"))
    src_port        = _clean(data.get("srcport") or data.get("src_port"))
    dst_port        = _clean(data.get("dstport") or data.get("dst_port"))
    src_user        = _clean(data.get("srcuser") or data.get("src_user") or data.get("user"))
    protocol        = _clean(data.get("protocol") or data.get("proto"))
    url             = _clean(data.get("url") or _get(data, "http.url"))
    status_code     = _clean(data.get("id") or _get(data, "http.response.status_code"))
    command         = _clean(data.get("command") or data.get("cmd") or data.get("process_name"))

    # ── FIM (syscheck) ───────────────────────────────────────────────────────
    syscheck        = src.get("syscheck") or {}
    fim_path        = _clean(syscheck.get("path"))
    fim_event       = _clean(syscheck.get("event"))  # added, modified, deleted
    fim_user_name   = _clean(syscheck.get("uname_after") or syscheck.get("uname"))
    is_fim_event    = bool(fim_path)

    # ── Vulnerability ────────────────────────────────────────────────────────
    vuln            = src.get("vulnerability") or {}
    cve_id          = _clean(vuln.get("cve"))
    cvss_score      = float(vuln.get("cvss", {}).get("cvss3", {}).get("base_score") or
                            vuln.get("severity_score") or 0)
    vuln_severity   = _clean(vuln.get("severity"))
    is_vuln_event   = bool(cve_id)

    # ── SCA (Security Config Assessment) ─────────────────────────────────────
    sca             = src.get("sca") or {}
    sca_check       = _clean(_get(sca, "check.title"))
    sca_result      = _clean(_get(sca, "check.result"))  # passed, failed, not applicable
    is_sca_fail     = sca_result == "failed"

    # ── Derived signals ──────────────────────────────────────────────────────
    level_score     = _rule_level_to_score(rule_level)
    groups_lower    = [str(g).lower() for g in rule_groups]
    is_high_risk_group = any(g in _HIGH_RISK_GROUPS for g in groups_lower)
    is_brute_force  = any("brute" in g or "authentication_fail" in g for g in groups_lower)
    is_web_attack   = any("web_attack" in g or "sql" in g or "xss" in g for g in groups_lower)
    is_fim_critical = is_fim_event and fim_event in ("modified", "deleted") and fim_path and \
                      any(fim_path.startswith(p) for p in ("/etc/", "/bin/", "/sbin/", "/usr/bin/", "C:\\Windows\\System32"))
    high_frequency  = rule_firedtimes >= 10

    # Presence flags
    has_rule_id     = rule_id is not None
    has_rule_desc   = rule_desc is not None
    has_agent       = agent_id is not None
    has_agent_name  = agent_name is not None
    has_agent_ip    = agent_ip is not None
    has_manager     = manager_name is not None
    has_src_ip      = src_ip is not None
    has_dst_ip      = dst_ip is not None
    has_src_user    = src_user is not None
    has_command     = command is not None
    has_fim         = is_fim_event
    has_mitre_data  = has_mitre
    has_timestamp   = timestamp is not None
    has_cve         = cve_id is not None

    # ── T — Telemetry ────────────────────────────────────────────────────────
    rule_fields     = [has_rule_id, has_rule_desc, _truthy(rule_level)]
    agent_fields    = [has_agent, has_agent_name, has_manager]
    event_fields    = [has_src_ip or has_dst_ip, has_src_user, has_command or has_fim]
    context_fields  = [has_mitre_data, has_timestamp, has_agent_ip]

    t = (
        sum(1.0 for x in rule_fields if x) / max(len(rule_fields), 1) * 0.30 +
        sum(1.0 for x in agent_fields if x) / max(len(agent_fields), 1) * 0.30 +
        sum(1.0 for x in event_fields if x) / max(len(event_fields), 1) * 0.25 +
        sum(1.0 for x in context_fields if x) / max(len(context_fields), 1) * 0.15
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = level_score

    if is_high_risk_group:      s = min(1.0, s + 0.15)
    if is_brute_force:          s = min(1.0, s + 0.10)
    if is_web_attack:           s = min(1.0, s + 0.12)
    if is_fim_critical:         s = min(1.0, s + 0.15)
    if has_mitre:               s = min(1.0, s + 0.05)
    if high_frequency:          s = min(1.0, s + 0.08)
    if is_vuln_event and cvss_score >= 9.0: s = min(1.0, s + 0.10)

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_agent_name:          b += 0.12
    if has_src_user:            b += 0.10
    if has_src_ip:              b += 0.08
    if has_command:             b += 0.08
    if has_mitre:               b += 0.08
    if has_fim:                 b += 0.06
    if high_frequency:          b += 0.05
    if has_agent_ip:            b += 0.04
    if is_sca_fail:             b += 0.04

    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_user":             has_src_user,
        "has_host":             has_agent_name,
        "has_command_line":     has_command,
        "has_process_path":     has_command,
        "has_parent_process":   False,
        "has_rule_id":          has_rule_id,
        "has_rule_desc":        has_rule_desc,
        "has_agent":            has_agent,
        "has_src_ip":           has_src_ip,
        "has_dst_ip":           has_dst_ip,
        "has_mitre":            has_mitre_data,
        "has_fim":              has_fim,
        "has_cve":              has_cve,
        "is_high_risk_group":   is_high_risk_group,
        "is_brute_force":       is_brute_force,
        "is_web_attack":        is_web_attack,
        "is_fim_critical":      is_fim_critical,
        "is_vuln_event":        is_vuln_event,
        "is_sca_fail":          is_sca_fail,
        "high_frequency":       high_frequency,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def wazuh_to_inputs_and_flags(event):
    return extract(event)
