# dfs_core/features/cve_context.py
"""
CVE Context → DFS Inputs

This extractor answers a different question than the others.

All other DFS extractors ask:
  "Should I trust this ALERT enough to act on it?"

This extractor asks:
  "Should I trust that this VULNERABILITY is exploitable
   in MY environment, right now, enough to prioritize it?"

The Zero Day Clock problem (Epp, 2026):
  - Median TTE collapsed from 771 days (2018) to 4 hours (2024)
  - 67.2% of exploited CVEs in 2026 are zero-days
  - Organizations remediate only ~10% of new vulns per month
  - CVSS alone is wrong: <10% of all CVEs are ever exploited
  - Only 0.2% are used by ransomware / APT groups

DFS solves the prioritization problem:
  S (Signal Clarity):   Exploit availability + threat intelligence + weaponization stage
  T (Telemetry):        Asset context + reachability + runtime exposure completeness
  B (Behavioral):       Coherence between vulnerability severity and actual attack surface

Data sources integrated:
  - EPSS (Exploit Prediction Scoring System) — FIRST.org
  - CISA KEV (Known Exploited Vulnerabilities catalog)
  - NVD (National Vulnerability Database) — CVSS v3/v4
  - VulnCheck KEV (extended KEV)
  - ExploitDB / Metasploit availability flags
  - Runtime reachability context (from SAST/SCA/IAST tools)
  - Asset inventory context

Decision output:
  DFS ≥ 0.78 → AUTOMATE: patch now, no human needed
  0.55-0.78  → ESCALATE: security team must review today
  0.30-0.55  → TRIAGE:   add to sprint, schedule within 2 weeks
  < 0.30     → INVESTIGATE: backlog, review quarterly
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
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a", "0"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))


# ---------------------------------------------------------------------------
# CVSS v3 base score → normalized risk
# ---------------------------------------------------------------------------
def _cvss_to_risk(score: float) -> float:
    """
    CVSS 0-10 → 0.0-1.0
    But we deliberately compress the top end — CVSS 9.8 ≠ DFS 0.98
    because CVSS ignores exploitability context.
    """
    if score >= 9.5:  return 0.75
    if score >= 9.0:  return 0.70
    if score >= 8.0:  return 0.62
    if score >= 7.0:  return 0.52
    if score >= 6.0:  return 0.42
    if score >= 5.0:  return 0.33
    if score >= 4.0:  return 0.25
    return 0.15


# ---------------------------------------------------------------------------
# Exploit maturity levels
# ---------------------------------------------------------------------------
_EXPLOIT_MATURITY_RISK = {
    "weaponized":           1.00,  # works in the wild, automated
    "ransomware":           0.98,  # actively used by ransomware groups
    "apt":                  0.97,  # nation-state / APT usage confirmed
    "metasploit":           0.92,  # Metasploit module exists
    "exploitdb":            0.85,  # public PoC on ExploitDB
    "poc_public":           0.80,  # public proof-of-concept
    "poc_private":          0.70,  # private PoC (researcher-reported)
    "theoretical":          0.45,  # no public PoC, theoretical
    "unproven":             0.30,  # no evidence of exploitability
    "none":                 0.10,
}

# Attack vector → exposure multiplier
_ATTACK_VECTOR_MULTIPLIER = {
    "network":              1.00,  # internet-facing = maximum exposure
    "adjacent":             0.75,  # local network access required
    "local":                0.55,  # local access required
    "physical":             0.35,  # physical access required
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps CVE context event → (DFSInputs, flags).

    The 'event' dict combines:
      - CVE metadata (from NVD / scanner output)
      - Threat intelligence enrichment (EPSS, KEV, exploit DB)
      - Asset/environment context (from CMDB, SCA, runtime)
    """

    # ── CVE identity ─────────────────────────────────────────────────────────
    cve_id          = _clean(event.get("cve_id") or event.get("id") or event.get("cve"))
    published_date  = _clean(event.get("published_date") or event.get("published"))
    description     = _clean(event.get("description") or event.get("summary"))

    # ── CVSS scoring ─────────────────────────────────────────────────────────
    cvss_v3         = float(event.get("cvss_v3") or event.get("cvss_score") or
                            _get(event, "cvss.v3.base_score") or 0.0)
    cvss_v4         = float(event.get("cvss_v4") or _get(event, "cvss.v4.base_score") or 0.0)
    cvss_vector     = _clean(event.get("cvss_vector") or _get(event, "cvss.v3.vector"))
    cvss_severity   = _clean(event.get("cvss_severity") or event.get("severity"))

    # Use v4 if available, else v3
    cvss_score      = cvss_v4 if cvss_v4 > 0 else cvss_v3

    # Parse attack vector from CVSS vector string
    av_raw          = ""
    if cvss_vector:
        for part in cvss_vector.split("/"):
            if part.startswith("AV:"):
                av_map = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
                av_raw = av_map.get(part.split(":")[1], "network")

    attack_vector   = _clean(event.get("attack_vector") or av_raw or "network")
    attack_complex  = _clean(event.get("attack_complexity") or "low")
    privileges_req  = _clean(event.get("privileges_required") or "none")
    user_interaction = _clean(event.get("user_interaction") or "none")

    # ── Threat intelligence ──────────────────────────────────────────────────
    # EPSS (Exploit Prediction Scoring System) — 0.0 to 1.0
    epss_score      = float(event.get("epss_score") or event.get("epss") or 0.0)
    epss_percentile = float(event.get("epss_percentile") or 0.0)

    # CISA KEV
    in_cisa_kev     = bool(event.get("in_cisa_kev") or event.get("cisa_kev") or False)
    kev_date_added  = _clean(event.get("kev_date_added"))
    kev_due_date    = _clean(event.get("kev_due_date"))
    ransomware_use  = bool(event.get("known_ransomware_use") or
                           event.get("ransomware_campaigns") or False)

    # VulnCheck KEV (extended)
    in_vulncheck_kev = bool(event.get("in_vulncheck_kev") or False)

    # Exploit availability
    exploit_maturity = _clean(event.get("exploit_maturity") or
                               event.get("exploit_status") or "none")
    has_metasploit  = bool(event.get("has_metasploit_module") or
                           event.get("metasploit") or False)
    has_exploitdb   = bool(event.get("has_exploitdb") or event.get("exploitdb") or False)
    has_poc         = bool(event.get("has_public_poc") or event.get("poc") or
                           has_metasploit or has_exploitdb)
    exploit_count   = int(event.get("exploit_count") or event.get("exploits") or 0)

    # Zero-day flag
    is_zero_day     = bool(event.get("is_zero_day") or event.get("zero_day") or False)
    exploited_before_disclosure = bool(
        event.get("exploited_before_disclosure") or
        event.get("before_disclosure") or False
    )

    # ── Asset / environment context ──────────────────────────────────────────
    asset           = event.get("asset") or event.get("affected_asset") or {}
    asset_id        = _clean(asset.get("id") or asset.get("hostname") or
                             event.get("asset_id") or event.get("hostname"))
    asset_type      = _clean(asset.get("type") or asset.get("asset_type") or
                             event.get("asset_type"))
    asset_criticality = _clean(asset.get("criticality") or event.get("asset_criticality"))
    is_internet_facing = bool(asset.get("internet_facing") or
                              event.get("internet_facing") or False)
    is_in_production = bool(asset.get("in_production") or
                            event.get("in_production") or True)
    owner           = _clean(asset.get("owner") or event.get("asset_owner"))
    environment     = _clean(asset.get("environment") or event.get("environment"))

    # ── Reachability (from SCA/SAST/IAST) ───────────────────────────────────
    reachability    = event.get("reachability") or event.get("reach") or {}
    is_reachable    = bool(reachability.get("is_reachable") or
                           event.get("is_reachable") or False)
    reachability_confidence = float(reachability.get("confidence") or
                                    event.get("reachability_confidence") or 0.0)
    call_path_exists = bool(reachability.get("call_path_exists") or
                            event.get("call_path") or False)
    loaded_in_runtime = bool(reachability.get("loaded_in_runtime") or
                             event.get("runtime_loaded") or False)

    # ── Patch availability ───────────────────────────────────────────────────
    patch           = event.get("patch") or event.get("remediation") or {}
    patch_available = bool(patch.get("available") or event.get("patch_available") or False)
    patch_version   = _clean(patch.get("version") or event.get("patch_version"))
    days_since_patch = float(patch.get("days_available") or
                             event.get("days_since_patch") or 0.0)
    patch_complexity = _clean(patch.get("complexity") or event.get("patch_complexity") or "medium")

    # ── Derived signals ──────────────────────────────────────────────────────
    cvss_risk       = _cvss_to_risk(cvss_score)
    av_multiplier   = _ATTACK_VECTOR_MULTIPLIER.get((attack_vector or "network").lower(), 1.0)

    # Exploit maturity risk
    em_raw          = (exploit_maturity or "none").lower()
    if ransomware_use:      em_raw = "ransomware"
    elif has_metasploit:    em_raw = max(em_raw, "metasploit",
                                        key=lambda x: _EXPLOIT_MATURITY_RISK.get(x, 0))
    elif has_exploitdb:     em_raw = max(em_raw, "exploitdb",
                                        key=lambda x: _EXPLOIT_MATURITY_RISK.get(x, 0))
    exploit_risk    = _EXPLOIT_MATURITY_RISK.get(em_raw, 0.30)

    # EPSS is our best single predictor — weight it heavily
    epss_weight     = epss_score  # already 0.0-1.0

    is_critical     = cvss_score >= 9.0
    is_high         = cvss_score >= 7.0
    is_actively_exploited = in_cisa_kev or ransomware_use or exploit_risk >= 0.90
    is_high_epss    = epss_score >= 0.50  # top ~2% of all CVEs
    is_very_high_epss = epss_score >= 0.90
    complex_attack  = (attack_complex or "").lower() == "high"
    needs_user_interaction = (user_interaction or "").lower() == "required"
    needs_privileges = (privileges_req or "").lower() in ("low", "high")

    # Presence flags
    has_cve_id      = cve_id is not None
    has_cvss        = cvss_score > 0
    has_epss        = epss_score > 0
    has_kev_data    = in_cisa_kev or in_vulncheck_kev
    has_exploit_data = _truthy(exploit_maturity) and exploit_maturity != "none"
    has_asset       = asset_id is not None
    has_owner       = owner is not None
    has_reachability = is_reachable or reachability_confidence > 0
    has_patch       = patch_available
    has_criticality = asset_criticality is not None
    has_description = description is not None

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    # Without reachability and asset context, CVSS alone is just noise
    vuln_fields     = [has_cve_id, has_cvss, has_description, has_epss]
    threat_fields   = [has_kev_data, has_exploit_data, bool(exploit_count > 0)]
    asset_fields    = [has_asset, has_owner, has_criticality, is_in_production]
    reach_fields    = [has_reachability, call_path_exists, loaded_in_runtime]

    t = (
        sum(1.0 for x in vuln_fields if x) / max(len(vuln_fields), 1) * 0.25 +
        sum(1.0 for x in threat_fields if x) / max(len(threat_fields), 1) * 0.30 +
        sum(1.0 for x in asset_fields if x) / max(len(asset_fields), 1) * 0.25 +
        sum(1.0 for x in reach_fields if x) / max(len(reach_fields), 1) * 0.20
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    # Blend: EPSS (best predictor) + exploit maturity + CVSS (weakest alone)
    s = (epss_weight * 0.40) + (exploit_risk * 0.35) + (cvss_risk * 0.25)

    # Hard boosts for confirmed exploitation
    if in_cisa_kev:             s = _clamp(s + 0.20)
    if ransomware_use:          s = _clamp(s + 0.18)
    if is_zero_day:             s = _clamp(s + 0.15)
    if exploited_before_disclosure: s = _clamp(s + 0.15)
    if in_vulncheck_kev:        s = _clamp(s + 0.10)
    if is_internet_facing:      s = _clamp(s + 0.08)
    if has_metasploit:          s = _clamp(s + 0.05)

    # Reduce signal for vulnerabilities that require complex conditions
    if complex_attack:          s = _clamp(s - 0.08)
    if needs_user_interaction:  s = _clamp(s - 0.05)
    if needs_privileges:        s = _clamp(s - 0.05)
    if not is_reachable and has_reachability:
                                s = _clamp(s - 0.15)  # confirmed unreachable

    s = _clamp(s)

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    # Coherence = CVSS severity matches actual exploitation evidence + asset context
    b = 0.35

    if has_asset:               b += 0.10
    if has_reachability:        b += 0.12
    if is_reachable:            b += 0.08  # confirmed reachable = coherent narrative
    if call_path_exists:        b += 0.07
    if loaded_in_runtime:       b += 0.07
    if has_epss:                b += 0.06  # EPSS adds probabilistic context
    if has_kev_data:            b += 0.05  # KEV = confirmed exploitation narrative
    if has_owner:               b += 0.05  # known owner = actionable
    if is_internet_facing:      b += 0.05

    # Incoherence: high CVSS but no exploitation evidence
    if is_critical and not has_poc and not in_cisa_kev and epss_score < 0.05:
        b = _clamp(b - 0.15)  # classic CVSS inflation

    # Incoherence: no reachability data at all
    if not has_reachability:    b = _clamp(b - 0.10)

    b = _clamp(b)

    flags = {
        # Standard DFS
        "has_user":                     has_owner,
        "has_host":                     has_asset,
        "has_command_line":             has_exploit_data,
        "has_process_path":             has_cvss,
        "has_parent_process":           has_reachability,
        # CVE-specific
        "has_cve_id":                   has_cve_id,
        "has_cvss":                     has_cvss,
        "has_epss":                     has_epss,
        "has_kev_data":                 has_kev_data,
        "has_exploit_data":             has_exploit_data,
        "has_asset":                    has_asset,
        "has_reachability":             has_reachability,
        "has_patch":                    has_patch,
        # Threat signals
        "in_cisa_kev":                  in_cisa_kev,
        "in_vulncheck_kev":             in_vulncheck_kev,
        "is_zero_day":                  is_zero_day,
        "exploited_before_disclosure":  exploited_before_disclosure,
        "ransomware_use":               ransomware_use,
        "has_metasploit":               has_metasploit,
        "has_public_poc":               has_poc,
        "is_actively_exploited":        is_actively_exploited,
        "is_high_epss":                 is_high_epss,
        "is_very_high_epss":            is_very_high_epss,
        # Asset context
        "is_internet_facing":           is_internet_facing,
        "is_reachable":                 is_reachable,
        "call_path_exists":             call_path_exists,
        "is_critical_asset":            (asset_criticality or "").lower() == "critical",
        # Complexity reducers
        "complex_attack":               complex_attack,
        "needs_user_interaction":       needs_user_interaction,
        "cvss_inflation":               is_critical and not has_poc and epss_score < 0.05,
    }

    return DFSInputs(_clamp(s), _clamp(t), _clamp(b)), flags


def cve_to_inputs_and_flags(event):
    return extract(event)
