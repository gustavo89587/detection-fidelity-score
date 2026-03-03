#!/usr/bin/env python3
# dfs_ai_v2.py
import argparse
import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd

# Optional PDF
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False


# -----------------------------
# Utils
# -----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def run_id_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


# -----------------------------
# Policy (Relevance)
# -----------------------------
DEFAULT_POLICY = {
    "min_structural_risk": 0.50,
    "min_drift": 0.60,
    "flag_prompt_leak_attempt": True,
    "flag_indirect_injection": True,
    "flag_shadow_ai": True,
}

def relevance_filter(df: pd.DataFrame, policy: dict) -> pd.DataFrame:
    """
    Data Relevance Policy: keep only security-relevant rows BEFORE detection.
    """
    p = {**DEFAULT_POLICY, **(policy or {})}

    cond = (
        (pd.to_numeric(df["structural_risk"], errors="coerce").fillna(0.0) >= p["min_structural_risk"]) |
        (pd.to_numeric(df["drift"], errors="coerce").fillna(0.0) >= p["min_drift"])
    )

    if p["flag_prompt_leak_attempt"]:
        cond = cond | (pd.to_numeric(df["prompt_leak_attempt"], errors="coerce").fillna(0).astype(int) == 1)
    if p["flag_indirect_injection"]:
        cond = cond | (pd.to_numeric(df["indirect_injection"], errors="coerce").fillna(0).astype(int) == 1)
    if p["flag_shadow_ai"]:
        cond = cond | (pd.to_numeric(df["shadow_ai"], errors="coerce").fillna(0).astype(int) == 1)

    # Always keep rows where a gate triggered (audit / justification)
    cond = cond | (pd.to_numeric(df["gate_triggered"], errors="coerce").fillna(0).astype(int) == 1)
    cond = cond | (pd.to_numeric(df["structural_gate"], errors="coerce").fillna(0).astype(int) == 1)

    return df[cond].copy()


# -----------------------------
# Alerts
# -----------------------------
@dataclass
class Alert:
    run_id: Any
    detector_id: str
    alert_level: int  # 1,2,3
    severity: str     # low/medium/high/critical
    confidence: float
    entity_type: str  # run/step
    entity_id: str
    timestamp_first: str
    timestamp_last: str
    count_events: int
    summary: str
    evidence: Dict[str, Any]
    tags: List[str]

    def row(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "detector_id": self.detector_id,
            "alert_level": int(self.alert_level),
            "severity": self.severity,
            "confidence": round(float(self.confidence), 3),
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "timestamp_first": self.timestamp_first,
            "timestamp_last": self.timestamp_last,
            "count_events": int(self.count_events),
            "summary": self.summary,
            "evidence_json": json.dumps(self.evidence, ensure_ascii=False),
            "tags": ",".join(self.tags),
        }


def detector_structural_risk(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []

    d = df.copy()
    d["structural_risk"] = pd.to_numeric(d["structural_risk"], errors="coerce").fillna(0.0)
    d["structural_gate"] = pd.to_numeric(d["structural_gate"], errors="coerce").fillna(0).astype(int)

    risky = d[(d["structural_risk"] >= 0.70) | (d["structural_gate"] == 1)].copy()
    for _, r in risky.iterrows():
        level = 3
        sev = "critical" if r["structural_risk"] >= 0.9 or r["structural_gate"] == 1 else "high"
        conf = 0.85 if r["structural_gate"] == 1 else 0.78
        alerts.append(Alert(
            run_id=r["run_id"],
            detector_id="structural_risk_escalation",
            alert_level=level,
            severity=sev,
            confidence=conf,
            entity_type="run",
            entity_id=str(r["run_id"]),
            timestamp_first=str(r.get("ts") or ""),
            timestamp_last=str(r.get("ts") or ""),
            count_events=1,
            summary=f"Risco estrutural elevado no step={r['step']} stage={r['stage']} (risk={r['structural_risk']}).",
            evidence={
                "step": int(r["step"]),
                "stage": str(r["stage"]),
                "structural_risk": float(r["structural_risk"]),
                "structural_gate": int(r["structural_gate"]),
                "decision": str(r["decision"]),
                "decision_reason": str(r["decision_reason"]),
            },
            tags=["ai.runtime", "risk.structural", "level.3"]
        ))
    return alerts


def detector_prompt_injection(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []

    d = df.copy()
    d["prompt_leak_attempt"] = pd.to_numeric(d["prompt_leak_attempt"], errors="coerce").fillna(0).astype(int)
    d["indirect_injection"] = pd.to_numeric(d["indirect_injection"], errors="coerce").fillna(0).astype(int)

    inj = d[(d["prompt_leak_attempt"] == 1) | (d["indirect_injection"] == 1)].copy()
    for _, r in inj.iterrows():
        alerts.append(Alert(
            run_id=r["run_id"],
            detector_id="prompt_injection_attempt",
            alert_level=3,
            severity="critical",
            confidence=0.90,
            entity_type="run",
            entity_id=str(r["run_id"]),
            timestamp_first=str(r.get("ts") or ""),
            timestamp_last=str(r.get("ts") or ""),
            count_events=1,
            summary=f"Sinal de prompt injection/leak no step={r['step']} stage={r['stage']}.",
            evidence={
                "step": int(r["step"]),
                "stage": str(r["stage"]),
                "prompt_leak_attempt": int(r["prompt_leak_attempt"]),
                "indirect_injection": int(r["indirect_injection"]),
                "trust": str(r["trust"]),
                "reasons": str(r["reasons"]),
                "decision": str(r["decision"]),
            },
            tags=["ai.runtime", "attack.injection", "level.3"]
        ))
    return alerts


def detector_drift_low_trust(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []

    d = df.copy()
    d["drift"] = pd.to_numeric(d["drift"], errors="coerce").fillna(0.0)

    risky = d[(d["drift"] >= 0.60) & (d["trust"].astype(str).str.upper() == "LOW")].copy()
    for _, r in risky.iterrows():
        alerts.append(Alert(
            run_id=r["run_id"],
            detector_id="drift_low_trust",
            alert_level=2,
            severity="medium",
            confidence=0.70,
            entity_type="run",
            entity_id=str(r["run_id"]),
            timestamp_first=str(r.get("ts") or ""),
            timestamp_last=str(r.get("ts") or ""),
            count_events=1,
            summary=f"Drift alto com baixa confiança no step={r['step']} stage={r['stage']} (drift={r['drift']}).",
            evidence={
                "step": int(r["step"]),
                "stage": str(r["stage"]),
                "drift": float(r["drift"]),
                "trust": str(r["trust"]),
                "gate_triggered": int(pd.to_numeric(r["gate_triggered"], errors="coerce") or 0),
                "reasons": str(r["reasons"]),
            },
            tags=["ai.runtime", "risk.drift", "level.2"]
        ))
    return alerts


def run_detectors(df_filtered: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    alerts += detector_prompt_injection(df_filtered)
    alerts += detector_structural_risk(df_filtered)
    alerts += detector_drift_low_trust(df_filtered)
    return alerts


# -----------------------------
# Incident aggregation + timeline (Enterprise layer)
# -----------------------------
def aggregate_incidents(df_all: pd.DataFrame, alerts_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Consolidate step-level alerts into incident-level objects per run_id.
    Goal: show ONE incident vs many alerts.
    """
    incidents: List[Dict[str, Any]] = []
    if df_all.empty:
        return incidents

    a = alerts_df.copy() if not alerts_df.empty else pd.DataFrame()

    for run_id, run_steps in df_all.groupby("run_id"):
        run_steps = run_steps.copy()
        run_steps["structural_risk"] = pd.to_numeric(run_steps["structural_risk"], errors="coerce").fillna(0.0)
        run_steps["drift"] = pd.to_numeric(run_steps["drift"], errors="coerce").fillna(0.0)

        # Signals (raw trace)
        has_block = (run_steps["decision"].astype(str).str.upper() == "BLOCK").any()
        has_structural_gate = (pd.to_numeric(run_steps["structural_gate"], errors="coerce").fillna(0).astype(int) == 1).any()
        has_prompt_leak = (pd.to_numeric(run_steps["prompt_leak_attempt"], errors="coerce").fillna(0).astype(int) == 1).any()
        has_indirect_inj = (pd.to_numeric(run_steps["indirect_injection"], errors="coerce").fillna(0).astype(int) == 1).any()
        has_shadow_ai = (pd.to_numeric(run_steps["shadow_ai"], errors="coerce").fillna(0).astype(int) == 1).any()

        max_risk = float(run_steps["structural_risk"].max())
        max_drift = float(run_steps["drift"].max())

        # Alerts presence
        run_alerts = a[a["run_id"] == run_id] if not a.empty else pd.DataFrame()
        dets = set(run_alerts["detector_id"].astype(str).tolist()) if not run_alerts.empty else set()

        has_injection_alert = "prompt_injection_attempt" in dets
        has_structural_alert = "structural_risk_escalation" in dets

        # Qualification rule (POC-strong and explainable)
        qualifies = (has_prompt_leak or has_indirect_inj or has_injection_alert) and (max_risk >= 0.7 or has_structural_gate or has_structural_alert)
        if not qualifies:
            continue

        # Severity & confidence
        if has_structural_gate or has_block or max_risk >= 0.9:
            severity = "CRITICAL"
            confidence = 0.91
        else:
            severity = "HIGH"
            confidence = 0.82

        # Attack chain narrative
        chain: List[str] = []
        if has_indirect_inj:
            chain.append("Indirect Injection")
        if max_drift >= 0.6:
            chain.append("Drift Escalation")
        if has_prompt_leak:
            chain.append("Prompt Leak Attempt")
        if has_shadow_ai:
            chain.append("Shadow AI Activity")
        if has_structural_gate:
            chain.append("Structural Gate Activated")

        # First step where risk crosses threshold 0.7
        run_sorted = run_steps.sort_values("step")
        risk_series = run_sorted["structural_risk"]
        crossed_at = None
        if (risk_series >= 0.7).any():
            idx = risk_series[risk_series >= 0.7].index[0]
            row = run_sorted.loc[idx]
            crossed_at = {"step": int(row["step"]), "stage": str(row["stage"]), "risk": float(row["structural_risk"])}

        incidents.append({
            "incident_id": f"INC-{run_id}-STRUCTURAL_COMPROMISE",
            "run_id": run_id,
            "severity": severity,
            "confidence": confidence,
            "final_decision": "BLOCK" if has_block else "REVIEW",
            "total_alerts": int(len(run_alerts)) if not run_alerts.empty else 0,
            "max_structural_risk": round(max_risk, 3),
            "max_drift": round(max_drift, 3),
            "attack_chain": chain,
            "risk_threshold_crossed_at": crossed_at,
        })

    return incidents


def build_risk_timeline(df_all: pd.DataFrame, run_id: Any) -> List[Dict[str, Any]]:
    run = df_all[df_all["run_id"] == run_id].sort_values("step").copy()
    if run.empty:
        return []

    run["drift"] = pd.to_numeric(run["drift"], errors="coerce").fillna(0.0)
    run["structural_risk"] = pd.to_numeric(run["structural_risk"], errors="coerce").fillna(0.0)

    out: List[Dict[str, Any]] = []
    for _, row in run.iterrows():
        out.append({
            "step": int(row["step"]),
            "stage": str(row["stage"]),
            "drift": float(row["drift"]),
            "structural_risk": float(row["structural_risk"]),
            "decision": str(row["decision"]),
        })
    return out


# -----------------------------
# Simulation (Datasets)
# -----------------------------
COLUMNS = [
    "ts","run_id","step","stage",
    "loss","distortion","drift","base","penalty",
    "gate_triggered","reasons","score","trust",
    "prompt_leak_attempt","indirect_injection","shadow_ai",
    "delegation_depth","structural_risk","structural_gate",
    "decision","decision_reason"
]

def _row(ts, run_id, step, stage,
         loss, distortion, drift, base, penalty,
         gate_triggered, reasons, score, trust,
         prompt_leak_attempt, indirect_injection, shadow_ai,
         delegation_depth, structural_risk, structural_gate,
         decision, decision_reason) -> Dict[str, Any]:
    return {
        "ts": ts,
        "run_id": run_id,
        "step": step,
        "stage": stage,
        "loss": round(loss, 3),
        "distortion": round(distortion, 3),
        "drift": round(drift, 3),
        "base": round(base, 3),
        "penalty": round(penalty, 3),
        "gate_triggered": int(gate_triggered),
        "reasons": reasons,
        "score": round(score, 3),
        "trust": trust,
        "prompt_leak_attempt": int(prompt_leak_attempt),
        "indirect_injection": int(indirect_injection),
        "shadow_ai": int(shadow_ai),
        "delegation_depth": int(delegation_depth),
        "structural_risk": round(structural_risk, 3),
        "structural_gate": int(structural_gate),
        "decision": decision,
        "decision_reason": decision_reason,
    }

def simulate_normal(n_runs: int = 5, steps_per_run: int = 5) -> pd.DataFrame:
    rows = []
    for rid in range(1, n_runs + 1):
        for step in range(1, steps_per_run + 1):
            stage = ["PLAN","RETRIEVE","TOOL_REC","EXECUTE","POST_CHE"][step-1]
            loss = clamp(random.uniform(0.1, 0.6), 0, 1)
            distortion = clamp(random.uniform(0.05, 0.4), 0, 1)
            drift = clamp(random.uniform(0.05, 0.45), 0, 1)
            base = clamp(random.uniform(0.15, 0.7), 0, 1)
            penalty = clamp(random.uniform(0.0, 0.05), 0, 1)
            gate = 1 if drift > 0.65 else 0
            reasons = "OK" if gate == 0 else "DRIFT_GATE_TRIGGERED"
            score = clamp(base - penalty - (drift * 0.1), 0, 1)
            trust = "HIGH" if score > 0.7 else ("MEDIUM" if score > 0.45 else "LOW")
            decision = "ALLOW" if trust == "HIGH" and gate == 0 else ("REVIEW" if trust != "LOW" else "BLOCK")
            d_reason = f"{trust}_TRUST" if gate == 0 else "DRIFT_GATE_TRIGGERED"
            rows.append(_row(
                utc_now_iso(), rid, step, stage,
                loss, distortion, drift, base, penalty,
                gate, reasons, score, trust,
                0, 0, 0,
                random.choice([1, 1, 2]),
                clamp(drift*0.6 + distortion*0.2, 0, 1),
                0,
                decision, d_reason
            ))
    return pd.DataFrame(rows, columns=COLUMNS)

def simulate_noise(n_rows: int = 50000) -> pd.DataFrame:
    rows = []
    for _ in range(n_rows):
        rid = random.randint(100, 300)
        step = random.randint(1, 5)
        stage = random.choice(["PLAN","RETRIEVE","TOOL_REC","EXECUTE","POST_CHE"])
        loss = random.uniform(0.0, 0.3)
        distortion = random.uniform(0.0, 0.2)
        drift = random.uniform(0.0, 0.25)
        base = random.uniform(0.3, 0.8)
        penalty = random.uniform(0.0, 0.02)
        gate = 0
        reasons = "OK"
        score = clamp(base - penalty, 0, 1)
        trust = "HIGH" if score > 0.7 else "MEDIUM"
        decision = "ALLOW"
        rows.append(_row(
            utc_now_iso(), rid, step, stage,
            loss, distortion, drift, base, penalty,
            gate, reasons, score, trust,
            0, 0, 0,
            1,
            clamp(drift*0.4 + distortion*0.1, 0, 1),
            0,
            decision, "HIGH_TRUST"
        ))
    return pd.DataFrame(rows, columns=COLUMNS)

def simulate_attack_sophisticated() -> pd.DataFrame:
    rows = []
    rid = 9001
    stages = ["PLAN","RETRIEVE","TOOL_REC","EXECUTE","POST_CHE"]
    drift_curve = [0.20, 0.55, 0.78, 0.92, 0.65]
    dist_curve  = [0.15, 0.35, 0.62, 0.70, 0.40]
    loss_curve  = [0.18, 0.40, 0.68, 0.82, 0.55]
    base_curve  = [0.55, 0.48, 0.42, 0.35, 0.38]
    pen_curve   = [0.01, 0.03, 0.05, 0.08, 0.04]
    deleg_curve = [1, 2, 3, 4, 3]

    for i, stage in enumerate(stages, start=1):
        drift = drift_curve[i-1]
        distortion = dist_curve[i-1]
        loss = loss_curve[i-1]
        base = base_curve[i-1]
        penalty = pen_curve[i-1]
        delegation_depth = deleg_curve[i-1]

        indirect_injection = 1 if stage in ("RETRIEVE","TOOL_REC") else 0
        prompt_leak_attempt = 1 if stage == "EXECUTE" else 0
        shadow_ai = 1 if stage in ("TOOL_REC","EXECUTE") else 0

        structural_risk = clamp((drift*0.55 + distortion*0.25 + loss*0.25) + (0.10 if shadow_ai else 0.0), 0, 1)
        gate_triggered = 1 if drift >= 0.75 else 0
        structural_gate = 1 if structural_risk >= 0.90 or (shadow_ai and prompt_leak_attempt) else 0

        reasons = []
        if gate_triggered: reasons.append("DRIFT_GATE_TRIGGERED")
        if indirect_injection: reasons.append("INDIRECT_INJECTION")
        if prompt_leak_attempt: reasons.append("PROMPT_LEAK_ATTEMPT")
        if shadow_ai: reasons.append("SHADOW_AI")
        if structural_gate: reasons.append("STRUCTURAL_GATE")

        reasons_str = "OK" if not reasons else "|".join(reasons)
        score = clamp(base - penalty - drift*0.12 - distortion*0.05, 0, 1)
        trust = "LOW" if structural_risk >= 0.75 or prompt_leak_attempt else ("MEDIUM" if score > 0.35 else "LOW")

        if structural_gate or (prompt_leak_attempt and indirect_injection):
            decision = "BLOCK"
            decision_reason = "STRUCTURAL_RISK_AT_EXECUTION"
        elif gate_triggered:
            decision = "REVIEW"
            decision_reason = "DRIFT_GATE_TRIGGERED"
        else:
            decision = "REVIEW"
            decision_reason = f"{trust}_TRUST"

        rows.append(_row(
            utc_now_iso(), rid, i, stage,
            loss, distortion, drift, base, penalty,
            gate_triggered, reasons_str, score, trust,
            prompt_leak_attempt, indirect_injection, shadow_ai,
            delegation_depth, structural_risk, structural_gate,
            decision, decision_reason
        ))

    return pd.DataFrame(rows, columns=COLUMNS)


# -----------------------------
# Summary + Report Generation (HTML + PDF)
# -----------------------------
def summarize(df_all: pd.DataFrame, df_filtered: pd.DataFrame, alerts_df: pd.DataFrame) -> Dict[str, Any]:
    total_steps = int(len(df_all))
    kept_steps = int(len(df_filtered))
    reduction = (1 - kept_steps / total_steps) * 100 if total_steps else 0.0

    decision_dist = df_all["decision"].astype(str).value_counts(dropna=False).to_dict()

    level_counts: Dict[str, int] = {}
    if not alerts_df.empty and "alert_level" in alerts_df.columns:
        level_counts = alerts_df["alert_level"].astype(str).value_counts().to_dict()

    inj_count = int((pd.to_numeric(df_all["prompt_leak_attempt"], errors="coerce").fillna(0).astype(int) == 1).sum()
                    + (pd.to_numeric(df_all["indirect_injection"], errors="coerce").fillna(0).astype(int) == 1).sum())
    shadow_count = int((pd.to_numeric(df_all["shadow_ai"], errors="coerce").fillna(0).astype(int) == 1).sum())
    structural_blocks = int(((pd.to_numeric(df_all["structural_gate"], errors="coerce").fillna(0).astype(int) == 1) |
                             (df_all["decision"].astype(str).str.upper() == "BLOCK")).sum())
    high_risk_steps = int((pd.to_numeric(df_all["structural_risk"], errors="coerce").fillna(0.0) >= 0.7).sum())

    incidents = aggregate_incidents(df_all, alerts_df)

    return {
        "events_raw": total_steps,
        "events_after_filter": kept_steps,
        "reduction_percent": round(reduction, 2),
        "decision_distribution": decision_dist,
        "alerts_total": int(len(alerts_df)),
        "alerts_by_level": level_counts,
        "incidents_total": int(len(incidents)),
        "incidents": incidents,
        "signals": {
            "prompt_injection_signals": inj_count,
            "shadow_ai_signals": shadow_count,
            "structural_blocks_or_gate": structural_blocks,
            "high_risk_steps": high_risk_steps,
        }
    }


def render_html_report(run_meta: dict, metrics: dict, alerts_df: pd.DataFrame, out_html: Path) -> None:
    # Alerts preview
    if alerts_df.empty:
        alerts_preview = "<p><b>Nenhum alerta gerado.</b></p>"
    else:
        top = alerts_df.head(10).to_dict(orient="records")
        rows = []
        for a in top:
            rows.append(
                "<tr>"
                f"<td>{a.get('detector_id')}</td>"
                f"<td>{a.get('alert_level')}</td>"
                f"<td>{a.get('severity')}</td>"
                f"<td>{a.get('entity_id')}</td>"
                f"<td>{a.get('summary')}</td>"
                "</tr>"
            )
        alerts_preview = (
            "<table><thead><tr>"
            "<th>Detector</th><th>Nível</th><th>Severidade</th><th>Entidade</th><th>Resumo</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )

    # Executive summary
    incidents = metrics.get("incidents", []) or []
    incidents_total = int(metrics.get("incidents_total", 0) or 0)
    exec_lines: List[str] = []

    if incidents_total >= 1:
        top_inc = incidents[0]
        chain = " → ".join(top_inc.get("attack_chain", [])) or "Behavioral escalation detected"
        exec_lines.append(f"{incidents_total} execução(ões) apresentou(aram) comprometimento estrutural.")
        exec_lines.append(f"Cadeia observada: {chain}.")
        exec_lines.append(
            f"Decisão final: {top_inc.get('final_decision')} "
            f"(sev={top_inc.get('severity')}, conf={top_inc.get('confidence')})."
        )
    else:
        exec_lines.append("Nenhum incidente estrutural consolidado nesta execução.")

    exec_summary_html = "<ul>" + "".join([f"<li>{line}</li>" for line in exec_lines]) + "</ul>"

    # Incident table
    if not incidents:
        incident_table = "<p><b>Nenhum incidente consolidado.</b></p>"
    else:
        rows = []
        for inc in incidents[:5]:
            crossed = inc.get("risk_threshold_crossed_at")
            crossed_txt = f"step {crossed['step']} ({crossed['stage']}) risk={crossed['risk']}" if crossed else "N/A"
            chain = " → ".join(inc.get("attack_chain", [])) or "-"
            rows.append(
                "<tr>"
                f"<td>{inc.get('incident_id')}</td>"
                f"<td>{inc.get('severity')}</td>"
                f"<td>{inc.get('confidence')}</td>"
                f"<td>{inc.get('final_decision')}</td>"
                f"<td>{inc.get('max_structural_risk')}</td>"
                f"<td>{crossed_txt}</td>"
                f"<td>{chain}</td>"
                "</tr>"
            )
        incident_table = (
            "<table><thead><tr>"
            "<th>Incident</th><th>Severity</th><th>Confidence</th><th>Decision</th>"
            "<th>Max Risk</th><th>Threshold Cross</th><th>Chain</th>"
            "</tr></thead><tbody>"
            + "".join(rows) +
            "</tbody></table>"
        )

    # Timeline block (injected in metrics during do_report)
    tl = metrics.get("risk_timeline", []) or []
    if not tl:
        timeline_block = "<p><b>Timeline indisponível.</b></p>"
    else:
        trows = []
        for item in tl:
            mark = " ← threshold" if float(item["structural_risk"]) >= 0.7 else ""
            trows.append(
                "<tr>"
                f"<td>{item['step']}</td>"
                f"<td>{item['stage']}</td>"
                f"<td>{float(item['drift']):.3f}</td>"
                f"<td>{float(item['structural_risk']):.3f}{mark}</td>"
                f"<td>{item['decision']}</td>"
                "</tr>"
            )
        timeline_block = (
            "<table><thead><tr>"
            "<th>Step</th><th>Stage</th><th>Drift</th><th>Structural Risk</th><th>Decision</th>"
            "</tr></thead><tbody>"
            + "".join(trows) +
            "</tbody></table>"
        )

    # Decisions distribution
    dd = metrics.get("decision_distribution", {})
    dd_str = ", ".join([f"{k}: {v}" for k, v in dd.items()]) if dd else "N/A"

    html = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<title>DFS AI Runtime Risk Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 28px; color: #111; }}
h1 {{ margin-bottom: 6px; }}
.small {{ color: #444; }}
.kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
.card {{ border: 1px solid #ddd; border-radius: 10px; padding: 12px; }}
.card h3 {{ margin: 0 0 6px 0; font-size: 14px; color: #333; }}
.big {{ font-size: 22px; font-weight: 700; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border-bottom: 1px solid #eee; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #fafafa; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #f2f2f2; }}
</style>
</head>
<body>
<h1>DFS – AI Runtime Risk Detection Report</h1>
<div class="small">
<b>run_id:</b> {run_meta.get("run_id")} · <b>generated_at:</b> {utc_now_iso()}
</div>

<div class="kpis">
  <div class="card"><h3>Eventos (bruto)</h3><div class="big">{metrics.get("events_raw")}</div></div>
  <div class="card"><h3>Eventos (após relevância)</h3><div class="big">{metrics.get("events_after_filter")}</div></div>
  <div class="card"><h3>Redução de ruído</h3><div class="big">{metrics.get("reduction_percent")}%</div></div>
  <div class="card"><h3>Alertas</h3><div class="big">{metrics.get("alerts_total")}</div></div>
</div>

<div class="card" style="margin-top:12px;">
  <h3>Executive Summary</h3>
  {exec_summary_html}
</div>

<div class="card" style="margin-top:12px;">
  <h3>Incidents (consolidated)</h3>
  {incident_table}
</div>

<div class="card" style="margin-top:12px;">
  <h3>Risk Escalation Timeline</h3>
  {timeline_block}
</div>

<div class="card" style="margin-top:12px;">
  <h3>Distribuição de decisões</h3>
  <div class="badge">{dd_str}</div>
</div>

<div class="card" style="margin-top:12px;">
  <h3>Principais sinais</h3>
  <ul>
    <li>Prompt injection/leak signals: <b>{metrics.get("signals", {}).get("prompt_injection_signals")}</b></li>
    <li>Shadow AI signals: <b>{metrics.get("signals", {}).get("shadow_ai_signals")}</b></li>
    <li>Structural blocks/gate: <b>{metrics.get("signals", {}).get("structural_blocks_or_gate")}</b></li>
    <li>High-risk steps (structural_risk ≥ 0.7): <b>{metrics.get("signals", {}).get("high_risk_steps")}</b></li>
  </ul>
</div>

<div class="card" style="margin-top:12px;">
  <h3>Findings (top 10)</h3>
  {alerts_preview}
</div>

<div class="small" style="margin-top:18px;">
<b>Artefatos:</b> alerts.csv · metrics.json · run.json
</div>
</body>
</html>
"""
    out_html.write_text(html, encoding="utf-8")


def render_pdf_report(run_meta: dict, metrics: dict, alerts_df: pd.DataFrame, out_pdf: Path) -> None:
    if not REPORTLAB_OK:
        return

    c = canvas.Canvas(str(out_pdf), pagesize=letter)
    _, height = letter
    x = 40
    y = height - 50

    def line(txt: str, dy: int = 16, bold: bool = False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 11 if not bold else 12)
        c.drawString(x, y, txt[:110])
        y -= dy

    line("DFS – AI Runtime Risk Detection Report", bold=True, dy=22)
    line(f"run_id: {run_meta.get('run_id')}   generated_at: {utc_now_iso()}", dy=18)

    line(f"Eventos (bruto): {metrics.get('events_raw')}")
    line(f"Eventos (após relevância): {metrics.get('events_after_filter')}")
    line(f"Redução de ruído: {metrics.get('reduction_percent')}%")
    line(f"Alertas: {metrics.get('alerts_total')}", dy=18)

    line(f"Incidentes consolidados: {metrics.get('incidents_total', 0)}", dy=18)

    dd = metrics.get("decision_distribution", {})
    dd_str = ", ".join([f"{k}: {v}" for k, v in dd.items()]) if dd else "N/A"
    line(f"Distribuição de decisões: {dd_str}", dy=18)

    # Executive summary (top incident)
    incs = metrics.get("incidents", []) or []
    if incs:
        top = incs[0]
        chain = " -> ".join(top.get("attack_chain", [])) or "-"
        line("Executive Summary:", bold=True, dy=18)
        line(f"- Incident: {top.get('incident_id')} (sev={top.get('severity')}, conf={top.get('confidence')})", dy=14)
        line(f"- Chain: {chain}", dy=14)
        line(f"- Final decision: {top.get('final_decision')}", dy=18)

    # Findings
    line("Findings (top 8):", bold=True, dy=18)
    if alerts_df.empty:
        line("Nenhum alerta gerado.")
    else:
        top = alerts_df.head(8).to_dict(orient="records")
        for a in top:
            line(f"[L{a.get('alert_level')}] {a.get('detector_id')}: {a.get('summary')}", dy=14)

    c.showPage()
    c.save()


# -----------------------------
# Core run + report
# -----------------------------
def do_run(input_csv: Path, runs_dir: Path, policy: dict) -> Path:
    df_all = pd.read_csv(input_csv)

    missing = [c for c in COLUMNS if c not in df_all.columns]
    if missing:
        raise ValueError(f"CSV missing required columns: {missing}")

    df_filtered = relevance_filter(df_all, policy)
    alerts = run_detectors(df_filtered)
    alerts_df = pd.DataFrame([a.row() for a in alerts])

    rid = run_id_utc()
    run_dir = runs_dir / rid
    ensure_dir(run_dir)

    df_all.to_csv(run_dir / "input.csv", index=False)
    df_filtered.to_csv(run_dir / "signals.csv", index=False)
    alerts_df.to_csv(run_dir / "alerts.csv", index=False)

    metrics = summarize(df_all, df_filtered, alerts_df)
    metrics["run_id"] = rid
    metrics["input_file"] = str(input_csv)
    metrics["runtime_seconds"] = None

    run_meta = {
        "run_id": rid,
        "started_at_utc": utc_now_iso(),
        "input_csv": str(input_csv),
        "outputs": {
            "input_csv_copy": str(run_dir / "input.csv"),
            "signals_csv": str(run_dir / "signals.csv"),
            "alerts_csv": str(run_dir / "alerts.csv"),
            "metrics_json": str(run_dir / "metrics.json"),
        },
        "policy": {**DEFAULT_POLICY, **(policy or {})},
    }

    t0 = time.time()
    write_json(run_dir / "run.json", run_meta)
    write_json(run_dir / "metrics.json", metrics)
    metrics["runtime_seconds"] = round(time.time() - t0, 4)
    write_json(run_dir / "metrics.json", metrics)

    return run_dir


def do_report(run_dir: Path) -> Tuple[Path, Path]:
    run_meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))

    alerts_path = run_dir / "alerts.csv"
    alerts_df = pd.read_csv(alerts_path) if alerts_path.exists() else pd.DataFrame()

    # Inject timeline for first incident (or first run_id in dataset)
    input_path = run_dir / "input.csv"
    if input_path.exists():
        df_all = pd.read_csv(input_path)
        incidents = metrics.get("incidents", []) or []
        if incidents:
            rid = incidents[0].get("run_id")
            metrics["risk_timeline"] = build_risk_timeline(df_all, rid)
        else:
            if not df_all.empty and "run_id" in df_all.columns:
                metrics["risk_timeline"] = build_risk_timeline(df_all, df_all["run_id"].iloc[0])

        # Persist enriched metrics (useful to share)
        write_json(run_dir / "metrics.json", metrics)

    out_html = run_dir / "report.html"
    render_html_report(run_meta, metrics, alerts_df, out_html)

    out_pdf = run_dir / "report.pdf"
    if REPORTLAB_OK:
        render_pdf_report(run_meta, metrics, alerts_df, out_pdf)
    else:
        out_pdf = Path("")

    return out_html, out_pdf


def do_simulate(out_dir: Path) -> List[Path]:
    ensure_dir(out_dir)

    p1 = out_dir / "normal.csv"
    p2 = out_dir / "noise.csv"
    p3 = out_dir / "attack_sophisticated.csv"

    simulate_normal(n_runs=7, steps_per_run=5).to_csv(p1, index=False)
    simulate_noise(n_rows=50000).to_csv(p2, index=False)
    simulate_attack_sophisticated().to_csv(p3, index=False)

    return [p1, p2, p3]


# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(prog="dfs_ai", description="DFS AI Runtime Risk Detection (CSV-based) – v2 Enterprise Report")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("simulate", help="Generate synthetic datasets for POC (normal/noise/attack)")
    s1.add_argument("--out", default="datasets", help="Output directory for datasets")

    s2 = sub.add_parser("run", help="Run policy+detectors against an input CSV and produce run artifacts")
    s2.add_argument("--input", required=True, help="Path to input CSV")
    s2.add_argument("--runs_dir", default="runs", help="Runs output directory")
    s2.add_argument("--min_structural_risk", type=float, default=DEFAULT_POLICY["min_structural_risk"])
    s2.add_argument("--min_drift", type=float, default=DEFAULT_POLICY["min_drift"])

    s3 = sub.add_parser("report", help="Generate executive report (HTML + PDF) from a run directory")
    s3.add_argument("--run_dir", required=True, help="Path to run directory (runs/<RUN_ID>)")

    args = ap.parse_args()

    if args.cmd == "simulate":
        paths = do_simulate(Path(args.out))
        print("[OK] datasets generated:")
        for p in paths:
            print(" -", p)
        return

    if args.cmd == "run":
        policy = {
            "min_structural_risk": float(args.min_structural_risk),
            "min_drift": float(args.min_drift),
        }
        run_dir = do_run(Path(args.input), Path(args.runs_dir), policy)
        print(f"[OK] run artifacts -> {run_dir}")
        print("  - input.csv")
        print("  - signals.csv (post relevance-policy)")
        print("  - alerts.csv")
        print("  - metrics.json (with incidents)")
        print("Next: python dfs_ai_v2.py report --run_dir", run_dir)
        return

    if args.cmd == "report":
        out_html, out_pdf = do_report(Path(args.run_dir))
        print("[OK] report generated:")
        print(" -", out_html)
        if out_pdf and str(out_pdf):
            print(" -", out_pdf)
        else:
            print(" - (PDF skipped: reportlab not available)")
        return


if __name__ == "__main__":
    main()