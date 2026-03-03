import csv
import random
from datetime import datetime, timezone

# ----------------------------
# DFS core (score + policy)
# ----------------------------

def classificar(score: float, t_high=0.75, t_med=0.5) -> str:
    if score >= t_high:
        return "HIGH"
    elif score >= t_med:
        return "MEDIUM"
    return "LOW"

def reason_codes(loss: float, distortion: float, drift: float, floor=0.3) -> str:
    reasons = []
    if loss < floor: reasons.append("LOSS_BELOW_FLOOR")
    if distortion < floor: reasons.append("DISTORTION_BELOW_FLOOR")
    if drift < floor: reasons.append("DRIFT_BELOW_FLOOR")
    return "|".join(reasons) if reasons else "OK"

def calcular_score(
    loss: float, distortion: float, drift: float,
    w_loss=0.30, w_distortion=0.45, w_drift=0.25,
    floor=0.30, penalty_scale=0.40,
    enable_drift_gate=True
):
    base = (loss * w_loss) + (distortion * w_distortion) + (drift * w_drift)

    severity = (
        max(0.0, floor - loss) +
        max(0.0, floor - distortion) +
        max(0.0, floor - drift)
    )
    penalty = penalty_scale * severity
    score = max(0.0, base - penalty)

    gate_triggered = False
    if enable_drift_gate and drift < floor:
        gate_triggered = True
        score = min(score, 0.49)  # hard gate: no MEDIUM/HIGH if drift collapses

    return round(score, 2), round(base, 2), round(penalty, 2), gate_triggered

# ----------------------------
# Agent pipeline simulation
# ----------------------------

STAGES = ["PLAN", "RETRIEVE", "TOOL_REQUEST", "EXECUTE", "POST_CHECK"]

def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def apply_stage_effects(state: dict, stage: str, flags: dict, rng: random.Random) -> dict:
    """
    state = {loss, distortion, drift}
    flags = signals toggles (shadow_ai, indirect_injection, prompt_leak_attempt, scope_expansion, delegation_depth)
    """
    loss = state["loss"]
    distortion = state["distortion"]
    drift = state["drift"]

    # Base "friction" per stage (systems are never lossless)
    if stage == "PLAN":
        # generally stable
        loss -= 0.02
        distortion -= 0.01
        drift -= 0.01

    elif stage == "RETRIEVE":
        # reading external context increases distortion risk (indirect injection)
        loss -= 0.03
        distortion -= 0.04
        drift -= 0.02

        if flags["indirect_injection"]:
            # poisoned doc/site: distortion + drift get hit
            distortion -= 0.18 + rng.random() * 0.07
            drift -= 0.10 + rng.random() * 0.06

    elif stage == "TOOL_REQUEST":
        # tool selection and scope negotiation is where drift often grows
        loss -= 0.02
        distortion -= 0.02
        drift -= 0.05

        if flags["scope_expansion"]:
            # asking for broader permissions than needed
            drift -= 0.16 + rng.random() * 0.08
            distortion -= 0.06 + rng.random() * 0.05

        # delegation depth increases decision uncertainty
        dd = flags["delegation_depth"]
        if dd >= 2:
            drift -= 0.03 * (dd - 1)
            loss -= 0.01 * (dd - 1)

    elif stage == "EXECUTE":
        # execution amplifies consequences: any misalignment matters more
        loss -= 0.03
        distortion -= 0.02
        drift -= 0.04

        if flags["prompt_leak_attempt"]:
            # leakage pressure is intent-corrupting; modeled as drift hit
            drift -= 0.18 + rng.random() * 0.08

    elif stage == "POST_CHECK":
        # governance / validation can recover a bit IF present
        # (think: policy checks, allowlists, human checkpoint)
        loss += 0.05
        distortion += 0.04
        drift += 0.03

        # but if shadow AI: missing inventory/telemetry reduces any recovery
        if flags["shadow_ai"]:
            loss -= 0.10 + rng.random() * 0.05  # visibility gap persists

    # Shadow AI hurts visibility across the whole run (Loss)
    if flags["shadow_ai"] and stage in ["PLAN", "RETRIEVE", "TOOL_REQUEST", "EXECUTE"]:
        loss -= 0.08 + rng.random() * 0.04

    return {
        "loss": round(clamp01(loss), 2),
        "distortion": round(clamp01(distortion), 2),
        "drift": round(clamp01(drift), 2),
    }

def generate_flags(rng: random.Random) -> dict:
    # Start conservative probabilities; you can tune these later.
    shadow_ai = rng.random() < 0.25
    indirect_injection = rng.random() < 0.20
    scope_expansion = rng.random() < 0.22
    prompt_leak_attempt = rng.random() < 0.18

    # delegation depth 1..3
    r = rng.random()
    if r < 0.70:
        delegation_depth = 1
    elif r < 0.92:
        delegation_depth = 2
    else:
        delegation_depth = 3

    return {
        "shadow_ai": shadow_ai,
        "indirect_injection": indirect_injection,
        "scope_expansion": scope_expansion,
        "prompt_leak_attempt": prompt_leak_attempt,
        "delegation_depth": delegation_depth,
    }

def simulate_runs(
    runs=30,
    seed=7,
    w_loss=0.30, w_distortion=0.45, w_drift=0.25,
    floor=0.30, penalty_scale=0.40,
    t_high=0.75, t_med=0.50
):
    rng = random.Random(seed)

    rows = []
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    gates = 0

    for run_id in range(1, runs + 1):
        flags = generate_flags(rng)

        # Start state (healthy baseline with small natural variation)
        state = {
            "loss": round(0.85 + rng.random() * 0.10, 2),
            "distortion": round(0.85 + rng.random() * 0.10, 2),
            "drift": round(0.85 + rng.random() * 0.10, 2),
        }

        for step, stage in enumerate(STAGES, start=1):
            state = apply_stage_effects(state, stage, flags, rng)

            score, base, penalty, gated = calcular_score(
                state["loss"], state["distortion"], state["drift"],
                w_loss=w_loss, w_distortion=w_distortion, w_drift=w_drift,
                floor=floor, penalty_scale=penalty_scale,
                enable_drift_gate=True
            )
            trust = classificar(score, t_high=t_high, t_med=t_med)
            why = reason_codes(state["loss"], state["distortion"], state["drift"], floor=floor)

            gates += 1 if gated else 0
            summary[trust] += 1

            rows.append([
                now_iso(),
                run_id,
                step,
                stage,
                state["loss"],
                state["distortion"],
                state["drift"],
                base,
                penalty,
                int(gated),
                why,
                score,
                trust,
                int(flags["shadow_ai"]),
                int(flags["indirect_injection"]),
                int(flags["scope_expansion"]),
                int(flags["prompt_leak_attempt"]),
                flags["delegation_depth"],
            ])

    return rows, summary, gates

def main():
    runs = 40
    seed = 7

    rows, summary, gates = simulate_runs(runs=runs, seed=seed)

    out_csv = "dfs_agent_timeline.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ts",
            "run_id","step","stage",
            "loss","distortion","drift",
            "base","penalty",
            "gate_triggered","reasons",
            "score","trust",
            "shadow_ai","indirect_injection","scope_expansion","prompt_leak_attempt",
            "delegation_depth",
        ])
        writer.writerows(rows)

    total = sum(summary.values())
    print("\n=== Agent Pipeline DFS Summary ===")
    print(f"runs={runs} | stages={len(STAGES)} | total_rows={total} | seed={seed}")
    print(f"trust_counts: HIGH={summary['HIGH']} MEDIUM={summary['MEDIUM']} LOW={summary['LOW']}")
    print(f"gates_triggered: {gates} ({(gates/total)*100:.1f}%)")
    print(f"Saved: {out_csv}")

if __name__ == "__main__":
    main()
