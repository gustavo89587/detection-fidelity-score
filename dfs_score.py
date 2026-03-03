import csv
import random

def classificar(score, t_high=0.75, t_med=0.5):
    if score >= t_high:
        return "HIGH"
    elif score >= t_med:
        return "MEDIUM"
    else:
        return "LOW"

def reason_codes(loss, distortion, drift, floor=0.3):
    reasons = []
    if loss < floor: reasons.append("LOSS_BELOW_FLOOR")
    if distortion < floor: reasons.append("DISTORTION_BELOW_FLOOR")
    if drift < floor: reasons.append("DRIFT_BELOW_FLOOR")
    return "|".join(reasons) if reasons else "OK"

def calcular_score(loss, distortion, drift,
                   w_loss=0.3, w_distortion=0.45, w_drift=0.25,
                   floor=0.3, penalty_scale=0.4,
                   enable_drift_gate=True):
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
        score = min(score, 0.49)  # hard gate: não existe MEDIUM/HIGH

    return score, base, penalty, gate_triggered

def run_monte_carlo(n=200, seed=42,
                    w_loss=0.3, w_distortion=0.45, w_drift=0.25,
                    floor=0.3, penalty_scale=0.4,
                    t_high=0.75, t_med=0.5):
    random.seed(seed)

    rows = []
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    gate_count = 0
    near_med = 0   # score perto do limiar MEDIUM (zona frágil)
    near_high = 0  # score perto do limiar HIGH  (zona frágil)

    for i in range(1, n + 1):
        # 0..1 uniform: simples e suficiente pra começar
        loss = round(random.random(), 2)
        distortion = round(random.random(), 2)
        drift = round(random.random(), 2)

        score, base, penalty, gated = calcular_score(
            loss, distortion, drift,
            w_loss=w_loss, w_distortion=w_distortion, w_drift=w_drift,
            floor=floor, penalty_scale=penalty_scale,
            enable_drift_gate=True
        )

        score = round(score, 2)
        pred = classificar(score, t_high=t_high, t_med=t_med)
        why = reason_codes(loss, distortion, drift, floor=floor)

        counts[pred] += 1
        gate_count += 1 if gated else 0

        # zonas de instabilidade: a poucos pontos do threshold
        if abs(score - t_med) <= 0.03:
            near_med += 1
        if abs(score - t_high) <= 0.03:
            near_high += 1

        rows.append([
            i, loss, distortion, drift,
            round(base, 2), round(penalty, 2),
            int(gated), why,
            score, pred
        ])

    # resumo elegante (console)
    print("\n=== DFS Monte Carlo Summary ===")
    print(f"N: {n} | seed: {seed}")
    print(f"Counts: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    print(f"Gates triggered: {gate_count} ({(gate_count/n)*100:.1f}%)")
    print(f"Near t_med (+/-0.03): {near_med}")
    print(f"Near t_high(+/-0.03): {near_high}")

    # export
    out = "dfs_monte_carlo_report.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id","loss","distortion","drift",
            "base","penalty","gate_triggered","reasons",
            "score","trust"
        ])
        writer.writerows(rows)

    print(f"Saved: {out}")

if __name__ == "__main__":
    run_monte_carlo(n=300, seed=7)
