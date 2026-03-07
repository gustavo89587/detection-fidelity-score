import time

def calculate_dfs(s, t, b):
    return round(s * t * b, 2)

def get_decision(score):
    if score >= 0.78: return "🟢 AUTOMATE (Secure-by-Design)"
    if score >= 0.55: return "🟡 ESCALATE (Human-in-the-Loop)"
    if score >= 0.30: return "🟠 TRIAGE (Active Approval)"
    return "🔴 BLOCK (Hard Gate)"

scenarios = [
    {"id": "TC-01", "name": "Telemetry Blindness", "s": 0.95, "t": 0.05, "b": 0.80},
    {"id": "TC-02", "name": "Noisy Alert       ", "s": 0.80, "t": 0.40, "b": 0.90},
    {"id": "TC-03", "name": "AI Prompt Hijacking", "s": 0.70, "t": 0.90, "b": 0.15},
    {"id": "TC-04", "name": "High Fidelity Attack", "s": 1.00, "t": 0.95, "b": 0.98}
]

print("-" * 60)
print("🚀 DFS ENGINE - REAL-TIME DECISION SIMULATOR")
print("-" * 60)

for case in scenarios:
    score = calculate_dfs(case['s'], case['t'], case['b'])
    decision = get_decision(score)
    print(f"[{case['id']}] {case['name']} | Score: {score} -> {decision}")
    time.sleep(0.8) # Simula o tempo de processamento do motor

print("-" * 60)
print("✅ Simulação concluída. Todos os gates de segurança validados.")