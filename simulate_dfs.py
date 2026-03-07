import time
import json
import logging
from datetime import datetime

# Configuração de Auditoria (Immutable-style Log)
logging.basicConfig(
    filename='dfs_audit_trail.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

def calculate_dfs(s, t, b):
    return round(s * t * b, 2)

def get_decision(score):
    if score >= 0.78: return "AUTOMATE", "🟢"
    if score >= 0.55: return "ESCALATE", "🟡"
    if score >= 0.30: return "TRIAGE", "🟠"
    return "BLOCK", "🔴"

# Cenários Reais incluindo a blindagem contra Hack de Prompt
scenarios = [
    {"id": "TC-01", "name": "Telemetry Blindness    ", "s": 0.95, "t": 0.05, "b": 0.80, "desc": "Logs deletados pelo atacante"},
    {"id": "TC-03", "name": "Prompt Injection Hack  ", "s": 0.85, "t": 0.90, "b": 0.10, "desc": "Técnica de Jailbreak detectada"},
    {"id": "TC-04", "name": "High Fidelity Response ", "s": 1.00, "t": 0.95, "b": 0.98, "desc": "Ransomware detectado com provas"}
]

print(f"{'='*70}\n🛡️  DFS ECOSYSTEM SHIELD - REAL-TIME AUDIT\n{'='*70}")

for case in scenarios:
    score = calculate_dfs(case['s'], case['t'], case['b'])
    action, icon = get_decision(score)
    
    # Registro de Auditoria (O "Rastreio")
    log_entry = f"ID: {case['id']} | Event: {case['name']} | Score: {score} | Action: {action}"
    logging.info(log_entry)
    
    print(f"{icon} [{case['id']}] {case['name']} | Score: {score} | -> {action}")
    print(f"   └─ Cause: {case['desc']}")
    time.sleep(1)

print(f"{'='*70}\n✅ Auditoria imutável gerada em: dfs_audit_trail.log\n{'='*70}")