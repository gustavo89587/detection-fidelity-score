"""
Manual test for Circuit Breaker + ABAC Token + Audit Ledger.
Run: python test_infra_manual.py
"""
import sys, time
sys.path.insert(0, ".")

from dfs_core.circuit_breaker import DFSCircuitBreaker, CircuitBreakerConfig
from dfs_core.abac_token import ABACTokenManager
from dfs_core.audit_ledger import DFSAuditLedger

print("\n" + "="*70)
print("  1. CIRCUIT BREAKER")
print("="*70)

breaker = DFSCircuitBreaker(CircuitBreakerConfig(
    max_consecutive_blocks=3,
    max_actions_per_minute=10,
    cooldown_seconds=5,
))

agent = "agent-test-01"
action = {"action_type": "read_file", "target_resource": "report.pdf", "environment": "dev"}

# Normal actions
for i in range(3):
    r = breaker.check(agent, action, dfs_score=0.15, decision_action="AUTOMATE")
    breaker.record(agent, action, 0.15, "AUTOMATE")
    print(f"  Action {i+1}: state={r.breaker_state} blocked={r.blocked}")

# Simulate 3 consecutive BLOCKs → should trip
block_action = {"action_type": "drop_database", "target_resource": "prod-db", "environment": "production"}
for i in range(3):
    breaker.record(agent, block_action, 0.85, "BLOCK")

r = breaker.check(agent, block_action, dfs_score=0.85, decision_action="BLOCK")
print(f"\n  After 3 blocks: state={r.breaker_state} blocked={r.blocked}")
print(f"  Reason: {r.reason}")

status = breaker.status(agent)
print(f"  Stats: total={status['total_actions']} blocked={status['total_blocked']} rate={status['block_rate']}")

print("\n" + "="*70)
print("  2. ABAC TOKEN MANAGER")
print("="*70)

manager = ABACTokenManager()

# Issue token for deploy
token = manager.issue(
    agent_id="agent-deploy-01",
    action_type="deploy_to_production",
    resource="k8s-prod-cluster",
    environment="production",
    authorized_by="jane@corp.com",
    valid_seconds=300,
    single_use=True,
)
print(f"  Token issued: jti={token.jti[:8]}... expires_in={token.expires_in}s")

# Valid action
valid_event = {
    "agent_id": "agent-deploy-01",
    "action_type": "deploy_to_production",
    "target_resource": "k8s-prod-cluster",
    "environment": "production",
}
result = manager.validate(token, valid_event, dfs_score=0.57)
print(f"  Valid action:     valid={result.valid} reason='{result.reason}'")

# Wrong resource
wrong_event = {**valid_event, "target_resource": "k8s-staging-cluster"}
result2 = manager.validate(token, wrong_event, dfs_score=0.57)
print(f"  Wrong resource:   valid={result2.valid} reason='{result2.reason}'")

# Consume and retry
manager.consume(token.jti)
result3 = manager.validate(token, valid_event, dfs_score=0.57)
print(f"  After consume:    valid={result3.valid} reason='{result3.reason}'")

# Wildcard token
wildcard = manager.issue(
    agent_id="agent-read-01",
    action_type="read_*",
    resource="reports/*",
    environment="production",
    authorized_by="bob@corp.com",
    valid_seconds=3600,
    single_use=False,
)
read_event = {"agent_id": "agent-read-01", "action_type": "read_file",
              "target_resource": "reports/q3.pdf", "environment": "production"}
result4 = manager.validate(wildcard, read_event, dfs_score=0.12)
print(f"  Wildcard token:   valid={result4.valid} reason='{result4.reason}'")

print("\n" + "="*70)
print("  3. AUDIT LEDGER + HASH CHAIN")
print("="*70)

ledger = DFSAuditLedger()

# Record events
e1 = ledger.append("GUARDRAIL",   {"score": 0.57, "action": "ESCALATE"},
                   agent_id="agent-deploy-01", action_type="deploy_to_production",
                   dfs_score=0.57, decision="ESCALATE")
e2 = ledger.append("ABAC",        {"token": token.jti, "result": "consumed"},
                   agent_id="agent-deploy-01")
e3 = ledger.append("CIRCUIT_BREAKER", {"event": "TRIP", "reason": "3 consecutive blocks"},
                   agent_id="agent-test-01", decision="TRIP")
e4 = ledger.append("GUARDRAIL",   {"score": 0.08, "action": "BLOCK"},
                   agent_id="agent-test-01", action_type="drop_database",
                   dfs_score=0.08, decision="BLOCK")

print(f"  Entries recorded: {len(ledger)}")
for e in ledger:
    print(f"  [{e.index}] {e.event_type:<20} {e.decision or '':<12} "
          f"hash={e.entry_hash[:12]}... prev={e.prev_hash[:12]}...")

# Verify chain
v = ledger.verify_chain()
print(f"\n  Chain verification: valid={v.valid} total={v.total}")
print(f"  Reason: {v.reason}")

# Stats
stats = ledger.stats()
print(f"\n  Ledger stats: {stats}")

# Tamper detection demo
print("\n  Tamper detection:")
original_score = ledger._entries[0].dfs_score
ledger._entries[0].dfs_score = 0.99   # simulate tampering
v2 = ledger.verify_chain()
print(f"  After tampering entry 0: valid={v2.valid} broken_at={v2.broken_at_index}")
print(f"  Reason: {v2.reason}")
ledger._entries[0].dfs_score = original_score  # restore

print("\n" + "="*70)
print("  INFRASTRUCTURE SUMMARY")
print("="*70)
print("  Circuit Breaker: velocity + error storm + scope + risk escalation")
print("  ABAC Token:      signed, time-bounded, single-use, wildcard matching")
print("  Audit Ledger:    append-only, hash-chained, tamper-evident")
print("  All three integrate with dfs_guardrail.py for full pipeline")
print("="*70 + "\n")
