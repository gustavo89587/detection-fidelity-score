# dfs-core/tests/test_bounded_actions.py
from dfs_core.guardrails import DFSGuardrail, DFSAction


def test_bounded_actions_bands():
    g = DFSGuardrail()

    assert g.decide(0.10).action == DFSAction.INVESTIGATE
    assert g.decide(0.60).action == DFSAction.ESCALATE
    assert g.decide(0.80).action == DFSAction.AUTOMATE_LITE
    assert g.decide(0.95).action == DFSAction.AUTOMATE_HARD
