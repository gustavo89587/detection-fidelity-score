# dfs-core/tests/test_guardrails.py
from dfs_core.guardrails import DFSGuardrail, DFSAction


def test_guardrail_bands():
    g = DFSGuardrail()

    assert g.decide(0.10).action == DFSAction.INVESTIGATE
    assert g.decide(0.54).action == DFSAction.INVESTIGATE

    assert g.decide(0.55).action == DFSAction.ESCALATE
    assert g.decide(0.70).action == DFSAction.ESCALATE
    assert g.decide(0.749).action == DFSAction.ESCALATE

    assert g.decide(0.75).action == DFSAction.AUTOMATE
    assert g.decide(0.95).action == DFSAction.AUTOMATE
