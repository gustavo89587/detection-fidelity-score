from dfs_core import DFSModel
from dfs_core.scoring import DFSInputs


def test_valid_score():
    model = DFSModel()
    score = model.score(DFSInputs(0.8, 0.7, 0.9))
    assert 0 <= score <= 1


def test_invalid_input():
    model = DFSModel()
    try:
        model.score(DFSInputs(1.2, 0.5, 0.5))
        assert False
    except ValueError:
        assert True


def test_interpretation_high_trust():
    model = DFSModel()
    # 0.95³ = 0.857 → acima de 0.80
    score = model.score(DFSInputs(0.95, 0.95, 0.95))
    assert model.interpret(score) == "High Trust"


def test_interpretation_operational():
    model = DFSModel()
    # 0.9³ = 0.729 → Operational
    score = model.score(DFSInputs(0.9, 0.9, 0.9))
    assert model.interpret(score) == "Operational"
