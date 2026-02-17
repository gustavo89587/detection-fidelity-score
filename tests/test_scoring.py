import dfs_core
print("dfs_core loaded from:", dfs_core.__file__)

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

def test_interpretation():
    model = DFSModel()
    score = model.score(DFSInputs(0.9, 0.9, 0.9))
    assert model.interpret(score) == "Operational"

