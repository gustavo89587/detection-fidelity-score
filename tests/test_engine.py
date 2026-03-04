from dfs.engine import evaluate

def test_engine_runs():
    snapshot = {"loss": 0.1, "distortion": 0.2, "drift": 0.1}
    result = evaluate(snapshot)
    assert result is not None