import dfs_core

def test_interpretation():
    print("dfs_core loaded from:", dfs_core.__file__)
    model = DFSModel()
    score = model.score(DFSInputs(0.9, 0.9, 0.9))
    print("score:", score)
    print("interpret:", model.interpret(score))
    assert model.interpret(score) == "High Trust"
