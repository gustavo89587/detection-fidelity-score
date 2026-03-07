import pytest
from dfs_gatekeeper import DFSConnector

def test_score_collapse():
    """Garante que se a telemetria for zero, o score desaba, não importa a severidade."""
    connector = DFSConnector(secret_key="test")
    # Severidade Máxima (S=1.0), mas Telemetria morta (T=0.0)
    score = connector.calculate_dfs(1.0, 0.0, 0.9)
    assert score == 0.0
    assert connector.get_decision_tier(score) == "BLOCK"

def test_automate_threshold():
    """Valida se o limiar de automação da RFC está sendo respeitado."""
    connector = DFSConnector(secret_key="test")
    # Caso ideal: S=0.9, T=0.9, B=0.97 (Score ~0.78)
    score = connector.calculate_dfs(0.9, 0.9, 0.97)
    assert connector.get_decision_tier(score) == "AUTOMATE"