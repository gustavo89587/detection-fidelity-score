import json
from pathlib import Path

def read_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input JSON not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))

def to_pretty_json(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
