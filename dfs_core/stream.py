# dfs_core/stream.py
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from dfs_core.pipeline import evaluate_event


@dataclass(frozen=True)
class StreamConfig:
    kind: str
    policy_path: str
    sleep_ms: int = 0
    limit: Optional[int] = None


def _iter_json_lines(path: str | Path) -> Iterable[Dict[str, Any]]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def run_stream(jsonl_path: str, cfg: StreamConfig) -> None:
    count = 0
    for evt in _iter_json_lines(jsonl_path):
        res = evaluate_event(
            evt,
            kind=cfg.kind,
            policy_path=cfg.policy_path,
            event_id=str(evt.get("event", {}).get("id") or evt.get("eventID") or ""),
        )

        # Emit DecisionCard as JSON (stdout-friendly)
        print(json.dumps(res.card.to_dict(), ensure_ascii=False))

        count += 1
        if cfg.limit is not None and count >= cfg.limit:
            break

        if cfg.sleep_ms and cfg.sleep_ms > 0:
            time.sleep(cfg.sleep_ms / 1000.0)
