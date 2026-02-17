# dfs_cli.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from dfs_core.pipeline import evaluate_event


def iter_json_lines(path: str) -> Any:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def cmd_score(args: argparse.Namespace) -> int:
    count = 0
    for evt in iter_json_lines(args.input):
        res = evaluate_event(
            evt,
            kind=args.kind,
            policy_path=args.policy,
            event_id=str(evt.get("event", {}).get("id") or evt.get("eventID") or ""),
        )
        print(json.dumps(res.card.to_dict(), ensure_ascii=False))
        count += 1
        if args.limit and count >= args.limit:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="dfs", description="Detection Fidelity Score CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    score = sub.add_parser("score", help="Score events from a JSONL file and emit DecisionCards")
    score.add_argument("input", help="Path to input JSONL file (one event per line)")
    score.add_argument("--kind", required=True, help='Event kind (e.g., "windows-sysmon-1", "windows-powershell-4104")')
    score.add_argument("--policy", required=True, help='Policy path (e.g., "policies/sysmon_1.policy.json")')
    score.add_argument("--limit", type=int, default=0, help="Stop after N events (0 = no limit)")
    score.set_defaults(fn=cmd_score)

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
