# dfs_cli.py

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dfs_core.pipeline import run_score_pipeline


def cmd_score(args: argparse.Namespace) -> int:
    try:
        for res in run_score_pipeline(
            events_path=args.input,
            policy_path=args.policy,
            limit=args.limit if args.limit else None,
        ):
            print(json.dumps(res, ensure_ascii=False, indent=2))

        return 0

    except Exception as e:
        print(f"[DFS ERROR] {e}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dfs",
        description="Detection Fidelity Score CLI",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    score = sub.add_parser(
        "score",
        help="Score events from a JSONL file and emit DecisionCards",
    )

    score.add_argument(
        "input",
        help="Path to input JSONL file (one event per line)",
    )

    score.add_argument(
        "--kind",
        required=True,
        help='Event kind (e.g., "windows-sysmon-1", "windows-powershell-4104")',
    )

    score.add_argument(
        "--policy",
        required=True,
        help='Policy path (e.g., "policies/sysmon_1.policy.json")',
    )

    score.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after N events (0 = no limit)",
    )

    score.set_defaults(fn=cmd_score)

    args = parser.parse_args()

    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())