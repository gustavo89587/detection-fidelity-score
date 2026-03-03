from dfs_core.simulate import simulate_agent_pipeline
import argparse
import sys

from dfs_core.engine import DecisionReliabilityEngine
from dfs_core.io import read_json, to_pretty_json

def cmd_evaluate(args: argparse.Namespace) -> int:
    snapshot = read_json(args.input)
    engine = DecisionReliabilityEngine()
    result = engine.evaluate(snapshot)

    out = result.to_dict()
    print(to_pretty_json(out))
    return 0

def cmd_simulate(args: argparse.Namespace) -> int:
    summary = simulate_agent_pipeline(
        runs=args.runs,
        seed=args.seed,
        out_csv=args.out
    )
    print(to_pretty_json(summary))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfs", description="DFS Decision Reliability CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate", help="Evaluate a decision snapshot JSON")
    ev.add_argument("input", help="Path to JSON file (must contain loss/distortion/drift)")
    ev.set_defaults(func=cmd_evaluate)

    sim = sub.add_parser("simulate", help="Simulate an agent pipeline and export CSV timeline")
    sim.add_argument("--runs", type=int, default=40, help="Number of runs")
    sim.add_argument("--seed", type=int, default=7, help="Random seed (reproducible)")
    sim.add_argument("--out", default="dfs_agent_timeline.csv", help="Output CSV path")
    sim.set_defaults(func=cmd_simulate)


    return p

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
