# cli/dfs.py
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# =========================
# Core utils
# =========================

def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def _repo_root() -> Path:
    return Path.cwd()


def _json_default(x: Any) -> Any:
    if is_dataclass(x):
        return asdict(x)
    if isinstance(x, Path):
        return str(x).replace("\\", "/")
    return x


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=_json_default))


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


# =========================
# Output safety (fail-closed)
# =========================

ALLOWED_OUT_ROOTS = ("dfs_core/runs", "output")


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_out_path(out_path: Path, allow_any_out: bool) -> Path:
    repo = _repo_root().resolve()
    out_abs = (repo / out_path).resolve() if not out_path.is_absolute() else out_path.resolve()

    if out_abs == repo:
        raise SystemExit("Refusing to write artifacts to repo root. Use dfs_core/runs/ or output/.")

    if allow_any_out:
        return out_abs

    allowed_parents = [(repo / p).resolve() for p in ALLOWED_OUT_ROOTS]
    if not any(_is_under(out_abs, ap) or out_abs == ap for ap in allowed_parents):
        allowed = ", ".join(ALLOWED_OUT_ROOTS)
        raise SystemExit(
            f"Refusing to write outside allowed roots ({allowed}). Got: {out_path.as_posix()}. "
            f"Use --allow-any-out to override."
        )
    return out_abs


# =========================
# Glob expansion (cross-shell)
# =========================

def _expand_policy_args(items: list[str]) -> list[str]:
    """
    Expands patterns like policies/*.policy.json no matter the shell.
    """
    expanded: list[str] = []

    for s in items:
        if any(ch in s for ch in ["*", "?", "["]):
            matches = list(Path().glob(s))
            if not matches:
                raise SystemExit(f"No policy files matched pattern: {s}")
            expanded.extend([str(p) for p in matches])
        else:
            expanded.append(s)

    # de-dup preserving order
    seen = set()
    result: list[str] = []
    for x in expanded:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result


# =========================
# Domain filter (optional)
# =========================

def _policy_domain_from_name(policy_name: str) -> str:
    n = (policy_name or "").lower()
    if "cloudtrail" in n:
        return "cloudtrail"
    if "sysmon" in n:
        return "sysmon"
    if "powershell" in n or "4104" in n:
        return "winlog"
    if "windows" in n or "4624" in n:
        return "winlog"
    return "unknown"


def _filter_policy_paths_by_domain(paths: list[str], domain: str) -> list[str]:
    """
    Cheap guardrail to avoid ranking policies outside dataset domain.
    Uses policy name/stem only (no schema change needed).
    """
    if domain == "any":
        return paths

    kept: list[str] = []
    for p in paths:
        stem = Path(p).stem
        dom = _policy_domain_from_name(stem)
        if dom == domain or dom == "unknown":
            kept.append(p)
    return kept


# =========================
# simulate
# =========================

def _default_simulate_out() -> Path:
    ts = _utc_stamp()
    return Path("dfs_core") / "runs" / ts / "reports" / "simulate.csv"


def cmd_simulate(args: argparse.Namespace) -> int:
    from dfs_core.simulate import simulate_agent_pipeline

    out = Path(args.out) if args.out else _default_simulate_out()
    out_abs = _validate_out_path(out, allow_any_out=args.allow_any_out)
    _ensure_dir(out_abs.parent)

    summary = simulate_agent_pipeline(
        runs=int(args.runs),
        seed=(int(args.seed) if args.seed is not None else None),
        out_csv=str(out_abs),
    )
    _print_json(summary)
    return 0


# =========================
# evaluate
# =========================

def _default_run_outdir() -> Path:
    return Path("dfs_core") / "runs" / _utc_stamp()


def cmd_evaluate(args: argparse.Namespace) -> int:
    from dfs_core.evaluate import load_policy, load_jsonl_events, evaluate_policy_on_events, to_dict

    out_dir = Path(args.out) if args.out else _default_run_outdir()
    out_abs = _validate_out_path(out_dir, allow_any_out=args.allow_any_out)
    _ensure_dir(out_abs)

    reports = out_abs / "reports"
    policies_dir = out_abs / "policies"
    _ensure_dir(reports)
    _ensure_dir(policies_dir)

    events_path = Path(args.events)
    policy_path = Path(args.policy)

    events = load_jsonl_events(events_path)
    policy = load_policy(policy_path)

    metrics, labeled = evaluate_policy_on_events(
        policy,
        events,
        alpha_op_cost=float(args.alpha_op_cost),
        bootstrap_iterations=int(args.bootstrap_iters),
        bootstrap_seed=int(args.bootstrap_seed),
    )

    (out_abs / "run.json").write_text(
        json.dumps(
            {
                "cmd": "evaluate",
                "events": str(events_path).replace("\\", "/"),
                "policy": str(policy_path).replace("\\", "/"),
                "out_dir": str(out_abs).replace("\\", "/"),
                "alpha_op_cost": float(args.alpha_op_cost),
                "bootstrap_iters": int(args.bootstrap_iters),
                "bootstrap_seed": int(args.bootstrap_seed),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    (out_abs / "metrics.json").write_text(
        json.dumps(to_dict(metrics), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if args.save_matches:
        (policies_dir / f"{policy_path.stem}.labeled.jsonl").write_text(
            "\n".join(json.dumps(x, ensure_ascii=False) for x in labeled[: int(args.max_matches)]),
            encoding="utf-8",
        )

    _print_json({"out_dir": str(out_abs).replace("\\", "/"), "metrics": metrics})
    return 0


# =========================
# compare
# =========================

def cmd_compare(args: argparse.Namespace) -> int:
    from dfs_core.evaluate import load_policy, load_jsonl_events, evaluate_policy_on_events, to_dict, PolicyEval

    out_dir = Path(args.out) if args.out else _default_run_outdir()
    out_abs = _validate_out_path(out_dir, allow_any_out=args.allow_any_out)
    _ensure_dir(out_abs)

    reports = out_abs / "reports"
    policies_dir = out_abs / "policies"
    _ensure_dir(reports)
    _ensure_dir(policies_dir)

    events_path = Path(args.events)
    events = load_jsonl_events(events_path)

    policy_args = _expand_policy_args(args.policies)
    policy_args = _filter_policy_paths_by_domain(policy_args, args.filter_domain)

    evals: list[PolicyEval] = []
    errors: list[dict[str, str]] = []

    for p_str in policy_args:
        p_path = Path(p_str)
        try:
            policy = load_policy(p_path)
            metrics, labeled = evaluate_policy_on_events(
                policy,
                events,
                alpha_op_cost=float(args.alpha_op_cost),
                bootstrap_iterations=int(args.bootstrap_iters),
                bootstrap_seed=int(args.bootstrap_seed),
            )
            evals.append(metrics)

            (policies_dir / f"{p_path.stem}.metrics.json").write_text(
                json.dumps(to_dict(metrics), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            if args.save_matches:
                (policies_dir / f"{p_path.stem}.labeled.jsonl").write_text(
                    "\n".join(json.dumps(x, ensure_ascii=False) for x in labeled[: int(args.max_matches)]),
                    encoding="utf-8",
                )

        except Exception as e:
            errors.append({"policy": str(p_path).replace("\\", "/"), "error": str(e)})
            continue

    if not evals:
        raise SystemExit("No valid policies evaluated. Check --policies input and policy JSON validity.")

    # Ranking: cost_adjusted_score desc, stability.std asc, weighted_avg_score desc
    def sort_key(m: PolicyEval):
        std = float(m.stability.get("std", 0.0)) if isinstance(m.stability, dict) else 0.0
        return (-m.cost_adjusted_score, std, -m.weighted_avg_score)

    ranked = sorted(evals, key=sort_key)

    # reports/ranking.csv
    ranking_csv = reports / "ranking.csv"
    with ranking_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "rank",
            "policy",
            "total_events",
            "avg_score",
            "weighted_avg_score",
            "op_cost_avg",
            "cost_adjusted_score",
            "stability_mean",
            "stability_std",
            "stability_p05",
            "stability_p95",
            "investigate_rate",
            "escalate_rate",
            "automate_rate",
        ])
        for i, m in enumerate(ranked, start=1):
            stab = m.stability or {}
            w.writerow([
                i,
                m.policy_name,
                m.total_events,
                m.avg_score,
                m.weighted_avg_score,
                m.op_cost_avg,
                m.cost_adjusted_score,
                stab.get("mean", 0.0),
                stab.get("std", 0.0),
                stab.get("p05", 0.0),
                stab.get("p95", 0.0),
                m.investigate_rate,
                m.escalate_rate,
                m.automate_rate,
            ])

    comparison = {
        "cmd": "compare",
        "events": str(events_path).replace("\\", "/"),
        "policies": [str(Path(p)).replace("\\", "/") for p in policy_args],
        "out_dir": str(out_abs).replace("\\", "/"),
        "alpha_op_cost": float(args.alpha_op_cost),
        "bootstrap_iters": int(args.bootstrap_iters),
        "bootstrap_seed": int(args.bootstrap_seed),
        "filter_domain": args.filter_domain,
        "errors": errors,
        "ranking": [to_dict(x) for x in ranked],
    }

    (out_abs / "comparison.json").write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    _print_json(comparison)
    return 0


# =========================
# argparse
# =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfs")
    sub = p.add_subparsers(dest="cmd", required=True)

    # simulate
    ps = sub.add_parser("simulate", help="Generate synthetic simulation CSV report")
    ps.add_argument("--runs", type=int, default=1, help="Number of runs")
    ps.add_argument("--seed", type=int, default=None, help="Random seed (reproducible)")
    ps.add_argument("--out", type=str, default=None, help="Output CSV path (default: dfs_core/runs/<ts>/reports/simulate.csv)")
    ps.add_argument("--allow-any-out", action="store_true", help="Allow writing outside dfs_core/runs/ and output/ (NOT recommended)")
    ps.set_defaults(func=cmd_simulate)

    # evaluate
    pe = sub.add_parser("evaluate", help="Evaluate a single policy against an events JSONL dataset")
    pe.add_argument("--events", required=True, help="Path to events JSONL")
    pe.add_argument("--policy", required=True, help="Path to policy JSON")
    pe.add_argument("--out", default=None, help="Output directory (default: dfs_core/runs/<ts>/)")
    pe.add_argument("--alpha-op-cost", type=float, default=0.15, help="Operational cost weight alpha")
    pe.add_argument("--bootstrap-iters", type=int, default=200, help="Bootstrap iterations for stability")
    pe.add_argument("--bootstrap-seed", type=int, default=12345, help="Bootstrap RNG seed")
    pe.add_argument("--save-matches", action="store_true", help="Save per-event labeled output (limited)")
    pe.add_argument("--max-matches", type=int, default=200, help="Max labeled events to save")
    pe.add_argument("--allow-any-out", action="store_true", help="Allow writing outside allowed roots")
    pe.set_defaults(func=cmd_evaluate)

    # compare
    pc = sub.add_parser("compare", help="Compare multiple policies on the same events dataset")
    pc.add_argument("--events", required=True, help="Path to events JSONL")
    pc.add_argument("--policies", nargs="+", required=True, help="One or more policy JSON files or globs (e.g. policies/*.policy.json)")
    pc.add_argument("--out", default=None, help="Output directory (default: dfs_core/runs/<ts>/)")
    pc.add_argument("--alpha-op-cost", type=float, default=0.15, help="Operational cost weight alpha")
    pc.add_argument("--bootstrap-iters", type=int, default=200, help="Bootstrap iterations for stability")
    pc.add_argument("--bootstrap-seed", type=int, default=12345, help="Bootstrap RNG seed")
    pc.add_argument("--save-matches", action="store_true", help="Save per-event labeled output per policy (limited)")
    pc.add_argument("--max-matches", type=int, default=200, help="Max labeled events to save per policy")
    pc.add_argument("--filter-domain", choices=["any", "winlog", "cloudtrail", "sysmon"], default="any",
                    help="Optional: filter policies by domain to avoid comparing irrelevant policies (recommended: winlog for 4104)")
    pc.add_argument("--allow-any-out", action="store_true", help="Allow writing outside allowed roots")
    pc.set_defaults(func=cmd_compare)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())