# examples/stream_simulation.py
from dfs_core.stream import run_stream, StreamConfig

def main() -> None:
    cfg = StreamConfig(
        kind="windows-powershell-4104",
        policy_path="policies/powershell_4104.policy.json",
        sleep_ms=200,
        limit=50,
    )
    run_stream("examples/events_4104.jsonl", cfg)

if __name__ == "__main__":
    main()
