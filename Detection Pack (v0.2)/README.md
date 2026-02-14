# Detection Pack (v0.2)

This pack expands DFS with drift siblings and stronger DDS compliance.

## Contents
- DFS-MSHTA-REMOTE-001 — mshta remote execution behavior
- DFS-RUNDLL32-UNTRUSTED-001 — rundll32 loading DLL from untrusted paths

Each detection includes:
- detection.yml (rule)
- dfs.yml (boundary + degradation)
- tests/ (atomic, expected, validation)
- notes.md (tuning + tradeoffs)
