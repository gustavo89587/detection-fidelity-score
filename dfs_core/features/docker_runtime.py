# dfs_core/features/docker_runtime.py
"""
Docker / Container Runtime Event → DFS Inputs

Sources supported:
  - Docker daemon audit events (via auditd or syslog)
  - Falco alert JSON (most common in production)
  - Docker API events (from /events endpoint)
  - Trivy/Grype vulnerability findings
  - CIS Docker Benchmark violations

DFS Mapping:
  S (Signal Clarity):   Falco priority + rule category + syscall/capability context
  T (Telemetry):        Container identity + image + process + network completeness
  B (Behavioral):       Coherence of container runtime narrative

Falco priority levels: EMERGENCY > ALERT > CRITICAL > ERROR > WARNING > NOTICE > INFO > DEBUG

Key threat patterns:
  - Privileged container execution
  - Host namespace sharing (pid, net, ipc)
  - Sensitive mount (/, /etc, /var/run/docker.sock)
  - Capability abuse (SYS_ADMIN, SYS_PTRACE, NET_ADMIN)
  - Shell spawned in container
  - Outbound connection from unexpected container
  - Write to /etc/passwd, /etc/shadow, /etc/sudoers
  - Container breakout indicators
  - Crypto mining (high CPU, mining pool domains)
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from dfs_core.scoring import DFSInputs


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


# Falco priority → normalized risk
_FALCO_PRIORITY_RISK = {
    "EMERGENCY": 1.00,
    "ALERT":     0.92,
    "CRITICAL":  0.85,
    "ERROR":     0.70,
    "WARNING":   0.55,
    "NOTICE":    0.35,
    "INFO":      0.20,
    "DEBUG":     0.10,
}

# Falco rule → risk tier (partial match)
_RULE_RISK = {
    # Breakout / critical
    "container_escape":             0.98,
    "breakout":                     0.98,
    "reverse_shell":                0.96,
    "reverse shell":                0.96,
    "shell_in_container":           0.90,
    "shell in container":           0.90,
    "spawned_process_in_container": 0.75,
    # Privilege
    "privileged_container":         0.88,
    "privileged container":         0.88,
    "run_shell_untrusted":          0.85,
    "sys_admin":                    0.85,
    "sys_ptrace":                   0.82,
    "net_admin":                    0.75,
    # Sensitive file access
    "write_below_etc":              0.80,
    "write below etc":              0.80,
    "read_sensitive_file":          0.72,
    "modify_shell_configuration":   0.75,
    "docker_socket":                0.85,
    "docker socket":                0.85,
    # Network
    "outbound_connection":          0.55,
    "unexpected_network":           0.60,
    "contact_ec2_instance_metadata": 0.70,
    "cryptocurrency_mining":        0.88,
    "crypto":                       0.88,
    # Image / registry
    "launch_privileged_container":  0.88,
    "launch_sensitive_mount":       0.82,
    "launch_disallowed_container":  0.70,
    # Recon
    "find_aws_credentials":         0.80,
    "search_private_keys":          0.78,
    "read_environment_variables":   0.65,
}

# Sensitive mounts that indicate container breakout risk
_SENSITIVE_MOUNTS = {
    "/", "/etc", "/proc", "/sys", "/dev",
    "/var/run/docker.sock", "/run/docker.sock",
    "/root", "/home", "/var/lib/docker",
    "/boot", "/lib/modules",
}

# Dangerous capabilities
_DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_NET_ADMIN",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_DAC_OVERRIDE",
    "CAP_SETUID", "CAP_SETGID", "CAP_NET_RAW",
    "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN",
}


def _rule_risk(rule_name: Optional[str]) -> float:
    if not rule_name:
        return 0.30
    rule_lower = rule_name.lower()
    for pattern, risk in sorted(_RULE_RISK.items(), key=lambda x: len(x[0]), reverse=True):
        if pattern in rule_lower:
            return risk
    return 0.35


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Docker/Falco/container runtime event → (DFSInputs, flags).

    Supports:
      - Falco JSON alert
      - Docker daemon event
      - Generic container security event
    """

    # ── Detect source format ─────────────────────────────────────────────────
    # Falco JSON has "rule", "priority", "output_fields"
    is_falco = "rule" in event or "priority" in event

    # ── Falco fields ─────────────────────────────────────────────────────────
    rule            = _clean(event.get("rule") or event.get("Rule"))
    priority_raw    = _clean(event.get("priority") or event.get("Priority") or "INFO")
    output          = _clean(event.get("output") or event.get("Output"))
    hostname        = _clean(event.get("hostname") or event.get("Hostname"))
    event_time      = _clean(event.get("time") or event.get("Time") or event.get("timestamp"))
    tags            = event.get("tags") or event.get("Tags") or []
    source          = _clean(event.get("source") or event.get("Source") or "syscall")

    output_fields   = event.get("output_fields") or event.get("OutputFields") or {}

    # ── Container context ────────────────────────────────────────────────────
    container_id    = _clean(
        output_fields.get("container.id") or
        event.get("container_id") or
        _get(event, "container.id")
    )
    container_name  = _clean(
        output_fields.get("container.name") or
        event.get("container_name") or
        _get(event, "container.name")
    )
    image_repo      = _clean(
        output_fields.get("container.image.repository") or
        output_fields.get("container.image") or
        event.get("image_name") or
        _get(event, "container.image.repository")
    )
    image_tag       = _clean(
        output_fields.get("container.image.tag") or
        _get(event, "container.image.tag")
    )
    image_digest    = _clean(
        output_fields.get("container.image.digest") or
        _get(event, "container.image.digest")
    )
    is_privileged   = bool(
        output_fields.get("container.privileged") or
        event.get("privileged") or
        _get(event, "container.privileged")
    )

    # ── Process context ──────────────────────────────────────────────────────
    proc_name       = _clean(output_fields.get("proc.name") or output_fields.get("process.name"))
    proc_cmdline    = _clean(output_fields.get("proc.cmdline") or output_fields.get("process.cmdline"))
    proc_exe        = _clean(output_fields.get("proc.exe") or output_fields.get("process.exe"))
    proc_pid        = _clean(output_fields.get("proc.pid") or output_fields.get("process.pid"))
    parent_name     = _clean(output_fields.get("proc.pname") or output_fields.get("parent.name"))
    parent_cmdline  = _clean(output_fields.get("proc.pcmdline") or output_fields.get("parent.cmdline"))
    user_name       = _clean(output_fields.get("user.name") or output_fields.get("user.uid"))
    user_uid        = _clean(output_fields.get("user.uid"))
    user_loginuid   = _clean(output_fields.get("user.loginuid"))

    # ── File/network context ─────────────────────────────────────────────────
    file_path       = _clean(output_fields.get("fd.name") or output_fields.get("file.path"))
    network_dst_ip  = _clean(output_fields.get("fd.rip") or output_fields.get("network.dst_ip"))
    network_dst_port = _clean(output_fields.get("fd.rport") or output_fields.get("network.dst_port"))
    syscall_type    = _clean(output_fields.get("syscall.type") or output_fields.get("evt.type"))

    # ── Namespace / capabilities ─────────────────────────────────────────────
    mounts_raw      = event.get("mounts") or event.get("Mounts") or []
    caps_raw        = event.get("capabilities") or output_fields.get("container.caps") or ""
    caps_str        = str(caps_raw).upper()

    mount_paths     = [str(m.get("Source", m) if isinstance(m, dict) else m) for m in mounts_raw]
    has_sensitive_mount = any(
        any(mount.startswith(s) for s in _SENSITIVE_MOUNTS)
        for mount in mount_paths
    )
    has_docker_socket_mount = any("docker.sock" in m for m in mount_paths)
    has_dangerous_cap = any(cap in caps_str for cap in _DANGEROUS_CAPS)

    namespace_pid   = bool(event.get("host_pid") or event.get("hostPID"))
    namespace_net   = bool(event.get("host_network") or event.get("hostNetwork"))
    namespace_ipc   = bool(event.get("host_ipc") or event.get("hostIPC"))

    # ── Derived signals ──────────────────────────────────────────────────────
    priority_score  = _FALCO_PRIORITY_RISK.get((priority_raw or "INFO").upper(), 0.20)
    rule_risk_score = _rule_risk(rule)

    rule_lower      = (rule or "").lower()
    output_lower    = (output or "").lower()

    is_shell_spawn   = "shell" in rule_lower or "bash" in (proc_name or "").lower() or "sh" in (proc_name or "")
    is_crypto        = "crypto" in rule_lower or "miner" in output_lower or "mining" in output_lower
    is_breakout      = "breakout" in rule_lower or "escape" in rule_lower
    is_reverse_shell = "reverse" in rule_lower or "reverse_shell" in rule_lower
    is_file_write    = "write" in rule_lower and ("etc" in rule_lower or "sensitive" in rule_lower)
    is_network_ioc   = _truthy(network_dst_ip)
    is_root_user     = user_name in ("root", "0") or user_uid == "0"
    is_using_docker_sock = "docker.sock" in (file_path or "") or has_docker_socket_mount
    image_is_latest  = (image_tag or "").lower() in ("latest", "", "none")
    has_image_digest = image_digest is not None  # pinned image = better supply chain

    # Presence flags
    has_rule         = rule is not None
    has_priority     = _truthy(priority_raw)
    has_container_id = container_id is not None
    has_container_name = container_name is not None
    has_image        = image_repo is not None
    has_proc         = proc_name is not None
    has_cmdline      = proc_cmdline is not None
    has_parent       = parent_name is not None
    has_user         = user_name is not None
    has_host         = hostname is not None
    has_file_ctx     = file_path is not None
    has_network_ctx  = network_dst_ip is not None
    has_syscall      = syscall_type is not None
    has_timestamp    = event_time is not None

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    core    = [has_rule, has_priority, has_container_id, has_image, has_host]
    process = [has_proc, has_cmdline, has_parent, has_user]
    context = [has_file_ctx or has_network_ctx, has_syscall, has_timestamp, has_container_name]

    t = (
        sum(1.0 for x in core if x) / max(len(core), 1) * 0.45 +
        sum(1.0 for x in process if x) / max(len(process), 1) * 0.35 +
        sum(1.0 for x in context if x) / max(len(context), 1) * 0.20
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = (rule_risk_score * 0.55) + (priority_score * 0.45)

    if is_privileged:           s = min(1.0, s + 0.08)
    if has_dangerous_cap:       s = min(1.0, s + 0.07)
    if has_sensitive_mount:     s = min(1.0, s + 0.07)
    if has_docker_socket_mount: s = min(1.0, s + 0.10)
    if namespace_pid or namespace_net: s = min(1.0, s + 0.05)
    if is_root_user:            s = min(1.0, s + 0.03)
    if is_crypto:               s = min(1.0, s + 0.05)
    if is_network_ioc:          s = min(1.0, s + 0.03)

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_container_id:        b += 0.12
    if has_image:               b += 0.10
    if has_proc:                b += 0.10
    if has_cmdline:             b += 0.08
    if has_parent:              b += 0.07
    if has_user:                b += 0.06
    if has_host:                b += 0.05
    if has_file_ctx:            b += 0.04
    if has_image_digest:        b += 0.03  # pinned = auditable
    if image_is_latest:         b -= 0.05  # :latest = untracked changes
    if is_privileged:           b -= 0.05  # privilege breaks isolation narrative
    if has_docker_socket_mount: b -= 0.08  # socket mount = full daemon access

    b = max(0.0, min(1.0, float(b)))

    flags = {
        # Standard DFS
        "has_user":                 has_user,
        "has_host":                 has_host,
        "has_command_line":         has_cmdline,
        "has_process_path":         has_proc,
        "has_parent_process":       has_parent,
        # Container-specific
        "has_container_id":         has_container_id,
        "has_container_name":       has_container_name,
        "has_image":                has_image,
        "has_image_digest":         has_image_digest,
        "has_cmdline":              has_cmdline,
        "has_network_ctx":          has_network_ctx,
        "has_file_ctx":             has_file_ctx,
        "has_syscall":              has_syscall,
        # Risk signals
        "is_privileged":            is_privileged,
        "is_root_user":             is_root_user,
        "is_shell_spawn":           is_shell_spawn,
        "is_reverse_shell":         is_reverse_shell,
        "is_breakout":              is_breakout,
        "is_crypto":                is_crypto,
        "is_file_write":            is_file_write,
        "is_network_ioc":           is_network_ioc,
        "is_using_docker_socket":   is_using_docker_sock,
        "has_sensitive_mount":      has_sensitive_mount,
        "has_docker_socket_mount":  has_docker_socket_mount,
        "has_dangerous_cap":        has_dangerous_cap,
        "namespace_pid":            namespace_pid,
        "namespace_net":            namespace_net,
        "image_is_latest":          image_is_latest,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def docker_to_inputs_and_flags(event):
    return extract(event)
