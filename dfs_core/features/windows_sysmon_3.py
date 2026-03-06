# dfs_core/features/windows_sysmon_3.py
"""
Sysmon Event ID 3 — Network Connection → DFS Inputs

Sysmon 3 is the primary source for:
  - C2 beaconing detection (periodic outbound to suspicious IPs)
  - Lateral movement (internal connections from unexpected processes)
  - Living-off-the-land (LOLBins making network calls: certutil, mshta, regsvr32)
  - DNS-over-HTTPS abuse, domain fronting indicators
  - Port scanning (many connections in short time)

DFS Mapping:
  S (Signal Clarity):   Process reputation + destination risk + port/protocol context
  T (Telemetry):        Process identity + network 5-tuple + DNS context completeness
  B (Behavioral):       Coherence of process → network → destination narrative

Key threat patterns:
  - LOLBin making outbound connection (certutil, mshta, wscript, regsvr32, rundll32)
  - Office process connecting out (winword, excel, powerpnt)
  - System process to unusual destination (svchost → external IP)
  - Connection on suspicious ports (4444, 1337, 8080, 31337)
  - DNS to newly registered / DGA-looking domain
  - Internal reconnaissance (SMB/RDP/WMI sweep)
  - Tor exit node IPs
  - High-frequency beaconing pattern
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
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "false", "n/a"):
        return False
    return True


def _is_redacted(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    s = v.strip().lower()
    return "redacted" in s or "[redacted" in s or "missing" in s


def _clean(v: Any) -> Optional[str]:
    if not _truthy(v):
        return None
    if _is_redacted(str(v)):
        return None
    return str(v)


# ---------------------------------------------------------------------------
# Threat tables
# ---------------------------------------------------------------------------

# LOLBins known to abuse network (partial match on exe name)
_LOLBIN_PROCESSES = {
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "installutil.exe",
    "cmstp.exe", "ieexec.exe", "infdefaultinstall.exe", "pcalua.exe",
    "syncappvpublishingserver.exe", "appsyncpublishingserver.exe",
    "msdeploy.exe", "desktopimgdownldr.exe", "bitsadmin.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "hh.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
    "msbuild.exe", "msconfig.exe", "msdtc.exe", "msiexec.exe",
    "nltestrpc.exe", "odbcconf.exe", "pcwrun.exe", "replace.exe",
    "rpcping.exe", "runscripthelper.exe", "sfc.exe", "sqldumper.exe",
    "squirrel.exe", "url.dll", "xwizard.exe",
}

# Office processes — should almost never make direct network connections
_OFFICE_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
}

# Browsers — network expected but track destination
_BROWSER_PROCESSES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "vivaldi.exe",
}

# Suspicious destination ports
_SUSPICIOUS_PORTS = {
    "4444", "1337", "31337", "8888", "9999", "6666", "1234",
    "4321", "1232", "8443", "9090", "5555", "7777", "2222",
}

# Common C2 framework default ports
_C2_PORTS = {
    "4444",   # Metasploit default
    "1337",   # common leet port
    "31337",  # Elite / Back Orifice
    "8080",   # Cobalt Strike common
    "8443",   # Cobalt Strike HTTPS
    "50050",  # Cobalt Strike team server
    "60000",  # Cobalt Strike
    "443",    # HTTPS (valid but watch for non-browser processes)
}

# Internal recon ports
_LATERAL_PORTS = {
    "445",    # SMB
    "139",    # NetBIOS
    "3389",   # RDP
    "5985",   # WinRM HTTP
    "5986",   # WinRM HTTPS
    "135",    # RPC
    "389",    # LDAP
    "636",    # LDAPS
    "88",     # Kerberos
    "464",    # Kerberos password change
}

# Private IP ranges (for lateral movement detection)
def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or
            a == 127
        )
    except ValueError:
        return False


def _is_public_ip(ip: str) -> bool:
    return _truthy(ip) and not _is_private_ip(ip)


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Sysmon Event ID 3 (NetworkConnect) → (DFSInputs, flags).
    Accepts ECS-mapped or raw winlog event_data format.
    """

    ed = _get(event, "winlog.event_data") or {}

    # ── Process context ──────────────────────────────────────────────────────
    image           = _clean(_get(event, "process.executable") or ed.get("Image"))
    pid             = _clean(_get(event, "process.pid") or ed.get("ProcessId"))
    cmdline         = _clean(_get(event, "process.command_line") or ed.get("CommandLine"))
    parent_image    = _clean(_get(event, "process.parent.executable") or ed.get("ParentImage"))
    user            = _clean(_get(event, "user.name") or ed.get("User"))
    guid            = _clean(ed.get("ProcessGuid"))
    rule_name       = _clean(ed.get("RuleName"))

    # ── Network 5-tuple ──────────────────────────────────────────────────────
    dst_ip          = _clean(_get(event, "destination.ip") or ed.get("DestinationIp"))
    dst_port        = _clean(_get(event, "destination.port") or ed.get("DestinationPort"))
    dst_host        = _clean(_get(event, "destination.domain") or ed.get("DestinationHostname"))
    src_ip          = _clean(_get(event, "source.ip") or ed.get("SourceIp"))
    src_port        = _clean(_get(event, "source.port") or ed.get("SourcePort"))
    protocol        = _clean(_get(event, "network.protocol") or ed.get("Protocol") or "tcp")
    initiated       = ed.get("Initiated")  # "true" = outbound

    # ── Host context ─────────────────────────────────────────────────────────
    host            = _clean(_get(event, "host.name") or _get(event, "winlog.computer_name"))
    timestamp       = _clean(_get(event, "@timestamp") or _get(event, "event.created"))

    # ── Derived signals ──────────────────────────────────────────────────────
    image_lower     = (image or "").lower()
    exe_name        = image_lower.split("\\")[-1] if "\\" in image_lower else image_lower

    is_lolbin           = exe_name in _LOLBIN_PROCESSES
    is_office_process   = exe_name in _OFFICE_PROCESSES
    is_browser          = exe_name in _BROWSER_PROCESSES
    is_system_process   = exe_name in ("svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe")
    is_powershell       = "powershell" in image_lower or "pwsh" in image_lower
    is_outbound         = str(initiated).lower() == "true" if initiated is not None else True

    dst_port_str        = str(dst_port or "")
    is_suspicious_port  = dst_port_str in _SUSPICIOUS_PORTS
    is_c2_port          = dst_port_str in _C2_PORTS
    is_lateral_port     = dst_port_str in _LATERAL_PORTS
    is_external_dst     = _is_public_ip(dst_ip or "")
    is_internal_dst     = _is_private_ip(dst_ip or "")
    is_lateral_movement = is_internal_dst and is_lateral_port and not is_browser

    # LOLBin/Office making external connection = very high signal
    is_lolbin_external  = is_lolbin and is_external_dst
    is_office_external  = is_office_process and is_external_dst
    is_ps_external      = is_powershell and is_external_dst

    # System process to external = unusual
    is_system_external  = is_system_process and is_external_dst

    # DNS hostname available (richer context)
    has_dns_context     = dst_host is not None and not _is_private_ip(dst_host or "")

    # DGA-like hostname heuristic (high entropy, no vowels, long random strings)
    def _looks_dga(domain: str) -> bool:
        if not domain or len(domain) < 8:
            return False
        sld = domain.split(".")[0].lower()
        vowels = sum(1 for c in sld if c in "aeiou")
        return len(sld) >= 12 and vowels / max(len(sld), 1) < 0.20
    is_dga_domain       = _looks_dga(dst_host or "")

    # Presence flags
    has_image           = image is not None
    has_cmdline         = cmdline is not None
    has_parent          = parent_image is not None
    has_user            = user is not None
    has_host            = host is not None
    has_dst_ip          = dst_ip is not None
    has_dst_port        = dst_port is not None
    has_dst_host        = dst_host is not None
    has_src_ip          = src_ip is not None
    has_guid            = guid is not None
    has_timestamp       = timestamp is not None
    has_protocol        = protocol is not None

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    process_fields  = [has_image, has_user, has_host, has_guid]
    network_fields  = [has_dst_ip, has_dst_port, has_src_ip, has_protocol]
    enrichment      = [has_dst_host, has_cmdline, has_parent, has_timestamp]

    t = (
        sum(1.0 for x in process_fields if x) / max(len(process_fields), 1) * 0.40 +
        sum(1.0 for x in network_fields if x) / max(len(network_fields), 1) * 0.35 +
        sum(1.0 for x in enrichment if x) / max(len(enrichment), 1) * 0.25
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = 0.25  # baseline — network connections are common

    if is_lolbin_external:      s += 0.45
    elif is_office_external:    s += 0.45
    elif is_ps_external:        s += 0.30
    elif is_system_external:    s += 0.25
    elif is_lateral_movement:   s += 0.35
    elif is_lolbin:             s += 0.25

    if is_suspicious_port:      s = min(1.0, s + 0.20)
    if is_c2_port and not is_browser: s = min(1.0, s + 0.10)
    if is_dga_domain:           s = min(1.0, s + 0.15)
    if is_external_dst and is_outbound: s = min(1.0, s + 0.05)

    # Browser connections are expected — reduce signal
    if is_browser:              s = max(0.05, s - 0.15)

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_image:               b += 0.12
    if has_dst_ip:              b += 0.10
    if has_dst_port:            b += 0.08
    if has_user:                b += 0.08
    if has_host:                b += 0.07
    if has_guid:                b += 0.07  # process GUID links to process creation
    if has_dst_host:            b += 0.05  # DNS name = richer narrative
    if has_parent:              b += 0.05
    if has_cmdline:             b += 0.05
    # Incoherence: system process to external = broken expected behavior
    if is_system_external:      b = max(0.0, b - 0.10)
    if is_dga_domain:           b = max(0.0, b - 0.05)

    b = max(0.0, min(1.0, float(b)))

    flags = {
        # Standard DFS
        "has_user":                 has_user,
        "has_host":                 has_host,
        "has_command_line":         has_cmdline,
        "has_process_path":         has_image,
        "has_parent_process":       has_parent,
        # Sysmon 3 specific
        "has_dst_ip":               has_dst_ip,
        "has_dst_port":             has_dst_port,
        "has_dst_host":             has_dst_host,
        "has_src_ip":               has_src_ip,
        "has_guid":                 has_guid,
        # Risk signals
        "is_lolbin":                is_lolbin,
        "is_office_process":        is_office_process,
        "is_powershell":            is_powershell,
        "is_system_process":        is_system_process,
        "is_browser":               is_browser,
        "is_lolbin_external":       is_lolbin_external,
        "is_office_external":       is_office_external,
        "is_ps_external":           is_ps_external,
        "is_system_external":       is_system_external,
        "is_lateral_movement":      is_lateral_movement,
        "is_outbound":              is_outbound,
        "is_external_dst":          is_external_dst,
        "is_internal_dst":          is_internal_dst,
        "is_suspicious_port":       is_suspicious_port,
        "is_c2_port":               is_c2_port,
        "is_lateral_port":          is_lateral_port,
        "is_dga_domain":            is_dga_domain,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def sysmon3_to_inputs_and_flags(event):
    return extract(event)
