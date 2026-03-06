# dfs_core/features/registry.py
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Callable, Any, Dict

@dataclass(frozen=True)
class FeatureSpec:
    module: str
    factory: str  # nome do callable dentro do módulo (ex.: "extract")


FEATURES: Dict[str, FeatureSpec] = {
    "windows-powershell-4104": FeatureSpec( 
        module="dfs_core.features.windows_powershell_4104",
        factory="extract",
    ),
    "aws-guardduty": FeatureSpec(module="dfs_core.features.aws_guardduty", factory="extract"),
    "guardduty":     FeatureSpec(module="dfs_core.features.aws_guardduty", factory="extract"),
    # você pode deixar os outros mapeados, mas NÃO vamos importar agora
    "windows-4624": FeatureSpec(module="dfs_core.features.windows_4624", factory="extract"),
    "windows-4688": FeatureSpec(module="dfs_core.features.windows_4688", factory="extract"),
    "windows-sysmon-1": FeatureSpec(module="dfs_core.features.windows_sysmon_1", factory="extract"),
    "registry": FeatureSpec(module="dfs_core.features.registry", factory="extract"),
    "aws-cloudtrail-iam": FeatureSpec(module="dfs_core.features.aws_cloudtrail_iam", factory="extract"),
    "elastic-siem":   FeatureSpec(module="dfs_core.features.elastic_siem",   factory="extract"),
    "splunk-notable": FeatureSpec(module="dfs_core.features.splunk_notable",  factory="extract"),
    "wazuh-alert":    FeatureSpec(module="dfs_core.features.wazuh_alert",     factory="extract"),     
    "azure-ad-signin": FeatureSpec(module="dfs_core.features.azure_ad_signin", factory="extract"),
    "gcp-audit":      FeatureSpec(module="dfs_core.features.gcp_audit_log",   factory="extract"),
    "gcp-scc":        FeatureSpec(module="dfs_core.features.gcp_scc",         factory="extract"),
    "docker":         FeatureSpec(module="dfs_core.features.docker_runtime",  factory="extract"),
    "windows-sysmon-3": FeatureSpec(module="dfs_core.features.windows_sysmon_3", factory="extract"),
    "wifi-csi":  FeatureSpec(module="dfs_core.features.wifi_csi", factory="extract"),
    "csi":       FeatureSpec(module="dfs_core.features.wifi_csi", factory="extract"),
    "cve-context": FeatureSpec(module="dfs_core.features.cve_context", factory="extract"),
    "cve":         FeatureSpec(module="dfs_core.features.cve_context", factory="extract"),
    "agent-action": FeatureSpec(module="dfs_core.features.agent_action", factory="extract"),
    "agent":        FeatureSpec(module="dfs_core.features.agent_action", factory="extract"),
}

class FeatureNotFoundError(RuntimeError):
    pass

def load_feature(kind: str) -> Callable[..., Any]:
    spec = FEATURES.get(kind)
    if not spec:
        raise FeatureNotFoundError(f"Unknown feature kind: {kind}")

    try:
        mod = importlib.import_module(spec.module)
    except Exception as e:
        # importante: erro de outro módulo não derruba tudo
        raise RuntimeError(
            f"Failed to import feature module for kind='{kind}' ({spec.module}). Error: {e}"
        ) from e

    try:
        fn = getattr(mod, spec.factory)
    except AttributeError as e:
        raise RuntimeError(
            f"Feature kind='{kind}' loaded module '{spec.module}' but missing factory '{spec.factory}'."
        ) from e

    if not callable(fn):
        raise RuntimeError(
            f"Feature kind='{kind}' factory '{spec.factory}' in '{spec.module}' is not callable."
        )

    return fn
