#!/usr/bin/env python3
"""Production Docker boundary probe for one candidate Nvoy runtime image."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

DOCKER = os.environ.get("NVOY_DOCKER", "docker")
IMAGE = sys.argv[1] if len(sys.argv) == 2 else ""
if "@sha256:" not in IMAGE:
    raise SystemExit("usage: runtime-image-boundary.py <immutable-runtime-image>")
STAMP = f"nvoy-boundary-{os.getpid()}-{int(time.time() * 1000)}"
VOLUMES = {name: f"{STAMP}-{name}" for name in ("instances", "state", "spool", "runtime", "provider", "workercreds")}
ADAPTER = f"{STAMP}-adapter"


def docker(args: list[str], input_text: str | None = None, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run([DOCKER, *args], text=True, input=input_text, capture_output=True, check=check)


def expect(label: str, result: subprocess.CompletedProcess, status: int = 0) -> None:
    if result.returncode != status:
        raise RuntimeError(f"{label}: {(result.stderr or result.stdout).strip()}")
    print(f"ok — {label}")


manifest = {
    "version": 1, "id": "boundary-test", "pubkey": "1" * 64,
    "state_dir": "/var/lib/nvoy/boundary-test", "runtime_dir": "/run/nvoy/boundary-test",
    "spool_dir": "/var/lib/nvoy-watcher/boundary-test",
    "broker_adapter_gid": 41001, "worker_handoff_gid": 41002,
    "watcher_uid": 41011, "broker_uid": 41012, "adapter_uid": 41013, "worker_uid": 41014,
    "bunker_uri_ref": "/etc/nvoy/credentials/unused.bunker",
    "bunker_client_ref": "/etc/nvoy/credentials/unused.client",
    "worker_image": "registry.example/worker@sha256:" + "d" * 64, "worker_runner": "codex",
    "worker_credential_ref": "/etc/nvoy/credentials/unused.provider",
    "grantors": ["4" * 64], "relays": ["wss://nos.lol"],
}


def mount(name: str, target: str) -> list[str]:
    return ["-v", f"{VOLUMES[name]}:{target}"]


try:
    expect("Docker daemon is available", docker(["version", "--format", "{{.Server.Version}}"]))
    for volume in VOLUMES.values():
        expect(f"create {volume}", docker(["volume", "create", volume]))
    seed_js = "const fs=require('node:fs');let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>fs.writeFileSync('/etc/nvoy/instances/boundary-test.json',s,{mode:0o644}))"
    expect("seed immutable instance manifest", docker(["run", "--rm", "-i", "--user", "0:0",
        *mount("instances", "/etc/nvoy/instances"), IMAGE, "node", "-e", seed_js], json.dumps(manifest)))
    expect("seed disposable worker provider credential", docker(["run", "--rm", "--user", "0:0",
        *mount("provider", "/run/nvoy-provider"), IMAGE, "node", "-e",
        "require('node:fs').writeFileSync('/run/nvoy-provider/provider','boundary-only',{mode:0o600})"]))
    rendered = docker(["run", "--rm", "--read-only", "--tmpfs", "/tmp:mode=1777", "--user", "0:0",
        *mount("instances", "/etc/nvoy/instances:ro"), IMAGE, "node", "mcp/tools/render-instance-compose.mjs",
        "--instance", "boundary-test", "--image", "registry.example/runtime@sha256:" + "a" * 64])
    expect("candidate image renders its Compose contract", rendered)
    if "name: nvoy-boundary-test" not in rendered.stdout:
        raise RuntimeError("rendered Compose did not bind the instance id")
    if f'target: "{manifest["runtime_dir"]}"' not in rendered.stdout:
        raise RuntimeError("rendered Compose did not produce YAML-safe volume targets")

    base = ["--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--tmpfs", "/tmp:mode=1777", *mount("instances", "/etc/nvoy/instances:ro")]
    expect("root-only initializer provisions isolated volumes", docker(["run", *base, "--user", "0:0",
        "--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE",
        "-e", "NVOY_WORKER_PROVIDER_SOURCE=/run/nvoy-provider/provider",
        *mount("state", manifest["state_dir"]), *mount("spool", manifest["spool_dir"]),
        *mount("runtime", manifest["runtime_dir"]), *mount("provider", "/run/nvoy-provider:ro"),
        *mount("workercreds", "/run/nvoy-worker-credentials"), IMAGE, "node", "mcp/tools/instance-runtime-init.mjs",
        "--instance", "boundary-test"]))
    expect("start keyless adapter", docker(["run", "-d", "--name", ADAPTER, "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--tmpfs", "/tmp:mode=1777",
        "--user", "41013:41001", "--group-add", "41002", *mount("instances", "/etc/nvoy/instances:ro"),
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "mcp/tools/instance-adapter.mjs",
        "--instance", "boundary-test"]))
    time.sleep(0.5)
    socket_probe = "const net=require('node:net');const c=net.createConnection('/run/nvoy/boundary-test/adapter.sock');c.on('connect',()=>process.exit(9));c.on('error',e=>process.exit(['EACCES','EPERM'].includes(e.code)?0:8));setTimeout(()=>process.exit(7),1500)"
    expect("worker cannot connect to adapter socket", docker(["run", *base, "--user", "41014:41002",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", socket_probe]))
    replace_probe = "const fs=require('node:fs');try{fs.unlinkSync('/run/nvoy/boundary-test/adapter.sock');process.exit(9)}catch(e){process.exit(['EACCES','EPERM'].includes(e.code)?0:8)}"
    expect("worker cannot replace adapter socket", docker(["run", *base, "--user", "41014:41002",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", replace_probe]))
    queue_probe = "const fs=require('node:fs');try{fs.appendFileSync('/run/nvoy/boundary-test/admitted-tasks.jsonl','forged\\n');process.exit(9)}catch(e){process.exit(['EACCES','EPERM'].includes(e.code)?0:8)}"
    expect("worker cannot forge admitted queue", docker(["run", *base, "--user", "41014:41002",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", queue_probe]))
    unlink_probe = "const fs=require('node:fs');try{fs.unlinkSync('/run/nvoy/boundary-test/admitted-tasks.jsonl');process.exit(9)}catch(e){process.exit(['EACCES','EPERM'].includes(e.code)?0:8)}"
    expect("worker cannot replace admitted queue", docker(["run", *base, "--user", "41014:41002",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", unlink_probe]))
    # Positive control on the worker itself. The three refusals above cannot distinguish "the worker
    # is confined to its own lane" from "the worker can write nothing at all" — and a runtime where
    # the worker cannot lodge a reply request is broken in a way every refusal above still passes.
    reply_probe = "const fs=require('node:fs');try{fs.appendFileSync('/run/nvoy/boundary-test/reply-requests.jsonl','');process.exit(0)}catch(e){process.exit(8)}"
    expect("worker can write only its bounded reply queue", docker(["run", *base, "--user", "41014:41002",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", reply_probe]))
    broker_probe = "const net=require('node:net');const c=net.createConnection('/run/nvoy/boundary-test/adapter.sock');c.on('connect',()=>process.exit(0));c.on('error',()=>process.exit(8));setTimeout(()=>process.exit(7),1500)"
    expect("broker group can connect to adapter socket", docker(["run", *base, "--user", "41012:41001",
        *mount("runtime", manifest["runtime_dir"]), IMAGE, "node", "-e", broker_probe]))
    print("runtime-image-boundary: all passed")
finally:
    docker(["rm", "-f", ADAPTER])
    for volume in VOLUMES.values():
        docker(["volume", "rm", "-f", volume])
