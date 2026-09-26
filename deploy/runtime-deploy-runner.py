#!/usr/bin/env python3
"""Pull and promote the latest successful immutable Nvoy runtime release.

The host needs only Python, Git, Docker, and the Compose plugin. Node and application packages
stay inside the candidate image. GitHub has no host credential; this runner pulls from main after
the release workflow has passed, stages every identity, and rolls back the complete touched set.

It runs on two events: a short timer tick, which asks GitHub for a release only while `main` has
moved past the deployed commit, and a change under the manifest root (nvoy-runtime-deploy.path),
which recreates the identity whose manifest changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ENV = os.environ
ROOT = Path(ENV.get("NVOY_INSTANCE_ROOT", "/etc/nvoy/instances")).resolve()
STATE = Path(ENV.get("NVOY_DEPLOY_STATE", "/var/lib/nvoy-deploy")).resolve()
HUB = Path(ENV.get("NVOY_DEPLOY_HUB", "/opt/nvoy-hub")).resolve()
SLUG = ENV.get("NVOY_GITHUB_SLUG", "JAFairweather/nvoy")
WORKFLOW = ENV.get("NVOY_RELEASE_WORKFLOW", "publish-runtime-images.yml")
DOCKER = ENV.get("NVOY_DOCKER", "docker")
GIT = ENV.get("NVOY_GIT", "git")
DRY_RUN = ENV.get("DRY_RUN") == "1"
SETTLE_MS = int(ENV.get("NVOY_SETTLE_MS", "3000"))
HEX40 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_REF = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", re.I)
# The timer ticks every 30 s. A full release lookup still happens at least this often, so a re-run
# release workflow is found even when `main` has not moved.
LOOKUP_EVERY_S = int(ENV.get("NVOY_LOOKUP_EVERY_S", "600"))
# GitHub creates a release run within seconds of a push; a commit outside the workflow's paths gets
# none, so stop asking about it after this.
NO_RELEASE_S = 120
# A failed attempt at the same release and manifests is not retried every tick; a transient fault
# (a registry blip) is retried after this, and any manifest edit or new release retries at once.
RETRY_AFTER_S = int(ENV.get("NVOY_RETRY_AFTER_S", "600"))


def log(message: str) -> None:
    print(f"nvoy-deploy: {message}", flush=True)


def read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def write_json(path: Path, value: dict) -> None:
    atomic_write(path, json.dumps(value, sort_keys=True) + "\n")


# A 30 s tick must not fill the journal: an outcome is logged when it differs from the last one.
def outcome(key: str, message: str) -> None:
    last = STATE / "LAST_OUTCOME"
    if (last.read_text().strip() if last.exists() else "") != key:
        log(message)
    atomic_write(last, key + "\n")


def alarm(message: str) -> None:
    print(f"nvoy-deploy: ALARM: {message}", file=sys.stderr, flush=True)


def run(argv: list[str], *, capture: bool = False, input_text: str | None = None,
        extra_env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, check=True, text=True, input=input_text,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            env={**ENV, **(extra_env or {})})
    return (result.stdout or "").strip()


def github_json(url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "nvoy-runtime-deploy/1"}
    if ENV.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {ENV['GH_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        return json.load(response)


def release_sha() -> tuple[str, list[dict]]:
    # Test-only seam is deliberately named as such; production NVOY_RELEASE_SHA is only an
    # assertion against GitHub's latest successful main workflow, never an authorization bypass.
    if ENV.get("NVOY_TEST_RELEASE_SHA"):
        return ENV["NVOY_TEST_RELEASE_SHA"].lower(), []
    # Unfiltered, newest first, and chosen here: GitHub's status=success filter is served from a
    # search index that silently omits runs — on 2026-09-24 it returned 4 of ~60 successful ones,
    # one of them a release older than this runner, which is how the Aug 28 downgrade happened.
    url = f"https://api.github.com/repos/{SLUG}/actions/workflows/{WORKFLOW}/runs?branch=main&per_page=30"
    runs = github_json(url).get("workflow_runs") or []
    release = pick_release(runs)
    if not release:
        raise RuntimeError("no completed successful main release workflow")
    sha = str(release.get("head_sha", "")).lower()
    expected = ENV.get("NVOY_RELEASE_SHA", "").lower()
    if expected and expected != sha:
        raise RuntimeError(f"launcher SHA {expected} is not the latest successful release {sha}")
    return sha, runs


def pick_release(runs: list[dict]) -> dict | None:
    return next((r for r in runs if r.get("status") == "completed" and r.get("conclusion") == "success"
                 and r.get("head_branch") == "main"), None)


# `git ls-remote` is not a GitHub API call, so it is cheap enough for every tick.
def remote_main() -> str:
    try:
        words = run([GIT, "-C", str(HUB), "ls-remote", "origin", "refs/heads/main"], capture=True).split()
    except subprocess.CalledProcessError:
        return ""
    head = words[0].lower() if words else ""
    return head if HEX40.fullmatch(head) else ""


# Whether asking GitHub about this `main` head can stop: its release run has finished, or none
# came for it (a commit outside the release paths). Runs are newest first.
def head_status(seen: dict, head: str, runs: list[dict], now: float) -> dict:
    first = seen.get("first_seen", now) if seen.get("head") == head else now
    mine = [r for r in runs if str(r.get("head_sha", "")).lower() == head and r.get("head_branch") == "main"]
    finished = bool(mine) and mine[0].get("status") == "completed"
    return {"head": head, "first_seen": first, "looked_up": now,
            "settled": finished or (not mine and now - first > NO_RELEASE_S)}


# A release is a main commit, so while `main` sits at the deployed commit, or at a head whose
# release run has settled, there is nothing new to ask GitHub about.
def current_release(deployed: str) -> str:
    head, seen, now = remote_main(), read_json(STATE / "REMOTE_HEAD.json") or {}, time.time()
    fresh = seen.get("head") == head and now - float(seen.get("looked_up", 0)) < LOOKUP_EVERY_S
    if HEX40.fullmatch(deployed) and head and fresh and (head == deployed or seen.get("settled")):
        return deployed
    sha, runs = release_sha()
    if head:
        write_json(STATE / "REMOTE_HEAD.json", head_status(seen, head, runs, now))
    return sha


def manifest_digests() -> dict[str, str]:
    return {path.stem: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(ROOT.glob("*.json"))}


def is_ancestor(older: str, newer: str) -> bool:
    result = subprocess.run([GIT, "-C", str(HUB), "merge-base", "--is-ancestor", older, newer], env=ENV)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git could not compare {older[:12]} with {newer[:12]}")
    return result.returncode == 0


def canonical_digest(tag: str) -> str:
    run([DOCKER, "pull", tag])
    refs = run([DOCKER, "image", "inspect", "--format", '{{join .RepoDigests "\\n"}}', tag], capture=True).split()
    wanted = tag.rsplit(":", 1)[0] + "@sha256:"
    found = next((ref for ref in refs if ref.startswith(wanted)), "")
    if not IMAGE_REF.fullmatch(found):
        raise RuntimeError(f"pull of {tag} produced no canonical digest")
    return found


def instances() -> list[dict]:
    result = []
    for path in sorted(ROOT.glob("*.json")):
        raw = json.loads(path.read_text())
        if not raw.get("id") or f"{raw['id']}.json" != path.name:
            raise RuntimeError(f"manifest filename/id mismatch: {path.name}")
        configured = raw.get("worker_enabled", raw.get("workerEnabled"))
        delivery = raw.get("delivery_mode", raw.get("deliveryMode", "headless"))
        enabled = delivery == "headless" if configured is None else configured
        if not isinstance(enabled, bool):
            raise RuntimeError(f"{path.name}: worker_enabled must be boolean")
        result.append({"id": raw["id"], "worker": enabled, "harness": raw.get("harness") is not None,
                       "notifier": raw.get("wake_webhook") is not None})
    if not result:
        raise RuntimeError(f"no instance manifests in {ROOT}")
    return result


def compose(path: Path, args: list[str], capture: bool = False) -> str:
    return run([DOCKER, "compose", "-f", str(path), *args], capture=capture)


def verify_compose(path: Path, instance: dict, runtime_ref: str, worker_ref: str) -> None:
    compose(path, ["config", "-q"])
    rendered = compose(path, ["config"], True)
    if runtime_ref not in rendered:
        raise RuntimeError(f"{instance['id']}: rendered Compose lost runtime digest")
    if (instance["worker"] or instance["harness"]) and worker_ref not in rendered:
        raise RuntimeError(f"{instance['id']}: rendered Compose lost worker digest")


def verify_running(path: Path, instance: dict) -> None:
    running = set(compose(path, ["ps", "--status", "running", "--services"], True).split())
    expected = (["watcher", "broker", "adapter"] + (["worker"] if instance["worker"] else [])
                + (["harness"] if instance["harness"] else []) + (["notifier"] if instance.get("notifier") else []))
    missing = [service for service in expected if service not in running]
    if missing:
        raise RuntimeError(f"{instance['id']}: services not running: {', '.join(missing)}")
    text = compose(path, ["ps", "-a", "--format", "json", "init"], True)
    try:
        rows = []
        for line in filter(None, text.splitlines()):
            value = json.loads(line)
            rows.extend(value if isinstance(value, list) else [value])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{instance['id']}: initializer status was not valid JSON") from error
    if not rows or any(row.get("State") != "exited" or int(row.get("ExitCode", -1)) != 0 for row in rows):
        raise RuntimeError(f"{instance['id']}: initializer did not complete cleanly")


def settle() -> None:
    if SETTLE_MS < 0 or SETTLE_MS > 60_000:
        raise RuntimeError("NVOY_SETTLE_MS must be between 0 and 60000")
    time.sleep(SETTLE_MS / 1000)


def atomic_write(path: Path, value: str) -> None:
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    temporary.write_text(value)
    os.chmod(temporary, 0o644)
    temporary.replace(path)


def render(instance: dict, runtime_ref: str, worker_ref: str) -> str:
    args = [DOCKER, "run", "--rm", "--read-only", "--tmpfs", "/tmp:mode=1777",
            "-e", f"NVOY_INSTANCE_ROOT={ROOT}", "-v", f"{ROOT}:{ROOT}:ro", runtime_ref,
            "node", "mcp/tools/render-instance-compose.mjs", "--instance", instance["id"],
            "--image", runtime_ref]
    if instance["worker"] or instance["harness"]:
        args.extend(["--worker-image", worker_ref])
    return run(args, capture=True) + "\n"


def boundary_test(runtime_ref: str) -> None:
    test = Path(ENV.get("NVOY_BOUNDARY_TEST", HUB / "deploy/runtime-image-boundary.py")).resolve()
    run([sys.executable, str(test), runtime_ref], extra_env={"NVOY_DOCKER": DOCKER})


def main() -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = STATE / ".deploy-lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        log("another deploy tick is active — leaving it to finish")
        return
    restore_to = None
    attempt = ""
    failed_file = STATE / "FAILED_ATTEMPT.json"
    try:
        deployed_file = STATE / "DEPLOYED_SHA"
        deployed = deployed_file.read_text().strip() if deployed_file.exists() else ""
        sha = current_release(deployed)
        if not HEX40.fullmatch(sha):
            raise RuntimeError(f"release workflow returned invalid SHA {sha}")
        identity_list = instances()
        digests = manifest_digests()
        manifests_file = STATE / "DEPLOYED_MANIFESTS.json"
        recorded = read_json(manifests_file)
        recreate: set[str] = set()
        # Releases only move forward. An older answer from the release lookup keeps the deployed
        # release (and still health-checks it); a release off the deployed line is refused.
        if HEX40.fullmatch(deployed) and sha != deployed:
            run([GIT, "-C", str(HUB), "fetch", "--quiet", "origin", "main"])
            if is_ancestor(sha, deployed):
                log(f"release lookup named {sha[:12]}, older than the deployed {deployed[:12]} — keeping the deployed release")
                sha = deployed
            elif not is_ancestor(deployed, sha):
                raise RuntimeError(f"release {sha[:12]} does not descend from the deployed {deployed[:12]} — refusing")
        if deployed == sha:
            try:
                for instance in identity_list:
                    verify_running(ROOT / f"{instance['id']}.compose.yml", instance)
                healthy = True
            except Exception as error:  # health fault must reconcile, not become a quiet no-op
                print(f"nvoy-deploy: current release is unhealthy ({error}) — reconciling it", file=sys.stderr)
                healthy = False
            if healthy and recorded is None:
                # A host upgrading to this runner has no record of what its stacks were started
                # from; take today's manifests as that record rather than recreating everything.
                write_json(manifests_file, digests)
                log(f"already current and healthy at {sha[:12]} — manifest baseline recorded")
                return
            # The services read their manifest when they start, and an unchanged Compose file
            # makes `up -d` a no-op, so an edited manifest's identity is recreated explicitly.
            recreate = {i for i, d in digests.items() if recorded is not None and recorded.get(i) != d}
            if healthy and not recreate:
                outcome(f"current {sha}", f"already current and healthy at {sha[:12]}")
                return
            if recreate:
                log(f"manifest changed for {', '.join(sorted(recreate))} — reconciling at {sha[:12]}")

        attempt = f"{sha} {hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest()}"
        failed = read_json(failed_file) or {}
        if failed.get("attempt") == attempt and time.time() - float(failed.get("at", 0)) < RETRY_AFTER_S:
            outcome(f"held {attempt}", f"{sha[:12]} with these manifests failed at {time.strftime('%H:%M:%S', time.localtime(float(failed['at'])))}"
                    f" — retrying after {RETRY_AFTER_S}s, or at once on a manifest edit or a new release")
            return

        run([GIT, "-C", str(HUB), "fetch", "--quiet", "origin", "main"])
        run([GIT, "-C", str(HUB), "cat-file", "-e", f"{sha}^{{commit}}"])
        run([GIT, "-C", str(HUB), "merge-base", "--is-ancestor", sha, "origin/main"])
        # This runner executes from the checkout it moves. Until the release is promoted, any exit
        # puts it back — a failed candidate must never leave the host running someone else's runner.
        previous = run([GIT, "-C", str(HUB), "rev-parse", "HEAD"], capture=True)
        if not HEX40.fullmatch(previous):
            raise RuntimeError(f"cannot read the deployer's own checkout (got {previous[:40]!r})")
        restore_to = previous
        run([GIT, "-C", str(HUB), "checkout", "--quiet", "--detach", sha])

        runtime_ref = canonical_digest(f"ghcr.io/jafairweather/nvoy-runtime:sha-{sha}")
        worker_ref = canonical_digest(f"ghcr.io/jafairweather/nvoy-worker:sha-{sha}")
        log(f"candidate {sha[:12]}: {len(identity_list)} identity(s), immutable images pulled")
        if DRY_RUN:
            log("DRY_RUN — source and image provenance verified; no instance changed")
            return

        boundary_test(runtime_ref)
        candidate = STATE / f"candidate-{sha}"
        backup = STATE / f"rollback-{int(time.time() * 1000)}"
        shutil.rmtree(candidate, ignore_errors=True)
        candidate.mkdir(mode=0o700)
        backup.mkdir(mode=0o700)
        changed: list[dict] = []
        try:
            for instance in identity_list:
                staged = candidate / f"{instance['id']}.compose.yml"
                staged.write_text(render(instance, runtime_ref, worker_ref))
                os.chmod(staged, 0o600)
                verify_compose(staged, instance, runtime_ref, worker_ref)
            for instance in identity_list:
                live = ROOT / f"{instance['id']}.compose.yml"
                if live.exists():
                    shutil.copy2(live, backup / live.name)
                staged = candidate / f"{instance['id']}.compose.yml"
                # Compose may recreate or start part of an identity before returning nonzero.
                # Record the attempt before crossing that process boundary so rollback includes
                # the identity whose `up` failed, not only earlier successful identities.
                changed.append(instance)
                compose(staged, ["up", "-d", "--remove-orphans"]
                        + (["--force-recreate"] if instance["id"] in recreate else []))
                settle()
                verify_running(staged, instance)
        except Exception as error:
            print(f"nvoy-deploy: candidate failed: {error}", file=sys.stderr)
            for instance in reversed(changed):
                old = backup / f"{instance['id']}.compose.yml"
                try:
                    if old.exists():
                        compose(old, ["up", "-d", "--remove-orphans"])
                        settle()
                        verify_running(old, instance)
                    else:
                        compose(candidate / f"{instance['id']}.compose.yml", ["down"])
                except Exception as rollback_error:
                    alarm(f"rollback failed for {instance['id']}: {rollback_error}")
            raise

        for instance in identity_list:
            atomic_write(ROOT / f"{instance['id']}.compose.yml",
                         (candidate / f"{instance['id']}.compose.yml").read_text())
        atomic_write(STATE / "DEPLOYED_RUNTIME_IMAGE", runtime_ref + "\n")
        atomic_write(STATE / "DEPLOYED_WORKER_IMAGE", worker_ref + "\n")
        atomic_write(deployed_file, sha + "\n")
        write_json(manifests_file, digests)
        failed_file.unlink(missing_ok=True)
        (STATE / "LAST_OUTCOME").unlink(missing_ok=True)
        restore_to = None
        log(f"deploy OK — {len(identity_list)} identity(s) verified at {sha[:12]}")
    except Exception:
        if attempt:
            write_json(failed_file, {"attempt": attempt, "at": time.time()})
            (STATE / "LAST_OUTCOME").unlink(missing_ok=True)
        raise
    finally:
        if restore_to and restore_to != sha:
            try:
                run([GIT, "-C", str(HUB), "checkout", "--quiet", "--detach", restore_to])
            except Exception as error:
                alarm(f"could not return the deployer's checkout to {restore_to[:12]}: {error}")
        shutil.rmtree(lock, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        alarm(str(error))
        sys.exit(1)
