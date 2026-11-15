#!/usr/bin/env python3
"""Replace one relay URL across fleet seat manifests and Bunker signer pointers.

Runs on nvoy-fleet without Node on the host. Dry-run by default: reads target
manifests and descriptor-pinned 0600 Bunker URI files, validates staged
manifests inside DEPLOYED_RUNTIME_IMAGE, and emits a secret-free JSON summary.

With --apply, acquires /var/lib/nvoy-deploy/.deploy-lock, writes 0600 backups
under /root/nvoy-relay-backups/<UTC>-<pid>, atomically updates Bunker URI files
before manifest JSON files (preserving non-relay query segments such as secret=
byte-for-byte), recreates only the touched seats' Compose stacks so init
refreshes broker_credentials and watcher/broker reload manifests, verifies init
exit 0 and running services, and updates DEPLOYED_MANIFESTS.json. Rolls back
all touched seats on failure and retains .deploy-lock if rollback cannot verify.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote_plus, urlsplit

ENV = os.environ
ROOT = Path(ENV.get("NVOY_INSTANCE_ROOT", "/etc/nvoy/instances")).resolve()
STATE = Path(ENV.get("NVOY_DEPLOY_STATE", "/var/lib/nvoy-deploy")).resolve()
BACKUP_ROOT = Path(ENV.get("NVOY_RELAY_BACKUPS", "/root/nvoy-relay-backups")).resolve()
DOCKER = ENV.get("NVOY_DOCKER", "docker")
SETTLE_MS = int(ENV.get("NVOY_SETTLE_MS", "3000"))
VALIDATE_SECONDS = float(ENV.get("NVOY_VALIDATE_SECONDS", "120"))

SEAT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$", re.I)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", re.I)
BUNKER_RE = re.compile(r"^bunker://([0-9a-fA-F]{64})\?([^\s#]+)$")
MAX_CREDENTIAL_BYTES = 4096
MAX_MANIFEST_BYTES = 512 * 1024

VALIDATE_ESTATE_JS = (
    "import('/srv/nvoy/mcp/tools/runtime_manifest.mjs')"
    ".then(m=>{m.assertNoCollisions('/etc/nvoy/instances');console.log('estate-valid')})"
    ".catch(e=>{console.error(e?.message||String(e));process.exit(1)})"
)


class SafeError(RuntimeError):
    """Sanitized operational error whose message never carries credential text."""


class RestoredFailure(SafeError):
    """Touched seats were rolled back and verified running after an apply fault."""


def fail(message: str) -> None:
    raise SafeError(message) from None


def validate_seat(value: str) -> str:
    seat = str(value or "").strip()
    if not SEAT_RE.fullmatch(seat):
        fail("invalid seat identifier")
    return seat


def validate_relay_url(raw_url: str, label: str = "relay URL") -> str:
    if not isinstance(raw_url, str) or not (1 <= len(raw_url) <= 512):
        fail(f"invalid {label}")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw_url):
        fail(f"invalid {label}")
    try:
        parts = urlsplit(raw_url)
        port = parts.port
    except ValueError:
        fail(f"invalid {label}")
    if (
        parts.scheme != "wss"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query != ""
        or parts.fragment != ""
        or (parts.path != "" and not parts.path.startswith("/"))
    ):
        fail(f"invalid {label}")
    if port is not None and not (1 <= port <= 65535):
        fail(f"invalid {label}")
    return raw_url


def relay_key(raw_url: str, label: str = "relay URL") -> str:
    validate_relay_url(raw_url, label)
    parts = urlsplit(raw_url)
    assert parts.hostname is not None
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parts.port
    port_part = f":{port}" if port is not None and port != 443 else ""
    path_part = "" if parts.path in ("", "/") else parts.path.rstrip("/")
    return f"wss://{host}{port_part}{path_part}"


def open_regular_nofollow(
    path: Path, *, max_bytes: int, secret_mode: bool, label: str
) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        fail(f"{label}: expected an absolute path")
    parent = path.parent
    try:
        if parent.is_symlink():
            fail(f"{label}: parent directory must not be a symlink")
        dir_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
    except SafeError:
        raise
    except OSError:
        fail(f"{label}: parent directory cannot be opened safely")
    fd = None
    try:
        try:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=dir_fd,
            )
        except OSError:
            fail(f"{label}: cannot open regular non-symlink file")
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(f"{label}: must be a regular non-symlink file")
        if st.st_uid != os.geteuid():
            fail(f"{label}: unexpected file owner")
        if secret_mode and (st.st_mode & 0o077) != 0:
            fail(f"{label}: credential file must be mode 0600 (no group/world access)")
        if not secret_mode and (st.st_mode & 0o022) != 0:
            fail(f"{label}: manifest file must not be group/world-writable")
        if st.st_size <= 0 or st.st_size > max_bytes:
            fail(f"{label}: unexpected file size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                fail(f"{label}: file exceeds maximum size")
        data = b"".join(chunks)
        if not data:
            fail(f"{label}: file is empty")
        return data, st
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dir_fd)


def atomic_write_nofollow(
    path: Path,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    expected_stat: os.stat_result | None,
    temp_stem: str,
    label: str,
) -> None:
    if not path.is_absolute():
        fail(f"{label}: expected an absolute path")
    parent = path.parent
    try:
        if parent.is_symlink():
            fail(f"{label}: parent directory must not be a symlink")
        dir_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
    except SafeError:
        raise
    except OSError:
        fail(f"{label}: parent directory cannot be opened safely")
    tmp_name = f".{temp_stem}.nvoy-relay-{os.getpid()}-{time.time_ns()}"
    tmp_created = False
    try:
        if expected_stat is not None:
            try:
                cur = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
            except OSError:
                fail(f"{label}: target disappeared before write")
            if (
                not stat.S_ISREG(cur.st_mode)
                or cur.st_dev != expected_stat.st_dev
                or cur.st_ino != expected_stat.st_ino
                or cur.st_size != expected_stat.st_size
                or cur.st_mtime_ns != expected_stat.st_mtime_ns
            ):
                fail(f"{label}: file changed concurrently during operation")
        try:
            fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
                dir_fd=dir_fd,
            )
            tmp_created = True
        except OSError:
            fail(f"{label}: cannot create temporary file")
        try:
            os.fchmod(fd, mode)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            view = memoryview(data)
            written = 0
            while written < len(data):
                written += os.write(fd, view[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        tmp_created = False
        os.fsync(dir_fd)
    finally:
        if tmp_created:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)


def dedup_relays(relays: list[str], label: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for r in relays:
        k = relay_key(r, label)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def rewrite_manifest_bytes(
    raw: bytes, seat: str, from_relay: str, to_relay: str
) -> tuple[bytes, dict, bool, list[str], list[str]]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{seat}: manifest is not valid UTF-8 JSON")
    if not isinstance(parsed, dict) or parsed.get("id") != seat:
        fail(f"{seat}: manifest id mismatch")
    relays = parsed.get("relays")
    if not isinstance(relays, list) or not relays or not all(isinstance(r, str) for r in relays):
        fail(f"{seat}: manifest relays must be a non-empty list of wss URLs")
    for r in relays:
        validate_relay_url(r, f"{seat} manifest relay")
    before = dedup_relays(relays, f"{seat} manifest relay")
    from_k = relay_key(from_relay, "from-relay")
    matched = any(relay_key(r, f"{seat} manifest relay") == from_k for r in relays)
    if not matched:
        return raw, parsed, False, before, list(before)
    replaced = [
        to_relay if relay_key(r, f"{seat} manifest relay") == from_k else r
        for r in relays
    ]
    after = dedup_relays(replaced, f"{seat} manifest relay")
    if not after:
        fail(f"{seat}: manifest relays would become empty")
    updated = dict(parsed)
    updated["relays"] = after
    encoded = (json.dumps(updated, indent=2) + "\n").encode("utf-8")
    return encoded, updated, True, before, after


def rewrite_bunker_uri_bytes(
    raw: bytes, seat: str, from_relay: str, to_relay: str
) -> tuple[bytes, bool, list[str], list[str]]:
    try:
        decoded = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{seat}: bunker credential is not valid ASCII")
    text = decoded.strip()
    if not text or "\n" in text or "\r" in text:
        fail(f"{seat}: bunker credential must contain one single-line URI")
    match = BUNKER_RE.fullmatch(text)
    if not match:
        fail(f"{seat}: invalid bunker URI structure")
    signer_pubkey = match.group(1).lower()
    query = match.group(2)
    try:
        parse_qs(query, strict_parsing=True)
    except Exception:
        fail(f"{seat}: malformed bunker URI query")
    segments = query.split("&")
    if not segments or any(not seg or "=" not in seg for seg in segments):
        fail(f"{seat}: malformed bunker URI query")

    raw_relays: list[str] = []
    parsed_segments: list[tuple[str, str, str]] = []
    for seg in segments:
        raw_key, raw_val = seg.split("=", 1)
        key = unquote_plus(raw_key)
        if not key:
            fail(f"{seat}: malformed bunker URI query")
        if key == "relay":
            relay_val = unquote_plus(raw_val)
            validate_relay_url(relay_val, f"{seat} signer relay")
            raw_relays.append(relay_val)
            parsed_segments.append((seg, "relay", relay_val))
        else:
            parsed_segments.append((seg, key, ""))

    if not (1 <= len(raw_relays) <= 8):
        fail(f"{seat}: invalid signer relay count")

    before = dedup_relays(raw_relays, f"{seat} signer relay")
    from_k = relay_key(from_relay, "from-relay")
    matched = any(relay_key(r, f"{seat} signer relay") == from_k for r in raw_relays)
    if not matched:
        return raw, False, before, list(before)

    out_segments: list[str] = []
    seen_keys: set[str] = set()
    after: list[str] = []
    for seg, key, relay_val in parsed_segments:
        if key == "relay":
            is_replaced = relay_key(relay_val, f"{seat} signer relay") == from_k
            effective = to_relay if is_replaced else relay_val
            eff_key = relay_key(effective, f"{seat} signer relay")
            if eff_key in seen_keys:
                continue
            seen_keys.add(eff_key)
            after.append(effective)
            out_segments.append(f"relay={quote(effective, safe='')}")
        else:
            # Preserve non-relay segments (such as secret=...) byte-for-byte untouched.
            out_segments.append(seg)

    if not (1 <= len(after) <= 8):
        fail(f"{seat}: invalid signer relay count after rewrite")

    rebuilt = f"bunker://{signer_pubkey}?{'&'.join(out_segments)}"
    try:
        split_check = urlsplit(rebuilt)
        qs_check = parse_qs(split_check.query, strict_parsing=True)
    except Exception:
        fail(f"{seat}: rewritten bunker URI failed strict validation")
    if (
        split_check.scheme != "bunker"
        or split_check.netloc != signer_pubkey
        or split_check.path != ""
        or split_check.fragment != ""
        or qs_check.get("relay") != after
    ):
        fail(f"{seat}: rewritten bunker URI failed strict validation")

    return (rebuilt + "\n").encode("ascii"), True, before, after


@dataclass
class SeatPlan:
    seat: str
    manifest_path: Path
    manifest_orig: bytes
    manifest_next: bytes
    manifest_stat: os.stat_result
    manifest_obj: dict
    manifest_changed: bool
    manifest_before: list[str]
    manifest_after: list[str]
    bunker_path: Path | None
    bunker_orig: bytes | None
    bunker_next: bytes | None
    bunker_stat: os.stat_result | None
    signer_changed: bool
    signer_before: list[str] | None
    signer_after: list[str] | None

    @property
    def any_change(self) -> bool:
        return self.manifest_changed or self.signer_changed


def instance_shape(raw: dict) -> dict:
    configured = raw.get("worker_enabled", raw.get("workerEnabled"))
    delivery = raw.get("delivery_mode", raw.get("deliveryMode", "headless"))
    enabled = delivery == "headless" if configured is None else configured
    if not isinstance(enabled, bool):
        fail(f"{raw.get('id', 'unknown')}: worker_enabled must be boolean")
    return {
        "id": raw["id"],
        "worker": enabled,
        "harness": raw.get("harness") is not None,
        "notifier": raw.get("wake_webhook") is not None,
        "door": raw.get("channel_door") is not None,
        "recall": raw.get("may_recall") is not None,
    }


def list_estate_seats() -> list[str]:
    if not ROOT.is_dir() or ROOT.is_symlink():
        fail(f"instance root {ROOT} is missing or a symlink")
    seats = sorted(path.stem for path in ROOT.glob("*.json"))
    if not seats:
        fail(f"no instance manifests in {ROOT}")
    for s in seats:
        validate_seat(s)
    return seats


def build_plans(
    target_seats: list[str], from_relay: str, to_relay: str
) -> list[SeatPlan]:
    plans: list[SeatPlan] = []
    for seat in target_seats:
        m_path = ROOT / f"{seat}.json"
        m_orig, m_stat = open_regular_nofollow(
            m_path,
            max_bytes=MAX_MANIFEST_BYTES,
            secret_mode=False,
            label=f"{seat} manifest",
        )
        m_next, m_obj, m_changed, m_before, m_after = rewrite_manifest_bytes(
            m_orig, seat, from_relay, to_relay
        )
        broker_mode = str(m_obj.get("broker_mode") or m_obj.get("brokerMode") or "local")
        key_ref = str(m_obj.get("key_ref") or m_obj.get("keyRef") or "")
        bunker_ref = str(m_obj.get("bunker_uri_ref") or m_obj.get("bunkerUriRef") or "")
        if broker_mode == "local" and not key_ref and not bunker_ref:
            fail(f"{seat}: local broker manifest has no credential reference")
        if bunker_ref:
            b_path = Path(bunker_ref)
            b_orig, b_stat = open_regular_nofollow(
                b_path,
                max_bytes=MAX_CREDENTIAL_BYTES,
                secret_mode=True,
                label=f"{seat} bunker credential",
            )
            b_next, s_changed, s_before, s_after = rewrite_bunker_uri_bytes(
                b_orig, seat, from_relay, to_relay
            )
            plans.append(
                SeatPlan(
                    seat=seat,
                    manifest_path=m_path,
                    manifest_orig=m_orig,
                    manifest_next=m_next,
                    manifest_stat=m_stat,
                    manifest_obj=m_obj,
                    manifest_changed=m_changed,
                    manifest_before=m_before,
                    manifest_after=m_after,
                    bunker_path=b_path,
                    bunker_orig=b_orig,
                    bunker_next=b_next,
                    bunker_stat=b_stat,
                    signer_changed=s_changed,
                    signer_before=s_before,
                    signer_after=s_after,
                )
            )
        else:
            plans.append(
                SeatPlan(
                    seat=seat,
                    manifest_path=m_path,
                    manifest_orig=m_orig,
                    manifest_next=m_next,
                    manifest_stat=m_stat,
                    manifest_obj=m_obj,
                    manifest_changed=m_changed,
                    manifest_before=m_before,
                    manifest_after=m_after,
                    bunker_path=None,
                    bunker_orig=None,
                    bunker_next=None,
                    bunker_stat=None,
                    signer_changed=False,
                    signer_before=None,
                    signer_after=None,
                )
            )
    return plans


def read_deployed_state() -> tuple[str, str, dict[str, str]]:
    sha_bytes, _ = open_regular_nofollow(
        STATE / "DEPLOYED_SHA",
        max_bytes=256,
        secret_mode=False,
        label="DEPLOYED_SHA",
    )
    sha = sha_bytes.decode("utf-8", errors="replace").strip()
    if not HEX40_RE.fullmatch(sha):
        fail("DEPLOYED_SHA does not contain a valid 40-hex commit")

    img_bytes, _ = open_regular_nofollow(
        STATE / "DEPLOYED_RUNTIME_IMAGE",
        max_bytes=512,
        secret_mode=False,
        label="DEPLOYED_RUNTIME_IMAGE",
    )
    image = img_bytes.decode("utf-8", errors="replace").strip()
    if not IMAGE_REF_RE.fullmatch(image):
        fail("DEPLOYED_RUNTIME_IMAGE does not contain a digest-pinned image reference")

    manifests_bytes, _ = open_regular_nofollow(
        STATE / "DEPLOYED_MANIFESTS.json",
        max_bytes=MAX_MANIFEST_BYTES,
        secret_mode=False,
        label="DEPLOYED_MANIFESTS.json",
    )
    try:
        recorded = json.loads(manifests_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("DEPLOYED_MANIFESTS.json is not valid JSON")
    if not isinstance(recorded, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in recorded.items()
    ):
        fail("DEPLOYED_MANIFESTS.json must map seat ids to sha256 digests")
    return sha, image, recorded


def validate_staged_estate(
    estate_seats: list[str], plans_by_seat: dict[str, SeatPlan], image: str
) -> None:
    tmp_parent = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="nvoy-relay-stage-", dir=tmp_parent) as stage_str:
        stage = Path(stage_str)
        os.chmod(stage, 0o755)
        for seat in estate_seats:
            if seat in plans_by_seat:
                content = plans_by_seat[seat].manifest_next
            else:
                content, _ = open_regular_nofollow(
                    ROOT / f"{seat}.json",
                    max_bytes=MAX_MANIFEST_BYTES,
                    secret_mode=False,
                    label=f"{seat} manifest",
                )
            staged_file = stage / f"{seat}.json"
            staged_file.write_bytes(content)
            os.chmod(staged_file, 0o644)
        try:
            result = subprocess.run(
                [
                    DOCKER,
                    "run",
                    "--rm",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--network",
                    "none",
                    "-v",
                    f"{stage}:/etc/nvoy/instances:ro",
                    "--entrypoint",
                    "node",
                    image,
                    "-e",
                    VALIDATE_ESTATE_JS,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=VALIDATE_SECONDS,
            )
        except subprocess.TimeoutExpired:
            fail(f"manifest container validation timed out after {VALIDATE_SECONDS:g}s")
        except OSError:
            fail("cannot execute docker for manifest validation")
        if result.returncode != 0 or not result.stdout.strip().endswith("estate-valid"):
            reason = (result.stderr.strip().splitlines() or ["validation failed"])[-1][:240]
            fail(f"staged manifest validation failed: {reason}")


def verify_compose_matches_candidate(seat: str, deployed_sha: str) -> Path:
    live = ROOT / f"{seat}.compose.yml"
    candidate = STATE / f"candidate-{deployed_sha}" / f"{seat}.compose.yml"
    live_bytes, _ = open_regular_nofollow(
        live, max_bytes=1024 * 1024, secret_mode=False, label=f"{seat} live compose"
    )
    cand_bytes, _ = open_regular_nofollow(
        candidate, max_bytes=1024 * 1024, secret_mode=False, label=f"{seat} candidate compose"
    )
    if live_bytes != cand_bytes:
        fail(f"{seat}: live compose differs from deployed candidate; stop and inspect")
    return live


def run_compose(compose_path: Path, args: list[str], *, capture: bool = False) -> str:
    try:
        res = subprocess.run(
            [DOCKER, "compose", "-f", str(compose_path), *args],
            check=True,
            text=True,
            capture_output=capture,
        )
    except subprocess.CalledProcessError as err:
        detail = ((err.stderr or "") if capture else "").strip().splitlines()
        suffix = f" ({detail[-1][:160]})" if detail else ""
        fail(f"docker compose {' '.join(args[:2])} failed for {compose_path.name}{suffix}")
    except OSError:
        fail("cannot execute docker compose")
    return (res.stdout or "").strip() if capture else ""


def settle() -> None:
    if SETTLE_MS < 0 or SETTLE_MS > 60_000:
        fail("NVOY_SETTLE_MS must be between 0 and 60000")
    if SETTLE_MS > 0:
        time.sleep(SETTLE_MS / 1000.0)


def verify_stack_running(compose_path: Path, shape: dict) -> None:
    running = set(run_compose(compose_path, ["ps", "--status", "running", "--services"], capture=True).split())
    expected = (
        ["watcher", "broker", "adapter"]
        + (["worker"] if shape["worker"] else [])
        + (["harness"] if shape["harness"] else [])
        + (["notifier"] if shape["notifier"] else [])
        + (["door"] if shape["door"] else [])
        + (["recall"] if shape["recall"] else [])
    )
    missing = [svc for svc in expected if svc not in running]
    if missing:
        fail(f"{shape['id']}: services not running after recreate: {', '.join(missing)}")
    init_text = run_compose(compose_path, ["ps", "-a", "--format", "json", "init"], capture=True)
    try:
        rows: list[dict] = []
        for line in filter(None, init_text.splitlines()):
            val = json.loads(line)
            rows.extend(val if isinstance(val, list) else [val])
    except json.JSONDecodeError:
        fail(f"{shape['id']}: init container status was not valid JSON")
    if not rows or any(row.get("State") != "exited" or int(row.get("ExitCode", -1)) != 0 for row in rows):
        fail(f"{shape['id']}: init container did not exit 0")


def write_private_backup(backup_dir: Path, plans: list[SeatPlan]) -> None:
    BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_info = BACKUP_ROOT.lstat()
    if (
        BACKUP_ROOT.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
        or (root_info.st_mode & 0o077) != 0
    ):
        fail("backup root must be a private 0700 directory owned by current user")
    backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    m_dir = backup_dir / "manifests"
    c_dir = backup_dir / "credentials"
    m_dir.mkdir(mode=0o700)
    c_dir.mkdir(mode=0o700)
    for plan in plans:
        if not plan.any_change:
            continue
        atomic_write_nofollow(
            m_dir / plan.manifest_path.name,
            plan.manifest_orig,
            mode=0o600,
            uid=os.geteuid(),
            gid=os.getegid(),
            expected_stat=None,
            temp_stem=plan.manifest_path.name,
            label=f"{plan.seat} manifest backup",
        )
        if plan.bunker_path is not None and plan.bunker_orig is not None:
            atomic_write_nofollow(
                c_dir / f"{plan.seat}--{plan.bunker_path.name}",
                plan.bunker_orig,
                mode=0o600,
                uid=os.geteuid(),
                gid=os.getegid(),
                expected_stat=None,
                temp_stem=plan.bunker_path.name,
                label=f"{plan.seat} credential backup",
            )


def update_deployed_manifests(recorded: dict[str, str], touched: list[SeatPlan]) -> None:
    updated = dict(recorded)
    for plan in touched:
        if plan.manifest_changed:
            updated[plan.seat] = hashlib.sha256(plan.manifest_next).hexdigest()
    payload = (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode("utf-8")
    target = STATE / "DEPLOYED_MANIFESTS.json"
    st = target.lstat()
    atomic_write_nofollow(
        target,
        payload,
        mode=stat.S_IMODE(st.st_mode),
        uid=st.st_uid,
        gid=st.st_gid,
        expected_stat=None,
        temp_stem="DEPLOYED_MANIFESTS.json",
        label="DEPLOYED_MANIFESTS.json",
    )


def apply_changes(
    estate_seats: list[str],
    target_seats: list[str],
    from_relay: str,
    to_relay: str,
) -> dict:
    lock = STATE / ".deploy-lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        fail("nvoy deploy runner is active or its lock is stale; stop and inspect")
    except OSError:
        fail("cannot create .deploy-lock under deploy state directory")

    retain_lock = False
    try:
        deployed_sha, runtime_image, recorded = read_deployed_state()
        plans = build_plans(target_seats, from_relay, to_relay)
        plans_by_seat = {p.seat: p for p in plans}
        touched = [p for p in plans if p.any_change]
        if not touched:
            return format_summary(
                mode="apply",
                from_relay=from_relay,
                to_relay=to_relay,
                deployed_sha=deployed_sha,
                backup_dir=None,
                plans=plans,
                recreated_seats=set(),
            )

        compose_paths: dict[str, Path] = {}
        shapes: dict[str, dict] = {}
        for plan in touched:
            compose_paths[plan.seat] = verify_compose_matches_candidate(plan.seat, deployed_sha)
            shapes[plan.seat] = instance_shape(plan.manifest_obj)

        validate_staged_estate(estate_seats, plans_by_seat, runtime_image)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        backup_dir = BACKUP_ROOT / stamp
        write_private_backup(backup_dir, touched)

        written_bunkers: list[SeatPlan] = []
        written_manifests: list[SeatPlan] = []
        recreated: list[SeatPlan] = []
        try:
            # 1. Write Bunker credentials first so any recreate reads updated URI pointers.
            for plan in touched:
                if plan.signer_changed:
                    assert (
                        plan.bunker_path is not None
                        and plan.bunker_next is not None
                        and plan.bunker_stat is not None
                    )
                    atomic_write_nofollow(
                        plan.bunker_path,
                        plan.bunker_next,
                        mode=0o600,
                        uid=plan.bunker_stat.st_uid,
                        gid=plan.bunker_stat.st_gid,
                        expected_stat=plan.bunker_stat,
                        temp_stem=plan.bunker_path.name,
                        label=f"{plan.seat} bunker credential",
                    )
                    written_bunkers.append(plan)

            # 2. Write manifest JSON files second via hidden non-.json temp names.
            for plan in touched:
                if plan.manifest_changed:
                    atomic_write_nofollow(
                        plan.manifest_path,
                        plan.manifest_next,
                        mode=stat.S_IMODE(plan.manifest_stat.st_mode),
                        uid=plan.manifest_stat.st_uid,
                        gid=plan.manifest_stat.st_gid,
                        expected_stat=plan.manifest_stat,
                        temp_stem=plan.manifest_path.name,
                        label=f"{plan.seat} manifest",
                    )
                    written_manifests.append(plan)

            # 3. Recreate only touched seats (volume-preserving: never `down` or `-v`).
            for plan in touched:
                recreated.append(plan)
                run_compose(
                    compose_paths[plan.seat],
                    ["up", "-d", "--remove-orphans", "--force-recreate"],
                )
                settle()
                verify_stack_running(compose_paths[plan.seat], shapes[plan.seat])

            # 4. Record new manifest digests so nvoy-runtime-deploy.path sees clean convergence.
            update_deployed_manifests(recorded, touched)
        except BaseException as apply_err:
            try:
                for plan in reversed(written_manifests):
                    atomic_write_nofollow(
                        plan.manifest_path,
                        plan.manifest_orig,
                        mode=stat.S_IMODE(plan.manifest_stat.st_mode),
                        uid=plan.manifest_stat.st_uid,
                        gid=plan.manifest_stat.st_gid,
                        expected_stat=None,
                        temp_stem=plan.manifest_path.name,
                        label=f"{plan.seat} manifest rollback",
                    )
                for plan in reversed(written_bunkers):
                    assert (
                        plan.bunker_path is not None
                        and plan.bunker_orig is not None
                        and plan.bunker_stat is not None
                    )
                    atomic_write_nofollow(
                        plan.bunker_path,
                        plan.bunker_orig,
                        mode=0o600,
                        uid=plan.bunker_stat.st_uid,
                        gid=plan.bunker_stat.st_gid,
                        expected_stat=None,
                        temp_stem=plan.bunker_path.name,
                        label=f"{plan.seat} credential rollback",
                    )
                for plan in reversed(recreated):
                    run_compose(
                        compose_paths[plan.seat],
                        ["up", "-d", "--remove-orphans", "--force-recreate"],
                    )
                    settle()
                    verify_stack_running(compose_paths[plan.seat], shapes[plan.seat])
            except BaseException as rb_err:
                retain_lock = True
                detail = str(rb_err) if isinstance(rb_err, SafeError) else rb_err.__class__.__name__
                print(
                    f"replace-instance-relay: UNSAFE: rollback incomplete ({detail}); "
                    f"deploy lock retained at {lock} and backups kept at {backup_dir}",
                    file=sys.stderr,
                )
                if isinstance(apply_err, SafeError):
                    raise
                fail(f"apply failed ({apply_err.__class__.__name__}) and rollback failed")
            msg = str(apply_err) if isinstance(apply_err, SafeError) else apply_err.__class__.__name__
            raise RestoredFailure(
                f"{msg}; restored original files and verified touched stacks (backup at {backup_dir})"
            ) from None

        return format_summary(
            mode="apply",
            from_relay=from_relay,
            to_relay=to_relay,
            deployed_sha=deployed_sha,
            backup_dir=str(backup_dir),
            plans=plans,
            recreated_seats={p.seat for p in recreated},
        )
    finally:
        if not retain_lock:
            shutil.rmtree(lock, ignore_errors=True)


def format_summary(
    *,
    mode: str,
    from_relay: str,
    to_relay: str,
    deployed_sha: str,
    backup_dir: str | None,
    plans: list[SeatPlan],
    recreated_seats: set[str],
) -> dict:
    return {
        "mode": mode,
        "from_relay": from_relay,
        "to_relay": to_relay,
        "deployed_sha": deployed_sha,
        "backup_dir": backup_dir,
        "changed_count": sum(1 for p in plans if p.any_change),
        "seats": [
            {
                "id": p.seat,
                "manifest_changed": p.manifest_changed,
                "signer_changed": p.signer_changed,
                "recreated": p.seat in recreated_seats,
                "manifest_relays_before": p.manifest_before,
                "manifest_relays_after": p.manifest_after,
                "signer_relays_before": p.signer_before,
                "signer_relays_after": p.signer_after,
            }
            for p in plans
        ],
    }


def dry_run(
    estate_seats: list[str],
    target_seats: list[str],
    from_relay: str,
    to_relay: str,
) -> dict:
    deployed_sha, runtime_image, _ = read_deployed_state()
    plans = build_plans(target_seats, from_relay, to_relay)
    if any(p.any_change for p in plans):
        validate_staged_estate(estate_seats, {p.seat: p for p in plans}, runtime_image)
    return format_summary(
        mode="dry-run",
        from_relay=from_relay,
        to_relay=to_relay,
        deployed_sha=deployed_sha,
        backup_dir=None,
        plans=plans,
        recreated_seats=set(),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--instance",
        action="append",
        dest="instances",
        metavar="SEAT",
        help="target one seat (may be repeated, e.g. --instance dj-codex)",
    )
    scope.add_argument(
        "--all",
        action="store_true",
        help="target every seat manifest under /etc/nvoy/instances",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="SEAT",
        help="seat to skip when --all is set (may be repeated)",
    )
    parser.add_argument(
        "--from-relay",
        default="wss://nos.lol",
        help="relay URL to replace (default: wss://nos.lol)",
    )
    parser.add_argument(
        "--to-relay",
        default="wss://relay.nave.pub",
        help="replacement relay URL (default: wss://relay.nave.pub)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write backups, atomically update files, and recreate touched stacks",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        from_relay = validate_relay_url(args.from_relay, "from-relay")
        to_relay = validate_relay_url(args.to_relay, "to-relay")
        if relay_key(from_relay, "from-relay") == relay_key(to_relay, "to-relay"):
            fail("--from-relay and --to-relay must refer to different relays")
        if args.exclude and not args.all:
            fail("--exclude is only valid with --all")

        estate_seats = list_estate_seats()
        estate_set = set(estate_seats)
        if args.all:
            excluded: set[str] = set()
            for raw_ex in args.exclude:
                ex = validate_seat(raw_ex)
                if ex not in estate_set:
                    fail(f"excluded seat {ex} has no manifest in {ROOT}")
                excluded.add(ex)
            target_seats = [s for s in estate_seats if s not in excluded]
            if not target_seats:
                fail("no target seats remain after exclusions")
        else:
            target_seats = []
            seen: set[str] = set()
            for raw_seat in args.instances or []:
                seat = validate_seat(raw_seat)
                if seat not in estate_set:
                    fail(f"seat {seat} has no manifest in {ROOT}")
                if seat not in seen:
                    seen.add(seat)
                    target_seats.append(seat)

        if args.apply:
            summary = apply_changes(estate_seats, target_seats, from_relay, to_relay)
        else:
            summary = dry_run(estate_seats, target_seats, from_relay, to_relay)
        print(json.dumps(summary, indent=2))
        return 0
    except SafeError as err:
        print(f"replace-instance-relay: STOP: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("replace-instance-relay: STOP: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
