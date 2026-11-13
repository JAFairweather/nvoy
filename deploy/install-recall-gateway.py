#!/usr/bin/env python3
"""Install one reviewed nvoy Hive read gateway on the fleet host.

The runtime image renders the units from the manifest. This script installs only
those units, never a key or a reader grant. Run it as root after the key and
trusted host pin have been placed by the operator.
"""

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/etc/nvoy/instances')
KEYS = Path('/etc/nvoy/recall-keys')
PIN = Path('/etc/nvoy/recall-known-hosts')
UNITS = Path('/etc/systemd/system')
IMAGE = re.compile(r'[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z', re.I)
ID = re.compile(r'[a-z0-9][a-z0-9._-]{1,63}\Z')
USER = re.compile(r'[a-z_][a-z0-9_-]*\Z')
RENDER_UID = 65532
RENDER_GID = 65532


def fail(message):
    raise RuntimeError(message)


def regular(path, label):
    if path.is_symlink() or not path.is_file():
        fail(f'{label} must be a regular non-symlink file')
    return path.stat()


def command(*args):
    subprocess.run(args, check=True, timeout=45)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance', required=True)
    parser.add_argument('--image', required=True, help='successful runtime image pinned by digest')
    parser.add_argument('--check', action='store_true', help='validate and render without changing the host')
    args = parser.parse_args()
    if not ID.fullmatch(args.instance) or not IMAGE.fullmatch(args.image):
        fail('instance or immutable image reference is invalid')
    if os.geteuid() != 0:
        fail('installer checks and installation require root')
    manifest_path = ROOT / f'{args.instance}.json'
    regular(manifest_path, 'manifest')
    raw = json.loads(manifest_path.read_text())
    recall = raw.get('may_recall') or {}
    user = raw.get('service_user')
    gid = recall.get('gateway_gid')
    if raw.get('id') != args.instance or not isinstance(user, str) or not USER.fullmatch(user) or \
            recall.get('read') != {'socket': '/run/nvoy-recall-gw/socket'} or \
            not isinstance(gid, int) or isinstance(gid, bool) or gid < 1:
        fail('manifest does not name the fixed per-instance gateway, group and broker user')
    owner = pwd.getpwnam(user)
    if owner.pw_uid != raw.get('broker_uid') or owner.pw_uid == 0:
        fail('service_user must be the non-root broker_uid')
    group_name = f'nvoy-recall-{args.instance}'
    try:
        group = grp.getgrnam(group_name)
        if group.gr_gid != gid or group.gr_mem:
            fail('existing recall group has the wrong GID or host members')
    except KeyError:
        try:
            grp.getgrgid(gid)
        except KeyError:
            group = None
        else:
            fail('gateway_gid is already assigned to another group')
    if any(account.pw_gid == gid for account in pwd.getpwall()):
        fail('gateway_gid is a host account primary group')
    key = KEYS / args.instance
    key_stat = regular(key, 'read key')
    if stat.S_IMODE(key_stat.st_mode) != 0o600 or key_stat.st_uid not in (0, owner.pw_uid):
        fail('read key has unsafe mode or owner')
    key_dir = KEYS.stat()
    if KEYS.is_symlink() or not stat.S_ISDIR(key_dir.st_mode) or key_dir.st_uid != 0 or key_dir.st_mode & 0o022:
        fail('read key directory is unsafe')
    pin_stat = regular(PIN, 'trusted host pin')
    if pin_stat.st_uid != 0 or stat.S_IMODE(pin_stat.st_mode) != 0o644 or pin_stat.st_size == 0:
        fail('trusted host pin is missing or writable')
    # The image contains the same renderer as the release under review. Nothing
    # secret is mounted: only manifest metadata and the empty output directory.
    with tempfile.TemporaryDirectory(prefix='nvoy-recall-') as stage_name:
        stage = Path(stage_name)
        # TemporaryDirectory is root-owned 0700. Give only the image's fixed
        # renderer identity access to this disposable output mount.
        os.chown(stage, RENDER_UID, RENDER_GID)
        command('docker', 'run', '--rm', '--read-only', '--network', 'none',
                '--tmpfs', '/tmp:mode=1777', '--user', f'{RENDER_UID}:{RENDER_GID}',
                '-e', f'NVOY_INSTANCE_ROOT={ROOT}',
                '-v', f'{ROOT}:{ROOT}:ro', '-v', f'{stage}:{stage}:rw', args.image,
                'node', 'mcp/tools/instance-unit.mjs', 'render', '--instance', args.instance,
                '--image', args.image, '--out-dir', str(stage))
        names = (f'nvoy-recall-gw-{args.instance}.socket', f'nvoy-recall-gw-{args.instance}@.service')
        for name in names:
            generated = stage / name
            regular(generated, 'generated unit')
            installed = UNITS / name
            if installed.exists() and (installed.is_symlink() or installed.read_bytes() != generated.read_bytes()):
                fail(f'{name} already exists with different content; review an update separately')
        if args.check:
            print(f'recall gateway {args.instance}: render and host prerequisites verified; no change')
            return
        if group is None:
            command('groupadd', '--system', '--gid', str(gid), group_name)
        # A root-owned 0711 parent permits traversal to exactly the broker-owned
        # 0600 key; it does not list keys or make any other instance key readable.
        os.chmod(KEYS, 0o711)
        os.chown(key, owner.pw_uid, owner.pw_gid)
        for name in names:
            installed = UNITS / name
            if not installed.exists():
                temporary = UNITS / f'.{name}.tmp-{os.getpid()}'
                shutil.copyfile(stage / name, temporary)
                os.chmod(temporary, 0o644)
                os.replace(temporary, installed)
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', names[0])
        command('systemctl', 'is-active', '--quiet', names[0])
        path = Path(f'/run/nvoy-recall-gw/{args.instance}/socket')
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner.pw_uid or \
                info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o660:
            fail('live socket ownership or mode does not match the manifest')
        print(f'recall gateway {args.instance}: socket active with dedicated group; reader grant still requires James')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(f'install-recall-gateway: {error}', file=sys.stderr)
        sys.exit(1)
