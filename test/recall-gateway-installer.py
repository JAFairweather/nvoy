#!/usr/bin/env python3
"""Exercise the host installer's renderer handoff for check and install."""

import contextlib
import importlib.util
import io
from pathlib import Path
import os
import pwd
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
import json


SCRIPT = Path(__file__).resolve().parents[1] / 'deploy/install-recall-gateway.py'
SPEC = importlib.util.spec_from_file_location('recall_installer', SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
IMAGE = 'example.test/nvoy-runtime@sha256:' + 'a' * 64
INSTANCE = 'recall-test'
UID, GID = 12345, 54321


class RecallInstallerTest(unittest.TestCase):
    def test_container_render_for_check_and_install(self):
        for check in (True, False):
            with self.subTest(check=check), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                manifests = root / 'instances'
                keys = root / 'keys'
                units = root / 'units'
                for directory in (manifests, keys, units):
                    directory.mkdir()
                manifest = manifests / f'{INSTANCE}.json'
                manifest.write_text(json.dumps({
                    'id': INSTANCE, 'service_user': 'recall_test',
                    'broker_uid': UID, 'may_recall': {
                        'read': {'socket': '/run/nvoy-recall-gw/socket'},
                        'gateway_gid': GID,
                    },
                }))
                key = keys / INSTANCE
                key.write_text('fixture only')
                pin = root / 'known_hosts'
                pin.write_text('fixture only')
                original_regular = installer.regular
                original_stat = Path.stat
                original_lstat = Path.lstat
                chowns = []
                docker_calls = []

                def fake_regular(path, label):
                    if path == key:
                        return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=UID)
                    if path == pin:
                        return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644,
                                                     st_uid=0, st_size=12)
                    return original_regular(path, label)

                def fake_stat(path, *args, **kwargs):
                    if path == keys:
                        return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
                    return original_stat(path, *args, **kwargs)

                def fake_lstat(path, *args, **kwargs):
                    if str(path) == f'/run/nvoy-recall-gw/{INSTANCE}/socket':
                        return types.SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660,
                                                     st_uid=UID, st_gid=GID)
                    return original_lstat(path, *args, **kwargs)

                def fake_command(*args):
                    if args[0] != 'docker':
                        return
                    docker_calls.append(args)
                    stage = Path(args[args.index('--out-dir') + 1])
                    self.assertIn((stage, installer.RENDER_UID, installer.RENDER_GID), chowns)
                    self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                    self.assertEqual(args[args.index('--user') + 1], '65532:65532')
                    self.assertEqual(args[args.index('-v', args.index('-v') + 1) + 1],
                                     f'{stage}:{stage}:rw')
                    for name in (f'nvoy-recall-gw-{INSTANCE}.socket',
                                 f'nvoy-recall-gw-{INSTANCE}@.service'):
                        (stage / name).write_text(f'generated {name}\n')

                def fake_chown(path, uid, gid):
                    chowns.append((Path(path), uid, gid))

                owner = types.SimpleNamespace(pw_uid=UID, pw_gid=GID)
                group = types.SimpleNamespace(gr_gid=GID, gr_mem=[])
                argv = [str(SCRIPT), '--instance', INSTANCE, '--image', IMAGE]
                if check:
                    argv.append('--check')
                with mock.patch.object(installer, 'ROOT', manifests), \
                     mock.patch.object(installer, 'KEYS', keys), \
                     mock.patch.object(installer, 'PIN', pin), \
                     mock.patch.object(installer, 'UNITS', units), \
                     mock.patch.object(installer, 'regular', side_effect=fake_regular), \
                     mock.patch.object(installer, 'command', side_effect=fake_command), \
                     mock.patch.object(installer.os, 'geteuid', return_value=0), \
                     mock.patch.object(installer.os, 'chown', side_effect=fake_chown), \
                     mock.patch.object(installer.pwd, 'getpwnam', return_value=owner), \
                     mock.patch.object(installer.pwd, 'getpwall', return_value=[]), \
                     mock.patch.object(installer.grp, 'getgrnam', return_value=group), \
                     mock.patch.object(Path, 'stat', fake_stat), \
                     mock.patch.object(Path, 'lstat', fake_lstat), \
                     mock.patch.object(sys, 'argv', argv), \
                     contextlib.redirect_stdout(io.StringIO()):
                    installer.main()
                self.assertEqual(len(docker_calls), 1)
                self.assertEqual(len(list(units.iterdir())), 0 if check else 2)


if __name__ == '__main__':
    unittest.main()
