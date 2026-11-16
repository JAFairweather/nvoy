#!/usr/bin/env python3
"""Run the real installer --check render against a local runtime image (CI only)."""

import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
from unittest import mock


SCRIPT = Path(__file__).with_name('install-recall-gateway.py')
SPEC = importlib.util.spec_from_file_location('recall_installer', SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
IMAGE_REF = 'example.test/nvoy-runtime@sha256:' + 'a' * 64


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0:
        raise SystemExit('usage as root: test-recall-gateway-container.py <local-runtime-image-tag>')
    local_image = sys.argv[1]
    owner = pwd.getpwnam('nobody')
    instance = 'recall-ci'
    with tempfile.TemporaryDirectory(prefix='nvoy-recall-ci-') as root_name:
        root = Path(root_name)
        os.chmod(root, 0o755)  # container may traverse to the public manifest
        manifests = root / 'instances'
        keys = root / 'keys'
        units = root / 'units'
        for directory in (manifests, keys, units):
            directory.mkdir()
        key = keys / instance
        key.write_text('fixture only\n')
        os.chmod(key, 0o600)
        pin = root / 'known_hosts'
        pin.write_text('fixture only\n')
        os.chmod(pin, 0o644)
        manifest = {
            'version': 1, 'id': instance, 'pubkey': '1' * 64,
            'state_dir': f'/var/lib/nvoy/{instance}',
            'runtime_dir': f'/run/nvoy/{instance}',
            'spool_dir': f'/var/lib/nvoy-watcher/{instance}',
            'bunker_uri_ref': f'/etc/nvoy/credentials/{instance}.bunker',
            'bunker_client_ref': f'/etc/nvoy/credentials/{instance}.client',
            'broker_adapter_gid': 41001, 'worker_handoff_gid': 41002,
            'watcher_uid': 41011, 'broker_uid': owner.pw_uid,
            'adapter_uid': 41013, 'worker_uid': 41014,
            'service_user': 'nobody', 'delivery_mode': 'notify_only',
            'worker_enabled': False, 'grantors': ['4' * 64],
            'relays': ['wss://nos.lol'],
            'may_recall': {'read': {'socket': '/run/nvoy-recall-gw/socket'},
                           'gateway_gid': 54123},
        }
        (manifests / f'{instance}.json').write_text(json.dumps(manifest))
        original_command = installer.command
        docker_calls = []

        def command(*args):
            if args[:2] == ('docker', 'run'):
                docker_calls.append(args)
                args = list(args)
                args[args.index(IMAGE_REF)] = local_image
            original_command(*args)

        argv = [str(SCRIPT), '--instance', instance, '--image', IMAGE_REF, '--check']
        with mock.patch.object(installer, 'ROOT', manifests), \
             mock.patch.object(installer, 'KEYS', keys), \
             mock.patch.object(installer, 'PIN', pin), \
             mock.patch.object(installer, 'UNITS', units), \
             mock.patch.object(installer, 'command', side_effect=command), \
             mock.patch.object(sys, 'argv', argv):
            installer.main()
        if len(docker_calls) != 1 or list(units.iterdir()):
            raise RuntimeError('--check must render in one container without installing units')
        print('recall gateway installer container --check: passed')


if __name__ == '__main__':
    main()
