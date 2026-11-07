#!/usr/bin/env python3
"""Exercise the updater in private temporary fixtures; no system service is called."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).absolute().parents[1] / 'update.sh'

def load_updater(bundle):
    code = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
    marker = '\ntry:\n    validate_package()\n    validate_installation()\n'
    if code.count(marker) != 1:
        raise AssertionError('Unexpected updater entry point')
    namespace = {'__name__': 'updater_review'}
    with patch.object(sys, 'argv', ['updater_review', '--check', str(bundle)]):
        exec(compile(code.split(marker)[0], str(SCRIPT), 'exec'), namespace)
    return namespace

class UpdateChecks(unittest.TestCase):
    def setUp(self):
        # The production updater deliberately rejects world-writable parents,
        # including /tmp. Use the private workspace rather than weakening it.
        self.temporary = tempfile.TemporaryDirectory(prefix='koto-update-fixture-', dir=SCRIPT.parents[3])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'bundle'; self.bundle.mkdir(mode=0o700)
        self.namespace = load_updater(self.bundle)
        self.uid = os.getuid()
        self.actual_regular = self.namespace['regular']
        self.actual_directory = self.namespace['directory']
        # Fixtures represent root-managed package paths while remaining owned
        # by the test runner. Ownership/permission checks themselves remain real.
        self.namespace['regular'] = lambda path, owner=0, **kwargs: self.actual_regular(path, self.uid, **kwargs)
        self.namespace['directory'] = lambda path, owner=0, **kwargs: self.actual_directory(path, self.uid, **kwargs)
        self.create_package()

    def create_package(self):
        elf = bytearray(64); elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', elf, 16, 3); struct.pack_into('<H', elf, 18, 62)
        self.files = {'bin/messenger-relay': bytes(elf) + b'NEW RELAY',
                      'bin/queue_ticket': bytes(elf) + b'NEW TICKET',
                      'issue-ticket.sh': b'NEW HELPER', 'update.sh': SCRIPT.read_bytes(),
                      'docs/ACCOUNTS.md': b'Account documentation.',
                      'BUILD_INFO.json': json.dumps({'release_version': '0.2.10', 'source_working_tree_clean': True, 'source_commit': 'a' * 40}).encode(),
                      'README.txt': b'UPDATE', 'docs/RELAY_DEPLOYMENT.md': b'INSTRUCTIONS'}
        for name, data in self.files.items():
            path = self.bundle / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(0o644)
        self.manifest()

    def manifest(self):
        (self.bundle / 'SHA256SUMS').write_text(''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in sorted(self.files.items())))
        (self.bundle / 'SHA256SUMS').chmod(0o644)

    def installed_fixture(self):
        self.install = self.root / 'installed'; (self.install / 'bin').mkdir(parents=True)
        self.replacements = {}
        self.originals = {}
        for name in ('bin/messenger-relay', 'bin/queue_ticket', 'issue-ticket.sh'):
            path = self.install / name; data = ('OLD ' + name).encode()
            path.write_bytes(data); path.chmod(0o755)
            self.replacements[name] = path; self.originals[name] = data
        self.database = self.root / 'state' / 'relay.sqlite'; self.database.parent.mkdir(mode=0o700)
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE messages(value TEXT)'); db.execute("INSERT INTO messages VALUES('before')")
        self.database.chmod(0o600)
        self.database_backup = self.database.parent / 'backups' / 'before.sqlite'
        self.database_backup.parent.mkdir(mode=0o700)
        with sqlite3.connect(self.database) as source, sqlite3.connect(self.database_backup) as destination:
            source.backup(destination)
        self.database_backup.chmod(0o600)
        self.rollback_base = self.root / 'rollback'
        self.proxy = self.root / 'Caddyfile'; self.proxy.write_text('UNCHANGED SHARED OTHER_SERVICE CONFIG')
        self.environment = self.root / 'relay.env'; self.environment.write_text('UNCHANGED PRIVATE ENV')
        self.lockfile = self.root / 'update.lock'
        paths = {'/var/backups/kotopizdelka-relay-update': self.rollback_base}
        self.namespace['Path'] = lambda value: Path(paths.get(str(value), value))
        operating_system = types.SimpleNamespace(**vars(os))
        operating_system.open = lambda path, *args, **kwargs: os.open(self.lockfile if str(path) == '/run/kotopizdelka-relay-update.lock' else path, *args, **kwargs)
        # The lock is the one fixed root-owned inode in this otherwise unprivileged fixture.
        operating_system.fstat = lambda descriptor: types.SimpleNamespace(st_uid=0, st_mode=os.fstat(descriptor).st_mode)
        self.namespace['os'] = operating_system
        self.namespace['REPLACEMENTS'] = self.replacements
        self.namespace['DATABASE'] = self.database
        self.namespace['backup_database'] = lambda: self.database_backup
        self.namespace['validate_installation'] = lambda: types.SimpleNamespace(pw_uid=self.uid)
        self.namespace['wait_healthy'] = lambda: None
        self.commands = []
        self.namespace['command'] = self.fake_command

    def fake_command(self, arguments, timeout=15):
        self.commands.append(arguments)
        return ''

    def assert_preserved_scope(self):
        self.assertEqual(self.proxy.read_text(), 'UNCHANGED SHARED OTHER_SERVICE CONFIG')
        self.assertEqual(self.environment.read_text(), 'UNCHANGED PRIVATE ENV')
        for arguments in self.commands:
            self.assertIn(arguments, [['systemctl', 'restart', 'kotopizdelka-relay.service'],
                                      ['systemctl', 'reset-failed', 'kotopizdelka-relay.service']])

    def test_complete_package_validates_without_executing_binary_or_system_command(self):
        self.namespace['command'] = lambda *arguments, **kwargs: self.fail('Unexpected command during package validation')
        self.namespace['validate_package']()

    def test_modified_file_unlisted_file_symlink_and_proxy_file_are_rejected(self):
        cases = ['modified', 'unlisted', 'symlink', 'proxy']
        for case in cases:
            with self.subTest(case=case):
                if case == 'modified':
                    path = self.bundle / 'README.txt'; path.write_bytes(b'ALTERED')
                elif case == 'unlisted':
                    path = self.bundle / 'extra'; path.write_bytes(b'EXTRA')
                elif case == 'symlink':
                    path = self.bundle / 'extra'; path.symlink_to(self.bundle / 'README.txt')
                else:
                    path = self.bundle / 'Caddyfile'; path.write_bytes(b'PROXY')
                    self.files['Caddyfile'] = b'PROXY'; self.manifest()
                with self.assertRaises(RuntimeError):
                    self.namespace['validate_package']()
                path.unlink()
                if case == 'modified': path.write_bytes(self.files['README.txt']); path.chmod(0o644)
                if case == 'proxy': del self.files['Caddyfile']; self.manifest()

    def test_unsafe_file_permissions_and_symlink_parent_are_rejected(self):
        private = self.root / 'private'; private.write_bytes(b'DATA'); private.chmod(0o644)
        with self.assertRaises(RuntimeError): self.actual_regular(private, self.uid, private=True)
        private.chmod(0o600)
        self.actual_regular(private, self.uid, private=True)
        linked = self.root / 'linked'; linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RuntimeError): self.actual_regular(linked / 'private', self.uid, private=True)

    def test_success_atomic_replacement_retains_private_old_programs_and_only_restarts_native(self):
        self.installed_fixture()
        self.namespace['update']()
        for name, path in self.replacements.items():
            self.assertEqual(path.read_bytes(), self.files[name])
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        folders = list(self.rollback_base.iterdir()); self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0].stat().st_mode & 0o777, 0o700)
        for name, original in self.originals.items():
            old = folders[0] / name
            self.assertEqual(old.read_bytes(), original)
            self.assertEqual(old.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.commands), 1)
        self.assert_preserved_scope()

    def test_failed_start_restores_programs_and_keeps_new_database_rows_and_additive_migration(self):
        self.installed_fixture()
        def failure_then_success(arguments, timeout=15):
            self.commands.append(arguments)
            if len(self.commands) == 1:
                with sqlite3.connect(self.database) as db:
                    db.execute('ALTER TABLE messages ADD COLUMN can_invite INTEGER DEFAULT 0')
                    db.execute("INSERT INTO messages(value) VALUES('after-backup')")
                raise RuntimeError('Injected native startup failure')
            return ''
        self.namespace['command'] = failure_then_success
        with self.assertRaisesRegex(RuntimeError, 'previous native relay was restored'):
            self.namespace['update']()
        for name, path in self.replacements.items(): self.assertEqual(path.read_bytes(), self.originals[name])
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute('SELECT value,can_invite FROM messages').fetchall(), [('before', 0), ('after-backup', 0)])
        self.assertEqual(self.commands, [['systemctl', 'restart', 'kotopizdelka-relay.service'],
                                        ['systemctl', 'reset-failed', 'kotopizdelka-relay.service'],
                                        ['systemctl', 'restart', 'kotopizdelka-relay.service']])
        self.assert_preserved_scope()

    def test_failure_during_second_replace_restores_all_original_files(self):
        self.installed_fixture()
        replace = self.namespace['atomic_replace']; calls = 0
        def fail_second(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('Injected rename failure')
            replace(source, destination)
        self.namespace['atomic_replace'] = fail_second
        with self.assertRaisesRegex(RuntimeError, 'previous native relay was restored'):
            self.namespace['update']()
        for name, path in self.replacements.items(): self.assertEqual(path.read_bytes(), self.originals[name])
        self.assertEqual(self.commands, [['systemctl', 'reset-failed', 'kotopizdelka-relay.service'],
                                        ['systemctl', 'restart', 'kotopizdelka-relay.service']])
        self.assert_preserved_scope()

    def test_readiness_polls_activating_then_active_instead_of_failing_early(self):
        states = iter(['activating', 'active'])
        self.namespace['property_value'] = lambda name: next(states)
        self.namespace['health'] = lambda: True
        clock = types.SimpleNamespace(monotonic=lambda: 100, sleep=lambda duration: None)
        self.namespace['time'] = clock
        self.namespace['wait_healthy']()

if __name__ == '__main__':
    unittest.main()
