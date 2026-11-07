import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'relay-backup.py'
spec = importlib.util.spec_from_file_location('relay_backup', MODULE)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Backups(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.owner = os.getuid()
        self.store = self.root / 'backups'
        self.store.mkdir(mode=0o700)
        self.sources = {}
        for name in b.LIMITS:
            p = self.root / 'installed' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            if name != 'relay.sqlite':
                p.write_bytes(b'PRIVATE-TEST-FIXTURE-' + name.encode())
                p.chmod(0o600)
            self.sources[name] = p
        self.live = sqlite3.connect(self.sources['relay.sqlite'])
        self.live.execute('PRAGMA journal_mode=WAL')
        self.live.execute('PRAGMA wal_autocheckpoint=0')
        for name in b.TABLES:
            self.live.execute('CREATE TABLE ' + name + '(value TEXT)')
        self.live.execute("INSERT INTO accounts VALUES('account-in-live-wal')")
        self.live.execute("INSERT INTO messages VALUES('encrypted-envelope-in-live-wal')")
        self.live.commit()
        self.sources['relay.sqlite'].chmod(0o600)
        Path(str(self.sources['relay.sqlite']) + '-wal').chmod(0o600)
        self.lock = self.root / 'updater.lock'
        self.lock.touch(mode=0o600)
        self.lock.chmod(0o600)

    def tearDown(self):
        self.live.close()
        self.temporary.cleanup()

    def create(self):
        return b.create(self.store, self.sources, self.owner, self.owner, self.lock)

    def repack(self, path, edit):
        contents = {}
        with tarfile.open(path) as source:
            for item in source:
                contents[item.name] = source.extractfile(item).read()
        edit(contents)
        target = self.root / 'changed.tar.gz'
        with tarfile.open(target, 'w:gz') as tar:
            for name, data in contents.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        target.chmod(0o600)
        return target

    def test_live_wal_is_restored_and_original_is_unchanged(self):
        archive = self.create()
        self.assertTrue(b.NAME.fullmatch(archive.name))
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        destination = self.root / 'recovered'
        b.stage_restore(archive, destination, self.owner)
        with sqlite3.connect(destination / 'relay.sqlite') as db:
            self.assertEqual(db.execute('SELECT value FROM accounts').fetchall(), [('account-in-live-wal',)])
            self.assertEqual(db.execute('SELECT value FROM messages').fetchall(), [('encrypted-envelope-in-live-wal',)])
        self.assertEqual((destination / 'relay.env').read_bytes(), self.sources['relay.env'].read_bytes())
        self.live.execute("INSERT INTO messages VALUES('after-snapshot')")
        self.live.commit()
        with sqlite3.connect(destination / 'relay.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
        self.assertEqual(self.live.execute('SELECT count(*) FROM messages').fetchone()[0], 2)
        info = b.latest(self.store, self.owner)
        self.assertEqual(info['sha256'], b.digest(archive))
        self.assertEqual(set(info), {'name', 'bytes', 'sha256'})

    def test_changed_service_database_layout_is_rejected(self):
        values = {'User': 'kotopizdelka-relay', 'WorkingDirectory': '/var/lib/kotopizdelka-relay',
                  'Environment': 'RELAY_DATABASE=/other/database.sqlite'}
        with patch.object(b.subprocess, 'check_output', side_effect=lambda args, **kw: values[args[3].split('=', 1)[1]]):
            self.assertRaises(b.BackupError, b.check_service_layout)

    def test_restore_refuses_existing_destination(self):
        archive = self.create()
        self.assertRaises(b.BackupError, b.stage_restore, archive, self.store, self.owner)

    def test_checksum_corruption_is_rejected(self):
        changed = self.repack(self.create(), lambda data: data.__setitem__('relay.env', b'TAMPERED'))
        self.assertRaises(b.BackupError, b.verify, changed, self.owner)

    def test_database_corruption_even_with_updated_manifest_is_rejected(self):
        def damage(data):
            data['relay.sqlite'] = b'not a database'
            m = json.loads(data['MANIFEST.json'])
            m['files']['relay.sqlite'] = {'bytes': len(data['relay.sqlite']), 'sha256': hashlib.sha256(data['relay.sqlite']).hexdigest()}
            data['MANIFEST.json'] = json.dumps(m).encode()
        changed = self.repack(self.create(), damage)
        self.assertRaises(sqlite3.DatabaseError, b.verify, changed, self.owner)

    def test_traversal_member_is_rejected_without_writes(self):
        changed = self.repack(self.create(), lambda data: data.__setitem__('../escaped', b'NO'))
        self.assertRaises(b.BackupError, b.verify, changed, self.owner)
        self.assertFalse((self.root / 'escaped').exists())

    def test_links_and_duplicate_members_are_rejected(self):
        for kind in ['link', 'duplicate']:
            p = self.root / (kind + '.tar.gz')
            with tarfile.open(p, 'w:gz') as tar:
                info = tarfile.TarInfo('relay.env')
                if kind == 'link':
                    info.type = tarfile.SYMTYPE; info.linkname = '/etc/passwd'; tar.addfile(info)
                else:
                    info.size = 1
                    tar.addfile(info, io.BytesIO(b'A')); tar.addfile(info, io.BytesIO(b'B'))
            p.chmod(0o600)
            self.assertRaises(b.BackupError, b.verify, p, self.owner)

    def test_symlink_archive_and_public_archive_are_rejected(self):
        archive = self.create()
        link = self.root / 'link'
        link.symlink_to(archive)
        self.assertRaises(b.BackupError, b.verify, link, self.owner)
        archive.chmod(0o644)
        self.assertRaises(b.BackupError, b.verify, archive, self.owner)

    def test_update_or_backup_in_progress_prevents_new_snapshot(self):
        with b.lock(self.lock, True, self.owner):
            self.assertRaises(b.BackupError, self.create)
        with b.lock(self.store / '.backup.lock', True, self.owner, create=True):
            self.assertRaises(b.BackupError, self.create)
        self.assertEqual(list(self.store.glob('*.tar.gz')), [])

    def test_failed_verification_keeps_all_old_backups(self):
        old = self.create()
        with patch.object(b, 'verify', side_effect=b.BackupError('simulated verify failure')):
            self.assertRaises(b.BackupError, self.create)
        self.assertEqual(list(self.store.glob('*.tar.gz')), [old])
        self.assertEqual(list(self.store.glob('.pending-*')), [])
        self.assertEqual(list(self.store.glob('.snapshot-*')), [])

    def test_interrupted_private_staging_is_cleaned_on_next_run(self):
        pending = self.store / ('.pending-' + 'a' * 32)
        pending.write_bytes(b'UNPUBLISHED'); pending.chmod(0o600)
        stage = self.store / '.snapshot-abcdefgh'; stage.mkdir(mode=0o700)
        (stage / 'relay.env').write_bytes(b'PRIVATE-ABANDONED')
        archive = self.create()
        self.assertTrue(archive.exists())
        self.assertFalse(pending.exists())
        self.assertFalse(stage.exists())

    def test_low_space_keeps_old_backups(self):
        old = self.create()
        with patch.object(b.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
            self.assertRaises(b.BackupError, self.create)
        self.assertEqual(list(self.store.glob('*.tar.gz')), [old])

    def test_verification_also_reserves_free_disk_space(self):
        archive = self.create()
        with patch.object(b.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
            self.assertRaises(b.BackupError, b.verify, archive, self.owner)
        self.assertTrue(archive.exists())

    def test_retention_keeps_recent_hourly_and_last_daily(self):
        for day in range(1, 29):
            for hour in range(24):
                p = self.store / f'relay-202609{day:02d}T{hour:02d}0000Z-aaaaaaaaaaaa.tar.gz'
                p.touch(mode=0o600)
        sentinel = self.store / 'manual-backup.keep'
        sentinel.touch()
        b.retention(self.store, self.owner)
        remaining = list(self.store.glob('*.tar.gz'))
        self.assertEqual(len(remaining), 60)  # 48 hourly plus 12 additional daily snapshots.
        self.assertTrue(sentinel.exists())
        self.assertTrue(any('20260915' in p.name for p in remaining))
        self.assertFalse(any('20260914' in p.name for p in remaining))


if __name__ == '__main__':
    unittest.main()
