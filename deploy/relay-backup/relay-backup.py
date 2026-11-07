#!/usr/bin/env python3
"""Private relay backups. Never restore over the running service or manage Caddy."""
import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import shlex
import subprocess
import sqlite3
import stat
import sys
import tarfile
import tempfile
import time
import uuid

NAME = re.compile(r'relay-(\d{8}T\d{6}Z)-[0-9a-f]{12}\.tar\.gz\Z')
TABLES = {'queues', 'messages', 'queue_tickets', 'accounts', 'account_sessions',
          'account_requests', 'account_link_tickets'}
LIMITS = {'relay.sqlite': 2 * 1024**3, 'relay.env': 65536,
          'bin/messenger-relay': 128 * 1024**2, 'bin/queue_ticket': 128 * 1024**2,
          'issue-ticket.sh': 65536, 'kotopizdelka-relay.service': 65536}
ROOT = Path('/var/backups/kotopizdelka-relay')
UPDATE_LOCK = Path('/run/kotopizdelka-relay-update.lock')


class BackupError(Exception):
    pass


def require(value, message):
    if not value:
        raise BackupError(message)


def regular(path, owners, private=False):
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'Symlink paths are not permitted.')
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid in owners and not s.st_mode & 0o022,
            'Unsafe file type, owner or writable permissions.')
    require(not private or not s.st_mode & 0o077, 'Private file permissions are too broad.')
    return s


def private_dir(path, owner):
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'Symlink directories are not permitted.')
    s = path.stat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == owner and stat.S_IMODE(s.st_mode) == 0o700,
            'Expected a private directory with mode 0700.')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def connect_readonly(path):
    return sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=5)


def check_db(db):
    require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'SQLite integrity check failed.')
    require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'SQLite foreign key check failed.')
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    require(TABLES <= tables, 'The database does not contain the expected relay/account schema.')
    return {name: db.execute('SELECT count(*) FROM ' + name).fetchone()[0] for name in sorted(TABLES)}


def snapshot(source, target):
    deadline = time.monotonic() + 90

    def progress(_status, _remaining, _total):
        require(time.monotonic() < deadline, 'SQLite backup deadline exceeded.')
        require(shutil.disk_usage(target.parent).free >= 256 * 1024**2, 'Free disk reserve reached; snapshot aborted.')

    with closing(connect_readonly(source)) as src, closing(sqlite3.connect(target)) as dest:
        src.backup(dest, pages=256, progress=progress, sleep=0.05)
        check_db(dest)
    target.chmod(0o600)


@contextmanager
def lock(path, exclusive, owner, create=False):
    descriptor = os.open(path, (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY) | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+b' if create else 'rb') as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == owner and not s.st_mode & 0o077,
                'Unsafe lock file.')
        try:
            fcntl.flock(stream, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError('Backup or native relay update is already running; retry later.') from None
        yield


def check_service_layout():
    def prop(name):
        return subprocess.check_output(['systemctl', 'show', 'kotopizdelka-relay.service',
                                        '--property=' + name, '--value'],
                                       text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
    require(prop('User') == 'kotopizdelka-relay' and
            prop('WorkingDirectory') == '/var/lib/kotopizdelka-relay',
            'The relay uses an unexpected service account or state directory.')
    require('RELAY_DATABASE=/var/lib/kotopizdelka-relay/relay.sqlite' in shlex.split(prop('Environment')),
            'The service database path differs from the backup layout.')
    require(prop('EnvironmentFiles') == '/etc/kotopizdelka-relay/relay.env (ignore_errors=no)',
            'The service uses an unexpected environment file.')
    require('path=/opt/kotopizdelka-relay/bin/messenger-relay ;' in prop('ExecStart'),
            'The service uses an unexpected executable.')
    environment_file = Path('/etc/kotopizdelka-relay/relay.env')
    require(regular(environment_file, {0}, private=True).st_size <= LIMITS['relay.env'],
            'The environment file exceeds the supported size limit.')
    environment = environment_file.read_text()
    require(not re.search(r'^\s*RELAY_DATABASE\s*=', environment, re.MULTILINE),
            'A relay.env database override requires a matching backup configuration.')


def installed_sources():
    return {'relay.sqlite': Path('/var/lib/kotopizdelka-relay/relay.sqlite'),
            'relay.env': Path('/etc/kotopizdelka-relay/relay.env'),
            'bin/messenger-relay': Path('/opt/kotopizdelka-relay/bin/messenger-relay'),
            'bin/queue_ticket': Path('/opt/kotopizdelka-relay/bin/queue_ticket'),
            'issue-ticket.sh': Path('/opt/kotopizdelka-relay/issue-ticket.sh'),
            'kotopizdelka-relay.service': Path('/etc/systemd/system/kotopizdelka-relay.service')}


@contextmanager
def unpack(archive, owner):
    s = regular(archive, {owner}, private=True)
    require(s.st_size <= sum(LIMITS.values()), 'Archive exceeds the supported size limit.')
    with tempfile.TemporaryDirectory(prefix='koto-backup-verify-') as directory:
        work = Path(directory)
        with tarfile.open(archive, 'r:gz') as tar:
            names = set()
            for item in tar:
                require(item.name in set(LIMITS) | {'MANIFEST.json'} and item.name not in names,
                        'Unexpected or duplicate archive member.')
                require(item.isfile() and 0 <= item.size <= LIMITS.get(item.name, 512 * 1024),
                        'Unsafe archive member type or size.')
                names.add(item.name)
                require(shutil.disk_usage(work).free >= item.size + 256 * 1024**2,
                        'Insufficient free space to verify this archive safely.')
                target = work / item.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                # Do not use extract/extractall: reject links and never trust archived paths/modes.
                with tar.extractfile(item) as source, target.open('xb') as dest:
                    remaining = item.size
                    while remaining:
                        data = source.read(min(remaining, 1024 * 1024))
                        require(bool(data), 'Truncated archive member.')
                        require(shutil.disk_usage(work).free >= len(data) + 256 * 1024**2,
                                'Free disk reserve reached during archive verification.')
                        dest.write(data)
                        remaining -= len(data)
                target.chmod(0o600)
        require(names == set(LIMITS) | {'MANIFEST.json'}, 'Incomplete recovery archive.')
        manifest = json.loads((work / 'MANIFEST.json').read_text())
        require(manifest.get('format') == 1 and set(manifest.get('files', {})) == set(LIMITS),
                'Unsupported recovery manifest.')
        for name in LIMITS:
            entry = manifest['files'][name]
            require(entry == {'bytes': (work / name).stat().st_size, 'sha256': digest(work / name)},
                    'Recovery archive checksum mismatch.')
        with closing(connect_readonly(work / 'relay.sqlite')) as db:
            counts = check_db(db)
        # Actually restore through SQLite's backup API into a second independent database.
        snapshot(work / 'relay.sqlite', work / 'restored-check.sqlite')
        with closing(connect_readonly(work / 'restored-check.sqlite')) as db:
            require(check_db(db) == counts, 'Restored database differs from the snapshot.')
        (work / 'restored-check.sqlite').unlink()
        yield work


def verify(archive, owner=0):
    with unpack(archive, owner):
        pass


def retention(root, owner, newest=48, daily=14):
    archives = sorted((p for p in root.iterdir() if NAME.fullmatch(p.name)), reverse=True)
    keep = set(archives[:newest])
    days = set()
    for path in archives:
        day = NAME.fullmatch(path.name).group(1)[:8]
        if day not in days and len(days) < daily:
            days.add(day)
            keep.add(path)
    for path in archives:
        if path not in keep:
            regular(path, {owner}, private=True)
            path.unlink()


def cleanup_interrupted(root, owner):
    # Called only under both locks. A killed job may leave private staging files.
    for path in root.iterdir():
        if re.fullmatch(r'\.pending-[0-9a-f]{32}', path.name):
            regular(path, {owner}, private=True)
            path.unlink()
        elif re.fullmatch(r'\.snapshot-[a-z0-9_]{8}', path.name):
            private_dir(path, owner)
            shutil.rmtree(path)


def create(root, sources, owner=0, database_owner=None, update_lock=UPDATE_LOCK):
    private_dir(root, owner)
    database_owner = owner if database_owner is None else database_owner
    require(set(sources) == set(LIMITS), 'Incomplete installed relay paths.')
    with lock(update_lock, False, owner), lock(root / '.backup.lock', True, owner, create=True):
        cleanup_interrupted(root, owner)
        for name, path in sources.items():
            s = regular(path, {database_owner} if name == 'relay.sqlite' else {owner},
                        private=name in ('relay.sqlite', 'relay.env'))
            require(s.st_size <= LIMITS[name], 'An installed file exceeds the supported size limit.')
        wal = Path(str(sources['relay.sqlite']) + '-wal')
        wal_size = regular(wal, {database_owner}, private=True).st_size if wal.exists() else 0
        needed = (sum(p.stat().st_size for p in sources.values()) + wal_size) * 4 + 512 * 1024**2
        require(shutil.disk_usage(root).free >= needed, 'Insufficient free space; existing backups were retained.')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        final = root / ('relay-' + stamp + '-' + uuid.uuid4().hex[:12] + '.tar.gz')
        pending = root / ('.pending-' + uuid.uuid4().hex)
        try:
            with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=root) as directory:
                stage = Path(directory)
                snapshot(sources['relay.sqlite'], stage / 'relay.sqlite')
                for name, source in sources.items():
                    if name != 'relay.sqlite':
                        target = stage / name
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        shutil.copyfile(source, target)
                        target.chmod(0o600)
                manifest = {'format': 1, 'created_utc': stamp,
                            'files': {n: {'bytes': (stage / n).stat().st_size, 'sha256': digest(stage / n)}
                                      for n in LIMITS}}
                (stage / 'MANIFEST.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
                with pending.open('xb') as output:
                    pending.chmod(0o600)
                    with tarfile.open(fileobj=output, mode='w:gz') as tar:
                        for name in [*LIMITS, 'MANIFEST.json']:
                            tar.add(stage / name, arcname=name, recursive=False)
                    output.flush()
                    os.fsync(output.fileno())
            verify(pending, owner)
            os.rename(pending, final)
            directory_fd = os.open(root, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            retention(root, owner)
        finally:
            pending.unlink(missing_ok=True)
        return final


def latest(root, owner=0):
    private_dir(root, owner)
    with lock(root / '.backup.lock', False, owner, create=True):
        archives = sorted((p for p in root.iterdir() if NAME.fullmatch(p.name)), reverse=True)
        require(bool(archives), 'No completed relay backup is available.')
        path = archives[0]
        verify(path, owner)
        return {'name': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path)}


def stage_restore(archive, destination, owner=0):
    require(not destination.exists() and not destination.is_symlink(), 'Recovery destination must not exist.')
    private_dir(destination.parent, owner)
    with unpack(archive, owner) as work:
        with tempfile.TemporaryDirectory(prefix='.restore-', dir=destination.parent) as directory:
            stage = Path(directory)
            for name in [*LIMITS, 'MANIFEST.json']:
                target = stage / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(work / name, target)
                target.chmod(0o600)
            os.rename(stage, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('create')
    sub.add_parser('latest')
    for mode in ('verify', 'stage-restore'):
        command = sub.add_parser(mode)
        command.add_argument('archive', type=Path)
        if mode == 'stage-restore':
            command.add_argument('destination', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Run this command as root (sudo).')
    os.umask(0o077)
    if args.command == 'create':
        check_service_layout()
        relay_uid = pwd.getpwnam('kotopizdelka-relay').pw_uid
        result = create(ROOT, installed_sources(), database_owner=relay_uid)
        print('Verified relay backup: ' + result.name)
    elif args.command == 'latest':
        print(json.dumps(latest(ROOT)))
    elif args.command == 'verify':
        verify(args.archive)
        print('PASS: checksums, SQLite integrity and isolated database restore.')
    else:
        stage_restore(args.archive, args.destination)
        print('Recovery staged in a new private directory. Running services and live files were not changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: ' + (str(error) if isinstance(error, BackupError) else type(error).__name__) +
              ' No credential values were printed.', file=sys.stderr)
        sys.exit(1)
