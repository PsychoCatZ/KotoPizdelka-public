#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $# -ne 1 || ( $1 != --check && $1 != --update ) ]]; then
    printf 'Usage: sudo bash ./update.sh --check | --update\n' >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then printf 'ERROR: Run the existing-installation check/update with sudo.\n' >&2; exit 1; fi
command -v python3 >/dev/null || { printf 'ERROR: Python 3 is required.\n' >&2; exit 1; }
relay_update_bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 - "$1" "$relay_update_bundle" <<'PY'
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

UNIT = 'kotopizdelka-relay.service'
USER = 'kotopizdelka-relay'
BASE = Path('/opt/kotopizdelka-relay')
DATABASE = Path('/var/lib/kotopizdelka-relay/relay.sqlite')
REPLACEMENTS = {'bin/messenger-relay': BASE / 'bin/messenger-relay',
                'bin/queue_ticket': BASE / 'bin/queue_ticket',
                'issue-ticket.sh': BASE / 'issue-ticket.sh'}
mode, bundle_text = sys.argv[1:]
bundle = Path(bundle_text)
os.umask(0o077)

def fail(message):
    raise RuntimeError(message)

def regular(path, owner=0, private=False, executable=False):
    for ancestor in (path, *path.parents):
        metadata = ancestor.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            fail('A required path contains a symlink.')
        if metadata.st_uid not in {0, owner} or metadata.st_mode & 0o022:
            fail('A required path has unexpected ownership or writable permissions.')
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner:
        fail('A required file is not regular or has unexpected ownership.')
    if private and metadata.st_mode & 0o077:
        fail('A private installed file has unexpected permissions.')
    if executable and stat.S_IMODE(metadata.st_mode) != 0o755:
        fail('An installed executable does not have mode 0755.')
    return metadata

def directory(path, owner=0, private=False):
    for ancestor in (path, *path.parents):
        metadata = ancestor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail('A required directory is absent, not a directory, or a symlink.')
        if metadata.st_uid not in {0, owner} or metadata.st_mode & 0o022:
            fail('A required directory has unsafe ownership or permissions.')
    metadata = path.stat()
    if metadata.st_uid != owner or (private and stat.S_IMODE(metadata.st_mode) != 0o700):
        fail('A private directory has unexpected ownership or permissions.')

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(arguments, timeout=15):
    try:
        return subprocess.check_output(arguments, text=True, stderr=subprocess.DEVNULL, timeout=timeout).strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        fail('An existing-installation system command failed; no credentials were printed.')

def property_value(name):
    return command(['systemctl', 'show', UNIT, '--property=' + name, '--value'])

def health():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open('http://127.0.0.1:8787/health', timeout=2) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False

def wait_healthy():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if property_value('ActiveState') == 'active' and health():
            return
        time.sleep(0.5)
    fail('The native relay did not become healthy before its deadline.')

def validate_package():
    directory(bundle)
    regular(bundle / 'SHA256SUMS')
    entries = {}
    for line in (bundle / 'SHA256SUMS').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)', line)
        if not match:
            fail('Malformed package checksum manifest.')
        digest, name = match.groups()
        parts = Path(name).parts
        if name.startswith('/') or '..' in parts or '.' in parts or name in entries:
            fail('Unsafe or duplicate package checksum path.')
        allowed = name in {*REPLACEMENTS, 'update.sh', 'BUILD_INFO.json', 'README.txt',
                           'docs/RELAY_DEPLOYMENT.md', 'docs/QUEUE_TICKETS.md', 'docs/PROTOCOL.md', 'docs/ACCOUNTS.md'} or name.startswith('licenses/')
        if not allowed:
            fail('The update package contains an unexpected file.')
        path = bundle / name
        regular(path)
        if sha256(path) != digest:
            fail('Package checksum verification failed.')
        entries[name] = digest
    required = {*REPLACEMENTS, 'update.sh', 'BUILD_INFO.json', 'README.txt', 'docs/RELAY_DEPLOYMENT.md'}
    if not required.issubset(entries):
        fail('The update package is incomplete.')
    actual = set()
    for path in bundle.rglob('*'):
        if path.is_symlink():
            fail('The update package contains a symlink.')
        if path.is_file():
            actual.add(str(path.relative_to(bundle)))
    if actual != set(entries) | {'SHA256SUMS'}:
        fail('The update package has unlisted files.')
    info = json.loads((bundle / 'BUILD_INFO.json').read_text())
    if info.get('release_version') != '0.2.10' or info.get('source_working_tree_clean') is not True or not re.fullmatch('[0-9a-f]{40}', info.get('source_commit', '')):
        fail('Unexpected update build metadata.')
    for name in ('messenger-relay', 'queue_ticket'):
        data = (bundle / 'bin' / name).read_bytes()
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62 or struct.unpack_from('<H', data, 16)[0] not in (2, 3):
            fail('The update binary is not Linux ELF64 x86_64.')

def validate_installation():
    if os.uname().machine != 'x86_64' or not Path('/run/systemd/system').is_dir():
        fail('A running Ubuntu x86_64 systemd installation is required.')
    os_release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            os_release[key] = value.strip('"')
    if os_release.get('ID') != 'ubuntu' or os_release.get('VERSION_ID') != '24.04':
        fail('This update is prepared for Ubuntu 24.04.')
    for name in ('systemctl', 'runuser', 'python3'):
        if shutil.which(name) is None:
            fail('A required existing-installation command is unavailable.')
    account = pwd.getpwnam(USER)
    if account.pw_uid == 0:
        fail('The relay service must use its separate account.')
    expected = {'LoadState': 'loaded', 'ActiveState': 'active', 'User': USER, 'Group': USER,
                'FragmentPath': '/etc/systemd/system/' + UNIT,
                'WorkingDirectory': str(DATABASE.parent)}
    for name, value in expected.items():
        if property_value(name) != value:
            fail('The existing native relay unit does not match this update layout.')
    executable = property_value('ExecStart')
    if len(re.findall(r'path=', executable)) != 1 or re.search(r'path=([^ ;]+)', executable).group(1) != str(REPLACEMENTS['bin/messenger-relay']) or re.search(r'argv\[\]=([^;]+);', executable).group(1).strip() != str(REPLACEMENTS['bin/messenger-relay']):
        fail('The native relay ExecStart is unexpected.')
    environments = dict(item.split('=', 1) for item in shlex.split(property_value('Environment')))
    if environments != {'RELAY_BIND': '127.0.0.1:8787', 'RELAY_DATABASE': str(DATABASE)}:
        fail('The native relay environment layout is unexpected.')
    environment_file = property_value('EnvironmentFiles')
    if environment_file != '/etc/kotopizdelka-relay/relay.env (ignore_errors=no)':
        fail('The native relay EnvironmentFile is unexpected.')
    regular(Path(expected['FragmentPath']))
    regular(Path('/etc/kotopizdelka-relay/relay.env'), private=True)
    directory(DATABASE.parent, account.pw_uid, private=True)
    regular(DATABASE, account.pw_uid, private=True)
    for suffix in ('-wal', '-shm'):
        path = Path(str(DATABASE) + suffix)
        if path.exists() or path.is_symlink():
            regular(path, account.pw_uid, private=True)
    for path in REPLACEMENTS.values():
        regular(path, executable=True)
    if command(['systemctl', 'is-active', 'kotopizdelka-relay-proxy.service']) != 'active' or not health():
        fail('The existing relay/proxy baseline is not healthy.')
    if (DATABASE.parent / 'backups').exists() or (DATABASE.parent / 'backups').is_symlink():
        directory(DATABASE.parent / 'backups', account.pw_uid, private=True)
    directory(Path('/var/backups'))
    rollback_base = Path('/var/backups/kotopizdelka-relay-update')
    if rollback_base.exists() or rollback_base.is_symlink():
        directory(rollback_base, private=True)
    return account

BACKUP_CODE = r'''
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
import signal
os.umask(0o077)
def deadline_exceeded(number, frame):
    raise TimeoutError('Backup process exceeded deadline')
signal.signal(signal.SIGALRM, deadline_exceeded)
signal.alarm(65)
root = Path('/var/lib/kotopizdelka-relay')
folder = root / 'backups'
if not folder.exists():
    folder.mkdir(mode=0o700)
for path in (root, folder):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError('Unsafe backup directory')
destination = folder / sys.argv[1]
descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
os.close(descriptor)
deadline = time.monotonic() + 60
def progress(status, remaining, total):
    if time.monotonic() >= deadline:
        raise TimeoutError('Backup exceeded deadline')
try:
    with closing(sqlite3.connect('file:' + str(root / 'relay.sqlite') + '?mode=ro', uri=True, timeout=5)) as source:
        with closing(sqlite3.connect(destination, timeout=5)) as target:
            source.backup(target, pages=256, progress=progress, sleep=0.1)
            if target.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise RuntimeError('Backup integrity failure')
except BaseException:
    destination.unlink(missing_ok=True)
    raise
print(destination)
'''

def backup_database():
    name = 'relay-before-0.2.10-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + str(time.time_ns()) + '.sqlite'
    try:
        result = subprocess.run(['runuser', '-u', USER, '--', 'python3', '-', name], input=BACKUP_CODE,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=75, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        fail('The private online SQLite backup failed; installed executables were preserved.')
    expected = DATABASE.parent / 'backups' / name
    if result.stdout.strip() != str(expected):
        fail('Unexpected online backup result; installed executables were preserved.')
    return expected

def atomic_replace(source, destination):
    descriptor, temporary_name = tempfile.mkstemp(prefix='.koto-update-', dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as target, source.open('rb') as original:
            shutil.copyfileobj(original, target)
            target.flush()
            os.fchmod(target.fileno(), 0o755)
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)

def update():
    descriptor = os.open('/run/kotopizdelka-relay-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        metadata = os.fstat(lock.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail('The update lock has unsafe ownership or permissions.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail('Another native relay update is already running.')
        # Repeat read-only checks under the updater lock before any mutation.
        validate_package()
        account = validate_installation()
        old_hashes = {name: sha256(path) for name, path in REPLACEMENTS.items()}
        database_backup = backup_database()
        regular(database_backup, account.pw_uid, private=True)
        rollback_base = Path('/var/backups/kotopizdelka-relay-update')
        if not rollback_base.exists():
            rollback_base.mkdir(mode=0o700)
        directory(rollback_base, private=True)
        rollback = Path(tempfile.mkdtemp(prefix='before-0.2.10-', dir=rollback_base))
        for name, path in REPLACEMENTS.items():
            target = rollback / name
            target.parent.mkdir(mode=0o700, exist_ok=True)
            with path.open('rb') as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination)
                destination.flush()
                os.fsync(destination.fileno())
            target.chmod(0o600)
            if sha256(target) != old_hashes[name]:
                fail('Installed executables changed during backup; no replacement was performed.')
        (rollback / 'DATABASE_BACKUP.txt').write_text(str(database_backup) + '\n')
        # Any package/install changes detected before replacement are fatal.
        validate_package()
        for name, path in REPLACEMENTS.items():
            regular(path, executable=True)
            if sha256(path) != old_hashes[name]:
                fail('Installed executables changed during backup; no replacement was performed.')
        try:
            for name, path in REPLACEMENTS.items():
                atomic_replace(bundle / name, path)
            command(['systemctl', 'restart', UNIT], timeout=45)
            wait_healthy()
        except BaseException:
            restored = False
            try:
                for name, path in REPLACEMENTS.items():
                    atomic_replace(rollback / name, path)
                # A crashing replacement may exhaust StartLimitBurst before
                # rollback. Clear only this native unit's runtime failure counter.
                command(['systemctl', 'reset-failed', UNIT])
                command(['systemctl', 'restart', UNIT], timeout=45)
                wait_healthy()
                restored = True
            except BaseException:
                pass
            state = 'The previous native relay was restored and is healthy.' if restored else 'Automatic native rollback did not become healthy; use the private backup for recovery.'
            fail('Update failed. ' + state + ' Backup: ' + str(rollback))
        print('Native relay update completed; loopback /health returned 200.')
        print('Private SQLite backup: ' + str(database_backup))
        print('Private binary rollback backup: ' + str(rollback))
        print('Only kotopizdelka-relay.service was restarted. Verify public HTTPS and the existing chat before issuing invitations.')

try:
    validate_package()
    validate_installation()
    if mode == '--check':
        print('Existing-installation preflight passed. No installed files, database, or services were changed.')
    else:
        update()
except (RuntimeError, OSError, ValueError, KeyError, AttributeError) as error:
    # Commands and SQLite details never enter this output, nor does relay.env.
    message = str(error) if isinstance(error, RuntimeError) else 'Update validation failed; inspect required paths and service layout.'
    raise SystemExit('ERROR: ' + message)
PY
