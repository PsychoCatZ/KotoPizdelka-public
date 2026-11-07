#!/usr/bin/env bash
# KotoPizdelka relay backup add-on v1. No relay/proxy restart or configuration replacement.
set -euo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then echo 'Run with sudo.' >&2; exit 1; fi
if [[ $# -ne 1 || ( $1 != --check && $1 != --install ) ]]; then
    echo 'Usage: sudo bash install.sh --check | --install' >&2; exit 1
fi
backup_bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 - "$backup_bundle" <<'PY'
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
root=Path(sys.argv[1])
required={'relay-backup.py','install.sh','kotopizdelka-relay-backup.service',
          'kotopizdelka-relay-backup.timer','kotopizdelka-relay-backup.tmpfiles',
          'Pull-RelayBackup.ps1','Register-RelayBackupTask.ps1','README.txt','BUILD_INFO.json'}
def safe(path,private=False):
    for p in (path,*path.parents):
        s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise SystemExit('Unsafe owner, permissions or symlink: '+str(p))
    if private and path.stat().st_mode & 0o077:raise SystemExit('Expected private permissions: '+str(path))
for p in [root,root/'SHA256SUMS']:safe(p)
listed=set()
for line in (root/'SHA256SUMS').read_text().splitlines():
    match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)',line)
    if not match:raise SystemExit('Invalid package checksum list.')
    h,name=match.groups()
    if name not in required or name in listed:raise SystemExit('Unexpected package file.')
    safe(root/name)
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=h:raise SystemExit('Package checksum mismatch.')
    listed.add(name)
if listed!=required or {p.name for p in root.iterdir()}!=required|{'SHA256SUMS'}:
    raise SystemExit('Incomplete package or unexpected files.')
for p in ['/opt/kotopizdelka-relay','/etc/kotopizdelka-relay/relay.env',
          '/etc/systemd/system/kotopizdelka-relay.service','/opt/kotopizdelka-relay/bin/messenger-relay',
          '/opt/kotopizdelka-relay/bin/queue_ticket','/opt/kotopizdelka-relay/issue-ticket.sh']:
    safe(Path(p),private=p.endswith('relay.env'))
account=pwd.getpwnam('kotopizdelka-relay')
db=Path('/var/lib/kotopizdelka-relay/relay.sqlite')
if db.is_symlink() or not db.is_file() or db.stat().st_uid!=account.pw_uid or db.stat().st_mode&0o077:
    raise SystemExit('Expected the private database owned by the existing relay account.')
for p in ['/opt/kotopizdelka-relay/backup','/var/backups/kotopizdelka-relay',
          '/etc/systemd/system/kotopizdelka-relay-backup.service',
          '/etc/systemd/system/kotopizdelka-relay-backup.timer',
          '/etc/tmpfiles.d/kotopizdelka-relay-backup.conf']:
    path=Path(p)
    if path.exists() or path.is_symlink():safe(path)
if not Path('/run/systemd/system').is_dir():raise SystemExit('A running systemd installation is required.')
subprocess.run(['systemctl','is-active','--quiet','kotopizdelka-relay.service'],check=True)
# Parse/compile without creating __pycache__ or executing the backup program.
namespace={'__name__':'backup_preflight'}
exec(compile((root/'relay-backup.py').read_bytes(),'relay-backup.py','exec'),namespace)
namespace['check_service_layout']()
print('Preflight passed. Existing relay, Caddy, other services and VPN are unchanged.')
PY
if [[ $1 == --check ]]; then exit 0; fi
install -d -m 0755 /opt/kotopizdelka-relay/backup
install -d -m 0700 /var/backups/kotopizdelka-relay
install -m 0755 "$backup_bundle/relay-backup.py" /opt/kotopizdelka-relay/backup/relay-backup.py
install -m 0644 "$backup_bundle/kotopizdelka-relay-backup.service" /etc/systemd/system/kotopizdelka-relay-backup.service
install -m 0644 "$backup_bundle/kotopizdelka-relay-backup.timer" /etc/systemd/system/kotopizdelka-relay-backup.timer
install -m 0644 "$backup_bundle/kotopizdelka-relay-backup.tmpfiles" /etc/tmpfiles.d/kotopizdelka-relay-backup.conf
systemd-tmpfiles --create /etc/tmpfiles.d/kotopizdelka-relay-backup.conf
systemctl daemon-reload
systemctl start kotopizdelka-relay-backup.service
systemctl enable --now kotopizdelka-relay-backup.timer
systemctl is-active --quiet kotopizdelka-relay-backup.timer
printf 'Installed. First backup verified; hourly timer enabled. No relay/proxy restart.\n'
printf 'Next: enable the Windows off-site pull. A copy on example deployment alone is insufficient.\n'
