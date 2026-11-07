#!/usr/bin/env python3
"""Create the backup add-on; no production state, credentials or native rebuild."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent
OUTPUT = ROOT / 'dist'
FILES = ['relay-backup.py', 'install.sh', 'kotopizdelka-relay-backup.service',
         'kotopizdelka-relay-backup.timer', 'kotopizdelka-relay-backup.tmpfiles',
         'Pull-RelayBackup.ps1', 'Register-RelayBackupTask.ps1']


def main():
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        raise SystemExit('Commit and freeze source before packaging.')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    files = {name: (SOURCE / name).read_bytes() for name in FILES}
    files['README.txt'] = (ROOT / 'docs/RELAY_BACKUPS.md').read_bytes()
    info = {'backup_addon_version': 1, 'source_commit': commit,
            'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(),
            'scope': 'Backup service/timer plus Windows SSH pull; no relay/proxy/client replacement.',
            'checks': 'Unit failure/WAL/retention tests; native restore scenario; PowerShell parser and systemd unit verification.',
            'runtime_limit': 'Real Windows DPAPI/task scheduler and example deployment systemd installation require operator verification.'}
    files['BUILD_INFO.json'] = (json.dumps(info, indent=2) + '\n').encode()
    files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                for name, data in sorted(files.items())).encode()
    server = OUTPUT / 'koto-relay-backup-1-2026-10-20.tar.gz'
    with server.open('xb') as output, tarfile.open(fileobj=output, mode='w:gz') as tar:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo('koto-relay-backup-1/' + name)
            item.size = len(data)
            item.mode = 0o755 if name.endswith(('.py', '.sh')) else 0o644
            item.uid = item.gid = 0
            tar.addfile(item, io.BytesIO(data))
    pc = OUTPUT / 'KotoPizdelka-RelayBackup-PC-1-2026-10-20.zip'
    with zipfile.ZipFile(pc, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in ['Pull-RelayBackup.ps1', 'Register-RelayBackupTask.ps1', 'README.txt', 'BUILD_INFO.json']:
            archive.writestr(name, files[name])
        archive.writestr('SHA256SUMS.txt', ''.join(hashlib.sha256(files[n]).hexdigest() + '  ' + n + '\n'
                                                 for n in ['Pull-RelayBackup.ps1', 'Register-RelayBackupTask.ps1', 'README.txt', 'BUILD_INFO.json']))
    instruction = OUTPUT / 'KotoPizdelka-RelayBackup-START-HERE-2026-10-20.txt'
    with instruction.open('xb') as target:
        target.write(files['README.txt'])
    hashes = OUTPUT / 'KotoPizdelka-RelayBackup-SHA256SUMS-2026-10-20.txt'
    with hashes.open('x') as target:
        for p in [server, pc, instruction]:
            target.write(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n')
    print('Created backup add-on, Windows pull bundle, instructions and checksums; source ' + commit)


if __name__ == '__main__':
    main()
