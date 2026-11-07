#!/usr/bin/env python3
"""Package a native relay update; this kit contains no Caddy or service configuration."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).absolute().parents[2]
PREFIX = 'koto-relay-update-0.2.10-linux-x64'

def read(path):
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.is_file():
        raise ValueError('Expected a regular file without symlink components: ' + str(path))
    return path.read_bytes()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def build_inputs():
    paths = ['Cargo.toml', 'Cargo.lock', 'crates/relay/Cargo.toml'] + [str(path.relative_to(ROOT)) for path in sorted((ROOT / 'crates/relay').rglob('*.rs'))]
    return {name: digest(read(ROOT / name)) for name in paths}

def git(*arguments):
    return subprocess.check_output(['git', '-C', str(ROOT), *arguments], text=True).strip()

def licenses():
    # cargo tree uses the same frozen lock and reports the shipped relay's own
    # dependency closure; desktop/Tauri dependencies are not bundled here.
    output = subprocess.check_output(['cargo', 'tree', '-p', 'messenger-relay', '--locked', '--offline',
                                      '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}'],
                                     cwd=ROOT, text=True)
    registry = Path(__import__('os').environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry/src'
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] == 'messenger-relay' or not parts[1].startswith('v'):
            continue
        name = parts[0] + '-' + parts[1][1:]
        locations = list(registry.glob('*/' + name))
        if len(locations) != 1:
            raise ValueError('Unable to locate a dependency license source: ' + name)
        crate = locations[0]
        found = sorted({path for pattern in ('LICENSE*', 'LICENCE*', 'COPYING*', 'NOTICE*') for path in crate.glob(pattern) if path.is_file()})
        if not found:
            # Some crates have license files in a dedicated subdirectory.
            found = sorted(path for folder in ('LICENSES', 'licenses') for path in (crate / folder).glob('*') if path.is_file())
        if not found:
            raise ValueError('No dependency license file found: ' + name)
        for path in found:
            result['licenses/' + name + '/' + path.name] = (read(path), 0o644)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--build-inputs', type=Path)
    parser.add_argument('--record-inputs', type=Path)
    arguments = parser.parse_args()
    if arguments.record_inputs:
        if arguments.output or arguments.build_inputs:
            parser.error('--record-inputs is a separate pre-build action.')
        with arguments.record_inputs.open('x') as target:
            target.write(json.dumps(build_inputs(), indent=2) + '\n')
        print('Recorded relay build inputs: ' + str(arguments.record_inputs))
        return
    if not arguments.output or not arguments.build_inputs:
        parser.error('--output and --build-inputs are required when packaging.')
    output = arguments.output.absolute()
    if output.exists() or output.is_symlink() or any(path.is_symlink() for path in output.parents) or not output.parent.is_dir():
        raise ValueError('Output must be a new file in an existing directory without symlinks.')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Commit and freeze the complete source tree before packaging.')
    recorded = json.loads(read(arguments.build_inputs.absolute()))
    if recorded != build_inputs():
        raise ValueError('Relay build inputs changed; record inputs and rebuild before packaging.')
    commit = git('rev-parse', 'HEAD')
    files = {}
    for name, path in [('messenger-relay', ROOT / 'target/release/messenger-relay'),
                       ('queue_ticket', ROOT / 'target/release/examples/queue_ticket')]:
        data = read(path)
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62 or struct.unpack_from('<H', data, 16)[0] not in (2, 3):
            raise ValueError('Expected Linux ELF64 x86_64 executable: ' + name)
        files['bin/' + name] = (data, 0o755)
    for name in ('update.sh', 'issue-ticket.sh'):
        files[name] = (read(ROOT / 'deploy/relay-linux' / name), 0o755)
    for name in ('RELAY_DEPLOYMENT.md', 'QUEUE_TICKETS.md', 'PROTOCOL.md', 'ACCOUNTS.md'):
        files['docs/' + name] = (read(ROOT / 'docs' / name), 0o644)
    files.update(licenses())
    info = {
        'release_version': '0.2.10',
        'relay_crate_version': tomllib.loads(read(ROOT / 'crates/relay/Cargo.toml').decode())['package']['version'],
        'source_commit': commit,
        'source_tree': git('rev-parse', 'HEAD^{tree}'),
        'source_working_tree_clean': True,
        'architecture': 'Linux x86_64; existing Ubuntu 24.04 systemd installation',
        'build_command': 'cargo build -p messenger-relay --release --bin messenger-relay --example queue_ticket --locked --offline',
        'build_input_sha256': recorded,
        'binary_sha256': {name: digest(data) for name, (data, _) in files.items() if name.startswith('bin/')},
        'scope': 'Native relay binaries and local ticket helper only. No Caddy, proxy, service unit, environment, system-user or VPN changes. Account tables are added to the existing database.',
        'validation_limit': 'Cloud build/protocol and isolated updater checks only; native VPS update and public HTTPS must be checked by the operator.',
    }
    files['BUILD_INFO.json'] = ((json.dumps(info, ensure_ascii=False, indent=2) + '\n').encode(), 0o644)
    readme = '''КотоПизделка 0.2.10 — обновление существующего relay, Ubuntu 24.04 x86_64

Этот пакет обновляет только messenger-relay, queue_ticket и issue-ticket.sh.
Caddy, его импорты, сертификаты, службы прокси, relay.env и VPN
не изменяются. Rust, Node.js и новый веб-сервер на VPS не нужны.

Распаковать в новый закрытый каталог от root. В каталоге пакета:
  sha256sum --check SHA256SUMS
  sudo bash ./update.sh --check
  sudo bash ./update.sh --update

Проверка --check ничего не изменяет. Обновление создаёт согласованную
SQLite-копию через backup API от пользователя relay и закрытую копию
прежних программ. Перезапускается только kotopizdelka-relay.service.
После обновления проверить публичный /health, прежний разговор и VPN.
Полные команды и границы проверки: docs/RELAY_DEPLOYMENT.md.

Регистрация и добавление по логину в клиенте работают без ручных билетов.
Для установок со старым Caddy matcher требуется отдельно разрешить
/v1/accounts/*: deploy/relay-linux/fix-accounts-proxy.py делает резервную
копию, проверяет Caddy и перезапускает только общий прокси. Native update
этого правила не меняет. После исправления GET /v1/accounts/session
без авторизации должен возвращать 401, а не 404.
Версия клиентской базы определяется клиентом; перед обновлением сохраните копию профиля.
Аккаунт рассчитан на один активный профиль; восстановление описано в docs/PROFILE_BACKUPS.md.

Для прежнего режима QR можно выдать билет (его секрет не публиковать):
  sudo /opt/kotopizdelka-relay/issue-ticket.sh --invite
По умолчанию он действует 86400 секунд. Старый одноочередный билет
выдаётся прежней командой без --invite, срок по умолчанию 3600 секунд.

При неудачном запуске скрипт возвращает прежние программы и запускает
только прежний native relay. SQLite-копию автоматически не восстанавливает:
это могло бы потерять сообщения, принятые после начала обновления.
Не использовать install.sh для обновления существующей установки.
'''
    files['README.txt'] = (readme.encode(), 0o644)
    sums = ''.join(f'{digest(data)}  {name}\n' for name, (data, _) in sorted(files.items()))
    files['SHA256SUMS'] = (sums.encode('ascii'), 0o644)
    with tempfile.TemporaryDirectory(prefix='koto-relay-update-package-') as temporary:
        staging = Path(temporary) / PREFIX
        for name, (data, mode) in files.items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        try:
            with output.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    for path in [staging, *sorted(staging.rglob('*'))]:
                        member = archive.gettarinfo(str(path), str(path.relative_to(staging.parent)))
                        member.uid = member.gid = member.mtime = 0
                        member.uname = member.gname = 'root'
                        member.mode = 0o755 if path.is_dir() else files[str(path.relative_to(staging))][1]
                        if path.is_file():
                            with path.open('rb') as original:
                                archive.addfile(member, original)
                        else:
                            archive.addfile(member)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    print(f'Created {output} ({output.stat().st_size} bytes); source commit {commit}')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit('ERROR: ' + str(error))
