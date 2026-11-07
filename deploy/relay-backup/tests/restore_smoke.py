#!/usr/bin/env python3
"""Real native relay: live WAL backup, original stopped, recovered account/queue delivery."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('backup', ROOT / 'deploy/relay-backup/relay-backup.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
os.umask(0o077)


def request(port, method, path, token=None, body=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(f'http://127.0.0.1:{port}' + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with opener.open(req, timeout=5) as r:
            data = r.read()
            return r.status, json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        return e.code, None


def start(binary, database, admin, log):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    env = dict(os.environ, RELAY_DATABASE=str(database), RELAY_ADMIN_TOKEN=admin, RELAY_BIND=f'127.0.0.1:{port}')
    p = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=log)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert p.poll() is None, 'Native relay exited before readiness.'
            try:
                if request(port, 'GET', '/health')[0] == 200:
                    return p, port
            except OSError:
                pass
            time.sleep(0.05)
        raise AssertionError('Native relay did not become ready.')
    except BaseException:
        p.kill(); p.wait(timeout=5)
        raise


def stop(p):
    if p is not None and p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)
            raise


def main():
    with tempfile.TemporaryDirectory(prefix='koto-native-restore-') as text:
        root = Path(text)
        installed = root / 'installed'; installed.mkdir(mode=0o700)
        sources = {name: installed / name for name in b.LIMITS}
        for name in b.LIMITS:
            sources[name].parent.mkdir(mode=0o700, exist_ok=True, parents=True)
        for name, source in [('bin/messenger-relay', ROOT / 'target/release/messenger-relay'),
                             ('bin/queue_ticket', ROOT / 'target/release/examples/queue_ticket'),
                             ('issue-ticket.sh', ROOT / 'deploy/relay-linux/issue-ticket.sh'),
                             ('kotopizdelka-relay.service', ROOT / 'deploy/relay-linux/systemd/kotopizdelka-relay.service')]:
            shutil.copyfile(source, sources[name]); sources[name].chmod(0o700 if name.startswith('bin/') else 0o600)
        admin = secrets.token_hex(32); session = secrets.token_hex(32); key = secrets.token_hex(32)
        sources['relay.env'].write_text('RELAY_ADMIN_TOKEN=' + admin + '\n')
        sources['relay.env'].chmod(0o600)
        backup_root = root / 'backups'; backup_root.mkdir(mode=0o700)
        lock = root / 'updater.lock'; lock.touch(mode=0o600)
        first = recovered = None
        with (root / 'original.log').open('wb') as log, (root / 'recovered.log').open('wb') as recovered_log:
            try:
                first, port = start(sources['bin/messenger-relay'], sources['relay.sqlite'], admin, log)
                code, queue = request(port, 'POST', '/v1/queues', admin)
                assert code == 201
                path = '/v1/queues/' + queue['id'] + '/messages'
                payload = base64.b64encode(secrets.token_bytes(1024)).decode()
                message = {'id': secrets.token_hex(16), 'payload': payload}
                assert request(port, 'POST', path, queue['write_token'], message)[0] == 202
                credentials = {'login': 'backuptest', 'password': 'temporary restore smoke password', 'public_key': key, 'session': session}
                assert request(port, 'POST', '/v1/accounts/register', body=credentials)[0] == 200
                assert Path(str(sources['relay.sqlite']) + '-wal').exists()
                archive = b.create(backup_root, sources, os.getuid(), os.getuid(), lock)
                after = {'id': secrets.token_hex(16), 'payload': payload}
                assert request(port, 'POST', path, queue['write_token'], after)[0] == 202
                assert len(request(port, 'GET', path, queue['read_token'])[1]['messages']) == 2
                # Simulate loss of the original process. Recovery uses only the archive.
                first.kill(); first.wait(timeout=5)
                destination = root / 'recovered'
                b.stage_restore(archive, destination, os.getuid())
                restored_admin = (destination / 'relay.env').read_text().strip().split('=', 1)[1]
                binary = destination / 'bin/messenger-relay'; binary.chmod(0o700)
                recovered, port = start(binary, destination / 'relay.sqlite', restored_admin, recovered_log)
                assert request(port, 'GET', '/v1/accounts/session', session)[0] == 200
                assert request(port, 'GET', path, queue['read_token']) == (200, {'messages': [message]})
                credentials['session'] = secrets.token_hex(32)
                assert request(port, 'POST', '/v1/accounts/login', body=credentials)[0] == 200
                assert request(port, 'POST', path, queue['write_token'], after)[0] == 202
                assert request(port, 'DELETE', path + '/' + message['id'], queue['read_token'])[0] == 204
                assert request(port, 'GET', path, queue['read_token']) == (200, {'messages': [after]})
                assert request(port, 'POST', '/v1/queues', restored_admin)[0] == 201
            finally:
                stop(first); stop(recovered)
        logs = (root / 'original.log').read_bytes() + (root / 'recovered.log').read_bytes()
        for secret in [admin, session, key, payload, queue['read_token'], queue['write_token']]:
            assert secret.encode() not in logs, 'Sensitive fixture data leaked to logs.'
    print('PASS: live WAL backup; original killed; restored native binary, admin token, account session/login, envelope, send/ACK and secret-free logs.')


if __name__ == '__main__':
    main()
