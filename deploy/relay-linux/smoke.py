#!/usr/bin/env python3
"""Exercise the bundled processes on loopback with a temporary TLS authority.

No system services, trust stores or existing databases are changed.
This checks the relay HTTP protocol, not client E2EE or systemd isolation.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def stop(process, sig):
    if process is not None and process.poll() is None:
        process.send_signal(sig)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError('A process did not shut down gracefully.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=Path(__file__).resolve().parent / 'bin')
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    template = Path(__file__).resolve().with_name('Caddyfile.template').read_text()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='koto-relay-smoke-') as work:
        work = Path(work)
        database = work / 'relay.sqlite'
        backend_port, tls_port = free_port(), free_port()
        while backend_port == tls_port:
            tls_port = free_port()
        site = f'https://localhost:{tls_port}'
        config = template.replace('RELAY_HOSTNAME', site)
        config = config.replace('admin off', 'admin off\n\tauto_https disable_redirects\n\tskip_install_trust', 1)
        config = config.replace(site + ' {', site + ' {\n\tbind 127.0.0.1\n\ttls internal', 1)
        config = config.replace('127.0.0.1:8787', f'127.0.0.1:{backend_port}')
        (work / 'Caddyfile').write_text(config)
        admin = secrets.token_hex(32)
        relay_env = dict(os.environ, RELAY_ADMIN_TOKEN=admin, RELAY_DATABASE=str(database),
                         RELAY_BIND=f'127.0.0.1:{backend_port}')
        proxy_env = dict(os.environ, XDG_DATA_HOME=str(work / 'data'), XDG_CONFIG_HOME=str(work / 'config'))
        relay = proxy = None
        with (work / 'relay.log').open('wb') as relay_log, (work / 'proxy.log').open('wb') as proxy_log:
            def start_relay():
                return subprocess.Popen([str(binaries / 'messenger-relay')], env=relay_env,
                                        stdout=subprocess.DEVNULL, stderr=relay_log)

            try:
                relay = start_relay()
                proxy = subprocess.Popen([str(binaries / 'caddy'), 'run', '--config', str(work / 'Caddyfile'),
                                          '--adapter', 'caddyfile'], env=proxy_env,
                                         stdout=subprocess.DEVNULL, stderr=proxy_log)
                ca = work / 'data/caddy/pki/authorities/local/root.crt'
                deadline = time.monotonic() + 15
                while not ca.is_file():
                    assert relay.poll() is None and proxy.poll() is None, 'A process exited before readiness.'
                    assert time.monotonic() < deadline, 'Temporary TLS authority was not ready.'
                    time.sleep(0.05)
                context = ssl.create_default_context(cafile=str(ca))
                # This opener is exclusively for the loopback test site.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                    urllib.request.HTTPSHandler(context=context))

                def request(method, path, token=None, body=None):
                    data = None if body is None else json.dumps(body).encode()
                    headers = {} if data is None else {'Content-Type': 'application/json'}
                    if token:
                        headers['Authorization'] = 'Bearer ' + token
                    req = urllib.request.Request(site + path, data=data, headers=headers, method=method)
                    try:
                        with opener.open(req, timeout=3) as response:
                            raw = response.read()
                            return response.status, json.loads(raw) if raw else None
                    except urllib.error.HTTPError as error:
                        return error.code, None

                def ready():
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        assert relay.poll() is None and proxy.poll() is None, 'A process exited.'
                        try:
                            if request('GET', '/health')[0] == 200:
                                return
                        except (OSError, urllib.error.URLError):
                            pass
                        time.sleep(0.05)
                    raise AssertionError('HTTPS relay was not ready.')

                ready()
                assert request('GET', '/v1/accounts/session')[0] == 401
                assert request('POST', '/v1/queues', admin)[0] == 403
                assert request('GET', '/unknown')[0] == 404
                ticket = subprocess.check_output([str(binaries / 'queue_ticket')],
                                                 env=dict(os.environ, RELAY_DATABASE=str(database)), text=True).strip()
                assert len(ticket) == 64 and all(c in '0123456789abcdef' for c in ticket)
                queue = secrets.token_hex(16)
                read, write = secrets.token_hex(32), secrets.token_hex(32)
                assert read != write
                proposal = {'id': queue, 'read_token': read, 'write_token': write}
                assert request('POST', '/v1/queues/redeem', ticket, proposal) == (201, {'id': queue})
                path = f'/v1/queues/{queue}/messages'
                payload = base64.b64encode(secrets.token_bytes(65536)).decode()
                message = {'id': secrets.token_hex(16), 'payload': payload}
                assert request('POST', path, write, message)[0] == 202
                # Invalid capabilities are indistinguishable from missing queues.
                assert request('GET', path, secrets.token_hex(32))[0] == 404
                assert request('GET', path, read) == (200, {'messages': [message]})
                oversized = dict(message, payload='X' * (96 * 1024))
                assert request('POST', path, write, oversized)[0] == 413

                stop(relay, signal.SIGINT)
                assert relay.returncode == 0
                assert request('GET', path, read)[0] == 502
                relay = start_relay()
                ready()
                assert request('POST', '/v1/queues/redeem', ticket, proposal) == (201, {'id': queue})
                assert request('POST', path, write, message)[0] == 202
                assert request('GET', path, read) == (200, {'messages': [message]})
                assert request('DELETE', path + '/' + message['id'], read)[0] == 204
                assert request('GET', path, read) == (200, {'messages': []})
                assert request('POST', path, write, message)[0] == 202
                assert request('GET', path, read) == (200, {'messages': []})
            finally:
                stop(proxy, signal.SIGTERM)
                stop(relay, signal.SIGINT)
        logs = (work / 'relay.log').read_bytes() + (work / 'proxy.log').read_bytes()
        for value in [admin, ticket, read, write, queue, payload]:
            assert value.encode() not in logs, 'Sensitive request data reached the process logs.'
        for file in work.glob('relay.sqlite*'):
            data = file.read_bytes()
            for value in [ticket, read, write, admin]:
                assert value.encode() not in data, 'An unencrypted capability reached SQLite.'
        print('PASS: TLS, authorization, body limits, restart, retry/ACK and request-log checks.')


if __name__ == '__main__':
    main()
