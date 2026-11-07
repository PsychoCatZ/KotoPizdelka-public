#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' \
        'Usage: ./install.sh --check <ASCII hostname> <expected IPv4>' \
        '       sudo ./install.sh --install <ASCII hostname> <expected IPv4>' \
        'Hostname and expected IPv4 must be supplied explicitly.' \
        'Fresh Ubuntu 24.04 x86_64 installation only. Existing installations are preserved.'
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
[[ $# -eq 3 ]] || { usage >&2; exit 1; }
relay_mode=$1
[[ $relay_mode == --check || $relay_mode == --install ]] || fail 'Use --check or --install.'
relay_host=$2
relay_expected_ip=$3
relay_bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

for relay_command in uname getent ss python3 sha256sum systemctl install useradd runuser od tr mktemp chmod; do
    command -v "$relay_command" >/dev/null || fail "Missing command: $relay_command"
done
[[ $(uname -m) == x86_64 ]] || fail 'This binary package requires x86_64.'
[[ -f /etc/os-release ]] || fail 'Cannot identify the operating system.'
# The file is provided by the operating system, not by the downloaded bundle.
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail 'This package is prepared for Ubuntu 24.04.'
[[ -d /run/systemd/system ]] || fail 'A running systemd host is required.'
if [[ $relay_mode == --install && $EUID -ne 0 ]]; then fail 'Run --install with sudo.'; fi

python3 - "$relay_host" "$relay_expected_ip" <<'PY'
import ipaddress, re, sys
name = sys.argv[1]
labels = name.split('.')
if (len(name) > 253 or len(labels) < 2 or
        not any('a' <= c <= 'z' for c in labels[-1]) or
        any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels)):
    raise SystemExit('ERROR: Use a lowercase ASCII DNS hostname (punycode for Cyrillic).')
try:
    address = ipaddress.IPv4Address(sys.argv[2])
except ipaddress.AddressValueError:
    raise SystemExit('ERROR: Expected address must be IPv4.')
if not address.is_global:
    raise SystemExit('ERROR: This package expects a public VPS IPv4 address.')
PY
[[ -f "$relay_bundle_dir/SHA256SUMS" ]] || fail 'Use the binary deployment package, not the source directory.'
(cd -- "$relay_bundle_dir" && sha256sum --check --quiet SHA256SUMS) || fail 'Package checksum verification failed.'
for relay_binary in messenger-relay queue_ticket caddy; do
    [[ -f "$relay_bundle_dir/bin/$relay_binary" && -x "$relay_bundle_dir/bin/$relay_binary" ]] || fail "Missing executable: $relay_binary"
done

for relay_path in /opt/kotopizdelka-relay /etc/kotopizdelka-relay /var/lib/kotopizdelka-relay /var/lib/kotopizdelka-proxy; do
    [[ ! -e $relay_path && ! -L $relay_path ]] || fail "Already exists: $relay_path. This script never replaces an existing installation."
done
for relay_account in kotopizdelka-relay kotopizdelka-proxy; do
    if getent passwd "$relay_account" >/dev/null || getent group "$relay_account" >/dev/null; then
        fail "Account or group already exists: $relay_account"
    fi
done
for relay_unit in kotopizdelka-relay.service kotopizdelka-relay-proxy.service; do
    for relay_unit_dir in /etc/systemd/system /run/systemd/system /run/systemd/transient /usr/lib/systemd/system /lib/systemd/system; do
        [[ ! -e $relay_unit_dir/$relay_unit && ! -L $relay_unit_dir/$relay_unit ]] || fail "Unit already exists: $relay_unit"
        [[ ! -e $relay_unit_dir/$relay_unit.d && ! -L $relay_unit_dir/$relay_unit.d ]] || fail "Unit drop-ins already exist: $relay_unit"
    done
done
relay_occupied=$(ss -H -ltn '( sport = :80 or sport = :443 or sport = :8787 )')
[[ -z $relay_occupied ]] || fail 'TCP 80, 443 or 8787 is occupied. Inspect the existing service; do not stop the VPN blindly.'
# Docker can publish ports via DNAT without appearing in ss output.
for relay_docker_socket in /run/docker.sock /var/run/docker.sock; do
    if [[ -S $relay_docker_socket ]]; then
        command -v docker >/dev/null || fail 'Docker is running, but its TCP port publications cannot be inspected.'
        python3 - "$relay_docker_socket" <<'PY'
import json, subprocess, sys
prefix = ['docker', '--host', 'unix://' + sys.argv[1]]
def run(args):
    try:
        return subprocess.check_output(prefix + args, text=True, stderr=subprocess.DEVNULL, timeout=15)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise SystemExit('ERROR: Cannot inspect local Docker ports. Run --check with sudo if needed.')
for container in run(['ps', '--format', '{{.ID}}']).splitlines():
    bindings = json.loads(run(['inspect', '--format', '{{json .NetworkSettings.Ports}}', container])) or {}
    for key, publications in bindings.items():
        if key.endswith('/tcp') and any(p.get('HostPort') in {'80', '443', '8787'} for p in publications or []):
            raise SystemExit('ERROR: An existing Docker container publishes TCP 80, 443 or 8787. Preserve it and resolve the conflict first.')
PY
        break
    fi
done
python3 - "$relay_host" "$relay_expected_ip" <<'PY'
import socket, sys
name, expected = sys.argv[1:]
try:
    actual = {r[4][0] for r in socket.getaddrinfo(name, None, socket.AF_INET)}
except socket.gaierror:
    raise SystemExit('ERROR: The hostname has no usable IPv4 DNS record yet.')
if actual != {expected}:
    raise SystemExit('ERROR: DNS A records do not point exclusively to the expected VPS IPv4. Wait for DNS propagation before installing.')
try:
    ipv6 = socket.getaddrinfo(name, None, socket.AF_INET6)
except socket.gaierror as error:
    if error.errno not in {socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME)}:
        raise SystemExit('ERROR: Unable to verify the absence of AAAA records.')
else:
    if ipv6:
        raise SystemExit('ERROR: This IPv4 deployment expects no AAAA record for the relay hostname.')
PY

relay_tmp_dir=$(mktemp -d)
readonly relay_tmp_dir
trap 'rm -rf -- "$relay_tmp_dir"' EXIT
python3 - "$relay_bundle_dir/Caddyfile.template" "$relay_tmp_dir/Caddyfile" "$relay_host" <<'PY'
from pathlib import Path
import sys
template = Path(sys.argv[1]).read_text()
if template.count('RELAY_HOSTNAME') != 1:
    raise SystemExit('ERROR: Unexpected Caddy template.')
Path(sys.argv[2]).write_text(template.replace('RELAY_HOSTNAME', sys.argv[3]))
PY
XDG_DATA_HOME="$relay_tmp_dir/data" XDG_CONFIG_HOME="$relay_tmp_dir/config" \
    "$relay_bundle_dir/bin/caddy" validate --config "$relay_tmp_dir/Caddyfile" --adapter caddyfile
printf 'Preflight passed for https://%s\n' "$relay_host"
if [[ $relay_mode == --check ]]; then exit 0; fi

for relay_account in kotopizdelka-relay kotopizdelka-proxy; do
    useradd --system --user-group --home-dir "/var/lib/$relay_account" --no-create-home --shell /usr/sbin/nologin "$relay_account"
    install -d -m 0700 -o "$relay_account" -g "$relay_account" "/var/lib/$relay_account"
done
install -d -m 0755 /opt/kotopizdelka-relay/bin /etc/kotopizdelka-relay
for relay_binary in messenger-relay queue_ticket caddy; do
    install -m 0755 "$relay_bundle_dir/bin/$relay_binary" "/opt/kotopizdelka-relay/bin/$relay_binary"
done
install -m 0644 "$relay_tmp_dir/Caddyfile" /etc/kotopizdelka-relay/Caddyfile
relay_admin_token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
[[ $relay_admin_token =~ ^[a-f0-9]{64}$ ]] || fail 'Unable to generate the administrative token.'
printf 'RELAY_ADMIN_TOKEN=%s\n' "$relay_admin_token" > /etc/kotopizdelka-relay/relay.env
chmod 0600 /etc/kotopizdelka-relay/relay.env
unset relay_admin_token
install -m 0755 "$relay_bundle_dir/issue-ticket.sh" /opt/kotopizdelka-relay/issue-ticket.sh
for relay_unit in kotopizdelka-relay.service kotopizdelka-relay-proxy.service; do
    install -m 0644 "$relay_bundle_dir/systemd/$relay_unit" "/etc/systemd/system/$relay_unit"
done
systemctl daemon-reload
systemctl enable --now kotopizdelka-relay.service kotopizdelka-relay-proxy.service
for relay_unit in kotopizdelka-relay.service kotopizdelka-relay-proxy.service; do
    systemctl is-active --quiet "$relay_unit" || fail "Service failed to start: $relay_unit. Inspect its journal; existing files are preserved."
done
printf '%s\n' \
    'Services started. Certificate issuance may still be in progress.' \
    'Verify public HTTPS and the existing VPN before creating contacts.' \
    'Issue one ticket: sudo /opt/kotopizdelka-relay/issue-ticket.sh' \
    'The admin token remains in the root-only relay.env file; it was not printed.'
