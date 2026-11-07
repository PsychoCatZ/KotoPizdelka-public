# Self-hosting a relay

Use your own Ubuntu 24.04 x86_64 host, DNS name and TLS certificate.
The source snapshot includes deployment scripts, not server state or credentials.
`198.51.100.42` and `relay.example.invalid` are documentation placeholders.
No service is provided at these addresses.

Build the native relay and queue-ticket helper:

```sh
cargo build -p messenger-relay --release --locked
cargo build -p messenger-relay --release --example queue_ticket --locked
```

See `deploy/relay-linux/package.py --help` for packaging and upstream Caddy download.
The installer requires explicit hostname and expected IPv4 arguments:

```sh
bash ./install.sh --check YOUR_HOSTNAME YOUR_IPV4
sudo bash ./install.sh --install YOUR_HOSTNAME YOUR_IPV4
```

Review the script before running it as root. It targets a fresh server and refuses
conflicting existing installations. Ports 80/443 must be available for its proxy.
For an existing proxy, prepare a separate reviewed integration instead of starting
a second process on those ports. Never put relay.env, live SQLite or issued tickets
in this repository. See deploy/relay-linux/Caddyfile.template and systemd/ for
service configuration, and docs/PROTOCOL.md for the HTTP interface.

The native relay listens on loopback by default. The public proxy restricts the
administrative queue-creation API; ticket issuance is a privileged local operation.
