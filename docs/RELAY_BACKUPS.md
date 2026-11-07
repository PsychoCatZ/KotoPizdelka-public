# Relay backups

The optional scripts under deploy/relay-backup provide a SQLite-consistent snapshot,
integrity checks, retention, a systemd timer and an encrypted Windows off-site pull.
They are supplied as source for review; no backup archives or production state are
included. See the service/timer files for scheduling and resource limits.

Build a kit using `python3 deploy/relay-backup/package.py` from a clean committed
checkout. Output is written under dist/. Review the included installer, run
`bash ./install.sh --check` and only then `sudo bash ./install.sh --install` on a
compatible existing relay installation.

For Windows, configure your own existing SSH alias (default example: relay-host)
and run Register-RelayBackupTask.ps1 with the chosen SshHost. The PC must be running
and the user logged in. Downloaded backups are encrypted using that Windows user's
DPAPI context. Losing the Windows profile can make those copies unrecoverable.

Server backups contain server secrets. Never publish them or attach them to issues.
A completed Type=oneshot service normally shows inactive/dead between timer runs;
monitor Result, ExecMainStatus and archive age. A server backup does not include
client profile keys or message history. See PROFILE_BACKUPS.md for client recovery.
