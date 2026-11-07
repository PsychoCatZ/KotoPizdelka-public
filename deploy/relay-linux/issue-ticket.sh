#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then printf 'ERROR: Run this operator command with sudo.\n' >&2; exit 1; fi
relay_ticket_arguments=()
relay_default_ttl=3600
if [[ ${1:-} == --invite ]]; then
    relay_ticket_arguments=(--invite)
    relay_default_ttl=86400
    shift
fi
if [[ $# -gt 1 || ! ${1:-$relay_default_ttl} =~ ^[0-9]{1,5}$ ]]; then
    printf 'ERROR: Usage: issue-ticket.sh [--invite] [TTL seconds: 1..86400]\n' >&2; exit 1
fi
relay_ticket_ttl=$((10#${1:-$relay_default_ttl}))
if [[ $relay_ticket_ttl -lt 1 || $relay_ticket_ttl -gt 86400 ]]; then
    printf 'ERROR: TTL must be between 1 and 86400 seconds.\n' >&2; exit 1
fi
relay_database=/var/lib/kotopizdelka-relay/relay.sqlite
if [[ ! -f $relay_database || -L $relay_database ]]; then
    printf 'ERROR: The installed relay database does not exist or is a symlink.\n' >&2; exit 1
fi
# Only the service account touches SQLite/WAL. The admin token is unnecessary.
exec runuser -u kotopizdelka-relay -- env \
    RELAY_DATABASE="$relay_database" RELAY_TICKET_TTL="$relay_ticket_ttl" \
    /opt/kotopizdelka-relay/bin/queue_ticket "${relay_ticket_arguments[@]}"
