#!/bin/sh
# Runs the server as an unprivileged user that owns the data directory.
set -e
DATA="${NYAPASSWORD_DATA:-/data}"
mkdir -p "$DATA"
chown -R nyapassword:nyapassword "$DATA"
chmod 700 "$DATA"
exec su-exec nyapassword "$@"
