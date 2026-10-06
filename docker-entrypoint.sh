#!/bin/sh
# Boot wrapper for root-owned volumes (e.g. Railway mounts /data as root:root).
# If running as root: fix ownership of the data dir, then re-exec as the
# unprivileged "app" user via gosu (installed in the image). If we are already
# non-root (local run, docker --user), just exec the command.
set -eu

APP_USER="app"
DATA_DIR="${DATA_DIR:-/data}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
  exec gosu "$APP_USER" "$@"
fi

exec "$@"
