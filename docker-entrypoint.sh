#!/usr/bin/env sh
set -e

# Ensure data directories exist and are writable
mkdir -p /data
mkdir -p /data/adhoc_ssl
chown -R appuser:appuser /data

# If there's an existing DB in /data and not linked in app dir, link it
if [ -f /data/chat.db ] && [ ! -e /opt/app/chat.db ]; then
  ln -s /data/chat.db /opt/app/chat.db
fi

# If there's no DB anywhere yet, initialize an empty file in /data and link it
if [ ! -f /data/chat.db ] && [ ! -e /opt/app/chat.db ]; then
  : > /data/chat.db
  chown appuser:appuser /data/chat.db
  ln -s /data/chat.db /opt/app/chat.db
fi

# Persist the .adhoc_ssl folder used by the server for ad hoc certs
if [ -d /opt/app/.adhoc_ssl ] || [ -L /opt/app/.adhoc_ssl ]; then
  rm -rf /opt/app/.adhoc_ssl
fi
ln -s /data/adhoc_ssl /opt/app/.adhoc_ssl

# Drop privileges and exec the actual command
exec gosu appuser:appuser "$@"
