#!/bin/sh
# Start the SSH daemon in the background. nginx then runs in the foreground
# and keeps the container alive.
set -eu

mkdir -p /run/sshd
/usr/sbin/sshd -e
