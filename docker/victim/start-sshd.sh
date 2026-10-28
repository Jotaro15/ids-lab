#!/bin/sh
# Start the SSH daemon in the background. nginx then runs in the foreground
# and keeps the container alive.
#
# -D keeps sshd attached to the container's output, so that -e can write its
# logs to it and they show up in `docker compose logs`. Without -D, sshd
# detaches and its logs are discarded. The trailing & does the backgrounding.
set -eu

mkdir -p /run/sshd
/usr/sbin/sshd -D -e < /dev/null &
