#!/usr/bin/env bash
# Removes the TAP device created by tap-up.sh.
set -euo pipefail
DEV="${1:-tap0}"
sudo ip link delete "$DEV"
echo "removed $DEV"
