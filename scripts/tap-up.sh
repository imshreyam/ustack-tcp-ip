#!/usr/bin/env bash
# Creates a persistent TAP device owned by the current user, so ustackd can
# attach to it without root. The kernel side gets 10.0.0.1/24; run ustackd
# with its default address 10.0.0.2 and talk to it from your normal shell:
#
#   scripts/tap-up.sh && build/ustackd
#   ping 10.0.0.2 ; curl http://10.0.0.2/
#
# (Prefer scripts/netns-demo.sh if you don't want to use sudo.)
set -euo pipefail

DEV="${1:-tap0}"
HOST_ADDR="${2:-10.0.0.1/24}"

sudo ip tuntap add dev "$DEV" mode tap user "$(id -un)"
sudo ip addr add "$HOST_ADDR" dev "$DEV"
sudo ip link set "$DEV" up
echo "created $DEV ($HOST_ADDR), owned by $(id -un)"
