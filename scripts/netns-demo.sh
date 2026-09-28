#!/usr/bin/env bash
# Runs ustackd against the real Linux kernel inside a throwaway network
# namespace. No sudo needed: `unshare` gives us root *inside* a private user +
# network namespace, which is enough to create a TAP device there. Nothing
# touches your real network configuration, and everything vanishes on exit.
#
#   scripts/netns-demo.sh            run the automated demo (ping, UDP, TCP, HTTP)
#   scripts/netns-demo.sh bash       interactive shell with the stack running
#   scripts/netns-demo.sh <cmd...>   run any command next to the stack
#
# Inside the namespace the kernel is 10.0.0.1 (tap0) and ustack is 10.0.0.2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/build/ustackd}"

if [[ "${USTACK_IN_NETNS:-}" != 1 ]]; then
    [[ -x "$BIN" ]] || { echo "build first: cmake -S . -B build && cmake --build build" >&2; exit 1; }
    exec unshare --user --map-root-user --net env USTACK_IN_NETNS=1 BIN="$BIN" "$0" "$@"
fi

ip link set lo up
ip tuntap add dev tap0 mode tap
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up

LOG="${USTACK_LOG:-/dev/stderr}"
"$BIN" --dev tap0 --ip 10.0.0.2 ${USTACK_ARGS:-} 2>>"$LOG" &
PID=$!
trap 'kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true' EXIT
sleep 0.3

if [[ $# -gt 0 ]]; then
    "$@"
    exit
fi

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "ICMP: ping 10.0.0.2 (ARP + IPv4 + ICMP)"
ping -c 3 -i 0.2 10.0.0.2

step "ICMP: large ping (3000 bytes -> IP fragmentation + reassembly both ways)"
ping -c 2 -i 0.2 -s 3000 10.0.0.2

step "UDP echo on port 7"
echo "hello over UDP" | timeout 2 nc -u -w1 10.0.0.2 7 || true

step "TCP echo on port 7"
echo "hello over TCP" | timeout 3 nc -q1 10.0.0.2 7 || true

step "HTTP: curl http://10.0.0.2/"
curl -sS -i --max-time 5 http://10.0.0.2/ | head -n 12
echo "..."

step "HTTP: 1 MiB download (flow control, congestion window, many segments)"
curl -sS --max-time 20 -o /tmp/ustack-big.$$ -w 'downloaded %{size_download} bytes in %{time_total}s (%{speed_download} B/s)\n' http://10.0.0.2/big
head -c 160 /tmp/ustack-big.$$; echo; rm -f /tmp/ustack-big.$$

step "TCP to a closed port (expect: connection refused via RST)"
curl -sS --max-time 3 http://10.0.0.2:81/ 2>&1 || true

step "Kernel's view of the neighbour (learned via our ARP replies)"
ip neigh show dev tap0

printf '\n\033[1;32mAll demo steps ran.\033[0m\n'
