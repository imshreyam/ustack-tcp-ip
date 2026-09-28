# ustack — a user-space TCP/IP stack in C++20

A from-scratch networking stack (Ethernet → ARP → IPv4 → ICMP/UDP/TCP → HTTP)
that runs entirely in user space. It reads and writes raw Ethernet frames on a
Linux **TAP** device, so the kernel's own TCP/IP never touches its traffic.
Real tools (`ping`, `nc`, `curl`, a browser) can talk to it.

```
 curl / ping / nc  (Linux kernel stack, 10.0.0.1)
          │  tap0
          ▼
 ┌──────────────── ustackd (10.0.0.2) ──────────────────┐
 │ app        HttpServer :80 · TCP echo :7 · UDP echo :7 │
 │ TCP        state machine, RTO, windows, cwnd, OOO     │
 │ UDP/ICMP   ports, checksums · echo, unreachable       │
 │ IPv4       validation, routing, frag/reassembly       │
 │ ARP        cache w/ timeouts, resolution queue        │
 │ Ethernet   MAC filter, EtherType demux                │
 └──────────── TapDevice ─ EventLoop (epoll + timerfd) ───┘
```

## Quick start

```bash
cmake -S . -B build && cmake --build build -j
./build/ustack_tests            # unit + two-stack integration tests (simulated time)
scripts/netns-demo.sh           # end-to-end demo against the real kernel, no sudo
```

`netns-demo.sh` uses `unshare` to create a private user and network namespace.
Inside it, it creates `tap0`, starts `ustackd`, and runs ping (including
fragmented pings), UDP/TCP echo, `curl`, a 1 MiB download, and a
connection-refused check. Your real network is never touched.

For an interactive playground (e.g. to run Wireshark/tcpdump or a browser-ish client):

```bash
scripts/netns-demo.sh bash      # a shell with the stack running on 10.0.0.2
  ping 10.0.0.2
  curl http://10.0.0.2/
  tcpdump -i tap0 -nn -vv       # watch your packets; tcpdump checks every checksum
```

### Using a real TAP device on your host (needs sudo once)

```bash
scripts/tap-up.sh               # creates tap0 owned by you, host side 10.0.0.1/24
./build/ustackd -v              # -v = debug logs, -vv = per-packet trace
# in another terminal (or open http://10.0.0.2/ in your browser):
ping 10.0.0.2
curl http://10.0.0.2/
echo hi | nc -u -w1 10.0.0.2 7
wireshark -i tap0 -k
scripts/tap-down.sh
```

### ustackd options

| option | meaning |
|---|---|
| `--dev tap0` | TAP device to attach to |
| `--ip 10.0.0.2 --netmask 255.255.255.0 --gateway A.B.C.D` | interface config |
| `--mac 02:00:00:00:00:02 --mtu 1500` | link config |
| `--ping 10.0.0.1` | the stack pings someone once a second (exercises ARP *resolution*) |
| `--fetch 10.0.0.1:8000/path` | HTTP GET over our TCP (active open); response goes to stdout |
| `-v`, `-vv` | debug / packet-trace logging |

## Project layout

```
src/ustack/
  util/     log.h, bytes.h (Bytes/ByteView, read_struct), fd.h (RAII fd)
  core/     timer.{h,cpp}   TimerQueue + RAII Timer, driven by an injected "now"
            event_loop.*    epoll + timerfd loop
  net/      headers.h       #pragma pack wire structs (network byte order)
            address.*       MacAddress, Ipv4Address (+ std::format support)
            checksum.*      RFC 1071 one's-complement sum, pseudo-header
            tap_device.*    /dev/net/tun, IFF_TAP | IFF_NO_PI
            ethernet.*      frame parse/build, EtherType dispatch
            arp.*           RFC 826, cache, pending-packet queue, retries
            ipv4.*          RFC 791, routing, fragmentation + reassembly
            icmp.*          echo request/reply, destination unreachable
            udp.*           RFC 768, port binding, port-unreachable
            tcp_types.h     states, 4-tuple, modular sequence arithmetic
            tcp_connection.* the TCP state machine (the big one)
            tcp.*           connection table, listeners, segment I/O, RST generation
  stack.*   wires all layers together
  app/      http_server.*   tiny HTTP server built on our TCP
apps/ustackd.cpp            the daemon (TAP + event loop + services)
tests/                      zero-dependency tests incl. a lossy virtual link
scripts/                    netns-demo.sh, tap-up.sh, tap-down.sh
```

## Stage checklist

| Stage | Status | Where to look |
|---|---|---|
| 1. Raw packet I/O over TAP | done | `tap_device.cpp`, `ethernet.cpp` |
| 2. ARP (reply, resolve, cache w/ timeout) | done | `arp.cpp` |
| 3. IPv4 (checksum, routing, frag/reassembly) | done | `ipv4.cpp`, `checksum.cpp` |
| 4. ICMP echo | done | `icmp.cpp` |
| 5. UDP + echo server | done | `udp.cpp`, `ustackd.cpp` |
| 6. TCP state machine, handshake, windows, RTO, OOO, teardown, simultaneous close | done | `tcp_connection.cpp` |
| 7. HTTP to curl / browser | done | `http_server.cpp` |
| Stretch: congestion control (slow start, AIMD, fast retransmit) | done | `on_new_ack`, `on_duplicate_ack` |
| Stretch: many connections (4-tuple table) | done | `tcp.cpp` |
| Stretch: BSD-socket-style API | todo | see ideas below |
| Stretch: IPv6 | todo | |

## Design notes (the interesting bits)

**The stack never touches real time or real devices.** `Stack` takes frames
through `receive_frame()` and emits them through a callback. Time comes from a
`TimerQueue` whose "now" is advanced from outside. `ustackd` drives both from
epoll + a timerfd. The tests instead connect two stacks with a `VirtualLink`
that drops, reorders and duplicates frames, and advance simulated time. That
makes a 30-second chain of retransmission timeouts run in microseconds, and
every run is deterministic for a given seed.

**Wire structs are `#pragma pack`ed and copied, never cast.** `read_struct<T>()`
memcpy's the header out of the buffer, which avoids unaligned-access and
strict-aliasing UB. Fields stay in network order, so you `ntohs()` at the point
of use.

**TCP send-side model.** The send buffer holds everything from the oldest
unacknowledged byte onward. `snd_una ≤ snd_nxt ≤ snd_max`, and a timeout
rewinds `snd_nxt` to `snd_una` (go-back-N). The FIN is treated as one more
sequence number after the last data byte, so FIN retransmission happens
automatically. The usable window is `min(peer window, cwnd) - in flight`.

**Bugs the lossy-link tests caught.** Each of these is worth reading about:
- *Pure ACKs sent with a rewound `snd_nxt`*: the peer rejects them as out of
  window, throwing away the ACK, so two peers recovering at once deadlock.
  The fix mirrors Linux's `tcp_acceptable_seq()`.
- *TIME-WAIT assassination (RFC 1337)*: a stray RST killed TIME_WAIT early.
  RSTs are now ignored in that state.
- *RTO stuck at 60 s on lossy paths*: Karn's algorithm rarely yields fresh
  samples, so backoff never decayed. The backoff is now dropped when new data
  is acknowledged (as BSD does).

**Simplifications (good next steps):** no window scaling, SACK or timestamps;
immediate ACKs (no delayed ACK); no Nagle; no urgent data; a single interface;
TIME_WAIT shortened to 2 × 5 s so demos don't leave 2-minute leftovers; and the
receive window is not trimmed for out-of-order bytes.

## Ideas for what to build next

1. **BSD-style socket API**: `my_socket/my_connect/my_send/my_recv` on top of
   the callback API. Run the stack on its own thread and use blocking calls
   with condition variables, or offer coroutines.
2. **Delayed ACKs + Nagle**, then measure how the segment count changes in tcpdump.
3. **Window scaling + timestamps (RFC 7323)** to get beyond 64 KiB in flight.
4. **SACK (RFC 2018)** and compare recovery time on the lossy link.
5. **IPv6 + NDP** (Neighbour Discovery replaces ARP).
6. **DHCP client** over our UDP, so the stack can join a real bridged LAN.
7. **pcap writer**: dump the VirtualLink traffic in tests to `.pcap` for Wireshark.

## References

- RFC 791 (IPv4), RFC 792 (ICMP), RFC 768 (UDP), RFC 826 (ARP)
- RFC 793 / RFC 9293 (TCP), RFC 1122 (host requirements), RFC 1337 (TIME-WAIT hazards)
- RFC 5681 (congestion control), RFC 6298 (RTO), RFC 1071 (checksum)
- Linux `Documentation/networking/tuntap.rst`
