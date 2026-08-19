# Oko

> **Heads up: this is a vibe-coded tool.**

*Oko* (Slovenian for "eye") is a container that watches a remote network so you don't have to be there
when something breaks.

MikroTik RouterOS can already stream its packet sniffer off-box as TZSP, and any Linux box can tap an
interface with `tcpdump` — but nothing keeps either stream around, so you only see traffic while you
happen to be watching. Oko keeps a rolling window of it on disk and serves it as pcapng over HTTP. So
from anywhere:

```bash
# the last 10 minutes, and then keep following live
curl -N https://oko.example.com/$TOKEN/last/10m/live | wireshark -k -i -
```

Wireshark opens already showing what just happened, and keeps updating.

### Two ways to feed it

| Source | How | Port |
|---|---|---|
| MikroTik, or anything speaking TZSP | `/tool sniffer streaming-server=<oko>` | 37008/udp |
| A Linux host or VM | [`oko-tap`](#capturing-from-a-linux-host-or-vm), which drives `tcpdump` | 37009/tcp |

Both land in the same store and the same queries. Each sender becomes its own pcapng interface, so one
capture can hold traffic from several routers and several VMs at once and still tell you which is which.

Prefer the TCP path where you have the choice: TCP does not lose packets under burst, and it can carry
`tcpdump -i any`, which TZSP cannot.

---

## Quick start

**On macOS or Windows** (Docker Desktop), and for trying it out anywhere:

```bash
export OKO_TOKENS=$(uuidgen)

docker run -d --name oko \
  -p 8080:8080 \
  -p 37008:37008/udp \
  -p 37009:37009/tcp \
  -v oko-data:/data \
  -e OKO_TOKENS=$OKO_TOKENS \
  davidkarlas/oko:latest
```

**On a Linux server, for real deployments**, use host networking instead — it preserves each sender's
source address, which is what per-sensor attribution depends on, and avoids the proxy that drops UDP:

```bash
docker run -d --name oko \
  --network host \
  -v oko-data:/data \
  -e OKO_TOKENS=$OKO_TOKENS \
  davidkarlas/oko:latest
```

> **`--network host` does not work on Docker Desktop.** Docker runs inside a Linux VM there, so "host"
> means *the VM's* network, not your Mac or PC. The container starts and reports healthy, but nothing is
> reachable on `127.0.0.1` — which looks exactly like Oko failing to listen. Use the published-ports
> form above. (Docker Desktop 4.34+ has a host-networking beta under Settings → Resources → Network, off
> by default.)

Either way, check it is up:

```bash
curl http://127.0.0.1:8080/healthz     # -> ok
```

Published for `linux/amd64` and `linux/arm64`, so it runs on ordinary x86 servers as well as on ARM
(Raspberry Pi, Ampere, Graviton, Apple Silicon). Pin a version for anything you care about:
`davidkarlas/oko:0.1.1`.

Why host networking matters on Linux: see
[the Docker note](#1-publishing-ingest-ports-through-dockers-bridge-breaks-sensor-attribution).

Then point something at it. A MikroTik:

```
/tool sniffer set streaming-enabled=yes streaming-server=<oko-host>:37008 filter-stream=yes
/tool sniffer start
```

Or a Linux host:

```bash
sudo tools/oko-tap/oko-tap --collector <oko-host>
```

Check that frames are arriving:

```bash
curl -s http://localhost:8080/$OKO_TOKENS/status | jq '.Ingest'
```

`PacketsPerSecond` should be non-zero, and `SocketDrops`, `PcapStreamErrors` and `CaptureLoopSuspects`
should all stay at `0`.

For a real deployment use `docker-compose.yml`, which puts Caddy in front for TLS — the token travels
in the URL, so it should not cross the internet in cleartext.

---

## The API

Every route is prefixed with an access token.

| Route | What it does |
|---|---|
| `GET /{token}/last/{duration}/live` | History, then follow. **The one you want.** |
| `GET /{token}/last/{duration}` | Recent history, then EOF |
| `GET /{token}/live` | Only what arrives from now on |
| `GET /{token}/from/{start}/to/{end}` | A closed range |
| `GET /{token}/from/{start}` | From an instant until now |
| `GET /{token}/status` | JSON diagnostics |
| `GET /healthz` | Liveness, no token required |

**Durations**: `500ms`, `90s`, `10m`, `2h`, `7d`.

**Instants**: unix seconds (`1769000000`), unix milliseconds (`1769000000123`), ISO-8601 UTC
(`2026-07-29T14:03:12Z` or `20260729T140312Z`), `now`, or relative (`-10m`).

Times are **UTC only**. A `+02:00` offset is rejected rather than guessed at: `+` means space in a
query string and is ambiguous unescaped in a path, so accepting it would silently give you the wrong
hour.

### Examples

```bash
T=<your-token>; H=https://oko.example.com

# What is happening right now?
curl -N $H/$T/live | wireshark -k -i -

# What happened while I was asleep?
curl $H/$T/from/2026-07-29T02:00:00Z/to/2026-07-29T06:00:00Z -o overnight.pcapng

# Last hour, straight into tshark
curl -s $H/$T/last/1h | tshark -r - -q -z conv,ip

# Save and open later
curl $H/$T/last/30m -o incident.pcapng
```

### If `wireshark -i -` does not work

Wireshark's own documentation notes that GUI capture from stdin is unreliable on some platforms
(`tshark` is fine). Use a named pipe instead:

```bash
mkfifo /tmp/oko
curl -N $H/$T/last/10m/live > /tmp/oko &
wireshark -k -i /tmp/oko
```

`curl -N` matters for live streams — without it curl buffers and Wireshark shows nothing for a while.

---

## Capturing from a Linux host or VM

A MikroTik speaks TZSP natively. An ordinary Linux box does not, so it pushes a pcap stream to Oko over
TCP instead. Nothing needs to be installed beyond `tcpdump` and `socat` (or `nc`).

**Use `oko-tap`** rather than assembling the pipeline yourself. It ships inside the image, so you can
pull it out onto the machine you want to capture without cloning the repo:

```bash
# --entrypoint is required, or the arguments go to Oko and it just starts the collector
docker run --rm --entrypoint cat davidkarlas/oko /usr/local/share/oko/oko-tap > oko-tap
chmod +x oko-tap
```

```bash
sudo ./oko-tap --collector oko.example.com

# persistent, restarts on failure and at boot
sudo ./oko-tap --collector oko.example.com --install-systemd
journalctl -u oko-tap -f
```

That is all. Under the hood it runs:

```
tcpdump -i any -U -s 0 -w - 'not (host oko.example.com and tcp port 37009)' | socat - TCP:oko.example.com:37009
```

Options: `--interface eth0`, `--filter 'not arp'`, `--port`, `--snaplen`, `--exclude-ssh`, `--dry-run`,
`--once`, `--uninstall-systemd`.

### Why not just run the pipeline by hand?

Because of the exclusion filter, and it is not a nicety. **If tcpdump captures the stream being sent to
the collector, every captured packet emits another packet, which is captured in turn** — each round
slightly larger, until the link saturates. It takes seconds, and it happens on the box you were trying
to diagnose.

`oko-tap` always ANDs its own exclusion onto whatever `--filter` you pass, so no argument can remove it:

```bash
$ oko-tap --collector 10.0.0.5 --filter 'host 10.0.0.5' --dry-run
tcpdump -i any -U -s 0 -w - '(host 10.0.0.5) and not (host 10.0.0.5 and tcp port 37009)' | nc 10.0.0.5 37009
```

Even asking explicitly for the collector's traffic cannot produce the loop.

If you do write the pipeline by hand, the exclusion you need is:

```
not (host <collector> and tcp port <port>)
```

Oko also keeps a backstop: it inspects each stored frame and counts any addressed to one of its own
ingest ports as `Ingest.CaptureLoopSuspects` in `/status`, logging loudly the first time. It counts them
rather than dropping them, since traffic to that port from somewhere else is still real capture data.

### Two things specific to the Linux path

**`tcpdump -i any` cannot be sent over TZSP.** Since tcpdump 4.99 / libpcap 1.10 the `any` device
produces `LINKTYPE_LINUX_SLL2` (Linux cooked v2, 276), and TZSP's encapsulation field has no code for
it — only Ethernet, Token Ring, SLIP, PPP, FDDI, raw IP and the 802.11 variants. The TCP path carries
the link type in the pcap header, so `-i any` works there. This is the main reason the TCP ingest exists.

**A VM usually only sees its own traffic.** To capture everything on the segment, the hypervisor's
virtual switch must permit promiscuous mode, or you need a mirror/SPAN port. On a gateway or router VM
this is moot, since the traffic already crosses its interfaces.

### Timestamps come from the capturing host

Oko keeps the timestamps `tcpdump` recorded rather than stamping on arrival, because the capturing
kernel stamps before any queuing delay. The consequence is that a sender with a wrong clock produces
wrongly-dated captures, and `/last/10m` then won't find its packets. Oko reports the skew — a warning in
the log and `Ingest.ClockSkewedSenders` in `/status` — rather than silently substituting arrival time,
which would hide a real problem. Fix NTP on the sender.

### Other senders

Anything that writes classic pcap to a pipe works:

```bash
# tshark and dumpcap default to pcapng, so ask for pcap explicitly
tshark  -i eth0 -F pcap -w - 'not (host oko and tcp port 37009)' | socat - TCP:oko:37009
dumpcap -i eth0 -P    -w - -f 'not (host oko and tcp port 37009)' | socat - TCP:oko:37009

# replay a file you already have
socat - TCP:oko:37009 < capture.pcap
```

Oko reads classic pcap only, in either endianness and with microsecond or nanosecond timestamps. A
pcapng stream is rejected with a message naming the flag that fixes it, rather than half-parsed.

`OKO_PCAP_TCP_PORT=0` disables this listener. Like the UDP port it is **unauthenticated** — anyone who
can reach it can inject frames and consume retention, so firewall both to the hosts that should be
sending.

---

## Which sender did this frame come from?

Oko writes pcapng rather than classic pcap specifically so that survives. Each sender becomes its own
interface, whichever ingest path it used:

```bash
tshark -r capture.pcapng -T fields -e frame.interface_name
# 10.0.0.1        <- MikroTik over TZSP
# 10.0.0.2        <- another MikroTik
# 192.168.1.40    <- a Linux VM running oko-tap

# and in Wireshark's display filter:
frame.interface_name == "192.168.1.40"
```

A classic pcap file has nowhere to put the sender's identity, and allows only one link type for the
whole file. That second limit is not hypothetical here: a MikroTik sends Ethernet (link type 1) while
`tcpdump -i any` sends Linux cooked v2 (276), and those two **cannot** coexist in a pcap file. In pcapng
each interface carries its own link type, so they share a capture happily.

A sender is identified by `(address, link type)`, so one host tapping both `eth0` and `any` shows up as
two interfaces — which is correct, because the frames genuinely have different shapes.

Interface IDs are assigned once and never reused, and are persisted in `/data/interfaces.json`.
**Do not delete that file**: pcapng interface IDs are positional, so losing it would make every
existing segment attribute its frames to the wrong sender. Oko refuses to start if it is corrupt
rather than silently misattributing.

---

## Configuration

All via `OKO_*` environment variables. Oko refuses to start on a value it cannot parse rather than
falling back to a default you did not ask for.

| Variable | Default | Notes |
|---|---|---|
| `OKO_TOKENS` | *(none)* | Comma-separated. **Without this, capture routes return 503.** |
| `OKO_TOKENS_FILE` | | One token per line; reloaded when the file changes |
| `OKO_ALLOW_ANONYMOUS` | `false` | Only if you really want an open collector |
| `OKO_UDP_PORT` | `37008` | Where TZSP arrives |
| `OKO_PCAP_TCP_PORT` | `37009` | Inbound classic-pcap streams (`tcpdump \| socat`); `0` disables |
| `OKO_UDP_BIND` | `0.0.0.0` | Applies to both listeners; `0.0.0.0` binds dual-stack |
| `OKO_DATA_DIR` | `/data` | Segments and the interface table |
| `OKO_FLUSH_BYTES` | `8388608` | Accumulated bytes that trigger a segment write |
| `OKO_FLUSH_INTERVAL` | `00:01:00` | Upper bound on how long data stays only in memory |
| `OKO_BLOCK_BYTES` | `1048576` | In-memory block size (minimum 128 KB) |
| `OKO_SNAPLEN` | `0` | Truncate frames to this many bytes; `0` keeps everything |
| `OKO_RETENTION_BYTES` | `53687091200` | 50 GB |
| `OKO_RETENTION_DURATION` | `7.00:00:00` | 7 days |
| `OKO_SOCKET_RECEIVE_BUFFER` | `8388608` | See the sysctl note below |
| `OKO_LIVE_FLUSH_MS` | `200` | Worst-case added latency for live streams |
| `OKO_LIVE_MAX_SUBSCRIBERS` | `8` | Concurrent live readers |

`ASPNETCORE_URLS` controls the HTTP listener (default `http://+:8080`).

---

## Three things that will silently bite you

### 1. Publishing ingest ports through Docker's bridge breaks sensor attribution

Publishing `-p 37008:37008/udp` or `-p 37009:37009/tcp` routes traffic through Docker's userland proxy,
which **replaces the source address**. Oko identifies sensors by that address, so every sender collapses
into one interface and the per-sensor attribution above stops working. This affects **both** ingest
paths.

Not theoretical. Running this image on Docker Desktop with published ports and pushing from the host,
`/status` reported:

```json
"Sensors": [ { "Address": "150.171.110.52", ... } ]
```

— an address unrelated to anything involved. Do not expect a recognisable gateway IP; it may be
arbitrary.

**On Linux, use `--network host`** (or `network_mode: host`). The sender's real address survives and
there is no proxy in the path.

On **Docker Desktop** (macOS/Windows) host networking is not an option — "host" there is the Linux VM,
not your machine, so the container becomes unreachable from `127.0.0.1`. Publish the ports instead and
accept the rewritten addresses; for local testing that is fine.

### 2. The same proxy drops UDP, which is a reason to prefer the TCP path

Same 800 packets, same container, same moment, measured:

| Path | Delivered | Kernel drops |
|---|---|---|
| pcap over TCP (`oko-tap`) | **800 / 800** | 0 |
| UDP / TZSP | 602 / 800 | 198 |

TCP retransmits; UDP does not. Sent straight to a natively-running Oko with no proxy in the way, the
same UDP replay delivered all 3500 of a larger capture with zero loss at 214k pps — so the proxy is the
bottleneck, not Oko. But where you have the choice (a Linux host rather than a MikroTik), the TCP path
is simply more robust.

Note the accounting: `602 + 198 = 800`. Every frame is either stored or counted as dropped, so
`/status` can always tell you whether a capture is complete.

### 3. `net.core.rmem_max` is not namespaced (UDP ingest only)

Oko asks for an 8 MB socket receive buffer for the TZSP listener. `net.core.rmem_max` is a **global**
sysctl, not a per-namespace one, so inside a container the request is silently clamped to roughly 208 KB
unless the host was tuned:

```bash
sysctl -w net.core.rmem_max=16777216   # and persist it in /etc/sysctl.d/
```

Without it, a traffic burst is dropped by the kernel before Oko ever sees it. Two things surface this:
Oko logs a warning at startup naming the buffer it was actually granted, and `/status` exposes
`Ingest.SocketDrops`, read from `/proc/net/udp`.

**Silent loss is the failure mode that ruins a UDP capture**, because nothing in the resulting file
admits to it — the frames simply are not there. Watch `SocketDrops`.

This does not apply to the pcap TCP ingest, which retransmits rather than dropping. It is one more
reason to prefer `oko-tap` where the sender is a Linux host.

---

## `/status`

```bash
curl -s http://localhost:8080/$TOKEN/status | jq
```

The fields worth knowing.

Counters shared by both ingest paths:

- `Listen` — the ports actually in use: `UdpPort`, `PcapTcpPort` (`0` when disabled) and `Bind`.
- `Ingest.PacketsPerSecond` / `BitsPerSecond` — sampled over a one-second window.
- `Ingest.CaptureLoopSuspects` — frames addressed to Oko's own ingest ports. **Non-zero means a tap is
  capturing its own stream**; fix its filter before it saturates the link.
- `Ingest.ClockSkewedSenders` — senders whose timestamps disagree with this host's clock, which makes
  time-range queries miss their packets.
- `Sensors[]` — per-sender packet counts, link type, and last-seen time.
- `Memory.PendingFlushBytes` — data waiting to be written. Sustained growth means storage is not
  keeping up with ingest.
- `Storage.OldestUtc` — how far back you can actually query.

TZSP / UDP path:

- `Ingest.SocketDrops` — kernel-dropped datagrams. Should be `0`. `null` means not Linux.
- `Ingest.SocketReceiveBufferBytes` — what the kernel actually granted, not what was asked for.
- `Ingest.Keepalives` — TZSP type-4 frames. A sensor that is connected but idle still sends these,
  which distinguishes "quiet link" from "router stopped talking to us".
- `Ingest.TzspParseErrors` — malformed datagrams; should be `0` from a real sensor.
- `Ingest.UnsupportedEncapsulation` — frames in an encapsulation Oko will not guess at.

pcap / TCP path:

- `Ingest.PcapStreamErrors` — rejected streams. Almost always a sender writing pcapng; the log line
  names the flag that fixes it.

---

## Development

Requires the .NET 10 SDK, and Wireshark for the tests (`tshark` and `capinfos` are used to validate
that the files Oko writes are genuinely valid pcapng — that check is the point, not an extra).

```bash
dotnet build
dotnet test
```

The test suite spawns the built `Oko` executable and drives it over real UDP, real TCP and HTTP, so build
before running the integration tests.

### Tools

| | |
|---|---|
| `tools/oko-tap/oko-tap` | POSIX shell. Runs on a **Linux host you want to capture**, drives `tcpdump` into the TCP ingest, and always injects the self-exclusion filter. |
| `tools/oko-replay` | .NET. Replays a capture file as **TZSP**, standing in for a MikroTik. For testing a deployment without hardware. |

`oko-tap` needs nothing installed but `tcpdump` and `socat` or `nc`:

```bash
tools/oko-tap/oko-tap --collector oko.example.com --dry-run   # show the pipeline, run nothing
sudo tools/oko-tap/oko-tap --collector oko.example.com --interface eth0 --filter 'not arp'
sudo tools/oko-tap/oko-tap --collector oko.example.com --install-systemd
```

`oko-replay` drives the UDP/TZSP path instead:

```bash
dotnet run --project tools/oko-replay -- capture.pcapng <oko-host> 37008 --rate 1000
dotnet run --project tools/oko-replay -- capture.pcapng localhost 37008 --rate 0 --sensor 10.9.9.9 --loop
```

`--sensor` adds a TZSP `TAG_SENSOR`, which Oko honours in preference to the datagram's source address —
useful for simulating several routers, and what a real sensor behind NAT would do.

### Releasing

```bash
docker login                          # once, interactively
./scripts/publish.sh --dry-run        # build both architectures, push nothing
./scripts/publish.sh                  # version comes from Directory.Build.props
```

The script runs the tests, refuses a dirty working tree so a published tag always corresponds to a real
commit, builds `linux/amd64` and `linux/arm64`, tags both the version and `latest`, and afterwards
verifies that both architectures are actually present in the pushed manifest.

The build **cross-compiles** rather than emulating: the SDK stage is pinned to `$BUILDPLATFORM` and
`dotnet publish -a` targets the other architecture. Emulating an x86 SDK under QEMU on an ARM machine
takes minutes per platform; this takes about 13 seconds each.

To bump the version, edit `<OkoVersion>` in `Directory.Build.props` — it feeds the assembly version, the
`shb_userappl` string recorded in every capture file, and the image tag.

---

## How it works

```
MikroTik ──TZSP/UDP────► TzspListener ───────┐
                                             │
Linux host ──pcap/TCP──► PcapStreamListener ─┤
  (oko-tap)                                  │
                                             ▼
                              CaptureBlock (1 MB of pcapng EPBs)
                                     │              │ full
                                     │              ▼
                                     │      CaptureStore ──► SegmentWriter ──► /data/segments/YYYY-MM-DD/
                                     └──► LiveHub ──► subscriber channels ──► HTTP live responses
```

Both listeners converge on the same three calls — resolve the sender to an interface, append to the
store, publish to the live hub — so everything downstream is unaware of which transport a frame arrived
on. The differences are confined to the listeners: TZSP stamps at receive time because the protocol
carries no usable timestamp, while the pcap path keeps the capturing kernel's own timestamps.

Each frame is encoded into its **final pcapng bytes on arrival**. So writing a segment is a copy to
disk, serving a query is a copy to the socket, and there is exactly one place the pcapng encoder can
be wrong.

Segment file names carry their own time range
(`20260729T140312123-20260729T140955456-000042.pcapng`), which means there is no index file to corrupt
or repair — the index is rebuilt by listing the directory at startup.

The delicate part is a query arriving exactly as data moves from memory to disk. `CaptureStore`
publishes a segment and releases its blocks under the same lock a reader takes its snapshot with, so a
packet is never in both places and never in neither. Every packet carries a monotonic sequence number,
which is what the tests assert against to prove no gaps or duplicates across that boundary.
