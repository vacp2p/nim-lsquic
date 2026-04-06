# nim-lsquic Benchmark Harness

Docker-based harness for measuring bandwidth and latency of nim-lsquic under
various network conditions. Runs a QUIC server and client in separate containers
connected via a Docker bridge network, with configurable latency, bandwidth
limits, and packet loss via `tc netem`.

## Defaults

| Parameter | CLI default | Docker Compose default |
|-----------|-------------|----------------------|
| Mode | `throughput` | `throughput` |
| Port | `14555` | `14555` |
| Upload size | 100 KB (`100000`) | 100 KB (`100000`) |
| Download size | 100 MB (`100000000`) | 10 MB (`10000000`) |
| Chunk size | 64 KB (`65536`) | 64 KB (`65536`) |
| Runs | `10` | `5` |
| Streams/conn | `4` | `4` |
| Connections | `4` | `4` |

> The Docker Compose defaults use a smaller download size and fewer runs to keep
> container-based benchmarks practical. Adjust via environment variables as needed.

## Benchmark Modes

| Mode | Connections | Streams/conn | What it measures |
|------|-------------|-------------|------------------|
| `throughput` | 1 | 1 | Baseline upload/download bandwidth |
| `latency` | 1 | 1 | Baseline RTT (ping/pong echo) |
| `multistream` | 1 | K (default: 4) | Stream contention within a single connection |
| `multiconn` | N (default: 4) | 1 | Connection contention across separate QUIC connections |
| `stress` | N (default: 4) | K (default: 4) | Combined connection + stream contention |

### `throughput`

Opens a single connection with a single stream. The client uploads a configurable
amount of data, then the server sends back a configurable download payload. This
gives you the baseline maximum bandwidth nim-lsquic can push through one stream
with no contention. Use this to establish an upper bound before testing with
concurrent load.

### `latency`

Opens a single connection with a single stream dedicated to ping/pong. The client
sends a small 64-byte payload, the server echoes it back, and the client measures
the round-trip time. Repeats for the configured number of runs. This gives you
the baseline RTT with no competing traffic — the floor against which you compare
the other modes.

### `multistream`

Opens a single connection with K streams. K-1 streams do bulk throughput
transfers (upload + download) while 1 stream acts as a **latency probe** running
the same ping/pong as the `latency` mode. All streams share the same QUIC
connection, meaning they share one congestion window, one flow control context,
and one `engine_process` call. This answers the question: *does bulk traffic on
other streams within the same connection degrade latency?* If the latency probe
p50/p95 increases significantly compared to the `latency` baseline, it points to
stream-level contention inside lsquic (stream scheduling, flow control
head-of-line blocking, or engine processing overhead).

### `multiconn`

Opens N separate QUIC connections, each with a single stream. N-1 connections do
bulk throughput transfers while 1 connection runs the latency probe. Each
connection gets its own congestion state, but on the server side they still share
the same UDP socket and the same lsquic engine (one `engine_process` call handles
all connections). This answers: *does load from other connections degrade latency
on a separate connection?* Degradation here points to server-side engine
contention or UDP socket bottlenecks rather than stream-level issues.

### `stress`

The most realistic scenario. Opens N connections with K streams each. On every
connection, K-1 streams do bulk transfers and 1 stream runs the latency probe.
This combines the contention from both `multistream` and `multiconn` — stream
scheduling pressure within each connection, plus engine-level pressure across
connections. Compare the latency probe results against the `latency`, `multistream`,
and `multiconn` baselines to isolate where degradation comes from.

## Network Scenarios

The matrix runner (`run.sh`) tests across these predefined network conditions
(all 5 used in full mode, only `lan` in `--quick` mode):

| Scenario | Latency | Bandwidth | Packet Loss |
|----------|---------|-----------|-------------|
| `lan` | 0ms | unlimited | 0% |
| `wan` | 25ms | 100 Mbit | 0% |
| `constrained` | 50ms | 10 Mbit | 0.1% |
| `lossy` | 25ms | 50 Mbit | 2% |
| `mobile` | 75ms | 5 Mbit | 1% |

### `run.sh` Matrix Defaults

**Full mode** (`./benchmarks/run.sh`):

| Mode | Runs | Streams | Connections | Upload | Download |
|------|------|---------|-------------|--------|----------|
| `throughput` | 5 | 1 | 1 | 100 KB | 10 MB |
| `latency` | 100 | 1 | 1 | — | — |
| `multistream` | 2 | 4 | 1 | 100 KB | 10 MB |
| `multiconn` | 2 | 1 | 4 | 100 KB | 10 MB |
| `stress` | 1 | 4 | 4 | 100 KB | 10 MB |

**Quick mode** (`./benchmarks/run.sh --quick`) — LAN scenario only:

| Mode | Runs | Streams | Connections | Upload | Download |
|------|------|---------|-------------|--------|----------|
| `throughput` | 3 | 1 | 1 | 100 KB | 1 MB |
| `latency` | 20 | 1 | 1 | — | — |
| `multistream` | 1 | 4 | 1 | 100 KB | 1 MB |
| `multiconn` | 1 | 1 | 3 | 100 KB | 1 MB |
| `stress` | 1 | 3 | 3 | 100 KB | 1 MB |

## Prerequisites

- Docker (with Compose V2)
- `NET_ADMIN` capability (needed for `tc netem` inside containers)

## Quick Start

```bash
# Run the full matrix (5 scenarios x 5 modes = 25 benchmarks)
./benchmarks/run.sh

# Quick mode: LAN only, smaller payloads, fewer runs
./benchmarks/run.sh --quick

# Single scenario or mode
./benchmarks/run.sh --scenario wan --mode latency

# Skip Docker image rebuild (if already built)
./benchmarks/run.sh --quick --no-build
```

## Direct Docker Compose Usage

For more control, run Docker Compose directly with environment variables:

```bash
# Throughput test with 50ms latency and 10Mbit bandwidth cap
BENCH_MODE=throughput BENCH_RUNS=5 \
BENCH_UPLOAD_SIZE=100000 BENCH_DOWNLOAD_SIZE=10000000 \
LATENCY_MS=50 BANDWIDTH_MBIT=10 \
  docker compose -f benchmarks/docker-compose.yml up \
    --abort-on-container-exit --exit-code-from bench-client

# Stress test: 8 connections x 8 streams, lossy network
BENCH_MODE=stress BENCH_CONNECTIONS=8 BENCH_STREAMS=8 \
LATENCY_MS=25 PACKET_LOSS_PCT=2 BANDWIDTH_MBIT=50 \
  docker compose -f benchmarks/docker-compose.yml up \
    --abort-on-container-exit --exit-code-from bench-client

# Clean up after
docker compose -f benchmarks/docker-compose.yml down --remove-orphans
```

### Environment Variables

**Benchmark parameters:**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCH_MODE` | `throughput` | Benchmark mode |
| `BENCH_RUNS` | `5` | Number of iterations |
| `BENCH_CONNECTIONS` | `4` | Number of QUIC connections (multiconn/stress) |
| `BENCH_STREAMS` | `4` | Streams per connection (multistream/stress) |
| `BENCH_UPLOAD_SIZE` | `100000` | Bytes to upload per stream (100 KB) |
| `BENCH_DOWNLOAD_SIZE` | `10000000` | Bytes to download per stream (10 MB) |
| `BENCH_CHUNK_SIZE` | `65536` | I/O chunk size (64 KB) |

**Network shaping (applied on client side):**

| Variable | Default | Description |
|----------|---------|-------------|
| `LATENCY_MS` | `0` | One-way delay in milliseconds |
| `BANDWIDTH_MBIT` | `0` | Bandwidth limit in Mbit/s (0 = unlimited) |
| `PACKET_LOSS_PCT` | `0` | Packet loss percentage |
| `JITTER_MS` | `0` | Delay jitter in milliseconds |

## Running Locally (Without Docker)

You can compile and run the benchmarks directly for loopback testing:

```bash
# Compile
nim c --threads:on -d:release --out:benchmarks/bench_server benchmarks/bench_server.nim
nim c --threads:on -d:release --out:benchmarks/bench_client benchmarks/bench_client.nim

# Run server in background
./benchmarks/bench_server --port 14555 &

# Run client
./benchmarks/bench_client --mode stress --server 127.0.0.1 --port 14555 \
  --connections 4 --streams 4 --runs 3 --json

# Kill server when done
kill %1
```

### Server CLI Options

```
--listen, -l       Listen address (default: 0.0.0.0)
--port, -p         Port (default: 14555)
```

### Client CLI Options

```
--mode, -m         Benchmark mode (default: throughput)
                   Options: throughput|latency|multistream|multiconn|stress
--server, -s       Server address (default: 127.0.0.1)
--port, -p         Server port (default: 14555)
--upload-size      Bytes to upload per stream (default: 100000 = 100 KB)
--download-size    Bytes to download per stream (default: 100000000 = 100 MB)
--chunk-size       I/O chunk size (default: 65536 = 64 KB)
--runs, -r         Number of iterations (default: 10)
--streams, -k      Streams per connection (default: 4)
--connections, -n  Number of connections (default: 4)
--json             Output results as JSON (default: human-readable)
```

## Output

### Summary Table

`run.sh` prints a summary table and saves it to `benchmarks/results/`:

```
Scenario        Mode           Conns  Strms  Upload          Download        Lat p50      Lat p95      Duration
========================================================================================================================
lan             throughput     1      1      178.18 Mbit/s   1.78 Gbit/s     -            -            13.470ms
lan             latency        1      1      -               -               28.110us     406.816us    997.421us
lan             multistream    1      4      91.69 Mbit/s    916.87 Mbit/s   37.590us     1.429ms      26.176ms
lan             multiconn      3      1      96.43 Mbit/s    964.31 Mbit/s   20.937us     753.864us    16.592ms
lan             stress         3      3      186.57 Mbit/s   1.87 Gbit/s     22.795us     2.706ms      25.727ms
wan             throughput     1      1      810.67 Kbit/s   81.07 Mbit/s    -            -            4.934s
wan             latency        1      1      -               -               25.283ms     25.420ms     2.529s
wan             multistream    1      4      1.81 Mbit/s     180.50 Mbit/s   25.166ms     26.293ms     2.659s
wan             multiconn      4      1      1.88 Mbit/s     188.34 Mbit/s   25.112ms     25.762ms     2.549s
wan             stress         4      4      6.64 Mbit/s     664.45 Mbit/s   25.171ms     27.585ms     1.445s
```

**Columns:**

- **Scenario** — network condition profile applied via `tc netem` (see
  [Network Scenarios](#network-scenarios) above for the exact latency, bandwidth,
  and loss values each name maps to)
- **Mode** — benchmark mode that was run
- **Conns** — number of QUIC connections used
- **Strms** — number of streams per connection
- **Upload** — aggregate upload throughput across all streams, computed as total
  bytes uploaded divided by total wall-clock duration. Shows `-` for latency-only
  modes where no bulk data is transferred.
- **Download** — same as Upload but for the download direction
- **Lat p50** — median (50th percentile) round-trip time from the latency probe
  stream. This is the RTT of a small ping/pong echo measured alongside any bulk
  transfers. Shows `-` for pure throughput mode which has no latency probe.
- **Lat p95** — 95th percentile RTT. Useful for spotting tail latency spikes
  caused by contention or packet loss.
- **Duration** — total wall-clock time for the entire benchmark run (all
  iterations, all streams)

### Human-Readable Output

Without `--json`, the client prints a detailed breakdown:

```
=== Benchmark Results ===
Mode: stress
Connections: 3, Streams/conn: 3
Total duration: 11.079ms

  Connection #1:
    Stream #1 [throughput]:
      Upload:   10000 bytes -> 41.39 Mbit/s
      Download: 50000 bytes -> 206.96 Mbit/s
      Duration: 1.933ms
    Stream #2 [throughput]:
      Upload:   10000 bytes -> 19.48 Mbit/s
      Download: 50000 bytes -> 97.38 Mbit/s
      Duration: 4.108ms
    Stream #3 [latency] (50 samples):
      Mean:  213.898us
      p50:   90.164us
      p95:   456.471us
      p99:   801.782us
      Min:   51.400us
      Max:   3.967ms
  Connection #2:
    ...
```

### JSON Output

With `--json`, the client outputs machine-readable JSON with per-stream latency
samples (in nanoseconds) for further analysis:

```json
{
  "mode": "latency",
  "connections": 1,
  "streams_per_conn": 1,
  "duration_ns": 253988269,
  "connections_results": [
    {
      "streams": [
        {
          "upload_bytes": 0,
          "download_bytes": 0,
          "duration_ns": 253906378,
          "latency_samples_ns": [25814400, 25296524, 25294871, ...]
        }
      ],
      "duration_ns": 253988269
    }
  ]
}
```

## How It Works

1. **Server** listens for QUIC connections and handles two stream protocols:
   - **Throughput** (type `0x01`): reads upload data, sends back requested download size
   - **Latency** (type `0x02`): echoes length-prefixed payloads back immediately

2. **Client** opens connections/streams based on the selected mode. In multi-stream
   and multi-connection modes, it runs bulk transfers alongside a latency probe
   to measure contention effects.

3. **Network shaping** is applied via `tc netem` in the Docker entrypoint (requires
   `NET_ADMIN` capability). Delay, bandwidth limits, and packet loss are applied
   on the client side.

4. **Results** are collected as JSON per run and aggregated into a summary table
   by `run.sh`.
