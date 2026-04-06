#!/bin/bash
set -e

# nim-lsquic benchmark runner
# Runs a matrix of benchmark scenarios via Docker Compose.
#
# Usage:
#   ./benchmarks/run.sh [--quick] [--mode MODE] [--scenario SCENARIO]
#
# Options:
#   --quick       Run minimal scenarios (LAN only, fewer runs)
#   --mode MODE   Run only one benchmark mode
#   --scenario SC Run only one network scenario
#   --no-build    Skip Docker image build
#   --help        Show this help

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
RESULTS_DIR="$SCRIPT_DIR/results"

QUICK=false
FILTER_MODE=""
FILTER_SCENARIO=""
NO_BUILD=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --quick) QUICK=true; shift ;;
    --mode) FILTER_MODE="$2"; shift 2 ;;
    --scenario) FILTER_SCENARIO="$2"; shift 2 ;;
    --no-build) NO_BUILD=true; shift ;;
    --help)
      head -12 "$0" | tail -10
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

mkdir -p "$RESULTS_DIR"

# -- Network scenarios --
# Format: NAME|LATENCY_MS|BANDWIDTH_MBIT|PACKET_LOSS_PCT
if [ "$QUICK" = true ]; then
  SCENARIOS=(
    "lan|0|0|0"
  )
else
  SCENARIOS=(
    "lan|0|0|0"
    "wan|25|100|0"
    "constrained|50|10|0.1"
    "lossy|25|50|2"
    "mobile|75|5|1"
  )
fi

# -- Benchmark modes --
# Format: MODE|RUNS|STREAMS|CONNECTIONS|UPLOAD_SIZE|DOWNLOAD_SIZE
if [ "$QUICK" = true ]; then
  BENCHMARKS=(
    "throughput|3|1|1|100000|1000000"
    "latency|20|1|1|0|0"
    "multistream|1|4|1|100000|1000000"
    "multiconn|1|1|3|100000|1000000"
    "stress|1|3|3|100000|1000000"
  )
else
  BENCHMARKS=(
    "throughput|5|1|1|100000|10000000"
    "latency|100|1|1|0|0"
    "multistream|2|4|1|100000|10000000"
    "multiconn|2|1|4|100000|10000000"
    "stress|1|4|4|100000|10000000"
  )
fi

# -- Build --
if [ "$NO_BUILD" = false ]; then
  echo "Building Docker images..."
  docker compose -f "$COMPOSE_FILE" build --quiet 2>&1
  echo "Build complete."
fi

# -- Run matrix --
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$RESULTS_DIR/summary_${TIMESTAMP}.txt"
JSON_DIR="$RESULTS_DIR/json_${TIMESTAMP}"
mkdir -p "$JSON_DIR"

printf "\n%-15s %-14s %-6s %-6s %-15s %-15s %-12s %-12s %-12s\n" \
  "Scenario" "Mode" "Conns" "Strms" "Upload" "Download" "Lat p50" "Lat p95" "Duration" | tee "$SUMMARY_FILE"
printf "%s\n" "$(printf '=%.0s' {1..120})" | tee -a "$SUMMARY_FILE"

run_bench() {
  local scenario_str="$1"
  local bench_str="$2"

  IFS='|' read -r sc_name sc_lat sc_bw sc_loss <<< "$scenario_str"
  IFS='|' read -r bm_mode bm_runs bm_streams bm_conns bm_upload bm_download <<< "$bench_str"

  # Apply filters
  if [ -n "$FILTER_MODE" ] && [ "$bm_mode" != "$FILTER_MODE" ]; then
    return
  fi
  if [ -n "$FILTER_SCENARIO" ] && [ "$sc_name" != "$FILTER_SCENARIO" ]; then
    return
  fi

  local run_name="${sc_name}_${bm_mode}"
  echo -n "Running ${run_name}... "

  # Latency is applied half on each side (client sends, server sends)
  # to simulate realistic RTT. For simplicity, apply full delay on client only.
  local env_args=(
    "LATENCY_MS=$sc_lat"
    "BANDWIDTH_MBIT=$sc_bw"
    "PACKET_LOSS_PCT=$sc_loss"
    "SERVER_LATENCY_MS=0"
    "SERVER_BANDWIDTH_MBIT=0"
    "SERVER_PACKET_LOSS_PCT=0"
    "BENCH_MODE=$bm_mode"
    "BENCH_RUNS=$bm_runs"
    "BENCH_STREAMS=$bm_streams"
    "BENCH_CONNECTIONS=$bm_conns"
    "BENCH_UPLOAD_SIZE=$bm_upload"
    "BENCH_DOWNLOAD_SIZE=$bm_download"
  )

  local env_file="$JSON_DIR/.env_${run_name}"
  printf "%s\n" "${env_args[@]}" > "$env_file"

  # Start server, run client, capture JSON output.
  # Docker compose prefixes lines with "bench-client-1  | ", so we strip that
  # and reconstruct just the JSON block.
  local raw_output
  raw_output=$(
    env "${env_args[@]}" docker compose -f "$COMPOSE_FILE" up \
      --abort-on-container-exit \
      --exit-code-from bench-client \
      2>/dev/null || true
  )

  # Extract the JSON from bench-client output lines
  local output
  output=$(echo "$raw_output" | sed -n 's/^bench-client-1  | //p' | sed -n '/^{/,/^}/p' || true)

  # Tear down
  env "${env_args[@]}" docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

  if [ -z "$output" ]; then
    echo "FAILED (no JSON output)"
    printf "%-15s %-14s %-6s %-6s %-15s %-15s %-12s %-12s %-12s\n" \
      "$sc_name" "$bm_mode" "$bm_conns" "$bm_streams" "FAILED" "-" "-" "-" "-" \
      | tee -a "$SUMMARY_FILE"
    return
  fi

  # Save raw JSON
  echo "$output" > "$JSON_DIR/${run_name}.json"

  # Parse key metrics with a simple approach
  local duration_ns upload_bps download_bps lat_p50 lat_p95
  duration_ns=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['duration_ns'])" 2>/dev/null || echo "0")

  # Extract throughput from first throughput stream
  local upload_str="-" download_str="-" lat_p50_str="-" lat_p95_str="-"

  python3 -c "
import sys, json

d = json.load(sys.stdin)
dur_ns = d['duration_ns']

# Aggregate throughput
total_up = 0
total_down = 0
latencies = []

for cr in d.get('connections_results', []):
    for sr in cr.get('streams', []):
        total_up += sr.get('upload_bytes', 0)
        total_down += sr.get('download_bytes', 0)
        latencies.extend(sr.get('latency_samples_ns', []))

# Format throughput
def fmt_bps(bytes_val, ns):
    if ns <= 0 or bytes_val <= 0:
        return '-'
    bps = bytes_val * 8 * 1e9 / ns
    if bps >= 1e9: return f'{bps/1e9:.2f} Gbit/s'
    if bps >= 1e6: return f'{bps/1e6:.2f} Mbit/s'
    if bps >= 1e3: return f'{bps/1e3:.2f} Kbit/s'
    return f'{bps:.0f} bit/s'

def fmt_dur(ns):
    if ns >= 1e9: return f'{ns/1e9:.3f}s'
    if ns >= 1e6: return f'{ns/1e6:.3f}ms'
    if ns >= 1e3: return f'{ns/1e3:.3f}us'
    return f'{ns}ns'

up_str = fmt_bps(total_up, dur_ns)
down_str = fmt_bps(total_down, dur_ns)

if latencies:
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[min(int(len(latencies) * 0.95), len(latencies)-1)]
    lat_p50_str = fmt_dur(p50)
    lat_p95_str = fmt_dur(p95)
else:
    lat_p50_str = '-'
    lat_p95_str = '-'

dur_str = fmt_dur(dur_ns)

print(f'{up_str}|{down_str}|{lat_p50_str}|{lat_p95_str}|{dur_str}')
" <<< "$output" 2>/dev/null | {
    IFS='|' read -r upload_str download_str lat_p50_str lat_p95_str dur_str
    echo "done"
    printf "%-15s %-14s %-6s %-6s %-15s %-15s %-12s %-12s %-12s\n" \
      "$sc_name" "$bm_mode" "$bm_conns" "$bm_streams" "$upload_str" "$download_str" \
      "$lat_p50_str" "$lat_p95_str" "$dur_str" \
      | tee -a "$SUMMARY_FILE"
  }

  rm -f "$env_file"
}

for scenario in "${SCENARIOS[@]}"; do
  for bench in "${BENCHMARKS[@]}"; do
    run_bench "$scenario" "$bench"
  done
done

echo ""
echo "Results saved to: $RESULTS_DIR/"
echo "  Summary: $SUMMARY_FILE"
echo "  JSON:    $JSON_DIR/"
