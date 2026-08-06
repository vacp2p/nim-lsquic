# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[json, sets, sequtils, os, algorithm, math, strutils]
from std/posix import Rusage, RUSAGE_SELF, getrusage
import chronos, results, stew/endians2, chronicles
import lsquic

export json, sets, sequtils, os, algorithm, math, strutils
export chronos, results, endians2, chronicles
export lsquic

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

const
  # Protocol message types
  MsgThroughput* = 0x01'u8
  MsgLatency* = 0x02'u8

  # Defaults
  DefaultChunkSize* = 65536 # 64KB
  DefaultUploadSize* = 100_000 # 100KB
  DefaultDownloadSize* = 100_000_000 # 100MB
  DefaultRuns* = 10
  DefaultStreams* = 4
  DefaultConnections* = 4
  DefaultPort* = 14555

type
  BenchMode* = enum
    Throughput = "throughput"
    Latency = "latency"
    MultiStream = "multistream"
    MultiConn = "multiconn"
    Stress = "stress"
    RampUp = "rampup"

  LatencySample* = object
    rttNs*: int64

  RampUpSample* = object
    elapsedMs*: int64 ## ms since download start
    throughputMbps*: float ## throughput in this window (Mbit/s)
    cumulativeBytes*: int ## total bytes received so far

  StreamResult* = object
    uploadBytes*: int
    downloadBytes*: int
    durationNs*: int64
    latencySamples*: seq[LatencySample]
    rampUpSamples*: seq[RampUpSample]
    timeToP90Ns*: int64 ## time to reach 90% of peak throughput (rampup only)

  ResourceUsage* = object
    cpuUserNs*: int64
    cpuSysNs*: int64
    maxRssBytes*: int64

  ConnectionResult* = object
    streamResults*: seq[StreamResult]
    durationNs*: int64

  RunResult* = object
    mode*: BenchMode
    connections*: int
    streamsPerConn*: int
    uploadSize*: int
    downloadSize*: int
    chunkSize*: int
    connResults*: seq[ConnectionResult]
    durationNs*: int64
    errors*: seq[string] ## streams that failed; the run continued without them
    usage*: ResourceUsage ## CPU/memory consumed by this process

# -- Resource usage --
#
# Taken from getrusage(RUSAGE_SELF) rather than sampled externally: the LAN runs
# finish in ~100ms, far too short for `docker stats` (1s granularity) to see,
# and the kernel's counters are exact rather than an average of samples.

proc resourceUsage*(): ResourceUsage =
  var ru: Rusage
  if getrusage(RUSAGE_SELF, addr ru) != 0:
    return ResourceUsage()

  ResourceUsage(
    cpuUserNs:
      ru.ru_utime.tv_sec.int64 * 1_000_000_000 + ru.ru_utime.tv_usec.int64 * 1_000,
    cpuSysNs:
      ru.ru_stime.tv_sec.int64 * 1_000_000_000 + ru.ru_stime.tv_usec.int64 * 1_000,
    # Linux reports ru_maxrss in kilobytes.
    maxRssBytes: ru.ru_maxrss.int64 * 1024,
  )

# Certificate loading - embedded test certs
const certDir = parentDir(parentDir(currentSourcePath())) / "tests" / "helpers"
const certificateStr = staticRead(certDir / "testCertificate.pem")
const privateKeyStr = staticRead(certDir / "testPrivateKey.pem")

proc strToSeq(val: string): seq[byte] =
  toSeq(val.toOpenArrayByte(0, val.high))

proc testCertificate*(): seq[byte] =
  strToSeq(certificateStr)

proc testPrivateKey*(): seq[byte] =
  strToSeq(privateKeyStr)

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc makeClient*(): QuicClient {.
    raises: [QuicConfigError, QuicError, TransportOsError]
.} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let clientTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["bench"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicClient.new(clientTLSConfig)

proc makeServer*(): QuicServer {.raises: [QuicConfigError].} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let serverTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["bench"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicServer.new(serverTLSConfig)

# Stats helpers
proc percentile*(samples: seq[int64], p: float): int64 =
  if samples.len == 0:
    return 0
  var sorted = samples
  sorted.sort()
  let idx = min(int(float(sorted.len - 1) * p), sorted.len - 1)
  sorted[idx]

# -- Stall counts --
#
# On shaped links the latency tail is not continuous: samples pile up on the
# rungs of lsquic's exponential retransmission backoff (observed around 6s, 12s,
# 25s and 50s under 2% loss). A percentile over a few hundred samples therefore
# reports *which rung one particular sample landed on*, which moves by 2-3x
# between runs of identical code. Counting how many samples cleared a fixed
# threshold is stable to about +/-1 over the same runs, because it aggregates
# the whole tail instead of indexing into it.
#
# Three thresholds rather than one: a cell's meaningful rung depends on its
# shaping. wan_multistream never stalls past 1s (so only the 100ms bucket
# carries information there), while lossy_stress routinely stalls past 10s.

const StallThresholdsNs* = [100_000_000'i64, 1_000_000_000'i64, 10_000_000_000'i64]

proc stallCounts*(samples: seq[int64]): seq[int] =
  result = newSeq[int](StallThresholdsNs.len)
  for s in samples:
    for i, threshold in StallThresholdsNs:
      if s > threshold:
        result[i].inc

proc mean*(samples: seq[int64]): float =
  if samples.len == 0:
    return 0.0
  var total: float = 0.0
  for s in samples:
    total += float(s)
  total / float(samples.len)

proc formatBps*(bytes: int, durationNs: int64): string =
  if durationNs <= 0:
    return "N/A"
  let bitsPerSec = float(bytes) * 8.0 * 1e9 / float(durationNs)
  if bitsPerSec >= 1e9:
    return $(bitsPerSec / 1e9).formatFloat(ffDecimal, 2) & " Gbit/s"
  elif bitsPerSec >= 1e6:
    return $(bitsPerSec / 1e6).formatFloat(ffDecimal, 2) & " Mbit/s"
  elif bitsPerSec >= 1e3:
    return $(bitsPerSec / 1e3).formatFloat(ffDecimal, 2) & " Kbit/s"
  else:
    return $bitsPerSec.formatFloat(ffDecimal, 2) & " bit/s"

proc formatDuration*(ns: int64): string =
  if ns >= 1_000_000_000:
    return $(float(ns) / 1e9).formatFloat(ffDecimal, 3) & "s"
  elif ns >= 1_000_000:
    return $(float(ns) / 1e6).formatFloat(ffDecimal, 3) & "ms"
  elif ns >= 1000:
    return $(float(ns) / 1e3).formatFloat(ffDecimal, 3) & "us"
  else:
    return $ns & "ns"

proc toJson*(r: RunResult): JsonNode =
  var connArr = newJArray()
  var allLatencies: seq[int64]
  for cr in r.connResults:
    var streamArr = newJArray()
    for sr in cr.streamResults:
      var latArr = newJArray()
      for l in sr.latencySamples:
        latArr.add(%l.rttNs)
        allLatencies.add(l.rttNs)
      var rampArr = newJArray()
      for s in sr.rampUpSamples:
        rampArr.add(
          %*{
            "elapsed_ms": s.elapsedMs,
            "throughput_mbps": s.throughputMbps,
            "cumulative_bytes": s.cumulativeBytes,
          }
        )
      var streamNode = %*{
        "upload_bytes": sr.uploadBytes,
        "download_bytes": sr.downloadBytes,
        "duration_ns": sr.durationNs,
        "latency_samples_ns": latArr,
      }
      if sr.rampUpSamples.len > 0:
        streamNode["ramp_up_samples"] = rampArr
        streamNode["time_to_p90_ns"] = %sr.timeToP90Ns
      streamArr.add(streamNode)
    connArr.add(%*{"streams": streamArr, "duration_ns": cr.durationNs})
  var json = %*{
    "mode": $r.mode,
    "connections": r.connections,
    "streams_per_conn": r.streamsPerConn,
    "upload_size": r.uploadSize,
    "download_size": r.downloadSize,
    "chunk_size": r.chunkSize,
    "duration_ns": r.durationNs,
    "connections_results": connArr,
    "errors": %r.errors,
    "latency_sample_count": allLatencies.len,
    "stall_thresholds_ns": %(@StallThresholdsNs),
    "stall_counts": %stallCounts(allLatencies),
    "client_cpu_user_ns": r.usage.cpuUserNs,
    "client_cpu_sys_ns": r.usage.cpuSysNs,
    "client_max_rss_bytes": r.usage.maxRssBytes,
  }
  json
