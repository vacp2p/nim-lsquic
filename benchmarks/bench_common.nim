# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[json, sets, sequtils, os, algorithm, math, strutils]
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

  LatencySample* = object
    rttNs*: int64

  StreamResult* = object
    uploadBytes*: int
    downloadBytes*: int
    durationNs*: int64
    latencySamples*: seq[LatencySample]

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
  for cr in r.connResults:
    var streamArr = newJArray()
    for sr in cr.streamResults:
      var latArr = newJArray()
      for l in sr.latencySamples:
        latArr.add(%l.rttNs)
      streamArr.add(%*{
        "upload_bytes": sr.uploadBytes,
        "download_bytes": sr.downloadBytes,
        "duration_ns": sr.durationNs,
        "latency_samples_ns": latArr,
      })
    connArr.add(%*{
      "streams": streamArr,
      "duration_ns": cr.durationNs,
    })
  result = %*{
    "mode": $r.mode,
    "connections": r.connections,
    "streams_per_conn": r.streamsPerConn,
    "upload_size": r.uploadSize,
    "download_size": r.downloadSize,
    "chunk_size": r.chunkSize,
    "duration_ns": r.durationNs,
    "connections_results": connArr,
  }
