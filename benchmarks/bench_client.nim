# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Benchmark client for nim-lsquic.
## Supports 5 benchmark modes:
##   throughput   - 1 conn, 1 stream: baseline bandwidth
##   latency      - 1 conn, 1 stream: baseline RTT
##   multistream  - 1 conn, K streams: stream contention
##   multiconn    - N conns, 1 stream each: connection contention
##   stress       - N conns, K streams each: realistic worst case

import ./bench_common

# -- Error handling --
#
# Transport-level failures are expected on the lossy and mobile scenarios: a
# peer can reset a stream or drop a connection mid-transfer, and the library
# reports that as a StreamError/ConnectionError. Losing one stream must not
# abort the whole benchmark, so failures are recorded and the remaining streams
# carry on. Defects are deliberately not caught - those are bugs, not network
# conditions, and should still crash loudly.

proc tryStream(
    f: Future[StreamResult]
): Future[Result[StreamResult, string]] {.async.} =
  try:
    return ok(await f)
  except CancelledError as e:
    raise e
  except IOError, QuicError, TransportError:
    return err(getCurrentExceptionMsg())

# -- Throughput on a single stream --

proc runThroughputStream(
    conn: Connection, uploadSize: int, downloadSize: int, chunkSize: int
): Future[StreamResult] {.async.} =
  let start = Moment.now()
  let stream = await conn.openStream()

  # Send type header
  await stream.write(@[MsgThroughput])

  # Send upload size (8 bytes) + download size (8 bytes)
  await stream.write(toSeq(uploadSize.uint64.toBytesBE()))
  await stream.write(toSeq(downloadSize.uint64.toBytesBE()))

  # Upload data
  let chunk = newSeq[byte](chunkSize)
  var remaining = uploadSize
  while remaining > 0:
    let toSend = min(remaining, chunkSize)
    await stream.write(chunk[0 ..< toSend])
    remaining -= toSend

  # Signal upload done
  await stream.close()

  # Download data
  var buf = newSeq[byte](chunkSize)
  var totalDown = 0
  while totalDown < downloadSize:
    let n = await stream.readOnce(buf[0].addr, buf.len)
    if n == 0:
      break
    totalDown += n

  let duration = Moment.now() - start
  return StreamResult(
    uploadBytes: uploadSize, downloadBytes: totalDown, durationNs: duration.nanoseconds
  )

# -- Latency ping/pong on a single stream --

proc runLatencyStream(conn: Connection, runs: int): Future[StreamResult] {.async.} =
  let stream = await conn.openStream()

  # Send type header
  await stream.write(@[MsgLatency])

  let payload = newSeq[byte](64) # small ping payload
  let payloadLenBytes = toSeq(payload.len.uint32.toBytesBE())
  var samples: seq[LatencySample]

  for i in 0 ..< runs:
    let start = Moment.now()

    # Send length-prefixed ping
    await stream.write(payloadLenBytes & payload)

    # Read response: 4 bytes length + payload
    var lenBuf = newSeq[byte](4)
    var read = 0
    while read < 4:
      let n = await stream.readOnce(lenBuf[read].addr, 4 - read)
      if n == 0:
        break
      read += n

    if read < 4:
      break

    let respLen = uint32.fromBytesBE(lenBuf).int
    var respBuf = newSeq[byte](respLen)
    read = 0
    while read < respLen:
      let n = await stream.readOnce(respBuf[read].addr, respLen - read)
      if n == 0:
        break
      read += n

    let rtt = Moment.now() - start
    samples.add(LatencySample(rttNs: rtt.nanoseconds))

  await stream.close()

  return StreamResult(
    latencySamples: samples,
    durationNs:
      if samples.len > 0:
        samples.mapIt(it.rttNs).foldl(a + b, 0'i64)
      else:
        0,
  )

# -- Mode: throughput (1 conn, 1 stream) --

proc modeThroughput(
    serverAddr: TransportAddress, uploadSize, downloadSize, chunkSize, runs: int
): Future[RunResult] {.async.} =
  var runResult = RunResult(
    mode: Throughput,
    connections: 1,
    streamsPerConn: 1,
    uploadSize: uploadSize,
    downloadSize: downloadSize,
    chunkSize: chunkSize,
  )

  let client = makeClient()
  let conn = await client.dial(serverAddr)
  let start = Moment.now()

  var connRes = ConnectionResult()
  for i in 0 ..< runs:
    let sr =
      await tryStream(runThroughputStream(conn, uploadSize, downloadSize, chunkSize))
    if sr.isOk:
      connRes.streamResults.add(sr.get())
    else:
      runResult.errors.add("run " & $(i + 1) & ": " & sr.error())

  connRes.durationNs = (Moment.now() - start).nanoseconds
  runResult.connResults.add(connRes)
  runResult.durationNs = connRes.durationNs

  conn.close()
  await client.stop()
  return runResult

# -- Mode: latency (1 conn, 1 stream) --

proc modeLatency(serverAddr: TransportAddress, runs: int): Future[RunResult] {.async.} =
  var runResult = RunResult(mode: Latency, connections: 1, streamsPerConn: 1)

  let client = makeClient()
  let conn = await client.dial(serverAddr)
  let start = Moment.now()

  var connRes = ConnectionResult()
  let sr = await tryStream(runLatencyStream(conn, runs))
  if sr.isOk:
    connRes.streamResults.add(sr.get())
  else:
    runResult.errors.add(sr.error())
  connRes.durationNs = (Moment.now() - start).nanoseconds
  runResult.connResults.add(connRes)
  runResult.durationNs = connRes.durationNs

  conn.close()
  await client.stop()
  return runResult

# -- Mode: multistream (1 conn, K streams) --

proc modeMultiStream(
    serverAddr: TransportAddress,
    numStreams, uploadSize, downloadSize, chunkSize, runs: int,
): Future[RunResult] {.async.} =
  var runResult = RunResult(
    mode: MultiStream,
    connections: 1,
    streamsPerConn: numStreams,
    uploadSize: uploadSize,
    downloadSize: downloadSize,
    chunkSize: chunkSize,
  )

  let client = makeClient()
  let conn = await client.dial(serverAddr)
  let start = Moment.now()

  var connRes = ConnectionResult()

  for run in 0 ..< runs:
    # Launch K-1 throughput streams + 1 latency probe in parallel
    var futs: seq[Future[StreamResult]]
    for s in 0 ..< numStreams - 1:
      futs.add(runThroughputStream(conn, uploadSize, downloadSize, chunkSize))

    # Latency probe on the last stream
    futs.add(runLatencyStream(conn, 50))

    # Wait for all streams to complete
    for f in futs:
      let sr = await tryStream(f)
      if sr.isOk:
        connRes.streamResults.add(sr.get())
      else:
        runResult.errors.add(sr.error())

  connRes.durationNs = (Moment.now() - start).nanoseconds
  runResult.connResults.add(connRes)
  runResult.durationNs = connRes.durationNs

  conn.close()
  await client.stop()
  return runResult

# -- Mode: multiconn (N conns, 1 stream each) --

proc modeMultiConn(
    serverAddr: TransportAddress,
    numConns, uploadSize, downloadSize, chunkSize, runs: int,
): Future[RunResult] {.async.} =
  var runResult = RunResult(
    mode: MultiConn,
    connections: numConns,
    streamsPerConn: 1,
    uploadSize: uploadSize,
    downloadSize: downloadSize,
    chunkSize: chunkSize,
  )

  # Create N separate clients (each gets its own engine context)
  var clients: seq[QuicClient]
  var conns: seq[Connection]
  for i in 0 ..< numConns:
    let client = makeClient()
    let conn = await client.dial(serverAddr)
    clients.add(client)
    conns.add(conn)

  let start = Moment.now()

  for run in 0 ..< runs:
    # Launch throughput on N-1 connections + latency probe on last
    var futs: seq[Future[StreamResult]]
    for i in 0 ..< numConns - 1:
      futs.add(runThroughputStream(conns[i], uploadSize, downloadSize, chunkSize))

    # Latency probe on last connection
    futs.add(runLatencyStream(conns[numConns - 1], 50))

    for i, f in futs:
      let sr = await tryStream(f)
      # Associate with the right connection metrics
      while runResult.connResults.len <= i:
        runResult.connResults.add(ConnectionResult())
      if sr.isOk:
        runResult.connResults[i].streamResults.add(sr.get())
      else:
        runResult.errors.add("conn " & $(i + 1) & ": " & sr.error())

  let totalDur = (Moment.now() - start).nanoseconds
  for cr in runResult.connResults.mitems:
    cr.durationNs = totalDur
  runResult.durationNs = totalDur

  for conn in conns:
    conn.close()
  for client in clients:
    await client.stop()

  return runResult

# -- Mode: stress (N conns, K streams each) --

proc modeStress(
    serverAddr: TransportAddress,
    numConns, numStreams, uploadSize, downloadSize, chunkSize, runs: int,
): Future[RunResult] {.async.} =
  var runResult = RunResult(
    mode: Stress,
    connections: numConns,
    streamsPerConn: numStreams,
    uploadSize: uploadSize,
    downloadSize: downloadSize,
    chunkSize: chunkSize,
  )

  var clients: seq[QuicClient]
  var conns: seq[Connection]
  for i in 0 ..< numConns:
    let client = makeClient()
    let conn = await client.dial(serverAddr)
    clients.add(client)
    conns.add(conn)

  let start = Moment.now()

  for run in 0 ..< runs:
    var allFuts: seq[Future[StreamResult]]
    var futConnIdx: seq[int] # track which connection each future belongs to

    for ci in 0 ..< numConns:
      # On each connection: K-1 throughput streams + 1 latency probe
      let throughputStreams = max(numStreams - 1, 0)
      for s in 0 ..< throughputStreams:
        allFuts.add(runThroughputStream(conns[ci], uploadSize, downloadSize, chunkSize))
        futConnIdx.add(ci)

      # Latency probe
      allFuts.add(runLatencyStream(conns[ci], 50))
      futConnIdx.add(ci)

    # Ensure we have connResults slots
    while runResult.connResults.len < numConns:
      runResult.connResults.add(ConnectionResult())

    for i, f in allFuts:
      let sr = await tryStream(f)
      if sr.isOk:
        runResult.connResults[futConnIdx[i]].streamResults.add(sr.get())
      else:
        runResult.errors.add("conn " & $(futConnIdx[i] + 1) & ": " & sr.error())

  let totalDur = (Moment.now() - start).nanoseconds
  for cr in runResult.connResults.mitems:
    cr.durationNs = totalDur
  runResult.durationNs = totalDur

  for conn in conns:
    conn.close()
  for client in clients:
    await client.stop()

  return runResult

# -- Mode: rampup (1 conn, 1 stream, measure throughput over time) --

const
  RampUpWindowMs = 50 ## sample window in milliseconds
  RampUpDownloadSize = 100_000_000 ## 100MB default for rampup

proc modeRampUp(
    serverAddr: TransportAddress, downloadSize: int, chunkSize: int
): Future[RunResult] {.async.} =
  var runResult = RunResult(
    mode: RampUp,
    connections: 1,
    streamsPerConn: 1,
    downloadSize: downloadSize,
    chunkSize: chunkSize,
  )

  let client = makeClient()
  let conn = await client.dial(serverAddr)

  let stream = await conn.openStream()

  # Send throughput header: no upload, just download
  await stream.write(@[MsgThroughput])
  await stream.write(toSeq(0'u64.toBytesBE())) # upload size = 0
  await stream.write(toSeq(downloadSize.uint64.toBytesBE()))
  await stream.close() # signal no upload data

  # Now read download data, recording (timestamp, cumulative bytes)
  type DataPoint = object
    elapsedNs: int64
    cumulativeBytes: int

  var buf = newSeq[byte](chunkSize)
  var totalDown = 0
  var points: seq[DataPoint]

  let start = Moment.now()

  try:
    while totalDown < downloadSize:
      let n = await stream.readOnce(buf[0].addr, buf.len)
      if n == 0:
        break
      totalDown += n
      let elapsed = Moment.now() - start
      points.add(DataPoint(elapsedNs: elapsed.nanoseconds, cumulativeBytes: totalDown))
  except CancelledError as e:
    raise e
  except IOError, QuicError, TransportError:
    # Keep the samples collected so far - a truncated ramp-up curve is still
    # informative about slow-start behaviour.
    runResult.errors.add("download: " & getCurrentExceptionMsg())

  let totalDuration = Moment.now() - start

  # Bucket into time windows
  var samples: seq[RampUpSample]
  let windowNs = RampUpWindowMs.int64 * 1_000_000

  if points.len > 0:
    var windowStart: int64 = 0
    var prevBytes = 0
    var pi = 0

    while windowStart < totalDuration.nanoseconds:
      let windowEnd = windowStart + windowNs
      # Advance to last point within this window
      while pi < points.len and points[pi].elapsedNs <= windowEnd:
        inc pi

      let cumBytes =
        if pi > 0:
          points[pi - 1].cumulativeBytes
        else:
          0
      let bytesInWindow = cumBytes - prevBytes
      let mbps = float(bytesInWindow) * 8.0 / float(windowNs) * 1e9 / 1e6

      samples.add(
        RampUpSample(
          elapsedMs: (windowStart + windowNs) div 1_000_000,
          throughputMbps: mbps,
          cumulativeBytes: cumBytes,
        )
      )

      prevBytes = cumBytes
      windowStart = windowEnd

  # Find peak throughput and time to reach 90% of peak
  var peakMbps = 0.0
  for s in samples:
    if s.throughputMbps > peakMbps:
      peakMbps = s.throughputMbps

  var timeToP90Ns: int64 = totalDuration.nanoseconds
  let threshold = peakMbps * 0.9
  for s in samples:
    if s.throughputMbps >= threshold:
      timeToP90Ns = s.elapsedMs * 1_000_000
      break

  var sr = StreamResult(
    downloadBytes: totalDown,
    durationNs: totalDuration.nanoseconds,
    rampUpSamples: samples,
    timeToP90Ns: timeToP90Ns,
  )

  var connRes =
    ConnectionResult(streamResults: @[sr], durationNs: totalDuration.nanoseconds)
  runResult.connResults.add(connRes)
  runResult.durationNs = totalDuration.nanoseconds

  conn.close()
  await client.stop()
  return runResult

# -- Print results --

proc printResults(runResult: RunResult) =
  echo ""
  echo "=== Benchmark Results ==="
  echo "Mode: ", runResult.mode
  echo "Connections: ",
    runResult.connections, ", Streams/conn: ", runResult.streamsPerConn
  echo "Total duration: ", formatDuration(runResult.durationNs)
  echo ""

  for ci, cr in runResult.connResults:
    echo "  Connection #", ci + 1, ":"

    for si, sr in cr.streamResults:
      if sr.uploadBytes > 0 or sr.downloadBytes > 0:
        echo "    Stream #", si + 1, " [throughput]:"
        echo "      Upload:   ",
          sr.uploadBytes, " bytes -> ", formatBps(sr.uploadBytes, sr.durationNs)
        echo "      Download: ",
          sr.downloadBytes, " bytes -> ", formatBps(sr.downloadBytes, sr.durationNs)
        echo "      Duration: ", formatDuration(sr.durationNs)

      if sr.latencySamples.len > 0:
        let rtts = sr.latencySamples.mapIt(it.rttNs)
        echo "    Stream #", si + 1, " [latency] (", rtts.len, " samples):"
        echo "      Mean:  ", formatDuration(int64(rtts.mean()))
        echo "      p50:   ", formatDuration(rtts.percentile(0.50))
        echo "      p95:   ", formatDuration(rtts.percentile(0.95))
        echo "      p99:   ", formatDuration(rtts.percentile(0.99))
        echo "      Min:   ", formatDuration(rtts.min())
        echo "      Max:   ", formatDuration(rtts.max())

      if sr.rampUpSamples.len > 0:
        echo "    Stream #",
          si + 1,
          " [ramp-up] (",
          sr.rampUpSamples.len,
          " windows, ",
          RampUpWindowMs,
          "ms each):"
        echo "      Time to 90% peak: ", formatDuration(sr.timeToP90Ns)
        let peakMbps = sr.rampUpSamples.mapIt(it.throughputMbps).foldl(max(a, b), 0.0)
        echo "      Peak throughput:  ", peakMbps.formatFloat(ffDecimal, 2), " Mbit/s"
        echo "      Timeline:"
        for s in sr.rampUpSamples:
          let bar = "#".repeat(min(int(s.throughputMbps / peakMbps * 40.0), 40))
          echo "        ",
            align($s.elapsedMs & "ms", 8),
            " | ",
            align(s.throughputMbps.formatFloat(ffDecimal, 1) & " Mbit/s", 15),
            " | ",
            bar

  if runResult.errors.len > 0:
    echo ""
    echo "  Failed streams (", runResult.errors.len, "):"
    for e in runResult.errors:
      echo "    ", e

  echo ""
  echo "  Client resource usage:"
  echo "    CPU user: ", formatDuration(runResult.usage.cpuUserNs)
  echo "    CPU sys:  ", formatDuration(runResult.usage.cpuSysNs)
  echo "    Peak RSS: ",
    (runResult.usage.maxRssBytes.float / 1024.0 / 1024.0).formatFloat(ffDecimal, 1),
    " MiB"
  echo ""

# -- Main --

when isMainModule:
  var mode = Throughput
  var serverHost = "127.0.0.1"
  var port = DefaultPort
  var uploadSize = DefaultUploadSize
  var downloadSize = DefaultDownloadSize
  var chunkSize = DefaultChunkSize
  var runs = DefaultRuns
  var numStreams = DefaultStreams
  var numConns = DefaultConnections
  var jsonOutput = false

  var i = 1
  while i <= paramCount():
    let arg = paramStr(i)
    case arg
    of "--mode", "-m":
      inc i
      case paramStr(i).toLowerAscii()
      of "throughput":
        mode = Throughput
      of "latency":
        mode = Latency
      of "multistream":
        mode = MultiStream
      of "multiconn":
        mode = MultiConn
      of "stress":
        mode = Stress
      of "rampup":
        mode = RampUp
      else:
        echo "Unknown mode: ", paramStr(i)
        quit(1)
    of "--server", "-s":
      inc i
      serverHost = paramStr(i)
    of "--port", "-p":
      inc i
      port = parseInt(paramStr(i))
    of "--upload-size":
      inc i
      uploadSize = parseInt(paramStr(i))
    of "--download-size":
      inc i
      downloadSize = parseInt(paramStr(i))
    of "--chunk-size":
      inc i
      chunkSize = parseInt(paramStr(i))
    of "--runs", "-r":
      inc i
      runs = parseInt(paramStr(i))
    of "--streams", "-k":
      inc i
      numStreams = parseInt(paramStr(i))
    of "--connections", "-n":
      inc i
      numConns = parseInt(paramStr(i))
    of "--json":
      jsonOutput = true
    of "--help", "-h":
      echo "Usage: bench_client [OPTIONS]"
      echo ""
      echo "Modes:"
      echo "  throughput   - 1 conn, 1 stream: baseline bandwidth"
      echo "  latency      - 1 conn, 1 stream: baseline RTT"
      echo "  multistream  - 1 conn, K streams: stream contention"
      echo "  multiconn    - N conns, 1 stream each: connection contention"
      echo "  stress       - N conns, K streams each: worst case"
      echo "  rampup       - 1 conn, 1 stream: congestion ramp-up timeline"
      echo ""
      echo "Options:"
      echo "  --mode, -m         Benchmark mode (default: throughput)"
      echo "  --server, -s       Server address (default: 127.0.0.1)"
      echo "  --port, -p         Server port (default: ", DefaultPort, ")"
      echo "  --upload-size      Bytes to upload (default: ", DefaultUploadSize, ")"
      echo "  --download-size    Bytes to download (default: ", DefaultDownloadSize, ")"
      echo "  --chunk-size       Chunk size (default: ", DefaultChunkSize, ")"
      echo "  --runs, -r         Number of runs (default: ", DefaultRuns, ")"
      echo "  --streams, -k      Streams per connection (default: ", DefaultStreams, ")"
      echo "  --connections, -n  Number of connections (default: ",
        DefaultConnections, ")"
      echo "  --json             Output results as JSON"
      quit(0)
    else:
      echo "Unknown argument: ", arg
      quit(1)
    inc i

  initializeLsquic(true, true)

  let serverAddr = initTAddress(serverHost & ":" & $port)

  echo "Connecting to ", serverHost, ":", port, " mode=", mode

  # Setup failures (dial, opening the first stream) leave nothing to report, so
  # they are fatal - but they must produce a readable message on stdout rather
  # than an unhandled-exception traceback on stderr, which the matrix runner
  # would discard.
  var benchResult: RunResult
  try:
    benchResult =
      case mode
      of Throughput:
        waitFor modeThroughput(serverAddr, uploadSize, downloadSize, chunkSize, runs)
      of Latency:
        waitFor modeLatency(serverAddr, runs)
      of MultiStream:
        waitFor modeMultiStream(
          serverAddr, numStreams, uploadSize, downloadSize, chunkSize, runs
        )
      of MultiConn:
        waitFor modeMultiConn(
          serverAddr, numConns, uploadSize, downloadSize, chunkSize, runs
        )
      of Stress:
        waitFor modeStress(
          serverAddr, numConns, numStreams, uploadSize, downloadSize, chunkSize, runs
        )
      of RampUp:
        waitFor modeRampUp(serverAddr, downloadSize, chunkSize)
  except CancelledError:
    echo "benchmark cancelled"
    cleanupLsquic()
    quit(1)
  except IOError, QuicError, TransportError, TransportOsError:
    echo "benchmark failed: ", getCurrentExceptionMsg()
    cleanupLsquic()
    quit(1)

  benchResult.usage = resourceUsage()

  var completedStreams = 0
  for cr in benchResult.connResults:
    for sr in cr.streamResults:
      if sr.uploadBytes > 0 or sr.downloadBytes > 0 or
          sr.latencySamples.len > 0 or sr.rampUpSamples.len > 0:
        inc completedStreams

  # Emitting a result set in which every stream failed would report zeroes as if
  # they were measurements, so fail the run instead.
  if completedStreams == 0:
    echo "benchmark failed: no streams completed"
    for e in benchResult.errors:
      echo "  ", e
    cleanupLsquic()
    quit(1)

  if jsonOutput:
    echo benchResult.toJson().pretty()
  else:
    printResults(benchResult)

  cleanupLsquic()
