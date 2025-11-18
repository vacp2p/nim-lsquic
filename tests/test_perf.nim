{.used.}

import chronos, chronos/unittest2/asynctests, results, std/sets, stew/endians2, sequtils
import
  lsquic/[api, listener, tlsconfig, connection, certificateverifier, stream, lsquic_ffi]
import ./helpers/certificate

initializeLsquic(true, true)

const
  runs = 10
  uploadSize = 100000 # 100KB
  downloadSize = 100000000 # 100MB
  chunkSize = 65536 # 64KB chunks like perf

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc runPerf(): Future[Duration] {.async.} =
  let address = initTAddress("127.0.0.1:12345")
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let clientTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  let serverTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  let client = QuicClient.new(clientTLSConfig)
  let server = QuicServer.new(serverTLSConfig)
  let listener = server.listen(address)
  let accepting = listener.accept()
  let dialing = client.dial(address)

  let outgoingConn = await dialing
  let incomingConn = await accepting

  let serverDone = newFuture[void]()
  let serverHandler = proc() {.async.} =
    let stream = await incomingConn.incomingStream()

    # Step 1: Read download size (8 bytes) 
    let clientDownloadSize = await stream.read()

    # Step 2: Read upload data until EOF
    var totalBytesRead = 0
    while true:
      let chunk = await stream.read()
      if chunk.len == 0:
        break
      totalBytesRead += chunk.len

    # Step 3: Send download data back
    var remainingToSend = uint64.fromBytesBE(clientDownloadSize)
    while remainingToSend > 0:
      let toSend = min(remainingToSend, chunkSize)
      try:
        await stream.write(newSeq[byte](toSend))
      except StreamError:
        echo "unexpected stream error on server: ", getCurrentExceptionMsg()
        quit(1)

      remainingToSend -= toSend
    await stream.close()
    serverDone.complete()

  # Start server handler
  asyncSpawn serverHandler()

  let startTime = Moment.now()

  # Step 1: Send download size, activate stream first
  let clientStream = await outgoingConn.openStream()
  try:
    await clientStream.write(toSeq(downloadSize.uint64.toBytesBE()))
  except StreamError:
    echo "unexpected stream error on client: ", getCurrentExceptionMsg()
    quit(1)

  # Step 2: Send upload data in chunks
  var remainingToSend = uploadSize
  while remainingToSend > 0:
    let toSend = min(remainingToSend, chunkSize)
    try:
      let sending = newSeq[byte](toSend)
      await clientStream.write(sending)
    except StreamError:
      echo "unexpected stream error on client: ", getCurrentExceptionMsg()
      quit(1)
    remainingToSend -= toSend

  # Step 3: Close write side
  await clientStream.close()

  # Step 4: Start reading download data
  var totalDownloaded = 0
  while totalDownloaded < downloadSize:
    let chunk = await clientStream.read()
    totalDownloaded += chunk.len

  let duration = Moment.now() - startTime

  await serverDone

  await listener.stop()
  await client.stop()

  return duration

suite "perf protocol simulation":
  asyncTest "test":
    var total: Duration
    for i in 0 ..< runs:
      let duration = await runPerf()
      total += duration
      echo "\trun #" & $(i + 1) & " duration: " & $duration

    echo "\tavrg duration: " & $(total div runs)
