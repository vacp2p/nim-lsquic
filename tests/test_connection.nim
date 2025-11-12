import chronos
import chronos/unittest2/asynctests
import results
import std/sets
import chronicles
import lsquic/api
import lsquic/listener
import lsquic/tlsconfig
import lsquic/connection
import ./helpers/certificate
import lsquic/certificateverifier
import lsquic/stream
import lsquic/lsquic_ffi
import stew/endians2
import sequtils

proc logging(ctx: pointer, buf: cstring, len: csize_t): cint {.cdecl.} =
  echo $buf
  return 0

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

let address = initTAddress("127.0.0.1:12345")

const
  runs = 1
  uploadSize = 100000 # 100KB
  downloadSize = 100000000 # 100MB
  chunkSize = 65536 # 64KB chunks like perf

proc runPerf(): Future[Duration] {.async.} =
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
    for i in 0 ..< 1:
      let duration = await runPerf()
      total += duration
      echo "\trun #" & $(i + 1) & " duration: " & $duration

    echo "\tavrg duration: " & $(total div runs)

suite "tests":
  asyncTest "test":
    let logger = struct_lsquic_logger_if(log_buf: logging)
    discard lsquic_set_log_level("debug")
    discard lsquic_logger_lopt("engine=debug,conn=debug,stream=debug")
    #lsquic_logger_init(addr logger, nil, LLTS_HHMMSSUS)

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

    check:
      outgoingConn.certificates().len == 1
      incomingConn.certificates().len == 1

    echo "Connected!"

    let outgoingBehaviour = proc() {.async.} =
      let stream = await outgoingConn.openStream()

      await stream.write(@[1'u8, 2, 3, 4, 5])
      await stream.write(@[6'u8, 7, 8, 9, 10])

      echo "Closing client stream"

      echo "Client closed"
      await stream.close()

      #echo "Client aborted"
      # stream.abort() # Not interested in RW anything else

    let incomingBehaviour = proc() {.async.} =
      try:
        let stream = await incomingConn.incomingStream()
        echo "Received stream in server"

        let chunk1 = await stream.read()
        echo "First chunk: ", chunk1
        let chunk2 = await stream.read()
        echo "Second chunk: ", chunk2
        let chunk3 = await stream.read()
        echo "EOF chunk: ", chunk3

        check:
          stream.isEof

        echo "Server closed"
        await stream.close()

        #echo "Server aborted"
        #stream.abort() # Not interested in RW anything else
      except StreamError:
        echo "Stream error: ", getCurrentExceptionMsg()
      except CancelledError:
        echo "Canceled incoming behavior"

    discard allFutures(outgoingBehaviour(), incomingBehaviour())

    await sleepAsync(1.seconds)

    outgoingConn.close()
    incomingConn.close()

    # Cannot create a stream once closed
    expect ConnectionError:
      discard await outgoingConn.openStream()

    await sleepAsync(1.seconds)

    await client.stop()
    await listener.stop()

    # TODO: destructors: (nice to have:)
    # - lsquic_global_cleanup() to free global resources. 
    # - lsquic_engine_destroy(engine)
    await sleepAsync(2.seconds)
