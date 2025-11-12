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

proc logging(ctx: pointer, buf: cstring, len: csize_t): cint {.cdecl.} =
  echo $buf
  return 0

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

suite "connections":
  setup:
    let address = initTAddress("127.0.0.1:12345")

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
      stream.close()

      #echo "Client aborted"
      # stream.abort() # Not interested in RW anything else

    let incomingBehaviour = proc() {.async.} =
      try:
        echo "HERE"
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
        stream.close()

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

    await sleepAsync(1.seconds)

    await client.stop()
    await listener.stop()

    # TODO: perf example
    # TODO: destructors: (nice to have:)
    # - lsquic_global_cleanup() to free global resources. 
    # - lsquic_engine_destroy(engine)
    await sleepAsync(2.seconds)
