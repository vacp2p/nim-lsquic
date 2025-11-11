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
      await sleepAsync(2.seconds)
      echo "CLOSING!"
      echo stream.close()
      await sleepAsync(10.seconds)


    let incomingBehaviour = proc() {.async.} =
      try:
        let stream = await incomingConn.incomingStream()
        echo "Received stream in server"
      except CancelledError:
        echo "Canceled incoming behavior"

    discard allFutures(outgoingBehaviour(), incomingBehaviour())

    await sleepAsync(1.seconds)

    #outgoingConn.close()
    #incomingConn.close()

    #await client.stop()
    #await listener.stop()

    # CLOSE WRITE, CLOSE READ, READ / WRITE / RESET
    # -- Create a write buffer
    # CLOSE ALL EVENT LOOPS RELATED TO WRITING / READING
    # TODO: destructors?
    # chronicles topics

    await sleepAsync(10.seconds)
