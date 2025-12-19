{.used.}

import chronos, chronos/unittest2/asynctests, results, chronicles
import lsquic
import ./helpers/clientserver

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

initializeLsquic(true, true)

proc runE2ETest(address: TransportAddress) {.async.} =
  let client = makeClient()
  let server = makeServer()
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

      var buf = newSeq[byte](16)
      let n1 = await stream.readOnce(buf)
      let chunk1 = buf[0 ..< n1]
      echo "First chunk: ", chunk1
      let n2 = await stream.readOnce(buf)
      let chunk2 = buf[0 ..< n2]
      echo "Second chunk: ", chunk2
      let n3 = await stream.readOnce(buf)
      let chunk3 = buf[0 ..< n3]
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

suite "connection":
  teardown:
    cleanupLsquic()

  asyncTest "e2e:ipv4":
    await runE2ETest(initTAddress("127.0.0.1:12345"))

  asyncTest "e2e:ipv6":
    skip() # not supported
    return
    await runE2ETest(initTAddress("[::1]:12345"))
