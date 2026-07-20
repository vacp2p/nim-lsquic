# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

{.used.}

import chronos, chronos/unittest2/asynctests, results, chronicles, sequtils
import lsquic
import ./helpers/clientserver

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

initializeLsquic(true, true)

proc runConnectionTest(
    listenAddress: TransportAddress, dialAddress: TransportAddress
) {.async.} =
  let client = makeClient()
  let server = makeServer()
  let listener = server.listen(listenAddress)
  let boundAddress = listener.localAddress()
  defer:
    await allFutures(client.stop(), listener.stop())
  let accepting = listener.accept()
  let dialing = client.dial(dialAddress)

  let outgoingConn = await dialing
  let incomingConn = await accepting

  check:
    outgoingConn.certificates().len == 1
    incomingConn.certificates().len == 1
    outgoingConn.remoteAddress().family == dialAddress.family
    outgoingConn.remoteAddress().port == dialAddress.port
    incomingConn.localAddress().family == boundAddress.family
    incomingConn.localAddress().port == boundAddress.port
    outgoingConn.localAddress().port == incomingConn.remoteAddress().port

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
      var received: seq[byte]
      while true:
        let n = await stream.readOnce(buf)
        if n == 0:
          break
        received.add(buf[0 ..< n])

      check:
        received == @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        stream.isEof

      let eofRead = await stream.readOnce(buf)
      check eofRead == 0

      echo "Server closed"
      await stream.close()

      #echo "Server aborted"
      #stream.abort() # Not interested in RW anything else
    except StreamError:
      raiseAssert "Stream error: " & getCurrentExceptionMsg()
    except CancelledError:
      raiseAssert "Canceled incoming behavior"

  await allFutures(outgoingBehaviour(), incomingBehaviour())

  outgoingConn.close()
  incomingConn.close()
  await allFutures(outgoingConn.closedFuture(), incomingConn.closedFuture())

  # Cannot create a stream once closed
  expect ConnectionClosedError:
    discard await outgoingConn.openStream()

proc runConnectionTest(address: TransportAddress) {.async.} =
  await runConnectionTest(address, address)

proc runEndpointAcceptTest(address: TransportAddress) {.async.} =
  let client = makeClient()
  let endpoint = makeEndpoint(address, {CanListen})
  let boundAddress = endpoint.localAddress()
  defer:
    await allFutures(client.stop(), endpoint.stop())

  let accepting = endpoint.accept()
  let outgoingConn = await client.dial(boundAddress)
  let incomingConn = await accepting

  check:
    outgoingConn.certificates().len == 1
    incomingConn.certificates().len == 1
    incomingConn.localAddress().port == boundAddress.port

  outgoingConn.close()
  incomingConn.close()
  await allFutures(outgoingConn.closedFuture(), incomingConn.closedFuture())

proc runEndpointSharedSocketDialTest(address: TransportAddress) {.async.} =
  let endpoint = makeEndpoint(address)
  let boundAddress = endpoint.localAddress()
  defer:
    await endpoint.stop()

  let accepting = endpoint.accept()
  let outgoingConn = await endpoint.dial(boundAddress)
  let incomingConn = await accepting

  check:
    outgoingConn.localAddress().port == boundAddress.port
    incomingConn.localAddress().port == boundAddress.port
    incomingConn.remoteAddress().port == boundAddress.port

  outgoingConn.close()
  incomingConn.close()
  await allFutures(outgoingConn.closedFuture(), incomingConn.closedFuture())

proc runEndpointDialOnlyTest(address: TransportAddress) {.async.} =
  let server = makeServer()
  let listener = server.listen(address)
  let boundAddress = listener.localAddress()
  let endpoint = makeDialEndpoint(boundAddress.family)
  defer:
    await allFutures(listener.stop(), endpoint.stop())

  let accepting = listener.accept()
  let outgoingConn = await endpoint.dial(boundAddress)
  let incomingConn = await accepting

  check:
    outgoingConn.remoteAddress().port == boundAddress.port
    incomingConn.localAddress().port == boundAddress.port

  outgoingConn.close()
  incomingConn.close()
  await allFutures(outgoingConn.closedFuture(), incomingConn.closedFuture())

proc runEndpointSharedSocketCrossDialTest(address: TransportAddress) {.async.} =
  let endpointA = makeEndpoint(address)
  let endpointB = makeEndpoint(address)
  let addressA = endpointA.localAddress()
  let addressB = endpointB.localAddress()
  defer:
    await allFutures(endpointA.stop(), endpointB.stop())

  let acceptInitial = endpointB.accept()
  let initialOutgoing = await endpointA.dial(addressB)
  let initialIncoming = await acceptInitial

  check:
    initialOutgoing.localAddress().port == addressA.port
    initialOutgoing.remoteAddress().port == addressB.port
    initialIncoming.localAddress().port == addressB.port
    initialIncoming.remoteAddress().port == addressA.port

  let
    acceptA = endpointA.accept()
    acceptB = endpointB.accept()
    dialAtoB = endpointA.dial(addressB)
    dialBtoA = endpointB.dial(addressA)

  let
    outgoingAtoB = await dialAtoB.wait(5.seconds)
    outgoingBtoA = await dialBtoA.wait(5.seconds)
    incomingA = await acceptA.wait(5.seconds)
    incomingB = await acceptB.wait(5.seconds)

  check:
    outgoingAtoB.localAddress().port == addressA.port
    outgoingAtoB.remoteAddress().port == addressB.port
    outgoingBtoA.localAddress().port == addressB.port
    outgoingBtoA.remoteAddress().port == addressA.port
    incomingA.localAddress().port == addressA.port
    incomingA.remoteAddress().port == addressB.port
    incomingB.localAddress().port == addressB.port
    incomingB.remoteAddress().port == addressA.port

  let conns = @[
    initialOutgoing, initialIncoming, outgoingAtoB, outgoingBtoA, incomingA, incomingB
  ]
  for conn in conns:
    conn.close()

  await allFutures(conns.mapIt(it.closedFuture()))

proc runConcurrentStreamOpenTest(address: TransportAddress) {.async.} =
  const streamCount = 16

  let client = makeClient()
  let server = makeServer()
  let listener = server.listen(address)
  defer:
    await allFutures(client.stop(), listener.stop())

  let accepting = listener.accept()
  let dialing = client.dial(address)

  let outgoingConn = await dialing
  let incomingConn = await accepting

  var received = newSeq[bool](streamCount)

  let receiveAll = proc() {.async.} =
    for _ in 0 ..< streamCount:
      let stream = await incomingConn.incomingStream()
      var id: array[1, byte]
      let n = await stream.readOnce(id[0].addr, id.len)
      check n == 1
      check id[0].int < streamCount
      received[id[0].int] = true
      await stream.close()

  var sendAll: seq[Future[void]]
  for i in 0 ..< streamCount:
    sendAll.add(
      (
        proc(idx: int): Future[void] {.async.} =
          let stream = await outgoingConn.openStream()
          await stream.write(@[byte(idx)])
          await stream.close()
      )(i)
    )

  await allFutures(receiveAll(), allFutures(sendAll))

  for seen in received:
    check seen

proc runCloseNotifiesPeerOnce(
    address: TransportAddress, closeIncomingSide: bool
) {.async.} =
  let client = makeClient()
  let server = makeServer()
  let listener = server.listen(address)
  let boundAddress = listener.localAddress()
  defer:
    await allFutures(client.stop(), listener.stop())

  let accepting = listener.accept()
  let outgoingConn = await client.dial(boundAddress)
  let incomingConn = await accepting

  let (closingConn, victimConn) =
    if closeIncomingSide:
      (incomingConn, outgoingConn)
    else:
      (outgoingConn, incomingConn)

  let victimStream = await victimConn.openStream()
  await victimStream.write(@[1'u8, 2, 3])
  let closerStream = await closingConn.incomingStream()
  var buf = newSeq[byte](3)
  discard await closerStream.readOnce(buf)

  closingConn.close()

  # The victim, not yet aware of the close, keeps opening streams, like
  # keepalive pings and gossip traffic. Streams that reach the closing
  # side after its own streams were torn down must not prevent the close
  # from being signaled.
  let opener = proc() {.async.} =
    try:
      let s = await victimConn.openStream()
      await s.write(@[0'u8])
    except CatchableError:
      discard

  var opens: seq[Future[void]]
  for _ in 0 ..< 20:
    opens.add(opener())
  defer:
    for fut in opens:
      await fut.cancelAndWait()

  # Both sides must observe the close promptly, not via the 30s idle
  # timeout or retransmission give-up.
  await allFutures(outgoingConn.closedFuture(), incomingConn.closedFuture()).wait(
    1.seconds
  )

proc runCloseNotifiesPeerTest(
    address: TransportAddress, closeIncomingSide: bool
) {.async.} =
  for _ in 0 ..< 3:
    await runCloseNotifiesPeerOnce(address, closeIncomingSide)

suite "connection":
  teardown:
    cleanupLsquic()

  asyncTest "ipv4":
    await runConnectionTest(initTAddress("127.0.0.1:12345"))

  asyncTest "ipv6":
    await runConnectionTest(initTAddress("[::1]:12345"))

  asyncTest "ipv6 dual-stack listener accepts ipv4 dial":
    await runConnectionTest(initTAddress("[::]:12347"), initTAddress("127.0.0.1:12347"))

  asyncTest "multiple concurrent stream opens":
    await runConcurrentStreamOpenTest(initTAddress("127.0.0.1:12346"))

  asyncTest "endpoint accepts inbound quic":
    await runEndpointAcceptTest(initTAddress("127.0.0.1:0"))

  asyncTest "endpoint dials from listener socket":
    await runEndpointSharedSocketDialTest(initTAddress("127.0.0.1:0"))

  asyncTest "dial-only endpoint works without listener":
    await runEndpointDialOnlyTest(initTAddress("127.0.0.1:0"))

  asyncTest "endpoints cross-dial from shared listener sockets":
    await runEndpointSharedSocketCrossDialTest(initTAddress("127.0.0.1:0"))

  asyncTest "close by accepting side reaches the dialer":
    await runCloseNotifiesPeerTest(initTAddress("127.0.0.1:0"), true)

  asyncTest "close by dialing side reaches the acceptor":
    await runCloseNotifiesPeerTest(initTAddress("127.0.0.1:0"), false)
