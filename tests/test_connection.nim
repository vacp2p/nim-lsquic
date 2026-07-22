# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

{.used.}

import chronos, chronos/unittest2/asynctests, results, sequtils
import lsquic
import ./helpers/[address, clientserver, futures, stream]

initializeLsquic(true, true)

const dialTimeout = 5.seconds

proc runConnectionTest(
    listenAddress: TransportAddress, dialAddress: TransportAddress
) {.async.} =
  let client = makeClient()
  let server = makeServer()
  let listener = server.listen(listenAddress)
  let boundAddress = listener.localAddress()
  # dial the requested address on the port the listener actually bound
  var effectiveDialAddress = dialAddress
  effectiveDialAddress.port = boundAddress.port
  defer:
    await allFutures(client.stop(), listener.stop())
  let accepting = listener.accept()
  let dialing = client.dial(effectiveDialAddress)

  let outgoingConn = await dialing
  let incomingConn = await accepting

  check:
    outgoingConn.certificates().len == 1
    incomingConn.certificates().len == 1
    outgoingConn.remoteAddress().family == effectiveDialAddress.family
    outgoingConn.remoteAddress().port == effectiveDialAddress.port
    incomingConn.localAddress().family == boundAddress.family
    incomingConn.localAddress().port == boundAddress.port
    outgoingConn.localAddress().port == incomingConn.remoteAddress().port

  let outgoingBehaviour = proc() {.async.} =
    let stream = await outgoingConn.openStream()

    await stream.write(@[1'u8, 2, 3, 4, 5])
    await stream.write(@[6'u8, 7, 8, 9, 10])
    await stream.close()

  let incomingBehaviour = proc() {.async.} =
    let stream = await incomingConn.incomingStream()

    let received = await readStreamTillEOF(stream)

    check:
      received == @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]
      stream.isEof

    var buf = newSeq[byte](8)
    check (await stream.readOnce(buf)) == 0

    await stream.close()

  await allFuturesRaising(outgoingBehaviour(), incomingBehaviour())

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
    outgoingAtoB = await dialAtoB.wait(dialTimeout)
    outgoingBtoA = await dialBtoA.wait(dialTimeout)
    incomingA = await acceptA.wait(dialTimeout)
    incomingB = await acceptB.wait(dialTimeout)

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
  let boundAddress = listener.localAddress()
  defer:
    await allFutures(client.stop(), listener.stop())

  let accepting = listener.accept()
  let dialing = client.dial(boundAddress)

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

suite "connection":
  asyncTest "ipv4":
    await runConnectionTest(AutoAddressIP4)

  asyncTest "ipv6":
    await runConnectionTest(AutoAddressIP6)

  asyncTest "ipv6 dual-stack listener accepts ipv4 dial":
    await runConnectionTest(WildcardIP6, AutoAddressIP4)

  asyncTest "multiple concurrent stream opens":
    await runConcurrentStreamOpenTest(AutoAddressIP4)

  asyncTest "endpoint accepts inbound quic":
    await runEndpointAcceptTest(AutoAddressIP4)

  asyncTest "endpoint dials from listener socket":
    await runEndpointSharedSocketDialTest(AutoAddressIP4)

  asyncTest "dial-only endpoint works without listener":
    await runEndpointDialOnlyTest(AutoAddressIP4)

  asyncTest "endpoints cross-dial from shared listener sockets":
    await runEndpointSharedSocketCrossDialTest(AutoAddressIP4)
