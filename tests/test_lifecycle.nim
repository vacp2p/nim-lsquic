# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import chronos, chronos/unittest2/asynctests, results, chronicles
import lsquic
import lsquic/[datagram]
import lsquic/context/[client, context, io]
import ./helpers/[address, certificate, clientserver, stream]

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

initializeLsquic(true, true)

suite "lifecycle":
  asyncTest "listener stop makes accept fail":
    let server = makeServer()
    let listener = server.listen(AutoAddressIP4)
    let accepting = listener.accept()

    await listener.stop()

    expect TransportError:
      discard await accepting

  asyncTest "listener stop fails all pending accepts":
    let server = makeServer()
    let listener = server.listen(AutoAddressIP4)
    let accepting1 = listener.accept()
    let accepting2 = listener.accept()
    let accepting3 = listener.accept()

    await listener.stop()

    expect TransportError:
      discard await accepting1
    expect TransportError:
      discard await accepting2
    expect TransportError:
      discard await accepting3

  asyncTest "connection close propagates to peer":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    peers.outgoing.close()

    check (await peers.outgoing.closedFuture().withTimeout(2.seconds))
    check (await peers.incoming.closedFuture().withTimeout(2.seconds))
    check peers.incoming.isClosed

  asyncTest "accept skips closed connection and client redials":
    let server = makeServer()
    let listener = server.listen(AutoAddressIP4)
    let address = listener.localAddress()
    let client = makeClient()
    var accepted: Future[Connection]
    var incomingStream: Future[Stream]
    defer:
      if not accepted.isNil and not accepted.finished:
        await accepted.cancelAndWait()
      if not incomingStream.isNil and not incomingStream.finished:
        await incomingStream.cancelAndWait()
      await allFutures(client.stop(), listener.stop())

    let stale = await client.dial(address)
    stale.abort()
    check (await stale.closedFuture().withTimeout(2.seconds))

    accepted = listener.accept()
    let outgoing = await client.dial(address)
    check (await accepted.withTimeout(2.seconds))
    let incoming = await accepted

    incomingStream = incoming.incomingStream()
    let outgoingStream = await outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    check (await incomingStream.withTimeout(2.seconds))

    let acceptedStream = await incomingStream
    var buf = newSeq[byte](1)
    check (await acceptedStream.readOnce(buf)) == 1
    check buf[0] == 1

    await outgoingStream.close()
    await acceptedStream.close()
    outgoing.close()
    incoming.close()

  asyncTest "client stop closes active connections":
    let peers = await connectPeers()

    await peers.client.stop()

    check (await peers.outgoing.closedFuture().withTimeout(2.seconds))
    check (await peers.incoming.closedFuture().withTimeout(2.seconds))

    peers.incoming.close()
    await peers.listener.stop()

  asyncTest "operations fail after connection close":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    peers.outgoing.close()
    check (await peers.outgoing.closedFuture().withTimeout(2.seconds))
    check (await peers.incoming.closedFuture().withTimeout(2.seconds))

    expect ConnectionClosedError:
      discard await peers.outgoing.openStream()

    expect ConnectionClosedError:
      discard await peers.incoming.incomingStream()

  asyncTest "abort wakes pending incoming stream":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let incomingWaiting = peers.incoming.incomingStream()
    peers.outgoing.abort()

    expect ConnectionClosedError:
      discard await incomingWaiting

  asyncTest "cancel pending outgoing streams clears queue":
    let quicConn = QuicConnection(incoming: newAsyncQueue[Stream]())
    let stream1 = Stream.new()
    let stream2 = Stream.new()
    let pending1 = quicConn.addPendingStream(stream1)
    let pending2 = quicConn.addPendingStream(stream2)

    quicConn.cancelPending()

    expect ConnectionError:
      await pending1
    expect ConnectionError:
      await pending2
    check quicConn.popPendingStream(nil).isNone()

  asyncTest "abort after open stream still closes connection":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let opening = peers.outgoing.openStream()
    peers.outgoing.abort()
    check (await opening.withTimeout(2.seconds))
    let stream = await opening
    check (await peers.outgoing.closedFuture().withTimeout(2.seconds))

    expect StreamError:
      await stream.write(@[1'u8])

  asyncTest "write after close raises stream error":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    let incomingStream = await peers.incoming.incomingStream()
    var kickoff = newSeq[byte](1)
    check (await incomingStream.readOnce(kickoff)) == 1
    check kickoff[0] == 1

    await outgoingStream.close()

    expect StreamError:
      await outgoingStream.write(@[1'u8])

    var buf = newSeq[byte](8)
    check (await incomingStream.readOnce(buf)) == 0
    await incomingStream.close()

  asyncTest "cancel pending write clears stream write task":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    # 16 MB exceeds the send window, so the write parks with a pending write task
    let writing = outgoingStream.write(newData(16 * 1024 * 1024, 0x7A'u8))

    check outgoingStream.toWrite.isSome

    await writing.cancelAndWait()

    check outgoingStream.toWrite.isNone()

  asyncTest "read once returns zero repeatedly after eof":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[9'u8, 8, 7, 6])
    let incomingStream = await peers.incoming.incomingStream()
    await outgoingStream.close()

    check (await incomingStream.readStreamTillEOF()) == @[9'u8, 8, 7, 6]

    var buf = newSeq[byte](8)
    check (await incomingStream.readOnce(buf)) == 0
    check (await incomingStream.readOnce(buf)) == 0
    await incomingStream.close()

  asyncTest "blocked read completes when peer half closes":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[42'u8])
    let incomingStream = await peers.incoming.incomingStream()
    var firstChunk = newSeq[byte](1)
    check (await incomingStream.readOnce(firstChunk)) == 1
    check firstChunk[0] == 42

    var buf = newSeq[byte](8)
    let reading = incomingStream.readOnce(buf)

    await sleepAsync(100.milliseconds)
    check not reading.finished

    await outgoingStream.close()

    check (await reading.withTimeout(2.seconds))
    check (await reading) == 0
    await incomingStream.close()

  asyncTest "close then EOF retires peer-initiated stream credit":
    const StreamCount = 120
    const StreamCreditTimeout = 30.seconds
    let peers = await connectPeers()
    defer:
      await peers.stop()

    proc openStreamWithTimeout(
        conn: Connection
    ): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
      let opening = conn.openStream()
      if not await opening.withTimeout(StreamCreditTimeout):
        await opening.cancelAndWait()
        doAssert false,
          "timed out opening stream; close+EOF should retire stream credit"
      await opening

    proc serve() {.async.} =
      for i in 0 ..< StreamCount:
        let stream = await peers.incoming.incomingStream()
        var buf = newSeq[byte](1)
        check (await stream.readOnce(buf)) == 1
        check buf[0] == byte(i mod 256)

        await stream.write(@[byte((i + 1) mod 256)])
        await stream.close()
        check (await stream.readOnce(buf)) == 0

    let serving = serve()

    for i in 0 ..< StreamCount:
      let stream = await peers.outgoing.openStreamWithTimeout()
      await stream.write(@[byte(i mod 256)])
      await stream.close()

      var buf = newSeq[byte](1)
      check (await stream.readOnce(buf)) == 1
      check buf[0] == byte((i + 1) mod 256)
      check (await stream.readOnce(buf)) == 0

    if not await serving.withTimeout(StreamCreditTimeout):
      await serving.cancelAndWait()
      doAssert false,
        "timed out serving streams; close+EOF should not leave stream handlers blocked"
    await serving

  asyncTest "cancelled blocked read clears pending read":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let incomingWaiting = peers.incoming.incomingStream()
    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    check (await incomingWaiting.withTimeout(2.seconds))
    let incomingStream = await incomingWaiting

    var firstByte = newSeq[byte](1)
    check (await incomingStream.readOnce(firstByte)) == 1
    check firstByte[0] == 1

    var cancelledBuf = newSeq[byte](8)
    let reading = incomingStream.readOnce(cancelledBuf)

    await sleepAsync(100.milliseconds)
    check not reading.finished
    check incomingStream.toRead.isSome

    await reading.cancelAndWait()

    check incomingStream.toRead.isNone()

    await outgoingStream.write(@[99'u8])
    await sleepAsync(100.milliseconds)
    check cancelledBuf[0] == 0

    var buf = newSeq[byte](1)
    let nextRead = incomingStream.readOnce(buf)
    check (await nextRead.withTimeout(2.seconds))
    check (await nextRead) == 1
    check buf[0] == 99
    await incomingStream.close()

  asyncTest "peer reset":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    let incomingStream = await peers.incoming.incomingStream()

    var firstByte = newSeq[byte](1)
    check (await incomingStream.readOnce(firstByte)) == 1
    check firstByte[0] == 1

    var buf = newSeq[byte](8)
    let reading = incomingStream.readOnce(buf)

    outgoingStream.abort()

    check (await reading.withTimeout(2.seconds))
    check (await reading) == 0
    check incomingStream.isEof

    var isReset = false
    try:
      await incomingStream.write(@[2'u8])
    except StreamResetError as exc:
      isReset = true
      check exc.how == ResetWrite

    check isReset

  asyncTest "zero length reads return zero":
    let stream = Stream.new()
    var empty: seq[byte] = @[]

    check (await stream.readOnce(empty)) == 0

  asyncTest "late datagrams are ignored after context stops":
    let verifier: CertificateVerifier = CustomCertificateVerifier.init(
      proc(serverName: string, derCertificates: seq[seq[byte]]): bool {.gcsafe.} =
        discard serverName
        derCertificates.len > 0
    )
    let tlsConfig = TLSConfig.new(
      testCertificate(), testPrivateKey(), @["test"].toHashSet(), Opt.some(verifier)
    )
    let ctx = ClientContext.new(tlsConfig).valueOr:
      raiseAssert error
    let local = initTAddress("127.0.0.1:12345")
    let remote = initTAddress("127.0.0.1:54321")

    ctx.stop()
    ctx.receive(Datagram(data: @[1'u8, 2, 3]), local, remote)
    ctx.processWhenReady()

    ctx.destroy()
    ctx.receive(Datagram(data: @[4'u8, 5, 6]), local, remote)
    ctx.processWhenReady()
