# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import chronos, chronos/unittest2/asynctests, results
import lsquic
import lsquic/[datagram]
import lsquic/context/[client, context, io, stream]
import ./helpers/[address, certificate, clientserver, stream, trackers]
from lsquic/lsquic_ffi import lsquic_stream_ctx_t, lsquic_conn_t

initializeLsquic(true, true)

const timeout = 2.seconds

suite "lifecycle":
  teardown:
    checkTrackers()

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

    check (await peers.outgoing.closedFuture().withTimeout(timeout))
    check (await peers.incoming.closedFuture().withTimeout(timeout))
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
    check (await stale.closedFuture().withTimeout(timeout))

    accepted = listener.accept()
    let outgoing = await client.dial(address)
    check (await accepted.withTimeout(timeout))
    let incoming = await accepted

    incomingStream = incoming.incomingStream()
    let outgoingStream = await outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    check (await incomingStream.withTimeout(timeout))

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

    check (await peers.outgoing.closedFuture().withTimeout(timeout))
    check (await peers.incoming.closedFuture().withTimeout(timeout))

    peers.incoming.close()
    await peers.listener.stop()

  asyncTest "operations fail after connection close":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    peers.outgoing.close()
    check (await peers.outgoing.closedFuture().withTimeout(timeout))
    check (await peers.incoming.closedFuture().withTimeout(timeout))

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
    check (await opening.withTimeout(timeout))
    let stream = await opening
    check (await peers.outgoing.closedFuture().withTimeout(timeout))

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
    let writing = outgoingStream.write(makeData(16 * 1024 * 1024))

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

    check (await reading.withTimeout(timeout))
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
    check (await incomingWaiting.withTimeout(timeout))
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
    check (await nextRead.withTimeout(timeout))
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

    check (await reading.withTimeout(timeout))
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
    defer:
      onClose(nil, cast[ptr lsquic_stream_ctx_t](stream)) # release the pin
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

  asyncTest "connection operations are guarded after context stops":
    let ctx = ClientContext.new(makeTLSConfig()).valueOr:
      raiseAssert error
    defer:
      ctx.destroy()

    # A stopped context must not act on any connection. We prove that by using an invalid connection pointer
    # While the context is stopped, the calls below must skip it, so the pointer is never used.
    # If a call went through, it would dereference the pointer and crash.
    # The pointer has to be non-nil: these calls already skip a nil connection.
    let quicConn = QuicConnection(lsquicConn: cast[ptr lsquic_conn_t](0xF00D))

    check ctx.isRunning()
    ctx.stop()
    check not ctx.isRunning()

    # While stopped, close and abort must do nothing (never reach the connection).
    ctx.close(quicConn)
    ctx.abort(quicConn)

    # While stopped, makeStream must fail cleanly instead of opening a stream.
    expect ConnectionClosedError:
      ctx.makeStream(quicConn)

  asyncTest "context destroy is idempotent":
    let ctx = ClientContext.new(makeTLSConfig()).valueOr:
      raiseAssert error

    ctx.stop()
    ctx.destroy()
    check not ctx.isRunning()

    # second destroy is a safe no-op: it must not free the engine or SSL_CTX twice.
    ctx.destroy()
    check not ctx.isRunning()

  asyncTest "listen-capable endpoint requires a certificate":
    # QuicEndpoint.new rejects a listen-capable endpoint with no certificate,
    # before any socket or context is created.
    expect QuicConfigError:
      discard QuicEndpoint.new(TLSConfig.new(), AutoAddressIP4, {CanListen})

  asyncTest "endpoint stop is idempotent":
    let endpoint = makeEndpoint(AutoAddressIP4)

    await endpoint.stop()
    # second stop is a safe no-op: the socket is not closed twice.
    await endpoint.stop()

  asyncTest "connection is auto-removed from manager after close":
    let server = makeEndpoint(AutoAddressIP4)
    let client = makeDialEndpoint(AddressFamily.IPv4)
    defer:
      await allFutures(client.stop(), server.stop())

    let accepting = server.accept()
    let outgoing = await client.dial(server.localAddress())
    let incoming = await accepting

    check:
      client.connectionCount == 1
      server.connectionCount == 1

    outgoing.close()
    check:
      await outgoing.closedFuture().withTimeout(timeout)
      await incoming.closedFuture().withTimeout(timeout)

    # Removal from the manager is scheduled on close; yield one tick so it runs
    # before we count.
    await sleepAsync(0.milliseconds)

    check:
      client.connectionCount == 0
      server.connectionCount == 0

  asyncTest "peer reset in both directions merges to read-write":
    let stream = Stream.new()
    defer:
      onClose(nil, cast[ptr lsquic_stream_ctx_t](stream)) # release the pin

    onReset(nil, cast[ptr lsquic_stream_ctx_t](stream), 0.cint)
    check:
      stream.resetHow == ResetRead
      stream.readResetByPeer()
      not stream.writeResetByPeer()
      not stream.closeWrite

    onReset(nil, cast[ptr lsquic_stream_ctx_t](stream), 1.cint)
    check:
      stream.resetHow == ResetReadWrite
      stream.readResetByPeer()
      stream.writeResetByPeer()
      stream.closeWrite

  asyncTest "peer read reset fails a parked read":
    let stream = Stream.new()
    defer:
      onClose(nil, cast[ptr lsquic_stream_ctx_t](stream)) # release the pin
    var buf = newSeq[byte](8)
    let doneFut =
      Future[int].Raising([CancelledError, StreamError]).init("test parked read")
    stream.toRead =
      Opt.some(ReadTask(data: buf[0].addr, dataLen: buf.len, doneFut: doneFut))

    onReset(nil, cast[ptr lsquic_stream_ctx_t](stream), 0.cint)

    check:
      stream.resetHow == ResetRead
      stream.toRead.isNone()

    expect StreamResetError:
      discard await doneFut

  asyncTest "read after read reset raises":
    let stream = Stream.new()
    defer:
      onClose(nil, cast[ptr lsquic_stream_ctx_t](stream)) # release the pin
    stream.markResetByPeer(ResetRead)
    check stream.resetHow == ResetRead

    var buf = newSeq[byte](8)
    expect StreamResetError:
      discard await stream.readOnce(buf)

  asyncTest "nil read destination is rejected":
    let stream = Stream.new()

    expect AssertionDefect:
      discard await stream.readOnce(nil, 8)

  asyncTest "read waiting for the read lock sees the stream closed by the engine":
    let stream = Stream.new()
    # hold the lock so the read parks after its pre-lock checks have passed
    await stream.readLock.acquire()

    var buf = newSeq[byte](8)
    let reading = stream.readOnce(buf)

    stream.closedByEngine = true
    stream.readLock.release()

    # the post-lock re-check keeps the read away from the freed native stream
    check (await reading.withTimeout(timeout))
    check (await reading) == 0

  asyncTest "read waiting for the read lock sees a peer reset":
    let stream = Stream.new()
    await stream.readLock.acquire()

    var buf = newSeq[byte](8)
    let reading = stream.readOnce(buf)

    stream.markResetByPeer(ResetRead)
    stream.readLock.release()

    expect StreamResetError:
      discard await reading

  asyncTest "concurrent reads on one stream are serialized":
    let peers = await connectPeers()
    defer:
      await peers.stop()

    let outgoingStream = await peers.outgoing.openStream()
    await outgoingStream.write(@[1'u8])
    let incomingStream = await peers.incoming.incomingStream()

    var kickoff = newSeq[byte](1)
    check (await incomingStream.readOnce(kickoff)) == 1
    check kickoff[0] == 1

    # Both reads park. A stream has a single pending-read slot, so `readLock` has
    # to keep the second reader out until the first one is done; otherwise the
    # second task would overwrite the first and the first read would hang.
    # The buffer lengths differ so the pending task identifies its owner.
    var firstBuf = newSeq[byte](4)
    var secondBuf = newSeq[byte](8)
    let firstRead = incomingStream.readOnce(firstBuf)
    let secondRead = incomingStream.readOnce(secondBuf)

    await sleepAsync(100.milliseconds)
    check not firstRead.finished
    check not secondRead.finished
    check incomingStream.toRead.valueOr(ReadTask()).dataLen == firstBuf.len

    await outgoingStream.write(@[7'u8])
    check (await firstRead.withTimeout(timeout))
    check (await firstRead) == 1
    check firstBuf[0] == 7

    # only now does the second read take the lock and claim the pending slot
    await sleepAsync(100.milliseconds)
    check not secondRead.finished
    check incomingStream.toRead.valueOr(ReadTask()).dataLen == secondBuf.len

    await outgoingStream.write(@[8'u8])
    check (await secondRead.withTimeout(timeout))
    check (await secondRead) == 1
    check secondBuf[0] == 8

    await incomingStream.close()
