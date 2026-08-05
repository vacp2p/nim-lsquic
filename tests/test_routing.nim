# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Tests for CID ownership, datagram header parsing and `routeDatagram`, which
## uses both to pick the context a datagram belongs to.
##
## These are internal; `-d:lsquic_testing` (set in tests/nim.cfg) publishes them,
## so they are asserted directly instead of through a handshake that would only
## fail as a timeout.

{.used.}

import chronos, chronos/unittest2/asynctests
import lsquic
import lsquic/[endpoint, lsquic_ffi]
import lsquic/context/context
import ./helpers/[address, clientserver, trackers]

initializeLsquic(true, true)

const dialTimeout = 5.seconds

func makeCid(bytes: openArray[byte]): CidKey =
  var cid = CidKey(len: bytes.len.uint8)
  for i, b in bytes:
    cid.bytes[i] = b
  cid

func makeCid(cidLen: int, fill: byte = 0xAB): CidKey =
  var cid = CidKey(len: cidLen.uint8)
  for i in 0 ..< cidLen:
    cid.bytes[i] = fill
  cid

const
  ClientCid = makeCid([0xC1'u8, 1, 2, 3, 4, 5, 6, 7])
  ServerCid = makeCid([0x5E'u8, 1, 2, 3, 4, 5, 6, 7])
  UnknownCid = makeCid([0xFF'u8, 1, 2, 3, 4, 5, 6, 7])

func nativeCids(cids: openArray[CidKey]): seq[lsquic_cid_t] =
  var native = newSeq[lsquic_cid_t](cids.len)
  for i, cid in cids:
    native[i] = lsquic_cid_t(len: cid.len, buf: cid.bytes)
  native

proc own(ctx: QuicContext, cids: varargs[CidKey]) =
  ## Register CIDs the way lsquic's `ea_new_scids` callback does.
  var native = nativeCids(cids)
  addCids(cast[pointer](ctx), nil, addr native[0], native.len.cuint)

proc disown(ctx: QuicContext, cids: varargs[CidKey]) =
  ## Retire CIDs the way lsquic's `ea_old_scids` callback does.
  var native = nativeCids(cids)
  removeCids(cast[pointer](ctx), nil, addr native[0], native.len.cuint)

proc newTrackingContext(T: typedesc): T =
  let ctx = T()
  ctx.initCidTracking()
  ctx

suite "cid ownership":
  test "registered cids are owned, unknown ones are not":
    let ctx = newTrackingContext(ClientContext)

    check not ctx.ownsCid(ClientCid)

    ctx.own(ClientCid, ServerCid)

    check:
      ctx.ownsCid(ClientCid)
      ctx.ownsCid(ServerCid)
      not ctx.ownsCid(UnknownCid)

  test "retired cids are dropped, the rest are kept":
    let ctx = newTrackingContext(ClientContext)
    ctx.own(ClientCid, ServerCid)

    ctx.disown(ClientCid)

    check:
      not ctx.ownsCid(ClientCid)
      ctx.ownsCid(ServerCid)

  test "cid identity ignores the bytes past the cid length":
    # lsquic hands us a fixed-size buffer and a length, only the first `len`
    # bytes identify the connection. A key that carried the buffer tail would
    # never match the key `packetDcid` builds from the wire.
    const
      Cid = makeCid(4)
      LongerCid = makeCid(6)
      Buffer = makeCid(MAX_CID_LEN) # the whole fixed buffer, tail included

    let ctx = newTrackingContext(ClientContext)
    var native = lsquic_cid_t(len: Cid.len, buf: Buffer.bytes)

    addCids(cast[pointer](ctx), nil, addr native, 1)

    check:
      ctx.ownsCid(Cid)
      # a longer cid sharing that prefix is a different connection
      not ctx.ownsCid(LongerCid)

  test "cids at both ends of the length range are tracked":
    for cidLen in [1, MAX_CID_LEN]:
      checkpoint("cidLen=" & $cidLen)
      let
        ctx = newTrackingContext(ClientContext)
        cid = makeCid(cidLen)
      ctx.own(cid)

      check ctx.ownsCid(cid)

const
  ## The first byte of a QUIC packet, bit by bit (RFC 9000 17.2/17.3):
  ##
  ##   long header:  1 F T T  R R P P
  ##   short header: 0 F S    R R K P P
  ##
  ## Routing looks at the header form (bit 7), the fixed bit F and, on a long
  ## header, the two packet type bits T. Everything below them is payload
  ## framing the endpoint never reads.
  LongHeaderForm = 0b1000_0000'u8
  FixedBit = 0b0100_0000'u8

  LongTypeInitial = 0b0000_0000'u8 # type bits 00
  LongTypeZeroRtt = 0b0001_0000'u8 # type bits 01
  LongTypeHandshake = 0b0010_0000'u8 # type bits 10
  LongTypeRetry = 0b0011_0000'u8 # type bits 11

  # reserved and packet number bits, below the type - set them all to prove
  # they are not part of the classification
  LowBits = 0b0000_1111'u8

  InitialFirstByte = LongHeaderForm or FixedBit or LongTypeInitial
  InitialWithLowBitsSet = InitialFirstByte or LowBits
  InitialWithoutFixedBit = LongHeaderForm or LongTypeInitial
  ZeroRttFirstByte = LongHeaderForm or FixedBit or LongTypeZeroRtt
  HandshakeFirstByte = LongHeaderForm or FixedBit or LongTypeHandshake
  RetryFirstByte = LongHeaderForm or FixedBit or LongTypeRetry

  ShortFirstByte = FixedBit # header form bit clear

const
  QuicVersion1 = [0x00'u8, 0x00, 0x00, 0x01]
  LongHeaderPrefixLen = 1 + QuicVersion1.len + 1 # first byte, version, dcid length
  ShortHeaderPrefixLen = 1 # first byte

func longHeaderPacket(
    dcid: CidKey, firstByte: byte = InitialFirstByte, declaredLen: uint8 = dcid.len
): seq[byte] =
  ## first byte, 4-byte version, DCID length, DCID, SCID length, then payload.
  ## `declaredLen` overrides the DCID length byte to build a malformed header.
  var packet = @[firstByte]
  packet.add(QuicVersion1)
  packet.add(declaredLen)
  for i in 0 ..< dcid.len.int:
    packet.add(dcid.bytes[i])
  packet.add(0'u8) # zero-length SCID
  packet.add(newSeq[byte](8))
  packet

func shortHeaderPacket(dcid: CidKey, firstByte: byte = ShortFirstByte): seq[byte] =
  ## A short header has no length byte: the DCID is `scidLen()` bytes wide.
  var packet = @[firstByte]
  for i in 0 ..< dcid.len.int:
    packet.add(dcid.bytes[i])
  packet.add(newSeq[byte](8))
  packet

suite "datagram header parsing":
  test "the short header cid is read at the engine's cid width":
    # a short header carries no length byte, so this width is the only thing
    # that tells the endpoint where the routing cid ends
    let endpoint = QuicEndpoint()
    var cid = CidKey()

    check endpoint.packetDcid(shortHeaderPacket(ClientCid), cid)
    check cid == ClientCid

  test "the long header cid is read at its declared length":
    let endpoint = QuicEndpoint()
    var cid = CidKey()

    for cidLen in [1, 4, 8, MAX_CID_LEN]:
      checkpoint("long header dcid length=" & $cidLen)
      let dcid = makeCid(cidLen, byte(cidLen))
      check endpoint.packetDcid(longHeaderPacket(dcid), cid)
      check cid == dcid

  test "malformed datagrams carry no routing cid":
    let endpoint = QuicEndpoint()
    let cases = {
      "empty datagram": newSeq[byte](),
      "zero length dcid": longHeaderPacket(makeCid(0)),
      "dcid longer than the maximum":
        longHeaderPacket(makeCid(MAX_CID_LEN), declaredLen = uint8(MAX_CID_LEN + 1)),
      "long header cut inside the dcid":
        longHeaderPacket(ClientCid)[0 ..< LongHeaderPrefixLen + 2],
      "short header cut inside the dcid":
        shortHeaderPacket(ClientCid)[0 ..< ShortHeaderPrefixLen + 3],
    }

    for (name, packet) in cases:
      checkpoint(name)
      var cid = CidKey()
      check not endpoint.packetDcid(packet, cid)

  test "only long header initial packets count as initial":
    # this is the rung that hands an unknown cid to the server context; every
    # other long header type has to fall through to the drop
    check:
      isIetfInitial(longHeaderPacket(ClientCid))
      isIetfInitial(longHeaderPacket(ClientCid, firstByte = InitialWithLowBitsSet))
      not isIetfInitial(longHeaderPacket(ClientCid, firstByte = ZeroRttFirstByte))
      not isIetfInitial(longHeaderPacket(ClientCid, firstByte = HandshakeFirstByte))
      not isIetfInitial(longHeaderPacket(ClientCid, firstByte = RetryFirstByte))
      not isIetfInitial(longHeaderPacket(ClientCid, firstByte = InitialWithoutFixedBit))
      not isIetfInitial(shortHeaderPacket(ClientCid))
      not isIetfInitial(newSeq[byte]())

suite "datagram routing":
  teardown:
    checkTrackers()

  asyncTest "the only engine on a socket takes every datagram":
    let listenOnly = makeEndpoint(AutoAddressIP4, {CanListen})
    let dialOnly = makeDialEndpoint(AddressFamily.IPv4)
    defer:
      await allFutures(listenOnly.stop(), dialOnly.stop())

    # a dial-only endpoint has no client context until it dials
    let accepting = listenOnly.accept()
    let outgoing = await dialOnly.dial(listenOnly.localAddress()).wait(dialTimeout)
    let incoming = await accepting.wait(dialTimeout)

    let address = listenOnly.localAddress()
    check:
      # one engine on the socket, so the cid is never read
      listenOnly.routeDatagram(shortHeaderPacket(UnknownCid), address, address) ==
        {rtServer}
      dialOnly.routeDatagram(shortHeaderPacket(UnknownCid), address, address) ==
        {rtClient}

    outgoing.close()
    incoming.close()
    await allFutures(outgoing.closedFuture(), incoming.closedFuture())

  asyncTest "an unknown cid reaches the server context only in an initial packet":
    # a self-dial puts both engines on one socket, so the cid decides
    let endpoint = makeEndpoint(AutoAddressIP4)
    defer:
      await endpoint.stop()

    let accepting = endpoint.accept()
    let outgoing = await endpoint.dial(endpoint.localAddress()).wait(dialTimeout)
    let incoming = await accepting.wait(dialTimeout)

    let address = endpoint.localAddress()
    check:
      # an unknown cid is worth handing over only when it can open a connection
      endpoint.routeDatagram(longHeaderPacket(UnknownCid), address, address) ==
        {rtServer}
      endpoint.routeDatagram(shortHeaderPacket(UnknownCid), address, address) == {}

    outgoing.close()
    incoming.close()
    await allFutures(outgoing.closedFuture(), incoming.closedFuture())
