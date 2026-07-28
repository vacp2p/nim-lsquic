# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Tests for CID ownership and datagram header parsing - the inputs
## `receiveDatagram` uses to pick the context a datagram belongs to.
##
## `scidLen`, `packetDcid` and `isIetfInitial` are internal; `-d:lsquic_testing`
## (set in tests/nim.cfg) publishes them, so they are asserted directly instead
## of through a handshake that would only fail as a timeout.

{.used.}

import std/sequtils
import chronos, chronos/unittest2/asynctests
import lsquic/[endpoint, lsquic_ffi]
import lsquic/context/context

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
  ClientCid = @[0xC1'u8, 1, 2, 3, 4, 5, 6, 7]
  ServerCid = @[0x5E'u8, 1, 2, 3, 4, 5, 6, 7]
  UnknownCid = @[0xFF'u8, 1, 2, 3, 4, 5, 6, 7]

func filledCid(cidLen: int, fill: byte = 0xAB): seq[byte] =
  newSeqWith(cidLen, fill)

func toCidKey(bytes: openArray[byte]): CidKey =
  var key = CidKey(len: bytes.len.uint8)
  for i, b in bytes:
    key.bytes[i] = b
  key

func nativeCids(cids: openArray[seq[byte]]): seq[lsquic_cid_t] =
  ## `len` is copied verbatim even when it overstates lsquic's fixed buffer -
  ## an oversized length is exactly what the length guard has to reject.
  var native = newSeq[lsquic_cid_t](cids.len)
  for i, cid in cids:
    native[i].len = cid.len.uint8
    for j in 0 ..< min(cid.len, MAX_CID_LEN):
      native[i].buf[j] = cid[j]
  native

proc own(ctx: QuicContext, cids: varargs[seq[byte]]) =
  ## Register CIDs the way lsquic's `ea_new_scids` callback does.
  var native = nativeCids(cids)
  addCids(cast[pointer](ctx), nil, addr native[0], native.len.cuint)

proc disown(ctx: QuicContext, cids: varargs[seq[byte]]) =
  ## Retire CIDs the way lsquic's `ea_old_scids` callback does.
  var native = nativeCids(cids)
  removeCids(cast[pointer](ctx), nil, addr native[0], native.len.cuint)

proc newTrackingContext(T: typedesc): T =
  let ctx = T()
  ctx.initCidTracking()
  ctx

func longHeaderPacket(
    dcid: openArray[byte], firstByte: byte = InitialFirstByte
): seq[byte] =
  ## first byte, 4-byte version, DCID length, DCID, SCID length, then payload.
  var packet = @[firstByte, 0x00'u8, 0x00, 0x00, 0x01] # QUIC v1
  packet.add(dcid.len.byte)
  packet.add(dcid)
  packet.add(0'u8) # zero-length SCID
  packet.add(newSeq[byte](8))
  packet

func shortHeaderPacket(
    dcid: openArray[byte], firstByte: byte = ShortFirstByte
): seq[byte] =
  ## A short header has no length byte: the DCID is `scidLen()` bytes wide.
  var packet = @[firstByte]
  packet.add(dcid)
  packet.add(newSeq[byte](8))
  packet

suite "cid ownership":
  test "registered cids are owned, unknown ones are not":
    let ctx = newTrackingContext(ClientContext)

    check not ctx.ownsCid(toCidKey(ClientCid))

    ctx.own(ClientCid, ServerCid)

    check:
      ctx.ownsCid(toCidKey(ClientCid))
      ctx.ownsCid(toCidKey(ServerCid))
      not ctx.ownsCid(toCidKey(UnknownCid))

  test "retired cids are dropped, the rest are kept":
    let ctx = newTrackingContext(ClientContext)
    ctx.own(ClientCid, ServerCid)

    ctx.disown(ClientCid)

    check:
      not ctx.ownsCid(toCidKey(ClientCid))
      ctx.ownsCid(toCidKey(ServerCid))

  test "cid identity ignores the bytes past the cid length":
    # lsquic hands us a fixed-size buffer and a length, only the first `len`
    # bytes identify the connection. A key that carried the buffer tail would
    # never match the key `packetDcid` builds from the wire.
    let ctx = newTrackingContext(ClientContext)
    var native = lsquic_cid_t(len: 4)
    for i in 0 ..< MAX_CID_LEN:
      native.buf[i] = byte(0xA0 + i)

    addCids(cast[pointer](ctx), nil, addr native, 1)

    check:
      ctx.ownsCid(toCidKey([0xA0'u8, 0xA1, 0xA2, 0xA3]))
      # a longer cid sharing that prefix is a different connection
      not ctx.ownsCid(toCidKey([0xA0'u8, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]))

  test "cid lengths outside 1..MAX_CID_LEN are rejected":
    for cidLen in [0, 1, MAX_CID_LEN, MAX_CID_LEN + 1]:
      checkpoint("cidLen=" & $cidLen)
      let
        ctx = newTrackingContext(ClientContext)
        cid = filledCid(cidLen)
      ctx.own(cid)

      if cidLen == 0 or cidLen > MAX_CID_LEN:
        # nothing was registered, not even a truncated key
        check not ctx.ownsCid(toCidKey(filledCid(min(cidLen, MAX_CID_LEN))))
      else:
        check ctx.ownsCid(toCidKey(cid))

  test "nil contexts and nil cid arrays are ignored":
    # these run as callbacks from C: a missing guard is a crash, not an error
    let
      ctx = newTrackingContext(ClientContext)
      missing: ClientContext = nil

    addCids(nil, nil, nil, 1)
    removeCids(nil, nil, nil, 1)
    addCids(cast[pointer](ctx), nil, nil, 1)
    removeCids(cast[pointer](ctx), nil, nil, 1)
    missing.trackConnectionCid(nil)
    ctx.trackConnectionCid(nil)

    check:
      not missing.ownsCid(toCidKey(ClientCid))
      not ctx.ownsCid(toCidKey(ClientCid))

suite "datagram header parsing":
  test "the short header cid is read at the engine's cid width":
    # a short header carries no length byte, so this width is the only thing
    # that tells the endpoint where the routing cid ends
    let endpoint = QuicEndpoint()
    check endpoint.scidLen() == LSQUIC_DF_SCID_LEN.cuint

    var cid = CidKey()
    check endpoint.packetDcid(shortHeaderPacket(ClientCid), cid)
    check cid == toCidKey(ClientCid)

  test "the long header cid is read at its declared length":
    let endpoint = QuicEndpoint()
    var cid = CidKey()

    for cidLen in [1, 4, 8, MAX_CID_LEN]:
      checkpoint("long header dcid length=" & $cidLen)
      let dcid = filledCid(cidLen, byte(cidLen))
      check endpoint.packetDcid(longHeaderPacket(dcid), cid)
      check cid == toCidKey(dcid)

  test "malformed datagrams carry no routing cid":
    let endpoint = QuicEndpoint()
    let cases = {
      "empty datagram": newSeq[byte](),
      "zero length dcid": longHeaderPacket(newSeq[byte]()),
      "dcid longer than the maximum": longHeaderPacket(filledCid(MAX_CID_LEN + 1)),
      "long header cut inside the dcid": longHeaderPacket(ClientCid)[0 ..< 8],
      "short header cut inside the dcid": @[ShortFirstByte, 1, 2, 3],
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
