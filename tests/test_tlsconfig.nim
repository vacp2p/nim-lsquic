# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sets, strutils]
import results
import unittest2
import boringssl
import lsquic
import lsquic/certificates
import lsquic/lsquic_ffi
import ./helpers/[certificate, trackers]

proc decodeAlpnWire(wire: string): HashSet[string] =
  ## Reverses the ALPN encoding that TLSConfig.new applies, so a test can check
  ## which protocol names ended up on the wire.
  ##
  ## Each name is stored as one byte holding its length followed by the name
  ## itself, and those pairs are concatenated:
  ##
  ##   {"test", "quic-echo"}  ->  "\x04test" & "\x09quic-echo"
  ##
  ## A length byte that points past the end of the buffer means the encoding is
  ## broken, so decoding stops there and the caller gets the names read so far.
  var decoded = initHashSet[string]()
  var i = 0
  while i < wire.len:
    let length = wire[i].byte.int
    if i + 1 + length > wire.len:
      return decoded
    decoded.incl(wire[i + 1 ..< i + 1 + length])
    i += 1 + length
  decoded

proc makeAlpnSet(protocols: varargs[string]): HashSet[string] =
  var alpn = initHashSet[string]()
  for protocol in protocols:
    alpn.incl(protocol)
  alpn

suite "tls config":
  teardown:
    checkTrackers()

  test "certificate requires key":
    expect QuicConfigError:
      discard TLSConfig.new(certificate = testCertificate())

  test "key requires certificate":
    expect QuicConfigError:
      discard TLSConfig.new(key = testPrivateKey())

  test "server requires certificate":
    let cfg = TLSConfig.new()
    expect QuicConfigError:
      discard QuicServer.new(cfg)

  test "single alpn value is encoded":
    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), makeAlpn())

    check cfg.alpnWire == "\x04test"

  test "every alpn value gets its own length prefix":
    let alpn = makeAlpnSet("test", "quic-echo")

    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), alpn)

    # alpn is a HashSet, so the encoder has no order to preserve: decode the
    # wire form back instead of pinning a byte string.
    check:
      cfg.alpnWire.len == (1 + "test".len) + (1 + "quic-echo".len)
      cfg.alpnWire.decodeAlpnWire() == alpn

  test "alpn value of 255 bytes still encodes":
    let protocol = repeat('a', 255)
    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), makeAlpnSet(protocol))

    check:
      cfg.alpnWire.len == 256
      cfg.alpnWire[0].byte.int == 255
      cfg.alpnWire.decodeAlpnWire() == makeAlpnSet(protocol)

  test "alpn value over 255 bytes is not encodable":
    let alpn = makeAlpnSet(repeat('a', 256))

    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), alpn)

  test "empty alpn value is not encodable":
    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), makeAlpnSet(""))

  test "alpn protocol list cannot exceed 65535 bytes":
    var alpn = initHashSet[string]()
    for i in 0 .. 256:
      let prefix = $i
      alpn.incl(prefix & repeat('a', 255 - prefix.len))

    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), alpn)

  test "valid pem certificate parses":
    let parsed = testCertificate().toX509()

    check parsed.isOk()
    let cert = parsed.valueOr:
      nil
    check not cert.isNil
    if not cert.isNil:
      check cert.x509toDERBytes().isSome()
    if not cert.isNil:
      X509_free(cert)

  test "der bytes round trip back to the same certificate":
    # Peers receive these bytes through certificates() and parse them back, so
    # they have to be a complete DER encoding, not a truncated or over-sized
    # copy of the i2d buffer.
    let cert = testCertificate().toX509().valueOr:
        raiseAssert "test certificate must parse: " & error
    defer:
      X509_free(cert)

    let der = cert.x509toDERBytes().valueOr:
      raiseAssert "test certificate must convert to DER"

    var readPos = cast[ptr uint8](unsafeAddr der[0])
    let reparsed = d2i_X509(nil, addr readPos, der.len.clong)
    defer:
      X509_free(reparsed)

    # a rejected encoding leaves reparsed nil, which converts back to Opt.none
    check reparsed.x509toDERBytes() == Opt.some(der)

  test "nil x509 DER conversion is rejected":
    let cert: ptr X509 = nil

    check cert.x509toDERBytes().isNone()

  test "valid pem key parses":
    let parsed = testPrivateKey().toPKey()

    check parsed.isOk()
    let pkey = parsed.valueOr:
      nil
    check not pkey.isNil
    if not pkey.isNil:
      EVP_PKEY_free(pkey)

  test "empty pem values are rejected":
    check @[].toX509().isErr()
    check @[].toPKey().isErr()

  test "invalid pem values are rejected":
    let invalidPem =
      @['n'.byte, 'o'.byte, 't'.byte, ' '.byte, 'p'.byte, 'e'.byte, 'm'.byte]

    check invalidPem.toX509().isErr()
    check invalidPem.toPKey().isErr()
