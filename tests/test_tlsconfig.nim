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
    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), @["test"])

    check cfg.alpnWire == "\x04test"

  test "every alpn value gets its own length prefix":
    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), @["test", "quic-echo"])

    check cfg.alpnWire == "\x04test\x09quic-echo"

  test "hash set alpn remains source compatible":
    let alpn = @["test"].toHashSet()
    let positional = TLSConfig.new(
      testCertificate(), testPrivateKey(), alpn, Opt.none(CertificateVerifier)
    )
    let named = TLSConfig.new(alpn = alpn)

    check positional.alpnWire == "\x04test"
    check named.alpnWire == "\x04test"

  test "duplicate alpn values are rejected":
    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), @["test", "test"])

  test "alpn value of 255 bytes still encodes":
    let protocol = repeat('a', 255)
    let cfg = TLSConfig.new(testCertificate(), testPrivateKey(), @[protocol])

    check:
      cfg.alpnWire.len == 256
      cfg.alpnWire[0].byte.int == 255
      cfg.alpnWire[1 .. ^1] == protocol

  test "alpn value over 255 bytes is not encodable":
    let alpn = @[repeat('a', 256)]

    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), alpn)

  test "empty alpn value is not encodable":
    expect QuicConfigError:
      discard TLSConfig.new(testCertificate(), testPrivateKey(), @[""])

  test "alpn protocol list cannot exceed 65535 bytes":
    var alpn: seq[string]
    for i in 0 .. 256:
      let prefix = $i
      alpn.add(prefix & repeat('a', 255 - prefix.len))

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
