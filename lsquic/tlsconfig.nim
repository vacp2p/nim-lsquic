# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/sets
import results
import ./[errors, certificateverifier, lsquic_ffi]

type TLSConfig* = ref object
  certVerifier*: Opt[CertificateVerifier]
  certificate*: seq[byte]
  key*: seq[byte]
  alpnWire*: string

proc new*(
    T: typedesc[TLSConfig],
    certificate: seq[byte] = @[],
    key: seq[byte] = @[],
    alpn: HashSet[string] = initHashSet[string](),
    certVerifier: Opt[CertificateVerifier] = Opt.none(CertificateVerifier),
): T =
  # In a config, certificate and keys are optional, but if using them, both must
  # be specified at the same time
  if certificate.len != 0 or key.len != 0:
    if certificate.len == 0:
      raise newException(QuicConfigError, "certificate is required in TLSConfig")

    if key.len == 0:
      raise newException(QuicConfigError, "key is required in TLSConfig")

  var alpnWire = newString(0)
  for a in alpn:
    alpnWire.add chr(a.len)
    alpnWire.add a

  TLSConfig(
    alpnWire: alpnWire, certVerifier: certVerifier, certificate: certificate, key: key
  )

proc toX509*(pemCertificate: seq[byte]): Result[ptr X509, string] =
  var
    bio = BIO_new_mem_buf(addr pemCertificate[0], ossl_ssize_t(pemCertificate.len))
    x509 = PEM_read_bio_X509(bio, nil, nil, nil)
  if BIO_free(bio) != 1:
    return err("could not free x509 bio")
  ok(x509)

proc toPKey*(pemKey: seq[byte]): Result[ptr EVP_PKEY, string] =
  var
    bio = BIO_new_mem_buf(addr pemKey[0], ossl_ssize_t(pemKey.len))
    p = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
  if BIO_free(bio) != 1:
    return err("could not free pkey bio")
  ok(p)
