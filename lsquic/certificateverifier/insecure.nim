# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ./certificateverifier

type InsecureCertificateVerifier* = ref object of CertificateVerifier

proc init*(
    t: typedesc[InsecureCertificateVerifier]
): InsecureCertificateVerifier {.gcsafe.} =
  return InsecureCertificateVerifier()

method verify*(
    self: InsecureCertificateVerifier,
    serverName: string,
    derCertificates: seq[seq[byte]],
): bool =
  return true
