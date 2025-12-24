# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ./certificateverifier

type
  certificateVerifierCB* =
    proc(serverName: string, derCertificates: seq[seq[byte]]): bool {.gcsafe.}

  CustomCertificateVerifier* = ref object of CertificateVerifier
    verifierCB: certificateVerifierCB

method verify*(
    self: CustomCertificateVerifier, serverName: string, derCertificates: seq[seq[byte]]
): bool =
  if self.verifierCB.isNil:
    raiseAssert "custom cert verifier was not setup"
  return self.verifierCB(serverName, derCertificates)

proc init*(
    t: typedesc[CustomCertificateVerifier], certVerifierCB: certificateVerifierCB
): CustomCertificateVerifier {.gcsafe.} =
  let response = CustomCertificateVerifier()
  response.verifierCB = certVerifierCB
  return response
