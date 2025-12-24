# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import results, std/sets, chronos, chronicles
import lsquic
import ./certificate

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc makeClient*(): QuicClient {.
    raises: [QuicConfigError, QuicError, TransportOsError]
.} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let clientTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicClient.new(clientTLSConfig)

proc makeServer*(): QuicServer {.raises: [QuicConfigError].} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let serverTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicServer.new(serverTLSConfig)
