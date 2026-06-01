# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import results, std/sets, chronos, chronicles
import lsquic
import ./certificate

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc makeTLSConfig*(): TLSConfig {.raises: [QuicConfigError].} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )

proc makeClient*(): QuicClient {.
    raises: [QuicConfigError, QuicError, TransportOsError]
.} =
  return QuicClient.new(makeTLSConfig())

proc makeServer*(): QuicServer {.raises: [QuicConfigError].} =
  return QuicServer.new(makeTLSConfig())

proc makeEndpoint*(
    address: TransportAddress,
    capabilities: QuicEndpointCapabilities = {CanListen, CanDial},
): QuicEndpoint {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  QuicEndpoint.new(makeTLSConfig(), address, capabilities)

proc makeDialEndpoint*(
    family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  QuicEndpoint.new(makeTLSConfig(), family)
