# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import results, std/sets, chronos, chronicles
import lsquic
import ./[address, certificate]

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc defaultCertificateVerifier*(): CertificateVerifier =
  CustomCertificateVerifier.init(certificateCb)

proc makeTLSConfig*(
    verifier: CertificateVerifier = defaultCertificateVerifier(),
    alpn: HashSet[string] = makeAlpn(),
): TLSConfig {.raises: [QuicConfigError].} =
  TLSConfig.new(testCertificate(), testPrivateKey(), alpn, Opt.some(verifier))

proc makeClient*(
    verifier: CertificateVerifier = defaultCertificateVerifier(),
    alpn: HashSet[string] = makeAlpn(),
): QuicClient {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  return QuicClient.new(makeTLSConfig(verifier, alpn))

proc makeServer*(
    verifier: CertificateVerifier = defaultCertificateVerifier(),
    alpn: HashSet[string] = makeAlpn(),
): QuicServer {.raises: [QuicConfigError].} =
  return QuicServer.new(makeTLSConfig(verifier, alpn))

proc makeEndpoint*(
    address: TransportAddress,
    capabilities: QuicEndpointCapabilities = {CanListen, CanDial},
): QuicEndpoint {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  QuicEndpoint.new(makeTLSConfig(), address, capabilities)

proc makeDialEndpoint*(
    family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  QuicEndpoint.new(makeTLSConfig(), family)

type ConnectedPeers* =
  tuple[
    client: QuicClient, listener: Listener, outgoing: Connection, incoming: Connection
  ]

proc connectPeers*(): Future[ConnectedPeers] {.async.} =
  let client = makeClient()
  let server = makeServer()
  let listener = server.listen(AutoAddressIP4)
  let accepting = listener.accept()
  let outgoing = await client.dial(listener.localAddress())
  let incoming = await accepting

  (client, listener, outgoing, incoming)

proc stop*(peers: ConnectedPeers) {.async.} =
  if not peers.outgoing.isNil:
    peers.outgoing.close()
  if not peers.incoming.isNil:
    peers.incoming.close()
  await allFutures(peers.client.stop(), peers.listener.stop())
