# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import ./[errors, connection, tlsconfig, endpoint, certificateverifier, socketconfig]

type QuicClient* = ref object of RootObj
  tlsConfig: TLSConfig
  socketConfig: QuicSocketConfig
  ip4Endpoint: QuicEndpoint
  ip6Endpoint: QuicEndpoint

proc new*(
    t: typedesc[QuicClient],
    tlsConfig: TLSConfig,
    socketConfig: QuicSocketConfig = DefaultQuicSocketConfig,
): QuicClient {.raises: [].} =
  QuicClient(tlsConfig: tlsConfig, socketConfig: socketConfig)

proc getEndpoint(
    self: QuicClient, family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  case family
  of AddressFamily.IPv4:
    if self.ip4Endpoint.isNil:
      self.ip4Endpoint = QuicEndpoint.new(self.tlsConfig, family, self.socketConfig)

    return self.ip4Endpoint
  of AddressFamily.IPv6:
    if self.ip6Endpoint.isNil:
      self.ip6Endpoint = QuicEndpoint.new(self.tlsConfig, family, self.socketConfig)

    return self.ip6Endpoint
  else:
    raise newException(QuicError, "client supports only IPv4/IPv6 address")

proc dial*(
    self: QuicClient, address: TransportAddress
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  await self.getEndpoint(address.family).dial(address)

proc dial*(
    self: QuicClient, address: TransportAddress, certVerifier: CertificateVerifier
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  await self.getEndpoint(address.family).dial(address, certVerifier)

proc stop*(self: QuicClient) {.async: (raises: [CancelledError]).} =
  var stops: seq[Future[void]]
  if not self.ip4Endpoint.isNil:
    stops.add(noCancel self.ip4Endpoint.stop())
  if not self.ip6Endpoint.isNil:
    stops.add(noCancel self.ip6Endpoint.stop())
  await allFutures(stops)
  self.ip4Endpoint = nil
  self.ip6Endpoint = nil
