# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import ./[errors, connection, tlsconfig, endpoint]

type QuicClient* = ref object of RootObj
  tlsConfig: TLSConfig
  endpoint4: QuicEndpoint
  endpoint6: QuicEndpoint

proc new*(t: typedesc[QuicClient], tlsConfig: TLSConfig): QuicClient {.raises: [].} =
  QuicClient(tlsConfig: tlsConfig)

proc getEndpoint(
    self: QuicClient, family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  case family
  of AddressFamily.IPv4:
    if self.endpoint4.isNil:
      self.endpoint4 = QuicEndpoint.new(self.tlsConfig, family)

    return self.endpoint4
  of AddressFamily.IPv6:
    if self.endpoint6.isNil:
      self.endpoint6 = QuicEndpoint.new(self.tlsConfig, family)

    return self.endpoint6
  else:
    raise newException(QuicError, "client supports only IPv4/IPv6 address")

proc dial*(
    self: QuicClient, address: TransportAddress
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  await self.getEndpoint(address.family).dial(address)

proc stop*(self: QuicClient) {.async: (raises: [CancelledError]).} =
  if not self.endpoint4.isNil:
    await noCancel self.endpoint4.stop()
  if not self.endpoint6.isNil:
    await noCancel self.endpoint6.stop()
  self.endpoint4 = nil
  self.endpoint6 = nil
