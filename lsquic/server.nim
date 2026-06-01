# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos, results
import ./[errors, tlsconfig, endpoint]

type QuicServer* = ref object of RootObj
  tlsConfig: TLSConfig

type Listener* = QuicEndpoint

proc new*(
    t: typedesc[QuicServer], tlsConfig: TLSConfig
): QuicServer {.raises: [QuicConfigError].} =
  if tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")

  return QuicServer(tlsConfig: tlsConfig)

proc newListener*(
    tlsConfig: TLSConfig, address: TransportAddress
): Result[Listener, string] =
  try:
    ok(QuicEndpoint.new(tlsConfig, address, {CanListen, CanDial}))
  except QuicConfigError, QuicError, TransportOsError:
    err(getCurrentExceptionMsg())

proc listen*(
    self: QuicServer, address: TransportAddress
): Listener {.raises: [QuicError, TransportOsError].} =
  newListener(self.tlsConfig, address).valueOr:
    raise newException(QuicError, error)
