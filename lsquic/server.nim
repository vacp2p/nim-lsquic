# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos, results
import ./[errors, connection, tlsconfig, endpoint, certificateverifier, socketconfig]

type
  QuicServer* = ref object of RootObj
    tlsConfig: TLSConfig
    socketConfig: QuicSocketConfig

  Listener* = ref object of RootObj
    endpoint: QuicEndpoint

proc new*(
    t: typedesc[QuicServer],
    tlsConfig: TLSConfig,
    socketConfig: QuicSocketConfig = DefaultQuicSocketConfig,
): QuicServer {.raises: [QuicConfigError].} =
  if tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")
  socketConfig.validate()
  return QuicServer(tlsConfig: tlsConfig, socketConfig: socketConfig)

proc newListener*(
    tlsConfig: TLSConfig,
    address: TransportAddress,
    socketConfig: QuicSocketConfig = DefaultQuicSocketConfig,
): Result[Listener, string] =
  try:
    ok(
      Listener(
        endpoint:
          QuicEndpoint.new(tlsConfig, address, {CanListen, CanDial}, socketConfig)
      )
    )
  except QuicConfigError, QuicError, TransportOsError:
    err(getCurrentExceptionMsg())

proc listen*(
    self: QuicServer, address: TransportAddress
): Listener {.raises: [QuicError].} =
  newListener(self.tlsConfig, address, self.socketConfig).valueOr:
    raise newException(QuicError, error)

proc listen*(
    self: QuicServer, address: TransportAddress, socketConfig: QuicSocketConfig
): Listener {.raises: [QuicError].} =
  newListener(self.tlsConfig, address, socketConfig).valueOr:
    raise newException(QuicError, error)

proc accept*(
    listener: Listener
): Future[Connection] {.async: (raises: [CancelledError, TransportError]).} =
  await listener.endpoint.accept()

proc dial*(
    listener: Listener, address: TransportAddress
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  await listener.endpoint.dial(address)

proc dial*(
    listener: Listener, address: TransportAddress, certVerifier: CertificateVerifier
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  if certVerifier.isNil:
    raise newException(QuicError, "certificate verifier is nil")

  await listener.endpoint.dial(address, certVerifier)

proc localAddress*(
    listener: Listener
): TransportAddress {.raises: [TransportOsError].} =
  listener.endpoint.localAddress()

proc stop*(listener: Listener) {.async: (raises: [CancelledError]).} =
  await listener.endpoint.stop()
