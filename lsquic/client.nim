# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles, results
import ./[errors, connection, tlsconfig, datagram, connectionmanager]
import ./context/[context, io, client]

type QuicClient* = ref object of RootObj
  quicContext: ClientContext
  connman: ConnectionManager
  udp: DatagramTransport

proc new*(
    t: typedesc[QuicClient], tlsConfig: TLSConfig
): QuicClient {.raises: [QuicError, TransportOsError].} =
  let clientCtx = ClientContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)

  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      let datagram = Datagram(data: udp.getMessage())
      clientCtx.receive(datagram, udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpected transport error", errorMsg = e.msg

  let client = QuicClient(
    quicContext: clientCtx,
    udp: newDatagramTransport(onReceive),
    connman: ConnectionManager.new(),
  )
  clientCtx.fd = cint(client.udp.fd)

  client

proc dial*(
    self: QuicClient, address: TransportAddress
): Future[Connection] {.async: (raises: [CancelledError, DialError, TransportOsError]).} =
  var connection =
    newOutgoingConnection(self.quicContext, self.udp.localAddress, address)
  self.connman.addConnection(connection)
  await connection.dial()
  connection

proc stop*(self: QuicClient) {.async: (raises: [CancelledError]).} =
  await noCancel self.connman.stop()
  # Politely wait before closing udp so connections closure go out
  # TODO: this should be ~ 3 times the PTO.
  # Find out if it's possible to react to shutting down the context and
  # lsquic engine. Maybe there's a callback that one can hook to and safely
  # stop the udp transport.
  await noCancel sleepAsync(300.milliseconds)
  await noCancel self.udp.closeWait()
