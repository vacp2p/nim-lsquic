# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
import ./[errors, connection, tlsconfig, datagram, connectionmanager]
import ./context/[server, client, context, io]

type
  QuicEndpointCapability* = enum
    CanListen
    CanDial

  QuicEndpointCapabilities* = set[QuicEndpointCapability]

  QuicEndpoint* = ref object of RootObj
    tlsConfig: TLSConfig
    capabilities: QuicEndpointCapabilities
    serverContext: ServerContext
    clientContext: ClientContext
    connman: ConnectionManager
    udp: DatagramTransport
    stopped: bool

proc createServerContext(tlsConfig: TLSConfig): ServerContext {.raises: [QuicError].} =
  ServerContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)

proc createClientContext(tlsConfig: TLSConfig): ClientContext {.raises: [QuicError].} =
  ClientContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)

proc receiveDatagram(
    endpoint: QuicEndpoint, data: seq[byte], local, remote: TransportAddress
) {.raises: [].} =
  if endpoint.isNil or endpoint.stopped:
    return

  if not endpoint.clientContext.isNil:
    endpoint.clientContext.receive(Datagram(data: data), local, remote)
  if not endpoint.serverContext.isNil:
    endpoint.serverContext.receive(Datagram(data: data), local, remote)

proc createUdp(
    endpoint: QuicEndpoint, address: TransportAddress
): DatagramTransport {.raises: [QuicError, TransportOsError].} =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      endpoint.receiveDatagram(udp.getMessage(), udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpected transport error", errorMsg = e.msg

  case address.family
  of AddressFamily.IPv4:
    newDatagramTransport(onReceive, local = address)
  of AddressFamily.IPv6:
    newDatagramTransport6(onReceive, local = address)
  else:
    raise newException(QuicError, "only IPv4/IPv6 address is supported")

proc createUdp(
    endpoint: QuicEndpoint, family: AddressFamily
): DatagramTransport {.raises: [QuicError, TransportOsError].} =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      endpoint.receiveDatagram(udp.getMessage(), udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpected transport error", errorMsg = e.msg

  case family
  of AddressFamily.IPv4:
    newDatagramTransport(onReceive)
  of AddressFamily.IPv6:
    newDatagramTransport6(onReceive)
  else:
    raise newException(QuicError, "client supports only IPv4/IPv6 address")

proc setContextFd(endpoint: QuicEndpoint) {.raises: [].} =
  if not endpoint.serverContext.isNil:
    endpoint.serverContext.fd = cint(endpoint.udp.fd)
  if not endpoint.clientContext.isNil:
    endpoint.clientContext.fd = cint(endpoint.udp.fd)

proc new*(
    _: type QuicEndpoint,
    tlsConfig: TLSConfig,
    address: TransportAddress,
    capabilities: QuicEndpointCapabilities = {CanListen, CanDial},
): QuicEndpoint {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  if CanListen in capabilities and tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")

  let serverContext =
    if CanListen in capabilities:
      createServerContext(tlsConfig)
    else:
      nil

  result = QuicEndpoint(
    tlsConfig: tlsConfig,
    capabilities: capabilities,
    serverContext: serverContext,
    connman: ConnectionManager.new(),
  )
  result.udp = result.createUdp(address)
  result.setContextFd()

proc new*(
    _: type QuicEndpoint, tlsConfig: TLSConfig, family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  result = QuicEndpoint(
    tlsConfig: tlsConfig, capabilities: {CanDial}, connman: ConnectionManager.new()
  )
  result.udp = result.createUdp(family)

proc ensureClientContext(
    endpoint: QuicEndpoint
): ClientContext {.raises: [QuicError].} =
  if CanDial notin endpoint.capabilities:
    raise newException(QuicError, "endpoint is not dial-capable")

  if endpoint.clientContext.isNil:
    endpoint.clientContext = createClientContext(endpoint.tlsConfig)
    endpoint.clientContext.fd = cint(endpoint.udp.fd)

  endpoint.clientContext

proc waitForIncoming(
    endpoint: QuicEndpoint
): Future[QuicConnection] {.async: (raises: [CancelledError]).} =
  await endpoint.serverContext.incoming.get()

proc accept*(
    endpoint: QuicEndpoint
): Future[Connection] {.async: (raises: [CancelledError, TransportError]).} =
  if endpoint.serverContext.isNil:
    raise newException(TransportError, "endpoint is not listen-capable")

  while true:
    let
      incomingFut = endpoint.waitForIncoming()
      closedFut = endpoint.connman.closed
      raceFut = await race(closedFut, incomingFut)

    if raceFut == closedFut:
      await incomingFut.cancelAndWait()
      raise newException(TransportError, "listener is stopped")

    let quicConn = await incomingFut
    if quicConn.lsquicConn.isNil:
      debug "Dropping already closed incoming connection"
      continue

    let conn = newIncomingConnection(endpoint.serverContext, quicConn)
    endpoint.connman.addConnection(conn)
    return conn

proc dial*(
    endpoint: QuicEndpoint, address: TransportAddress
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  let ctx = endpoint.ensureClientContext()
  let connection = newOutgoingConnection(ctx, endpoint.udp.localAddress(), address)
  endpoint.connman.addConnection(connection)
  await connection.dial()
  connection

proc localAddress*(
    endpoint: QuicEndpoint
): TransportAddress {.raises: [TransportOsError].} =
  endpoint.udp.localAddress()

proc datagramTransport*(endpoint: QuicEndpoint): DatagramTransport {.raises: [].} =
  endpoint.udp

proc stop*(endpoint: QuicEndpoint) {.async: (raises: [CancelledError]).} =
  if endpoint.stopped:
    return

  endpoint.stopped = true
  await noCancel endpoint.connman.stop()
  # Politely wait before closing udp so connection close packets can be sent.
  await noCancel sleepAsync(300.milliseconds)

  if not endpoint.clientContext.isNil:
    endpoint.clientContext.stop()
  if not endpoint.serverContext.isNil:
    endpoint.serverContext.stop()

  await noCancel endpoint.udp.closeWait()

  if not endpoint.clientContext.isNil:
    endpoint.clientContext.destroy()
    endpoint.clientContext = nil
  if not endpoint.serverContext.isNil:
    endpoint.serverContext.destroy()
    endpoint.serverContext = nil
