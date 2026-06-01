# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
import ./[errors, connection, tlsconfig, datagram, connectionmanager, lsquic_ffi]
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

const CloseWait: Duration = 300.milliseconds

proc createServerContext(
    tlsConfig: TLSConfig, fd: cint
): ServerContext {.raises: [QuicError].} =
  var context = ServerContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)
  context.fd = fd
  context

proc createClientContext(
    tlsConfig: TLSConfig, fd: cint
): ClientContext {.raises: [QuicError].} =
  var context = ClientContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)
  context.fd = fd
  context

proc serverCidLen(endpoint: QuicEndpoint): cuint {.raises: [].} =
  if not endpoint.serverContext.isNil and endpoint.serverContext.settings.es_scid_len != 0:
    return endpoint.serverContext.settings.es_scid_len
  if not endpoint.clientContext.isNil and endpoint.clientContext.settings.es_scid_len != 0:
    return endpoint.clientContext.settings.es_scid_len
  LSQUIC_DF_SCID_LEN.cuint

proc packetDcid(
    endpoint: QuicEndpoint, packet: seq[byte], cid: var CidKey
): bool {.raises: [].} =
  if packet.len == 0:
    return false

  var cidLen: uint8
  let offset = lsquic_dcid_from_packet(
    unsafeAddr packet[0],
    packet.len.csize_t,
    endpoint.serverCidLen(),
    addr cidLen,
  )
  if offset < 0:
    return false

  let start = offset.int
  if cidLen == 0 or cidLen.int > MAX_CID_LEN or start + cidLen.int > packet.len:
    return false

  cid = CidKey(len: cidLen)
  for i in 0 ..< cidLen.int:
    cid.bytes[i] = packet[start + i]
  true

proc receiveDatagram(
    endpoint: QuicEndpoint, data: seq[byte], local, remote: TransportAddress
) {.raises: [].} =
  if endpoint.isNil or endpoint.stopped:
    return

  var cid: CidKey
  if endpoint.packetDcid(data, cid):
    if not endpoint.clientContext.isNil and endpoint.clientContext.ownsCid(cid):
      endpoint.clientContext.receive(Datagram(data: data), local, remote)
      return

    if not endpoint.serverContext.isNil and endpoint.serverContext.ownsCid(cid):
      endpoint.serverContext.receive(Datagram(data: data), local, remote)
      return

  # Unknown CIDs can be new handshakes; each engine gets a chance to claim them.
  # Endpoints can have both contexts; each engine needs to see the packet.
  if not endpoint.clientContext.isNil:
    endpoint.clientContext.receive(Datagram(data: data), local, remote)
  if not endpoint.serverContext.isNil:
    endpoint.serverContext.receive(Datagram(data: data), local, remote)

proc receiveFromUdp(
    endpoint: QuicEndpoint, udp: DatagramTransport, remote: TransportAddress
) {.raises: [].} =
  try:
    endpoint.receiveDatagram(udp.getMessage(), udp.localAddress(), remote)
  except TransportError as e:
    warn "Could not read received datagram", errorMsg = e.msg

proc createUdp(
    endpoint: QuicEndpoint, address: TransportAddress
): DatagramTransport {.raises: [QuicError, TransportOsError].} =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    endpoint.receiveFromUdp(udp, remote)

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
    endpoint.receiveFromUdp(udp, remote)

  case family
  of AddressFamily.IPv4:
    newDatagramTransport(onReceive)
  of AddressFamily.IPv6:
    newDatagramTransport6(onReceive)
  else:
    raise newException(QuicError, "endpoint supports only IPv4/IPv6 address")

proc new*(
    _: type QuicEndpoint,
    tlsConfig: TLSConfig,
    address: TransportAddress,
    capabilities: QuicEndpointCapabilities = {CanListen, CanDial},
): QuicEndpoint {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  if CanListen in capabilities and tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")

  var endpoint = QuicEndpoint(
    tlsConfig: tlsConfig, capabilities: capabilities, connman: ConnectionManager.new()
  )
  endpoint.udp = endpoint.createUdp(address)

  if CanListen in capabilities:
    endpoint.serverContext = createServerContext(tlsConfig, cint(endpoint.udp.fd))

  endpoint

proc new*(
    _: type QuicEndpoint, tlsConfig: TLSConfig, family: AddressFamily
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  var endpoint = QuicEndpoint(
    tlsConfig: tlsConfig, capabilities: {CanDial}, connman: ConnectionManager.new()
  )
  endpoint.udp = endpoint.createUdp(family)
  endpoint

proc ensureClientContext(
    endpoint: QuicEndpoint
): ClientContext {.raises: [QuicError].} =
  if CanDial notin endpoint.capabilities:
    raise newException(QuicError, "endpoint is not dial-capable")

  if endpoint.clientContext.isNil:
    endpoint.clientContext =
      createClientContext(endpoint.tlsConfig, cint(endpoint.udp.fd))

  endpoint.clientContext

proc waitForIncoming(
    endpoint: QuicEndpoint
): Future[QuicConnection] {.async: (raises: [CancelledError]).} =
  await endpoint.serverContext.incoming.get()

proc accept*(
    endpoint: QuicEndpoint
): Future[Connection] {.async: (raises: [CancelledError, TransportError]).} =
  if CanListen notin endpoint.capabilities:
    raise newException(TransportError, "endpoint is not listen-capable")

  if endpoint.stopped or endpoint.serverContext.isNil:
    raise newException(TransportError, "endpoint is stopped")

  while true:
    let
      incomingFut = endpoint.waitForIncoming()
      closedFut = endpoint.connman.closed
      raceFut = await race(closedFut, incomingFut)

    if raceFut == closedFut:
      await incomingFut.cancelAndWait()
      raise newException(TransportError, "endpoint is stopped")

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
  var connected = false
  try:
    await connection.dial()
    connected = true
  finally:
    if not connected:
      endpoint.connman.removeConnection(connection)

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
  await noCancel sleepAsync(CloseWait)

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
