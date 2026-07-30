# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
when defined(windows):
  from chronos/osdefs import SOL_SOCKET, SO_RCVBUF
else:
  from posix import SOL_SOCKET, SO_RCVBUF
import
  ./[
    errors, connection, tlsconfig, connectionmanager, lsquic_ffi, certificateverifier,
    socketconfig,
  ]
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

proc socketReceiveBufferBytes(
    udp: DatagramTransport
): int {.raises: [TransportOsError].} =
  let value = getSockOpt2(udp.fd, int(SOL_SOCKET), int(SO_RCVBUF)).valueOr:
    raiseTransportOsError(error)
    return
  value.int

proc configureReceiveBuffer(
    udp: DatagramTransport, socketConfig: QuicSocketConfig
) {.raises: [TransportOsError].} =
  let requested = socketConfig.receiveBufferBytes
  if requested == 0:
    # Zero keeps the OS default socket buffer.
    return

  let setRes = setSockOpt2(udp.fd, int(SOL_SOCKET), int(SO_RCVBUF), requested)
  if setRes.isErr():
    raiseTransportOsError(setRes.error())

  let effective = udp.socketReceiveBufferBytes()
  if effective < requested:
    when defined(linux):
      warn "QUIC UDP receive buffer capped below requested size",
        requestedBytes = requested,
        effectiveBytes = effective,
        hint = "raise net.core.rmem_max if Linux caps SO_RCVBUF"
    else:
      warn "QUIC UDP receive buffer capped below requested size",
        requestedBytes = requested, effectiveBytes = effective
  else:
    debug "Configured QUIC UDP receive buffer",
      requestedBytes = requested, effectiveBytes = effective

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

proc scidLen(endpoint: QuicEndpoint): cuint {.raises: [].} =
  if not endpoint.serverContext.isNil and
      endpoint.serverContext.settings.es_scid_len != 0:
    return endpoint.serverContext.settings.es_scid_len
  if not endpoint.clientContext.isNil and
      endpoint.clientContext.settings.es_scid_len != 0:
    return endpoint.clientContext.settings.es_scid_len
  LSQUIC_DF_SCID_LEN.cuint

proc packetDcid(
    endpoint: QuicEndpoint, packet: openArray[byte], cid: var CidKey
): bool {.raises: [].} =
  if packet.len == 0:
    return false

  var cidLen: uint8
  let offset = lsquic_dcid_from_packet(
    unsafeAddr packet[0], packet.len.csize_t, endpoint.scidLen(), addr cidLen
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

func isIetfInitial(packet: openArray[byte]): bool {.raises: [].} =
  if packet.len == 0:
    return false
  (packet[0] and 0xC0'u8) == 0xC0'u8 and (packet[0] and 0x30'u8) == 0

proc receiveDatagram(
    endpoint: QuicEndpoint, data: openArray[byte], local, remote: TransportAddress
) {.raises: [].} =
  if endpoint.isNil or endpoint.stopped:
    return

  let
    hasClientContext = not endpoint.clientContext.isNil
    hasServerContext = not endpoint.serverContext.isNil

  var cid: CidKey
  if endpoint.packetDcid(data, cid):
    if hasClientContext and endpoint.clientContext.ownsCid(cid):
      trace "Routing datagram to client context", cid
      endpoint.clientContext.receive(data, local, remote)
      return

    if hasServerContext and endpoint.serverContext.ownsCid(cid):
      trace "Routing datagram to server context", cid
      endpoint.serverContext.receive(data, local, remote)
      return

  if hasClientContext and not hasServerContext:
    endpoint.clientContext.receive(data, local, remote)
    return

  if hasServerContext and not hasClientContext:
    endpoint.serverContext.receive(data, local, remote)
    return

  if hasServerContext and data.isIetfInitial():
    trace "Routing initial datagram with unknown CID to server context",
      bytes = data.len, local, remote
    endpoint.serverContext.receive(data, local, remote)
    return

  trace "Dropping datagram with unknown CID", bytes = data.len, local, remote

proc receiveFromUdp(
    endpoint: QuicEndpoint, udp: DatagramTransport, remote: TransportAddress
) {.raises: [].} =
  try:
    var
      msg: seq[byte]
      msgLen: int
    udp.peekMessage(msg, msgLen)
    if msgLen > 0:
      endpoint.receiveDatagram(
        msg.toOpenArray(0, msgLen - 1), udp.localAddress(), remote
      )
  except TransportError as e:
    warn "Could not read received datagram", errorMsg = e.msg

proc createUdp(
    endpoint: QuicEndpoint, address: TransportAddress, socketConfig: QuicSocketConfig
): DatagramTransport {.raises: [QuicError, TransportOsError].} =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    endpoint.receiveFromUdp(udp, remote)

  let udp =
    case address.family
    of AddressFamily.IPv4:
      newDatagramTransport(onReceive, local = address)
    of AddressFamily.IPv6:
      newDatagramTransport6(onReceive, local = address)
    else:
      raise newException(QuicError, "only IPv4/IPv6 address is supported")

  udp.configureReceiveBuffer(socketConfig)
  udp

proc createUdp(
    endpoint: QuicEndpoint, family: AddressFamily, socketConfig: QuicSocketConfig
): DatagramTransport {.raises: [QuicError, TransportOsError].} =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    endpoint.receiveFromUdp(udp, remote)

  let udp =
    case family
    of AddressFamily.IPv4:
      newDatagramTransport(onReceive)
    of AddressFamily.IPv6:
      newDatagramTransport6(onReceive)
    else:
      raise newException(QuicError, "endpoint supports only IPv4/IPv6 address")

  udp.configureReceiveBuffer(socketConfig)
  udp

proc new*(
    _: type QuicEndpoint,
    tlsConfig: TLSConfig,
    address: TransportAddress,
    capabilities: QuicEndpointCapabilities = {CanListen, CanDial},
    socketConfig: QuicSocketConfig = DefaultQuicSocketConfig,
): QuicEndpoint {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  if CanListen in capabilities and tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")

  socketConfig.validate()

  var endpoint = QuicEndpoint(
    tlsConfig: tlsConfig, capabilities: capabilities, connman: ConnectionManager.new()
  )
  endpoint.udp = endpoint.createUdp(address, socketConfig)

  var initialized = false

  defer:
    if not initialized:
      if not endpoint.serverContext.isNil:
        endpoint.serverContext.destroy()
      if not endpoint.clientContext.isNil:
        endpoint.clientContext.destroy()
      if not endpoint.udp.isNil:
        endpoint.udp.close()

  if CanListen in capabilities:
    endpoint.serverContext = createServerContext(tlsConfig, cint(endpoint.udp.fd))

  initialized = true
  endpoint

proc new*(
    _: type QuicEndpoint,
    tlsConfig: TLSConfig,
    family: AddressFamily,
    socketConfig: QuicSocketConfig = DefaultQuicSocketConfig,
): QuicEndpoint {.raises: [QuicError, TransportOsError].} =
  socketConfig.validate()

  var endpoint = QuicEndpoint(
    tlsConfig: tlsConfig, capabilities: {CanDial}, connman: ConnectionManager.new()
  )
  endpoint.udp = endpoint.createUdp(family, socketConfig)
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

proc dial(
    endpoint: QuicEndpoint,
    address: TransportAddress,
    certVerifier: Opt[CertificateVerifier],
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  let ctx = endpoint.ensureClientContext()
  let connection =
    newOutgoingConnection(ctx, endpoint.udp.localAddress(), address, certVerifier)
  endpoint.connman.addConnection(connection)
  var connected = false
  try:
    await connection.dial()
    connected = true
  finally:
    if not connected:
      endpoint.connman.removeConnection(connection)

  connection

proc dial*(
    endpoint: QuicEndpoint, address: TransportAddress
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  if endpoint.tlsConfig.certVerifier.isNone:
    raise newException(
      QuicError, "certificate verifier is required; use dial(address, certVerifier)"
    )

  await endpoint.dial(address, Opt.none(CertificateVerifier))

proc dial*(
    endpoint: QuicEndpoint, address: TransportAddress, certVerifier: CertificateVerifier
): Future[Connection] {.
    async: (raises: [CancelledError, QuicError, DialError, TransportOsError])
.} =
  if certVerifier.isNil:
    raise newException(QuicError, "certificate verifier is nil")

  await endpoint.dial(address, Opt.some(certVerifier))

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

when defined(lsquic_testing):
  proc connectionCount*(endpoint: QuicEndpoint): int {.raises: [].} =
    ## Test-only: number of connections tracked by this endpoint's manager.
    endpoint.connman.len

  export scidLen, packetDcid, isIetfInitial
