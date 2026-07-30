# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
when defined(windows):
  from chronos/osdefs import SOL_SOCKET, SO_RCVBUF
else:
  from posix import SOL_SOCKET, SO_RCVBUF, Tmsghdr, IOVec, MSG_TRUNC
import
  ./[
    errors, connection, tlsconfig, connectionmanager, lsquic_ffi, certificateverifier,
    socketconfig,
  ]
import ./context/[server, client, context, io]
import ./helpers/transportaddr
from chronos/osdefs import Sockaddr_storage, SockAddr, SockLen, SocketHandle
when defined(windows):
  from std/winlean import recvfrom
else:
  from chronos/osdefs import recvfrom

when defined(linux):
  const DrainSlotBytes = 2048
    ## Per-datagram slot in the batch buffer. recvmmsg needs the space reserved
    ## up front, so this trades a fixed 128 KB per endpoint against being able
    ## to read a whole burst in one syscall. Comfortably above the largest
    ## datagram the engine negotiates, and anything longer is reported by
    ## MSG_TRUNC rather than silently cut.

  type MMsgHdr {.importc: "struct mmsghdr", header: "<sys/socket.h>", bycopy.} = object
    msg_hdr: Tmsghdr
    msg_len: cuint

  proc recvmmsg(
    sockfd: SocketHandle,
    msgvec: ptr MMsgHdr,
    vlen: cuint,
    flags: cint,
    timeout: pointer,
  ): cint {.importc, header: "<sys/socket.h>".}

type
  QuicEndpointCapability* = enum
    CanListen
    CanDial

  QuicEndpointCapabilities* = set[QuicEndpointCapability]

  RouteTarget = enum
    rtClient
    rtServer

  QuicEndpoint* = ref object of RootObj
    tlsConfig: TLSConfig
    capabilities: QuicEndpointCapabilities
    serverContext: ServerContext
    clientContext: ClientContext
    connman: ConnectionManager
    udp: DatagramTransport
    gso: SegmentationOffload
    stopped: bool
    drainBuf: seq[byte]
    when defined(linux):
      # Preallocated once: one slot, address and message header per datagram of
      # a batch, so a drain is a single recvmmsg rather than a recvfrom each.
      drainAddrs: seq[Sockaddr_storage]
      drainIovs: seq[IOVec]
      drainMsgs: seq[MMsgHdr]

const
  CloseWait: Duration = 300.milliseconds

  MaxDatagramsPerWakeup = 64
    ## Capped so that a busy socket cannot starve the rest of the event loop.

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
    tlsConfig: TLSConfig, fd: cint, gso: SegmentationOffload
): ServerContext {.raises: [QuicError].} =
  var context = ServerContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)
  context.fd = fd
  context.gso = gso
  context

proc createClientContext(
    tlsConfig: TLSConfig, fd: cint, gso: SegmentationOffload
): ClientContext {.raises: [QuicError].} =
  var context = ClientContext.new(tlsConfig).valueOr:
    raise newException(QuicError, error)
  context.fd = fd
  context.gso = gso
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

proc routeDatagram(
    endpoint: QuicEndpoint, data: openArray[byte], local, remote: TransportAddress
): set[RouteTarget] {.raises: [].} =
  if endpoint.isNil or endpoint.stopped:
    return {}

  let
    hasClientContext = not endpoint.clientContext.isNil
    hasServerContext = not endpoint.serverContext.isNil

  var cid: CidKey
  if endpoint.packetDcid(data, cid):
    if hasClientContext and endpoint.clientContext.ownsCid(cid):
      trace "Routing datagram to client context", cid
      endpoint.clientContext.packetIn(data, local, remote)
      return {rtClient}

    if hasServerContext and endpoint.serverContext.ownsCid(cid):
      trace "Routing datagram to server context", cid
      endpoint.serverContext.packetIn(data, local, remote)
      return {rtServer}

  if hasClientContext and not hasServerContext:
    endpoint.clientContext.packetIn(data, local, remote)
    return {rtClient}

  if hasServerContext and not hasClientContext:
    endpoint.serverContext.packetIn(data, local, remote)
    return {rtServer}

  if hasServerContext and data.isIetfInitial():
    trace "Routing initial datagram with unknown CID to server context",
      bytes = data.len, local, remote
    endpoint.serverContext.packetIn(data, local, remote)
    return {rtServer}

  trace "Dropping datagram with unknown CID", bytes = data.len, local, remote
  {}

proc recvDatagram(
    fd: SocketHandle,
    buf: var seq[byte],
    remoteAddress: var Sockaddr_storage,
    remoteAddrLen: var SockLen,
): int {.raises: [].} =
  when defined(windows):
    recvfrom(
      fd,
      cast[cstring](addr buf[0]),
      cint(buf.len),
      cint(0),
      cast[ptr SockAddr](addr remoteAddress),
      addr remoteAddrLen,
    ).int
  else:
    recvfrom(
      fd,
      addr buf[0],
      buf.len,
      cint(0),
      cast[ptr SockAddr](addr remoteAddress),
      addr remoteAddrLen,
    ).int

when defined(linux):
  proc initDrainBatch(endpoint: QuicEndpoint) {.raises: [].} =
    endpoint.drainBuf = newSeq[byte](MaxDatagramsPerWakeup * DrainSlotBytes)
    endpoint.drainAddrs = newSeq[Sockaddr_storage](MaxDatagramsPerWakeup)
    endpoint.drainIovs = newSeq[IOVec](MaxDatagramsPerWakeup)
    endpoint.drainMsgs = newSeq[MMsgHdr](MaxDatagramsPerWakeup)
    for i in 0 ..< MaxDatagramsPerWakeup:
      endpoint.drainIovs[i] = IOVec(
        iov_base: addr endpoint.drainBuf[i * DrainSlotBytes], iov_len: DrainSlotBytes
      )
      endpoint.drainMsgs[i].msg_hdr.msg_name = addr endpoint.drainAddrs[i]
      endpoint.drainMsgs[i].msg_hdr.msg_iov = addr endpoint.drainIovs[i]
      when defined(x86_64) and not defined(android):
        endpoint.drainMsgs[i].msg_hdr.msg_iovlen = 1.csize_t
      else:
        endpoint.drainMsgs[i].msg_hdr.msg_iovlen = 1.cint

  proc drainDatagrams(
      endpoint: QuicEndpoint, udp: DatagramTransport, local: TransportAddress
  ): set[RouteTarget] {.raises: [].} =
    ## Chronos hands this callback a single datagram per event-loop wakeup, so
    ## whatever else has already arrived is read here. recvmmsg takes the whole
    ## burst in one syscall instead of one recvfrom per datagram plus a final
    ## one to discover the socket is empty.
    if endpoint.drainMsgs.len == 0:
      endpoint.initDrainBatch()

    # the kernel writes these back, so they are reset for every call
    for i in 0 ..< MaxDatagramsPerWakeup:
      endpoint.drainMsgs[i].msg_hdr.msg_namelen = SockLen(sizeof(Sockaddr_storage))
      endpoint.drainMsgs[i].msg_hdr.msg_flags = 0

    let received = recvmmsg(
      SocketHandle(udp.fd),
      addr endpoint.drainMsgs[0],
      MaxDatagramsPerWakeup.cuint,
      0,
      nil,
    )
    if received <= 0:
      # Empty, or an error the transport will report again on the next wakeup.
      return {}

    var targets: set[RouteTarget]
    for i in 0 ..< received:
      let
        hdr = addr endpoint.drainMsgs[i]
        length = hdr.msg_len.int
      if length <= 0:
        continue
      if (hdr.msg_hdr.msg_flags and MSG_TRUNC) != 0:
        warn "Dropping oversized datagram", bytes = length, slot = DrainSlotBytes
        continue
      targets.incl endpoint.routeDatagram(
        endpoint.drainBuf.toOpenArray(
          i * DrainSlotBytes, i * DrainSlotBytes + length - 1
        ),
        local,
        toTransportAddress(cast[ptr SockAddr](addr endpoint.drainAddrs[i])),
      )

    targets

else:
  proc drainDatagrams(
      endpoint: QuicEndpoint, udp: DatagramTransport, local: TransportAddress
  ): set[RouteTarget] {.raises: [].} =
    ## One recvfrom per datagram, for platforms without recvmmsg.
    if endpoint.drainBuf.len == 0:
      endpoint.drainBuf = newSeq[byte](DefaultDatagramBufferSize)

    var targets: set[RouteTarget]
    for _ in 0 ..< MaxDatagramsPerWakeup:
      var
        remoteAddress: Sockaddr_storage
        remoteAddrLen = SockLen(sizeof(Sockaddr_storage))
      let res = recvDatagram(
        SocketHandle(udp.fd), endpoint.drainBuf, remoteAddress, remoteAddrLen
      )
      if res < 0:
        # Empty, or an error the transport will report again on the next wakeup.
        break

      if res > 0:
        targets.incl endpoint.routeDatagram(
          endpoint.drainBuf.toOpenArray(0, res - 1),
          local,
          toTransportAddress(cast[ptr SockAddr](addr remoteAddress)),
        )

    targets

proc receiveFromUdp(
    endpoint: QuicEndpoint, udp: DatagramTransport, remote: TransportAddress
) {.raises: [].} =
  var
    targets: set[RouteTarget]
    local: TransportAddress

  try:
    var
      msg: seq[byte]
      msgLen: int
    local = udp.localAddress()
    udp.peekMessage(msg, msgLen)
    if msgLen > 0:
      targets = endpoint.routeDatagram(msg.toOpenArray(0, msgLen - 1), local, remote)
  except TransportError as e:
    warn "Could not read received datagram", errorMsg = e.msg
    return

  targets = targets + endpoint.drainDatagrams(udp, local)

  if rtClient in targets:
    endpoint.clientContext.processWhenReady()
  if rtServer in targets:
    endpoint.serverContext.processWhenReady()

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
  endpoint.gso = SegmentationOffload(
    enabled: socketConfig.segmentationOffload and probeSegmentationOffload(udp.fd)
  )
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
  endpoint.gso = SegmentationOffload(
    enabled: socketConfig.segmentationOffload and probeSegmentationOffload(udp.fd)
  )
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
    endpoint.serverContext =
      createServerContext(tlsConfig, cint(endpoint.udp.fd), endpoint.gso)

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
      createClientContext(endpoint.tlsConfig, cint(endpoint.udp.fd), endpoint.gso)

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

proc segmentationOffloadActive*(endpoint: QuicEndpoint): bool {.raises: [].} =
  ## True while the endpoint socket uses UDP segmentation offload. The config
  ## must ask for it, the probe must find support, and no send error must
  ## disable it.
  endpoint.gso.enabled

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
