# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[sequninit, transportaddr]
import std/[nativesockets, net]

when defined(linux) or defined(windows):
  import ./sendbatch

when not defined(windows):
  import chronicles
  import posix

when defined(linux) or defined(windows):
  const
    MaxOutBatchSize = 64
    MaxOutBatchIovecs = MaxGsoIovecs

  static:
    doAssert MaxOutBatchIovecs >= MaxGsoIovecs

  proc packetPayloadSize(spec: struct_lsquic_out_spec): int =
    if spec.iov.isNil or spec.iovlen == 0:
      return 0

    let iovs = cast[ptr UncheckedArray[struct_iovec]](spec.iov)
    var total: uint64
    for i in 0 ..< spec.iovlen.int:
      total += uint64(iovs[i].iov_len)
      if total > uint64(int.high):
        return int.high
    total.int

when defined(linux):
  {.passc: "-D_GNU_SOURCE".}

  const
    SOL_UDP = 17.cint
    UDP_SEGMENT = 103

  type
    MMsgHdr {.importc: "struct mmsghdr", header: "<sys/socket.h>", bycopy.} = object
      msg_hdr: Tmsghdr
      msg_len: cuint

    GsoControl = object
      hdr: Tcmsghdr
      data: array[64, byte]

  proc sendmmsg(
    sockfd: SocketHandle, msgvec: ptr MMsgHdr, vlen: cuint, flags: cint
  ): cint {.importc, header: "<sys/socket.h>".}

when defined(windows):
  const
    UDP_SEND_MSG_SIZE = 2.cint
    WSAEINVAL = 10022.cint
    WSAEMSGSIZE = 10040.cint
    WSAENOPROTOOPT = 10042.cint
    WSAEOPNOTSUPP = 10045.cint
    WSAID_WSASENDMSG = GUID(
      D1: 0xa441e712'u32,
      D2: 0x754f'u16,
      D3: 0x43ca'u16,
      D4: [0x84'u8, 0xa7'u8, 0x0d'u8, 0xee'u8, 0x44'u8, 0xcf'u8, 0x60'u8, 0x6d'u8],
    )

  type
    WsaCMsgHdr = object
      cmsg_len: csize_t
      cmsg_level: cint
      cmsg_type: cint

    WsaMsg = object
      name: ptr SockAddr
      namelen: cint
      lpBuffers: ptr WSABUF
      dwBufferCount: DWORD
      Control: WSABUF
      dwFlags: DWORD

    WsaGsoControl = object
      hdr: WsaCMsgHdr
      data: array[64, byte]

    LpfnWsaSendMsg = proc(
      s: SocketHandle,
      lpMsg: ptr WsaMsg,
      dwFlags: DWORD,
      lpNumberOfBytesSent: ptr DWORD,
      lpOverlapped: POVERLAPPED,
      lpCompletionRoutine: POVERLAPPED_COMPLETION_ROUTINE,
    ): cint {.stdcall, gcsafe, raises: [].}

proc prepareDestAddr(
    localSa: ptr SockAddr,
    destSa: ptr SockAddr,
    destStorage: var Sockaddr_storage,
    destAddrLen: var SockLen,
) =
  ## Chronos normalizes IPv4 peers on dual-stack `::` sockets back to IPv4.
  ## When lsquic later asks us to send on that IPv6 socket, sending directly to
  ## an AF_INET destination can fail with EINVAL. Re-map the destination to an
  ## IPv6-mapped address when the local path is IPv6.
  let
    localAddress = localSa.toTransportAddress()
    destAddress = destSa.toTransportAddress()
  if localAddress.family == AddressFamily.IPv6 and
      destAddress.family == AddressFamily.IPv4:
    let mappedDest = destAddress.toIPv6()
    mappedDest.toSAddr(destStorage, destAddrLen)
  else:
    destAddrLen = sockAddrLen(destSa.sa_family.int)
    copyMem(addr destStorage, destSa, destAddrLen)

when not defined(windows):
  proc makeMsgHdr(
      iov: ptr IOVec,
      iovlen: csize_t,
      destStorage: var Sockaddr_storage,
      destAddrLen: SockLen,
  ): Tmsghdr =
    when defined(linux) and defined(x86_64) and not defined(android):
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: iov,
        msg_iovlen: iovlen,
        msg_control: nil,
        msg_controllen: 0,
        msg_flags: 0,
      )
    else:
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: iov,
        msg_iovlen: iovlen.cint,
        msg_control: nil,
        msg_controllen: 0,
        msg_flags: 0,
      )

when defined(linux):
  proc copyIovs(
      dest: var array[MaxOutBatchIovecs, IOVec],
      destPos: var int,
      spec: struct_lsquic_out_spec,
  ) =
    let iovs = cast[ptr UncheckedArray[IOVec]](spec.iov)
    for i in 0 ..< spec.iovlen.int:
      dest[destPos] = iovs[i]
      inc destPos

  proc setUdpSegmentControl(
      msg: var Tmsghdr, control: var GsoControl, segmentSize: uint16
  ) =
    zeroMem(addr control, sizeof(control))
    msg.msg_control = cast[pointer](addr control)
    msg.msg_controllen = CMSG_SPACE(csize_t(sizeof(segmentSize)))

    let cmsg = CMSG_FIRSTHDR(addr msg)
    cmsg.cmsg_level = SOL_UDP
    cmsg.cmsg_type = UDP_SEGMENT
    cmsg.cmsg_len = CMSG_LEN(csize_t(sizeof(segmentSize)))
    cast[ptr uint16](CMSG_DATA(cmsg))[] = segmentSize

  proc isUnsupportedGsoErr(e: cint): bool =
    e == EINVAL or e == ENOTSUP or e == EOPNOTSUPP

  proc sendPacketsMmsg(
      quicCtx: QuicContext,
      specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
      nspecs: cuint,
      gsoEnabled: bool,
  ): cint =
    var
      destStorages {.noinit.}: array[MaxOutBatchSize, Sockaddr_storage]
      destAddrLens {.noinit.}: array[MaxOutBatchSize, SockLen]
      shapes: array[MaxOutBatchSize, PacketShape]
      msgs {.noinit.}: array[MaxOutBatchSize, MMsgHdr]
      controls {.noinit.}: array[MaxOutBatchSize, GsoControl]
      gsoIovs {.noinit.}: array[MaxOutBatchIovecs, IOVec]

    let batchCount = min(nspecs.int, MaxOutBatchSize)
    for i in 0 ..< batchCount:
      let curr = specsArr[i]
      prepareDestAddr(curr.local_sa, curr.dest_sa, destStorages[i], destAddrLens[i])
      shapes[i] = PacketShape(
        local: curr.local_sa.toTransportAddress(),
        dest: cast[ptr SockAddr](addr destStorages[i]).toTransportAddress(),
        ecn: curr.ecn,
        size: curr.packetPayloadSize(),
        iovCount: curr.iovlen.int,
      )

    let groups = buildSendGroups(shapes.toOpenArray(0, batchCount - 1), gsoEnabled)

    var
      msgCount = 0
      gsoIovCount = 0
      gsoUsed = false

    for group in groups:
      let curr = specsArr[group.first]
      if group.gso:
        let iovStart = gsoIovCount
        for i in group.first ..< group.first + group.count:
          copyIovs(gsoIovs, gsoIovCount, specsArr[i])

        msgs[msgCount] = MMsgHdr(
          msg_hdr: makeMsgHdr(
            addr gsoIovs[iovStart],
            group.iovCount.csize_t,
            destStorages[group.first],
            destAddrLens[group.first],
          ),
          msg_len: 0,
        )
        setUdpSegmentControl(
          msgs[msgCount].msg_hdr, controls[msgCount], group.segmentSize.uint16
        )
        gsoUsed = true
      else:
        msgs[msgCount] = MMsgHdr(
          msg_hdr: makeMsgHdr(
            cast[ptr IOVec](curr.iov),
            curr.iovlen,
            destStorages[group.first],
            destAddrLens[group.first],
          ),
          msg_len: 0,
        )
      inc msgCount

    let res = sendmmsg(SocketHandle(quicCtx.fd), addr msgs[0], msgCount.cuint, 0)
    if res < 0:
      let savedErrno = errno
      if gsoUsed and isUnsupportedGsoErr(savedErrno):
        quicCtx.gsoDisabled = true
        return sendPacketsMmsg(quicCtx, specsArr, nspecs, false)

      trace "sendmmsg failed", nspecs
      errno = savedErrno
      return res

    let sent = sentSpecCount(groups, res.int)
    if sent < nspecs.int:
      trace "sendmmsg partially sent", sent, nspecs
      errno = EAGAIN
    sent.cint

when defined(windows):
  func wsaAlign(value, alignment: int): int =
    ((value + alignment - 1) div alignment) * alignment

  func wsaCmsgLen(payloadLen: int): int =
    wsaAlign(sizeof(WsaCMsgHdr), sizeof(pointer)) + payloadLen

  func wsaCmsgSpace(payloadLen: int): int =
    wsaAlign(
      sizeof(WsaCMsgHdr) + wsaAlign(payloadLen, sizeof(pointer)), sizeof(pointer)
    )

  proc fillWsaBufs(
      dest: var openArray[WSABUF], destPos: var int, spec: struct_lsquic_out_spec
  ) =
    let iovs = cast[ptr UncheckedArray[struct_iovec]](spec.iov)
    for i in 0 ..< spec.iovlen.int:
      dest[destPos] =
        WSABUF(len: ULONG(iovs[i].iov_len), buf: cast[cstring](iovs[i].iov_base))
      inc destPos

  proc getWsaSendMsg(quicCtx: QuicContext): LpfnWsaSendMsg =
    if not quicCtx.wsaSendMsg.isNil:
      return cast[LpfnWsaSendMsg](quicCtx.wsaSendMsg)

    var
      guid = WSAID_WSASENDMSG
      fnPtr: pointer
      bytesReturned: DWORD

    let rc = wsaIoctl(
      SocketHandle(quicCtx.fd),
      SIO_GET_EXTENSION_FUNCTION_POINTER,
      cast[pointer](addr guid),
      DWORD(sizeof(guid)),
      cast[pointer](addr fnPtr),
      DWORD(sizeof(fnPtr)),
      addr bytesReturned,
      nil,
      nil,
    )
    if rc != 0 or fnPtr.isNil or bytesReturned != DWORD(sizeof(fnPtr)):
      return nil

    quicCtx.wsaSendMsg = fnPtr
    cast[LpfnWsaSendMsg](fnPtr)

  proc setUdpSendMsgSizeControl(
      msg: var WsaMsg, control: var WsaGsoControl, segmentSize: uint32
  ) =
    zeroMem(addr control, sizeof(control))

    msg.Control = WSABUF(
      len: ULONG(wsaCmsgSpace(sizeof(segmentSize))), buf: cast[cstring](addr control)
    )

    control.hdr.cmsg_len = csize_t(wsaCmsgLen(sizeof(segmentSize)))
    control.hdr.cmsg_level = IPPROTO_UDP.cint
    control.hdr.cmsg_type = UDP_SEND_MSG_SIZE
    cast[ptr uint32](addr control.data[0])[] = segmentSize

  proc isUnsupportedWindowsGsoErr(e: cint): bool =
    e == WSAEINVAL or e == WSAEMSGSIZE or e == WSAENOPROTOOPT or e == WSAEOPNOTSUPP

  proc sendWindowsPacket(
      fd: cint,
      spec: struct_lsquic_out_spec,
      destStorage: var Sockaddr_storage,
      destAddrLen: SockLen,
  ): cint =
    if spec.iov.isNil or spec.iovlen == 0:
      return -1

    var
      bufs = newSeq[WSABUF](spec.iovlen.int)
      bufCount = 0
      bytesSent: DWORD

    fillWsaBufs(bufs, bufCount, spec)
    wsaSendTo(
      SocketHandle(fd),
      addr bufs[0],
      DWORD(bufCount),
      addr bytesSent,
      0'u32,
      cast[ptr SockAddr](addr destStorage),
      cint(destAddrLen),
      nil,
      nil,
    )

  proc sendWindowsGsoGroup(
      fd: cint,
      wsaSendMsg: LpfnWsaSendMsg,
      specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
      group: SendGroup,
      destStorage: var Sockaddr_storage,
      destAddrLen: SockLen,
  ): cint =
    var
      bufs {.noinit.}: array[MaxOutBatchIovecs, WSABUF]
      bufCount = 0
      control: WsaGsoControl
      bytesSent: DWORD

    for i in group.first ..< group.first + group.count:
      fillWsaBufs(bufs, bufCount, specsArr[i])

    var msg = WsaMsg(
      name: cast[ptr SockAddr](addr destStorage),
      namelen: cint(destAddrLen),
      lpBuffers: addr bufs[0],
      dwBufferCount: DWORD(bufCount),
      Control: WSABUF(),
      dwFlags: 0'u32,
    )
    msg.setUdpSendMsgSizeControl(control, group.segmentSize.uint32)

    wsaSendMsg(SocketHandle(fd), addr msg, 0'u32, addr bytesSent, nil, nil)

  proc sendPacketsWindows(
      quicCtx: QuicContext,
      specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
      nspecs: cuint,
      gsoEnabled: bool,
  ): cint =
    var
      destStorages {.noinit.}: array[MaxOutBatchSize, Sockaddr_storage]
      destAddrLens {.noinit.}: array[MaxOutBatchSize, SockLen]
      shapes: array[MaxOutBatchSize, PacketShape]

    let batchCount = min(nspecs.int, MaxOutBatchSize)
    for i in 0 ..< batchCount:
      let curr = specsArr[i]
      prepareDestAddr(curr.local_sa, curr.dest_sa, destStorages[i], destAddrLens[i])
      shapes[i] = PacketShape(
        local: curr.local_sa.toTransportAddress(),
        dest: cast[ptr SockAddr](addr destStorages[i]).toTransportAddress(),
        ecn: curr.ecn,
        size: curr.packetPayloadSize(),
        iovCount: curr.iovlen.int,
      )

    let groups = buildSendGroups(shapes.toOpenArray(0, batchCount - 1), gsoEnabled)

    var sent = 0
    for group in groups:
      var res: cint
      if group.gso:
        let wsaSendMsg = quicCtx.getWsaSendMsg()
        if wsaSendMsg.isNil:
          quicCtx.gsoDisabled = true
          if sent == 0:
            return sendPacketsWindows(quicCtx, specsArr, nspecs, false)
          break

        res = sendWindowsGsoGroup(
          quicCtx.fd,
          wsaSendMsg,
          specsArr,
          group,
          destStorages[group.first],
          destAddrLens[group.first],
        )
        if res != 0 and isUnsupportedWindowsGsoErr(wsaGetLastError()):
          quicCtx.gsoDisabled = true
          if sent == 0:
            return sendPacketsWindows(quicCtx, specsArr, nspecs, false)
          break
      else:
        res = sendWindowsPacket(
          quicCtx.fd,
          specsArr[group.first],
          destStorages[group.first],
          destAddrLens[group.first],
        )

      if res != 0:
        if sent == 0:
          return -1
        break

      sent += group.count

    sent.cint

proc receive*(
    ctx: QuicContext,
    data: openArray[byte],
    local: TransportAddress,
    remote: TransportAddress,
    ecn: cint = 0,
) =
  if data.len == 0 or not ctx.isRunning():
    return

  var
    localAddress: Sockaddr_storage
    localAddrLen: SockLen
    remoteAddress: Sockaddr_storage
    remoteAddrLen: SockLen

  local.toSAddr(localAddress, localAddrLen)
  remote.toSAddr(remoteAddress, remoteAddrLen)

  discard lsquic_engine_packet_in(
    ctx.engine,
    cast[ptr uint8](addr data[0]),
    data.len.csize_t,
    cast[ptr SockAddr](addr localAddress),
    cast[ptr SockAddr](addr remoteAddress),
    cast[pointer](ctx),
    ecn,
  )

  ctx.processWhenReady()

proc receive*(
    ctx: QuicContext,
    datagram: sink Datagram,
    local: TransportAddress,
    remote: TransportAddress,
) =
  ctx.receive(datagram.data, local, remote, datagram.ecn)

proc sendPacketsOut*(
    ctx: pointer, specs: ptr struct_lsquic_out_spec, nspecs: cuint
): cint {.cdecl.} =
  let quicCtx = cast[QuicContext](ctx)
  if nspecs == 0:
    return 0

  let specsArr = cast[ptr UncheckedArray[struct_lsquic_out_spec]](specs)

  when defined(linux):
    sendPacketsMmsg(
      quicCtx, specsArr, nspecs, not defined(gcRefc) and not quicCtx.gsoDisabled
    )
  elif defined(windows):
    var sent = 0
    for i in 0 ..< nspecs.int:
      let curr = specsArr[i]
      var
        destStorage: Sockaddr_storage
        destAddrLen: SockLen
      prepareDestAddr(curr.local_sa, curr.dest_sa, destStorage, destAddrLen)

      let res = sendWindowsPacket(quicCtx.fd, curr, destStorage, destAddrLen)
      if res != 0:
        if sent == 0:
          return -1
        break

      sent.inc

    sent.cint
  else:
    var sent = 0
    for i in 0 ..< nspecs.int:
      let curr = specsArr[i]
      var
        destStorage: Sockaddr_storage
        destAddrLen: SockLen
      prepareDestAddr(curr.local_sa, curr.dest_sa, destStorage, destAddrLen)

      let msg =
        makeMsgHdr(cast[ptr IOVec](curr.iov), curr.iovlen, destStorage, destAddrLen)

      let res = sendmsg(SocketHandle(quicCtx.fd), msg.addr, 0)
      if res < 0:
        trace "sendmsg failed", sent, nspecs
        if sent == 0:
          return -1
        break

      sent.inc

    sent.cint
