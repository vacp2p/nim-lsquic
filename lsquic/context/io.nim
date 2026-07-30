# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[sequninit, transportaddr]
import std/[nativesockets, net]

when not defined(windows):
  import chronicles
  import posix

when defined(linux) or defined(windows):
  import ./gso

when defined(linux):
  {.passc: "-D_GNU_SOURCE".}

  const SendmmsgBatchSize = 64

  type MMsgHdr {.importc: "struct mmsghdr", header: "<sys/socket.h>", bycopy.} = object
    msg_hdr: Tmsghdr
    msg_len: cuint

  proc sendmmsg(
    sockfd: SocketHandle, msgvec: ptr MMsgHdr, vlen: cuint, flags: cint
  ): cint {.importc, header: "<sys/socket.h>".}

when defined(windows):
  {.pragma: wsa, stdcall, dynlib: "ws2_32.dll".}

  type
    WSABUF = object
      len: culong
      buf: ptr char

    WSAMSG = object
      name: ptr SockAddr
      namelen: cint
      lpBuffers: ptr WSABUF
      dwBufferCount: culong
      control: WSABUF
      dwFlags: culong

    # struct _WSACMSGHDR: SIZE_T cmsg_len; INT cmsg_level; INT cmsg_type
    WsaCmsgHdr = object
      cmsg_len: csize_t
      cmsg_level: cint
      cmsg_type: cint

  const
    WsaCmsgDataOff =
      (sizeof(WsaCmsgHdr) + sizeof(csize_t) - 1) and not (sizeof(csize_t) - 1)
    WsaCmsgLen = WsaCmsgDataOff + sizeof(DWORD)
    WsaCmsgSpace = (WsaCmsgLen + sizeof(csize_t) - 1) and not (sizeof(csize_t) - 1)
    WSAEINVAL = 10022
    WSAEWOULDBLOCK = 10035
    WSAEMSGSIZE = 10040
    WSAENOPROTOOPT = 10042
    WSAEOPNOTSUPP = 10045

  proc WSASendMsg(
    s: SocketHandle,
    lpMsg: ptr WSAMSG,
    dwFlags: culong,
    lpNumberOfBytesSent: ptr culong,
    lpOverlapped: pointer,
    lpCompletionRoutine: pointer,
  ): cint {.wsa, importc: "WSASendMsg".}

  # lsquic inspects the CRT errno on Windows too (send_batch compares against
  # EAGAIN/EMSGSIZE), so WSA errors must be bridged into it
  var cErrno {.importc: "errno", header: "<errno.h>".}: cint
  var cEAGAIN {.importc: "EAGAIN", header: "<errno.h>".}: cint
  var cEMSGSIZE {.importc: "EMSGSIZE", header: "<errno.h>".}: cint
  var cEIO {.importc: "EIO", header: "<errno.h>".}: cint

  proc setSendErrno(wsaError: cint) =
    cErrno =
      if wsaError == WSAEWOULDBLOCK:
        cEAGAIN
      elif wsaError == WSAEMSGSIZE:
        cEMSGSIZE
      else:
        cEIO

when defined(linux):
  const
    SOL_UDP = 17
    UDP_SEGMENT = 103

when defined(windows):
  const UDP_SEND_MSG_SIZE = 2

proc probeSegmentationOffload*(fd: AsyncFD): bool =
  ## Returns true when the socket supports UDP segmentation offload
  ## (Linux GSO via UDP_SEGMENT, kernel 4.18+; Windows USO via
  ## UDP_SEND_MSG_SIZE, Windows 10 1803+). Setting the option to 0 keeps
  ## socket-wide segmentation off; the send path enables it per message.
  when defined(linux):
    setSockOpt2(fd, SOL_UDP, UDP_SEGMENT, 0).isOk()
  elif defined(windows):
    setSockOpt2(fd, IPPROTO_UDP, UDP_SEND_MSG_SIZE, 0).isOk()
  else:
    false

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
  if localSa.isIPv6Family() and destSa.isIPv4Family():
    let mappedDest = destSa.toTransportAddress().toIPv6()
    mappedDest.toSAddr(destStorage, destAddrLen)
  else:
    destAddrLen = sockAddrLen(destSa.sa_family.int)
    copyMem(addr destStorage, destSa, destAddrLen)

when not defined(windows):
  proc makeMsgHdr(
      spec: struct_lsquic_out_spec,
      destStorage: var Sockaddr_storage,
      destAddrLen: SockLen,
  ): Tmsghdr =
    when defined(linux) and defined(x86_64) and not defined(android):
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: cast[ptr IOVec](spec.iov),
        msg_iovlen: spec.iovlen.csize_t,
        msg_control: nil,
        msg_controllen: 0,
        msg_flags: 0,
      )
    else:
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: cast[ptr IOVec](spec.iov),
        msg_iovlen: spec.iovlen.cint,
        msg_control: nil,
        msg_controllen: 0,
        msg_flags: 0,
      )

proc packetIn*(
    ctx: QuicContext,
    data: openArray[byte],
    local: TransportAddress,
    remote: TransportAddress,
    ecn: cint = 0,
): bool {.discardable.} =
  ## Returns false when the engine did not take the datagram, so that a caller
  ## draining a burst knows whether it has to tick at all.
  if data.len == 0 or not ctx.isRunning():
    return false

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

  true

proc receive*(
    ctx: QuicContext,
    data: openArray[byte],
    local: TransportAddress,
    remote: TransportAddress,
    ecn: cint = 0,
) =
  ## With several datagrams in hand, prefer `packetIn` and one
  ## `processWhenReady`: lsquic picks what to send once per tick, so a tick per
  ## datagram is a send batch per datagram.
  if ctx.packetIn(data, local, remote, ecn):
    ctx.processWhenReady()

proc receive*(
    ctx: QuicContext,
    datagram: sink Datagram,
    local: TransportAddress,
    remote: TransportAddress,
) =
  ctx.receive(datagram.data, local, remote, datagram.ecn)

proc sendPlain(
    quicCtx: QuicContext,
    specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
    first: int,
    nspecs: int,
): cint =
  ## Sends specs[first ..< nspecs] without segmentation offload; returns the
  ## number of specs sent starting at `first`, with errno set on short returns.
  when defined(linux):
    var
      destStorages {.noinit.}: array[SendmmsgBatchSize, Sockaddr_storage]
      msgs {.noinit.}: array[SendmmsgBatchSize, MMsgHdr]
      sent = 0

    while first + sent < nspecs:
      let nmsgs = min(nspecs - first - sent, SendmmsgBatchSize)
      for i in 0 ..< nmsgs:
        let curr = specsArr[first + sent + i]
        var destAddrLen: SockLen
        prepareDestAddr(curr.local_sa, curr.dest_sa, destStorages[i], destAddrLen)
        msgs[i] =
          MMsgHdr(msg_hdr: makeMsgHdr(curr, destStorages[i], destAddrLen), msg_len: 0)

      let res = sendmmsg(SocketHandle(quicCtx.fd), addr msgs[0], nmsgs.cuint, 0)
      if res < 0:
        let savedErrno = errno
        trace "sendmmsg failed", sent, nspecs
        errno = savedErrno
        if sent == 0:
          return -1
        return sent.cint

      sent += res.int
      if res < nmsgs.cint:
        trace "sendmmsg partially sent", sent, nspecs
        errno = EAGAIN
        return sent.cint

    sent.cint
  else:
    when defined(windows):
      # Reused across specs rather than allocated per packet. Bounded like the
      # segmented path's bufPool, which makes the same assumption about iovlen.
      var bufs {.noinit.}: array[MaxBatch, WSABUF]
    var sent = 0
    for i in first ..< nspecs:
      let curr = specsArr[i]
      var
        destStorage: Sockaddr_storage
        destAddrLen: SockLen
      prepareDestAddr(curr.local_sa, curr.dest_sa, destStorage, destAddrLen)

      when defined(windows):
        let iovArr = cast[ptr UncheckedArray[struct_iovec]](curr.iov)

        for j in 0 ..< curr.iovlen.int:
          let src = iovArr[j]
          bufs[j].len = culong(src.iov_len)
          bufs[j].buf = cast[ptr char](src.iov_base)

        var msg = WSAMSG(
          name: cast[ptr SockAddr](addr destStorage),
          namelen: cint(destAddrLen),
          lpBuffers: addr bufs[0],
          dwBufferCount: culong(curr.iovlen),
          control: WSABUF(len: 0, buf: nil),
          dwFlags: 0,
        )
        var bytesSent: culong = 0
        let res =
          WSASendMsg(SocketHandle(quicCtx.fd), addr msg, 0, addr bytesSent, nil, nil)
        if res != 0:
          setSendErrno(wsaGetLastError())
          if sent == 0:
            return -1
          break
      else:
        let msg = makeMsgHdr(curr, destStorage, destAddrLen)

        let res = sendmsg(SocketHandle(quicCtx.fd), msg.addr, 0)
        if res < 0:
          trace "sendmsg failed", sent, nspecs
          if sent == 0:
            return -1
          break

      sent.inc

    sent.cint

when defined(linux):
  type GsoCmsgBuf = object
    data {.align(8).}: array[32, byte] # >= CMSG_SPACE(sizeof(uint16)) everywhere

  proc makeGsoMsgHdr(
      destStorage: var Sockaddr_storage,
      destAddrLen: SockLen,
      iov: ptr IOVec,
      iovlen: int,
      control: pointer,
      controllen: SockLen,
  ): Tmsghdr =
    when defined(x86_64) and not defined(android):
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: iov,
        msg_iovlen: iovlen.csize_t,
        msg_control: control,
        msg_controllen: controllen,
        msg_flags: 0,
      )
    else:
      Tmsghdr(
        msg_name: cast[pointer](addr destStorage),
        msg_namelen: destAddrLen,
        msg_iov: iov,
        msg_iovlen: iovlen.cint,
        msg_control: control,
        msg_controllen: controllen,
        msg_flags: 0,
      )

  proc sendOneSpec(quicCtx: QuicContext, spec: struct_lsquic_out_spec): int =
    var
      destStorage: Sockaddr_storage
      destAddrLen: SockLen
    prepareDestAddr(spec.local_sa, spec.dest_sa, destStorage, destAddrLen)
    let msg = makeMsgHdr(spec, destStorage, destAddrLen)
    sendmsg(SocketHandle(quicCtx.fd), msg.addr, 0)

  proc sendSegmented(
      quicCtx: QuicContext,
      specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
      nspecs: int,
  ): cint =
    ## Sends each multi-packet group as one segmented datagram. Returns the
    ## number of specs sent, always as a prefix of the batch.
    var
      groups {.noinit.}: array[MaxBatch, GsoGroup]
      iovPool {.noinit.}: array[MaxBatch, IOVec]
      destStorages {.noinit.}: array[SendmmsgBatchSize, Sockaddr_storage]
      msgs {.noinit.}: array[SendmmsgBatchSize, MMsgHdr]
      cmsgBufs {.noinit.}: array[SendmmsgBatchSize, GsoCmsgBuf]

    let ngroups = groupSpecs(specsArr, nspecs, groups)

    var g = 0
    while g < ngroups:
      let nmsgs = min(ngroups - g, SendmmsgBatchSize)
      var iovUsed = 0
      for m in 0 ..< nmsgs:
        let
          grp = addr groups[g + m]
          first = grp.firstSpec.int
          head = addr specsArr[first]
        var destAddrLen: SockLen
        prepareDestAddr(head.local_sa, head.dest_sa, destStorages[m], destAddrLen)
        if grp.useGso:
          let iovStart = iovUsed
          for j in 0 ..< grp.count.int:
            let s = addr specsArr[first + j]
            iovPool[iovUsed] =
              IOVec(iov_base: s.iov[].iov_base, iov_len: s.iov[].iov_len)
            inc iovUsed
          msgs[m] = MMsgHdr(
            msg_hdr: makeGsoMsgHdr(
              destStorages[m],
              destAddrLen,
              addr iovPool[iovStart],
              grp.count.int,
              cast[pointer](addr cmsgBufs[m]),
              SockLen(CMSG_SPACE(2)),
            ),
            msg_len: 0,
          )
          let hdr = CMSG_FIRSTHDR(addr msgs[m].msg_hdr)
          hdr.cmsg_level = SOL_UDP
          hdr.cmsg_type = UDP_SEGMENT
          hdr.cmsg_len = SockLen(CMSG_LEN(2))
          cast[ptr uint16](CMSG_DATA(hdr))[] = uint16(grp.segSize)
        else:
          msgs[m] = MMsgHdr(
            msg_hdr: makeMsgHdr(head[], destStorages[m], destAddrLen), msg_len: 0
          )

      let res = sendmmsg(SocketHandle(quicCtx.fd), addr msgs[0], nmsgs.cuint, 0)
      if res < 0:
        # the first message of this chunk failed, so groups[g] is the failed
        # group
        let
          savedErrno = errno
          p = groups[g].firstSpec.int
        if savedErrno == EMSGSIZE and groups[g].useGso:
          # send each member alone, so lsquic gets one EMSGSIZE per packet
          for j in 0 ..< groups[g].count.int:
            let idx = p + j
            if sendOneSpec(quicCtx, specsArr[idx]) < 0:
              # members are adjacent, so this is the first unsent spec of the
              # batch and can keep its own errno
              let memberErrno = errno
              trace "gso member resend failed", idx, nspecs
              errno = memberErrno
              if idx == 0:
                return -1
              return idx.cint
          inc g
          continue
        if savedErrno == EIO or savedErrno == EINVAL or savedErrno == ENOTSUP or
            savedErrno == EOPNOTSUPP:
          # the kernel refused the segmented send
          quicCtx.gso.enabled = false
          info "UDP GSO disabled after send error", errorCode = savedErrno
          let plainSent = sendPlain(quicCtx, specsArr, p, nspecs)
          if plainSent < 0:
            if p == 0:
              return -1
            return p.cint
          return (p + plainSent).cint
        trace "gso sendmmsg failed", p, nspecs
        errno = if savedErrno == EWOULDBLOCK: EAGAIN else: savedErrno
        if p == 0:
          return -1
        return p.cint

      g += res
      if res < nmsgs.cint:
        # sendmmsg does not report the error that stopped it
        trace "gso sendmmsg partially sent", sentGroups = g, ngroups, nspecs
        errno = EAGAIN
        return groups[g].firstSpec.cint

    nspecs.cint

when defined(windows):
  proc sendOneSpec(quicCtx: QuicContext, spec: struct_lsquic_out_spec): cint =
    ## Sends one spec without segmentation. On failure the caller reads
    ## wsaGetLastError. Only GSO group members use this proc.
    doAssert spec.iovlen == 1
    var
      destStorage: Sockaddr_storage
      destAddrLen: SockLen
    prepareDestAddr(spec.local_sa, spec.dest_sa, destStorage, destAddrLen)
    var buf =
      WSABUF(len: culong(spec.iov[].iov_len), buf: cast[ptr char](spec.iov[].iov_base))
    var msg = WSAMSG(
      name: cast[ptr SockAddr](addr destStorage),
      namelen: cint(destAddrLen),
      lpBuffers: addr buf,
      dwBufferCount: 1,
      control: WSABUF(len: 0, buf: nil),
      dwFlags: 0,
    )
    var bytesSent: culong = 0
    WSASendMsg(SocketHandle(quicCtx.fd), addr msg, 0, addr bytesSent, nil, nil)

  proc sendSegmented(
      quicCtx: QuicContext,
      specsArr: ptr UncheckedArray[struct_lsquic_out_spec],
      nspecs: int,
  ): cint =
    ## Sends each multi-packet group as one segmented datagram. Windows has no
    ## sendmmsg, so this proc sends one WSASendMsg per group. Returns a prefix
    ## count, as the Linux path does.
    var
      groups {.noinit.}: array[MaxBatch, GsoGroup]
      bufPool {.noinit.}: array[MaxBatch, WSABUF]
      cmsgBuf {.align(8).}: array[32, byte]

    let ngroups = groupSpecs(specsArr, nspecs, groups)

    var g = 0
    while g < ngroups:
      let
        grp = addr groups[g]
        first = grp.firstSpec.int
        head = addr specsArr[first]
      var
        destStorage: Sockaddr_storage
        destAddrLen: SockLen
      prepareDestAddr(head.local_sa, head.dest_sa, destStorage, destAddrLen)

      var msg = WSAMSG(
        name: cast[ptr SockAddr](addr destStorage),
        namelen: cint(destAddrLen),
        control: WSABUF(len: 0, buf: nil),
        dwFlags: 0,
      )
      if grp.useGso:
        for j in 0 ..< grp.count.int:
          let s = addr specsArr[first + j]
          bufPool[j] =
            WSABUF(len: culong(s.iov[].iov_len), buf: cast[ptr char](s.iov[].iov_base))
        msg.lpBuffers = addr bufPool[0]
        msg.dwBufferCount = culong(grp.count)
        let hdr = cast[ptr WsaCmsgHdr](addr cmsgBuf[0])
        hdr.cmsg_len = csize_t(WsaCmsgLen)
        hdr.cmsg_level = IPPROTO_UDP
        hdr.cmsg_type = UDP_SEND_MSG_SIZE
        cast[ptr DWORD](addr cmsgBuf[WsaCmsgDataOff])[] = DWORD(grp.segSize)
        msg.control =
          WSABUF(len: culong(WsaCmsgSpace), buf: cast[ptr char](addr cmsgBuf[0]))
      else:
        let iovArr = cast[ptr UncheckedArray[struct_iovec]](head.iov)
        for j in 0 ..< head.iovlen.int:
          bufPool[j] = WSABUF(
            len: culong(iovArr[j].iov_len), buf: cast[ptr char](iovArr[j].iov_base)
          )
        msg.lpBuffers = addr bufPool[0]
        msg.dwBufferCount = culong(head.iovlen)

      var bytesSent: culong = 0
      let res =
        WSASendMsg(SocketHandle(quicCtx.fd), addr msg, 0, addr bytesSent, nil, nil)
      if res != 0:
        let
          wsaErr = wsaGetLastError()
          p = grp.firstSpec.int
        if wsaErr == WSAEMSGSIZE and grp.useGso:
          # send each member alone, so lsquic gets one error per packet
          for j in 0 ..< grp.count.int:
            let idx = p + j
            if sendOneSpec(quicCtx, specsArr[idx]) != 0:
              # members are adjacent, so this is the first unsent spec of the
              # batch and can keep its own error
              setSendErrno(wsaGetLastError())
              if idx == 0:
                return -1
              return idx.cint
          inc g
          continue
        if wsaErr == WSAEINVAL or wsaErr == WSAEOPNOTSUPP or wsaErr == WSAENOPROTOOPT:
          # the stack refused the segmented send
          quicCtx.gso.enabled = false
          let plainSent = sendPlain(quicCtx, specsArr, p, nspecs)
          if plainSent < 0:
            if p == 0:
              return -1
            return p.cint
          return (p + plainSent).cint
        setSendErrno(wsaErr)
        if p == 0:
          return -1
        return p.cint

      inc g

    nspecs.cint

proc sendPacketsOut*(
    ctx: pointer, specs: ptr struct_lsquic_out_spec, nspecs: cuint
): cint {.cdecl.} =
  let quicCtx = cast[QuicContext](ctx)
  if nspecs == 0:
    return 0

  let specsArr = cast[ptr UncheckedArray[struct_lsquic_out_spec]](specs)
  when defined(linux) or defined(windows):
    if quicCtx.gso.enabled and nspecs.int <= MaxBatch:
      return sendSegmented(quicCtx, specsArr, nspecs.int)
  sendPlain(quicCtx, specsArr, 0, nspecs.int)

when defined(lsquic_testing):
  proc prepareDestAddrForTest*(
      localSa: ptr SockAddr,
      destSa: ptr SockAddr,
      destStorage: var Sockaddr_storage,
      destAddrLen: var SockLen,
  ) =
    ## Test-only accessor for the destination remapping.
    prepareDestAddr(localSa, destSa, destStorage, destAddrLen)
