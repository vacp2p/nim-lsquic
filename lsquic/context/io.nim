# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[openarray, transportaddr]
import std/nativesockets

when not defined(windows):
  import posix

when defined(linux):
  {.passc: "-D_GNU_SOURCE".}

  type MMsgHdr {.importc: "struct mmsghdr", header: "<sys/socket.h>", bycopy.} = object
    msg_hdr: Tmsghdr
    msg_len: cuint

  proc sendmmsg(
    sockfd: SocketHandle, msgvec: ptr MMsgHdr, vlen: cuint, flags: cint
  ): cint {.importc, header: "<sys/socket.h>".}

when defined(windows):
  import std/winlean

  {.pragma: wsa, stdcall, dynlib: "ws2_32.dll".}

  type WSABUF* = object
    len*: culong
    buf*: ptr char

  proc WSASendTo*(
    s: SocketHandle,
    lpBuffers: ptr WSABUF,
    dwBufferCount: culong,
    lpNumberOfBytesSent: ptr culong,
    dwFlags: culong,
    lpTo: ptr SockAddr,
    iToLen: cint,
    lpOverlapped: pointer,
    lpCompletionRoutine: pointer,
  ): cint {.wsa, importc: "WSASendTo".}

proc receive*(
    ctx: QuicContext,
    datagram: sink Datagram,
    local: TransportAddress,
    remote: TransportAddress,
) =
  if datagram.len == 0:
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
    datagram.data.toPtr,
    datagram.data.len.csize_t,
    cast[ptr SockAddr](addr localAddress),
    cast[ptr SockAddr](addr remoteAddress),
    cast[pointer](ctx),
    datagram.ecn,
  )

  ctx.processWhenReady()

proc sendPacketsOut*(
    ctx: pointer, specs: ptr struct_lsquic_out_spec, nspecs: cuint
): cint {.cdecl.} =
  let quicCtx = cast[QuicContext](ctx)
  if nspecs == 0:
    return 0

  let specsArr = cast[ptr UncheckedArray[struct_lsquic_out_spec]](specs)

  when defined(linux):
    var msgs = newSeq[MMsgHdr](nspecs.int)
    for i in 0 ..< nspecs.int:
      let curr = specsArr[i]
      let destAddrLen: SockLen = sockAddrLen(curr.dest_sa.sa_family.int)
      msgs[i] = MMsgHdr(
        msg_hdr:
          when defined(x86_64):
            Tmsghdr(
              msg_name: cast[pointer](curr.dest_sa),
              msg_namelen: destAddrLen,
              msg_iov: cast[ptr IOVec](curr.iov),
              msg_iovlen: curr.iovlen.csize_t,
              msg_control: nil,
              msg_controllen: 0,
              msg_flags: 0,
            )
          else:
            Tmsghdr(
              msg_name: cast[pointer](curr.dest_sa),
              msg_namelen: destAddrLen,
              msg_iov: cast[ptr IOVec](curr.iov),
              msg_iovlen: curr.iovlen.cint,
              msg_control: nil,
              msg_controllen: 0,
              msg_flags: 0,
            ),
        msg_len: 0,
      )

    let res = sendmmsg(SocketHandle(quicCtx.fd), addr msgs[0], nspecs, 0)
    let savedErrno = errno
    if res < nspecs.cint:
      if res < 0:
        errno = savedErrno
      else:
        errno = EAGAIN
    return res
  else:
    var sent = 0
    for i in 0 ..< nspecs.int:
      let curr = specsArr[i]

      let destAddrLen: SockLen = sockAddrLen(curr.dest_sa.sa_family.int)

      when defined(windows):
        let iovArr = cast[ptr UncheckedArray[struct_iovec]](curr.iov)

        var bufs = newSeq[WSABUF](curr.iovlen.int)
        for j in 0 ..< curr.iovlen.int:
          let src = iovArr[j]
          bufs[j].len = culong(src.iov_len)
          bufs[j].buf = cast[ptr char](src.iov_base)

        var bytesSent: culong = 0
        let res = WSASendTo(
          SocketHandle(quicCtx.fd),
          addr bufs[0],
          culong(curr.iovlen),
          addr bytesSent,
          0, # flags
          cast[ptr SockAddr](curr.dest_sa),
          cint(destAddrLen),
          nil,
          nil, # no overlapped
        )
        if res != 0:
          if sent == 0:
            return -1
          break
      else:
        let msg =
          when defined(x86_64):
            Tmsghdr(
              msg_name: cast[pointer](curr.dest_sa),
              msg_namelen: destAddrLen,
              msg_iov: cast[ptr IOVec](curr.iov),
              msg_iovlen: curr.iovlen.csize_t,
              msg_control: nil,
              msg_controllen: 0,
              msg_flags: 0,
            )
          else:
            Tmsghdr(
              msg_name: cast[pointer](curr.dest_sa),
              msg_namelen: destAddrLen,
              msg_iov: cast[ptr IOVec](curr.iov),
              msg_iovlen: curr.iovlen.cint,
              msg_control: nil,
              msg_controllen: 0,
              msg_flags: 0,
            )

        let res = sendmsg(SocketHandle(quicCtx.fd), msg.addr, 0)
        if res < 0:
          if sent == 0:
            return -1
          break

      sent.inc

    sent.cint
