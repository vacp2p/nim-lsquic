import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[openarray, sequninit]
import std/[nativesockets, net]

when not defined(windows):
  import posix

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
  var sent = 0
  let specsArr = cast[ptr UncheckedArray[struct_lsquic_out_spec]](specs)
  for i in 0 ..< nspecs.int:
    let curr = specsArr[i]

    let destAddrLen: SockLen =
      case curr.dest_sa.sa_family.uint16
      of AF_INET.uint16:
        sizeof(Sockaddr_in).uint32
      of AF_INET6.uint16:
        sizeof(Sockaddr_in6).uint32
      else:
        0.uint32

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
        break
    else:
      let msg =
        when defined(linux) and defined(x86_64):
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
        break

    sent.inc

  sent.cint
