import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[openarray, sequninit]
import std/[nativesockets, net]

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

    let msg = Tmsghdr(
      msg_name: cast[pointer](curr.dest_sa),
      msg_namelen: destAddrLen,
      msg_iov: cast[ptr IOVec](curr.iov),
      msg_iovlen: curr.iovlen,
      msg_control: nil,
      msg_controllen: 0,
      msg_flags: 0,
    )

    let res = sendmsg(SocketHandle(quicCtx.fd), msg.addr, 0)
    if res < 0:
      break

    sent.inc

  sent.cint
