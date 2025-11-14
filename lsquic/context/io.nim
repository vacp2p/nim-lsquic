import chronos
import chronicles
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[openarray, sequninit]

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

proc sendPacketsOut*(
    ctx: pointer, specs: ptr struct_lsquic_out_spec, nspecs: cuint
): cint {.cdecl.} =
  let quicCtx = cast[QuicContext](ctx)
  var sent = 0
  let specsArr = cast[ptr UncheckedArray[struct_lsquic_out_spec]](specs)
  for i in 0 ..< nspecs.int:
    let curr = specsArr[i]
    let sock = cast[ptr SockAddr](curr.dest_sa)
    var destAddress: Sockaddr_storage
    let destAddrLen: SockLen =
      case sock.sa_family.uint16
      of AF_INET.uint16:
        sizeof(Sockaddr_in).uint32
      of AF_INET6.uint16:
        sizeof(Sockaddr_in6).uint32
      else:
        0.uint32
    copyMem(addr destAddress, curr.dest_sa, destAddrLen)
    var taddr: TransportAddress
    fromSAddr(addr destAddress, destAddrLen, taddr)

    let iovArr = cast[ptr UncheckedArray[struct_iovec]](curr.iov)
    var totalLen: int = 0
    for j in 0 ..< curr.iovlen.int:
      totalLen += iovArr[j].iov_len.int

    let data = newSeqUninit[byte](totalLen)
    var currLen: int = 0
    for j in 0 ..< curr.iovlen.int:
      let currIov = iovArr[j]
      if currIov.iov_len == 0:
        continue
      copyMem(addr data[currLen], currIov.iov_base, currIov.iov_len)
      currLen += currIov.iov_len.int

    let datagram = Datagram(data: data, ecn: curr.ecn, taddr: taddr)
    try:
      quicCtx.outgoing.putNoWait(datagram)
      sent.inc
    except AsyncQueueFullError:
      discard # nothing to do

  sent.cint
