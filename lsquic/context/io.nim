import chronos
import chronos/osdefs
import ./context
import ../[lsquic_ffi, datagram]
import ../helpers/[openarray, sequninit, transportaddr]

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

    let iovArr = cast[ptr UncheckedArray[struct_iovec]](curr.iov)
    var totalLen: int = 0
    for j in 0 ..< curr.iovlen.int:
      totalLen += iovArr[j].iov_len.int

    if totalLen == 0:
      continue

    let taddr = toTransportAddress(curr.dest_sa)
    let data = newSeqUninit[byte](totalLen)
    var currLen: int = 0
    for j in 0 ..< curr.iovlen.int:
      let currIov = iovArr[j]
      if currIov.iov_len == 0:
        continue
      copyMem(addr data[currLen], currIov.iov_base, currIov.iov_len)
      currLen += currIov.iov_len.int

    try:
      discard quicCtx.dtp.sendTo(taddr, data)
    except TransportError:
      discard

    sent.inc

  sent.cint
