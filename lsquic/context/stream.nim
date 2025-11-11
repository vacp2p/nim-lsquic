import chronicles
import chronos
import ../[lsquic_ffi, stream]
import ../helpers/sequninit

proc onClose*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "Stream closed"
  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)
  if not streamCtx.closeWrite:
    streamCtx.isEof = true
    streamCtx.closed.fire()
    # TODO: remove pending writes)

type StreamReadContext = object
  stream: ptr lsquic_stream_t
  ctx: ptr lsquic_stream_ctx_t

proc readCtxCb(
    ctx: pointer, data: ptr uint8, len: csize_t, fin: cint
): csize_t {.cdecl.} =
  let readContext = cast[ptr StreamReadContext](ctx)
  let streamCtx = cast[Stream](readContext.ctx)
  if len != 0:
    var s = newSeqUninit[byte](len)
    copyMem(addr s[0], data, len)
    streamCtx.incoming.putNoWait(s)
  if fin != 0:
    streamCtx.incoming.putNoWait(@[])
  len

proc onRead*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "stream read"
  let readContext = StreamReadContext(stream: stream, ctx: ctx)
  let nread = lsquic_stream_readf(stream, readCtxCb, (addr readContext))
  if nread < 0:
    discard
    # TODO: notify stream of error and close

  if lsquic_stream_wantread(stream, 0) == -1:
    discard
    # TODO: notify stream of error and close

proc onWrite*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "onWrite"

  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)
  if streamCtx.toWrite.len == 0:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      discard
      # TODO: notify stream of error and close

  # always drain from head of queue to preserve order
  while streamCtx.toWrite.len > 0:
    var w = streamCtx.toWrite[0]
    if w.offset >= w.data.len:
      if not w.doneFut.finished:
        w.doneFut.complete()
      streamCtx.toWrite.delete(0)
      continue

    let p = w.data[w.offset].addr
    let nAvail = (w.data.len - w.offset).csize_t
    let n: ssize_t = lsquic_stream_write(stream, p, nAvail)

    if n > 0:
      w.offset += n.int
      if w.offset >= w.data.len:
        if not w.doneFut.finished:
          w.doneFut.complete()
        if lsquic_stream_flush(stream) != 0:
          discard # TODO: handle error
        streamCtx.toWrite.delete(0)
    elif n == 0:
      # flow control; stop
      break
    else:
      # error: fail all pending
      for pendingWrite in streamCtx.toWrite.mitems:
        if not pendingWrite.doneFut.finished:
          pendingWrite.doneFut.fail(newException(StreamError, "write failed"))
      streamCtx.toWrite.setLen(0)
      return

  if streamCtx.toWrite.len == 0:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      discard # TODO: handle error

  return
