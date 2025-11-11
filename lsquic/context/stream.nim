import chronicles
import chronos
import ../[lsquic_ffi, stream]
import ../helpers/sequninit

proc onClose*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "Stream closed"
  if ctx.isNil:
    debug "stream_ctx is nil onClose"

  let streamCtx = cast[Stream](ctx)
  if not streamCtx.closeWrite:
    streamCtx.isEof = true
    streamCtx.closed.fire()
    # TODO: reset / eof?

type StreamReadContext = object
  stream: ptr lsquic_stream_t
  ctx: ptr lsquic_stream_ctx_t

proc readCtxCb(
    ctx: pointer, data: ptr uint8, len: csize_t, fin: cint
): csize_t {.cdecl.} =
  let readContext = cast[ptr StreamReadContext](ctx)
  let stream = cast[Stream](readContext.ctx)
  if len != 0:
    var s = newSeqUninit[byte](len)
    copyMem(addr s[0], data, len)
    stream.incoming.putNoWait(s)
  if fin != 0:
    stream.incoming.putNoWait(@[])
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
