import chronicles
import ../[lsquic_ffi, stream]

proc onClose*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "Stream closed"
  if ctx.isNil:
    debug "stream_ctx is nil onClose"

  let streamCtx = cast[Stream](ctx)
  if not streamCtx.localClosed:
    streamCtx.remoteClosed = true
  # TODO: reset / eof

proc onReset*(
    stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t, how: cint
) {.cdecl.} =
  trace "Stream reset", how

  if ctx.isNil:
    debug "stream_ctx is nil onReset"
    return

  let streamCtx = cast[Stream](ctx)
  if streamCtx.reset:
    return
  streamCtx.reset = true

  if (how == 0 or how == 1):
    discard lsquic_stream_wantread(stream, 0)

  if (how == 1 or how == 2):
    discard lsquic_stream_wantwrite(stream, 0)

  # TODO: reset / eof
