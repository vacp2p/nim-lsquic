import std/[deques, posix]
import chronicles
import chronos
import ../[lsquic_ffi, stream]
import ../helpers/sequninit

proc onClose*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  debug "Stream closed"
  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)

  streamCtx.closedByEngine = true

  if not streamCtx.closeWrite:
    streamCtx.abortPendingWrites("stream closed")

  streamCtx.isEof = true

  # Always signal closure so waiters are released, even if we already shut down
  # the write side locally.
  if not streamCtx.closed.isSet():
    streamCtx.closed.fire()

  if streamCtx.toRead.isSome:
    let doneFut = streamCtx.toRead.unsafeGet().doneFut
    if not doneFut.finished:
      doneFut.fail(newException(StreamError, "stream closed"))

  GC_unref(streamCtx)

proc onRead*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "stream read"
  if ctx.isNil:
    debug "stream_ctx is nil onRead"
    return

  let streamCtx = cast[Stream](ctx)

  let task = streamCtx.toRead.valueOr:
    if lsquic_stream_wantread(stream, 0) == -1:
      error "could not set stream wantread", streamId = lsquic_stream_id(stream)
      streamCtx.abort()
    return

  let n = lsquic_stream_read(stream, task.data, task.dataLen.csize_t)

  # TODO: handle errs diff from EWOULDBLOCK

  if n < 0 and errno == EWOULDBLOCK:
    return

  if n == 0:
    streamCtx.isEof = true

  task.doneFut.complete(int(n))

  streamCtx.toRead = Opt.none(ReadTask)

proc onWrite*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "onWrite"

  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)

  var w = streamCtx.toWrite.valueOr:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      error "could not set stream wantwrite", streamId = lsquic_stream_id(stream)
      streamCtx.abort()
    return

  while not w.doneFut.finished:
    let p = w.data[w.offset].addr
    let nAvail = (w.data.len - w.offset).csize_t
    let n: ssize_t = lsquic_stream_write(stream, p, nAvail)
    if n > 0:
      w.offset += n.int
      if w.offset >= w.data.len:
        if not w.doneFut.finished:
          w.doneFut.complete()
    elif n == 0:
      # Nothing to write, try later
      break
    else:
      streamCtx.abortPendingWrites("write failed")
      break

  if lsquic_stream_flush(stream) != 0:
    streamCtx.abort()
    return

  if not w.doneFut.finished:
    streamCtx.toWrite = Opt.some(w)
    return

  streamCtx.toWrite = Opt.none(WriteTask)

  if lsquic_stream_wantwrite(stream, 0) == -1:
    echo "NO LONGER WANT TO WRITE"
    error "could not set stream wantwrite", streamId = lsquic_stream_id(stream)
    streamCtx.abort()
