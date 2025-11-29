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

  if streamCtx.toRead.len > 0:
    let e = newException(StreamError, "stream closed")
    for t in streamCtx.toRead:
      if not t.doneFut.finished:
        t.doneFut.fail(e)
    streamCtx.toRead.clear()

  GC_unref(streamCtx)

proc onRead*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "stream read"
  if ctx.isNil:
    debug "stream_ctx is nil onRead"
    return

  let streamCtx = cast[Stream](ctx)
  

  # keep going while there's pending read tasks and stream still has data (or fin)
  while streamCtx.toRead.len > 0:
    var task = streamCtx.toRead.popFirst()
    if task.dataLen <= 0:
      task.doneFut.complete(0)
      continue

    let n = lsquic_stream_read(stream, task.data, task.dataLen.csize_t)

    # TODO: handle errs diff from EWOULDBLOCK
    # TODO: duplication
    if n < 0 and errno == EWOULDBLOCK:
      streamCtx.toRead.addFirst(task)
      return

    if n > 0:
      task.doneFut.complete(int(n))
      continue

    if n == 0:
      streamCtx.isEof = true
      streamCtx.toRead.addFirst(task)
      for t in streamCtx.toRead:
        if not t.doneFut.finished:
          t.doneFut.complete(0)
      streamCtx.toRead.clear()
      break

  # Nothing waiting to read yet. Stop callbacks until a reader shows up.
  if lsquic_stream_wantread(stream, 0) == -1:
    error "could not set stream wantread", streamId = lsquic_stream_id(stream)
    streamCtx.abort()

proc onWrite*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "onWrite"

  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)

  # always drain from head of queue to preserve order
  while streamCtx.toWrite.len > 0:
    var w = streamCtx.toWrite.popFirst()
    let p = w.data[w.offset].addr
    let nAvail = (w.data.len - w.offset).csize_t
    let n: ssize_t = lsquic_stream_write(stream, p, nAvail)
    if n > 0:
      w.offset += n.int
      if w.offset >= w.data.len:
        if not w.doneFut.finished:
          w.doneFut.complete()
      else:
        streamCtx.toWrite.addFirst(w)
    elif n == 0:
      # Nothing to write
      streamCtx.toWrite.addFirst(w)
      break
    else:
      streamCtx.toWrite.addFirst(w)
      streamCtx.abortPendingWrites("write failed")
      break

  if lsquic_stream_flush(stream) != 0:
    streamCtx.abort()
    return

  if streamCtx.toWrite.len == 0:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      error "could not set stream wantwrite", streamId = lsquic_stream_id(stream)
      streamCtx.abort()
