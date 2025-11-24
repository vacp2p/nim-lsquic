import chronicles
import chronos
import ../[lsquic_ffi, stream]
import ../helpers/sequninit
import posix
import std/deques

const writeTrimThreshold = 64 * 1024

proc onClose*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  debug "Stream closed"
  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)

  streamCtx.closedByEngine = true

  if not streamCtx.closeWrite:
    streamCtx.abortPendingWrites("stream closed")

  # Always signal closure so waiters are released, even if we already shut down
  # the write side locally.
  streamCtx.isEof = true
  if not streamCtx.closed.isSet():
    streamCtx.closed.fire()

  if streamCtx.toRead.len > 0:
    let e = newException(StreamError, "stream closed")
    for t in streamCtx.toRead:
      if not t.doneFut.finished:
        t.doneFut.fail(e)
    streamCtx.toRead = initDeque[ReadTask]()

  GC_unref(streamCtx)

proc onRead*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "stream read"
  if ctx.isNil:
    debug "stream_ctx is nil onRead"
    return

  let streamCtx = cast[Stream](ctx)
  if streamCtx.toRead.len == 0:
    # Nothing waiting to read yet. Stop callbacks until a reader shows up.
    if lsquic_stream_wantread(stream, 0) == -1:
      error "could not set stream wantread", streamId = lsquic_stream_id(stream)
      streamCtx.abort()
    return

  # keep going while there's pending read tasks and stream still has data (or fin)
  while streamCtx.toRead.len > 0:
    var task = streamCtx.toRead.peekFirst()
    if task.dataLen <= 0:
      task.doneFut.complete(0)
      discard streamCtx.toRead.popFirst()
      continue

    let n = lsquic_stream_read(stream, task.data, csize_t(task.dataLen))

    if n > 0:
      task.doneFut.complete(int(n))
      discard streamCtx.toRead.popFirst()
      continue

    if n == 0:
      streamCtx.isEof = true
      for t in streamCtx.toRead:
        if not t.doneFut.finished:
          t.doneFut.complete(0)
      streamCtx.toRead = initDeque[ReadTask]()
      break

    if errno == EAGAIN:
      break

    for t in streamCtx.toRead:
      if not t.doneFut.finished:
        t.doneFut.fail(newException(StreamError, "could not read from stream"))
    streamCtx.toRead = initDeque[ReadTask]()
    break

proc onWrite*(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  trace "onWrite"

  if ctx.isNil:
    debug "stream_ctx is nil onClose"
    return

  let streamCtx = cast[Stream](ctx)
  if streamCtx.toWrite.len == 0:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      error "could not set stream wantwrite", streamId = lsquic_stream_id(stream)
      streamCtx.abort()

  # always drain from head of queue to preserve order
  while streamCtx.toWrite.len > 0:
    var w = streamCtx.toWrite.popFirst()
    if w.offset >= w.data.len:
      if not w.doneFut.finished:
        w.doneFut.complete()
      continue

    let p = w.data[w.offset].addr
    let nAvail = (w.data.len - w.offset).csize_t
    let n: ssize_t = lsquic_stream_write(stream, p, nAvail)
    if n > 0:
      streamCtx.queuedWriteBytes = max(streamCtx.queuedWriteBytes - n.int, 0)
      w.offset += n.int
      if w.offset >= writeTrimThreshold and w.offset < w.data.len:
        # Drop already-sent prefix to let GC reclaim memory on slow links.
        w.data = w.data[w.offset ..< w.data.len]
        w.offset = 0
        # queuedWriteBytes already tracks remaining bytes after decrement above.
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
      streamCtx.abortPendingWrites("write failed")
      return

  if lsquic_stream_flush(stream) != 0:
    streamCtx.abort()
    return

  if streamCtx.toWrite.len == 0:
    if lsquic_stream_wantwrite(stream, 0) == -1:
      error "could not set stream wantwrite", streamId = lsquic_stream_id(stream)
      streamCtx.abort()

  streamCtx.doProcess()

  return
