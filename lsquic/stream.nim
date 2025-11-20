import chronos
import chronicles
import ./lsquic_ffi

type StreamError* = object of IOError

type WriteTask = ref object
  data*: seq[byte]
  offset*: int
  doneFut*: Future[void].Raising([CancelledError, StreamError])

type Stream* = ref object
  quicStream*: ptr lsquic_stream_t
  closedByEngine*: bool
  closeWrite*: bool
  incoming*: AsyncQueue[seq[byte]]
  closed*: AsyncEvent # This is called when on_close callback is executed
  isEof*: bool # Received a FIN from remote
  toWrite*: seq[WriteTask]
  readBuf: seq[byte] # Cached incoming chunk when readInto only partially consumes it
  readOffset: int
  doProcess*: proc() {.gcsafe, raises: [].}

template readInto*(
    stream: Stream, dst: var openArray[byte]
): untyped =
  ## Convenience helper that forwards an openArray/seq to the pointer-based API.
  (if dst.len == 0: stream.readInto(cast[ptr byte](nil), 0)
   else: stream.readInto(dst[0].addr, dst.len))

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t = nil): T =
  let s = Stream(
    quicStream: quicStream,
    incoming: newAsyncQueue[seq[byte]](),
    closed: newAsyncEvent(),
  )
  GC_ref(s) # Keep it pinned until stream_if.on_close is executed
  s

proc abortPendingWrites*(stream: Stream, reason: string = "") =
  for pendingWrite in stream.toWrite.mitems:
    if not pendingWrite.doneFut.finished:
      pendingWrite.doneFut.fail(newException(StreamError, reason))
  stream.toWrite.setLen(0)

proc abort*(stream: Stream) =
  if stream.closeWrite and stream.isEof:
    if not stream.closed.isSet():
      stream.closed.fire()
    stream.abortPendingWrites("stream aborted")
    return

  if not stream.closedByEngine:
    let ret = lsquic_stream_close(stream.quicStream)
    if ret != 0:
      trace "could not abort stream", streamId = lsquic_stream_id(stream.quicStream)
    stream.doProcess()

  stream.closeWrite = true
  stream.isEof = true
  stream.abortPendingWrites("stream aborted")
  stream.closed.fire()

proc close*(stream: Stream) {.async: (raises: [StreamError, CancelledError]).} =
  if stream.closeWrite or stream.closedByEngine:
    return

  # Closing only the write side
  let ret = lsquic_stream_shutdown(stream.quicStream, 1)
  if ret == 0:
    if stream.isEof:
      if lsquic_stream_close(stream.quicStream) != 0:
        stream.abort()
        raise newException(StreamError, "could not close the stream")
      stream.doProcess()

    stream.abortPendingWrites("steam closed")
    stream.closeWrite = true

proc readInto*(
    stream: Stream, dst: ptr byte, dstLen: int
): Future[int] {.async: (raises: [CancelledError, StreamError]).} =
  ## Reads available data into the caller-provided buffer at `dst`, up to `dstLen`
  ## bytes. Returns the number of bytes copied, or 0 on EOF. The caller owns the
  ## buffer and ensures it stays alive for the duration of the await.
  if dstLen == 0 or dst.isNil:
    return 0

  # Serve from cached chunk first (even if we've already seen EOF).
  if stream.readOffset < stream.readBuf.len:
    let n = min(dstLen, stream.readBuf.len - stream.readOffset)
    copyMem(dst, stream.readBuf[stream.readOffset].addr, n)
    stream.readOffset.inc(n)
    if stream.readOffset >= stream.readBuf.len:
      stream.readBuf.setLen(0)
      stream.readOffset = 0
    return n

  if stream.isEof or stream.closedByEngine:
    return 0

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    stream.abort()
    raise newException(StreamError, "could not set wantread")

  let incomingFut = stream.incoming.get()
  let closedFut = stream.closed.wait()
  let raceFut = await race(closedFut, incomingFut)
  if raceFut == closedFut:
    await incomingFut.cancelAndWait()
    stream.isEof = true
    stream.closeWrite = true
    return 0

  let incoming = await incomingFut
  if incoming.len == 0:
    if stream.closeWrite and not stream.closedByEngine:
      # We were already closed for write. Close the stream completely
      if lsquic_stream_close(stream.quicStream) != 0:
        stream.abort()
        raise newException(StreamError, "could not close the stream")
      stream.doProcess()
    stream.isEof = true
    return 0

  let copied = min(dstLen, incoming.len)
  copyMem(dst, incoming[0].addr, copied)

  if copied < incoming.len:
    # Save the remainder for the next call without another memcpy.
    stream.readBuf = incoming
    stream.readOffset = copied

  return copied

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if stream.closeWrite or stream.closedByEngine:
    raise newException(StreamError, "stream closed")

  let closedFut = stream.closed.wait()
  let doneFut = Future[void].Raising([CancelledError, StreamError]).init()
  stream.toWrite.add(WriteTask(data: data, doneFut: doneFut))
  discard lsquic_stream_wantwrite(stream.quicStream, 1)
  stream.doProcess()

  let raceFut = await race(closedFut, doneFut)
  if raceFut == closedFut:
    if not doneFut.finished:
      doneFut.fail(newException(StreamError, "stream closed"))
    stream.closeWrite = true

  await doneFut
