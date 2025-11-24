import std/deques
import chronos
import chronicles
import ./lsquic_ffi

type StreamError* = object of IOError

type WriteTask = object
  data*: seq[byte]
  offset*: int
  doneFut*: Future[void].Raising([CancelledError, StreamError])

type ReadTask* = object
  data*: ptr byte
  dataLen*: int
  doneFut*: Future[int].Raising([CancelledError, StreamError])

type Stream* = ref object
  quicStream*: ptr lsquic_stream_t
  closedByEngine*: bool
  closeWrite*: bool
  # This is called when on_close callback is executed
  closed*: AsyncEvent
  # Reuse a single closed-event waiter to minimize allocations on hot paths.
  # (no per call allocation)
  closedWaiter*: Future[void].Raising([CancelledError])
  isEof*: bool # Received a FIN from remote
  toWrite*: Deque[WriteTask]
  toRead*: Deque[ReadTask]
  doProcess*: proc() {.gcsafe, raises: [].}

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t = nil): T =
  let closed = newAsyncEvent()
  let closedWaiter = closed.wait()
  let s = Stream(quicStream: quicStream, closed: closed, closedWaiter: closedWaiter)
  GC_ref(s) # Keep it pinned until stream_if.on_close is executed
  s

proc abortPendingWrites*(stream: Stream, reason: string = "") =
  for pendingWrite in stream.toWrite.mitems:
    if not pendingWrite.doneFut.finished:
      pendingWrite.doneFut.fail(newException(StreamError, reason))
  stream.toWrite.clear()

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
  if dstLen == 0 or dst.isNil:
    raiseAssert "dst cannot be nil"

  if stream.isEof or stream.closedByEngine:
    return 0

  let doneFut = Future[int].Raising([CancelledError, StreamError]).init()
  stream.toRead.addLast(ReadTask(data: dst, dataLen: dstLen, doneFut: doneFut))

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    stream.abort()
    raise newException(StreamError, "could not set wantread")

  let raceFut = await race(stream.closedWaiter, doneFut)
  if raceFut == stream.closedWaiter:
    await doneFut.cancelAndWait()
    stream.isEof = true
    stream.closeWrite = true
    return 0

  return await doneFut

template readInto*(stream: Stream, dst: var openArray[byte]): untyped =
  ## Convenience helper that forwards an openArray/seq to the pointer-based API.
  (if dst.len == 0: stream.readInto(nil, 0)
  else: stream.readInto(dst[0].addr, dst.len))

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if stream.closeWrite or stream.closedByEngine:
    raise newException(StreamError, "stream closed")

  # Apply simple backpressure: block when queued bytes exceed the cap.
  while stream.toWrite.len > 0:
    let head = stream.toWrite.peekFirst()
    if head.doneFut.finished:
      break
    let raceFut = await race(stream.closedWaiter, head.doneFut)
    if raceFut == stream.closedWaiter:
      stream.closeWrite = true
      raise newException(StreamError, "stream closed")

  let doneFut = Future[void].Raising([CancelledError, StreamError]).init()
  stream.toWrite.addLast(WriteTask(data: data, doneFut: doneFut))
  discard lsquic_stream_wantwrite(stream.quicStream, 1)
  stream.doProcess()

  let raceFut = await race(stream.closedWaiter, doneFut)
  if raceFut == stream.closedWaiter:
    if not doneFut.finished:
      doneFut.fail(newException(StreamError, "stream closed"))
    stream.closeWrite = true

  await doneFut
