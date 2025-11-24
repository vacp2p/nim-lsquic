import chronos
import chronicles
import ./lsquic_ffi
import std/deques

const
  defaultMaxQueuedBytes = 4 * 1024 * 1024

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
  closed*: AsyncEvent # This is called when on_close callback is executed
  closedWaiter*: Future[void].Raising([CancelledError])
  isEof*: bool # Received a FIN from remote
  toWrite*: Deque[WriteTask]
  queuedWriteBytes*: int
  maxQueuedBytes*: int
  toRead*: Deque[ReadTask]
  doProcess*: proc() {.gcsafe, raises: [].}

template readInto*(stream: Stream, dst: var openArray[byte]): untyped =
  ## Convenience helper that forwards an openArray/seq to the pointer-based API.
  (
    if dst.len == 0: stream.readInto(cast[ptr byte](nil), 0)
    else: stream.readInto(dst[0].addr, dst.len)
  )

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t = nil): T =
  let s = Stream(
    quicStream: quicStream,
    closed: newAsyncEvent(),
    maxQueuedBytes: defaultMaxQueuedBytes,
  )
  GC_ref(s) # Keep it pinned until stream_if.on_close is executed
  s

proc closedWait*(stream: Stream): Future[void].Raising([CancelledError]) {.inline.} =
  ## Lazily create a single waiter for the closed event to avoid per-call allocations.
  if stream.closedWaiter.isNil:
    stream.closedWaiter = stream.closed.wait()
  stream.closedWaiter

proc abortPendingWrites*(stream: Stream, reason: string = "") =
  for pendingWrite in stream.toWrite.mitems:
    if not pendingWrite.doneFut.finished:
      pendingWrite.doneFut.fail(newException(StreamError, reason))
  stream.queuedWriteBytes = 0
  stream.toWrite = initDeque[WriteTask]()

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
    return 0

  if stream.isEof or stream.closedByEngine:
    return 0

  let doneFut = Future[int].Raising([CancelledError, StreamError]).init()
  stream.toRead.addLast(ReadTask(data: dst, dataLen: dstLen, doneFut: doneFut))

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    stream.abort()
    raise newException(StreamError, "could not set wantread")

  let closedFut = stream.closedWait()
  let raceFut = await race(closedFut, doneFut)
  if raceFut == closedFut:
    await doneFut.cancelAndWait()
    stream.isEof = true
    stream.closeWrite = true
    return 0

  return await doneFut

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if stream.closeWrite or stream.closedByEngine:
    raise newException(StreamError, "stream closed")

  let closedFut = stream.closedWait()

  # Apply simple backpressure: block when queued bytes exceed the cap.
  while stream.toWrite.len > 0 and
        stream.queuedWriteBytes + data.len > stream.maxQueuedBytes:
    let head = stream.toWrite.peekFirst()
    if head.doneFut.finished:
      break
    let raceFut = await race(closedFut, head.doneFut)
    if raceFut == closedFut:
      stream.closeWrite = true
      raise newException(StreamError, "stream closed")

  let doneFut = Future[void].Raising([CancelledError, StreamError]).init()
  stream.queuedWriteBytes += data.len
  stream.toWrite.addLast(WriteTask(data: data, doneFut: doneFut))
  discard lsquic_stream_wantwrite(stream.quicStream, 1)
  stream.doProcess()

  let raceFut = await race(closedFut, doneFut)
  if raceFut == closedFut:
    if not doneFut.finished:
      doneFut.fail(newException(StreamError, "stream closed"))
    stream.closeWrite = true

  await doneFut
