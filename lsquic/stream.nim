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
  closeWrite*: bool
  incoming*: AsyncQueue[seq[byte]]
  closed*: AsyncEvent # This is called when on_close callback is executed
  isEof*: bool # Received a FIN from remote
  toWrite*: seq[WriteTask]
  shouldClose*: Future[void].Raising([CancelledError])

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

  let ret = lsquic_stream_close(stream.quicStream)
  if ret != 0:
    error "could not abort stream", streamId = lsquic_stream_id(stream.quicStream)

  stream.closeWrite = true
  stream.isEof = true
  stream.abortPendingWrites("stream aborted")
  stream.closed.fire()

proc close*(stream: Stream) {.async: (raises: [StreamError, CancelledError]).} =
  if stream.closeWrite:
    return

  if stream.toWrite.len != 0:
    stream.shouldClose = Future[void].Raising([CancelledError]).init()
    await stream.shouldClose

  # Closing only the write side
  let ret = lsquic_stream_shutdown(stream.quicStream, 1)
  if ret == 0:
    if stream.isEof:
      if lsquic_stream_close(stream.quicStream) != 0:
        stream.abort()
        raise newException(StreamError, "could not close the stream")

    stream.abortPendingWrites("steam closed")
    stream.closeWrite = true

proc read*(
    stream: Stream
): Future[seq[byte]] {.async: (raises: [CancelledError, StreamError]).} =
  if stream.isEof:
    return @[]

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
    return @[]

  let incoming = await incomingFut
  if incoming.len == 0:
    if stream.closeWrite:
      # We were already closed for write. Close the stream completely
      if lsquic_stream_close(stream.quicStream) != 0:
        stream.abort()
        raise newException(StreamError, "could not close the stream")
    stream.isEof = true

  return incoming

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if stream.closeWrite:
    raise newException(StreamError, "stream closed 3")

  let closedFut = stream.closed.wait()
  let doneFut = Future[void].Raising([CancelledError, StreamError]).init()
  stream.toWrite.add(WriteTask(data: data, doneFut: doneFut))
  discard lsquic_stream_wantwrite(stream.quicStream, 1)
  let raceFut = await race(closedFut, doneFut)
  if raceFut == closedFut:
    if not doneFut.finished:
      doneFut.fail(newException(StreamError, "stream closed 2"))
    stream.closeWrite = true

  await doneFut
