import chronos
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

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t = nil): T =
  Stream(
    quicStream: quicStream,
    incoming: newAsyncQueue[seq[byte]](),
    closed: newAsyncEvent(),
  )

proc close*(stream: Stream): bool =
  if stream.closeWrite:
    return true

  # Closing only the write side
  let ret = lsquic_stream_shutdown(stream.quicStream, 1)
  if ret == 0:
    if stream.isEof:
      if lsquic_stream_close(stream.quicStream) != 0:
        raise newException(StreamError, "could not close the stream")

    stream.closeWrite = true
    return true
  false
  # TODO: clear all pending writes

proc abort*(stream: Stream): bool =
  let ret = lsquic_stream_close(stream.quicStream) == 0
  if ret:
    stream.closeWrite = true
    stream.isEof = true
    return true
  false
  # TODO: clear all pending writes and cancel reads

proc read*(
    stream: Stream
): Future[seq[byte]] {.async: (raises: [CancelledError, StreamError]).} =
  if stream.isEof:
    return @[]

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    discard stream.abort()
    raise newException(StreamError, "could not set wantread")

  let incomingFut = stream.incoming.get()
  let closedFut = stream.closed.wait()
  let raceFut = await race(closedFut, incomingFut)
  if raceFut == closedFut:
    await incomingFut.cancelAndWait()
    stream.isEof = true
    stream.closeWrite = true
    raise newException(StreamError, "connection closed")

  let incoming = await incomingFut
  if incoming.len == 0:
    if stream.closeWrite:
      # We were already closed for write. Close the stream completely
      if lsquic_stream_close(stream.quicStream) != 0:
        discard stream.abort()
        raise newException(StreamError, "could not close the stream")
    stream.isEof = true

  return incoming

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if stream.closeWrite:
    raise newException(StreamError, "stream is closed")

  let closedFut = stream.closed.wait()
  let doneFut = Future[void].Raising([CancelledError, StreamError]).init()
  stream.toWrite.add(WriteTask(data: data, doneFut: doneFut))
  discard lsquic_stream_wantwrite(stream.quicStream, 1)
  let raceFut = await race(closedFut, doneFut)
  if raceFut == closedFut:
    doneFut.fail(newException(StreamError, "connection closed"))
    stream.closeWrite = true

  await doneFut
