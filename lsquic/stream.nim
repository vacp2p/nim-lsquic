import chronos
import ./lsquic_ffi

type StreamError* = object of IOError

type Stream* = ref object
  quicStream*: ptr lsquic_stream_t
  closeWrite*: bool
  incoming*: AsyncQueue[seq[byte]]
  closed*: AsyncEvent # This is called when on_close callback is executed
  isEof*: bool # Received a FIN from remote

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t): T =
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

proc abort*(stream: Stream): bool =
  let ret = lsquic_stream_close(stream.quicStream) == 0
  if ret:
    stream.closeWrite = true
    stream.isEof = true
    return true
  false

proc read*(
    stream: Stream
): Future[seq[byte]] {.async: (raises: [CancelledError, StreamError]).} =
  if stream.isEof:
    return @[]

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    discard stream.abort()
    raise newException(StreamError, "could not set wantread")

  try:
    let incomingFut = stream.incoming.get()
    let closedFut = stream.closed.wait()
    let raceFut = await race(closedFut, incomingFut)
    if raceFut == closedFut:
      await incomingFut.cancelAndWait()
      stream.isEof = true
      stream.closeWrite = true
      raise newException(StreamError, "connection closed")
    return await incomingFut
  except AsyncQueueEmptyError:
    if stream.closeWrite:
      if lsquic_stream_close(stream.quicStream) != 0:
        discard stream.abort()
        raise newException(StreamError, "could not close the stream")
    stream.isEof = true
    return @[]

proc write*(
    stream: Stream, bytes: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  # TODO:
  discard
