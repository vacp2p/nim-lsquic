import ./lsquic_ffi

type StreamError* = object of IOError

type Stream* = ref object
  quicStream*: ptr lsquic_stream_t
  localClosed*: bool
  remoteClosed*: bool
  reset*: bool

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t): T =
  Stream(quicStream: quicStream)

proc close*(stream: Stream): bool =
  let ret = lsquic_stream_shutdown(stream.quicStream, 1) # Only write
  if ret == 0:
    stream.localClosed = true
    return true
  false

proc abort*(stream: Stream): bool =
  let ret = lsquic_stream_close(stream.quicStream) == 0
  if ret:
    stream.localClosed = true
    return true
  false
