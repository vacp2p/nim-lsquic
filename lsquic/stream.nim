import ./lsquic_ffi

type StreamError* = object of IOError

type Stream* = ref object
  quicStream*: ptr lsquic_stream_t
  localClosed*: bool
  remoteClosed*: bool
  reset*: bool

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t): T =
  Stream(quicStream: quicStream)
