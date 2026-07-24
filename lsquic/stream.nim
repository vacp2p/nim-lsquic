# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import std/[deques, posix]
import chronos
import chronicles
import ./[lsquic_ffi, errors, tracking]

type WriteTask* = object
  data*: ptr byte
  dataLen*: int
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
  closeRequested: bool
  # This is called when on_close callback is executed
  closed*: AsyncEvent
  # Reuse a single closed-event waiter to minimize allocations on hot paths.
  # (no per call allocation)
  closedWaiter*: Future[void].Raising([CancelledError])
  resetByPeer*: bool
  resetHow*: StreamResetHow
  writeLock*: AsyncLock
  toWrite*: Opt[WriteTask]
  readLock*: AsyncLock
  isEof*: bool # Received a FIN from remote
  toRead*: Opt[ReadTask]
  doProcess*: proc() {.gcsafe, raises: [].}

proc new*(T: typedesc[Stream], quicStream: ptr lsquic_stream_t = nil): T =
  let closed = newAsyncEvent()
  let closedWaiter = closed.wait()
  let s = Stream(
    quicStream: quicStream,
    closed: closed,
    closedWaiter: closedWaiter,
    readLock: newAsyncLock(),
    writeLock: newAsyncLock(),
  )
  pin(s) # Keep it pinned until stream_if.on_close is executed
  s

proc readResetByPeer*(stream: Stream): bool {.raises: [].} =
  stream.resetByPeer and stream.resetHow in {ResetRead, ResetReadWrite}

proc writeResetByPeer*(stream: Stream): bool {.raises: [].} =
  stream.resetByPeer and stream.resetHow in {ResetWrite, ResetReadWrite}

proc markResetByPeer*(stream: Stream, how: StreamResetHow) {.raises: [].} =
  let mergedHow =
    if stream.resetByPeer and stream.resetHow != how: ResetReadWrite else: how

  stream.resetByPeer = true
  stream.resetHow = mergedHow

  if mergedHow in {ResetWrite, ResetReadWrite}:
    stream.closeWrite = true

proc newStreamResetError*(
    stream: Stream, operation: string
): ref StreamResetError {.raises: [].} =
  let exc = newException(
    StreamResetError, operation & " reset by peer (" & $stream.resetHow & ")"
  )
  exc.how = stream.resetHow
  exc

proc failPendingRead*(stream: Stream, error: ref StreamError) {.raises: [].} =
  let task = stream.toRead.valueOr:
    return
  if not task.doneFut.finished:
    task.doneFut.fail(error)
  stream.toRead = Opt.none(ReadTask)

proc abortPendingWrites*(stream: Stream, error: ref StreamError) {.raises: [].} =
  let task = stream.toWrite.valueOr:
    return
  if not task.doneFut.finished:
    task.doneFut.fail(error)
  stream.toWrite = Opt.none(WriteTask)

proc abortPendingWrites*(stream: Stream, reason: string = "") {.raises: [].} =
  stream.abortPendingWrites(newException(StreamError, reason))

proc clearPendingRead(
    stream: Stream, doneFut: Future[int].Raising([CancelledError, StreamError])
) {.raises: [].} =
  let task = stream.toRead.valueOr:
    return
  if task.doneFut != doneFut:
    return

  stream.toRead = Opt.none(ReadTask)

  if stream.closedByEngine or stream.quicStream.isNil:
    return

  if lsquic_stream_wantread(stream.quicStream, 0) == -1:
    error "could not set stream wantread",
      streamId = lsquic_stream_id(stream.quicStream)

proc clearPendingWrite(
    stream: Stream, doneFut: Future[void].Raising([CancelledError, StreamError])
) {.raises: [].} =
  let task = stream.toWrite.valueOr:
    return
  if task.doneFut != doneFut:
    return

  stream.toWrite = Opt.none(WriteTask)

  if stream.closedByEngine or stream.quicStream.isNil:
    return

  if lsquic_stream_wantwrite(stream.quicStream, 0) == -1:
    error "could not set stream wantwrite",
      streamId = lsquic_stream_id(stream.quicStream)

template raiseIfReadReset(stream: Stream) =
  if stream.readResetByPeer():
    raise stream.newStreamResetError("stream read")

template raiseIfWriteReset(stream: Stream) =
  if stream.writeResetByPeer():
    raise stream.newStreamResetError("stream write")

template processWhenAvailable(stream: Stream) =
  if not isNil(stream.doProcess):
    stream.doProcess()

proc requestClose(stream: Stream): bool {.raises: [].} =
  if stream.closedByEngine or stream.quicStream.isNil or stream.closeRequested:
    return true

  stream.closeRequested = true
  let ret = lsquic_stream_close(stream.quicStream)
  if ret != 0:
    let closeErrno = errno
    if closeErrno == EBADF:
      stream.processWhenAvailable()
      return true

    stream.closeRequested = false
    trace "could not close stream",
      streamId = lsquic_stream_id(stream.quicStream), errno = closeErrno
    return false

  stream.processWhenAvailable()
  true

proc closeIfDone*(stream: Stream): bool {.raises: [].} =
  if stream.closeWrite and stream.isEof:
    return stream.requestClose()

  true

proc abort*(stream: Stream) =
  stream.closeWrite = true
  stream.isEof = true
  stream.abortPendingWrites("stream aborted")
  discard stream.requestClose()
  if not stream.closed.isSet():
    stream.closed.fire()

proc close*(stream: Stream) {.async: (raises: [StreamError, CancelledError]).} =
  if stream.closeWrite or stream.closedByEngine:
    return

  # Closing only the write side
  let ret = lsquic_stream_shutdown(stream.quicStream, 1)
  if ret == 0:
    stream.abortPendingWrites("stream closed")
    stream.closeWrite = true
    if not stream.closeIfDone():
      stream.abort()
      raise newException(StreamError, "could not close the stream")
    if not stream.isEof:
      stream.doProcess()
  else:
    raise newException(StreamError, "could not close the stream")

proc readOnce*(
    stream: Stream, dst: ptr byte, dstLen: int
): Future[int] {.async: (raises: [CancelledError, StreamError]).} =
  if dstLen == 0:
    return 0

  if dst.isNil:
    raiseAssert "dst cannot be nil"

  raiseIfReadReset(stream)

  if stream.isEof or stream.closedByEngine:
    return 0

  await stream.readLock.acquire()

  defer:
    try:
      stream.readLock.release()
    except AsyncLockError:
      discard # should not happen - lock acquired directly above

  raiseIfReadReset(stream)

  # In case stream was closed while waiting for lock being acquired
  if stream.closedByEngine:
    return 0

  let n = lsquic_stream_read(stream.quicStream, dst, dstLen.csize_t)

  if n == 0:
    stream.isEof = true
    if not stream.closeIfDone():
      stream.abort()
      raise newException(StreamError, "could not close the stream")
    return 0
  elif n > 0:
    return n

  if n < 0 and errno == ECONNRESET:
    if not stream.readResetByPeer():
      stream.markResetByPeer(ResetRead)
    raise stream.newStreamResetError("stream read")

  if n < 0 and errno != EWOULDBLOCK:
    stream.abort()
    raise newException(StreamError, "could not read: " & $errno)

  if lsquic_stream_wantread(stream.quicStream, 1) == -1:
    stream.abort()
    raise newException(StreamError, "could not set wantread")

  let doneFut =
    Future[int].Raising([CancelledError, StreamError]).init("Stream.readOnce")
  stream.toRead = Opt.some(ReadTask(data: dst, dataLen: dstLen, doneFut: doneFut))

  try:
    stream.doProcess()

    let raceFut = await race(stream.closedWaiter, doneFut)
    if raceFut == stream.closedWaiter:
      if not doneFut.finished:
        await doneFut.cancelAndWait()
      raiseIfReadReset(stream)
      stream.isEof = true
      stream.closeWrite = true
      discard stream.closeIfDone()
      return 0

    return await doneFut
  finally:
    stream.clearPendingRead(doneFut)

template readOnce*(stream: Stream, dst: var openArray[byte]): untyped =
  ## Convenience helper that forwards an openArray/seq to the pointer-based API.
  (if dst.len == 0: stream.readOnce(nil, 0)
  else: stream.readOnce(dst[0].addr, dst.len))

proc write*(
    stream: Stream, data: seq[byte]
) {.async: (raises: [CancelledError, StreamError]).} =
  if data.len == 0:
    return

  raiseIfWriteReset(stream)

  if stream.closeWrite or stream.closedByEngine:
    raise newException(StreamError, "stream closed")

  await stream.writeLock.acquire()

  defer:
    try:
      stream.writeLock.release()
    except AsyncLockError:
      discard # should not happen - lock acquired directly above

  raiseIfWriteReset(stream)

  if stream.closedByEngine:
    raise newException(StreamError, "stream closed")

  # Try to write immediately
  let p = data[0].addr
  let n = lsquic_stream_write(stream.quicStream, p, data.len.csize_t)
  if n >= data.len:
    if lsquic_stream_flush(stream.quicStream) != 0:
      stream.abort()
      raise newException(StreamError, "could not flush stream")
    stream.doProcess()
    return
  elif n < 0:
    if errno == ECONNRESET:
      if not stream.writeResetByPeer():
        stream.markResetByPeer(ResetWrite)
      raise stream.newStreamResetError("stream write")
    error "could not write to stream", streamId = lsquic_stream_id(stream.quicStream), n
    raise newException(StreamError, "could not write")

  # Enqueue otherwise
  if lsquic_stream_wantwrite(stream.quicStream, 1) == -1:
    stream.abort()
    raise newException(StreamError, "could not set wantwrite")

  let doneFut = Future[void].Raising([CancelledError, StreamError]).init("Stream.write")
  stream.toWrite = Opt.some(
    WriteTask(data: data[0].addr, dataLen: data.len, doneFut: doneFut, offset: n)
  )

  try:
    stream.doProcess()

    let raceFut = await race(stream.closedWaiter, doneFut)
    if raceFut == stream.closedWaiter:
      raiseIfWriteReset(stream)
      if not doneFut.finished:
        doneFut.fail(newException(StreamError, "stream closed"))
      stream.closeWrite = true

    await doneFut
  finally:
    stream.clearPendingWrite(doneFut)
