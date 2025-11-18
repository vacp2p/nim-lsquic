import chronos

type ManyQueue*[T] = ref object of RootRef
  data: seq[T]
  getFut: Future[seq[T]].Raising([CancelledError])

proc get*[T](q: ManyQueue[T]): Future[seq[T]].Raising([CancelledError]) =
  let fut = Future[seq[T]].Raising([CancelledError]).init("ManyQueue.get")

  if q.data.len == 0:
    q.getFut = fut
    return fut

  fut.complete(move q.data)

  return fut

proc put*[T](q: ManyQueue[T], e: sink T) =
  q.data.add(e)

  if isNil(q.getFut):
    return

  q.getFut.complete(move q.data)
  q.getFut = nil
