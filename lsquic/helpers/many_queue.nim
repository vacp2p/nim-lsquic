import chronos

type ManyQueue*[T] = ref object of RootRef
  data: seq[T]
  getFut: Future[seq[T]]

proc new*[T](MQ: typedesc[ManyQueue[T]]): ManyQueue[T] =
  ManyQueue[T](data: @[], getFut: nil)

proc get*[T](
    q: ManyQueue[T]
): Future[seq[T]] {.async: (raises: [CancelledError], raw: true).} =
  let fut = newFuture[seq[T]]("ManyQueue.get")

  if q.data.len == 0:
    q.getFut = fut
    return fut

  fut.complete(move q.data)

  return fut

proc put*[T](q: ManyQueue[T], e: sink T) =
  q.data.add(e)

  if not isNil(q.getFut):
    q.getFut.complete(move q.data)
    q.getFut = nil
