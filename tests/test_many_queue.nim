import
  chronos,
  chronos/unittest2/asynctests
import lsquic/helpers/many_queue

suite "ManyQueue":
  asyncTest "get returns imidietly with all data":
    let q = ManyQueue[int].new()
    q.put(1)
    q.put(2)

    # should get all data
    check (await q.get().wait(10.milliseconds)) == @[1, 2]

    # should not complete get; queue is empty
    check not (await q.get().withTimeout(10.milliseconds))

  asyncTest "get waits on first put":
    let q = ManyQueue[int].new()

    let getFut = q.get()
    q.put(1)
    q.put(2)
    
    # first put should complete get future
    check (await getFut) == @[1]

    # get remaining data
    check (await q.get()) == @[2]

    check not (await q.get().withTimeout(10.milliseconds))

  asyncTest "last get receives data":
    let q = ManyQueue[int].new()

    let getFut1 = q.get()
    let getFut2 = q.get()
    let getFut3 = q.get()

    q.put(1)

    check (await getFut3) == @[1]
    check not getFut1.completed
    check not getFut2.completed