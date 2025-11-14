import results
import chronos

type Timeout* = ref object
  timer: Opt[TimerCallback]
  onExpiry: proc() {.gcsafe, raises: [].}
  expired: AsyncEvent
  stopped: bool

proc setTimer(timeout: Timeout, moment: Moment) =
  proc onTimeout(_: pointer) =
    if timeout.stopped:
      return
    timeout.expired.fire()
    timeout.onExpiry()

  timeout.timer = Opt.some(setTimer(moment, onTimeout))

const skip = proc() =
  discard

proc newTimeout*(onExpiry: proc() {.gcsafe, raises: [].} = skip): Timeout =
  Timeout(onExpiry: onExpiry, expired: newAsyncEvent())

proc stop*(timeout: Timeout) =
  timeout.stopped = true
  if timeout.timer.isSome():
    timeout.timer.unsafeGet().clearTimer()

proc set*(timeout: Timeout, moment: Moment) =
  timeout.stop()
  timeout.stopped = false
  timeout.expired.clear()
  timeout.setTimer(moment)

proc set*(timeout: Timeout, duration: Duration) =
  timeout.set(Moment.fromNow(duration))

proc expired*(timeout: Timeout) {.async.} =
  await timeout.expired.wait()
