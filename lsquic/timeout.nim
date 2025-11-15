import results
import chronos

type Timeout* = ref object
  timer: Opt[TimerCallback]
  onExpiry: proc() {.gcsafe, raises: [].}
  expired: AsyncEvent
  lastMoment: Moment
  scheduledMoment: Opt[Moment]
  stopped: bool

proc setTimer(timeout: Timeout, moment: Moment) {.gcsafe, raises: [].} =
  proc onTimeout(_: pointer) {.gcsafe, raises: [].} =
    if timeout.stopped:
      return

    if timeout.lastMoment > moment:
      timeout.setTimer(timeout.lastMoment)
      return

    timeout.timer = Opt.none(TimerCallback)
    timeout.scheduledMoment = Opt.none(Moment)
    timeout.expired.fire()
    timeout.onExpiry()

  timeout.timer = Opt.some(setTimer(moment, onTimeout))
  timeout.scheduledMoment = Opt.some(moment)

const skip = proc() =
  discard

proc newTimeout*(onExpiry: proc() {.gcsafe, raises: [].} = skip): Timeout =
  Timeout(
    onExpiry: onExpiry, expired: newAsyncEvent(), scheduledMoment: Opt.none(Moment)
  )

proc stop*(timeout: Timeout) =
  timeout.stopped = true
  if timeout.timer.isSome():
    timeout.timer.unsafeGet().clearTimer()
    timeout.timer = Opt.none(TimerCallback)
  timeout.scheduledMoment = Opt.none(Moment)

proc set*(timeout: Timeout, moment: Moment) =
  timeout.lastMoment = moment
  timeout.stopped = false
  timeout.expired.clear()

  if timeout.timer.isNone():
    timeout.setTimer(moment)
    return

  if timeout.scheduledMoment.isSome():
    let scheduled = timeout.scheduledMoment.get()
    if moment < scheduled:
      timeout.timer.unsafeGet().clearTimer()
      timeout.timer = Opt.none(TimerCallback)
      timeout.scheduledMoment = Opt.none(Moment)
      timeout.setTimer(moment)
  else:
    # Should not happen, but reset defensively.
    timeout.timer.unsafeGet().clearTimer()
    timeout.setTimer(moment)

proc set*(timeout: Timeout, duration: Duration) =
  timeout.set(Moment.fromNow(duration))

proc expired*(timeout: Timeout) {.async.} =
  await timeout.expired.wait()
