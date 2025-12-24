# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import results
import chronos

type Timeout* = ref object
  timer: Opt[TimerCallback]
  onExpiry: proc() {.gcsafe, raises: [].}

const skip = proc() =
  discard

proc newTimeout*(onExpiry: proc() {.gcsafe, raises: [].} = skip): Timeout =
  Timeout(onExpiry: onExpiry)

proc stop*(timeout: Timeout) =
  if timeout.timer.isSome:
    timeout.timer.unsafeGet().clearTimer()
    timeout.timer = Opt.none(TimerCallback)

proc set*(timeout: Timeout, moment: Moment) =
  timeout.stop()

  proc onTimeout(_: pointer) {.gcsafe, raises: [].} =
    timeout.stop()
    timeout.onExpiry()

  timeout.timer = Opt.some(setTimer(moment, onTimeout))

proc set*(timeout: Timeout, duration: Duration) =
  timeout.set(Moment.fromNow(duration))
