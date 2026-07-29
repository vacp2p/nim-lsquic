# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests
import lsquic/timeout

const fireTimeout = 2.seconds

suite "timeout":
  asyncTest "earlier deadline replaces later deadline":
    let fired = newAsyncEvent()
    var fireCount = 0
    let timeout = newTimeout(
      proc() =
        inc fireCount
        fired.fire()
    )

    timeout.set(400.milliseconds)
    timeout.set(50.milliseconds)

    check (await fired.wait().withTimeout(fireTimeout))
    check fireCount == 1

  asyncTest "later deadline does not replace earlier deadline":
    let fired = newAsyncEvent()
    var fireCount = 0
    let timeout = newTimeout(
      proc() =
        inc fireCount
        fired.fire()
    )

    timeout.set(50.milliseconds)
    timeout.set(400.milliseconds)

    check (await fired.wait().withTimeout(fireTimeout))
    check fireCount == 1

  asyncTest "expiry callback can re-arm the timeout":
    let rearmedFired = newAsyncEvent()
    var fireCount = 0
    var timeout: Timeout
    timeout = newTimeout(
      proc() =
        inc fireCount
        if fireCount == 1:
          timeout.set(50.milliseconds)
        else:
          rearmedFired.fire()
    )

    timeout.set(50.milliseconds)

    check (await rearmedFired.wait().withTimeout(fireTimeout))
    check fireCount == 2

  asyncTest "stop cancels expiry":
    var fired = 0
    let timeout = newTimeout(
      proc() =
        inc fired
    )

    timeout.set(100.milliseconds)
    timeout.stop()

    await sleepAsync(250.milliseconds)

    check fired == 0
