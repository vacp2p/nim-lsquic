# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests
import lsquic
import ./helpers/[address, clientserver]

suite "runtime":
  asyncTest "init and cleanup are repeatable and leave a usable global":
    # start from a known-clean global regardless of prior state
    cleanupLsquic()

    for _ in 0 ..< 3:
      initializeLsquic(true, true)
      initializeLsquic(true, true) # second init is a no-op via the `initialized` guard
      cleanupLsquic()
      cleanupLsquic() # second cleanup is a safe no-op

    # after the repeated cycle a fresh init must leave a working stack:
    # QuicServer.listen builds a real lsquic engine
    initializeLsquic(true, true)
    let listener = QuicServer.new(makeTLSConfig()).listen(AutoAddressIP4)
    defer:
      await listener.stop()
      cleanupLsquic()

    check listener.localAddress().port != Port(0)

  test "per-role init flags are accepted":
    cleanupLsquic()
    initializeLsquic(client = true, server = false)
    cleanupLsquic()
    initializeLsquic(client = false, server = true)
    cleanupLsquic()
