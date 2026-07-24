# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests
import lsquic
import ./helpers/[address, clientserver, trackers]

initializeLsquic(true, true)

const timeout = 2.seconds

suite "leaks":
  asyncTest "connection is auto-removed from manager after close":
    let server = makeEndpoint(AutoAddressIP4)
    let client = makeDialEndpoint(AddressFamily.IPv4)
    defer:
      await allFutures(client.stop(), server.stop())

    let accepting = server.accept()
    let outgoing = await client.dial(server.localAddress())
    let incoming = await accepting

    check:
      client.connectionCount == 1
      server.connectionCount == 1

    outgoing.close()
    check:
      await outgoing.closedFuture().withTimeout(timeout)
      await incoming.closedFuture().withTimeout(timeout)

    # Closing a connection schedules its removal from the manager, but that runs
    # on the later moment, yield one event-loop tick so it happens before we count.
    await sleepAsync(0.milliseconds)

    check:
      client.connectionCount == 0
      server.connectionCount == 0

  asyncTest "no datagram transport leak after connection churn":
    const rounds = 6
    let before = datagramTransportCounter()

    for _ in 0 ..< rounds:
      let server = makeEndpoint(AutoAddressIP4)
      let client = makeDialEndpoint(AddressFamily.IPv4)
      let accepting = server.accept()
      let outgoing = await client.dial(server.localAddress())
      discard await accepting

      outgoing.close()
      check await outgoing.closedFuture().withTimeout(timeout)
      await allFutures(client.stop(), server.stop())

    let after = datagramTransportCounter()
    let opened = after.opened - before.opened
    let closed = after.closed - before.closed
    check:
      opened > 0'u64
      opened == closed
      allTrackerLeaks().len == 0
