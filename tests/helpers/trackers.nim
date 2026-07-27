# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, sequtils, unittest2

proc reconcileTracker(name: string, opened: int, closed: int) =
  if opened >= closed:
    for _ in 0 ..< opened - closed:
      untrackCounter(name)
  else:
    for _ in 0 ..< closed - opened:
      trackCounter(name)

template checkTracker(name: string) =
  if isCounterLeaked(name):
    let tracker = getTrackerCounter(name)
    let opened = int(tracker.opened)
    let closed = int(tracker.closed)

    checkpoint "\t" & name & ": opened " & $opened & ", closed " & $closed & " (delta " &
      $(opened - closed) & ")"
    fail()

    # Reconcile the counter so the leak does not cascade into following tests.
    reconcileTracker(name, opened, closed)

template checkTrackers*() =
  ## Fail the current test for every chronos tracker counter left unbalanced,
  ## reporting its opened/closed totals and the delta.
  ##
  ## Reconciles the counters as a side effect, so the same leak is not reported
  ## again by every following test.
  let names = getThreadDispatcher().trackerCounterKeys().toSeq()
  for name in names:
    checkTracker(name)

template finalCheckTrackers*(): untyped =
  ## finalCheckTrackers is a utility used for performing a final tracker check 
  ## outside the test suite. It should be called at the very end of a test file 
  ## (typically containing a bundle of tests) to ensure that no tests have left 
  ## any trackers open.

  suite "Final checkTrackers":
    test "test":
      # checkTrackers must be executed within a suite or test. otherwise, 
      # its output won't appear on stdout.
      checkTrackers()