# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

const DgramTransportTrackerName* = "datagram.transport"
  ## chronos `DgramTransportTrackerName`.
  ## Kept local so we don't depend on its re-export path.

proc datagramTransportCounter*(): TrackerCounter =
  ## Opened/closed counts for chronos datagram transports.
  getTrackerCounter(DgramTransportTrackerName)

proc allTrackerLeaks*(): seq[string] =
  ## Names of every chronos tracker counter whose `opened != closed` on the
  ## current thread dispatcher. Empty means no leaked transports.
  for name in getThreadDispatcher().trackerCounterKeys():
    if isCounterLeaked(name):
      result.add(name)
