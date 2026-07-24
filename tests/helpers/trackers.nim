# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

proc allLeakedTrackers*(): seq[string] =
  ## Names of every chronos tracker counter whose `opened != closed` on the
  ## current thread dispatcher. Empty means no leaked transports.
  for name in getThreadDispatcher().trackerCounterKeys():
    if isCounterLeaked(name):
      result.add(name)

template checkTrackers*() =
  check allLeakedTrackers() == newSeq[string]()
