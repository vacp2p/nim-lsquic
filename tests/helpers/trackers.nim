# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, unittest2

proc allLeakedTrackers*(): seq[string] =
  ## Names of every chronos tracker counter whose `opened != closed` on the
  ## current thread dispatcher. Empty means nothing tracked was left unreleased.
  var trackers: seq[string]
  for name in getThreadDispatcher().trackerCounterKeys():
    if isCounterLeaked(name):
      trackers.add(name)
  trackers

template checkTrackers*() =
  check allLeakedTrackers() == newSeq[string]()
