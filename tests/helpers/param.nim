# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

const fast {.booldefine.}: bool = false

proc isFast*(): bool =
  return fast
