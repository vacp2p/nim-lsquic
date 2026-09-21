# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Bounded renderers for values used in structured log fields.

import std/oserrors
import chronos
import chronicles

const ShortLogMax* = 64

func shortLog*(value: string): string {.raises: [].} =
  ## Returns a bounded preview without emitting an entire peer-provided string.
  if value.len <= ShortLogMax:
    return value

  const prefixLength = ShortLogMax div 2
  value[0 ..< prefixLength] & "..." & value[value.len - prefixLength .. ^1]

func shortLog*(address: TransportAddress): string {.raises: [].} =
  ## TransportAddress may contain a 108-byte Unix-domain socket path.
  shortLog($address)

chronicles.formatIt(TransportAddress):
  shortLog(it)

func osErrorLabel*(code: cint): string {.raises: [].} =
  ## Uses the platform's error text instead of a bare numeric error code.
  shortLog(osErrorMsg(OSErrorCode(code.int32)))
