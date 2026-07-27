# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ./errors

type QuicSocketConfig* = object
  receiveBufferBytes*: int

const
  DefaultQuicReceiveBufferBytes* = 8 * 1024 * 1024
  DefaultQuicSocketConfig* =
    QuicSocketConfig(receiveBufferBytes: DefaultQuicReceiveBufferBytes)

proc validate*(config: QuicSocketConfig) {.raises: [QuicConfigError].} =
  if config.receiveBufferBytes < 0:
    raise
      newException(QuicConfigError, "socket receive buffer size must be non-negative")
