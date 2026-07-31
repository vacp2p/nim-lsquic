# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ./errors

const DefaultQuicReceiveBufferBytes* = 8 * 1024 * 1024

type QuicSocketConfig* = object
  receiveBufferBytes*: int = DefaultQuicReceiveBufferBytes
  segmentationOffload*: bool = true

const DefaultQuicSocketConfig* = QuicSocketConfig()

proc validate*(config: QuicSocketConfig) {.raises: [QuicConfigError].} =
  if config.receiveBufferBytes < 0:
    raise
      newException(QuicConfigError, "socket receive buffer size must be non-negative")
