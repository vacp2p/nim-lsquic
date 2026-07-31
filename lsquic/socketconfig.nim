# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ./errors

const
  DefaultQuicReceiveBufferBytes* = 8 * 1024 * 1024

  MaxReceiveDatagramSize* = 2048
    ## Largest UDP payload the receive path accepts, advertised to the peer as
    ## `max_udp_payload_size`. The batched drain reserves a slot of this size
    ## per datagram up front, so what it is able to accept has to be what the
    ## peer was told to stay under: with no transport parameter sent, the peer
    ## applies the RFC 9000 default of 65527 and may legally send what the
    ## batch would then have to drop.

  MaxDatagramsPerWakeup* = 64
    ## Capped so that a busy socket cannot starve the rest of the event loop.

type QuicSocketConfig* = object
  receiveBufferBytes*: int = DefaultQuicReceiveBufferBytes
  segmentationOffload*: bool = true

const DefaultQuicSocketConfig* = QuicSocketConfig()

proc validate*(config: QuicSocketConfig) {.raises: [QuicConfigError].} =
  if config.receiveBufferBytes < 0:
    raise
      newException(QuicConfigError, "socket receive buffer size must be non-negative")
