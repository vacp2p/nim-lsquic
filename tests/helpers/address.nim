# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos, chronos/osdefs

proc toSockaddrStorage*(address: TransportAddress): Sockaddr_storage =
  ## Returns storage the caller owns, so a `ptr SockAddr` into it stays valid.
  var
    storage: Sockaddr_storage
    length: SockLen
  address.toSAddr(storage, length)
  storage

template AutoAddressIP4*(): TransportAddress =
  initTAddress("127.0.0.1:0")

template AutoAddressIP6*(): TransportAddress =
  initTAddress("[::1]:0")

template WildcardIP6*(): TransportAddress =
  initTAddress("[::]:0")
