# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos

template AutoAddressIP4*(): TransportAddress =
  initTAddress("127.0.0.1:0")

template AutoAddressIP6*(): TransportAddress =
  initTAddress("[::1]:0")

template WildcardIP6*(): TransportAddress =
  initTAddress("[::]:0")
