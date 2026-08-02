# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import unittest2
import chronos
import chronos/osdefs
import lsquic/helpers/transportaddr

proc storageFor(address: TransportAddress): Sockaddr_storage =
  var
    storage: Sockaddr_storage
    length: SockLen
  address.toSAddr(storage, length)
  storage

proc asSockAddr(storage: var Sockaddr_storage): ptr SockAddr =
  cast[ptr SockAddr](addr storage)

suite "Transport address conversion":
  test "sockAddrLen accepts the two supported families":
    check:
      sockAddrLen(AF_INET.int) == Opt.some(sizeof(Sockaddr_in).SockLen)
      sockAddrLen(AF_INET6.int) == Opt.some(sizeof(Sockaddr_in6).SockLen)

  test "sockAddrLen rejects every other family":
    # AF_UNSPEC is what a zeroed `Sockaddr_storage` holds when the kernel never
    # filled it in; the rest stand in for a family this build does not expect,
    # including the AF_INET6 values used by platforms other than this one.
    for family in [0, 1, 23, 24, 26, 28, 30, 4242]:
      if family == AF_INET6.int:
        continue
      check sockAddrLen(family).isNone()

  test "toTransportAddress round-trips IPv4":
    let expected = initTAddress("127.0.0.1:4433")
    var storage = storageFor(expected)
    check storage.asSockAddr().toTransportAddress() == Opt.some(expected)

  test "toTransportAddress round-trips IPv6":
    let expected = initTAddress("[::1]:4433")
    var storage = storageFor(expected)
    check storage.asSockAddr().toTransportAddress() == Opt.some(expected)

  test "toTransportAddress rejects an unsupported family":
    # The drain loop and the lsquic `{.cdecl.}` callbacks are all `raises: []`,
    # so this must stay a `none` rather than a Defect that aborts the process.
    var storage = storageFor(initTAddress("127.0.0.1:4433"))
    storage.ss_family = type(storage.ss_family)(4242)
    check storage.asSockAddr().toTransportAddress().isNone()
