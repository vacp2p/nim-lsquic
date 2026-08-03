# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/osdefs, nativesockets, unittest2
import lsquic/[lsquic_ffi, context/context, context/io]
import ./helpers/[address, trackers]

when not defined(windows):
  from posix import EAGAIN, EBADF, errno

proc makeOutSpec(
    iov: ptr struct_iovec, local, dest: ptr Sockaddr_storage
): struct_lsquic_out_spec =
  struct_lsquic_out_spec(
    iov: iov,
    iovlen: 1,
    local_sa: cast[ptr SockAddr](local),
    dest_sa: cast[ptr SockAddr](dest),
  )

suite "packets out":
  teardown:
    checkTrackers()

  test "a send with no packets sent out reports -1":
    let ctx = QuicContext(fd: -1)
    var
      payload = @[1'u8, 2, 3]
      localStorage = toSockaddrStorage(initTAddress("127.0.0.1:1000"))
      destStorage = toSockaddrStorage(initTAddress("127.0.0.1:4433"))
      iov = struct_iovec(iov_base: addr payload[0], iov_len: payload.len.csize_t)
      spec = makeOutSpec(addr iov, addr localStorage, addr destStorage)

    let res = sendPacketsOut(cast[pointer](ctx), addr spec, 1)
    let savedErrno = errno

    check res == -1
    # The engine reads errno to decide whether to retry or close the connection.
    when not defined(windows):
      check savedErrno == EBADF

  test "a send with some packets sent out reports the count":
    # Returning -1 would make the engine resend a datagram that already went out.
    let fd = createNativeSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    defer:
      nativesockets.close(fd)

    let ctx = QuicContext(fd: cint(fd))
    var
      payload = @[1'u8, 2, 3]
      localStorage = toSockaddrStorage(initTAddress("127.0.0.1:1000"))
      ipv4DestStorage = toSockaddrStorage(initTAddress("127.0.0.1:4433"))
      ipv6DestStorage = toSockaddrStorage(initTAddress("[::1]:4433"))
      iov = struct_iovec(iov_base: addr payload[0], iov_len: payload.len.csize_t)
      specs = [
        makeOutSpec(addr iov, addr localStorage, addr ipv4DestStorage),
        makeOutSpec(addr iov, addr localStorage, addr ipv6DestStorage),
      ]

    let res = sendPacketsOut(cast[pointer](ctx), addr specs[0], 2)
    let savedErrno = errno

    check res == 1
    # Linux overwrites errno with EAGAIN here, the other platforms leave alone
    # whatever the failed send set.
    when defined(linux):
      check savedErrno == EAGAIN

  test "a batch larger than one sendmmsg call sends every packet":
    # SendmmsgBatchSize is 64, so 65 specs take two sendmmsg calls.
    const SpecCount = 65

    let fd = createNativeSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    defer:
      nativesockets.close(fd)

    let ctx = QuicContext(fd: cint(fd))
    var
      payload = @[1'u8, 2, 3]
      localStorage = toSockaddrStorage(initTAddress("127.0.0.1:1000"))
      destStorage = toSockaddrStorage(initTAddress("127.0.0.1:4433"))
      iov = struct_iovec(iov_base: addr payload[0], iov_len: payload.len.csize_t)
      specs = newSeq[struct_lsquic_out_spec](SpecCount)
    for spec in specs.mitems:
      spec = makeOutSpec(addr iov, addr localStorage, addr destStorage)

    check sendPacketsOut(cast[pointer](ctx), addr specs[0], SpecCount.cuint) == SpecCount
