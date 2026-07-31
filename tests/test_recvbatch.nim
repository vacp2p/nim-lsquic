# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

when defined(linux):
  import std/posix
  import unittest2
  import ../lsquic/helpers/recvbatch
  import ../lsquic/socketconfig

  proc makeSocket(): SocketHandle =
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    doAssert fd.int >= 0
    fd

  proc bindLoopback(fd: SocketHandle): Sockaddr_in =
    var address = Sockaddr_in(sin_family: AF_INET.uint16, sin_port: 0)
    address.sin_addr.s_addr = 0x0100007F'u32 # 127.0.0.1, network order
    doAssert bindSocket(fd, cast[ptr SockAddr](addr address), SockLen(sizeof(address))) ==
      0
    var length = SockLen(sizeof(result))
    doAssert getsockname(fd, cast[ptr SockAddr](addr result), addr length) == 0
    doAssert fcntl(fd.cint, F_SETFL, O_NONBLOCK) == 0
    # a burst has to survive in the socket buffer until one recvmmsg takes it
    var size = 4 * 1024 * 1024
    discard setsockopt(fd, SOL_SOCKET, SO_RCVBUF, addr size, SockLen(sizeof(size)))

  proc send(fd: SocketHandle, dest: Sockaddr_in, payload: openArray[byte]) =
    let sent = sendto(
      fd,
      unsafeAddr payload[0],
      payload.len,
      0,
      cast[ptr SockAddr](unsafeAddr dest),
      SockLen(sizeof(dest)),
    )
    doAssert sent == payload.len, "sendto sent " & $sent & " of " & $payload.len

  proc datagram(length: int, tag: byte): seq[byte] =
    ## Distinct content per datagram, so a slot read at the wrong offset or
    ## with the wrong length cannot pass.
    result = newSeq[byte](length)
    for i in 0 ..< length:
      result[i] = byte((i + tag.int) and 0xFF)

  proc port(address: Sockaddr_in): uint16 =
    address.sin_port.uint16

  proc senderPort(batch: var RecvBatch, i: int): uint16 =
    cast[ptr Sockaddr_in](batch.sender(i)).sin_port.uint16

  suite "recvmmsg drain batch":
    setup:
      var
        batch: RecvBatch
        receiver = makeSocket()
        sender = makeSocket()
      let
        destination = receiver.bindLoopback()
        source = sender.bindLoopback()
      batch.init()

    teardown:
      discard close(receiver.cint)
      discard close(sender.cint)

    test "an empty socket reports no datagrams":
      check batch.receive(receiver) < 0

    test "a burst is drained by one call, each slot holding its own datagram":
      let lengths = [1, 64, 1200, MaxReceiveDatagramSize, 300, 1500]
      for i, length in lengths:
        sender.send(destination, datagram(length, byte(i)))

      check batch.receive(receiver) == lengths.len
      for i, length in lengths:
        check batch.datagramLen(i) == length
        check not batch.truncated(i)
        check @(batch.payload(i, length)) == datagram(length, byte(i))

      # and the socket is now empty
      check batch.receive(receiver) < 0

    test "an oversized datagram is flagged without disturbing its neighbours":
      let oversized = MaxReceiveDatagramSize + 1
      sender.send(destination, datagram(1200, 1))
      sender.send(destination, datagram(oversized, 2))
      sender.send(destination, datagram(60000, 3))
      sender.send(destination, datagram(900, 4))

      check batch.receive(receiver) == 4

      check not batch.truncated(0)
      check @(batch.payload(0, 1200)) == datagram(1200, 1)

      # MSG_TRUNC reports the length the datagram had on the wire, not the
      # length that fit in the slot
      check batch.truncated(1)
      check batch.datagramLen(1) == oversized
      check batch.truncated(2)
      check batch.datagramLen(2) == 60000

      check not batch.truncated(3)
      check @(batch.payload(3, 900)) == datagram(900, 4)

    test "a zero-length datagram occupies a slot without a payload":
      sender.send(destination, datagram(1200, 1))
      var nothing: byte
      doAssert sendto(
        sender,
        addr nothing,
        0,
        0,
        cast[ptr SockAddr](unsafeAddr destination),
        SockLen(sizeof(destination)),
      ) == 0
      sender.send(destination, datagram(700, 3))

      check batch.receive(receiver) == 3
      check batch.datagramLen(1) == 0
      check @(batch.payload(2, 700)) == datagram(700, 3)

    test "each slot carries the address of its own sender":
      var second = makeSocket()
      let secondSource = second.bindLoopback()

      sender.send(destination, datagram(100, 1))
      second.send(destination, datagram(200, 2))
      sender.send(destination, datagram(300, 3))

      check batch.receive(receiver) == 3
      check batch.senderPort(0) == source.port
      check batch.senderPort(1) == secondSource.port
      check batch.senderPort(2) == source.port

      discard close(second.cint)

    test "state does not leak from one call into the next":
      # `receive` only resets the slots the previous call filled, so a shorter
      # burst after a longer one must not inherit its flags or addresses.
      var second = makeSocket()
      let secondSource = second.bindLoopback()

      # the truncated datagram has to land in a slot the shorter second burst
      # will reuse, or nothing is being tested
      second.send(destination, datagram(MaxReceiveDatagramSize + 1, 9))
      for i in 0 ..< 5:
        sender.send(destination, datagram(1200, byte(i)))
      check batch.receive(receiver) == 6
      check batch.truncated(0)

      second.send(destination, datagram(400, 7))
      sender.send(destination, datagram(500, 8))
      check batch.receive(receiver) == 2

      for i in 0 ..< 2:
        check not batch.truncated(i)
      check batch.datagramLen(0) == 400
      check batch.senderPort(0) == secondSource.port
      check batch.senderPort(1) == source.port
      check @(batch.payload(1, 500)) == datagram(500, 8)

      discard close(second.cint)
