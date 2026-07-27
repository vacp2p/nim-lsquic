# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import unittest2
import lsquic/context/sendbatch

when defined(linux):
  import posix
  import std/nativesockets

  const
    TestSolUdp = 17.cint
    TestUdpSegment = 103.cint

  when defined(x86_64) and not defined(android):
    const TestMsgIovLen = 1.csize_t
  else:
    const TestMsgIovLen = 1.cint

  type UdpSegmentControl = object
    hdr: Tcmsghdr
    data: array[64, byte]

  proc loopbackAddr(port: uint16): Sockaddr_in =
    Sockaddr_in(
      sin_family: TSa_Family(posix.AF_INET),
      sin_port: nativesockets.htons(port),
      sin_addr: InAddr(s_addr: nativesockets.htonl(0x7F000001'u32)),
    )

  proc setUdpSegment(msg: var Tmsghdr, control: var UdpSegmentControl) =
    let segmentSize = 1200'u16
    zeroMem(addr control, sizeof(control))
    msg.msg_control = cast[pointer](addr control)
    msg.msg_controllen = CMSG_SPACE(csize_t(sizeof(segmentSize)))

    let cmsg = CMSG_FIRSTHDR(addr msg)
    cmsg.cmsg_level = TestSolUdp
    cmsg.cmsg_type = TestUdpSegment
    cmsg.cmsg_len = CMSG_LEN(csize_t(sizeof(segmentSize)))
    cast[ptr uint16](CMSG_DATA(cmsg))[] = segmentSize

proc taddr(port: int): TransportAddress =
  initTAddress("127.0.0.1:" & $port)

proc packet(
    destPort: int,
    size: int = 1200,
    ecn: cint = 0,
    localPort: int = 4000,
    iovCount: int = 1,
): PacketShape =
  PacketShape(
    local: taddr(localPort),
    dest: taddr(destPort),
    ecn: ecn,
    size: size,
    iovCount: iovCount,
  )

suite "send batching":
  test "GSO disabled keeps one send message per packet":
    let groups = buildSendGroups(@[packet(5000), packet(5000)], false)

    check groups.len == 2
    check groups[0].count == 1
    check groups[0].gso == false
    check groups[1].count == 1
    check groups[1].gso == false

  test "same flow and same size form one GSO group":
    let groups = buildSendGroups(@[packet(5000), packet(5000), packet(5000)], true)

    check groups.len == 1
    check groups[0].first == 0
    check groups[0].count == 3
    check groups[0].segmentSize == 1200
    check groups[0].iovCount == 3
    check groups[0].gso == true

  test "shorter packet is allowed only at the end of a GSO group":
    let groups = buildSendGroups(
      @[packet(5000), packet(5000), packet(5000, size = 900), packet(5000)], true
    )

    check groups.len == 2
    check groups[0].count == 3
    check groups[0].segmentSize == 1200
    check groups[0].gso == true
    check groups[1].first == 3
    check groups[1].count == 1
    check groups[1].gso == false

  test "destination, local address, and ECN changes split groups":
    let groups = buildSendGroups(
      @[
        packet(5000),
        packet(5001),
        packet(5001),
        packet(5001, ecn = 1),
        packet(5001, ecn = 1, localPort = 4001),
      ],
      true,
    )

    check groups.len == 4
    check groups[0].count == 1
    check groups[0].gso == false
    check groups[1].count == 2
    check groups[1].gso == true
    check groups[2].count == 1
    check groups[2].gso == false
    check groups[3].count == 1
    check groups[3].gso == false

  test "larger later packet cannot join a GSO group":
    let groups = buildSendGroups(@[packet(5000, size = 1000), packet(5000)], true)

    check groups.len == 2
    check groups[0].count == 1
    check groups[0].gso == false
    check groups[1].count == 1
    check groups[1].gso == false

  test "GSO groups are capped at the segment limit":
    var packets: seq[PacketShape]
    for _ in 0 ..< MaxGsoSegments + 1:
      packets.add packet(5000)

    let groups = buildSendGroups(packets, true)

    check groups.len == 2
    check groups[0].count == MaxGsoSegments
    check groups[0].gso == true
    check groups[1].count == 1
    check groups[1].gso == false
    check sentSpecCount(groups, 1) == MaxGsoSegments
    check sentSpecCount(groups, 2) == MaxGsoSegments + 1

  test "sentSpecCount maps mixed plain and GSO send results":
    let groups =
      buildSendGroups(@[packet(5000), packet(5001), packet(5001), packet(5002)], true)

    check groups.len == 3
    check groups[0].count == 1
    check groups[1].count == 2
    check groups[2].count == 1
    check sentSpecCount(groups, 1) == 1
    check sentSpecCount(groups, 2) == 3
    check sentSpecCount(groups, 3) == 4

  test "GSO groups respect the iovec limit":
    let groups =
      buildSendGroups(@[packet(5000, iovCount = MaxGsoIovecs), packet(5000)], true)

    check groups.len == 2
    check groups[0].count == 1
    check groups[0].gso == false
    check groups[1].count == 1
    check groups[1].gso == false

  test "Linux UDP_SEGMENT sends multiple datagrams":
    when defined(linux):
      let recvFd = posix.socket(posix.AF_INET, posix.SOCK_DGRAM, 0)
      let sendFd = posix.socket(posix.AF_INET, posix.SOCK_DGRAM, 0)
      defer:
        if recvFd != SocketHandle(-1):
          discard posix.close(recvFd)
        if sendFd != SocketHandle(-1):
          discard posix.close(sendFd)

      if recvFd == SocketHandle(-1) or sendFd == SocketHandle(-1):
        return

      var timeout = Timeval(tv_sec: Time(1), tv_usec: Suseconds(0))
      discard setsockopt(
        recvFd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        cast[pointer](addr timeout),
        SockLen(sizeof(timeout)),
      )

      var recvAddr = loopbackAddr(0)
      let bindRes =
        bindSocket(recvFd, cast[ptr SockAddr](addr recvAddr), SockLen(sizeof(recvAddr)))
      doAssert bindRes == 0

      var
        boundAddr: Sockaddr_in
        boundAddrLen = SockLen(sizeof(boundAddr))
      let sockNameRes =
        getsockname(recvFd, cast[ptr SockAddr](addr boundAddr), addr boundAddrLen)
      doAssert sockNameRes == 0

      var payload: array[2400, byte]
      for i in 0 ..< 1200:
        payload[i] = 1
      for i in 1200 ..< payload.len:
        payload[i] = 2

      var iov = IOVec(iov_base: addr payload[0], iov_len: payload.len.csize_t)
      var msg = Tmsghdr(
        msg_name: cast[pointer](addr boundAddr),
        msg_namelen: boundAddrLen,
        msg_iov: addr iov,
        msg_iovlen: TestMsgIovLen,
        msg_control: nil,
        msg_controllen: 0,
        msg_flags: 0,
      )
      var control: UdpSegmentControl
      msg.setUdpSegment(control)

      let sent = sendmsg(sendFd, addr msg, 0)
      if sent < 0 and (errno == EINVAL or errno == ENOTSUP or errno == EOPNOTSUPP):
        skip()
      elif sent < 0:
        doAssert sent >= 0
      else:
        doAssert sent == payload.len

        var buf: array[1500, byte]
        let first = recv(recvFd, addr buf[0], buf.len, 0)
        doAssert first == 1200
        doAssert buf[0] == 1

        let second = recv(recvFd, addr buf[0], buf.len, 0)
        doAssert second == 1200
        doAssert buf[0] == 2
    else:
      skip()
