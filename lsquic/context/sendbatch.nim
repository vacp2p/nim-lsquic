# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

const
  MaxGsoSegments* = 64
  MaxGsoIovecs* = 1024
  MaxUdpSegmentSize* = int(uint16.high)

type
  PacketShape* = object
    local*: TransportAddress
    dest*: TransportAddress
    ecn*: cint
    size*: int
    iovCount*: int

  SendGroup* = object
    first*: int
    count*: int
    segmentSize*: int
    iovCount*: int
    gso*: bool

func sameFlow(a, b: PacketShape): bool =
  a.local == b.local and a.dest == b.dest and a.ecn == b.ecn

func canUseGso(packet: PacketShape): bool =
  packet.size > 0 and packet.size <= MaxUdpSegmentSize and packet.iovCount > 0

func buildSendGroups*(
    packets: openArray[PacketShape], gsoEnabled: bool
): seq[SendGroup] =
  var i = 0
  while i < packets.len:
    let first = packets[i]
    if not gsoEnabled or not first.canUseGso():
      result.add SendGroup(
        first: i, count: 1, segmentSize: 0, iovCount: first.iovCount, gso: false
      )
      inc i
      continue

    let start = i
    var
      count = 1
      iovCount = first.iovCount
    inc i

    while i < packets.len and count < MaxGsoSegments:
      let curr = packets[i]
      if not curr.canUseGso() or not first.sameFlow(curr):
        break
      if iovCount + curr.iovCount > MaxGsoIovecs:
        break
      if curr.size == first.size:
        iovCount += curr.iovCount
        inc count
        inc i
      elif curr.size < first.size:
        iovCount += curr.iovCount
        inc count
        inc i
        break
      else:
        break

    result.add SendGroup(
      first: start,
      count: count,
      segmentSize: (if count > 1: first.size else: 0),
      iovCount: iovCount,
      gso: count > 1,
    )

func sentSpecCount*(groups: openArray[SendGroup], sentMessages: int): int =
  for i in 0 ..< min(sentMessages, groups.len):
    result += groups[i].count
