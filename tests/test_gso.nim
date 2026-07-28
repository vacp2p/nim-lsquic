# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/osdefs, chronos/unittest2/asynctests
import ../lsquic/context/gso
import ../lsquic/lsquic_ffi

type SpecDef = object
  dest: int
  sizes: seq[int] # one iovec per entry; len > 1 means a coalesced datagram
  ecn: int

proc spec(dest: int, size: int, ecn = 0): SpecDef =
  SpecDef(dest: dest, sizes: @[size], ecn: ecn)

proc coalesced(dest: int, sizes: seq[int]): SpecDef =
  SpecDef(dest: dest, sizes: sizes)

proc makeAddr(address: string): Sockaddr_storage =
  var length: SockLen
  initTAddress(address).toSAddr(result, length)

proc build(
    dests: var seq[Sockaddr_storage],
    defs: seq[SpecDef],
    iovecs: var seq[struct_iovec],
    specs: var seq[struct_lsquic_out_spec],
) =
  var total = 0
  for d in defs:
    total += d.sizes.len
  iovecs = newSeq[struct_iovec](total)
  specs = newSeq[struct_lsquic_out_spec](defs.len)

  var k = 0
  for i, d in defs:
    specs[i] = struct_lsquic_out_spec(
      iov: addr iovecs[k],
      iovlen: csize_t(d.sizes.len),
      dest_sa: cast[ptr SockAddr](addr dests[d.dest]),
      ecn: cint(d.ecn),
    )
    for size in d.sizes:
      iovecs[k] = struct_iovec(iov_base: nil, iov_len: csize_t(size))
      inc k

proc run(
    dests: var seq[Sockaddr_storage],
    defs: seq[SpecDef],
    groups: var array[MaxBatch, GsoGroup],
    order: var array[MaxBatch, uint16],
): int =
  var
    iovecs: seq[struct_iovec]
    specs: seq[struct_lsquic_out_spec]
  build(dests, defs, iovecs, specs)
  groupSpecs(
    cast[ptr UncheckedArray[struct_lsquic_out_spec]](addr specs[0]),
    specs.len,
    groups,
    order,
  )

proc members(
    groups: array[MaxBatch, GsoGroup], order: array[MaxBatch, uint16], g: int
): seq[int] =
  var start = 0
  for k in 0 ..< g:
    start += groups[k].count.int
  for j in 0 ..< groups[g].count.int:
    result.add order[start + j].int

proc checkAscendingFirstSpec(groups: array[MaxBatch, GsoGroup], ngroups: int) =
  for g in 1 ..< ngroups:
    check groups[g].firstSpec > groups[g - 1].firstSpec

suite "gso grouping":
  setup:
    var
      dests = @[
        makeAddr("127.0.0.1:1001"), makeAddr("127.0.0.1:1002"), makeAddr("[::1]:1003")
      ]
      groups: array[MaxBatch, GsoGroup]
      order: array[MaxBatch, uint16]

  test "round-robin interleave collapses to one group per destination":
    var defs: seq[SpecDef]
    for _ in 0 ..< 3:
      for d in 0 ..< 3:
        defs.add spec(d, 1200)
    let n = run(dests, defs, groups, order)

    check n == 3
    for g in 0 ..< n:
      check groups[g].count == 3
      check groups[g].segSize == 1200
      check groups[g].useGso
    check members(groups, order, 0) == @[0, 3, 6]
    check members(groups, order, 1) == @[1, 4, 7]
    check members(groups, order, 2) == @[2, 5, 8]
    checkAscendingFirstSpec(groups, n)

  test "trailing shorter segment joins and closes the group":
    let defs = @[spec(0, 1200), spec(0, 1200), spec(0, 600), spec(0, 1200)]
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == 3
    check groups[0].totalBytes == 3000
    check groups[1].firstSpec == 3
    check groups[1].count == 1
    check members(groups, order, 0) == @[0, 1, 2]

  test "larger packet closes the group and starts its own":
    let defs = @[spec(0, 1200), spec(0, 1500), spec(0, 1500)]
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == 1
    check not groups[0].useGso
    check groups[1].firstSpec == 1
    check groups[1].count == 2
    check groups[1].segSize == 1500
    checkAscendingFirstSpec(groups, n)

  test "segment count cap splits a destination":
    var defs: seq[SpecDef]
    for _ in 0 ..< MaxGsoSegments + 1:
      defs.add spec(0, 500)
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == MaxGsoSegments
    check groups[1].count == 1

  test "byte cap splits a destination":
    var defs: seq[SpecDef]
    for _ in 0 ..< 46:
      defs.add spec(0, 1472)
    let n = run(dests, defs, groups, order)

    # 44 * 1472 = 64768; another full segment would exceed 65535
    check n == 2
    check groups[0].count == 44
    check groups[0].totalBytes == 64768
    check groups[1].count == 2

  test "coalesced multi-iovec spec forms a solo group":
    let defs = @[spec(0, 1200), coalesced(0, @[500, 700]), spec(0, 1200)]
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == 2
    check groups[0].useGso
    check groups[1].firstSpec == 1
    check groups[1].count == 1
    check not groups[1].useGso
    check members(groups, order, 0) == @[0, 2]
    check members(groups, order, 1) == @[1]
    checkAscendingFirstSpec(groups, n)

  test "differing ecn splits groups":
    let defs = @[spec(0, 1200, ecn = 0), spec(0, 1200, ecn = 2), spec(0, 1200, ecn = 0)]
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == 2
    check members(groups, order, 0) == @[0, 2]
    check groups[1].count == 1

  test "ipv4 and ipv6 destinations never merge":
    let defs = @[spec(0, 1200), spec(2, 1200), spec(0, 1200), spec(2, 1200)]
    let n = run(dests, defs, groups, order)

    check n == 2
    check groups[0].count == 2
    check groups[1].count == 2
    check members(groups, order, 1) == @[1, 3]
