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

proc checkGroupInvariants(
    groups: array[MaxBatch, GsoGroup], ngroups: int, nspecs: int
) =
  ## Properties every grouping must hold regardless of input. The first is what
  ## the send path's prefix accounting rests on: groups tile specs[0 ..< nspecs]
  ## contiguously and in order, so groups[k].firstSpec is exactly the number of
  ## specs preceding group k. The rest keep a segmented send within what the
  ## kernel will accept.
  var next = 0
  for g in 0 ..< ngroups:
    check groups[g].firstSpec.int == next
    check groups[g].count.int >= 1
    next += groups[g].count.int
    if groups[g].useGso:
      check groups[g].count.int <= MaxGsoSegments
      check groups[g].totalBytes.int <= MaxGsoBytes
  check next == nspecs

proc run(
    dests: var seq[Sockaddr_storage],
    defs: seq[SpecDef],
    groups: var array[MaxBatch, GsoGroup],
): int =
  var
    iovecs: seq[struct_iovec]
    specs: seq[struct_lsquic_out_spec]
  build(dests, defs, iovecs, specs)
  result = groupSpecs(
    cast[ptr UncheckedArray[struct_lsquic_out_spec]](addr specs[0]), specs.len, groups
  )
  checkGroupInvariants(groups, result, specs.len)

proc members(groups: array[MaxBatch, GsoGroup], g: int): seq[int] =
  for j in 0 ..< groups[g].count.int:
    result.add groups[g].firstSpec.int + j

suite "gso grouping":
  setup:
    var
      dests = @[
        makeAddr("127.0.0.1:1001"), makeAddr("127.0.0.1:1002"), makeAddr("[::1]:1003")
      ]
      groups: array[MaxBatch, GsoGroup]

  test "adjacent packets to one destination form a single group":
    var defs: seq[SpecDef]
    for _ in 0 ..< 4:
      defs.add spec(0, 1200)
    let n = run(dests, defs, groups)

    check n == 1
    check groups[0].count == 4
    check groups[0].segSize == 1200
    check groups[0].totalBytes == 4800
    check groups[0].useGso
    check members(groups, 0) == @[0, 1, 2, 3]

  test "interleaved destinations do not group":
    var defs: seq[SpecDef]
    for _ in 0 ..< 3:
      for d in 0 ..< 3:
        defs.add spec(d, 1200)
    let n = run(dests, defs, groups)

    # Only adjacent specs are grouped, so a round-robin batch yields solo
    # groups; the send path falls back to plain sendmmsg for them.
    check n == 9
    for g in 0 ..< n:
      check groups[g].count == 1
      check not groups[g].useGso

  test "a run resumes after an interruption from another destination":
    let defs =
      @[spec(0, 1200), spec(0, 1200), spec(1, 1200), spec(0, 1200), spec(0, 1200)]
    let n = run(dests, defs, groups)

    check n == 3
    check members(groups, 0) == @[0, 1]
    check members(groups, 1) == @[2]
    check members(groups, 2) == @[3, 4]
    check groups[0].useGso
    check not groups[1].useGso
    check groups[2].useGso

  test "trailing shorter segment joins and closes the group":
    let defs = @[spec(0, 1200), spec(0, 1200), spec(0, 600), spec(0, 1200)]
    let n = run(dests, defs, groups)

    check n == 2
    check groups[0].count == 3
    check groups[0].totalBytes == 3000
    check groups[1].firstSpec == 3
    check groups[1].count == 1
    check members(groups, 0) == @[0, 1, 2]

  test "larger packet closes the group and starts its own":
    let defs = @[spec(0, 1200), spec(0, 1500), spec(0, 1500)]
    let n = run(dests, defs, groups)

    check n == 2
    check groups[0].count == 1
    check not groups[0].useGso
    check groups[1].firstSpec == 1
    check groups[1].count == 2
    check groups[1].segSize == 1500

  test "segment count cap splits a destination":
    var defs: seq[SpecDef]
    for _ in 0 ..< MaxGsoSegments + 1:
      defs.add spec(0, 500)
    let n = run(dests, defs, groups)

    check n == 2
    check groups[0].count == MaxGsoSegments
    check groups[1].count == 1

  test "byte cap splits a destination below the kernel limit":
    # 62 * 1040 = 64480; a 63rd segment would reach 65520, past the 65507 a
    # single IPv4 datagram can carry - the kernel rejects the whole send with
    # EMSGSIZE, so the group must close first.
    var defs: seq[SpecDef]
    for _ in 0 ..< 63:
      defs.add spec(0, 1040)
    let n = run(dests, defs, groups)

    check n == 2
    check groups[0].count == 62
    check groups[0].totalBytes == 64480
    check groups[1].count == 1

  test "coalesced multi-iovec spec forms a solo group":
    let defs = @[spec(0, 1200), coalesced(0, @[500, 700]), spec(0, 1200)]
    let n = run(dests, defs, groups)

    check n == 3
    check groups[1].count == 1
    check not groups[1].useGso
    check members(groups, 1) == @[1]

  test "differing ecn splits groups":
    let defs = @[spec(0, 1200, ecn = 0), spec(0, 1200, ecn = 2), spec(0, 1200, ecn = 2)]
    let n = run(dests, defs, groups)

    check n == 2
    check groups[0].count == 1
    check groups[1].count == 2
    check members(groups, 1) == @[1, 2]

  test "ipv4 and ipv6 destinations never merge":
    let defs = @[spec(0, 1200), spec(0, 1200), spec(2, 1200), spec(2, 1200)]
    let n = run(dests, defs, groups)

    check n == 2
    check members(groups, 0) == @[0, 1]
    check members(groups, 1) == @[2, 3]

  test "a full MaxBatch batch groups without overflowing":
    var defs: seq[SpecDef]
    for _ in 0 ..< MaxBatch:
      defs.add spec(0, 1200)
    let n = run(dests, defs, groups)

    # 54 * 1200 = 64800, and a 55th segment would exceed the byte cap
    check n == 19
    check groups[0].count == 54

  test "a full MaxBatch batch of interleaved destinations is all solo groups":
    var defs: seq[SpecDef]
    for i in 0 ..< MaxBatch:
      defs.add spec(i mod 3, 1200)
    let n = run(dests, defs, groups)

    check n == MaxBatch
