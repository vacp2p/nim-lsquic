# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos/osdefs
import ../lsquic_ffi

## Groups an lsquic out_spec batch into runs of adjacent packets with the same
## destination. The send path gives each run to the kernel as one segmented UDP
## datagram (Linux GSO / Windows USO).
##
## The code groups only adjacent specs. A run then maps to a contiguous index
## range, so the send path can report a true prefix count to lsquic.

const
  MaxBatch* = 1024
    ## lsquic MAX_OUT_BATCH_SIZE: upper bound on specs per callback invocation.
  MaxGsoSegments* = 64 ## Linux UDP_MAX_SEGMENTS; reused as the segment cap on Windows.
  MaxGsoBytes* = 65507
    ## Maximum total payload of one segmented datagram. The IPv4 limit is 0xFFFF
    ## minus the 20-byte IP header and the 8-byte UDP header. A larger payload
    ## fails the whole send with EMSGSIZE. IPv6 allows 65527. Use the lower value
    ## for both.

type GsoGroup* = object
  firstSpec*: uint16
  count*: uint16 ## members are specs[firstSpec ..< firstSpec + count]
  segSize*: uint32 ## only the last member can be smaller
  totalBytes*: uint32
  useGso*: bool ## false for a solo group, which needs no segmentation cmsg

proc sameDest(a, b: ptr SockAddr): bool =
  if a.sa_family != b.sa_family:
    return false
  if int(a.sa_family) == int(AF_INET):
    # family + port + address occupy the first 8 bytes of sockaddr_in
    equalMem(a, b, 8)
  elif int(a.sa_family) == int(AF_INET6):
    # family + port + flowinfo + address + scope_id: first 28 bytes
    equalMem(a, b, 28)
  else:
    false

proc groupSpecs*(
    specs: ptr UncheckedArray[struct_lsquic_out_spec],
    nspecs: int,
    groups: var array[MaxBatch, GsoGroup],
): int =
  ## Returns the number of groups. The groups come in index order, so
  ## groups[k].firstSpec is the exact number of specs before group k.
  doAssert nspecs <= MaxBatch

  var
    ngroups = 0
    open = -1 # group of the previous spec, while it can still grow

  for i in 0 ..< nspecs:
    let spec = addr specs[i]
    var placed = false

    if open >= 0 and spec.iovlen == 1:
      let
        head = addr specs[groups[open].firstSpec.int]
        segLen = uint32(spec.iov[].iov_len)
      if head.ecn == spec.ecn and sameDest(head.dest_sa, spec.dest_sa):
        if segLen == groups[open].segSize:
          inc groups[open].count
          groups[open].totalBytes += segLen
          if groups[open].count.int == MaxGsoSegments or
              groups[open].totalBytes + groups[open].segSize > MaxGsoBytes:
            open = -1
          placed = true
        elif segLen < groups[open].segSize:
          # GSO allows exactly one trailing shorter segment
          inc groups[open].count
          groups[open].totalBytes += segLen
          open = -1
          placed = true
        # a larger packet, such as a PMTUD probe, starts a new group

    if not placed:
      groups[ngroups] = GsoGroup(firstSpec: uint16(i), count: 1)
      open = -1
      if spec.iovlen == 1:
        let segLen = uint32(spec.iov[].iov_len)
        groups[ngroups].segSize = segLen
        groups[ngroups].totalBytes = segLen
        if segLen * 2 <= MaxGsoBytes:
          open = ngroups
      inc ngroups

  for g in 0 ..< ngroups:
    groups[g].useGso = groups[g].count >= 2

  ngroups
