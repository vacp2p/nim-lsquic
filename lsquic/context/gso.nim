# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos/osdefs
import ../lsquic_ffi

## Groups an lsquic out_spec batch into runs of adjacent packets sharing a
## destination, so each run can be sent as one segmented UDP datagram
## (Linux GSO / Windows USO).
##
## Only adjacent specs are grouped. lsquic's engine round-robins across
## connections, so a batch drawn from many peers interleaves destinations and
## the runs stay short — but such batches are themselves short, and grouping
## across the whole batch was measured to gain nothing there while costing a
## quadratic scan. Contiguous runs also keep a group's members at exactly
## specs[firstSpec ..< firstSpec + count], which is what lets the send path
## report a true prefix count back to lsquic.

const
  MaxBatch* = 1024
    ## lsquic MAX_OUT_BATCH_SIZE: upper bound on specs per callback invocation.
  MaxGsoSegments* = 64 ## Linux UDP_MAX_SEGMENTS; reused as the segment cap on Windows.
  MaxGsoBytes* = 65507
    ## Maximum total payload of one segmented datagram: the IPv4 ceiling of
    ## 0xFFFF less the 20-byte IP and 8-byte UDP headers. Going over fails the
    ## whole send with EMSGSIZE. IPv6 permits 65527; use the lower bound for both.

type GsoGroup* = object
  firstSpec*: uint16 ## index of the first member spec
  count*: uint16 ## members are specs[firstSpec ..< firstSpec + count]
  segSize*: uint32 ## segment size; only the last member may be smaller
  totalBytes*: uint32
  useGso*: bool ## false for solo groups: sent without a segmentation cmsg

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
  ## Buckets specs[0 ..< nspecs] into runs of adjacent same-destination specs.
  ## Returns the number of groups.
  ##
  ## Invariant the send path's partial-failure accounting relies on: group k
  ## holds exactly specs[firstSpec ..< firstSpec + count], and groups are
  ## emitted in index order, so groups[k].firstSpec is the exact number of
  ## specs preceding group k.
  doAssert nspecs <= MaxBatch

  var
    ngroups = 0
    open = -1 # group the previous spec landed in, while it can still grow

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
          # close once another full segment cannot fit, so appends always fit
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
        # a larger packet (e.g. a PMTUD probe) falls through to a fresh group

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
