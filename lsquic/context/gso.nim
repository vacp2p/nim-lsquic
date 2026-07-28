# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos/osdefs
import ../lsquic_ffi

## Groups an lsquic out_spec batch by destination so that packets to the same
## peer can be sent as one segmented UDP datagram (Linux GSO / Windows USO).
## lsquic's engine emits at most one packet per connection per iteration
## (fairness round-robin), so packets to the same destination are rarely
## adjacent in the batch — grouping must consider the whole batch.

const
  MaxBatch* = 1024
    ## lsquic MAX_OUT_BATCH_SIZE: upper bound on specs per callback invocation.
  MaxGsoSegments* = 64 ## Linux UDP_MAX_SEGMENTS; reused as the segment cap on Windows.
  MaxGsoBytes* = 65535 ## Maximum total payload of one segmented super-datagram.

type GsoGroup* = object
  firstSpec*: uint16 ## index of the first member spec
  count*: uint16 ## number of member specs
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
    specOrder: var array[MaxBatch, uint16],
): int =
  ## Buckets specs[0 ..< nspecs] into destination groups; member indices land
  ## grouped-contiguously in specOrder. Returns the number of groups.
  ##
  ## Invariant the send path's partial-failure accounting relies on: groups are
  ## ordered by ascending firstSpec, so every spec with an index below
  ## groups[k].firstSpec belongs to a group before k. If k is the first group
  ## not fully sent, groups[k].firstSpec is the exact prefix count to report
  ## back to lsquic.
  doAssert nspecs <= MaxBatch

  var
    specGroup {.noinit.}: array[MaxBatch, uint16]
    open {.noinit.}: array[MaxBatch, uint16] # indices of open groups
    nopen = 0
    ngroups = 0

  template closeOpen(idx: int) =
    open[idx] = open[nopen - 1]
    dec nopen

  for i in 0 ..< nspecs:
    let spec = addr specs[i]
    var placed = false
    if spec.iovlen == 1:
      let segLen = uint32(spec.iov[].iov_len)
      var j = 0
      while j < nopen:
        let g = open[j].int
        let head = addr specs[groups[g].firstSpec.int]
        if head.ecn == spec.ecn and sameDest(head.dest_sa, spec.dest_sa):
          if segLen == groups[g].segSize:
            specGroup[i] = uint16(g)
            inc groups[g].count
            groups[g].totalBytes += segLen
            # close once another full segment cannot fit, so appends always fit
            if groups[g].count.int == MaxGsoSegments or
                groups[g].totalBytes + groups[g].segSize > MaxGsoBytes:
              closeOpen(j)
            placed = true
          elif segLen < groups[g].segSize:
            # GSO allows exactly one trailing shorter segment
            specGroup[i] = uint16(g)
            inc groups[g].count
            groups[g].totalBytes += segLen
            closeOpen(j)
            placed = true
          else:
            # larger packet (e.g. PMTUD probe): close and start a fresh group
            closeOpen(j)
          break
        inc j

    if not placed:
      groups[ngroups] = GsoGroup(firstSpec: uint16(i), count: 1)
      specGroup[i] = uint16(ngroups)
      if spec.iovlen == 1:
        let segLen = uint32(spec.iov[].iov_len)
        groups[ngroups].segSize = segLen
        groups[ngroups].totalBytes = segLen
        if segLen * 2 <= MaxGsoBytes:
          open[nopen] = uint16(ngroups)
          inc nopen
      inc ngroups

  var
    offsets {.noinit.}: array[MaxBatch, int]
    off = 0
  for g in 0 ..< ngroups:
    offsets[g] = off
    off += groups[g].count.int
    groups[g].useGso = groups[g].count >= 2
  for i in 0 ..< nspecs:
    specOrder[offsets[specGroup[i].int]] = uint16(i)
    inc offsets[specGroup[i].int]

  ngroups
