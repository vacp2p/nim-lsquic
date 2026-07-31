# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## A reusable recvmmsg batch: one syscall drains a whole burst, where a
## recvfrom loop needs one syscall per datagram plus a final one to discover
## the socket is empty.
##
## recvmmsg wants its buffers reserved up front, so a slot has to hold any
## datagram the peer may legally send. Slots are `MaxReceiveDatagramSize`, the
## same value the engine advertises as `max_udp_payload_size`. Anything longer
## is reported by MSG_TRUNC rather than silently cut, and the caller drops it.

when defined(linux):
  import std/posix
  import ./mmsg
  import ../socketconfig

  type RecvBatch* = object
    buf*: seq[byte]
    addrs: seq[Sockaddr_storage]
    iovs: seq[IOVec]
    msgs: seq[MMsgHdr]
    dirty: int ## slots the kernel filled on the previous call

  func initialized*(batch: RecvBatch): bool {.raises: [].} =
    batch.msgs.len > 0

  proc init*(batch: var RecvBatch) {.raises: [].} =
    batch.buf = newSeq[byte](MaxDatagramsPerWakeup * MaxReceiveDatagramSize)
    batch.addrs = newSeq[Sockaddr_storage](MaxDatagramsPerWakeup)
    batch.iovs = newSeq[IOVec](MaxDatagramsPerWakeup)
    batch.msgs = newSeq[MMsgHdr](MaxDatagramsPerWakeup)
    batch.dirty = 0
    for i in 0 ..< MaxDatagramsPerWakeup:
      batch.iovs[i] = IOVec(
        iov_base: addr batch.buf[i * MaxReceiveDatagramSize],
        iov_len: MaxReceiveDatagramSize.csize_t,
      )
      batch.msgs[i].msg_hdr.msg_name = addr batch.addrs[i]
      batch.msgs[i].msg_hdr.msg_namelen = SockLen(sizeof(Sockaddr_storage))
      batch.msgs[i].msg_hdr.msg_iov = addr batch.iovs[i]
      when defined(x86_64) and not defined(android):
        batch.msgs[i].msg_hdr.msg_iovlen = 1.csize_t
      else:
        batch.msgs[i].msg_hdr.msg_iovlen = 1.cint

  proc receive*(batch: var RecvBatch, fd: SocketHandle): int {.raises: [].} =
    ## Reads a whole burst. Returns the number of datagrams, or a negative
    ## value when the socket is empty or the read failed.
    ##
    ## MSG_TRUNC makes the kernel report the true length of a datagram that did
    ## not fit, so an oversized one can be logged with the size it actually was
    ## rather than the size that was copied.
    for i in 0 ..< batch.dirty:
      # msg_namelen is in/out: the kernel writes back the length of the address
      # it stored, and that value is the capacity on the next call, so only the
      # slots it filled last time need restoring. msg_flags needs no reset, the
      # kernel writes it on every slot it fills.
      batch.msgs[i].msg_hdr.msg_namelen = SockLen(sizeof(Sockaddr_storage))

    let received =
      recvmmsg(fd, addr batch.msgs[0], MaxDatagramsPerWakeup.cuint, MSG_TRUNC, nil).int
    batch.dirty = max(received, 0)
    received

  func datagramLen*(batch: RecvBatch, i: int): int {.raises: [].} =
    ## The length the datagram had on the wire, which for a truncated one is
    ## more than was copied into the slot.
    batch.msgs[i].msg_len.int

  func truncated*(batch: RecvBatch, i: int): bool {.raises: [].} =
    (batch.msgs[i].msg_hdr.msg_flags and MSG_TRUNC) != 0

  proc sender*(batch: var RecvBatch, i: int): ptr SockAddr {.raises: [].} =
    cast[ptr SockAddr](addr batch.addrs[i])

  template payload*(batch: RecvBatch, i, length: int): openArray[byte] =
    batch.buf.toOpenArray(
      i * MaxReceiveDatagramSize, i * MaxReceiveDatagramSize + length - 1
    )
