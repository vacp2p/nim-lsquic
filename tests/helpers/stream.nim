# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronos
import unittest2
import lsquic

proc newData*(size: int, val: byte = byte(0xEE)): seq[byte] =
  var data = newSeq[byte](size)
  for i in 0 ..< size:
    data[i] = val
  return data

proc patternData*(size: int): seq[byte] =
  var data = newSeq[byte](size)
  for i in 0 ..< size:
    data[i] = byte(i mod 251)
  return data

proc readAllChunked*(
    stream: Stream, bufSize: int
): Future[tuple[data: seq[byte], reads: int]] {.async.} =
  ## Drains `stream` to EOF using a fixed `bufSize` buffer, asserting that no
  ## read ever returns more than the buffer can hold. Returns the reassembled
  ## data together with the number of non-empty reads it took to receive it.
  var buf = newSeq[byte](bufSize)
  var received: seq[byte]
  var reads = 0
  while true:
    let n = await stream.readOnce(buf)
    if n == 0:
      break
    check n <= bufSize
    received.add(buf[0 ..< n])
    inc reads
  return (received, reads)

proc readStreamTillEOF*(
    stream: Stream, maxBytes: int = int.high
): Future[seq[byte]] {.async.} =
  ## Reads from stream until EOF is reached or the received data size meets/exceeds maxBytes

  var buf = newSeq[byte](4096)
  var receivedData: seq[byte]
  while true:
    let n = await stream.readOnce(buf)
    if n == 0:
      break
    receivedData.add(buf[0 ..< n])
    if receivedData.len >= maxBytes:
      break
  return receivedData

proc checkEqual*(a: seq[byte], b: seq[byte]) =
  if a.len != b.len:
    checkpoint("sequences do not have the same length: " & $a.len & " != " & $b.len)
    fail()
    return

  for i in 0 ..< a.len:
    if a[i] != b[i]:
      checkpoint("sequences do not have same data")
      fail()
      return
