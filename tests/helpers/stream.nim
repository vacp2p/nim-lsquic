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
