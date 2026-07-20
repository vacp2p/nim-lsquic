# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import sequtils
import os
import std/sets

const certificateStr =
  staticRead(parentDir(currentSourcePath()) / "testCertificate.pem")
const privateKeyStr = staticRead(parentDir(currentSourcePath()) / "testPrivateKey.pem")

proc strToSeq(val: string): seq[byte] =
  toSeq(val.toOpenArrayByte(0, val.high))

proc testCertificate*(): seq[byte] =
  strToSeq(certificateStr)

proc testPrivateKey*(): seq[byte] =
  strToSeq(privateKeyStr)

proc singleAlpn*(name: string = "test"): HashSet[string] =
  var alpn = initHashSet[string]()
  alpn.incl(name)
  alpn
