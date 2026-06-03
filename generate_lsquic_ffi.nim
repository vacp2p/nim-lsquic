# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import futhark
import std/json
from os import parentDir, `/`

import boringssl

const preludeTypes = ["struct_lsquic_cid", "lsquic_cid_t"]

proc dropPreludeTypesAndGeneratedCEnumsImpl(opirOutput: JsonNode): JsonNode =
  var resp = newJArray()
  for node in opirOutput:
    # enums are generated manually to avoid issue described in
    # https://github.com/PMunch/futhark/issues/152
    if node{"kind"}.getStr("") == "enum":
      continue

    # Futhark incorrectly maps the struct alignment on lsquic_cid_t to field alignment,
    # so the prelude supplies the correct native layout instead.
    if node{"name"}.getStr("") in preludeTypes:
      continue

    resp.add node
  resp

importc:
  outputPath currentSourcePath.parentDir / "tmp_lsquic_ffi.nim"
  path currentSourcePath.parentDir / "libs/lsquic/include"
  addopircallback proc(opirOutput: JsonNode): JsonNode {.closure.} =
    dropPreludeTypesAndGeneratedCEnumsImpl(opirOutput)
  rename FILE, CFile # Rename `FILE` that STB uses to `CFile` which is the Nim equivalent
  rename struct_sockaddr, SockAddr # Rename `struct_sockaddr` for chronos SockAddr
  "lsquic.h"
