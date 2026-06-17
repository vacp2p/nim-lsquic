# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import futhark
import std/json
from os import parentDir, `/`

import chronos/osdefs
import boringssl

include lsquic/lsquic_ffi_types

# These are emitted from the C headers, but supplied by the shared types file.
const manualPreludeSymbols =
  ["MAX_CID_LEN", "GQUIC_CID_LEN", "struct_lsquic_cid", "lsquic_cid_t"]

# Futhark would otherwise emit opaque placeholders for aliases to these types
# when declaration guards are disabled.
const predeclaredTypeNames = [
  "lsquic_cid_t", "struct_ssl_st", "struct_ssl_ctx_st", "struct_ssl_session_st",
  "struct_stack_st_X509",
]

# Opir nests type descriptions inside fields, parameters, and return values.
# Rewriting aliases to bases makes Futhark reuse the Nim types already in scope.
proc rewriteKnownTypeAliases(node: JsonNode, knownTypeNames: openArray[string]) =
  case node.kind
  of JObject:
    if node{"kind"}.getStr("") == "alias":
      let aliasName = node{"value"}.getStr("")
      if aliasName in knownTypeNames:
        node["kind"] = %"base"
        return

      # chronos already provides this type under Nim's SockAddr spelling.
      if aliasName == "struct_sockaddr":
        node["kind"] = %"base"
        node["value"] = %"SockAddr"
        return

    for _, value in node.pairs:
      rewriteKnownTypeAliases(value, knownTypeNames)
  of JArray:
    for value in node.items:
      rewriteKnownTypeAliases(value, knownTypeNames)
  else:
    discard

proc normalizeOpirImpl(opirOutput: JsonNode): JsonNode =
  var knownTypeNames: seq[string]
  for name in predeclaredTypeNames:
    knownTypeNames.add name

  for node in opirOutput.items:
    if node{"kind"}.getStr("") == "enum" and node.hasKey("name") and
        node["name"].kind == JString:
      knownTypeNames.add node{"name"}.getStr("")

  var resp = newJArray()
  for node in opirOutput.items:
    if node{"name"}.getStr("") in manualPreludeSymbols:
      continue

    # enums are generated manually to avoid issue described in
    # https://github.com/PMunch/futhark/issues/152
    if node{"kind"}.getStr("") == "enum":
      continue

    rewriteKnownTypeAliases(node, knownTypeNames)

    resp.add node
  resp

importc:
  outputPath currentSourcePath.parentDir / "tmp_lsquic_ffi.nim"
  path currentSourcePath.parentDir / "libs/lsquic/include"
  addopircallback proc(opirOutput: JsonNode): JsonNode {.closure.} =
    normalizeOpirImpl(opirOutput)
  rename FILE, CFile # Rename `FILE` that STB uses to `CFile` which is the Nim equivalent
  "lsquic.h"
