# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

when defined(windows):
  {.passl: "-lws2_32".}
  when defined(clang):
    {.passl: "-lpthread".}

import std/[os, strutils]
import chronos/osdefs
{.push warning[UnusedImport]: off.}
import zlib
{.pop.}
import boringssl

include lsquic/lsquic_ffi_types

# use rsplit as a workaround for cross compilation path separator issue
const root = currentSourcePath.rsplit({DirSep, AltSep}, 2)[0]
const lsquicInclude = root & "/libs/lsquic/include"
const liblsquicInclude = root & "/libs/lsquic/src/liblsquic"
const lsqpack = root & "/libs/lsquic/src/liblsquic/ls-qpack"
const lshpack = root & "/libs/lsquic/src/lshpack"
const xxhash = root & "/libs/lsquic/src/lshpack/deps/xxhash"

when defined(windows):
  const wincompat = root & "/libs/lsquic/wincompat"
  {.passc: "-I" & wincompat.}

{.passc: "-I" & lsquicInclude.}
{.passc: "-I" & liblsquicInclude.}
{.passc: "-I" & lsqpack.}
{.passc: "-I" & lshpack.}
{.passc: "-I" & xxhash.}

{.compile: "../lsquic_units/lsquic_support_unit.c".}
{.compile: "../lsquic_units/lsquic_qpack_unit.c".}
{.compile: "../lsquic_units/lsquic_core_unit.c".}
{.compile: "../lsquic_units/lsquic_cubic_unit.c".}
{.compile: "../lsquic_units/lsquic_connection_unit.c".}
{.compile: "../lsquic_units/lsquic_engine_unit.c".}
{.compile: "../lsquic_units/lsquic_frame_unit.c".}
{.compile: "../lsquic_units/lsquic_full_conn_ietf_unit.c".}
{.compile: "../lsquic_units/lsquic_http_unit.c".}
{.compile: "../lsquic_units/lsquic_packet_unit.c".}
{.compile: "../lsquic_units/lsquic_mini_conn_ietf_unit.c".}
{.compile: "../lsquic_units/lsquic_parse_unit.c".}
{.compile: "../lsquic_units/lsquic_parse_q046_unit.c".}
{.compile: "../lsquic_units/lsquic_parse_q050_unit.c".}
{.compile: "../lsquic_units/lsquic_parse_gquic_be_unit.c".}
{.compile: "../lsquic_units/lsquic_parse_ietf_unit.c".}
{.compile: "../lsquic_units/lsquic_qlog_unit.c".}
{.compile: "../lsquic_units/lsquic_purga_unit.c".}
{.compile: "../lsquic_units/lsquic_stream_unit.c".}
