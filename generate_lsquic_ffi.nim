# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import futhark
from os import parentDir, `/`

import boringssl

importc:
  outputPath currentSourcePath.parentDir / "tmp_lsquic_ffi.nim"
  path currentSourcePath.parentDir / "libs/lsquic/include"
  rename FILE, CFile # Rename `FILE` that STB uses to `CFile` which is the Nim equivalent
  rename struct_sockaddr, SockAddr # Rename `struct_sockaddr` for chronos SockAddr
  "lsquic.h"
