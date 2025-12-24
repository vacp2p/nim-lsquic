# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import futhark
from os import parentDir, `/`

importc:
  outputPath currentSourcePath.parentDir / "tmp_lsquic_ffi.nim"
  path currentSourcePath.parentDir / "libs/lsquic/include"
  path currentSourcePath.parentDir / "libs/boringssl/include"
  rename FILE, CFile # Rename `FILE` that STB uses to `CFile` which is the Nim equivalent
  rename struct_sockaddr, SockAddr # Rename `struct_sockaddr` for chronos SockAddr
  "lsquic.h"
  "openssl/ssl.h"
  "openssl/crypto.h"
  "openssl/rand.h"
  "openssl/asn1.h"
