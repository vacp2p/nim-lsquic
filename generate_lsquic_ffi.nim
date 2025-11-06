import futhark
from os import parentDir, `/`

importc:
  outputPath currentSourcePath.parentDir / "tmp_lsquic_ffi.nim"
  path currentSourcePath.parentDir / "libs/lsquic/include"
  rename FILE, CFile # Rename `FILE` that STB uses to `CFile` which is the Nim equivalent
  "lsquic.h"
  "openssl/ssl.h"
  "openssl/crypto.h"
  "openssl/rand.h"
  "openssl/asn1.h"