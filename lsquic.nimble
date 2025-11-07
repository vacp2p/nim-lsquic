packageName = "lsquic"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Nim wrapper around the lsquic library"
license = "MIT"
installDirs = @["libs"]
installFiles = @["lsquic.nim", "lsquic_ffi.nim", "boringssl.nim"]

requires "nim >= 2.0.0", "zlib"

task format, "Format nim code using nph":
  exec "nimble install nph"
  exec "nph ."

task test, "Run tests":
  when defined(windows):
    exec "nim cpp -d:nimDebugDlOpen -r --threads:on tests/test_lsquic.nim"
  else:
    exec "nim cpp -r --threads:on tests/test_lsquic.nim"
