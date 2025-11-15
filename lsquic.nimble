packageName = "lsquic"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Nim wrapper around the lsquic library"
license = "MIT"
installDirs = @["libs"]
installFiles = @["lsquic.nim", "boringssl.nim"]

requires "nim >= 2.0.0"
requires "zlib"
requires "nim >= 2.0.0"
requires "stew >= 0.4.0"
requires "https://github.com/status-im/nim-chronos#03d928216facac908489757426a8b022ba4ceac7"
requires "chronos >= 4.0.4"
requires "nimcrypto >= 0.6.0"
requires "unittest2"
requires "chronicles >= 0.11.0"

before install:
  exec "git submodule update --init --recursive"

task format, "Format nim code using nph":
  exec "nimble install nph"
  exec "nph ."

task test, "Run tests":
  when defined(windows):
    exec "nim c --mm:refc -d:nimDebugDlOpen --threads:on tests/test_connection.nim"
  else:
    exec "nim c --mm:refc --threads:on tests/test_connection.nim"
  exec "./tests/test_connection --output-level=VERBOSE"

task test_release, "Run tests - release":
  when defined(windows):
    exec "nim c -d:release --mm:refc -d:nimDebugDlOpen --threads:on tests/test_connection.nim"
  else:
    exec "nim c -d:release --mm:refc --threads:on tests/test_connection.nim"
  exec "./tests/test_connection --output-level=VERBOSE"
