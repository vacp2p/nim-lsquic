packageName = "lsquic"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Nim wrapper around the lsquic library"
license = "MIT"

import os, strutils

const rootInstallFiles = @[
  "lsquic.nim",
  "boringssl.nim",
]

installDirs = @[
  "lsquic",
  "libs/lsquic/include",
  "libs/lsquic/src/lshpack",
  "libs/lsquic/wincompat",
]

const filteredInstallRoots = @[
  "libs/lsquic/src/liblsquic",
  "libs/vac_boringssl/include",
  "libs/vac_boringssl/crypto",
  "libs/vac_boringssl/decrepit",
  "libs/vac_boringssl/gen",
  "libs/vac_boringssl/ssl",
  "libs/vac_boringssl/third_party/fiat",
]

const skippedInstallDirs = @[
  "libs/lsquic/docs",
  "libs/lsquic/tests",
  "libs/lsquic/tools",
  "libs/lsquic/src/liblsquic/ls-qpack/bin",
  "libs/lsquic/src/liblsquic/ls-qpack/fuzz",
  "libs/lsquic/src/liblsquic/ls-qpack/test",
  "libs/lsquic/src/liblsquic/ls-qpack/tools",
  "libs/lsquic/src/lshpack/test",
  "libs/vac_boringssl/cmake",
  "libs/vac_boringssl/crypto/cipher/test",
  "libs/vac_boringssl/crypto/fipsmodule/policydocs",
  "libs/vac_boringssl/crypto/evp/test",
  "libs/vac_boringssl/crypto/fipsmodule/bn/test",
  "libs/vac_boringssl/crypto/pkcs7/test",
  "libs/vac_boringssl/crypto/pkcs8/test",
  "libs/vac_boringssl/crypto/rsa/test",
  "libs/vac_boringssl/crypto/test",
  "libs/vac_boringssl/crypto/x509/test",
  "libs/vac_boringssl/docs",
  "libs/vac_boringssl/fuzz",
  "libs/vac_boringssl/gen/test_support",
  "libs/vac_boringssl/ssl/test",
  "libs/vac_boringssl/third_party/wycheproof_testvectors",
]

proc normalizeInstallPath(path: string): string =
  path.replace('\\', '/')

proc isHiddenPath(path: string): bool =
  let norm = normalizeInstallPath(path)
  let tail = norm.splitPath.tail
  tail.len > 0 and tail[0] == '.'

proc isSkippedInstallPath(path: string): bool =
  let norm = normalizeInstallPath(path)
  if isHiddenPath(norm):
    return true

  for skipped in skippedInstallDirs:
    if norm == skipped or norm.startsWith(skipped & "/"):
      return true

  false

proc collectInstallFiles(root: string) =
  for kind, path in walkDir(root):
    let norm = normalizeInstallPath(path)
    case kind
    of pcDir:
      if not isSkippedInstallPath(norm):
        collectInstallFiles(norm)
    of pcFile:
      if not isSkippedInstallPath(norm):
        installFiles.add(norm)
    else:
      discard

installFiles = rootInstallFiles
for root in filteredInstallRoots:
  collectInstallFiles(root)

requires "nim >= 2.0.0"
requires "zlib"
requires "stew >= 0.4.0"
requires "chronos >= 4.0.4"
requires "nimcrypto >= 0.6.0"
requires "unittest2"
requires "chronicles >= 0.11.0"

var flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler

task format, "Format nim code using nph":
  exec "nph ./. *.nim"

task test, "Run tests":
  var nimc = "nim c -d:fast --threads:on " & flags

  when defined(windows):
    nimc &= " -d:nimDebugDlOpen"

  exec nimc & " tests/test_all.nim"
  exec "./tests/test_all --output-level=VERBOSE"

task test_release, "Run tests - release":
  flags = flags & " -d:release "
  testTask()
