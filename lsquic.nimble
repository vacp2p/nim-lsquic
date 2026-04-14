packageName = "lsquic"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Nim wrapper around the lsquic library"
license = "MIT"

skipDirs = @[
  "benchmarks",
  "tests",
  "libs/lsquic/bin",
  "libs/lsquic/docs",
  "libs/lsquic/qir",
  "libs/lsquic/tests",
  "libs/lsquic/tools",
  "libs/lsquic/src/liblsquic/ls-qpack/bin",
  "libs/lsquic/src/liblsquic/ls-qpack/fuzz",
  "libs/lsquic/src/liblsquic/ls-qpack/test",
  "libs/lsquic/src/liblsquic/ls-qpack/tools",
  "libs/lsquic/src/lshpack/test",
  "libs/lsquic/src/lshpack/bin",
  "libs/vac_boringssl/.bcr",
  "libs/vac_boringssl/.github",
  "libs/vac_boringssl/bench",
  "libs/vac_boringssl/cmake",
  "libs/vac_boringssl/crypto/cipher/test",
  "libs/vac_boringssl/crypto/evp/test",
  "libs/vac_boringssl/crypto/fipsmodule/bn/test",
  "libs/vac_boringssl/crypto/fipsmodule/policydocs",
  "libs/vac_boringssl/crypto/pkcs7/test",
  "libs/vac_boringssl/crypto/pkcs8/test",
  "libs/vac_boringssl/crypto/rsa/test",
  "libs/vac_boringssl/crypto/test",
  "libs/vac_boringssl/crypto/x509/test",
  "libs/vac_boringssl/docs",
  "libs/vac_boringssl/fuzz",
  "libs/vac_boringssl/gen/test_support",
  "libs/vac_boringssl/infra",
  "libs/vac_boringssl/pki",
  "libs/vac_boringssl/rust",
  "libs/vac_boringssl/ssl/test",
  "libs/vac_boringssl/third_party/benchmark",
  "libs/vac_boringssl/third_party/googletest",
  "libs/vac_boringssl/third_party/wycheproof_testvectors",
  "libs/vac_boringssl/tool",
  "libs/vac_boringssl/util",
]

skipFiles = @[
  "extras.nim",
  "generate_lsquic_ffi.nim",
  "build.sh",
  "libs/vac_boringssl/ssl/ssl_c_test.c",
  "libs/vac_boringssl/ssl/ssl_internal_test.cc",
  "libs/vac_boringssl/ssl/ssl_test.cc",
  "libs/vac_boringssl/ssl/span_test.cc",
]

installFiles = @[
  "lsquic.nim",
  "boringssl.nim",
]

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
