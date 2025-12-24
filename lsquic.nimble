packageName = "lsquic"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Nim wrapper around the lsquic library"
license = "MIT"
installDirs = @["libs"]
installFiles = @["lsquic.nim", "boringssl.nim"]

requires "nim >= 2.0.0"
requires "zlib"
requires "stew >= 0.4.0"
requires "chronos >= 4.0.4"
requires "nimcrypto >= 0.6.0"
requires "unittest2"
requires "chronicles >= 0.11.0"

var flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler

before install:
  when defined(windows):
    # On Windows MinGW there's no assembly for adx so we fall back to portable implementation via patch
    exec "git submodule update --init --recursive"
    exec "git -C ./libs/boringssl/third_party/fiat/ apply ../../../p256_64.h.patch"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/aes-gcm-avx2-x86_64-win.asm -o aes-gcm-avx2-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/aes-gcm-avx512-x86_64-win.asm -o aes-gcm-avx512-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/aesni-gcm-x86_64-win.asm -o aesni-gcm-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/aesni-x86-win.asm -o aesni-x86-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/aesni-x86_64-win.asm -o aesni-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/ghash-ssse3-x86-win.asm -o ghash-ssse3-x86-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/ghash-ssse3-x86_64-win.asm -o ghash-ssse3-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/ghash-x86-win.asm -o ghash-x86-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/ghash-x86_64-win.asm -o ghash-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/p256-x86_64-asm-win.asm -o p256-x86_64-asm-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/p256_beeu-x86_64-asm-win.asm -o p256_beeu-x86_64-asm-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/rdrand-x86_64-win.asm -o rdrand-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/rsaz-avx2-win.asm -o rsaz-avx2-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/sha1-x86_64-win.asm -o sha1-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/sha256-x86_64-win.asm -o sha256-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/sha512-x86_64-win.asm -o sha512-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/vpaes-x86-win.asm -o vpaes-x86-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/vpaes-x86_64-win.asm -o vpaes-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/x86-mont-win.asm -o x86-mont-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/x86_64-mont-win.asm -o x86_64-mont-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/bcm/x86_64-mont5-win.asm -o x86_64-mont5-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/crypto/md5-x86_64-win.asm -o md5-x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/crypto/chacha20_poly1305_x86_64-win.asm -o chacha20_poly1305_x86_64-win.o"
    exec "nasm -f win64 ./libs/boringssl/gen/crypto/chacha-x86_64-win.asm -o chacha-x86_64-win.o"

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
