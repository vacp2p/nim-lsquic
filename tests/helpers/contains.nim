# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

proc contains*(a: seq[byte], sub: seq[byte]): bool =
  for i in 0 ..< a.len - sub.len:
    if a[i ..< i + sub.len] == sub:
      return true
