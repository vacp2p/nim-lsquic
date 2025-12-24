# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

proc `[]=`*[T, U, V](
    target: var openArray[T], slice: HSlice[U, V], replacement: openArray[T]
) =
  doAssert replacement.len == slice.len
  for i in 0 ..< replacement.len:
    target[slice.a + i] = replacement[i]

template toOpenArray*[T](a: ptr T, length: uint): openArray[T] =
  toOpenArray(cast[ptr UncheckedArray[T]](a), 0, length.int - 1)

proc toPtr*[T](a: var openArray[T]): ptr T =
  if a.len == 0:
    nil
  else:
    addr a[0]
