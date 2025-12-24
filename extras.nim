# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const
  LSQUIC_GLOBAL_CLIENT* = (1 shl 0)
  LSQUIC_GLOBAL_SERVER* = (1 shl 1)

# Engine modes
const
  LSENG_SERVER* = (1 shl 0)
  LSENG_HTTP* = (1 shl 1)
  LSENG_HTTP_SERVER* = (LSENG_SERVER or LSENG_HTTP)
