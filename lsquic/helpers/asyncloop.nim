# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos

proc asyncLoop*(
    repeat: proc(): Future[void].Raising([CancelledError]) {.gcsafe, raises: [].}
): Future[void] {.async: (raises: [CancelledError]).} =
  ## Repeatedly calls the async proc `repeat` until cancelled.
  while true:
    try:
      await repeat()
    except CancelledError as e:
      raise e
