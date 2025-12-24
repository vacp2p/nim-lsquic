# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos
import ./connection

type ConnectionManager* = ref object of RootObj
  connections: seq[Connection]
  closed*: Future[void]

proc new*(T: typedesc[ConnectionManager]): T =
  let ret = ConnectionManager()
  ret.closed = newFuture[void]()
  ret

proc stop*(connman: ConnectionManager) {.async: (raises: [CancelledError]).} =
  if connman.closed.finished:
    return

  connman.closed.complete()
  for conn in connman.connections:
    conn.abort()

proc addConnection*(connman: ConnectionManager, conn: Connection) =
  connman.connections.add(conn)
