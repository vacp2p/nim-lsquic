# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

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
