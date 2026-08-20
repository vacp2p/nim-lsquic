# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

import chronicles
import chronos, results
import chronos/osdefs
import ./[errors, stream, lsquic_ffi, certificateverifier]
import ./context/context
import ./helpers/transportaddr

type
  Connection* = ref object of RootObj
    local: TransportAddress
    remote: TransportAddress
    ensureClosedFut: Future[void]
    isClosed*: bool
    closed: AsyncEvent
    # Reuse a single closed-event waiter to minimize allocations on hot paths.
    closedWaiter: Future[void].Raising([CancelledError])
    quicContext: QuicContext
    quicConn: QuicConnection

  IncomingConnection = ref object of Connection

  OutgoingConnection = ref object of Connection
    serverName: string
    certVerifier: Opt[CertificateVerifier]

proc ensureClosed(connection: Connection) {.async: (raises: [CancelledError]).} =
  await connection.closedWaiter
  debug "Closing connection"
  connection.isClosed = true
  if not connection.quicConn.closedLocal:
    connection.quicConn.closedRemote = true

proc close*(conn: Connection) {.raises: [].} =
  if conn.isClosed:
    return
  conn.isClosed = true
  conn.quicConn.closedLocal = true
  conn.quicContext.close(conn.quicConn)

proc abort*(conn: Connection) {.gcsafe, raises: [].} =
  if conn.isClosed:
    return
  conn.isClosed = true
  conn.quicConn.closedLocal = true
  conn.quicContext.abort(conn.quicConn)

# TODO: refactor this into a single newConnection

proc newOutgoingConnection*(
    quicContext: QuicContext,
    local: TransportAddress,
    remote: TransportAddress,
    serverName: string = "",
    certVerifier: Opt[CertificateVerifier] = Opt.none(CertificateVerifier),
): OutgoingConnection =
  let closed = newAsyncEvent()
  let closedWaiter = closed.wait()
  let conn = OutgoingConnection(
    quicContext: quicContext,
    local: local,
    remote: remote,
    closed: closed,
    serverName: serverName,
    certVerifier: certVerifier,
    closedWaiter: closedWaiter,
  )
  conn.ensureClosedFut = conn.ensureClosed()
  conn

proc newIncomingConnection*(
    quicContext: QuicContext, quicConn: QuicConnection
): Connection =
  let closed = newAsyncEvent()
  let closedWaiter = closed.wait()
  let conn = IncomingConnection(
    quicContext: quicContext,
    quicConn: quicConn,
    closed: closed,
    closedWaiter: closedWaiter,
    local: quicConn.local,
    remote: quicConn.remote,
    isClosed: quicConn.lsquicConn.isNil,
  )
  conn.ensureClosedFut = conn.ensureClosed()
  if conn.isClosed:
    conn.closed.fire()
  else:
    conn.quicConn.onClose = proc() {.raises: [].} =
      conn.closed.fire()
  conn

proc closedFuture*(connection: Connection): Future[void] {.raises: [].} =
  connection.ensureClosedFut

proc dial*(
    connection: OutgoingConnection
) {.async: (raw: true, raises: [CancelledError, DialError]).} =
  let retFut =
    Future[void].Raising([CancelledError, DialError]).init("OutgoingConnection.dial")
  let onClose = proc() {.raises: [].} =
    connection.closed.fire()

  connection.quicConn = connection.quicContext.dial(
    connection.local, connection.remote, retFut, onClose, connection.serverName,
    connection.certVerifier,
  ).valueOr:
    retFut.fail(newException(DialError, "could not dial: " & error))
    nil
  retFut

proc takeQueuedStream(connection: Connection): Opt[Stream] {.raises: [].} =
  try:
    Opt.some(connection.quicConn.incoming.getNoWait())
  except AsyncQueueEmptyError:
    Opt.none(Stream)

proc waitForIncomingStream(
    connection: Connection
): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
  let incomingFut = connection.quicConn.incomingStream()

  try:
    discard await race(incomingFut, connection.closedWaiter)
    if incomingFut.finished:
      return await incomingFut

    await incomingFut.cancelAndWait()
  except CancelledError as exc:
    if not incomingFut.finished:
      await incomingFut.cancelAndWait()
    raise exc

  let queued = connection.takeQueuedStream()
  if queued.isSome:
    return queued.get()

  raise newException(ConnectionClosedError, "connection closed")

proc incomingStream*(
    connection: Connection
): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
  if connection.quicConn.closedLocal:
    raise newException(ConnectionClosedError, "connection closed")

  let queued = connection.takeQueuedStream()
  let stream =
    if queued.isSome:
      queued.get()
    elif connection.isClosed:
      raise newException(ConnectionClosedError, "connection closed")
    else:
      await connection.waitForIncomingStream()
  stream.doProcess = proc(urgent: bool) {.gcsafe, raises: [].} =
    if urgent:
      connection.quicContext.processWhenReady()
    else:
      connection.quicContext.processSoon()
  stream

proc openStream*(
    connection: Connection
): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
  if connection.isClosed:
    raise newException(ConnectionClosedError, "connection closed")

  let available = connection.quicConn.takeAvailableStream()
  if available.isSome:
    return available.get()

  let s = Stream.new()
  s.doProcess = proc(urgent: bool) {.gcsafe, raises: [].} =
    if urgent:
      connection.quicContext.processWhenReady()
    else:
      connection.quicContext.processSoon()
  let created = connection.quicConn.addPendingStream(s)
  connection.quicContext.makeStream(connection.quicConn)
  connection.quicContext.processWhenReady()
  await created
  s

proc certificates*(conn: Connection): seq[seq[byte]] {.raises: [].} =
  conn.quicContext.certificates(conn.quicConn)

proc localAddress*(connection: Connection): TransportAddress {.raises: [].} =
  connection.local

proc remoteAddress*(connection: Connection): TransportAddress {.raises: [].} =
  ## Returns the current remote address while the connection is live, falling
  ## back to the last cached address after closure.
  if connection.quicConn.isNil or connection.quicConn.lsquicConn.isNil:
    return connection.remote

  var local, remote: ptr SockAddr
  if lsquic_conn_get_sockaddr(connection.quicConn.lsquicConn, addr local, addr remote) ==
      0 and not remote.isNil:
    connection.remote = remote.toTransportAddress()

  connection.remote

when defined(lsquic_testing):
  proc setCachedRemoteAddressForTest*(
      connection: Connection, remote: TransportAddress
  ) {.raises: [].} =
    connection.remote = remote
