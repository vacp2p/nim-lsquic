import chronicles
import chronos
import ./[stream, tlsconfig, datagram, lsquic_ffi]
import ./context/[context, io]

logScope:
  topics = "quic connection"

export ConnectionError

type DialError* = object of IOError

type
  Connection* = ref object of RootObj
    local: TransportAddress
    remote: TransportAddress
    ensureClosedFut: Future[void]
    isClosed: bool
    closed: AsyncEvent
    quicContext: QuicContext
    quicConn: QuicConnection

  IncomingConnection = ref object of Connection

  OutgoingConnection = ref object of Connection

proc ensureClosed(connection: Connection) {.async: (raises: [CancelledError]).} =
  await connection.closed.wait()
  debug "Closing connection"
  if not connection.quicConn.closedLocal:
    connection.quicConn.closedRemote = true
  echo "TODO: reset streams?"

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

proc newOutgoingConnection*(
    quicContext: QuicContext, local: TransportAddress, remote: TransportAddress
): OutgoingConnection =
  let conn = OutgoingConnection(
    quicContext: quicContext,
    quicConn: QuicClientConn(),
    local: local,
    remote: remote,
    closed: newAsyncEvent(),
  )
  conn.ensureClosedFut = conn.ensureClosed()
  conn.quicConn.onClose = proc() {.raises: [].} =
    conn.closed.fire()
  conn

proc receive*(connection: Connection, datagram: sink Datagram) =
  connection.quicContext.receive(datagram, connection.local, connection.remote)

proc dial*(
    connection: OutgoingConnection
) {.async: (raw: true, raises: [CancelledError, DialError]).} =
  let retFut = newFuture[void]()
  connection.quicConn = connection.quicContext.dial(
    connection.local, connection.remote, retFut
  ).valueOr:
    retFut.fail(newException(DialError, "could not dial: " & error))
    nil
  connection.quicConn.onClose = proc() {.raises: [].} =
    connection.closed.fire()
  retFut

proc newIncomingConnection*(
    tlsConfig: TLSConfig, quicContext: QuicContext, serverConn: QuicServerConn
): Connection =
  let conn = IncomingConnection(
    quicContext: quicContext, quicConn: serverConn, closed: newAsyncEvent()
  )
  conn.ensureClosedFut = conn.ensureClosed()
  conn.quicConn.onClose = proc() {.raises: [].} =
    conn.closed.fire()
  conn

method incomingStream*(
    connection: Connection
): Future[Stream] {.base, async: (raises: [CancelledError, ConnectionError]).} =
  raiseAssert "incomingStream not implemented"

method incomingStream*(
    connection: IncomingConnection
): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
  let closedFut = connection.closed.wait()
  let incomingFut = connection.quicConn.incomingStream()
  let raceFut = await race(closedFut, incomingFut)
  if raceFut == closedFut:
    await incomingFut.cancelAndWait()
    raise newException(ConnectionError, "connection is closed")
  let stream = await incomingFut
  stream

method openStream*(
    connection: Connection
): Future[Stream] {.base, async: (raises: [CancelledError, ConnectionError]).} =
  raiseAssert "openStream not implemented"

method openStream*(
    connection: OutgoingConnection
): Future[Stream] {.async: (raises: [CancelledError, ConnectionError]).} =
  let s = Stream()
  let created = connection.quicConn.addPendingStream(s)
  connection.quicContext.makeStream(connection.quicConn)
  await created
  s

proc certificates*(conn: Connection): seq[seq[byte]] {.raises: [].} =
  conn.quicContext.certificates(conn.quicConn)

proc localAddress*(connection: Connection): TransportAddress {.raises: [].} =
  connection.local

proc remoteAddress*(connection: Connection): TransportAddress {.raises: [].} =
  connection.remote
