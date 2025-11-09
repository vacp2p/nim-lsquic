import chronicles
import chronos
import ./[stream, tlsconfig, datagram, lsquic_ffi]
import ./context/[context, io]

logScope:
  topics = "quic connection"

type DialError* = object of IOError

type
  Connection* = ref object of RootObj
    local: TransportAddress
    remote: TransportAddress
    incoming*: AsyncQueue[Stream]
    ensureClosedFut: Future[void]
    isClosed: bool
    closed: AsyncEvent
    quicContext: QuicContext
    quicConn: QuicConnection

  IncomingConnection = ref object of Connection

  OutgoingConnection = ref object of Connection

proc ensureClosed(connection: Connection) {.async: (raises: [CancelledError]).} =
  await connection.closed.wait()
  echo "Closing connection"
  connection.incoming.clear()
  echo "TODO: close/reset streams"

proc close*(conn: Connection) {.raises: [].} =
  if conn.isClosed:
    return
  conn.isClosed = true
  conn.quicContext.close(conn.quicConn)

proc abort*(conn: Connection) {.gcsafe, raises: [].} =
  if conn.isClosed:
    return
  conn.isClosed = true
  conn.quicContext.abort(conn.quicConn)

proc newOutgoingConnection*(
    quicContext: QuicContext, local: TransportAddress, remote: TransportAddress
): OutgoingConnection =
  let conn = OutgoingConnection(
    quicContext: quicContext,
    quicConn: QuicClientConn(),
    local: local,
    remote: remote,
    incoming: newAsyncQueue[Stream](),
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
  let incoming = newAsyncQueue[Stream]()
  let conn = IncomingConnection(
    quicContext: quicContext,
    quicConn: serverConn,
    closed: newAsyncEvent(),
    incoming: incoming,
  )
  conn.ensureClosedFut = conn.ensureClosed()
  conn.quicConn.onClose = proc() {.raises: [].} =
    conn.closed.fire()
  conn

# proc handleNewStream(
#     connection: Connection,
#     streamFut: Future[Stream].Raising([CancelledError, QuicError]),
# ): Future[Stream] {.async: (raises: [CancelledError, QuicError]).} =
#   let closedFut = connection.closed.wait()
#   let raceFut = await race(streamFut, closedFut)
#   if raceFut == closedFut:
#     raise newException(QuicError, "connection closed")

# return await streamFut

proc incomingStream*(
    connection: Connection
): Future[Stream] {.async: (raises: [CancelledError]).} =
  #return await connection.handleNewStream(connection.quic.incomingStream())
  # TODO:
  discard

proc openStream*(
    connection: Connection, unidirectional = false
): Future[Stream] {.async: (raises: [CancelledError]).} =
  #return await connection.handleNewStream(connection.quic.openStream(unidirectional))
  # TODO:
  discard

proc certificates*(conn: Connection): seq[seq[byte]] {.raises: [].} =
  conn.quicContext.certificates(conn.quicConn)

proc localAddress*(connection: Connection): TransportAddress {.raises: [].} =
  connection.local

proc remoteAddress*(connection: Connection): TransportAddress {.raises: [].} =
  connection.remote
