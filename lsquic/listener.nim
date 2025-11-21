import chronicles
import chronos
import chronos/osdefs
import results
import ./[connection, tlsconfig, datagram, connectionmanager]
import ./context/[server, context, io]

export stop

type Listener* = ref object of ConnectionManager
  incoming: AsyncQueue[QuicConnection]

proc newListener*(
    tlsConfig: TLSConfig, address: TransportAddress
): Result[Listener, string] =
  let incoming = newAsyncQueue[QuicConnection]()
  var quicContext: ServerContext
  let listener = Listener(incoming: incoming)

  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      let datagram = Datagram(data: udp.getMessage())
      listener.quicContext.receive(datagram, udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpect transport error", errorMsg = e.msg

  let dtp = newDatagramTransport(onReceive, local = address)
  quicContext = ?ServerContext.new(tlsConfig, incoming, dtp)

  listener.init(tlsConfig, quicContext)
  ok(listener)

proc waitForIncoming(
    listener: Listener
): Future[QuicConnection] {.async: (raises: [CancelledError]).} =
  await listener.incoming.get()

proc accept*(
    listener: Listener
): Future[Connection] {.async: (raises: [CancelledError, TransportError]).} =
  let
    incomingFut = listener.waitForIncoming()
    closedFut = listener.closed
    raceFut = await race(closedFut, incomingFut)

  if raceFut == closedFut:
    await incomingFut.cancelAndWait()
    raise newException(TransportError, "listener is stopped")

  let quicConn = await incomingFut
  let conn = newIncomingConnection(listener.tlsConfig, listener.quicContext, quicConn)
  listener.addConnection(conn)
  conn

proc localAddress*(
    listener: Listener
): TransportAddress {.raises: [TransportOsError].} =
  listener.quicContext.dtp.localAddress()
