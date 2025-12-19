import chronicles
import chronos
import chronos/osdefs
import results
import ./[connection, tlsconfig, datagram, connectionmanager]
import ./context/[server, context, io]

export stop

type Listener* = ref object of RootObj
  quicContext: ServerContext
  connman: ConnectionManager
  udp: DatagramTransport
  tlsConfig: TLSConfig

proc newListener*(
    tlsConfig: TLSConfig, address: TransportAddress
): Result[Listener, string] =
  let quicContext = ?ServerContext.new(tlsConfig)

  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      let datagram = Datagram(data: udp.getMessage())
      quicContext.receive(datagram, udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpect transport error", errorMsg = e.msg

  let listener = Listener(
    tlsConfig: tlsConfig,
    quicContext: quicContext,
    connman: ConnectionManager.new(),
    udp: newDatagramTransport(onReceive, local = address),
  )
  quicContext.fd = cint(listener.udp.fd)

  ok(listener)

proc waitForIncoming(
    listener: Listener
): Future[QuicConnection] {.async: (raises: [CancelledError]).} =
  await listener.quicContext.incoming.get()

proc accept*(
    listener: Listener
): Future[Connection] {.async: (raises: [CancelledError, TransportError]).} =
  let
    incomingFut = listener.waitForIncoming()
    closedFut = listener.connman.closed
    raceFut = await race(closedFut, incomingFut)

  if raceFut == closedFut:
    await incomingFut.cancelAndWait()
    raise newException(TransportError, "listener is stopped")

  let quicConn = await incomingFut
  let conn = newIncomingConnection(listener.tlsConfig, listener.quicContext, quicConn)
  listener.connman.addConnection(conn)
  conn

proc localAddress*(
    listener: Listener
): TransportAddress {.raises: [TransportOsError].} =
  listener.udp.localAddress()

proc stop*(listener: Listener) {.async: (raises: [CancelledError]).} =
  await noCancel listener.connman.stop()
  # Politely wait before closing udp so connections closure go out
  # TODO: this should be ~ 3 times the PTO.
  # Find out if it's possible to react to shutting down the context and
  # lsquic engine. Maybe there's a callback that one can hook to and safely
  # stop the udp transport.
  await noCancel sleepAsync(300.milliseconds)
  await noCancel listener.udp.closeWait()
