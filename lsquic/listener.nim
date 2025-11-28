import chronicles
import chronos
import chronos/osdefs
import results
import ./[connection, tlsconfig, connectionmanager]
import ./context/[server, context, io, udp]
import net

export stop

type Listener* = ref object of ConnectionManager
  incoming: AsyncQueue[QuicConnection]

proc newListener*(
    tlsConfig: TLSConfig, address: TransportAddress
): Result[Listener, string] {.raises:[].} =
  let incoming = newAsyncQueue[QuicConnection]()
  var quicContext: ServerContext
  let listener = Listener(incoming: incoming)

  proc onReceive(
      remote: TransportAddress, data: sink seq[byte]
  ) {.gcsafe, async: (raises: []).} =
    listener.quicContext.receive(remote, data)

  let udp =
    try:
      let sock = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
      UDP(sock: sock, onReceive: onReceive, local: address)
    except OSError as e:
      return err(e.msg)

  udp.start()
  quicContext = ?ServerContext.new(tlsConfig, incoming, udp)

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
  listener.quicContext.udp.localAddress()
