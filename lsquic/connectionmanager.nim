import chronicles
import chronos
import chronos/osdefs
import ./[connection, tlsconfig]
import ./context/context

type ConnectionManager* = ref object of RootObj
  tlsConfig*: TLSConfig
  udp*: DatagramTransport
  quicContext*: QuicContext
  connections: seq[Connection]
  loop*: Future[void]
  closed*: Future[void]

proc init*(
    c: ConnectionManager,
    tlsConfig: TLSConfig,
    udp: DatagramTransport,
    quicContext: QuicContext,
) =
  c.tlsConfig = tlsConfig
  c.quicContext = quicContext
  c.udp = udp
  c.quicContext = quicContext
  c.closed = newFuture[void]()

proc new*(
    T: typedesc[ConnectionManager],
    tlsConfig: TLSConfig,
    udp: DatagramTransport,
    quicContext: QuicContext,
): T =
  let ret = ConnectionManager()
  ret.init(tlsConfig, udp, quicContext)
  ret

proc localAddress*(
    connman: ConnectionManager
): TransportAddress {.raises: [TransportOsError].} =
  connman.udp.localAddress()

proc closeUdp*(connman: ConnectionManager) {.async: (raises: []).} =
  await connman.udp.closeWait()

proc stop*(connman: ConnectionManager) {.async: (raises: [CancelledError]).} =
  if connman.closed.finished:
    return

  connman.closed.complete()
  for conn in connman.connections:
    conn.abort()

  # Politely wait before closing udp so connections closure go out
  # TODO: this should be ~ 3 times the PTO.
  # Find out if it's possible to react to shutting down the context and
  # lsquic engine. Maybe there's a callback that one can hook to and safely
  # stop the udp transport.
  await noCancel sleepAsync(300.milliseconds)
  await noCancel connman.closeUdp()
  connman.quicContext.stop()

proc addConnection*(connman: ConnectionManager, conn: Connection) =
  connman.connections.add(conn)
