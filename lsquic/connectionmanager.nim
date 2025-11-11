import chronicles
import chronos
import chronos/osdefs
import results
import ./[connection, tlsconfig, datagram]
import ./helpers/asyncloop
import ./context/context

type ConnectionManager* = ref object of RootObj
  tlsConfig*: TLSConfig
  udp*: DatagramTransport
  quicContext*: QuicContext
  outgoing*: AsyncQueue[Datagram]
  connections: seq[Connection]
  loop*: Future[void]
  closed*: Future[void]

proc init*(
    c: ConnectionManager,
    tlsConfig: TLSConfig,
    udp: DatagramTransport,
    quicContext: QuicContext,
    outgoing: AsyncQueue[Datagram],
) =
  c.tlsConfig = tlsConfig
  c.quicContext = quicContext
  c.outgoing = outgoing
  c.udp = udp
  c.quicContext = quicContext
  c.closed = newFuture[void]()

proc new*(
    T: typedesc[ConnectionManager],
    tlsConfig: TLSConfig,
    udp: DatagramTransport,
    quicContext: QuicContext,
    outgoing: AsyncQueue[Datagram],
): T =
  let ret = ConnectionManager()
  ret.init(tlsConfig, udp, quicContext, outgoing)
  ret

proc localAddress*(
    connman: ConnectionManager
): TransportAddress {.raises: [TransportOsError].} =
  connman.udp.localAddress()

proc startSending*(connman: ConnectionManager) =
  trace "Starting sending loop"

  proc send() {.async: (raises: [CancelledError]).} =
    try:
      let datagram = await connman.outgoing.get()
      await connman.udp.sendTo(datagram.taddr, datagram.data)
    except TransportError as e:
      trace "Failed to send datagram", errorMsg = e.msg

  connman.loop = asyncLoop(send)

proc stopSending*(connman: ConnectionManager) {.async: (raises: [CancelledError]).} =
  await connman.loop.cancelAndWait()

proc closeUdp*(connman: ConnectionManager) {.async: (raises: []).} =
  await connman.udp.closeWait()

proc stop*(connman: ConnectionManager) {.async: (raises: [CancelledError]).} =
  if connman.closed.completed():
    return

  connman.closed.complete()
  for conn in connman.connections:
    conn.abort()
  await connman.stopSending()
  await connman.closeUdp()

proc addConnection*(connman: ConnectionManager, conn: Connection) =
  connman.connections.add(conn)
