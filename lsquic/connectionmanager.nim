import chronicles, sequtils
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
  outgoing*: ManyQueue[Datagram]
  connections: seq[Connection]
  loop*: Future[void]
  closed*: Future[void]

proc init*(
    c: ConnectionManager,
    tlsConfig: TLSConfig,
    udp: DatagramTransport,
    quicContext: QuicContext,
    outgoing: ManyQueue[Datagram],
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
    outgoing: ManyQueue[Datagram],
): T =
  let ret = ConnectionManager()
  ret.init(tlsConfig, udp, quicContext, outgoing)
  ret

proc localAddress*(
    connman: ConnectionManager
): TransportAddress {.raises: [TransportOsError].} =
  connman.udp.localAddress()

proc startSending*(connman: ConnectionManager) =
  debug "Starting sending loop"

  proc send() {.async: (raises: [CancelledError]).} =
    try:
      let datagrams = await connman.outgoing.get()

      # sendTo many datagrams at once
      #let req = datagrams.mapIt((it.taddr, it.data))
      #discard connman.udp.sendTo(req)

      for d in datagrams:
        await connman.udp.sendTo(d.taddr, d.data)
    except CancelledError as e:
      raise e
    except CatchableError as e:
      debug "Failed to send datagram", errorMsg = e.msg

  connman.loop = asyncLoop(send)

proc stopSending*(connman: ConnectionManager) {.async: (raises: [CancelledError]).} =
  await connman.loop.cancelAndWait()

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
  await noCancel connman.stopSending()
  await noCancel connman.closeUdp()
  connman.quicContext.stop()

proc addConnection*(connman: ConnectionManager, conn: Connection) =
  connman.connections.add(conn)
