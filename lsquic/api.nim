import std/sets
import chronos
import chronicles
import results
import ./[listener, connection, tlsconfig, datagram, connectionmanager]
import ./context/[context, io, client, udp]
import lsquic_ffi
import net

type Quic = ref object of RootObj

type QuicClient* = ref object of Quic
  connman: ConnectionManager

type QuicServer* = ref object of Quic
  tlsConfig: TLSConfig

type QuicError* = object of CatchableError

var initialized: bool

proc initializeLsquic*(client: bool = true, server: bool = true) =
  if initialized:
    return

  initialized = true
  var flags = 0.cint
  if client:
    flags = flags or LSQUIC_GLOBAL_CLIENT
  if server:
    flags = flags or LSQUIC_GLOBAL_SERVER

  if lsquic_global_init(flags) != 0:
    raiseAssert "lsquic initialization failed"

proc new*(
    t: typedesc[QuicServer], tlsConfig: TLSConfig
): QuicServer {.raises: [QuicConfigError].} =
  if tlsConfig.certificate.len == 0:
    raise newException(QuicConfigError, "tlsConfig does not contain a certificate")

  return QuicServer(tlsConfig: tlsConfig)

proc listen*(
    self: QuicServer, address: TransportAddress
): Listener {.raises: [QuicError, TransportOsError].} =
  newListener(self.tlsConfig, address).valueOr:
    raise newException(QuicError, error)

proc new*(
    t: typedesc[QuicClient], tlsConfig: TLSConfig
): QuicClient {.raises: [QuicError, TransportOsError].} =
  var clientCtx: ClientContext

  proc onReceive(
      remote: TransportAddress, data: sink seq[byte]
  ) {.async: (raises: []).} =
    clientCtx.receive(remote, data)

  let udp =
    try:
      let sock = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
      UDP(sock: sock, onReceive: onReceive)
    except OSError as e:
      raise newException(QuicError, e.msg)
  
  udp.start()
  clientCtx = ClientContext.new(tlsConfig, udp).valueOr:
    raise newException(QuicError, error)

  let client = QuicClient(connman: ConnectionManager.new(tlsConfig, clientCtx))
  client

proc dial*(
    self: QuicClient, address: TransportAddress
): Future[Connection] {.async: (raises: [CancelledError, DialError, TransportOsError]).} =
  var connection = newOutgoingConnection(
    self.connman.quicContext, self.connman.quicContext.udp.localAddress(), address
  )
  self.connman.addConnection(connection)
  await connection.dial()
  connection

proc stop*(self: QuicClient) {.async: (raises: [CancelledError]).} =
  await self.connman.stop()
