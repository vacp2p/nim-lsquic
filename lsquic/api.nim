import std/sets
import chronos
import chronicles
import results
import ./[listener, connection, tlsconfig, datagram, connectionmanager]
import ./context/[context, io, client]
import ./helpers/[many_queue]
import lsquic_ffi

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
  let outgoing = ManyQueue[Datagram].new()

  let clientCtx = ClientContext.new(tlsConfig, outgoing).valueOr:
    raise newException(QuicError, error)

  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    try:
      let datagram = Datagram(data: udp.getMessage())
      clientCtx.receive(datagram, udp.localAddress(), remote)
    except TransportError as e:
      error "Unexpected transport error", errorMsg = e.msg

  let datagramTransport = newDatagramTransport(onReceive)

  let client = QuicClient(
    connman: ConnectionManager.new(tlsConfig, datagramTransport, clientCtx, outgoing)
  )

  clientCtx.fd = cint(datagramTransport.fd)

  client.connman.startSending()
  client

proc dial*(
    self: QuicClient, address: TransportAddress
): Future[Connection] {.async: (raises: [CancelledError, DialError, TransportOsError]).} =
  var connection = newOutgoingConnection(
    self.connman.quicContext, self.connman.udp.localAddress, address
  )
  self.connman.addConnection(connection)
  await connection.dial()
  connection

proc stop*(self: QuicClient) {.async: (raises: [CancelledError]).} =
  await self.connman.stop()
