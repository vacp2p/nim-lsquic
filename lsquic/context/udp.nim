import chronos
import net
import ../helpers/async_loop

const bufferSize = 1024

type OnReceive* = proc(remote: TransportAddress, datagram: sink seq[byte]) {.async: (raises: []).}

type UDP* = ref object of RootObj
  local*: TransportAddress
  sock*: Socket
  onReceive*: OnReceive
  loop: Future[void]

proc start*(u: UDP) {.raises: [].} =
  try:
    u.sock.bindAddr(address = $u.local.host, port = u.local.port)
  except CatchableError as e:
    discard

  proc read() {.async: (raises: [CancelledError]).} =
    var buffer = newString(bufferSize)
    # let (msgLen, remoteAddr) = u.sock.recvFrom(buffer, bufferSize, $u.local.host, u.local.port)
    # let bytes = cast[seq[byte]](buffer[0 ..< msgLen])
    # u.onReceive(remoteAddr, bytes)

  u.loop = asyncLoop(read)

proc closeWait*(u: UDP) {.async: (raises: [CancelledError]).} =
  await u.loop.cancelAndWait()
  u.sock.close()

proc sendTo*(u: UDP, sockAddr: TransportAddress, datagram: sink seq[byte]) =
  if datagram.len == 0:
    return

  let dataStr = cast[string](datagram)
  u.sock.sendTo($sockAddr.host, sockAddr.port, dataStr)

proc localAddress*(u: UDP): TransportAddress {.raises:[].} =
  var ip: string
  var port: Port
  # u.socket.getSockName(ip, port)
  return TransportAddress()
