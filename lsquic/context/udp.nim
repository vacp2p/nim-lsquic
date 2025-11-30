import chronos
import net
import ../helpers/async_loop

const bufferSize = 1024

type OnReceive* =
  proc(remote: TransportAddress, datagram: sink seq[byte]) {.async: (raises: []).}

type UDP* = ref object of RootObj
  local*: TransportAddress
  sock*: Socket
  onReceive*: OnReceive
  loop: Future[void]

proc localAddress*(u: UDP): TransportAddress {.raises: [].} =
  try:
    let (address, port) = u.sock.getLocalAddr()
    return initTAddress(address, port)
  except CatchableError as e:
    raiseAssert "should not happen" & e.msg

proc start*(u: UDP) {.raises: [].} =
  try:
    u.sock.bindAddr(address = $u.local.host, port = u.local.port)
  except CatchableError as e:
    raiseAssert "should not happen" & e.msg

  echo "Started at local addres ", u.localAddress()

  proc read() {.async: (raises: [CancelledError]).} =
    var buffer = newString(bufferSize)
    var srcAddr: string
    var srcPort: Port
    
    echo "reading"

    try:
      let msgLen = u.sock.recvFrom(buffer, bufferSize, srcAddr, srcPort)
      let msg = cast[seq[byte]](buffer[0 ..< msgLen])
      let remoteAddr = initTAddress(srcAddr, srcPort)
      echo "Received from ", srcAddr, ": ", msg
      await u.onReceive(remoteAddr, msg)
    except CatchableError as e:
      raiseAssert "should not happen" & e.msg
    
    echo "readin end"

  u.loop = asyncLoop(read)

proc closeWait*(u: UDP) {.async: (raises: [CancelledError]).} =
  await u.loop.cancelAndWait()
  u.sock.close()

proc sendTo*(u: UDP, sockAddr: TransportAddress, datagram: sink seq[byte]) =
  echo "sending"
  if datagram.len == 0:
    return

  let dataStr = cast[string](datagram)
  u.sock.sendTo($sockAddr.host, sockAddr.port, dataStr)