import chronos
import chronicles

proc newDatagramTransport*(): DatagramTransport =
  proc onReceive(
      udp: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    discard

  newDatagramTransport(onReceive)

proc sendTo*(datagram: seq[byte], remote: TransportAddress) {.async.} =
  trace "Sending datagram", remote
  let udp = newDatagramTransport()
  await udp.sendTo(remote, datagram.toPtr, datagram.len)
  trace "Sent datagram", remote
  await udp.closeWait()
