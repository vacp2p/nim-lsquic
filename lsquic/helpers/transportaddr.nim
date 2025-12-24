# Nim-LibP2P
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos
import chronos/osdefs
import ../lsquic_ffi

proc toTransportAddress*(sock: ptr SockAddr): TransportAddress =
  var destAddress: Sockaddr_storage
  let destAddrLen: SockLen =
    case sock.sa_family.uint16
    of AF_INET.uint16:
      sizeof(Sockaddr_in).uint32
    of AF_INET6.uint16:
      sizeof(Sockaddr_in6).uint32
    else:
      0.uint32
  copyMem(addr destAddress, sock, destAddrLen)
  var taddr: TransportAddress
  fromSAddr(addr destAddress, destAddrLen, taddr)
  taddr
