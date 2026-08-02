# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import chronos/osdefs
import results
import ../lsquic_ffi

proc sockAddrLen*(family: int): Opt[SockLen] {.inline.} =
  ## `none` for any family other than AF_INET/AF_INET6. Every caller runs in a
  ## `{.raises: [].}` receive callback or a `{.cdecl.}` callback invoked by
  ## lsquic, so a Defect here would abort the process rather than be handled.
  case family
  of AF_INET.int:
    Opt.some(sizeof(Sockaddr_in).SockLen)
  of AF_INET6.int:
    Opt.some(sizeof(Sockaddr_in6).SockLen)
  else:
    Opt.none(SockLen)

proc toTransportAddress*(sock: ptr SockAddr): Opt[TransportAddress] =
  let destAddrLen = ?sockAddrLen(sock.sa_family.int)
  var destAddress: Sockaddr_storage
  copyMem(addr destAddress, sock, destAddrLen)
  var taddr: TransportAddress
  fromSAddr(addr destAddress, destAddrLen, taddr)
  Opt.some(taddr)
