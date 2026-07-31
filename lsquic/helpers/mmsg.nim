# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Shared `struct mmsghdr` wiring for the batched send and receive paths.
##
## glibc hides both calls behind `__USE_GNU`, so `_GNU_SOURCE` belongs next to
## the declarations rather than being inherited from whichever module happens
## to be in the import graph.

when defined(linux):
  import std/posix

  {.passc: "-D_GNU_SOURCE".}

  type MMsgHdr* {.importc: "struct mmsghdr", header: "<sys/socket.h>", bycopy.} = object
    msg_hdr*: Tmsghdr
    msg_len*: cuint

  proc sendmmsg*(
    sockfd: SocketHandle, msgvec: ptr MMsgHdr, vlen: cuint, flags: cint
  ): cint {.importc, header: "<sys/socket.h>".}

  proc recvmmsg*(
    sockfd: SocketHandle,
    msgvec: ptr MMsgHdr,
    vlen: cuint,
    flags: cint,
    timeout: pointer,
  ): cint {.importc, header: "<sys/socket.h>".}
