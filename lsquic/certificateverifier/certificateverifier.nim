# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

type CertificateVerifier* = ref object of RootObj

## `serverName` is the expected server identity on clients and the requested
## SNI value on servers; it is not the client's certificate identity.
method verify*(
    self: CertificateVerifier, serverName: string, derCertificates: seq[seq[byte]]
): bool {.base.} =
  raiseAssert "override method: verify"
