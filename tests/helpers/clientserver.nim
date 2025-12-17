import results, std/sets
import chronos, chronicles
import lsquic/[api, tlsconfig, certificateverifier, lsquic_ffi]
import ./certificate

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'" 

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc makeClient*(): QuicClient {.raises: [QuicConfigError, QuicError, TransportOsError].} =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let clientTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicClient.new(clientTLSConfig)

proc makeServer*(): QuicServer  {.raises: [QuicConfigError].}=
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let serverTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["test"].toHashSet(),
    Opt.some(customCertVerif),
  )
  return QuicServer.new(serverTLSConfig)
