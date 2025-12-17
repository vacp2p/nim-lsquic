{.used.}

import chronos, chronos/unittest2/asynctests, results, std/sets, chronicles, net
import
  lsquic/[api, tlsconfig, connection, certificateverifier, lsquic_ffi]
import ./helpers/certificate

proc certificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  return derCertificates.len > 0

proc makeClient(): QuicClient =
  let customCertVerif: CertificateVerifier =
    CustomCertificateVerifier.init(certificateCb)
  let clientTLSConfig = TLSConfig.new(
    testCertificate(),
    testPrivateKey(),
    @["quic-echo-example"].toHashSet(),
    Opt.some(customCertVerif),
  )
  let client = QuicClient.new(clientTLSConfig)
  return client

initializeLsquic(true, true)

# quic.rocks:4433 (官方QUIC测试服务器) 
# quic.rocks:443 (标准HTTPS端口)
# www.google.com:443 (Google QUIC)
# www.cloudflare.com:443 (Cloudflare QUIC)
# quic.aiortc.org:443 (AIO RTC QUIC)
# http3-test.litespeedtech.com:443 (LiteSpeed HTTP/3) 
# nghttp2.org:443 (nghttp2 HTTP/3)

suite "Interop":
  asyncTest "client":
    let client = makeClient()
    let taseq = resolveTAddress("quic.rocks:4433")
    echo "===========", $taseq[0]
    let dialingFut = client.dial(taseq[0])
    let conn = await dialingFut

    check:
      conn.certificates().len == 1

    conn.close()


