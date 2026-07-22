# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests, results, chronicles
import lsquic
import ./helpers/[address, certificate, clientserver]

trace "chronicles has to be imported to fix Error: undeclared identifier: 'activeChroniclesStream'"

initializeLsquic(true, true)

type RejectVerifierRecorder = ref object
  rejectCount: int
  fired: AsyncEvent

type VerifierRecorder = ref object
  count: int
  fired: AsyncEvent

proc acceptingCertificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  discard serverName
  derCertificates.len > 0

proc rejectingCertificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  discard serverName
  discard derCertificates
  false

proc raisingCertificateCb(
    serverName: string, derCertificates: seq[seq[byte]]
): bool {.gcsafe.} =
  discard serverName
  discard derCertificates
  raise newException(ValueError, "verifier failed")

proc makeRejectingCertificateCb(
    recorder: RejectVerifierRecorder
): certificateVerifierCB =
  return proc(_: string, _: seq[seq[byte]]): bool {.gcsafe.} =
    inc recorder.rejectCount
    recorder.fired.fire()
    false

proc makeCertificateCb(
    recorder: VerifierRecorder, accepted: bool
): certificateVerifierCB =
  return proc(_: string, derCertificates: seq[seq[byte]]): bool {.gcsafe.} =
    inc recorder.count
    recorder.fired.fire()
    if accepted:
      derCertificates.len > 0
    else:
      false

proc makeClientWithoutVerifier(): QuicClient {.raises: [QuicConfigError].} =
  QuicClient.new(
    TLSConfig.new(
      certificate = testCertificate(), key = testPrivateKey(), alpn = makeAlpn()
    )
  )

suite "certificate verifier":
  asyncTest "accepting custom verifier allows handshake":
    let client = makeClient(CustomCertificateVerifier.init(acceptingCertificateCb))
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(listener.localAddress())
    let incoming = await accepting

    check:
      outgoing.certificates().len == 1
      incoming.certificates().len == 1

    outgoing.close()
    incoming.close()

  asyncTest "rejecting client verifier rejects handshake":
    let client = makeClient(CustomCertificateVerifier.init(rejectingCertificateCb))
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    expect DialError:
      discard await client.dial(listener.localAddress())

  asyncTest "per-dial accepting verifier overrides rejecting default":
    let client = makeClient(CustomCertificateVerifier.init(rejectingCertificateCb))
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(
      listener.localAddress(), CustomCertificateVerifier.init(acceptingCertificateCb)
    )
    let incoming = await accepting

    check:
      outgoing.certificates().len == 1
      incoming.certificates().len == 1

    outgoing.close()
    incoming.close()

  asyncTest "per-dial rejecting verifier overrides accepting default":
    let client = makeClient(CustomCertificateVerifier.init(acceptingCertificateCb))
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    expect DialError:
      discard await client.dial(
        listener.localAddress(), CustomCertificateVerifier.init(rejectingCertificateCb)
      )

  asyncTest "per-dial verifier works without default verifier":
    let client = makeClientWithoutVerifier()
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(
      listener.localAddress(), CustomCertificateVerifier.init(acceptingCertificateCb)
    )
    let incoming = await accepting

    check:
      outgoing.certificates().len == 1
      incoming.certificates().len == 1

    outgoing.close()
    incoming.close()

  asyncTest "dial without default or per-dial verifier fails fast":
    let client = makeClientWithoutVerifier()
    defer:
      await client.stop()

    expect QuicError:
      discard await client.dial(AutoAddressIP4)

  asyncTest "concurrent per-dial verifiers stay isolated":
    let client = makeClientWithoutVerifier()
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let okListener = server.listen(AutoAddressIP4)
    let rejectListener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), okListener.stop(), rejectListener.stop())

    let okRecorder = VerifierRecorder(fired: newAsyncEvent())
    let rejectRecorder = VerifierRecorder(fired: newAsyncEvent())
    let accepting = okListener.accept()
    let okDial = client.dial(
      okListener.localAddress(),
      CustomCertificateVerifier.init(okRecorder.makeCertificateCb(true)),
    )
    let rejectDial = client.dial(
      rejectListener.localAddress(),
      CustomCertificateVerifier.init(rejectRecorder.makeCertificateCb(false)),
    )

    let outgoing = await okDial
    let incoming = await accepting
    expect DialError:
      discard await rejectDial

    check:
      outgoing.certificates().len == 1
      incoming.certificates().len == 1
      okRecorder.count == 1
      rejectRecorder.count == 1

    outgoing.close()
    incoming.close()

  asyncTest "raising client verifier rejects handshake":
    let client = makeClient(CustomCertificateVerifier.init(raisingCertificateCb))
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    expect DialError:
      discard await client.dial(listener.localAddress())

  asyncTest "alpn mismatch rejects handshake":
    let client = makeClient(
      CustomCertificateVerifier.init(acceptingCertificateCb), makeAlpn("client-proto")
    )
    let server = makeServer(
      CustomCertificateVerifier.init(acceptingCertificateCb), makeAlpn("server-proto")
    )
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    expect DialError:
      discard await client.dial(listener.localAddress())

  asyncTest "server-side verifier callback does not fail handshake without client auth":
    let recorder = RejectVerifierRecorder(fired: newAsyncEvent())
    let client = makeClient(CustomCertificateVerifier.init(acceptingCertificateCb))
    let server =
      makeServer(CustomCertificateVerifier.init(recorder.makeRejectingCertificateCb()))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let outgoing = await client.dial(listener.localAddress())
    check (await recorder.fired.wait().withTimeout(2.seconds))

    check:
      outgoing.certificates().len == 1
      recorder.rejectCount == 1

    outgoing.close()

  asyncTest "insecure verifier allows handshake":
    let client = makeClient(InsecureCertificateVerifier.init())
    let server = makeServer(CustomCertificateVerifier.init(acceptingCertificateCb))
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(listener.localAddress())
    let incoming = await accepting

    check:
      outgoing.certificates().len == 1
      incoming.certificates().len == 1

    outgoing.close()
    incoming.close()
