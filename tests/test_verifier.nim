# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests, results
import lsquic
import ./helpers/[address, certificate, clientserver, trackers]

initializeLsquic(true, true)

const dialTimeout = 5.seconds

type RejectVerifierRecorder = ref object
  rejectCount: int
  fired: AsyncEvent

type VerifierRecorder = ref object
  count: int
  fired: AsyncEvent
  serverNames: seq[string]

type ServerNameRecorder = ref object
  serverName: string
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
  return proc(serverName: string, derCertificates: seq[seq[byte]]): bool {.gcsafe.} =
    inc recorder.count
    recorder.serverNames.add(serverName)
    recorder.fired.fire()
    if accepted:
      derCertificates.len > 0
    else:
      false

proc makeRecordingCertificateCb(recorder: ServerNameRecorder): certificateVerifierCB =
  return proc(serverName: string, _: seq[seq[byte]]): bool {.gcsafe.} =
    recorder.serverName = serverName
    inc recorder.count
    recorder.fired.fire()
    true

proc makeClientWithoutVerifier(): QuicClient {.raises: [QuicConfigError].} =
  QuicClient.new(
    TLSConfig.new(
      certificate = testCertificate(), key = testPrivateKey(), alpn = makeAlpn()
    )
  )

suite "certificate verifier":
  teardown:
    checkTrackers()

  test "base verifier requires an override":
    # Guard for a subtype that forgets to implement verify: it must raise
    # rather than silently accept or reject a peer.
    let verifier = CertificateVerifier()

    expect AssertionDefect:
      discard verifier.verify("example.com", @[])

  test "custom verifier requires a callback":
    let verifier = CustomCertificateVerifier.init(nil)

    expect AssertionDefect:
      discard verifier.verify("example.com", @[])

  test "insecure verifier accepts any input":
    let verifier = InsecureCertificateVerifier.init()

    check:
      verifier.verify("example.com", @[testCertificate()])
      # a server verifying a client that sent no certificate sees an empty chain
      verifier.verify("", @[])

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

  asyncTest "verifier receives an empty server name without explicit SNI":
    let clientRecorder = ServerNameRecorder(fired: newAsyncEvent())
    let serverRecorder = ServerNameRecorder(fired: newAsyncEvent())
    let client = makeClient(
      CustomCertificateVerifier.init(clientRecorder.makeRecordingCertificateCb())
    )
    let server = makeServer(
      CustomCertificateVerifier.init(serverRecorder.makeRecordingCertificateCb())
    )
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(listener.localAddress())
    let incoming = await accepting
    check (await serverRecorder.fired.wait().withTimeout(2.seconds))

    check:
      clientRecorder.count == 1
      clientRecorder.serverName == ""
      serverRecorder.count == 1
      serverRecorder.serverName == ""

    outgoing.close()
    incoming.close()

  asyncTest "dial hostname is sent as SNI and reaches both verifiers":
    let clientRecorder = VerifierRecorder(fired: newAsyncEvent())
    let serverRecorder = VerifierRecorder(fired: newAsyncEvent())
    let client = makeClient(
      CustomCertificateVerifier.init(clientRecorder.makeCertificateCb(true))
    )
    let server = makeServer(
      CustomCertificateVerifier.init(serverRecorder.makeCertificateCb(true))
    )
    let listener = server.listen(AutoAddressIP4)
    defer:
      await allFutures(client.stop(), listener.stop())

    let accepting = listener.accept()
    let outgoing = await client.dial(listener.localAddress(), "example.com")
    let incoming = await accepting

    check:
      clientRecorder.serverNames == @["example.com"]
      serverRecorder.serverNames == @["example.com"]

    outgoing.close()
    incoming.close()

  asyncTest "explicit hostname rejects empty and embedded null values":
    let client = makeClient()
    defer:
      await client.stop()

    expect QuicError:
      discard await client.dial(AutoAddressIP4, "")
    expect QuicError:
      discard await client.dial(AutoAddressIP4, "example.com\0invalid")

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

  asyncTest "nil per-dial verifier does not fall back to the default":
    let client = makeClient(CustomCertificateVerifier.init(acceptingCertificateCb))
    defer:
      await client.stop()

    let noVerifier: CertificateVerifier = nil
    expect QuicError:
      discard await client.dial(AutoAddressIP4, noVerifier)

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
      discard await client.dial(listener.localAddress()).wait(dialTimeout)

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
