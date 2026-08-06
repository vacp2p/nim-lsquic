# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/unittest2/asynctests, results
when defined(windows):
  from chronos/osdefs import SOL_SOCKET, SO_RCVBUF
else:
  from posix import SOL_SOCKET, SO_RCVBUF
import lsquic
import ./helpers/[address, clientserver, trackers]

proc socketReceiveBufferBytes(
    udp: DatagramTransport
): int {.raises: [TransportOsError].} =
  let res = getSockOpt2(udp.fd, int(SOL_SOCKET), int(SO_RCVBUF))
  if res.isErr():
    raiseTransportOsError(res.error())
  int(res.get())

proc ignoreDatagram(
    udp: DatagramTransport, remote: TransportAddress
) {.async: (raises: []).} =
  discard

suite "runtime":
  teardown:
    checkTrackers()

  asyncTest "init and cleanup are repeatable and leave a usable global":
    # start from a known-clean global regardless of prior state
    cleanupLsquic()

    for _ in 0 ..< 3:
      initializeLsquic(true, true)
      initializeLsquic(true, true) # second init is a no-op via the `initialized` guard
      cleanupLsquic()
      cleanupLsquic() # second cleanup is a safe no-op

    # after the repeated cycle a fresh init must leave a working stack:
    # QuicServer.listen builds a real lsquic engine
    initializeLsquic(true, true)
    let listener = QuicServer.new(makeTLSConfig()).listen(AutoAddressIP4)
    defer:
      await listener.stop()
      cleanupLsquic()

    check listener.localAddress().port != Port(0)

  test "per-role init flags are accepted":
    cleanupLsquic()
    initializeLsquic(client = true, server = false)
    cleanupLsquic()
    initializeLsquic(client = false, server = true)
    cleanupLsquic()

  asyncTest "default socket config creates endpoint with receive buffer":
    cleanupLsquic()
    initializeLsquic(true, true)
    let endpoint = QuicEndpoint.new(makeTLSConfig(), AutoAddressIP4)
    defer:
      await endpoint.stop()
      cleanupLsquic()

    check endpoint.datagramTransport().socketReceiveBufferBytes() > 0

  asyncTest "zero receive buffer keeps the OS default":
    cleanupLsquic()
    initializeLsquic(true, true)
    let unconfigured = newDatagramTransport(ignoreDatagram, local = AutoAddressIP4)
    let endpoint = QuicEndpoint.new(
      makeTLSConfig(),
      AutoAddressIP4,
      {CanListen, CanDial},
      QuicSocketConfig(receiveBufferBytes: 0),
    )
    defer:
      await endpoint.stop()
      await unconfigured.closeWait()
      cleanupLsquic()

    check endpoint.datagramTransport().socketReceiveBufferBytes() ==
      unconfigured.socketReceiveBufferBytes()

  asyncTest "socket receive buffer setting is readable":
    cleanupLsquic()
    initializeLsquic(true, true)
    const requested = 64 * 1024
    let endpoint = QuicEndpoint.new(
      makeTLSConfig(),
      AutoAddressIP4,
      {CanListen, CanDial},
      QuicSocketConfig(receiveBufferBytes: requested),
    )
    defer:
      await endpoint.stop()
      cleanupLsquic()

    check endpoint.datagramTransport().socketReceiveBufferBytes() >= requested

  test "negative socket receive buffer is rejected":
    expect QuicConfigError:
      discard QuicEndpoint.new(
        makeTLSConfig(),
        AutoAddressIP4,
        {CanListen, CanDial},
        QuicSocketConfig(receiveBufferBytes: -1),
      )

  test "negative server socket receive buffer is rejected":
    expect QuicConfigError:
      discard QuicServer.new(makeTLSConfig(), QuicSocketConfig(receiveBufferBytes: -1))
