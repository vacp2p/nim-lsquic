# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

type
  QuicError* = object of CatchableError
  QuicConfigError* = object of QuicError
  StreamError* = object of IOError
  ConnectionError* = object of IOError
  ConnectionClosedError* = object of ConnectionError
  DialError* = object of IOError
