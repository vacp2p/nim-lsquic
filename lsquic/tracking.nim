# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Pinning for objects handed across the lsquic FFI boundary:
## `pin` - keeps a heap object alive while C holds a raw pointer to it
## `unpin` - releases it once C is done, an engine `on_close`/`on_conn_closed` callback,
##  or a local cleanup path (cancelled pending stream, failed dial).
##
## Under `-d:lsquic_testing`, pin/unpin also tracks the objects.

when defined(lsquic_testing):
  import std/typetraits
  import chronos

template pin*[T](obj: T) =
  GC_ref(obj)
  when defined(lsquic_testing):
    trackCounter(typetraits.name(T))

template unpin*[T](obj: T) =
  when defined(lsquic_testing):
    untrackCounter(typetraits.name(T))
  GC_unref(obj)
