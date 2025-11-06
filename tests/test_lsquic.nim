import unittest
import lsquic_ffi
import boringssl

test "BoringSSL bindings":
  let
    clientMethod = TLS_client_method()
    ssl_ctx = SSL_CTX_new(clientMethod)
    ssl = SSL_new(ssl_ctx)

  check ssl != nil

test "lsquic bindings":
    check lsquic_global_init(LSQUIC_GLOBAL_CLIENT or LSQUIC_GLOBAL_SERVER) == 0
    