import chronos
import chronos/osdefs
import chronicles
import
  ../[
    lsquic_ffi, tlsconfig, datagram, timeout, certificates, certificateverifier, stream
  ]

let SSL_CTX_ID = SSL_CTX_get_ex_new_index(0, nil, nil, nil, nil) # Yes, this is global
doAssert SSL_CTX_ID >= 0, "could not generate global ssl_ctx id"

type ConnectionError* = object of IOError

type QuicContext* = ref object of RootObj
  settings*: struct_lsquic_engine_settings
  api*: struct_lsquic_engine_api
  engine*: ptr struct_lsquic_engine
  stream_if*: struct_lsquic_stream_if
  tlsConfig*: TLSConfig
  outgoing*: AsyncQueue[Datagram]
  tickTimeout*: Timeout

type PendingStream = object
  stream: Stream
  created: Future[void].Raising([CancelledError, ConnectionError])

type QuicConnection* = ref object of RootObj
  local*: TransportAddress
  remote*: TransportAddress
  lsquicConn*: ptr lsquic_conn_t
  onClose*: proc() {.gcsafe, raises: [].}
  closedLocal*: bool
  closedRemote*: bool

type QuicServerConn* = ref object of QuicConnection
  incoming*: AsyncQueue[Stream]

type QuicClientConn* = ref object of QuicConnection
  connectedFut*: Future[void]
  pendingStreams: seq[PendingStream]

type ClientContext* = ref object of QuicContext

type ServerContext* = ref object of QuicContext
  incoming*: AsyncQueue[QuicServerConn]

method incomingStream*(
    quicConn: QuicConnection
): Future[Stream] {.base, async: (raises: [CancelledError]).} =
  raiseAssert "incoming streams not implemented"

method incomingStream*(
    quicConn: QuicServerConn
): Future[Stream] {.async: (raises: [CancelledError]).} =
  await quicConn.incoming.get()

method addPendingStream*(
    quicConn: QuicConnection, s: Stream
): Future[void].Raising([CancelledError, ConnectionError]) {.base, raises: [], gcsafe.} =
  raiseAssert "adding pending streams not implemented"

method addPendingStream*(
    quicConn: QuicClientConn, s: Stream
): Future[void].Raising([CancelledError, ConnectionError]) {.raises: [], gcsafe.} =
  let created = Future[void].Raising([CancelledError, ConnectionError]).init()
  quicConn.pendingStreams.add(PendingStream(stream: s, created: created))
  created

proc popPendingStream*(
    quicConn: QuicClientConn, stream: ptr lsquic_stream_t
): Opt[Stream] {.raises: [], gcsafe.} =
  if quicConn.pendingStreams.len == 0:
    debug "no pending streams!"
    return Opt.none(Stream)

  let pending = quicConn.pendingStreams.pop()
  pending.stream.quicStream = stream
  pending.created.complete()
  Opt.some(pending.stream)

proc cancelPending*(quicConn: QuicClientConn) =
  for pending in quicConn.pendingStreams:
    pending.created.fail(newException(ConnectionError, "can't open new streams"))

proc alpnSelectProtoCB(
    ssl: ptr SSL,
    outv: ptr ptr uint8,
    outlen: ptr uint8,
    inv: ptr uint8,
    inlen: cuint,
    userData: pointer,
): cint {.cdecl.} =
  let serverCtx = cast[ServerContext](userData)
  let alpnStr = serverCtx.tlsConfig.alpnStr()

  if (
    SSL_select_next_proto(
      outv,
      outlen,
      cast[ptr uint8](alpnStr.cstring),
      cast[cuint](alpnStr.len),
      inv,
      inlen,
    ) == OPENSSL_NPN_NEGOTIATED
  ):
    return SSL_TLSEXT_ERR_OK

  return SSL_TLSEXT_ERR_ALERT_FATAL

proc verifyCertificate(
    ssl: ptr SSL, out_alert: ptr uint8
): enum_ssl_verify_result_t {.cdecl.} =
  let sslCtx = SSL_get_SSL_CTX(ssl)

  let quicCtx = cast[QuicContext](SSL_CTX_get_ex_data(sslCtx, SSL_CTX_ID))
  if quicCtx.isNil:
    raiseAssert "could not obtain context"

  let derCertificates = getFullCertChain(ssl)

  let serverName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
  doAssert quicCtx.tlsConfig.certVerifier.isSome, "no custom validator set"
  if quicCtx.tlsConfig.certVerifier.get().verify($serverName, derCertificates):
    return ssl_verify_ok
  else:
    out_alert[] = SSL_AD_CERTIFICATE_UNKNOWN
    return ssl_verify_invalid

proc getSSLCtx*(peer_ctx: pointer, sockaddr: ptr SockAddr): ptr SSL_CTX {.cdecl.} =
  let quicCtx = cast[QuicContext](peer_ctx)

  let sslCtx = SSL_CTX_new(
    if quicCtx is ServerContext:
      TLS_server_method()
    else:
      TLS_client_method()
  )
  if sslCtx.isNil:
    error "failed to create SSL_CTX"
    return nil

  if SSL_CTX_set_ex_data(sslCtx, SSL_CTX_ID, peer_ctx) != 1:
    raiseAssert "could not set data in sslCtx"

  discard SSL_CTX_set_mode(sslCtx, SSL_MODE_RELEASE_BUFFERS)
  const ssl_opts =
    (SSL_OP_ALL and not SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) or SSL_OP_SINGLE_ECDH_USE or
    SSL_OP_CIPHER_SERVER_PREFERENCE
  discard SSL_CTX_set_options(sslCtx, uint32(ssl_opts))

  if quicCtx.tlsConfig.key.len != 0 and quicCtx.tlsConfig.certificate.len != 0:
    let pkey = quicCtx.tlsConfig.key.toPKey().valueOr:
      raiseAssert "could not convert certificate to pkey: " & error

    let cert = quicCtx.tlsConfig.certificate.toX509().valueOr:
      raiseAssert "could not convert certificate to x509: " & error

    defer:
      X509_free(cert)
      EVP_PKEY_free(pkey)

    if SSL_CTX_use_certificate(sslCtx, cert) != 1:
      raiseAssert "could not use certificate"

    if SSL_CTX_use_PrivateKey(sslCtx, pkey) != 1:
      raiseAssert "could not use private key"

    if SSL_CTX_check_private_key(sslCtx) != 1:
      raiseAssert "cant use private key with certificate"

  if (SSL_CTX_set1_sigalgs_list(sslCtx, "ed25519:ecdsa_secp256r1_sha256") != 1):
    raiseAssert "could not set supported algorithm list"

  if quicCtx.tlsConfig.certVerifier.isSome:
    SSL_CTX_set_custom_verify(
      sslCtx, SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verifyCertificate
    )

  if quicCtx of ServerContext:
    SSL_CTX_set_alpn_select_cb(sslCtx, alpnSelectProtoCB, peer_ctx)
  else:
    let alpnStr = quicCtx.tlsConfig.alpnStr()
    if SSL_CTX_set_alpn_protos(
      sslCtx, cast[ptr uint8](alpnStr.cstring), cast[cuint](alpnStr.len)
    ) != 0:
      raiseAssert "can't set client alpn"

  discard SSL_CTX_set_min_proto_version(sslCtx, TLS1_3_VERSION)
  discard SSL_CTX_set_max_proto_version(sslCtx, TLS1_3_VERSION)

  sslCtx

proc close*(ctx: QuicContext, conn: QuicConnection) =
  lsquic_conn_close(conn.lsquicConn)

proc abort*(ctx: QuicContext, conn: QuicConnection) =
  lsquic_conn_abort(conn.lsquicConn)

proc certificates*(ctx: QuicContext, conn: QuicConnection): seq[seq[byte]] =
  let x509chain = lsquic_conn_get_full_cert_chain(conn.lsquicConn)
  let ret = x509chain.getCertChain()
  OPENSSL_sk_free(cast[ptr OPENSSL_STACK](x509chain))
  ret

method dial*(
    ctx: QuicContext,
    local: TransportAddress,
    remote: TransportAddress,
    connectedFut: Future[void],
): Result[QuicConnection, string] {.base, gcsafe, raises: [].} =
  raiseAssert "dial not implemented"

method makeStream*(
    ctx: QuicContext, quicConn: QuicConnection
) {.base, gcsafe, raises: [].} =
  raiseAssert "makeStream not implemented"
