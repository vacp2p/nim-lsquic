import results
import chronicles
import chronos
import chronos/osdefs
import ./[context, io, stream]
import ../[lsquic_ffi, tlsconfig, datagram, timeout]
import ../helpers/sequninit

proc onNewConn(
    stream_if_ctx: pointer, conn: ptr lsquic_conn_t
): ptr lsquic_conn_ctx_t {.cdecl.} =
  trace "New connection established: client"
  let conn_ctx = lsquic_conn_get_ctx(conn)
  cast[ptr lsquic_conn_ctx_t](conn_ctx)

proc onHandshakeDone(
    conn: ptr lsquic_conn_t, status: enum_lsquic_hsk_status
) {.cdecl.} =
  trace "Handshake done", status
  let conn_ctx = lsquic_conn_get_ctx(conn)
  if conn_ctx.isNil:
    debug "conn_ctx is nil in onHandshakeDone"
    return

  let quicClientConn = cast[QuicClientConn](conn_ctx)
  if quicClientConn.connectedFut.completed():
    return

  if status == LSQ_HSK_FAIL or status == LSQ_HSK_RESUMED_FAIL:
    quicClientConn.connectedFut.fail(
      newException(ConnectionError, "could not connect to server. Handshake failed")
    )
  else:
    quicClientConn.connectedFut.complete()

proc onConnClosed(conn: ptr lsquic_conn_t) {.cdecl.} =
  trace "Connection closed: client"
  let conn_ctx = lsquic_conn_get_ctx(conn)
  if not conn_ctx.isNil:
    let quicClientConn = cast[QuicClientConn](conn_ctx)
    if not quicClientConn.connectedFut.completed():
      # Not connected yet
      var buf: array[256, char]
      let connStatus =
        lsquic_conn_status(conn, cast[cstring](addr buf[0]), buf.len.csize_t)
      let msg = $cast[cstring](addr buf[0])
      quicClientConn.connectedFut.fail(
        newException(
          ConnectionError,
          "could not connect to server. Status: " & $connStatus & ". " & msg,
        )
      )
    quicClientConn.cancelPending()
    quicClientConn.onClose()
  lsquic_conn_set_ctx(conn, nil)

proc onNewStream(
    stream_if_ctx: pointer, stream: ptr lsquic_stream_t
): ptr lsquic_stream_ctx_t {.cdecl.} =
  trace "New stream created: client"
  let conn = lsquic_stream_conn(stream)
  let conn_ctx = lsquic_conn_get_ctx(conn)
  if conn_ctx.isNil:
    debug "conn_ctx is nil in onNewStream"
    return nil

  let quicConn = cast[QuicClientConn](conn_ctx)
  let streamCtx = quicConn.popPendingStream(stream).valueOr:
    return

  # Clients have to write first
  discard lsquic_stream_wantread(stream, 0)
  discard lsquic_stream_wantwrite(stream, 1)
  return cast[ptr lsquic_stream_ctx_t](streamCtx)

proc onWrite(stream: ptr lsquic_stream_t, ctx: ptr lsquic_stream_ctx_t) {.cdecl.} =
  #trace "onWrite: client"
  #let msg = "hello".cstring
  #discard lsquic_stream_write(stream, msg, msg.len.csize_t)
  #discard lsquic_stream_flush(stream)
  discard lsquic_stream_wantwrite(stream, 0)

method dial*(
    ctx: ClientContext,
    local: TransportAddress,
    remote: TransportAddress,
    connectedFut: Future[void],
): Result[QuicConnection, string] {.raises: [], gcsafe.} =
  var
    localAddress: Sockaddr_storage
    localAddrLen: SockLen
    remoteAddress: Sockaddr_storage
    remoteAddrLen: SockLen

  local.toSAddr(localAddress, localAddrLen)
  remote.toSAddr(remoteAddress, remoteAddrLen)

  let quicClientConn =
    QuicClientConn(connectedFut: connectedFut, local: local, remote: remote)

  let conn = lsquic_engine_connect(
    ctx.engine,
    N_LSQVER,
    cast[ptr SockAddr](addr localAddress),
    cast[ptr SockAddr](addr remoteAddress),
    cast[pointer](ctx),
    cast[ptr lsquic_conn_ctx_t](quicClientConn),
    nil,
    0,
    nil,
    0,
    nil,
    0,
  )
  if conn.isNil:
    return err("could not dial: " & $remote)

  quicClientConn.lsquicConn = conn

  ok(quicClientConn)

proc new*(
    T: typedesc[ClientContext], tlsConfig: TLSConfig, outgoing: AsyncQueue[Datagram]
): Result[T, string] =
  if lsquic_global_init(LSQUIC_GLOBAL_CLIENT) != 0:
    return err("lsquic initialization failed")

  var ctx = ClientContext()
  ctx.tlsConfig = tlsConfig
  ctx.outgoing = outgoing
  lsquic_engine_init_settings(addr ctx.settings, 0)
  ctx.settings.es_versions = 1.cuint shl LSQVER_I001.cuint #IETF QUIC v1
  ctx.stream_if = struct_lsquic_stream_if(
    on_new_conn: onNewConn,
    on_hsk_done: onHandshakeDone,
    on_conn_closed: onConnClosed,
    on_new_stream: onNewStream,
    on_read: onRead,
    on_write: onWrite,
    on_close: onClose,
  )
  ctx.api = struct_lsquic_engine_api(
    ea_settings: addr ctx.settings,
    ea_stream_if_ctx: cast[pointer](ctx),
    ea_packets_out_ctx: cast[pointer](ctx),
    ea_stream_if: addr ctx.stream_if,
    ea_get_ssl_ctx: getSSLCtx,
    ea_packets_out: sendPacketsOut,
  )

  ctx.engine = lsquic_engine_new(0, addr ctx.api)
  if ctx.engine.isNil:
    return err("failed to create lsquic engine")

  ctx.tickTimeout = newTimeout(
    proc() =
      var diff: cint
      let connsToProcess = lsquic_engine_earliest_adv_tick(ctx.engine, addr diff)
      if connsToProcess == 1:
        lsquic_engine_process_conns(ctx.engine)
      if lsquic_engine_has_unsent_packets(ctx.engine) != 0:
        lsquic_engine_send_unsent_packets(ctx.engine)
      let nextTimeout = Moment.init((if diff > 0: diff else: 0).int64, 1.microseconds)
      ctx.tickTimeout.set(nextTimeout)
  )
  ctx.tickTimeout.set(Moment.now())

  return ok(ctx)

method makeStream*(
    ctx: ClientContext, quicConn: QuicConnection
) {.gcsafe, raises: [].} =
  trace "Creating stream: client"
  lsquic_conn_make_stream(quicConn.lsquicConn)
