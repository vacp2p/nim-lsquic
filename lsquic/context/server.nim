import results
import chronicles
import chronos
import chronos/osdefs
import ./[context, io, stream]
import ../[lsquic_ffi, tlsconfig, datagram, timeout, stream]
import ../helpers/[sequninit, transportaddr]

proc onNewConn(
    stream_if_ctx: pointer, conn: ptr lsquic_conn_t
): ptr lsquic_conn_ctx_t {.cdecl.} =
  debug "New connection established: server"
  var local: ptr SockAddr
  var remote: ptr SockAddr
  discard lsquic_conn_get_sockaddr(conn, addr local, addr remote)
  let quicServerConn = QuicServerConn(
    incoming: newAsyncQueue[Stream](),
    local: local.toTransportAddress(),
    remote: remote.toTransportAddress(),
    lsquicConn: conn,
  )
  GC_ref(quicServerConn) # Keep it pinned until on_conn_closed is called
  let serverCtx = cast[ServerContext](stream_if_ctx)
  serverCtx.incoming.putNoWait(quicServerConn)
  cast[ptr lsquic_conn_ctx_t](quicServerConn)

proc onConnClosed(conn: ptr lsquic_conn_t) {.cdecl.} =
  debug "Connection closed: server"
  let conn_ctx = lsquic_conn_get_ctx(conn)
  if not conn_ctx.isNil:
    let quicConn = cast[QuicConnection](conn_ctx)
    quicConn.onClose()
  lsquic_conn_set_ctx(conn, nil)

proc onNewStream(
    stream_if_ctx: pointer, stream: ptr lsquic_stream_t
): ptr lsquic_stream_ctx_t {.cdecl.} =
  debug "New stream created: server"
  let conn = lsquic_stream_conn(stream)
  let conn_ctx = lsquic_conn_get_ctx(conn)
  if conn_ctx.isNil:
    debug "conn_ctx is nil in onNewStream"
    return nil

  let streamCtx = Stream.new(stream)
  let quicConn = cast[QuicServerConn](conn_ctx)
  quicConn.incoming.putNoWait(streamCtx)

  discard lsquic_stream_wantread(stream, 1)
  return cast[ptr lsquic_stream_ctx_t](streamCtx)

proc new*(
    T: typedesc[ServerContext],
    tlsConfig: TLSConfig,
    outgoing: AsyncQueue[Datagram],
    incoming: AsyncQueue[QuicServerConn],
): Result[T, string] =
  if lsquic_global_init(LSQUIC_GLOBAL_SERVER) != 0:
    return err("lsquic initialization failed")

  var ctx = ServerContext()
  ctx.tlsConfig = tlsConfig
  ctx.outgoing = outgoing
  ctx.incoming = incoming
  lsquic_engine_init_settings(addr ctx.settings, LSENG_SERVER)
  ctx.settings.es_versions = 1.cuint shl LSQVER_I001.cuint #IETF QUIC v1
  ctx.stream_if = struct_lsquic_stream_if(
    on_new_conn: onNewConn,
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

  ctx.engine = lsquic_engine_new(LSENG_SERVER, addr ctx.api)
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
