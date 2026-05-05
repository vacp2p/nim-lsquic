# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

when defined(windows):
  {.passl: "-lws2_32".}
  when defined(clang):
    {.passl: "-lpthread".}

import std/[os, strutils]
import chronos/osdefs
import zlib
import boringssl

type ptrdiff_t* {.importc: "ptrdiff_t", header: "<stddef.h>".} = int

# use rsplit as a workaround for cross compilation path separator issue
const root = currentSourcePath.rsplit({DirSep, AltSep}, 2)[0]
const lsquicInclude = root & "/libs/lsquic/include"
const liblsquicInclude = root & "/libs/lsquic/src/liblsquic"
const lsqpack = root & "/libs/lsquic/src/liblsquic/ls-qpack"
const lshpack = root & "/libs/lsquic/src/lshpack"
const xxhash = root & "/libs/lsquic/src/lshpack/deps/xxhash"

when defined(windows):
  const wincompat = root & "/libs/lsquic/wincompat"
  {.passc: "-I" & wincompat.}

{.passc: "-I" & lsquicInclude.}
{.passc: "-I" & liblsquicInclude.}
{.passc: "-I" & lsqpack.}
{.passc: "-I" & lshpack.}
{.passc: "-I" & xxhash.}

const HAVE_BORINGSSL = "-DHAVE_BORINGSSL"
const XXH_HEADER_NAME = "-DXXH_HEADER_NAME=\"<lsquic_xxhash.h>\""

{.compile: "../libs/lsquic/src/liblsquic/lsquic_xxhash.c".}
{.compile("../libs/lsquic/src/liblsquic/ls-qpack/lsqpack.c", XXH_HEADER_NAME).}
{.compile("../libs/lsquic/src/lshpack/lshpack.c", XXH_HEADER_NAME).}
{.compile: "../libs/lsquic/src/liblsquic/ls-sfparser.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_adaptive_cc.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_alarmset.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_arr.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_attq.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_bbr.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_bw_sampler.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_cfcw.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_chsk_stream.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_conn.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_crand.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_crt_compress.c".}
{.compile("../libs/lsquic/src/liblsquic/lsquic_crypto.c", HAVE_BORINGSSL).}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_cubic.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_di_error.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_di_hash.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_di_nocopy.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_enc_sess_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_enc_sess_ietf.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_eng_hist.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_engine.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_ev_log.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_frab_list.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_frame_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_frame_reader.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_frame_writer.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_full_conn.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_full_conn_ietf.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_global.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_handshake.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hash.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hcsi_reader.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hcso_writer.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_headers_stream.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hkdf.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hpi.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_hspack_valid.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_http.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_http1x_if.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_logger.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_malo.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_min_heap.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_mini_conn.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_mini_conn_ietf.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_minmax.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_mm.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_pacer.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_packet_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_packet_gquic.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_packet_in.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_packet_out.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_packet_resize.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_Q046.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_Q050.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_gquic_be.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_gquic_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_ietf_v1.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_parse_iquic_common.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_pr_queue.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_purga.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_qdec_hdl.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_qenc_hdl.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_qlog.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_qpack_exp.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_rechist.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_rtt.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_send_ctl.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_senhist.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_set.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_sfcw.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_shsk_stream.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_spi.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_stock_shi.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_str.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_stream.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_tokgen.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_trans_params.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_trechist.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_util.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_varint.c".}
{.compile: "../libs/lsquic/src/liblsquic/lsquic_version.c".}

{.warning[UnusedImport]: off.}
{.hint[XDeclaredButNotUsed]: off.}
from macros import hint, warning, newLit, getSize

from os import parentDir

when not declared(ownSizeOf):
  macro ownSizeof(x: typed): untyped =
    newLit(x.getSize)

type enum_lsquic_version_570425828* {.size: sizeof(cuint).} = enum
  LSQVER_043 = 0
  LSQVER_046 = 1
  LSQVER_050 = 2
  LSQVER_ID27 = 3
  LSQVER_ID29 = 4
  LSQVER_I001 = 5
  LSQVER_I002 = 6
  LSQVER_RESVED = 7
  N_LSQVER = 8
  LSQVER_VERNEG = 9

type enum_lsquic_hsk_status_570425830* {.size: sizeof(cuint).} = enum
  LSQ_HSK_FAIL = 0
  LSQ_HSK_OK = 1
  LSQ_HSK_RESUMED_OK = 2
  LSQ_HSK_RESUMED_FAIL = 3

type enum_lsquic_hsi_flag_570425854* {.size: sizeof(cuint).} = enum
  LSQUIC_HSI_HTTP1X = 2
  LSQUIC_HSI_HASH_NAME = 4
  LSQUIC_HSI_HASH_NAMEVAL = 8

type enum_lsquic_logger_timestamp_style_570425866* {.size: sizeof(cuint).} = enum
  LLTS_NONE = 0
  LLTS_HHMMSSMS = 1
  LLTS_YYYYMMDD_HHMMSSMS = 2
  LLTS_CHROMELIKE = 3
  LLTS_HHMMSSUS = 4
  LLTS_YYYYMMDD_HHMMSSUS = 5
  N_LLTS = 6

type enum_lsquic_crypto_ver_570425875* {.size: sizeof(cuint).} = enum
  LSQ_CRY_QUIC = 0
  LSQ_CRY_TLSv13 = 1

type enum_LSQUIC_CONN_STATUS_570425879* {.size: sizeof(cuint).} = enum
  LSCONN_ST_HSK_IN_PROGRESS = 0
  LSCONN_ST_CONNECTED = 1
  LSCONN_ST_HSK_FAILURE = 2
  LSCONN_ST_GOING_AWAY = 3
  LSCONN_ST_TIMED_OUT = 4
  LSCONN_ST_RESET = 5
  LSCONN_ST_USER_ABORTED = 6
  LSCONN_ST_ERROR = 7
  LSCONN_ST_CLOSED = 8
  LSCONN_ST_PEER_GOING_AWAY = 9
  LSCONN_ST_VERNEG_FAILURE = 10

when not declared(struct_ssl_st):
  type struct_ssl_st* = object
else:
  static:
    hint("Declaration of " & "struct_ssl_st" & " already exists, not redeclaring")
when not declared(struct_lsquic_stream):
  type struct_lsquic_stream* = object
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_stream" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_conn):
  type struct_lsquic_conn* = object
else:
  static:
    hint("Declaration of " & "struct_lsquic_conn" & " already exists, not redeclaring")
when not declared(buf):
  type buf* = object
else:
  static:
    hint("Declaration of " & "buf" & " already exists, not redeclaring")
when not declared(struct_lsxpack_header):
  type struct_lsxpack_header* = object
else:
  static:
    hint(
      "Declaration of " & "struct_lsxpack_header" & " already exists, not redeclaring"
    )
when not declared(struct_stack_st_X509):
  type struct_stack_st_X509* = object
else:
  static:
    hint(
      "Declaration of " & "struct_stack_st_X509" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_CFCW_SERVER):
  type LSQUIC_DF_CFCW_SERVER* = object
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_CFCW_SERVER" & " already exists, not redeclaring"
    )
when not declared(SockAddr):
  type SockAddr* = object
else:
  static:
    hint("Declaration of " & "SockAddr" & " already exists, not redeclaring")
when not declared(struct_lsquic_stream_ctx):
  type struct_lsquic_stream_ctx* = object
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_stream_ctx" & " already exists, not redeclaring"
    )
when not declared(struct_ssl_session_st):
  type struct_ssl_session_st* = object
else:
  static:
    hint(
      "Declaration of " & "struct_ssl_session_st" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_conn_ctx):
  type struct_lsquic_conn_ctx* = object
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_conn_ctx" & " already exists, not redeclaring"
    )
when not declared(struct_ssl_ctx_st):
  type struct_ssl_ctx_st* = object
else:
  static:
    hint("Declaration of " & "struct_ssl_ctx_st" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_SFCW_SERVER):
  type LSQUIC_DF_SFCW_SERVER* = object
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SFCW_SERVER" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_engine):
  type struct_lsquic_engine* = object
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_engine" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SFCW_CLIENT):
  type LSQUIC_DF_SFCW_CLIENT* = object
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SFCW_CLIENT" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_CFCW_CLIENT):
  type LSQUIC_DF_CFCW_CLIENT* = object
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_CFCW_CLIENT" & " already exists, not redeclaring"
    )
type
  struct_lsquic_cid_570425806 {.pure, inheritable, bycopy.} = object
    buf* {.align(8'i64).}: array[20'i64, uint8]
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:27:28
    len* {.align(8'i64).}: uint_fast8_t_570425809

  uint_fast8_t_570425808 = uint8 ## Generated based on /usr/include/stdint.h:60:24
  lsquic_cid_t_570425810 = struct_lsquic_cid_570425807
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:32:3
  lsquic_stream_id_t_570425812 = uint64
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:40:18
  lsquic_engine_t_570425814 = struct_lsquic_engine
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:43:30
  lsquic_conn_t_570425816 = struct_lsquic_conn
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:46:28
  lsquic_conn_ctx_t_570425818 = struct_lsquic_conn_ctx
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:49:32
  lsquic_stream_t_570425820 = struct_lsquic_stream
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:52:30
  lsquic_stream_ctx_t_570425822 = struct_lsquic_stream_ctx
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:55:34
  lsquic_http_headers_t_570425824 = struct_lsquic_http_headers_570425827
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:58:36
  struct_lsquic_http_headers_570425826 {.pure, inheritable, bycopy.} = object
    count*: cint
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1714:8
    headers*: ptr struct_lsxpack_header

  struct_lsquic_stream_if_570425832 {.pure, inheritable, bycopy.} = object
    on_new_conn*: proc(
      a0: pointer, a1: ptr lsquic_conn_t_570425817
    ): ptr lsquic_conn_ctx_t_570425819 {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:163:8
    on_goaway_received*: proc(a0: ptr lsquic_conn_t_570425817): void {.cdecl.}
    on_conn_closed*: proc(a0: ptr lsquic_conn_t_570425817): void {.cdecl.}
    on_new_stream*: proc(
      a0: pointer, a1: ptr lsquic_stream_t_570425821
    ): ptr lsquic_stream_ctx_t_570425823 {.cdecl.}
    on_read*: proc(
      a0: ptr lsquic_stream_t_570425821, a1: ptr lsquic_stream_ctx_t_570425823
    ): void {.cdecl.}
    on_write*: proc(
      a0: ptr lsquic_stream_t_570425821, a1: ptr lsquic_stream_ctx_t_570425823
    ): void {.cdecl.}
    on_close*: proc(
      a0: ptr lsquic_stream_t_570425821, a1: ptr lsquic_stream_ctx_t_570425823
    ): void {.cdecl.}
    on_dg_write*: proc(
      a0: ptr lsquic_conn_t_570425817, a1: pointer, a2: csize_t
    ): ssize_t_570425835 {.cdecl.}
    on_datagram*:
      proc(a0: ptr lsquic_conn_t_570425817, a1: pointer, a2: csize_t): void {.cdecl.}
    on_hsk_done*: proc(
      a0: ptr lsquic_conn_t_570425817, a1: enum_lsquic_hsk_status_570425831
    ): void {.cdecl.}
    on_new_token*:
      proc(a0: ptr lsquic_conn_t_570425817, a1: ptr uint8, a2: csize_t): void {.cdecl.}
    on_sess_resume_info*:
      proc(a0: ptr lsquic_conn_t_570425817, a1: ptr uint8, a2: csize_t): void {.cdecl.}
    on_reset*: proc(
      a0: ptr lsquic_stream_t_570425821, a1: ptr lsquic_stream_ctx_t_570425823, a2: cint
    ): void {.cdecl.}
    on_conncloseframe_received*: proc(
      a0: ptr lsquic_conn_t_570425817, a1: cint, a2: uint64, a3: cstring, a4: cint
    ): void {.cdecl.}

  ssize_t_570425834 = compiler_ssize_t_570425885
    ## Generated based on /usr/include/x86_64-linux-gnu/sys/types.h:108:19
  lsquic_lookup_cert_f_570425836 =
    proc(a0: pointer, a1: ptr SockAddr, a2: cstring): ptr struct_ssl_ctx_st {.cdecl.}
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:255:31
  struct_lsquic_engine_settings_570425838 {.pure, inheritable, bycopy.} = object
    es_versions*: cuint
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:476:8
    es_cfcw*: cuint
    es_sfcw*: cuint
    es_max_cfcw*: cuint
    es_max_sfcw*: cuint
    es_max_streams_in*: cuint
    es_handshake_to*: culong
    es_idle_conn_to*: culong
    es_silent_close*: cint
    es_max_header_list_size*: cuint
    es_ua*: cstring
    es_sttl*: uint64
    es_pdmd*: uint32
    es_aead*: uint32
    es_kexs*: uint32
    es_max_inchoate*: cuint
    es_support_srej*: cint
    es_support_push*: cint
    es_support_tcid0*: cint
    es_support_nstp*: cint
    es_honor_prst*: cint
    es_send_prst*: cint
    es_progress_check*: cuint
    es_rw_once*: cint
    es_proc_time_thresh*: cuint
    es_pace_packets*: cint
    es_clock_granularity*: cuint
    es_cc_algo*: cuint
    es_cc_rtt_thresh*: cuint
    es_noprogress_timeout*: cuint
    es_init_max_data*: cuint
    es_init_max_stream_data_bidi_remote*: cuint
    es_init_max_stream_data_bidi_local*: cuint
    es_init_max_stream_data_uni*: cuint
    es_init_max_streams_bidi*: cuint
    es_init_max_streams_uni*: cuint
    es_idle_timeout*: cuint
    es_ping_period*: cuint
    es_scid_len*: cuint
    es_scid_iss_rate*: cuint
    es_qpack_dec_max_size*: cuint
    es_qpack_dec_max_blocked*: cuint
    es_qpack_enc_max_size*: cuint
    es_qpack_enc_max_blocked*: cuint
    es_ecn*: cint
    es_allow_migration*: cint
    es_retry_token_duration*: cuint
    es_ql_bits*: cint
    es_spin*: cint
    es_delayed_acks*: cint
    es_timestamps*: cint
    es_max_udp_payload_size_rx*: cushort
    es_grease_quic_bit*: cint
    es_dplpmtud*: cint
    es_base_plpmtu*: cushort
    es_max_plpmtu*: cushort
    es_mtu_probe_timer*: cuint
    es_datagrams*: cint
    es_optimistic_nat*: cint
    es_ext_http_prio*: cint
    es_qpack_experiment*: cint
    es_ptpc_periodicity*: cuint
    es_ptpc_max_packtol*: cuint
    es_ptpc_dyn_target*: cint
    es_ptpc_target*: cfloat
    es_ptpc_prop_gain*: cfloat
    es_ptpc_int_gain*: cfloat
    es_ptpc_err_thresh*: cfloat
    es_ptpc_err_divisor*: cfloat
    es_delay_onclose*: cint
    es_max_batch_size*: cuint
    es_check_tp_sanity*: cint
    es_amp_factor*: cint
    es_send_verneg*: cint
    es_preferred_address*: array[24'i64, uint8]

  struct_lsquic_out_spec_570425840 {.pure, inheritable, bycopy.} = object
    iov*: ptr struct_iovec_570425843
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1185:8
    iovlen*: csize_t
    local_sa*: ptr SockAddr
    dest_sa*: ptr SockAddr
    peer_ctx*: pointer
    conn_ctx*: ptr lsquic_conn_ctx_t_570425819
    ecn*: cint

  struct_iovec_570425842 {.pure, inheritable, bycopy.} = object
    iov_base*: pointer
      ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/struct_iovec.h:26:8
    iov_len*: csize_t

  lsquic_packets_out_f_570425844 = proc(
    a0: pointer, a1: ptr struct_lsquic_out_spec_570425841, a2: cuint
  ): cint {.cdecl.}
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1209:15
  struct_lsquic_shared_hash_if_570425846 {.pure, inheritable, bycopy.} = object
    shi_insert*: proc(
      a0: pointer, a1: pointer, a2: cuint, a3: pointer, a4: cuint, a5: time_t_570425849
    ): cint {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1219:8
    shi_delete*: proc(a0: pointer, a1: pointer, a2: cuint): cint {.cdecl.}
    shi_lookup*: proc(
      a0: pointer, a1: pointer, a2: cuint, a3: ptr pointer, a4: ptr cuint
    ): cint {.cdecl.}

  time_t_570425848 = compiler_time_t_570425887
    ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/time_t.h:10:18
  struct_lsquic_packout_mem_if_570425850 {.pure, inheritable, bycopy.} = object
    pmi_allocate*: proc(
      a0: pointer,
      a1: pointer,
      a2: ptr lsquic_conn_ctx_t_570425819,
      a3: cushort,
      a4: cschar,
    ): pointer {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1257:8
    pmi_release*:
      proc(a0: pointer, a1: pointer, a2: pointer, a3: cschar): void {.cdecl.}
    pmi_return*: proc(a0: pointer, a1: pointer, a2: pointer, a3: cschar): void {.cdecl.}

  lsquic_cids_update_f_570425852 = proc(
    a0: pointer, a1: ptr pointer, a2: ptr lsquic_cid_t_570425811, a3: cuint
  ): void {.cdecl.}
    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1278:16
  struct_lsquic_hset_if_570425856 {.pure, inheritable, bycopy.} = object
    hsi_create_header_set*:
      proc(a0: pointer, a1: ptr lsquic_stream_t_570425821, a2: cint): pointer {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1296:8
    hsi_prepare_decode*: proc(
      a0: pointer, a1: ptr struct_lsxpack_header, a2: csize_t
    ): ptr struct_lsxpack_header {.cdecl.}
    hsi_process_header*:
      proc(a0: pointer, a1: ptr struct_lsxpack_header): cint {.cdecl.}
    hsi_discard_header_set*: proc(a0: pointer): void {.cdecl.}
    hsi_flags*: enum_lsquic_hsi_flag_570425855

  struct_lsquic_engine_api_570425858 {.pure, inheritable, bycopy.} = object
    ea_settings*: ptr struct_lsquic_engine_settings_570425839
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1369:8
    ea_stream_if*: ptr struct_lsquic_stream_if_570425833
    ea_stream_if_ctx*: pointer
    ea_packets_out*: lsquic_packets_out_f_570425845
    ea_packets_out_ctx*: pointer
    ea_lookup_cert*: lsquic_lookup_cert_f_570425837
    ea_cert_lu_ctx*: pointer
    ea_get_ssl_ctx*:
      proc(a0: pointer, a1: ptr SockAddr): ptr struct_ssl_ctx_st {.cdecl.}
    ea_shi*: ptr struct_lsquic_shared_hash_if_570425847
    ea_shi_ctx*: pointer
    ea_pmi*: ptr struct_lsquic_packout_mem_if_570425851
    ea_pmi_ctx*: pointer
    ea_new_scids*: lsquic_cids_update_f_570425853
    ea_live_scids*: lsquic_cids_update_f_570425853
    ea_old_scids*: lsquic_cids_update_f_570425853
    ea_cids_update_ctx*: pointer
    ea_verify_cert*: proc(a0: pointer, a1: ptr struct_stack_st_X509): cint {.cdecl.}
    ea_verify_ctx*: pointer
    ea_hsi_if*: ptr struct_lsquic_hset_if_570425857
    ea_hsi_ctx*: pointer
    ea_stats_fh*: pointer
    ea_alpn*: cstring
    ea_generate_scid*: proc(
      a0: pointer, a1: ptr lsquic_conn_t_570425817, a2: ptr uint8, a3: cuint
    ): void {.cdecl.}
    ea_gen_scid_ctx*: pointer

  struct_lsquic_reader_570425860 {.pure, inheritable, bycopy.} = object
    lsqr_read*: proc(a0: pointer, a1: pointer, a2: csize_t): csize_t {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1673:8
    lsqr_size*: proc(a0: pointer): csize_t {.cdecl.}
    lsqr_ctx*: pointer

  struct_lsquic_ext_http_prio_570425862 {.pure, inheritable, bycopy.} = object
    urgency*: uint8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1871:8
    incremental*: cschar

  struct_lsquic_logger_if_570425864 {.pure, inheritable, bycopy.} = object
    log_buf*: proc(a0: pointer, a1: cstring, a2: csize_t): cint {.cdecl.}
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1944:8

  struct_lsquic_conn_info_570425877 {.pure, inheritable, bycopy.} = object
    lci_cwnd*: uint32
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:2131:8
    lci_pmtu*: uint32
    lci_rtt*: uint32
    lci_rttvar*: uint32
    lci_rtt_min*: uint32
    lci_bytes_rcvd*: uint64
    lci_bytes_sent*: uint64
    lci_pkts_rcvd*: uint64
    lci_pkts_sent*: uint64
    lci_pkts_lost*: uint64
    lci_pkts_retx*: uint64
    lci_bw_estimate*: uint64

  compiler_ssize_t_570425884 = clong
    ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:194:27
  compiler_time_t_570425886 = clong
    ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:160:26
  struct_lsquic_reader_570425861 = (
    when declared(struct_lsquic_reader):
      when ownSizeof(struct_lsquic_reader) != ownSizeof(struct_lsquic_reader_570425860):
        static:
          warning(
            "Declaration of " & "struct_lsquic_reader" &
              " exists but with different size"
          )
      struct_lsquic_reader
    else:
      struct_lsquic_reader_570425860
  )
  lsquic_lookup_cert_f_570425837 = (
    when declared(lsquic_lookup_cert_f):
      when ownSizeof(lsquic_lookup_cert_f) != ownSizeof(lsquic_lookup_cert_f_570425836):
        static:
          warning(
            "Declaration of " & "lsquic_lookup_cert_f" &
              " exists but with different size"
          )
      lsquic_lookup_cert_f
    else:
      lsquic_lookup_cert_f_570425836
  )
  struct_lsquic_engine_api_570425859 = (
    when declared(struct_lsquic_engine_api):
      when ownSizeof(struct_lsquic_engine_api) !=
          ownSizeof(struct_lsquic_engine_api_570425858):
        static:
          warning(
            "Declaration of " & "struct_lsquic_engine_api" &
              " exists but with different size"
          )
      struct_lsquic_engine_api
    else:
      struct_lsquic_engine_api_570425858
  )
  compiler_ssize_t_570425885 = (
    when declared(compiler_ssize_t):
      when ownSizeof(compiler_ssize_t) != ownSizeof(compiler_ssize_t_570425884):
        static:
          warning(
            "Declaration of " & "compiler_ssize_t" & " exists but with different size"
          )
      compiler_ssize_t
    else:
      compiler_ssize_t_570425884
  )
  struct_lsquic_shared_hash_if_570425847 = (
    when declared(struct_lsquic_shared_hash_if):
      when ownSizeof(struct_lsquic_shared_hash_if) !=
          ownSizeof(struct_lsquic_shared_hash_if_570425846):
        static:
          warning(
            "Declaration of " & "struct_lsquic_shared_hash_if" &
              " exists but with different size"
          )
      struct_lsquic_shared_hash_if
    else:
      struct_lsquic_shared_hash_if_570425846
  )
  lsquic_stream_t_570425821 = (
    when declared(lsquic_stream_t):
      when ownSizeof(lsquic_stream_t) != ownSizeof(lsquic_stream_t_570425820):
        static:
          warning(
            "Declaration of " & "lsquic_stream_t" & " exists but with different size"
          )
      lsquic_stream_t
    else:
      lsquic_stream_t_570425820
  )
  struct_lsquic_ext_http_prio_570425863 = (
    when declared(struct_lsquic_ext_http_prio):
      when ownSizeof(struct_lsquic_ext_http_prio) !=
          ownSizeof(struct_lsquic_ext_http_prio_570425862):
        static:
          warning(
            "Declaration of " & "struct_lsquic_ext_http_prio" &
              " exists but with different size"
          )
      struct_lsquic_ext_http_prio
    else:
      struct_lsquic_ext_http_prio_570425862
  )
  enum_lsquic_crypto_ver_570425876 = (
    when declared(enum_lsquic_crypto_ver):
      when ownSizeof(enum_lsquic_crypto_ver) !=
          ownSizeof(enum_lsquic_crypto_ver_570425875):
        static:
          warning(
            "Declaration of " & "enum_lsquic_crypto_ver" &
              " exists but with different size"
          )
      enum_lsquic_crypto_ver
    else:
      enum_lsquic_crypto_ver_570425875
  )
  struct_lsquic_conn_info_570425878 = (
    when declared(struct_lsquic_conn_info):
      when ownSizeof(struct_lsquic_conn_info) !=
          ownSizeof(struct_lsquic_conn_info_570425877):
        static:
          warning(
            "Declaration of " & "struct_lsquic_conn_info" &
              " exists but with different size"
          )
      struct_lsquic_conn_info
    else:
      struct_lsquic_conn_info_570425877
  )
  enum_lsquic_hsk_status_570425831 = (
    when declared(enum_lsquic_hsk_status):
      when ownSizeof(enum_lsquic_hsk_status) !=
          ownSizeof(enum_lsquic_hsk_status_570425830):
        static:
          warning(
            "Declaration of " & "enum_lsquic_hsk_status" &
              " exists but with different size"
          )
      enum_lsquic_hsk_status
    else:
      enum_lsquic_hsk_status_570425830
  )
  struct_lsquic_cid_570425807 = (
    when declared(struct_lsquic_cid):
      when ownSizeof(struct_lsquic_cid) != ownSizeof(struct_lsquic_cid_570425806):
        static:
          warning(
            "Declaration of " & "struct_lsquic_cid" & " exists but with different size"
          )
      struct_lsquic_cid
    else:
      struct_lsquic_cid_570425806
  )
  lsquic_stream_id_t_570425813 = (
    when declared(lsquic_stream_id_t):
      when ownSizeof(lsquic_stream_id_t) != ownSizeof(lsquic_stream_id_t_570425812):
        static:
          warning(
            "Declaration of " & "lsquic_stream_id_t" & " exists but with different size"
          )
      lsquic_stream_id_t
    else:
      lsquic_stream_id_t_570425812
  )
  struct_lsquic_logger_if_570425865 = (
    when declared(struct_lsquic_logger_if):
      when ownSizeof(struct_lsquic_logger_if) !=
          ownSizeof(struct_lsquic_logger_if_570425864):
        static:
          warning(
            "Declaration of " & "struct_lsquic_logger_if" &
              " exists but with different size"
          )
      struct_lsquic_logger_if
    else:
      struct_lsquic_logger_if_570425864
  )
  struct_lsquic_packout_mem_if_570425851 = (
    when declared(struct_lsquic_packout_mem_if):
      when ownSizeof(struct_lsquic_packout_mem_if) !=
          ownSizeof(struct_lsquic_packout_mem_if_570425850):
        static:
          warning(
            "Declaration of " & "struct_lsquic_packout_mem_if" &
              " exists but with different size"
          )
      struct_lsquic_packout_mem_if
    else:
      struct_lsquic_packout_mem_if_570425850
  )
  enum_lsquic_logger_timestamp_style_570425867 = (
    when declared(enum_lsquic_logger_timestamp_style):
      when ownSizeof(enum_lsquic_logger_timestamp_style) !=
          ownSizeof(enum_lsquic_logger_timestamp_style_570425866):
        static:
          warning(
            "Declaration of " & "enum_lsquic_logger_timestamp_style" &
              " exists but with different size"
          )
      enum_lsquic_logger_timestamp_style
    else:
      enum_lsquic_logger_timestamp_style_570425866
  )
  lsquic_conn_t_570425817 = (
    when declared(lsquic_conn_t):
      when ownSizeof(lsquic_conn_t) != ownSizeof(lsquic_conn_t_570425816):
        static:
          warning(
            "Declaration of " & "lsquic_conn_t" & " exists but with different size"
          )
      lsquic_conn_t
    else:
      lsquic_conn_t_570425816
  )
  struct_lsquic_http_headers_570425827 = (
    when declared(struct_lsquic_http_headers):
      when ownSizeof(struct_lsquic_http_headers) !=
          ownSizeof(struct_lsquic_http_headers_570425826):
        static:
          warning(
            "Declaration of " & "struct_lsquic_http_headers" &
              " exists but with different size"
          )
      struct_lsquic_http_headers
    else:
      struct_lsquic_http_headers_570425826
  )
  enum_lsquic_version_570425829 = (
    when declared(enum_lsquic_version):
      when ownSizeof(enum_lsquic_version) != ownSizeof(enum_lsquic_version_570425828):
        static:
          warning(
            "Declaration of " & "enum_lsquic_version" & " exists but with different size"
          )
      enum_lsquic_version
    else:
      enum_lsquic_version_570425828
  )
  ssize_t_570425835 = (
    when declared(ssize_t):
      when ownSizeof(ssize_t) != ownSizeof(ssize_t_570425834):
        static:
          warning("Declaration of " & "ssize_t" & " exists but with different size")
      ssize_t
    else:
      ssize_t_570425834
  )
  enum_lsquic_hsi_flag_570425855 = (
    when declared(enum_lsquic_hsi_flag):
      when ownSizeof(enum_lsquic_hsi_flag) != ownSizeof(enum_lsquic_hsi_flag_570425854):
        static:
          warning(
            "Declaration of " & "enum_lsquic_hsi_flag" &
              " exists but with different size"
          )
      enum_lsquic_hsi_flag
    else:
      enum_lsquic_hsi_flag_570425854
  )
  enum_LSQUIC_CONN_STATUS_570425880 = (
    when declared(enum_LSQUIC_CONN_STATUS):
      when ownSizeof(enum_LSQUIC_CONN_STATUS) !=
          ownSizeof(enum_LSQUIC_CONN_STATUS_570425879):
        static:
          warning(
            "Declaration of " & "enum_LSQUIC_CONN_STATUS" &
              " exists but with different size"
          )
      enum_LSQUIC_CONN_STATUS
    else:
      enum_LSQUIC_CONN_STATUS_570425879
  )
  struct_lsquic_engine_settings_570425839 = (
    when declared(struct_lsquic_engine_settings):
      when ownSizeof(struct_lsquic_engine_settings) !=
          ownSizeof(struct_lsquic_engine_settings_570425838):
        static:
          warning(
            "Declaration of " & "struct_lsquic_engine_settings" &
              " exists but with different size"
          )
      struct_lsquic_engine_settings
    else:
      struct_lsquic_engine_settings_570425838
  )
  lsquic_cids_update_f_570425853 = (
    when declared(lsquic_cids_update_f):
      when ownSizeof(lsquic_cids_update_f) != ownSizeof(lsquic_cids_update_f_570425852):
        static:
          warning(
            "Declaration of " & "lsquic_cids_update_f" &
              " exists but with different size"
          )
      lsquic_cids_update_f
    else:
      lsquic_cids_update_f_570425852
  )
  compiler_time_t_570425887 = (
    when declared(compiler_time_t):
      when ownSizeof(compiler_time_t) != ownSizeof(compiler_time_t_570425886):
        static:
          warning(
            "Declaration of " & "compiler_time_t" & " exists but with different size"
          )
      compiler_time_t
    else:
      compiler_time_t_570425886
  )
  lsquic_conn_ctx_t_570425819 = (
    when declared(lsquic_conn_ctx_t):
      when ownSizeof(lsquic_conn_ctx_t) != ownSizeof(lsquic_conn_ctx_t_570425818):
        static:
          warning(
            "Declaration of " & "lsquic_conn_ctx_t" & " exists but with different size"
          )
      lsquic_conn_ctx_t
    else:
      lsquic_conn_ctx_t_570425818
  )
  struct_lsquic_stream_if_570425833 = (
    when declared(struct_lsquic_stream_if):
      when ownSizeof(struct_lsquic_stream_if) !=
          ownSizeof(struct_lsquic_stream_if_570425832):
        static:
          warning(
            "Declaration of " & "struct_lsquic_stream_if" &
              " exists but with different size"
          )
      struct_lsquic_stream_if
    else:
      struct_lsquic_stream_if_570425832
  )
  struct_lsquic_hset_if_570425857 = (
    when declared(struct_lsquic_hset_if):
      when ownSizeof(struct_lsquic_hset_if) != ownSizeof(
        struct_lsquic_hset_if_570425856
      ):
        static:
          warning(
            "Declaration of " & "struct_lsquic_hset_if" &
              " exists but with different size"
          )
      struct_lsquic_hset_if
    else:
      struct_lsquic_hset_if_570425856
  )
  struct_iovec_570425843 = (
    when declared(struct_iovec):
      when ownSizeof(struct_iovec) != ownSizeof(struct_iovec_570425842):
        static:
          warning(
            "Declaration of " & "struct_iovec" & " exists but with different size"
          )
      struct_iovec
    else:
      struct_iovec_570425842
  )
  lsquic_stream_ctx_t_570425823 = (
    when declared(lsquic_stream_ctx_t):
      when ownSizeof(lsquic_stream_ctx_t) != ownSizeof(lsquic_stream_ctx_t_570425822):
        static:
          warning(
            "Declaration of " & "lsquic_stream_ctx_t" & " exists but with different size"
          )
      lsquic_stream_ctx_t
    else:
      lsquic_stream_ctx_t_570425822
  )
  lsquic_cid_t_570425811 = (
    when declared(lsquic_cid_t):
      when ownSizeof(lsquic_cid_t) != ownSizeof(lsquic_cid_t_570425810):
        static:
          warning(
            "Declaration of " & "lsquic_cid_t" & " exists but with different size"
          )
      lsquic_cid_t
    else:
      lsquic_cid_t_570425810
  )
  uint_fast8_t_570425809 = (
    when declared(uint_fast8_t):
      when ownSizeof(uint_fast8_t) != ownSizeof(uint_fast8_t_570425808):
        static:
          warning(
            "Declaration of " & "uint_fast8_t" & " exists but with different size"
          )
      uint_fast8_t
    else:
      uint_fast8_t_570425808
  )
  struct_lsquic_out_spec_570425841 = (
    when declared(struct_lsquic_out_spec):
      when ownSizeof(struct_lsquic_out_spec) !=
          ownSizeof(struct_lsquic_out_spec_570425840):
        static:
          warning(
            "Declaration of " & "struct_lsquic_out_spec" &
              " exists but with different size"
          )
      struct_lsquic_out_spec
    else:
      struct_lsquic_out_spec_570425840
  )
  lsquic_engine_t_570425815 = (
    when declared(lsquic_engine_t):
      when ownSizeof(lsquic_engine_t) != ownSizeof(lsquic_engine_t_570425814):
        static:
          warning(
            "Declaration of " & "lsquic_engine_t" & " exists but with different size"
          )
      lsquic_engine_t
    else:
      lsquic_engine_t_570425814
  )
  time_t_570425849 = (
    when declared(time_t):
      when ownSizeof(time_t) != ownSizeof(time_t_570425848):
        static:
          warning("Declaration of " & "time_t" & " exists but with different size")
      time_t
    else:
      time_t_570425848
  )
  lsquic_http_headers_t_570425825 = (
    when declared(lsquic_http_headers_t):
      when ownSizeof(lsquic_http_headers_t) != ownSizeof(
        lsquic_http_headers_t_570425824
      ):
        static:
          warning(
            "Declaration of " & "lsquic_http_headers_t" &
              " exists but with different size"
          )
      lsquic_http_headers_t
    else:
      lsquic_http_headers_t_570425824
  )
  lsquic_packets_out_f_570425845 = (
    when declared(lsquic_packets_out_f):
      when ownSizeof(lsquic_packets_out_f) != ownSizeof(lsquic_packets_out_f_570425844):
        static:
          warning(
            "Declaration of " & "lsquic_packets_out_f" &
              " exists but with different size"
          )
      lsquic_packets_out_f
    else:
      lsquic_packets_out_f_570425844
  )

when not declared(struct_lsquic_reader):
  type struct_lsquic_reader* = struct_lsquic_reader_570425860
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_reader" & " already exists, not redeclaring"
    )
when not declared(lsquic_lookup_cert_f):
  type lsquic_lookup_cert_f* = lsquic_lookup_cert_f_570425836
else:
  static:
    hint(
      "Declaration of " & "lsquic_lookup_cert_f" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_engine_api):
  type struct_lsquic_engine_api* = struct_lsquic_engine_api_570425858
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_engine_api" & " already exists, not redeclaring"
    )
when not declared(compiler_ssize_t):
  type compiler_ssize_t* = compiler_ssize_t_570425884
else:
  static:
    hint("Declaration of " & "compiler_ssize_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_shared_hash_if):
  type struct_lsquic_shared_hash_if* = struct_lsquic_shared_hash_if_570425846
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_shared_hash_if" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_t):
  type lsquic_stream_t* = lsquic_stream_t_570425820
else:
  static:
    hint("Declaration of " & "lsquic_stream_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_ext_http_prio):
  type struct_lsquic_ext_http_prio* = struct_lsquic_ext_http_prio_570425862
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_ext_http_prio" &
        " already exists, not redeclaring"
    )
when not declared(enum_lsquic_crypto_ver):
  type enum_lsquic_crypto_ver* = enum_lsquic_crypto_ver_570425875
else:
  static:
    hint(
      "Declaration of " & "enum_lsquic_crypto_ver" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_conn_info):
  type struct_lsquic_conn_info* = struct_lsquic_conn_info_570425877
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_conn_info" & " already exists, not redeclaring"
    )
when not declared(enum_lsquic_hsk_status):
  type enum_lsquic_hsk_status* = enum_lsquic_hsk_status_570425830
else:
  static:
    hint(
      "Declaration of " & "enum_lsquic_hsk_status" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_cid):
  type struct_lsquic_cid* = struct_lsquic_cid_570425806
else:
  static:
    hint("Declaration of " & "struct_lsquic_cid" & " already exists, not redeclaring")
when not declared(lsquic_stream_id_t):
  type lsquic_stream_id_t* = lsquic_stream_id_t_570425812
else:
  static:
    hint("Declaration of " & "lsquic_stream_id_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_logger_if):
  type struct_lsquic_logger_if* = struct_lsquic_logger_if_570425864
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_logger_if" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_packout_mem_if):
  type struct_lsquic_packout_mem_if* = struct_lsquic_packout_mem_if_570425850
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_packout_mem_if" &
        " already exists, not redeclaring"
    )
when not declared(enum_lsquic_logger_timestamp_style):
  type enum_lsquic_logger_timestamp_style* =
    enum_lsquic_logger_timestamp_style_570425866

else:
  static:
    hint(
      "Declaration of " & "enum_lsquic_logger_timestamp_style" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_t):
  type lsquic_conn_t* = lsquic_conn_t_570425816
else:
  static:
    hint("Declaration of " & "lsquic_conn_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_http_headers):
  type struct_lsquic_http_headers* = struct_lsquic_http_headers_570425826
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_http_headers" &
        " already exists, not redeclaring"
    )
when not declared(enum_lsquic_version):
  type enum_lsquic_version* = enum_lsquic_version_570425828
else:
  static:
    hint("Declaration of " & "enum_lsquic_version" & " already exists, not redeclaring")
when not declared(ssize_t):
  type ssize_t* = ssize_t_570425834
else:
  static:
    hint("Declaration of " & "ssize_t" & " already exists, not redeclaring")
when not declared(enum_lsquic_hsi_flag):
  type enum_lsquic_hsi_flag* = enum_lsquic_hsi_flag_570425854
else:
  static:
    hint(
      "Declaration of " & "enum_lsquic_hsi_flag" & " already exists, not redeclaring"
    )
when not declared(enum_LSQUIC_CONN_STATUS):
  type enum_LSQUIC_CONN_STATUS* = enum_LSQUIC_CONN_STATUS_570425879
else:
  static:
    hint(
      "Declaration of " & "enum_LSQUIC_CONN_STATUS" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_engine_settings):
  type struct_lsquic_engine_settings* = struct_lsquic_engine_settings_570425838
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_engine_settings" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_cids_update_f):
  type lsquic_cids_update_f* = lsquic_cids_update_f_570425852
else:
  static:
    hint(
      "Declaration of " & "lsquic_cids_update_f" & " already exists, not redeclaring"
    )
when not declared(compiler_time_t):
  type compiler_time_t* = compiler_time_t_570425886
else:
  static:
    hint("Declaration of " & "compiler_time_t" & " already exists, not redeclaring")
when not declared(lsquic_conn_ctx_t):
  type lsquic_conn_ctx_t* = lsquic_conn_ctx_t_570425818
else:
  static:
    hint("Declaration of " & "lsquic_conn_ctx_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_stream_if):
  type struct_lsquic_stream_if* = struct_lsquic_stream_if_570425832
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_stream_if" & " already exists, not redeclaring"
    )
when not declared(struct_lsquic_hset_if):
  type struct_lsquic_hset_if* = struct_lsquic_hset_if_570425856
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_hset_if" & " already exists, not redeclaring"
    )
when not declared(struct_iovec):
  type struct_iovec* = struct_iovec_570425842
else:
  static:
    hint("Declaration of " & "struct_iovec" & " already exists, not redeclaring")
when not declared(lsquic_stream_ctx_t):
  type lsquic_stream_ctx_t* = lsquic_stream_ctx_t_570425822
else:
  static:
    hint("Declaration of " & "lsquic_stream_ctx_t" & " already exists, not redeclaring")
when not declared(lsquic_cid_t):
  type lsquic_cid_t* = lsquic_cid_t_570425810
else:
  static:
    hint("Declaration of " & "lsquic_cid_t" & " already exists, not redeclaring")
when not declared(uint_fast8_t):
  type uint_fast8_t* = uint_fast8_t_570425808
else:
  static:
    hint("Declaration of " & "uint_fast8_t" & " already exists, not redeclaring")
when not declared(struct_lsquic_out_spec):
  type struct_lsquic_out_spec* = struct_lsquic_out_spec_570425840
else:
  static:
    hint(
      "Declaration of " & "struct_lsquic_out_spec" & " already exists, not redeclaring"
    )
when not declared(lsquic_engine_t):
  type lsquic_engine_t* = lsquic_engine_t_570425814
else:
  static:
    hint("Declaration of " & "lsquic_engine_t" & " already exists, not redeclaring")
when not declared(time_t):
  type time_t* = time_t_570425848
else:
  static:
    hint("Declaration of " & "time_t" & " already exists, not redeclaring")
when not declared(lsquic_http_headers_t):
  type lsquic_http_headers_t* = lsquic_http_headers_t_570425824
else:
  static:
    hint(
      "Declaration of " & "lsquic_http_headers_t" & " already exists, not redeclaring"
    )
when not declared(lsquic_packets_out_f):
  type lsquic_packets_out_f* = lsquic_packets_out_f_570425844
else:
  static:
    hint(
      "Declaration of " & "lsquic_packets_out_f" & " already exists, not redeclaring"
    )
when not declared(MAX_CID_LEN):
  when 20 is static:
    const MAX_CID_LEN* = 20
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:13:9
  else:
    let MAX_CID_LEN* = 20
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:13:9
else:
  static:
    hint("Declaration of " & "MAX_CID_LEN" & " already exists, not redeclaring")
when not declared(GQUIC_CID_LEN):
  when 8 is static:
    const GQUIC_CID_LEN* = 8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:14:9
  else:
    let GQUIC_CID_LEN* = 8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:14:9
else:
  static:
    hint("Declaration of " & "GQUIC_CID_LEN" & " already exists, not redeclaring")
when not declared(idbuf):
  when buf is typedesc:
    type idbuf* = buf
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9

  else:
    when buf is static:
      const idbuf* = buf
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9
    else:
      let idbuf* = buf
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9
else:
  static:
    hint("Declaration of " & "idbuf" & " already exists, not redeclaring")
when not declared(LSQUIC_MAJOR_VERSION):
  when 4 is static:
    const LSQUIC_MAJOR_VERSION* = 4
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:28:9
  else:
    let LSQUIC_MAJOR_VERSION* = 4
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:28:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_MAJOR_VERSION" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_MINOR_VERSION):
  when 3 is static:
    const LSQUIC_MINOR_VERSION* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:29:9
  else:
    let LSQUIC_MINOR_VERSION* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:29:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_MINOR_VERSION" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_PATCH_VERSION):
  when 2 is static:
    const LSQUIC_PATCH_VERSION* = 2
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:30:9
  else:
    let LSQUIC_PATCH_VERSION* = 2
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:30:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_PATCH_VERSION" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MAX_STREAMS_IN):
  when 100 is static:
    const LSQUIC_DF_MAX_STREAMS_IN* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:280:9
  else:
    let LSQUIC_DF_MAX_STREAMS_IN* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:280:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MAX_STREAMS_IN" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_DATA_SERVER):
  when LSQUIC_DF_CFCW_SERVER is typedesc:
    type LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9

  else:
    when LSQUIC_DF_CFCW_SERVER is static:
      const LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9
    else:
      let LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_DATA_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_DATA_CLIENT):
  when LSQUIC_DF_CFCW_CLIENT is typedesc:
    type LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9

  else:
    when LSQUIC_DF_CFCW_CLIENT is static:
      const LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9
    else:
      let LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_DATA_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER):
  when LSQUIC_DF_SFCW_SERVER is typedesc:
    type LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9

  else:
    when LSQUIC_DF_SFCW_SERVER is static:
      const LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER):
  when 0 is static:
    const LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:286:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:286:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT):
  when 0 is static:
    const LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:287:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:287:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT):
  when LSQUIC_DF_SFCW_CLIENT is typedesc:
    type LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9

  else:
    when LSQUIC_DF_SFCW_CLIENT is static:
      const LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_BIDI):
  when LSQUIC_DF_MAX_STREAMS_IN is typedesc:
    type LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9

  else:
    when LSQUIC_DF_MAX_STREAMS_IN is static:
      const LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN
        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_BIDI" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT):
  when 100 is static:
    const LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:290:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:290:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER):
  when 3 is static:
    const LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:291:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:291:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_IDLE_TIMEOUT):
  when 30 is static:
    const LSQUIC_DF_IDLE_TIMEOUT* = 30
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:299:9
  else:
    let LSQUIC_DF_IDLE_TIMEOUT* = 30
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:299:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_IDLE_TIMEOUT" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PING_PERIOD):
  when 15 is static:
    const LSQUIC_DF_PING_PERIOD* = 15
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:304:9
  else:
    let LSQUIC_DF_PING_PERIOD* = 15
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:304:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PING_PERIOD" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SILENT_CLOSE):
  when 1 is static:
    const LSQUIC_DF_SILENT_CLOSE* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:312:9
  else:
    let LSQUIC_DF_SILENT_CLOSE* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:312:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SILENT_CLOSE" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MAX_HEADER_LIST_SIZE):
  when 0 is static:
    const LSQUIC_DF_MAX_HEADER_LIST_SIZE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:318:9
  else:
    let LSQUIC_DF_MAX_HEADER_LIST_SIZE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:318:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MAX_HEADER_LIST_SIZE" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_UA):
  when "LSQUIC" is static:
    const LSQUIC_DF_UA* = "LSQUIC"
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:321:9
  else:
    let LSQUIC_DF_UA* = "LSQUIC"
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:321:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_UA" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_STTL):
  when 86400 is static:
    const LSQUIC_DF_STTL* = 86400
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:323:9
  else:
    let LSQUIC_DF_STTL* = 86400
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:323:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_STTL" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_SREJ_SERVER):
  when 1 is static:
    const LSQUIC_DF_SUPPORT_SREJ_SERVER* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:326:9
  else:
    let LSQUIC_DF_SUPPORT_SREJ_SERVER* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:326:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SUPPORT_SREJ_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SUPPORT_SREJ_CLIENT):
  when 0 is static:
    const LSQUIC_DF_SUPPORT_SREJ_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:327:9
  else:
    let LSQUIC_DF_SUPPORT_SREJ_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:327:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SUPPORT_SREJ_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SUPPORT_NSTP):
  when 0 is static:
    const LSQUIC_DF_SUPPORT_NSTP* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:330:9
  else:
    let LSQUIC_DF_SUPPORT_NSTP* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:330:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SUPPORT_NSTP" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SUPPORT_PUSH):
  when 1 is static:
    const LSQUIC_DF_SUPPORT_PUSH* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:332:9
  else:
    let LSQUIC_DF_SUPPORT_PUSH* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:332:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SUPPORT_PUSH" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SUPPORT_TCID0):
  when 1 is static:
    const LSQUIC_DF_SUPPORT_TCID0* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:333:9
  else:
    let LSQUIC_DF_SUPPORT_TCID0* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:333:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SUPPORT_TCID0" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_HONOR_PRST):
  when 0 is static:
    const LSQUIC_DF_HONOR_PRST* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:335:9
  else:
    let LSQUIC_DF_HONOR_PRST* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:335:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_HONOR_PRST" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SEND_PRST):
  when 0 is static:
    const LSQUIC_DF_SEND_PRST* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:341:9
  else:
    let LSQUIC_DF_SEND_PRST* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:341:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_SEND_PRST" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_SEND_VERNEG):
  when 1 is static:
    const LSQUIC_DF_SEND_VERNEG* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:347:9
  else:
    let LSQUIC_DF_SEND_VERNEG* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:347:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SEND_VERNEG" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PROGRESS_CHECK):
  when 1000 is static:
    const LSQUIC_DF_PROGRESS_CHECK* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:350:9
  else:
    let LSQUIC_DF_PROGRESS_CHECK* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:350:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PROGRESS_CHECK" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_RW_ONCE):
  when 0 is static:
    const LSQUIC_DF_RW_ONCE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:353:9
  else:
    let LSQUIC_DF_RW_ONCE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:353:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_RW_ONCE" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_PROC_TIME_THRESH):
  when 0 is static:
    const LSQUIC_DF_PROC_TIME_THRESH* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:356:9
  else:
    let LSQUIC_DF_PROC_TIME_THRESH* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:356:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PROC_TIME_THRESH" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PACE_PACKETS):
  when 1 is static:
    const LSQUIC_DF_PACE_PACKETS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:359:9
  else:
    let LSQUIC_DF_PACE_PACKETS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:359:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PACE_PACKETS" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_CLOCK_GRANULARITY):
  when 1000 is static:
    const LSQUIC_DF_CLOCK_GRANULARITY* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:362:9
  else:
    let LSQUIC_DF_CLOCK_GRANULARITY* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:362:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_CLOCK_GRANULARITY" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_SCID_LEN):
  when 8 is static:
    const LSQUIC_DF_SCID_LEN* = 8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:365:9
  else:
    let LSQUIC_DF_SCID_LEN* = 8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:365:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_SCID_LEN" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_SCID_ISS_RATE):
  when 60 is static:
    const LSQUIC_DF_SCID_ISS_RATE* = 60
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:368:9
  else:
    let LSQUIC_DF_SCID_ISS_RATE* = 60
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:368:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_SCID_ISS_RATE" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QPACK_DEC_MAX_BLOCKED):
  when 100 is static:
    const LSQUIC_DF_QPACK_DEC_MAX_BLOCKED* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:370:9
  else:
    let LSQUIC_DF_QPACK_DEC_MAX_BLOCKED* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:370:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_QPACK_DEC_MAX_BLOCKED" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QPACK_DEC_MAX_SIZE):
  when 4096 is static:
    const LSQUIC_DF_QPACK_DEC_MAX_SIZE* = 4096
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:371:9
  else:
    let LSQUIC_DF_QPACK_DEC_MAX_SIZE* = 4096
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:371:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_QPACK_DEC_MAX_SIZE" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QPACK_ENC_MAX_BLOCKED):
  when 100 is static:
    const LSQUIC_DF_QPACK_ENC_MAX_BLOCKED* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:372:9
  else:
    let LSQUIC_DF_QPACK_ENC_MAX_BLOCKED* = 100
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:372:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_QPACK_ENC_MAX_BLOCKED" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QPACK_ENC_MAX_SIZE):
  when 4096 is static:
    const LSQUIC_DF_QPACK_ENC_MAX_SIZE* = 4096
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:373:9
  else:
    let LSQUIC_DF_QPACK_ENC_MAX_SIZE* = 4096
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:373:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_QPACK_ENC_MAX_SIZE" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QPACK_EXPERIMENT):
  when 0 is static:
    const LSQUIC_DF_QPACK_EXPERIMENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:376:9
  else:
    let LSQUIC_DF_QPACK_EXPERIMENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:376:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_QPACK_EXPERIMENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_ECN):
  when 0 is static:
    const LSQUIC_DF_ECN* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:379:9
  else:
    let LSQUIC_DF_ECN* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:379:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_ECN" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_ALLOW_MIGRATION):
  when 1 is static:
    const LSQUIC_DF_ALLOW_MIGRATION* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:382:9
  else:
    let LSQUIC_DF_ALLOW_MIGRATION* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:382:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_ALLOW_MIGRATION" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_RETRY_TOKEN_DURATION):
  when 10 is static:
    const LSQUIC_DF_RETRY_TOKEN_DURATION* = 10
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:385:9
  else:
    let LSQUIC_DF_RETRY_TOKEN_DURATION* = 10
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:385:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_RETRY_TOKEN_DURATION" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_QL_BITS):
  when 2 is static:
    const LSQUIC_DF_QL_BITS* = 2
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:388:9
  else:
    let LSQUIC_DF_QL_BITS* = 2
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:388:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_QL_BITS" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_SPIN):
  when 1 is static:
    const LSQUIC_DF_SPIN* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:391:9
  else:
    let LSQUIC_DF_SPIN* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:391:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_SPIN" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_DELAYED_ACKS):
  when 1 is static:
    const LSQUIC_DF_DELAYED_ACKS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:394:9
  else:
    let LSQUIC_DF_DELAYED_ACKS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:394:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_DELAYED_ACKS" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_PERIODICITY):
  when 3 is static:
    const LSQUIC_DF_PTPC_PERIODICITY* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:400:9
  else:
    let LSQUIC_DF_PTPC_PERIODICITY* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:400:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_PERIODICITY" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_MAX_PACKTOL):
  when 150 is static:
    const LSQUIC_DF_PTPC_MAX_PACKTOL* = 150
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:401:9
  else:
    let LSQUIC_DF_PTPC_MAX_PACKTOL* = 150
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:401:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_MAX_PACKTOL" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_DYN_TARGET):
  when 1 is static:
    const LSQUIC_DF_PTPC_DYN_TARGET* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:402:9
  else:
    let LSQUIC_DF_PTPC_DYN_TARGET* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:402:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_DYN_TARGET" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_TARGET):
  when 1.0 is static:
    const LSQUIC_DF_PTPC_TARGET* = 1.0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:403:9
  else:
    let LSQUIC_DF_PTPC_TARGET* = 1.0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:403:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_TARGET" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_PROP_GAIN):
  when 0.8 is static:
    const LSQUIC_DF_PTPC_PROP_GAIN* = 0.8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:404:9
  else:
    let LSQUIC_DF_PTPC_PROP_GAIN* = 0.8
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:404:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_PROP_GAIN" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_INT_GAIN):
  when 0.35 is static:
    const LSQUIC_DF_PTPC_INT_GAIN* = 0.35
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:405:9
  else:
    let LSQUIC_DF_PTPC_INT_GAIN* = 0.35
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:405:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_INT_GAIN" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_ERR_THRESH):
  when 0.05 is static:
    const LSQUIC_DF_PTPC_ERR_THRESH* = 0.05
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:406:9
  else:
    let LSQUIC_DF_PTPC_ERR_THRESH* = 0.05
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:406:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_ERR_THRESH" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_PTPC_ERR_DIVISOR):
  when 0.05 is static:
    const LSQUIC_DF_PTPC_ERR_DIVISOR* = 0.05
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:407:9
  else:
    let LSQUIC_DF_PTPC_ERR_DIVISOR* = 0.05
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:407:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_PTPC_ERR_DIVISOR" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_TIMESTAMPS):
  when 1 is static:
    const LSQUIC_DF_TIMESTAMPS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:410:9
  else:
    let LSQUIC_DF_TIMESTAMPS* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:410:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_TIMESTAMPS" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_AMP_FACTOR):
  when 3 is static:
    const LSQUIC_DF_AMP_FACTOR* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:413:9
  else:
    let LSQUIC_DF_AMP_FACTOR* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:413:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_AMP_FACTOR" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_CC_ALGO):
  when 3 is static:
    const LSQUIC_DF_CC_ALGO* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:416:9
  else:
    let LSQUIC_DF_CC_ALGO* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:416:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_CC_ALGO" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_CC_RTT_THRESH):
  when 1500 is static:
    const LSQUIC_DF_CC_RTT_THRESH* = 1500
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:419:9
  else:
    let LSQUIC_DF_CC_RTT_THRESH* = 1500
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:419:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_CC_RTT_THRESH" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_DATAGRAMS):
  when 0 is static:
    const LSQUIC_DF_DATAGRAMS* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:422:9
  else:
    let LSQUIC_DF_DATAGRAMS* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:422:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_DATAGRAMS" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_OPTIMISTIC_NAT):
  when 1 is static:
    const LSQUIC_DF_OPTIMISTIC_NAT* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:425:9
  else:
    let LSQUIC_DF_OPTIMISTIC_NAT* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:425:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_OPTIMISTIC_NAT" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_EXT_HTTP_PRIO):
  when 1 is static:
    const LSQUIC_DF_EXT_HTTP_PRIO* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:428:9
  else:
    let LSQUIC_DF_EXT_HTTP_PRIO* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:428:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_EXT_HTTP_PRIO" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX):
  when 0 is static:
    const LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:431:9
  else:
    let LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:431:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_GREASE_QUIC_BIT):
  when 1 is static:
    const LSQUIC_DF_GREASE_QUIC_BIT* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:437:9
  else:
    let LSQUIC_DF_GREASE_QUIC_BIT* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:437:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_GREASE_QUIC_BIT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_DPLPMTUD):
  when 1 is static:
    const LSQUIC_DF_DPLPMTUD* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:440:9
  else:
    let LSQUIC_DF_DPLPMTUD* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:440:9
else:
  static:
    hint("Declaration of " & "LSQUIC_DF_DPLPMTUD" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_BASE_PLPMTU):
  when 0 is static:
    const LSQUIC_DF_BASE_PLPMTU* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:443:9
  else:
    let LSQUIC_DF_BASE_PLPMTU* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:443:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_BASE_PLPMTU" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MAX_PLPMTU):
  when 0 is static:
    const LSQUIC_DF_MAX_PLPMTU* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:446:9
  else:
    let LSQUIC_DF_MAX_PLPMTU* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:446:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MAX_PLPMTU" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER):
  when 60 is static:
    const LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER* = 60
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:449:9
  else:
    let LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER* = 60
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:449:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT):
  when 0 is static:
    const LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:452:9
  else:
    let LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:452:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MTU_PROBE_TIMER):
  when 1000 is static:
    const LSQUIC_DF_MTU_PROBE_TIMER* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:455:9
  else:
    let LSQUIC_DF_MTU_PROBE_TIMER* = 1000
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:455:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MTU_PROBE_TIMER" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_DELAY_ONCLOSE):
  when 0 is static:
    const LSQUIC_DF_DELAY_ONCLOSE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:458:9
  else:
    let LSQUIC_DF_DELAY_ONCLOSE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:458:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_DELAY_ONCLOSE" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_MAX_BATCH_SIZE):
  when 0 is static:
    const LSQUIC_DF_MAX_BATCH_SIZE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:464:9
  else:
    let LSQUIC_DF_MAX_BATCH_SIZE* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:464:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_MAX_BATCH_SIZE" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DF_CHECK_TP_SANITY):
  when 1 is static:
    const LSQUIC_DF_CHECK_TP_SANITY* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:467:9
  else:
    let LSQUIC_DF_CHECK_TP_SANITY* = 1
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:467:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DF_CHECK_TP_SANITY" &
        " already exists, not redeclaring"
    )
when not declared(LSQUIC_MAX_HTTP_URGENCY):
  when 7 is static:
    const LSQUIC_MAX_HTTP_URGENCY* = 7
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1867:9
  else:
    let LSQUIC_MAX_HTTP_URGENCY* = 7
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1867:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_MAX_HTTP_URGENCY" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DEF_HTTP_URGENCY):
  when 3 is static:
    const LSQUIC_DEF_HTTP_URGENCY* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1868:9
  else:
    let LSQUIC_DEF_HTTP_URGENCY* = 3
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1868:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DEF_HTTP_URGENCY" & " already exists, not redeclaring"
    )
when not declared(LSQUIC_DEF_HTTP_INCREMENTAL):
  when 0 is static:
    const LSQUIC_DEF_HTTP_INCREMENTAL* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1869:9
  else:
    let LSQUIC_DEF_HTTP_INCREMENTAL* = 0
      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1869:9
else:
  static:
    hint(
      "Declaration of " & "LSQUIC_DEF_HTTP_INCREMENTAL" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_init_settings):
  proc lsquic_engine_init_settings*(
    a0: ptr struct_lsquic_engine_settings_570425839, lsquic_engine_flags: cuint
  ): void {.cdecl, importc: "lsquic_engine_init_settings".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_init_settings" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_check_settings):
  proc lsquic_engine_check_settings*(
    settings: ptr struct_lsquic_engine_settings_570425839,
    lsquic_engine_flags: cuint,
    err_buf: cstring,
    err_buf_sz: csize_t,
  ): cint {.cdecl, importc: "lsquic_engine_check_settings".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_check_settings" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_get_conns_count):
  proc lsquic_engine_get_conns_count*(
    engine: ptr lsquic_engine_t_570425815
  ): cuint {.cdecl, importc: "lsquic_engine_get_conns_count".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_get_conns_count" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_new):
  proc lsquic_engine_new*(
    lsquic_engine_flags: cuint, api: ptr struct_lsquic_engine_api_570425859
  ): ptr lsquic_engine_t_570425815 {.cdecl, importc: "lsquic_engine_new".}

else:
  static:
    hint("Declaration of " & "lsquic_engine_new" & " already exists, not redeclaring")
when not declared(lsquic_engine_connect):
  proc lsquic_engine_connect*(
    a0: ptr lsquic_engine_t_570425815,
    a1: enum_lsquic_version_570425829,
    local_sa: ptr SockAddr,
    peer_sa: ptr SockAddr,
    peer_ctx: pointer,
    conn_ctx: ptr lsquic_conn_ctx_t_570425819,
    hostname: cstring,
    base_plpmtu: cushort,
    sess_resume: ptr uint8,
    sess_resume_len: csize_t,
    token: ptr uint8,
    token_sz: csize_t,
  ): ptr lsquic_conn_t_570425817 {.cdecl, importc: "lsquic_engine_connect".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_connect" & " already exists, not redeclaring"
    )
when not declared(lsquic_engine_packet_in):
  proc lsquic_engine_packet_in*(
    a0: ptr lsquic_engine_t_570425815,
    packet_in_data: ptr uint8,
    packet_in_size: csize_t,
    sa_local: ptr SockAddr,
    sa_peer: ptr SockAddr,
    peer_ctx: pointer,
    ecn: cint,
  ): cint {.cdecl, importc: "lsquic_engine_packet_in".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_packet_in" & " already exists, not redeclaring"
    )
when not declared(lsquic_engine_process_conns):
  proc lsquic_engine_process_conns*(
    engine: ptr lsquic_engine_t_570425815
  ): void {.cdecl, importc: "lsquic_engine_process_conns".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_process_conns" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_has_unsent_packets):
  proc lsquic_engine_has_unsent_packets*(
    engine: ptr lsquic_engine_t_570425815
  ): cint {.cdecl, importc: "lsquic_engine_has_unsent_packets".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_has_unsent_packets" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_send_unsent_packets):
  proc lsquic_engine_send_unsent_packets*(
    engine: ptr lsquic_engine_t_570425815
  ): void {.cdecl, importc: "lsquic_engine_send_unsent_packets".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_send_unsent_packets" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_destroy):
  proc lsquic_engine_destroy*(
    a0: ptr lsquic_engine_t_570425815
  ): void {.cdecl, importc: "lsquic_engine_destroy".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_destroy" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_n_avail_streams):
  proc lsquic_conn_n_avail_streams*(
    a0: ptr lsquic_conn_t_570425817
  ): cuint {.cdecl, importc: "lsquic_conn_n_avail_streams".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_n_avail_streams" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_make_stream):
  proc lsquic_conn_make_stream*(
    a0: ptr lsquic_conn_t_570425817
  ): void {.cdecl, importc: "lsquic_conn_make_stream".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_make_stream" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_n_pending_streams):
  proc lsquic_conn_n_pending_streams*(
    a0: ptr lsquic_conn_t_570425817
  ): cuint {.cdecl, importc: "lsquic_conn_n_pending_streams".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_n_pending_streams" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_cancel_pending_streams):
  proc lsquic_conn_cancel_pending_streams*(
    a0: ptr lsquic_conn_t_570425817, n: cuint
  ): cuint {.cdecl, importc: "lsquic_conn_cancel_pending_streams".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_cancel_pending_streams" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_going_away):
  proc lsquic_conn_going_away*(
    a0: ptr lsquic_conn_t_570425817
  ): void {.cdecl, importc: "lsquic_conn_going_away".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_going_away" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_close):
  proc lsquic_conn_close*(
    a0: ptr lsquic_conn_t_570425817
  ): void {.cdecl, importc: "lsquic_conn_close".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_close" & " already exists, not redeclaring")
when not declared(lsquic_stream_wantread):
  proc lsquic_stream_wantread*(
    s: ptr lsquic_stream_t_570425821, is_want: cint
  ): cint {.cdecl, importc: "lsquic_stream_wantread".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_wantread" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_read):
  proc lsquic_stream_read*(
    s: ptr lsquic_stream_t_570425821, buf: pointer, len: csize_t
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_read".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_read" & " already exists, not redeclaring")
when not declared(lsquic_stream_readv):
  proc lsquic_stream_readv*(
    s: ptr lsquic_stream_t_570425821, vec: ptr struct_iovec_570425843, iovcnt: cint
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_readv".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_readv" & " already exists, not redeclaring")
when not declared(lsquic_stream_readf):
  proc lsquic_stream_readf*(
    s: ptr lsquic_stream_t_570425821,
    readf: proc(a0: pointer, a1: ptr uint8, a2: csize_t, a3: cint): csize_t {.cdecl.},
    ctx: pointer,
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_readf".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_readf" & " already exists, not redeclaring")
when not declared(lsquic_stream_wantwrite):
  proc lsquic_stream_wantwrite*(
    s: ptr lsquic_stream_t_570425821, is_want: cint
  ): cint {.cdecl, importc: "lsquic_stream_wantwrite".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_wantwrite" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_write):
  proc lsquic_stream_write*(
    s: ptr lsquic_stream_t_570425821, buf: pointer, len: csize_t
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_write".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_write" & " already exists, not redeclaring")
when not declared(lsquic_stream_writev):
  proc lsquic_stream_writev*(
    s: ptr lsquic_stream_t_570425821, vec: ptr struct_iovec_570425843, count: cint
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_writev".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_writev" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_pwritev):
  proc lsquic_stream_pwritev*(
    s: ptr lsquic_stream_t_570425821,
    preadv: proc(
      a0: pointer, a1: ptr struct_iovec_570425843, a2: cint
    ): ssize_t_570425835 {.cdecl.},
    user_data: pointer,
    n_to_write: csize_t,
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_pwritev".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_pwritev" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_writef):
  proc lsquic_stream_writef*(
    a0: ptr lsquic_stream_t_570425821, a1: ptr struct_lsquic_reader_570425861
  ): ssize_t_570425835 {.cdecl, importc: "lsquic_stream_writef".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_writef" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_flush):
  proc lsquic_stream_flush*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_flush".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_flush" & " already exists, not redeclaring")
when not declared(lsquic_stream_send_headers):
  proc lsquic_stream_send_headers*(
    s: ptr lsquic_stream_t_570425821,
    headers: ptr lsquic_http_headers_t_570425825,
    eos: cint,
  ): cint {.cdecl, importc: "lsquic_stream_send_headers".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_send_headers" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_get_hset):
  proc lsquic_stream_get_hset*(
    a0: ptr lsquic_stream_t_570425821
  ): pointer {.cdecl, importc: "lsquic_stream_get_hset".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_get_hset" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_push_stream):
  proc lsquic_conn_push_stream*(
    c: ptr lsquic_conn_t_570425817,
    hdr_set: pointer,
    s: ptr lsquic_stream_t_570425821,
    headers: ptr lsquic_http_headers_t_570425825,
  ): cint {.cdecl, importc: "lsquic_conn_push_stream".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_push_stream" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_is_push_enabled):
  proc lsquic_conn_is_push_enabled*(
    a0: ptr lsquic_conn_t_570425817
  ): cint {.cdecl, importc: "lsquic_conn_is_push_enabled".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_is_push_enabled" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_shutdown):
  proc lsquic_stream_shutdown*(
    s: ptr lsquic_stream_t_570425821, how: cint
  ): cint {.cdecl, importc: "lsquic_stream_shutdown".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_shutdown" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_close):
  proc lsquic_stream_close*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_close".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_close" & " already exists, not redeclaring")
when not declared(lsquic_stream_has_unacked_data):
  proc lsquic_stream_has_unacked_data*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_has_unacked_data".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_has_unacked_data" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_server_cert_chain):
  proc lsquic_conn_get_server_cert_chain*(
    a0: ptr lsquic_conn_t_570425817
  ): ptr struct_stack_st_X509 {.cdecl, importc: "lsquic_conn_get_server_cert_chain".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_server_cert_chain" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_full_cert_chain):
  proc lsquic_conn_get_full_cert_chain*(
    a0: ptr lsquic_conn_t_570425817
  ): ptr struct_stack_st_X509 {.cdecl, importc: "lsquic_conn_get_full_cert_chain".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_full_cert_chain" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_id):
  proc lsquic_stream_id*(
    s: ptr lsquic_stream_t_570425821
  ): lsquic_stream_id_t_570425813 {.cdecl, importc: "lsquic_stream_id".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_id" & " already exists, not redeclaring")
when not declared(lsquic_stream_get_ctx):
  proc lsquic_stream_get_ctx*(
    s: ptr lsquic_stream_t_570425821
  ): ptr lsquic_stream_ctx_t_570425823 {.cdecl, importc: "lsquic_stream_get_ctx".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_get_ctx" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_set_ctx):
  proc lsquic_stream_set_ctx*(
    stream: ptr lsquic_stream_t_570425821, ctx: ptr lsquic_stream_ctx_t_570425823
  ): void {.cdecl, importc: "lsquic_stream_set_ctx".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_set_ctx" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_is_pushed):
  proc lsquic_stream_is_pushed*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_is_pushed".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_is_pushed" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_is_rejected):
  proc lsquic_stream_is_rejected*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_is_rejected".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_is_rejected" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_refuse_push):
  proc lsquic_stream_refuse_push*(
    s: ptr lsquic_stream_t_570425821
  ): cint {.cdecl, importc: "lsquic_stream_refuse_push".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_refuse_push" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_push_info):
  proc lsquic_stream_push_info*(
    a0: ptr lsquic_stream_t_570425821,
    ref_stream_id: ptr lsquic_stream_id_t_570425813,
    hdr_set: ptr pointer,
  ): cint {.cdecl, importc: "lsquic_stream_push_info".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_push_info" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_priority):
  proc lsquic_stream_priority*(
    s: ptr lsquic_stream_t_570425821
  ): cuint {.cdecl, importc: "lsquic_stream_priority".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_priority" & " already exists, not redeclaring"
    )
when not declared(lsquic_stream_set_priority):
  proc lsquic_stream_set_priority*(
    s: ptr lsquic_stream_t_570425821, priority: cuint
  ): cint {.cdecl, importc: "lsquic_stream_set_priority".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_set_priority" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_get_http_prio):
  proc lsquic_stream_get_http_prio*(
    a0: ptr lsquic_stream_t_570425821, a1: ptr struct_lsquic_ext_http_prio_570425863
  ): cint {.cdecl, importc: "lsquic_stream_get_http_prio".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_get_http_prio" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_set_http_prio):
  proc lsquic_stream_set_http_prio*(
    a0: ptr lsquic_stream_t_570425821, a1: ptr struct_lsquic_ext_http_prio_570425863
  ): cint {.cdecl, importc: "lsquic_stream_set_http_prio".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_stream_set_http_prio" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_stream_conn):
  proc lsquic_stream_conn*(
    s: ptr lsquic_stream_t_570425821
  ): ptr lsquic_conn_t_570425817 {.cdecl, importc: "lsquic_stream_conn".}

else:
  static:
    hint("Declaration of " & "lsquic_stream_conn" & " already exists, not redeclaring")
when not declared(lsquic_conn_id):
  proc lsquic_conn_id*(
    c: ptr lsquic_conn_t_570425817
  ): ptr lsquic_cid_t_570425811 {.cdecl, importc: "lsquic_conn_id".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_id" & " already exists, not redeclaring")
when not declared(lsquic_conn_get_engine):
  proc lsquic_conn_get_engine*(
    c: ptr lsquic_conn_t_570425817
  ): ptr lsquic_engine_t_570425815 {.cdecl, importc: "lsquic_conn_get_engine".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_engine" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_sockaddr):
  proc lsquic_conn_get_sockaddr*(
    c: ptr lsquic_conn_t_570425817, local: ptr ptr SockAddr, peer: ptr ptr SockAddr
  ): cint {.cdecl, importc: "lsquic_conn_get_sockaddr".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_sockaddr" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_want_datagram_write):
  proc lsquic_conn_want_datagram_write*(
    a0: ptr lsquic_conn_t_570425817, is_want: cint
  ): cint {.cdecl, importc: "lsquic_conn_want_datagram_write".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_want_datagram_write" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_min_datagram_size):
  proc lsquic_conn_get_min_datagram_size*(
    a0: ptr lsquic_conn_t_570425817
  ): csize_t {.cdecl, importc: "lsquic_conn_get_min_datagram_size".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_min_datagram_size" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_set_min_datagram_size):
  proc lsquic_conn_set_min_datagram_size*(
    a0: ptr lsquic_conn_t_570425817, sz: csize_t
  ): cint {.cdecl, importc: "lsquic_conn_set_min_datagram_size".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_set_min_datagram_size" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_logger_init):
  proc lsquic_logger_init*(
    a0: ptr struct_lsquic_logger_if_570425865,
    logger_ctx: pointer,
    a2: enum_lsquic_logger_timestamp_style_570425867,
  ): void {.cdecl, importc: "lsquic_logger_init".}

else:
  static:
    hint("Declaration of " & "lsquic_logger_init" & " already exists, not redeclaring")
when not declared(lsquic_set_log_level):
  proc lsquic_set_log_level*(
    log_level: cstring
  ): cint {.cdecl, importc: "lsquic_set_log_level".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_set_log_level" & " already exists, not redeclaring"
    )
when not declared(lsquic_logger_lopt):
  proc lsquic_logger_lopt*(
    optarg: cstring
  ): cint {.cdecl, importc: "lsquic_logger_lopt".}

else:
  static:
    hint("Declaration of " & "lsquic_logger_lopt" & " already exists, not redeclaring")
when not declared(lsquic_engine_quic_versions):
  proc lsquic_engine_quic_versions*(
    a0: ptr lsquic_engine_t_570425815
  ): cuint {.cdecl, importc: "lsquic_engine_quic_versions".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_quic_versions" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_global_init):
  proc lsquic_global_init*(flags: cint): cint {.cdecl, importc: "lsquic_global_init".}
else:
  static:
    hint("Declaration of " & "lsquic_global_init" & " already exists, not redeclaring")
when not declared(lsquic_global_cleanup):
  proc lsquic_global_cleanup*(): void {.cdecl, importc: "lsquic_global_cleanup".}
else:
  static:
    hint(
      "Declaration of " & "lsquic_global_cleanup" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_quic_version):
  proc lsquic_conn_quic_version*(
    c: ptr lsquic_conn_t_570425817
  ): enum_lsquic_version_570425829 {.cdecl, importc: "lsquic_conn_quic_version".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_quic_version" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_crypto_keysize):
  proc lsquic_conn_crypto_keysize*(
    c: ptr lsquic_conn_t_570425817
  ): cint {.cdecl, importc: "lsquic_conn_crypto_keysize".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_crypto_keysize" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_crypto_alg_keysize):
  proc lsquic_conn_crypto_alg_keysize*(
    c: ptr lsquic_conn_t_570425817
  ): cint {.cdecl, importc: "lsquic_conn_crypto_alg_keysize".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_crypto_alg_keysize" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_conn_crypto_ver):
  proc lsquic_conn_crypto_ver*(
    c: ptr lsquic_conn_t_570425817
  ): enum_lsquic_crypto_ver_570425876 {.cdecl, importc: "lsquic_conn_crypto_ver".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_crypto_ver" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_crypto_cipher):
  proc lsquic_conn_crypto_cipher*(
    c: ptr lsquic_conn_t_570425817
  ): cstring {.cdecl, importc: "lsquic_conn_crypto_cipher".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_crypto_cipher" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_str2ver):
  proc lsquic_str2ver*(
    str: cstring, len: csize_t
  ): enum_lsquic_version_570425829 {.cdecl, importc: "lsquic_str2ver".}

else:
  static:
    hint("Declaration of " & "lsquic_str2ver" & " already exists, not redeclaring")
when not declared(lsquic_alpn2ver):
  proc lsquic_alpn2ver*(
    alpn: cstring, len: csize_t
  ): enum_lsquic_version_570425829 {.cdecl, importc: "lsquic_alpn2ver".}

else:
  static:
    hint("Declaration of " & "lsquic_alpn2ver" & " already exists, not redeclaring")
when not declared(lsquic_engine_cooldown):
  proc lsquic_engine_cooldown*(
    a0: ptr lsquic_engine_t_570425815
  ): void {.cdecl, importc: "lsquic_engine_cooldown".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_cooldown" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_ctx):
  proc lsquic_conn_get_ctx*(
    a0: ptr lsquic_conn_t_570425817
  ): ptr lsquic_conn_ctx_t_570425819 {.cdecl, importc: "lsquic_conn_get_ctx".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_get_ctx" & " already exists, not redeclaring")
when not declared(lsquic_conn_set_ctx):
  proc lsquic_conn_set_ctx*(
    a0: ptr lsquic_conn_t_570425817, a1: ptr lsquic_conn_ctx_t_570425819
  ): void {.cdecl, importc: "lsquic_conn_set_ctx".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_set_ctx" & " already exists, not redeclaring")
when not declared(lsquic_conn_get_peer_ctx):
  proc lsquic_conn_get_peer_ctx*(
    a0: ptr lsquic_conn_t_570425817, local_sa: ptr SockAddr
  ): pointer {.cdecl, importc: "lsquic_conn_get_peer_ctx".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_peer_ctx" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_get_sni):
  proc lsquic_conn_get_sni*(
    a0: ptr lsquic_conn_t_570425817
  ): cstring {.cdecl, importc: "lsquic_conn_get_sni".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_get_sni" & " already exists, not redeclaring")
when not declared(lsquic_conn_abort):
  proc lsquic_conn_abort*(
    a0: ptr lsquic_conn_t_570425817
  ): void {.cdecl, importc: "lsquic_conn_abort".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_abort" & " already exists, not redeclaring")
when not declared(lsquic_conn_get_info):
  proc lsquic_conn_get_info*(
    conn: ptr lsquic_conn_t_570425817, info: ptr struct_lsquic_conn_info_570425878
  ): cint {.cdecl, importc: "lsquic_conn_get_info".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_conn_get_info" & " already exists, not redeclaring"
    )
when not declared(lsquic_get_alt_svc_versions):
  proc lsquic_get_alt_svc_versions*(
    versions: cuint
  ): cstring {.cdecl, importc: "lsquic_get_alt_svc_versions".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_get_alt_svc_versions" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_get_h3_alpns):
  proc lsquic_get_h3_alpns*(
    versions: cuint
  ): ptr cstring {.cdecl, importc: "lsquic_get_h3_alpns".}

else:
  static:
    hint("Declaration of " & "lsquic_get_h3_alpns" & " already exists, not redeclaring")
when not declared(lsquic_is_valid_hs_packet):
  proc lsquic_is_valid_hs_packet*(
    a0: ptr lsquic_engine_t_570425815, a1: ptr uint8, a2: csize_t
  ): cint {.cdecl, importc: "lsquic_is_valid_hs_packet".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_is_valid_hs_packet" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_cid_from_packet):
  proc lsquic_cid_from_packet*(
    a0: ptr uint8, bufsz: csize_t, cid: ptr lsquic_cid_t_570425811
  ): cint {.cdecl, importc: "lsquic_cid_from_packet".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_cid_from_packet" & " already exists, not redeclaring"
    )
when not declared(lsquic_dcid_from_packet):
  proc lsquic_dcid_from_packet*(
    a0: ptr uint8, bufsz: csize_t, server_cid_len: cuint, cid_len: ptr uint8
  ): cint {.cdecl, importc: "lsquic_dcid_from_packet".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_dcid_from_packet" & " already exists, not redeclaring"
    )
when not declared(lsquic_engine_earliest_adv_tick):
  proc lsquic_engine_earliest_adv_tick*(
    engine: ptr lsquic_engine_t_570425815, diff: ptr cint
  ): cint {.cdecl, importc: "lsquic_engine_earliest_adv_tick".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_earliest_adv_tick" &
        " already exists, not redeclaring"
    )
when not declared(lsquic_engine_count_attq):
  proc lsquic_engine_count_attq*(
    engine: ptr lsquic_engine_t_570425815, from_now: cint
  ): cuint {.cdecl, importc: "lsquic_engine_count_attq".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_engine_count_attq" & " already exists, not redeclaring"
    )
when not declared(lsquic_conn_status):
  proc lsquic_conn_status*(
    a0: ptr lsquic_conn_t_570425817, errbuf: cstring, bufsz: csize_t
  ): enum_LSQUIC_CONN_STATUS_570425880 {.cdecl, importc: "lsquic_conn_status".}

else:
  static:
    hint("Declaration of " & "lsquic_conn_status" & " already exists, not redeclaring")
when not declared(lsquic_ver2str):
  var lsquic_ver2str* {.importc: "lsquic_ver2str".}: array[8'i64, cstring]
else:
  static:
    hint("Declaration of " & "lsquic_ver2str" & " already exists, not redeclaring")
when not declared(lsquic_ssl_to_conn):
  proc lsquic_ssl_to_conn*(
    a0: ptr struct_ssl_st
  ): ptr lsquic_conn_t_570425817 {.cdecl, importc: "lsquic_ssl_to_conn".}

else:
  static:
    hint("Declaration of " & "lsquic_ssl_to_conn" & " already exists, not redeclaring")
when not declared(lsquic_ssl_sess_to_resume_info):
  proc lsquic_ssl_sess_to_resume_info*(
    a0: ptr struct_ssl_st,
    a1: ptr struct_ssl_session_st,
    buf: ptr ptr uint8,
    buf_sz: ptr csize_t,
  ): cint {.cdecl, importc: "lsquic_ssl_sess_to_resume_info".}

else:
  static:
    hint(
      "Declaration of " & "lsquic_ssl_sess_to_resume_info" &
        " already exists, not redeclaring"
    )
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH 

const
  LSQUIC_GLOBAL_CLIENT* = (1 shl 0)
  LSQUIC_GLOBAL_SERVER* = (1 shl 1)

# Engine modes
const
  LSENG_SERVER* = (1 shl 0)
  LSENG_HTTP* = (1 shl 1)
  LSENG_HTTP_SERVER* = (LSENG_SERVER or LSENG_HTTP)
