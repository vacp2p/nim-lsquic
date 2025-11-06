import os
import strformat, strutils
import ./boringssl
import zlib

# Socket definitions
import nativesockets

type ptrdiff_t* {.importc: "ptrdiff_t", header: "<stddef.h>".} = int

{.passc: "-include stddef.h".}
{.passc: "-DXXH_HEADER_NAME=\\\"lsquic_xxhash.h\\\"".}

const root = currentSourcePath.parentDir
const lsquicInclude = root / "libs/lsquic/include"
const boringsslInclude = root / "libs/boringssl/include"
const liblsquicInclude = root / "libs/lsquic/src/liblsquic"
const lsqpack = root / "libs/lsquic/src/liblsquic/ls-qpack"
const lshpack = root / "libs/lsquic/src/lshpack"
const xxhash = root / "libs/lsquic/src/lshpack/deps/xxhash"

{.passc: fmt"-I{lsquicInclude}".}
{.passc: fmt"-I{boringsslInclude}".}
{.passc: fmt"-I{liblsquicInclude}".}
{.passc: fmt"-I{lsqpack}".}
{.passc: fmt"-I{lshpack}".}
{.passc: fmt"-I{xxhash}".}

{.passc: "-DHAVE_BORINGSSL".}

{.compile: "./libs/lsquic/src/liblsquic/lsquic_xxhash.c".}
{.compile: "./libs/lsquic/src/liblsquic/ls-qpack/lsqpack.c".}
{.compile: "./libs/lsquic/src/lshpack/lshpack.c".}
{.compile: "./libs/lsquic/src/liblsquic/ls-sfparser.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_adaptive_cc.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_alarmset.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_arr.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_attq.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_bbr.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_bw_sampler.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_cfcw.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_chsk_stream.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_conn.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_crand.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_crt_compress.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_crypto.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_cubic.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_di_error.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_di_hash.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_di_nocopy.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_enc_sess_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_enc_sess_ietf.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_eng_hist.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_engine.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_ev_log.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_frab_list.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_frame_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_frame_reader.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_frame_writer.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_full_conn.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_full_conn_ietf.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_global.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_handshake.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hash.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hcsi_reader.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hcso_writer.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_headers_stream.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hkdf.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hpi.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_hspack_valid.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_http.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_http1x_if.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_logger.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_malo.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_min_heap.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_mini_conn.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_mini_conn_ietf.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_minmax.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_mm.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_pacer.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_packet_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_packet_gquic.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_packet_in.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_packet_out.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_packet_resize.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_Q046.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_Q050.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_gquic_be.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_gquic_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_ietf_v1.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_parse_iquic_common.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_pr_queue.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_purga.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_qdec_hdl.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_qenc_hdl.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_qlog.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_qpack_exp.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_rechist.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_rtt.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_send_ctl.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_senhist.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_set.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_sfcw.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_shsk_stream.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_spi.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_stock_shi.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_str.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_stream.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_tokgen.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_trans_params.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_trechist.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_util.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_varint.c".}
{.compile: "./libs/lsquic/src/liblsquic/lsquic_version.c".}

{.warning[UnusedImport]: off.}
{.hint[XDeclaredButNotUsed]: off.}
from macros import hint, warning, newLit, getSize

from os import parentDir

when not declared(ownSizeOf):
  macro ownSizeof(x: typed): untyped =
    newLit(x.getSize)

when not declared(SSL_CT_VALIDATION_PERMISSIVE):
  const
    SSL_CT_VALIDATION_PERMISSIVE* = cuint(0)
else:
  static :
    hint("Declaration of " & "SSL_CT_VALIDATION_PERMISSIVE" &
        " already exists, not redeclaring")
when not declared(SSL_CT_VALIDATION_STRICT):
  const
    SSL_CT_VALIDATION_STRICT* = cuint(1)
else:
  static :
    hint("Declaration of " & "SSL_CT_VALIDATION_STRICT" &
        " already exists, not redeclaring")
type
  enum_lsquic_version_536871422* {.size: sizeof(cuint).} = enum
    LSQVER_043 = 0, LSQVER_046 = 1, LSQVER_050 = 2, LSQVER_ID27 = 3,
    LSQVER_ID29 = 4, LSQVER_I001 = 5, LSQVER_I002 = 6, LSQVER_RESVED = 7,
    N_LSQVER = 8, LSQVER_VERNEG = 9
type
  enum_lsquic_hsk_status_536871424* {.size: sizeof(cuint).} = enum
    LSQ_HSK_FAIL = 0, LSQ_HSK_OK = 1, LSQ_HSK_RESUMED_OK = 2,
    LSQ_HSK_RESUMED_FAIL = 3
type
  enum_lsquic_hsi_flag_536871448* {.size: sizeof(cuint).} = enum
    LSQUIC_HSI_HTTP1X = 2, LSQUIC_HSI_HASH_NAME = 4, LSQUIC_HSI_HASH_NAMEVAL = 8
type
  enum_lsquic_logger_timestamp_style_536871467* {.size: sizeof(cuint).} = enum
    LLTS_NONE = 0, LLTS_HHMMSSMS = 1, LLTS_YYYYMMDD_HHMMSSMS = 2,
    LLTS_CHROMELIKE = 3, LLTS_HHMMSSUS = 4, LLTS_YYYYMMDD_HHMMSSUS = 5,
    N_LLTS = 6
type
  enum_lsquic_crypto_ver_536871469* {.size: sizeof(cuint).} = enum
    LSQ_CRY_QUIC = 0, LSQ_CRY_TLSv13 = 1
type
  enum_LSQUIC_CONN_STATUS_536871473* {.size: sizeof(cuint).} = enum
    LSCONN_ST_HSK_IN_PROGRESS = 0, LSCONN_ST_CONNECTED = 1,
    LSCONN_ST_HSK_FAILURE = 2, LSCONN_ST_GOING_AWAY = 3,
    LSCONN_ST_TIMED_OUT = 4, LSCONN_ST_RESET = 5, LSCONN_ST_USER_ABORTED = 6,
    LSCONN_ST_ERROR = 7, LSCONN_ST_CLOSED = 8, LSCONN_ST_PEER_GOING_AWAY = 9,
    LSCONN_ST_VERNEG_FAILURE = 10
type
  enum_OSSL_HANDSHAKE_STATE_536871761* {.size: sizeof(cuint).} = enum
    TLS_ST_BEFORE = 0, TLS_ST_OK = 1, DTLS_ST_CR_HELLO_VERIFY_REQUEST = 2,
    TLS_ST_CR_SRVR_HELLO = 3, TLS_ST_CR_CERT = 4, TLS_ST_CR_CERT_STATUS = 5,
    TLS_ST_CR_KEY_EXCH = 6, TLS_ST_CR_CERT_REQ = 7, TLS_ST_CR_SRVR_DONE = 8,
    TLS_ST_CR_SESSION_TICKET = 9, TLS_ST_CR_CHANGE = 10,
    TLS_ST_CR_FINISHED = 11, TLS_ST_CW_CLNT_HELLO = 12, TLS_ST_CW_CERT = 13,
    TLS_ST_CW_KEY_EXCH = 14, TLS_ST_CW_CERT_VRFY = 15, TLS_ST_CW_CHANGE = 16,
    TLS_ST_CW_NEXT_PROTO = 17, TLS_ST_CW_FINISHED = 18,
    TLS_ST_SW_HELLO_REQ = 19, TLS_ST_SR_CLNT_HELLO = 20,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST = 21, TLS_ST_SW_SRVR_HELLO = 22,
    TLS_ST_SW_CERT = 23, TLS_ST_SW_KEY_EXCH = 24, TLS_ST_SW_CERT_REQ = 25,
    TLS_ST_SW_SRVR_DONE = 26, TLS_ST_SR_CERT = 27, TLS_ST_SR_KEY_EXCH = 28,
    TLS_ST_SR_CERT_VRFY = 29, TLS_ST_SR_NEXT_PROTO = 30, TLS_ST_SR_CHANGE = 31,
    TLS_ST_SR_FINISHED = 32, TLS_ST_SW_SESSION_TICKET = 33,
    TLS_ST_SW_CERT_STATUS = 34, TLS_ST_SW_CHANGE = 35, TLS_ST_SW_FINISHED = 36,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS = 37, TLS_ST_CR_ENCRYPTED_EXTENSIONS = 38,
    TLS_ST_CR_CERT_VRFY = 39, TLS_ST_SW_CERT_VRFY = 40,
    TLS_ST_CR_HELLO_REQ = 41, TLS_ST_SW_KEY_UPDATE = 42,
    TLS_ST_CW_KEY_UPDATE = 43, TLS_ST_SR_KEY_UPDATE = 44,
    TLS_ST_CR_KEY_UPDATE = 45, TLS_ST_EARLY_DATA = 46,
    TLS_ST_PENDING_EARLY_DATA_END = 47, TLS_ST_CW_END_OF_EARLY_DATA = 48,
    TLS_ST_SR_END_OF_EARLY_DATA = 49
when not declared(struct_lsxpack_header):
  type
    struct_lsxpack_header* = object
else:
  static :
    hint("Declaration of " & "struct_lsxpack_header" &
        " already exists, not redeclaring")
when not declared(struct_ossl_lib_ctx_st):
  type
    struct_ossl_lib_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_ossl_lib_ctx_st" &
        " already exists, not redeclaring")
when not declared(OPENSSL_VERSION_NUMBER):
  type
    OPENSSL_VERSION_NUMBER* = object
else:
  static :
    hint("Declaration of " & "OPENSSL_VERSION_NUMBER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SFCW_CLIENT):
  type
    LSQUIC_DF_SFCW_CLIENT* = object
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SFCW_CLIENT" &
        " already exists, not redeclaring")
when not declared(SSL_get_shared_group):
  type
    SSL_get_shared_group* = object
else:
  static :
    hint("Declaration of " & "SSL_get_shared_group" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_stream_ctx):
  type
    struct_lsquic_stream_ctx* = object
else:
  static :
    hint("Declaration of " & "struct_lsquic_stream_ctx" &
        " already exists, not redeclaring")
when not declared(struct_ssl_session_st):
  type
    struct_ssl_session_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_session_st" &
        " already exists, not redeclaring")
when not declared(struct_sockaddr):
  type
    struct_sockaddr* = object
else:
  static :
    hint("Declaration of " & "struct_sockaddr" &
        " already exists, not redeclaring")
when not declared(SSL_set1_groups_list):
  type
    SSL_set1_groups_list* = object
else:
  static :
    hint("Declaration of " & "SSL_set1_groups_list" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_ASN1_TYPE):
  type
    struct_stack_st_ASN1_TYPE* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_ASN1_TYPE" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_stream):
  type
    struct_lsquic_stream* = object
else:
  static :
    hint("Declaration of " & "struct_lsquic_stream" &
        " already exists, not redeclaring")
when not declared(struct_bio_st):
  type
    struct_bio_st* = object
else:
  static :
    hint("Declaration of " & "struct_bio_st" &
        " already exists, not redeclaring")
when not declared(SSL_set1_groups):
  type
    SSL_set1_groups* = object
else:
  static :
    hint("Declaration of " & "SSL_set1_groups" &
        " already exists, not redeclaring")
when not declared(struct_ssl_cipher_st):
  type
    struct_ssl_cipher_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_cipher_st" &
        " already exists, not redeclaring")
when not declared(struct_rsa_st):
  type
    struct_rsa_st* = object
else:
  static :
    hint("Declaration of " & "struct_rsa_st" &
        " already exists, not redeclaring")
when not declared(struct_asn1_pctx_st):
  type
    struct_asn1_pctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_asn1_pctx_st" &
        " already exists, not redeclaring")
when not declared(struct_asn1_sctx_st):
  type
    struct_asn1_sctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_asn1_sctx_st" &
        " already exists, not redeclaring")
when not declared(struct_engine_st):
  type
    struct_engine_st* = object
else:
  static :
    hint("Declaration of " & "struct_engine_st" &
        " already exists, not redeclaring")
when not declared(struct_ssl_dane_st):
  type
    struct_ssl_dane_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_dane_st" &
        " already exists, not redeclaring")
when not declared(struct_IO_wide_data):
  type
    struct_IO_wide_data* = object
else:
  static :
    hint("Declaration of " & "struct_IO_wide_data" &
        " already exists, not redeclaring")
when not declared(struct_ASN1_ITEM_st):
  type
    struct_ASN1_ITEM_st* = object
else:
  static :
    hint("Declaration of " & "struct_ASN1_ITEM_st" &
        " already exists, not redeclaring")
when not declared(struct_x509_store_ctx_st):
  type
    struct_x509_store_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_x509_store_ctx_st" &
        " already exists, not redeclaring")
when not declared(union_bio_addr_st):
  type
    union_bio_addr_st* = object
else:
  static :
    hint("Declaration of " & "union_bio_addr_st" &
        " already exists, not redeclaring")
when not declared(struct_bignum_st):
  type
    struct_bignum_st* = object
else:
  static :
    hint("Declaration of " & "struct_bignum_st" &
        " already exists, not redeclaring")
when not declared(struct_comp_method_st):
  type
    struct_comp_method_st* = object
else:
  static :
    hint("Declaration of " & "struct_comp_method_st" &
        " already exists, not redeclaring")
when not declared(struct_ASN1_TLC_st):
  type
    struct_ASN1_TLC_st* = object
else:
  static :
    hint("Declaration of " & "struct_ASN1_TLC_st" &
        " already exists, not redeclaring")
when not declared(struct_v3_ext_ctx):
  type
    struct_v3_ext_ctx* = object
else:
  static :
    hint("Declaration of " & "struct_v3_ext_ctx" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_engine):
  type
    struct_lsquic_engine* = object
else:
  static :
    hint("Declaration of " & "struct_lsquic_engine" &
        " already exists, not redeclaring")
when not declared(struct_x509_store_st):
  type
    struct_x509_store_st* = object
else:
  static :
    hint("Declaration of " & "struct_x509_store_st" &
        " already exists, not redeclaring")
when not declared(struct_x509_st):
  type
    struct_x509_st* = object
else:
  static :
    hint("Declaration of " & "struct_x509_st" &
        " already exists, not redeclaring")
when not declared(struct_ctlog_store_st):
  type
    struct_ctlog_store_st* = object
else:
  static :
    hint("Declaration of " & "struct_ctlog_store_st" &
        " already exists, not redeclaring")
when not declared(struct_evp_md_st):
  type
    struct_evp_md_st* = object
else:
  static :
    hint("Declaration of " & "struct_evp_md_st" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_groups_list):
  type
    SSL_CTX_set1_groups_list* = object
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_groups_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_groups):
  type
    SSL_CTX_set1_groups* = object
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_groups" &
        " already exists, not redeclaring")
when not declared(struct_dh_st):
  type
    struct_dh_st* = object
else:
  static :
    hint("Declaration of " & "struct_dh_st" & " already exists, not redeclaring")
when not declared(struct_bio_method_st):
  type
    struct_bio_method_st* = object
else:
  static :
    hint("Declaration of " & "struct_bio_method_st" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CFCW_CLIENT):
  type
    LSQUIC_DF_CFCW_CLIENT* = object
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CFCW_CLIENT" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_conn):
  type
    struct_lsquic_conn* = object
else:
  static :
    hint("Declaration of " & "struct_lsquic_conn" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_conn_ctx):
  type
    struct_lsquic_conn_ctx* = object
else:
  static :
    hint("Declaration of " & "struct_lsquic_conn_ctx" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_void):
  type
    struct_stack_st_void* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_void" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_X509_ALGOR):
  type
    struct_stack_st_X509_ALGOR* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_X509_ALGOR" &
        " already exists, not redeclaring")
when not declared(struct_ossl_core_handle_st):
  type
    struct_ossl_core_handle_st* = object
else:
  static :
    hint("Declaration of " & "struct_ossl_core_handle_st" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_SSL_COMP):
  type
    struct_stack_st_SSL_COMP* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_SSL_COMP" &
        " already exists, not redeclaring")
when not declared(struct_ssl_method_st):
  type
    struct_ssl_method_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_method_st" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SFCW_SERVER):
  type
    LSQUIC_DF_SFCW_SERVER* = object
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SFCW_SERVER" &
        " already exists, not redeclaring")
when not declared(struct_ASN1_TEMPLATE_st):
  type
    struct_ASN1_TEMPLATE_st* = object
else:
  static :
    hint("Declaration of " & "struct_ASN1_TEMPLATE_st" &
        " already exists, not redeclaring")
when not declared(struct_IO_codecvt):
  type
    struct_IO_codecvt* = object
else:
  static :
    hint("Declaration of " & "struct_IO_codecvt" &
        " already exists, not redeclaring")
when not declared(struct_ssl_st):
  type
    struct_ssl_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_st" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_SCT):
  type
    struct_stack_st_SCT* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_SCT" &
        " already exists, not redeclaring")
when not declared(struct_evp_rand_ctx_st):
  type
    struct_evp_rand_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_evp_rand_ctx_st" &
        " already exists, not redeclaring")
when not declared(struct_ssl_comp_st):
  type
    struct_ssl_comp_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_comp_st" &
        " already exists, not redeclaring")
when not declared(struct_tls_sigalgs_st):
  type
    struct_tls_sigalgs_st* = object
else:
  static :
    hint("Declaration of " & "struct_tls_sigalgs_st" &
        " already exists, not redeclaring")
when not declared(SSL_get1_groups):
  type
    SSL_get1_groups* = object
else:
  static :
    hint("Declaration of " & "SSL_get1_groups" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CFCW_SERVER):
  type
    LSQUIC_DF_CFCW_SERVER* = object
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CFCW_SERVER" &
        " already exists, not redeclaring")
when not declared(struct_ct_policy_eval_ctx_st):
  type
    struct_ct_policy_eval_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_ct_policy_eval_ctx_st" &
        " already exists, not redeclaring")
when not declared(struct_evp_pkey_st):
  type
    struct_evp_pkey_st* = object
else:
  static :
    hint("Declaration of " & "struct_evp_pkey_st" &
        " already exists, not redeclaring")
when not declared(struct_ASN1_VALUE_st):
  type
    struct_ASN1_VALUE_st* = object
else:
  static :
    hint("Declaration of " & "struct_ASN1_VALUE_st" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_X509):
  type
    struct_stack_st_X509* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_X509" &
        " already exists, not redeclaring")
when not declared(struct_openssl_ssl_test_functions):
  type
    struct_openssl_ssl_test_functions* = object
else:
  static :
    hint("Declaration of " & "struct_openssl_ssl_test_functions" &
        " already exists, not redeclaring")
when not declared(struct_stack_st):
  type
    struct_stack_st* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st" &
        " already exists, not redeclaring")
when not declared(struct_X509_VERIFY_PARAM_st):
  type
    struct_X509_VERIFY_PARAM_st* = object
else:
  static :
    hint("Declaration of " & "struct_X509_VERIFY_PARAM_st" &
        " already exists, not redeclaring")
when not declared(struct_ssl_conf_ctx_st):
  type
    struct_ssl_conf_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_conf_ctx_st" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_SSL_CIPHER):
  type
    struct_stack_st_SSL_CIPHER* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_SSL_CIPHER" &
        " already exists, not redeclaring")
when not declared(struct_stack_st_X509_NAME):
  type
    struct_stack_st_X509_NAME* = object
else:
  static :
    hint("Declaration of " & "struct_stack_st_X509_NAME" &
        " already exists, not redeclaring")
when not declared(struct_ssl_ctx_st):
  type
    struct_ssl_ctx_st* = object
else:
  static :
    hint("Declaration of " & "struct_ssl_ctx_st" &
        " already exists, not redeclaring")
when not declared(struct_asn1_object_st):
  type
    struct_asn1_object_st* = object
else:
  static :
    hint("Declaration of " & "struct_asn1_object_st" &
        " already exists, not redeclaring")
when not declared(struct_lhash_st_SSL_SESSION):
  type
    struct_lhash_st_SSL_SESSION* = object
else:
  static :
    hint("Declaration of " & "struct_lhash_st_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(struct_ossl_init_settings_st):
  type
    struct_ossl_init_settings_st* = object
else:
  static :
    hint("Declaration of " & "struct_ossl_init_settings_st" &
        " already exists, not redeclaring")
when not declared(buf):
  type
    buf* = object
else:
  static :
    hint("Declaration of " & "buf" & " already exists, not redeclaring")
when not declared(struct_IO_marker):
  type
    struct_IO_marker* = object
else:
  static :
    hint("Declaration of " & "struct_IO_marker" &
        " already exists, not redeclaring")
type
  struct_lsquic_cid_536871400 {.pure, inheritable, bycopy.} = object
    buf* {.align(8'i64).}: array[20'i64, uint8] ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:27:28
    len* {.align(8'i64).}: uint_fast8_t_536871403
  uint_fast8_t_536871402 = uint8 ## Generated based on /usr/include/stdint.h:60:24
  lsquic_cid_t_536871404 = struct_lsquic_cid_536871401 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:32:3
  lsquic_stream_id_t_536871406 = uint64 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:40:18
  lsquic_engine_t_536871408 = struct_lsquic_engine ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:43:30
  lsquic_conn_t_536871410 = struct_lsquic_conn ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:46:28
  lsquic_conn_ctx_t_536871412 = struct_lsquic_conn_ctx ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:49:32
  lsquic_stream_t_536871414 = struct_lsquic_stream ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:52:30
  lsquic_stream_ctx_t_536871416 = struct_lsquic_stream_ctx ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:55:34
  lsquic_http_headers_t_536871418 = struct_lsquic_http_headers_536871421 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:58:36
  struct_lsquic_http_headers_536871420 {.pure, inheritable, bycopy.} = object
    count*: cint             ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1714:8
    headers*: ptr struct_lsxpack_header
  struct_lsquic_stream_if_536871426 {.pure, inheritable, bycopy.} = object
    on_new_conn*: proc (a0: pointer; a1: ptr lsquic_conn_t_536871411): ptr lsquic_conn_ctx_t_536871413 {.
        cdecl.}              ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:163:8
    on_goaway_received*: proc (a0: ptr lsquic_conn_t_536871411): void {.cdecl.}
    on_conn_closed*: proc (a0: ptr lsquic_conn_t_536871411): void {.cdecl.}
    on_new_stream*: proc (a0: pointer; a1: ptr lsquic_stream_t_536871415): ptr lsquic_stream_ctx_t_536871417 {.
        cdecl.}
    on_read*: proc (a0: ptr lsquic_stream_t_536871415;
                    a1: ptr lsquic_stream_ctx_t_536871417): void {.cdecl.}
    on_write*: proc (a0: ptr lsquic_stream_t_536871415;
                     a1: ptr lsquic_stream_ctx_t_536871417): void {.cdecl.}
    on_close*: proc (a0: ptr lsquic_stream_t_536871415;
                     a1: ptr lsquic_stream_ctx_t_536871417): void {.cdecl.}
    on_dg_write*: proc (a0: ptr lsquic_conn_t_536871411; a1: pointer;
                        a2: csize_t): ssize_t_536871429 {.cdecl.}
    on_datagram*: proc (a0: ptr lsquic_conn_t_536871411; a1: pointer;
                        a2: csize_t): void {.cdecl.}
    on_hsk_done*: proc (a0: ptr lsquic_conn_t_536871411;
                        a1: enum_lsquic_hsk_status_536871425): void {.cdecl.}
    on_new_token*: proc (a0: ptr lsquic_conn_t_536871411; a1: ptr uint8;
                         a2: csize_t): void {.cdecl.}
    on_sess_resume_info*: proc (a0: ptr lsquic_conn_t_536871411; a1: ptr uint8;
                                a2: csize_t): void {.cdecl.}
    on_reset*: proc (a0: ptr lsquic_stream_t_536871415;
                     a1: ptr lsquic_stream_ctx_t_536871417; a2: cint): void {.
        cdecl.}
    on_conncloseframe_received*: proc (a0: ptr lsquic_conn_t_536871411;
                                       a1: cint; a2: uint64; a3: cstring;
                                       a4: cint): void {.cdecl.}
  ssize_t_536871428 = compiler_ssize_t_536871813 ## Generated based on /usr/include/x86_64-linux-gnu/sys/types.h:108:19
  lsquic_lookup_cert_f_536871430 = proc (a0: pointer; a1: ptr struct_sockaddr;
      a2: cstring): ptr struct_ssl_ctx_st {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:255:31
  struct_lsquic_engine_settings_536871432 {.pure, inheritable, bycopy.} = object
    es_versions*: cuint      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:476:8
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
  struct_lsquic_out_spec_536871434 {.pure, inheritable, bycopy.} = object
    iov*: ptr struct_iovec_536871437 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1185:8
    iovlen*: csize_t
    local_sa*: ptr struct_sockaddr
    dest_sa*: ptr struct_sockaddr
    peer_ctx*: pointer
    conn_ctx*: ptr lsquic_conn_ctx_t_536871413
    ecn*: cint
  struct_iovec_536871436 {.pure, inheritable, bycopy.} = object
    iov_base*: pointer       ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/struct_iovec.h:26:8
    iov_len*: csize_t
  lsquic_packets_out_f_536871438 = proc (a0: pointer;
      a1: ptr struct_lsquic_out_spec_536871435; a2: cuint): cint {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1209:15
  struct_lsquic_shared_hash_if_536871440 {.pure, inheritable, bycopy.} = object
    shi_insert*: proc (a0: pointer; a1: pointer; a2: cuint; a3: pointer;
                       a4: cuint; a5: time_t_536871443): cint {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1219:8
    shi_delete*: proc (a0: pointer; a1: pointer; a2: cuint): cint {.cdecl.}
    shi_lookup*: proc (a0: pointer; a1: pointer; a2: cuint; a3: ptr pointer;
                       a4: ptr cuint): cint {.cdecl.}
  time_t_536871442 = compiler_time_t_536871815 ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/time_t.h:10:18
  struct_lsquic_packout_mem_if_536871444 {.pure, inheritable, bycopy.} = object
    pmi_allocate*: proc (a0: pointer; a1: pointer; a2: ptr lsquic_conn_ctx_t_536871413;
                         a3: cushort; a4: cschar): pointer {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1257:8
    pmi_release*: proc (a0: pointer; a1: pointer; a2: pointer; a3: cschar): void {.
        cdecl.}
    pmi_return*: proc (a0: pointer; a1: pointer; a2: pointer; a3: cschar): void {.
        cdecl.}
  lsquic_cids_update_f_536871446 = proc (a0: pointer; a1: ptr pointer;
      a2: ptr lsquic_cid_t_536871405; a3: cuint): void {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1278:16
  struct_lsquic_hset_if_536871457 {.pure, inheritable, bycopy.} = object
    hsi_create_header_set*: proc (a0: pointer; a1: ptr lsquic_stream_t_536871415;
                                  a2: cint): pointer {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1296:8
    hsi_prepare_decode*: proc (a0: pointer; a1: ptr struct_lsxpack_header;
                               a2: csize_t): ptr struct_lsxpack_header {.cdecl.}
    hsi_process_header*: proc (a0: pointer; a1: ptr struct_lsxpack_header): cint {.
        cdecl.}
    hsi_discard_header_set*: proc (a0: pointer): void {.cdecl.}
    hsi_flags*: enum_lsquic_hsi_flag_536871449
  struct_lsquic_engine_api_536871459 {.pure, inheritable, bycopy.} = object
    ea_settings*: ptr struct_lsquic_engine_settings_536871433 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1369:8
    ea_stream_if*: ptr struct_lsquic_stream_if_536871427
    ea_stream_if_ctx*: pointer
    ea_packets_out*: lsquic_packets_out_f_536871439
    ea_packets_out_ctx*: pointer
    ea_lookup_cert*: lsquic_lookup_cert_f_536871431
    ea_cert_lu_ctx*: pointer
    ea_get_ssl_ctx*: proc (a0: pointer; a1: ptr struct_sockaddr): ptr struct_ssl_ctx_st {.
        cdecl.}
    ea_shi*: ptr struct_lsquic_shared_hash_if_536871441
    ea_shi_ctx*: pointer
    ea_pmi*: ptr struct_lsquic_packout_mem_if_536871445
    ea_pmi_ctx*: pointer
    ea_new_scids*: lsquic_cids_update_f_536871447
    ea_live_scids*: lsquic_cids_update_f_536871447
    ea_old_scids*: lsquic_cids_update_f_536871447
    ea_cids_update_ctx*: pointer
    ea_verify_cert*: proc (a0: pointer; a1: ptr struct_stack_st_X509): cint {.
        cdecl.}
    ea_verify_ctx*: pointer
    ea_hsi_if*: ptr struct_lsquic_hset_if_536871458
    ea_hsi_ctx*: pointer
    ea_stats_fh*: pointer
    ea_alpn*: cstring
    ea_generate_scid*: proc (a0: pointer; a1: ptr lsquic_conn_t_536871411;
                             a2: ptr uint8; a3: cuint): void {.cdecl.}
    ea_gen_scid_ctx*: pointer
  struct_lsquic_reader_536871461 {.pure, inheritable, bycopy.} = object
    lsqr_read*: proc (a0: pointer; a1: pointer; a2: csize_t): csize_t {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1673:8
    lsqr_size*: proc (a0: pointer): csize_t {.cdecl.}
    lsqr_ctx*: pointer
  struct_lsquic_ext_http_prio_536871463 {.pure, inheritable, bycopy.} = object
    urgency*: uint8          ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1861:8
    incremental*: cschar
  struct_lsquic_logger_if_536871465 {.pure, inheritable, bycopy.} = object
    log_buf*: proc (a0: pointer; a1: cstring; a2: csize_t): cint {.cdecl.} ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1934:8
  struct_lsquic_conn_info_536871471 {.pure, inheritable, bycopy.} = object
    lci_cwnd*: uint32        ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:2121:8
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
  struct_CRYPTO_dynlock_536871475 {.pure, inheritable, bycopy.} = object
    dummy*: cint             ## Generated based on /usr/include/openssl/crypto.h:73:9
  CRYPTO_dynlock_536871477 = struct_CRYPTO_dynlock_536871476 ## Generated based on /usr/include/openssl/crypto.h:75:3
  struct_crypto_ex_data_st_536871481 {.pure, inheritable, bycopy.} = object
    ctx*: ptr OSSL_LIB_CTX_536871484 ## Generated based on /usr/include/openssl/crypto.h:180:8
    sk*: ptr struct_stack_st_void
  OSSL_LIB_CTX_536871483 = struct_ossl_lib_ctx_st ## Generated based on /usr/include/openssl/types.h:215:32
  sk_void_compfunc_536871485 = proc (a0: ptr pointer; a1: ptr pointer): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/crypto.h:185:1
  sk_void_freefunc_536871487 = proc (a0: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:185:1
  sk_void_copyfunc_536871489 = proc (a0: pointer): pointer {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:185:1
  OPENSSL_STACK_536871491 = struct_stack_st ## Generated based on /usr/include/openssl/stack.h:23:25
  OPENSSL_sk_compfunc_536871493 = proc (a0: pointer; a1: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/stack.h:25:15
  OPENSSL_sk_copyfunc_536871495 = proc (a0: pointer): pointer {.cdecl.} ## Generated based on /usr/include/openssl/stack.h:27:17
  OPENSSL_sk_freefunc_536871497 = proc (a0: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/stack.h:26:16
  CRYPTO_EX_new_536871499 = proc (a0: pointer; a1: pointer;
                                  a2: ptr CRYPTO_EX_DATA_536871502; a3: cint;
                                  a4: clong; a5: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:238:14
  CRYPTO_EX_DATA_536871501 = struct_crypto_ex_data_st_536871482 ## Generated based on /usr/include/openssl/types.h:200:34
  CRYPTO_EX_free_536871503 = proc (a0: pointer; a1: pointer;
                                   a2: ptr CRYPTO_EX_DATA_536871502; a3: cint;
                                   a4: clong; a5: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:240:14
  CRYPTO_EX_dup_536871505 = proc (a0: ptr CRYPTO_EX_DATA_536871502;
                                  a1: ptr CRYPTO_EX_DATA_536871502;
                                  a2: ptr pointer; a3: cint; a4: clong;
                                  a5: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:242:13
  struct_crypto_threadid_st_536871507 {.pure, inheritable, bycopy.} = object
    dummy*: cint             ## Generated based on /usr/include/openssl/crypto.h:306:16
  CRYPTO_THREADID_536871509 = struct_crypto_threadid_st_536871508 ## Generated based on /usr/include/openssl/crypto.h:308:3
  CRYPTO_malloc_fn_536871511 = proc (a0: csize_t; a1: cstring; a2: cint): pointer {.
      cdecl.}                ## Generated based on /usr/include/openssl/crypto.h:333:17
  CRYPTO_realloc_fn_536871513 = proc (a0: pointer; a1: csize_t; a2: cstring;
                                      a3: cint): pointer {.cdecl.} ## Generated based on /usr/include/openssl/crypto.h:334:17
  CRYPTO_free_fn_536871515 = proc (a0: pointer; a1: cstring; a2: cint): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/crypto.h:336:16
  struct_tm_536871517 {.pure, inheritable, bycopy.} = object
    tm_sec*: cint            ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/struct_tm.h:7:8
    tm_min*: cint
    tm_hour*: cint
    tm_mday*: cint
    tm_mon*: cint
    tm_year*: cint
    tm_wday*: cint
    tm_yday*: cint
    tm_isdst*: cint
    tm_gmtoff*: clong
    tm_zone*: cstring
  OPENSSL_INIT_SETTINGS_536871519 = struct_ossl_init_settings_st ## Generated based on /usr/include/openssl/types.h:178:38
  CRYPTO_ONCE_536871521 = pthread_once_t_536871524 ## Generated based on /usr/include/openssl/crypto.h:520:24
  pthread_once_t_536871523 = cint ## Generated based on /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h:53:30
  CRYPTO_THREAD_LOCAL_536871525 = pthread_key_t_536871528 ## Generated based on /usr/include/openssl/crypto.h:521:23
  pthread_key_t_536871527 = cuint ## Generated based on /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h:49:22
  CRYPTO_THREAD_ID_typedef_536871529 = pthread_t_536871532 ## Generated based on /usr/include/openssl/crypto.h:522:19
  pthread_t_536871531 = culong ## Generated based on /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h:27:27
  OSSL_CORE_HANDLE_536871533 = struct_ossl_core_handle_st ## Generated based on /usr/include/openssl/core.h:30:36
  OSSL_DISPATCH_536871535 = struct_ossl_dispatch_st_536871817 ## Generated based on /usr/include/openssl/types.h:217:33
  sk_X509_ALGOR_compfunc_536871537 = proc (a0: ptr ptr X509_ALGOR_536871540;
      a1: ptr ptr X509_ALGOR_536871540): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:129:1
  X509_ALGOR_536871539 = struct_X509_algor_st_536871819 ## Generated based on /usr/include/openssl/types.h:158:30
  sk_X509_ALGOR_freefunc_536871541 = proc (a0: ptr X509_ALGOR_536871540): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:129:1
  sk_X509_ALGOR_copyfunc_536871543 = proc (a0: ptr X509_ALGOR_536871540): ptr X509_ALGOR_536871540 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:129:1
  struct_asn1_string_st_536871545 {.pure, inheritable, bycopy.} = object
    length*: cint            ## Generated based on /usr/include/openssl/asn1.h:183:8
    type_field*: cint
    data*: ptr uint8
    flags*: clong
  struct_ASN1_ENCODING_st_536871547 {.pure, inheritable, bycopy.} = object
    enc*: ptr uint8          ## Generated based on /usr/include/openssl/asn1.h:201:16
    len*: clong
    modified*: cint
  ASN1_ENCODING_536871549 = struct_ASN1_ENCODING_st_536871548 ## Generated based on /usr/include/openssl/asn1.h:205:3
  struct_asn1_string_table_st_536871551 {.pure, inheritable, bycopy.} = object
    nid*: cint               ## Generated based on /usr/include/openssl/asn1.h:223:8
    minsize*: clong
    maxsize*: clong
    mask*: culong
    flags*: culong
  sk_ASN1_STRING_TABLE_compfunc_536871553 = proc (a0: ptr ptr ASN1_STRING_TABLE_536871556;
      a1: ptr ptr ASN1_STRING_TABLE_536871556): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:231:1
  ASN1_STRING_TABLE_536871555 = struct_asn1_string_table_st_536871552 ## Generated based on /usr/include/openssl/types.h:67:37
  sk_ASN1_STRING_TABLE_freefunc_536871557 = proc (a0: ptr ASN1_STRING_TABLE_536871556): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:231:1
  sk_ASN1_STRING_TABLE_copyfunc_536871559 = proc (a0: ptr ASN1_STRING_TABLE_536871556): ptr ASN1_STRING_TABLE_536871556 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:231:1
  ASN1_TEMPLATE_536871561 = struct_ASN1_TEMPLATE_st ## Generated based on /usr/include/openssl/asn1.h:273:33
  ASN1_TLC_536871563 = struct_ASN1_TLC_st ## Generated based on /usr/include/openssl/asn1.h:274:28
  ASN1_VALUE_536871565 = struct_ASN1_VALUE_st ## Generated based on /usr/include/openssl/asn1.h:276:30
  d2i_of_void_536871567 = proc (a0: ptr pointer; a1: ptr ptr uint8; a2: clong): pointer {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:369:15
  i2d_of_void_536871569 = proc (a0: pointer; a1: ptr ptr uint8): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:370:13
  ASN1_ITEM_EXP_536871571 = proc (): ptr ASN1_ITEM_536871574 {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:415:26
  ASN1_ITEM_536871573 = struct_ASN1_ITEM_st ## Generated based on /usr/include/openssl/types.h:69:29
  struct_asn1_type_st_value_t {.union, bycopy.} = object
    ptr_field*: cstring
    boolean*: ASN1_BOOLEAN_536871578
    asn1_string*: ptr ASN1_STRING_536871580
    object_field*: ptr ASN1_OBJECT_536871582
    integer*: ptr ASN1_INTEGER_536871584
    enumerated*: ptr ASN1_ENUMERATED_536871586
    bit_string*: ptr ASN1_BIT_STRING_536871588
    octet_string*: ptr ASN1_OCTET_STRING_536871590
    printablestring*: ptr ASN1_PRINTABLESTRING_536871592
    t61string*: ptr ASN1_T61STRING_536871594
    ia5string*: ptr ASN1_IA5STRING_536871596
    generalstring*: ptr ASN1_GENERALSTRING_536871598
    bmpstring*: ptr ASN1_BMPSTRING_536871600
    universalstring*: ptr ASN1_UNIVERSALSTRING_536871602
    utctime*: ptr ASN1_UTCTIME_536871604
    generalizedtime*: ptr ASN1_GENERALIZEDTIME_536871606
    visiblestring*: ptr ASN1_VISIBLESTRING_536871608
    utf8string*: ptr ASN1_UTF8STRING_536871610
    set*: ptr ASN1_STRING_536871580
    sequence*: ptr ASN1_STRING_536871580
    asn1_value*: ptr ASN1_VALUE_536871566
  struct_asn1_type_st_536871575 {.pure, inheritable, bycopy.} = object
    type_field*: cint        ## Generated based on /usr/include/openssl/asn1.h:520:8
    value*: struct_asn1_type_st_value_t
  ASN1_BOOLEAN_536871577 = cint ## Generated based on /usr/include/openssl/types.h:61:13
  ASN1_STRING_536871579 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:60:31
  ASN1_OBJECT_536871581 = struct_asn1_object_st ## Generated based on /usr/include/openssl/types.h:66:31
  ASN1_INTEGER_536871583 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:45:31
  ASN1_ENUMERATED_536871585 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:46:31
  ASN1_BIT_STRING_536871587 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:47:31
  ASN1_OCTET_STRING_536871589 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:48:31
  ASN1_PRINTABLESTRING_536871591 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:49:31
  ASN1_T61STRING_536871593 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:50:31
  ASN1_IA5STRING_536871595 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:51:31
  ASN1_GENERALSTRING_536871597 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:52:31
  ASN1_BMPSTRING_536871599 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:54:31
  ASN1_UNIVERSALSTRING_536871601 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:53:31
  ASN1_UTCTIME_536871603 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:55:31
  ASN1_GENERALIZEDTIME_536871605 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:57:31
  ASN1_VISIBLESTRING_536871607 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:58:31
  ASN1_UTF8STRING_536871609 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:59:31
  sk_ASN1_TYPE_compfunc_536871611 = proc (a0: ptr ptr ASN1_TYPE_536871614;
      a1: ptr ptr ASN1_TYPE_536871614): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:551:1
  ASN1_TYPE_536871613 = struct_asn1_type_st_536871576 ## Generated based on /usr/include/openssl/types.h:65:29
  sk_ASN1_TYPE_freefunc_536871615 = proc (a0: ptr ASN1_TYPE_536871614): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:551:1
  sk_ASN1_TYPE_copyfunc_536871617 = proc (a0: ptr ASN1_TYPE_536871614): ptr ASN1_TYPE_536871614 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:551:1
  ASN1_SEQUENCE_ANY_536871619 = struct_stack_st_ASN1_TYPE ## Generated based on /usr/include/openssl/asn1.h:579:29
  struct_BIT_STRING_BITNAME_st_536871621 {.pure, inheritable, bycopy.} = object
    bitnum*: cint            ## Generated based on /usr/include/openssl/asn1.h:585:16
    lname*: cstring
    sname*: cstring
  BIT_STRING_BITNAME_536871623 = struct_BIT_STRING_BITNAME_st_536871622 ## Generated based on /usr/include/openssl/asn1.h:589:3
  sk_ASN1_OBJECT_compfunc_536871625 = proc (a0: ptr ptr ASN1_OBJECT_536871582;
      a1: ptr ptr ASN1_OBJECT_536871582): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:631:1
  sk_ASN1_OBJECT_freefunc_536871627 = proc (a0: ptr ASN1_OBJECT_536871582): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:631:1
  sk_ASN1_OBJECT_copyfunc_536871629 = proc (a0: ptr ASN1_OBJECT_536871582): ptr ASN1_OBJECT_536871582 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:631:1
  BIO_536871631 = struct_bio_st ## Generated based on /usr/include/openssl/types.h:86:23
  sk_ASN1_INTEGER_compfunc_536871633 = proc (a0: ptr ptr ASN1_INTEGER_536871584;
      a1: ptr ptr ASN1_INTEGER_536871584): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:697:1
  sk_ASN1_INTEGER_freefunc_536871635 = proc (a0: ptr ASN1_INTEGER_536871584): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:697:1
  sk_ASN1_INTEGER_copyfunc_536871637 = proc (a0: ptr ASN1_INTEGER_536871584): ptr ASN1_INTEGER_536871584 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:697:1
  ASN1_TIME_536871639 = struct_asn1_string_st_536871546 ## Generated based on /usr/include/openssl/types.h:56:31
  sk_ASN1_UTF8STRING_compfunc_536871641 = proc (a0: ptr ptr ASN1_UTF8STRING_536871610;
      a1: ptr ptr ASN1_UTF8STRING_536871610): cint {.cdecl.} ## Generated based on /usr/include/openssl/asn1.h:759:1
  sk_ASN1_UTF8STRING_freefunc_536871643 = proc (a0: ptr ASN1_UTF8STRING_536871610): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:759:1
  sk_ASN1_UTF8STRING_copyfunc_536871645 = proc (a0: ptr ASN1_UTF8STRING_536871610): ptr ASN1_UTF8STRING_536871610 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:759:1
  ASN1_NULL_536871647 = cint ## Generated based on /usr/include/openssl/types.h:62:13
  sk_ASN1_GENERALSTRING_compfunc_536871649 = proc (
      a0: ptr ptr ASN1_GENERALSTRING_536871598; a1: ptr ptr ASN1_GENERALSTRING_536871598): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:796:1
  sk_ASN1_GENERALSTRING_freefunc_536871651 = proc (a0: ptr ASN1_GENERALSTRING_536871598): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:796:1
  sk_ASN1_GENERALSTRING_copyfunc_536871653 = proc (a0: ptr ASN1_GENERALSTRING_536871598): ptr ASN1_GENERALSTRING_536871598 {.
      cdecl.}                ## Generated based on /usr/include/openssl/asn1.h:796:1
  BIGNUM_536871655 = struct_bignum_st ## Generated based on /usr/include/openssl/types.h:87:26
  EVP_PKEY_536871657 = struct_evp_pkey_st ## Generated based on /usr/include/openssl/types.h:107:28
  EVP_MD_536871659 = struct_evp_md_st ## Generated based on /usr/include/openssl/types.h:103:26
  Cfile_536871661 = struct_IO_FILE_536871821 ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/FILE.h:7:25
  CONF_536871663 = struct_conf_st_536871823 ## Generated based on /usr/include/openssl/types.h:177:24
  X509V3_CTX_536871665 = struct_v3_ext_ctx ## Generated based on /usr/include/openssl/types.h:176:27
  ASN1_PCTX_536871667 = struct_asn1_pctx_st ## Generated based on /usr/include/openssl/types.h:70:29
  ASN1_SCTX_536871669 = struct_asn1_sctx_st ## Generated based on /usr/include/openssl/types.h:71:29
  BIO_METHOD_536871671 = struct_bio_method_st ## Generated based on /usr/include/openssl/bio.h:296:30
  ssl_crock_st_536871673 = ptr struct_ssl_st ## Generated based on /usr/include/openssl/ssl.h:227:24
  TLS_SESSION_TICKET_EXT_536871675 = struct_tls_session_ticket_ext_st_536871678 ## Generated based on /usr/include/openssl/ssl.h:228:42
  struct_tls_session_ticket_ext_st_536871677 {.pure, inheritable, bycopy.} = object
    length*: cushort         ## Generated based on /usr/include/openssl/tls1.h:1215:8
    data*: pointer
  SSL_METHOD_536871679 = struct_ssl_method_st ## Generated based on /usr/include/openssl/ssl.h:229:30
  SSL_CIPHER_536871681 = struct_ssl_cipher_st ## Generated based on /usr/include/openssl/ssl.h:230:30
  SSL_SESSION_536871683 = struct_ssl_session_st ## Generated based on /usr/include/openssl/ssl.h:231:31
  TLS_SIGALGS_536871685 = struct_tls_sigalgs_st ## Generated based on /usr/include/openssl/ssl.h:232:31
  SSL_CONF_CTX_536871687 = struct_ssl_conf_ctx_st ## Generated based on /usr/include/openssl/ssl.h:233:32
  SSL_COMP_536871689 = struct_ssl_comp_st ## Generated based on /usr/include/openssl/ssl.h:234:28
  struct_srtp_protection_profile_st_536871691 {.pure, inheritable, bycopy.} = object
    name*: cstring           ## Generated based on /usr/include/openssl/ssl.h:240:16
    id*: culong
  SRTP_PROTECTION_PROFILE_536871693 = struct_srtp_protection_profile_st_536871692 ## Generated based on /usr/include/openssl/ssl.h:243:3
  sk_SRTP_PROTECTION_PROFILE_compfunc_536871695 = proc (
      a0: ptr ptr SRTP_PROTECTION_PROFILE_536871694;
      a1: ptr ptr SRTP_PROTECTION_PROFILE_536871694): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:244:1
  sk_SRTP_PROTECTION_PROFILE_freefunc_536871697 = proc (
      a0: ptr SRTP_PROTECTION_PROFILE_536871694): void {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:244:1
  sk_SRTP_PROTECTION_PROFILE_copyfunc_536871699 = proc (
      a0: ptr SRTP_PROTECTION_PROFILE_536871694): ptr SRTP_PROTECTION_PROFILE_536871694 {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:244:1
  tls_session_ticket_ext_cb_fn_536871701 = proc (a0: ptr SSL_536871704;
      a1: ptr uint8; a2: cint; a3: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:273:15
  SSL_536871703 = struct_ssl_st ## Generated based on /usr/include/openssl/types.h:184:23
  tls_session_secret_cb_fn_536871705 = proc (a0: ptr SSL_536871704; a1: pointer;
      a2: ptr cint; a3: ptr struct_stack_st_SSL_CIPHER; a4: ptr ptr SSL_CIPHER_536871682;
      a5: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:275:15
  custom_ext_add_cb_536871707 = proc (a0: ptr SSL_536871704; a1: cuint;
                                      a2: ptr ptr uint8; a3: ptr csize_t;
                                      a4: ptr cint; a5: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:306:15
  custom_ext_free_cb_536871709 = proc (a0: ptr SSL_536871704; a1: cuint;
                                       a2: ptr uint8; a3: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:310:16
  custom_ext_parse_cb_536871711 = proc (a0: ptr SSL_536871704; a1: cuint;
                                        a2: ptr uint8; a3: csize_t;
                                        a4: ptr cint; a5: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:313:15
  SSL_custom_ext_add_cb_ex_536871713 = proc (a0: ptr SSL_536871704; a1: cuint;
      a2: cuint; a3: ptr ptr uint8; a4: ptr csize_t; a5: ptr X509_536871716;
      a6: csize_t; a7: ptr cint; a8: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:318:15
  X509_536871715 = struct_x509_st ## Generated based on /usr/include/openssl/types.h:157:24
  SSL_custom_ext_free_cb_ex_536871717 = proc (a0: ptr SSL_536871704; a1: cuint;
      a2: cuint; a3: ptr uint8; a4: pointer): void {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:325:16
  SSL_custom_ext_parse_cb_ex_536871719 = proc (a0: ptr SSL_536871704; a1: cuint;
      a2: cuint; a3: ptr uint8; a4: csize_t; a5: ptr X509_536871716;
      a6: csize_t; a7: ptr cint; a8: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:330:15
  SSL_verify_cb_536871721 = proc (a0: cint; a1: ptr X509_STORE_CTX_536871724): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:338:15
  X509_STORE_CTX_536871723 = struct_x509_store_ctx_st ## Generated based on /usr/include/openssl/types.h:165:34
  SSL_async_callback_fn_536871725 = proc (a0: ptr SSL_536871704; a1: pointer): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:341:15
  SSL_CTX_536871727 = struct_ssl_ctx_st ## Generated based on /usr/include/openssl/types.h:185:27
  GEN_SESSION_CB_536871729 = proc (a0: ptr SSL_536871704; a1: ptr uint8;
                                   a2: ptr cuint): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:683:15
  ENGINE_536871731 = struct_engine_st ## Generated based on /usr/include/openssl/types.h:183:26
  SSL_CTX_npn_advertised_cb_func_536871733 = proc (a0: ptr SSL_536871704;
      a1: ptr ptr uint8; a2: ptr cuint; a3: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:781:15
  SSL_CTX_npn_select_cb_func_536871735 = proc (a0: ptr SSL_536871704;
      a1: ptr ptr uint8; a2: ptr uint8; a3: ptr uint8; a4: cuint; a5: pointer): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:790:15
  SSL_CTX_alpn_select_cb_func_536871737 = proc (a0: ptr SSL_536871704;
      a1: ptr ptr uint8; a2: ptr uint8; a3: ptr uint8; a4: cuint; a5: pointer): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:819:15
  SSL_psk_client_cb_func_536871739 = proc (a0: ptr SSL_536871704; a1: cstring;
      a2: cstring; a3: cuint; a4: ptr uint8; a5: cuint): cuint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:838:24
  SSL_psk_server_cb_func_536871741 = proc (a0: ptr SSL_536871704; a1: cstring;
      a2: ptr uint8; a3: cuint): cuint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:847:24
  SSL_psk_find_session_cb_func_536871743 = proc (a0: ptr SSL_536871704;
      a1: ptr uint8; a2: csize_t; a3: ptr ptr SSL_SESSION_536871684): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:860:15
  SSL_psk_use_session_cb_func_536871745 = proc (a0: ptr SSL_536871704;
      a1: ptr EVP_MD_536871660; a2: ptr ptr uint8; a3: ptr csize_t;
      a4: ptr ptr SSL_SESSION_536871684): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:864:15
  SSL_CTX_keylog_cb_func_536871747 = proc (a0: ptr SSL_536871704; a1: cstring): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:935:16
  sk_SSL_CIPHER_compfunc_536871749 = proc (a0: ptr ptr SSL_CIPHER_536871682;
      a1: ptr ptr SSL_CIPHER_536871682): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:977:1
  sk_SSL_CIPHER_freefunc_536871751 = proc (a0: ptr SSL_CIPHER_536871682): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:977:1
  sk_SSL_CIPHER_copyfunc_536871753 = proc (a0: ptr SSL_CIPHER_536871682): ptr SSL_CIPHER_536871682 {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:977:1
  sk_SSL_COMP_compfunc_536871755 = proc (a0: ptr ptr SSL_COMP_536871690;
      a1: ptr ptr SSL_COMP_536871690): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:1003:1
  sk_SSL_COMP_freefunc_536871757 = proc (a0: ptr SSL_COMP_536871690): void {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:1003:1
  sk_SSL_COMP_copyfunc_536871759 = proc (a0: ptr SSL_COMP_536871690): ptr SSL_COMP_536871690 {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:1003:1
  OSSL_HANDSHAKE_STATE_536871763 = enum_OSSL_HANDSHAKE_STATE_536871762 ## Generated based on /usr/include/openssl/ssl.h:1114:3
  pem_password_cb_536871765 = proc (a0: cstring; a1: cint; a2: cint; a3: pointer): cint {.
      cdecl.}                ## Generated based on /usr/include/openssl/types.h:223:13
  X509_STORE_536871767 = struct_x509_store_st ## Generated based on /usr/include/openssl/types.h:164:30
  RSA_536871769 = struct_rsa_st ## Generated based on /usr/include/openssl/types.h:143:23
  SSL_DANE_536871771 = struct_ssl_dane_st ## Generated based on /usr/include/openssl/types.h:156:28
  X509_VERIFY_PARAM_536871773 = struct_X509_VERIFY_PARAM_st ## Generated based on /usr/include/openssl/types.h:170:37
  SSL_client_hello_cb_fn_536871775 = proc (a0: ptr SSL_536871704; a1: ptr cint;
      a2: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:1924:15
  off_t_536871777 = compiler_off_t_536871825 ## Generated based on /usr/include/x86_64-linux-gnu/sys/types.h:85:17
  DH_536871779 = struct_dh_st ## Generated based on /usr/include/openssl/types.h:134:22
  COMP_METHOD_536871781 = struct_comp_method_st ## Generated based on /usr/include/openssl/types.h:188:31
  BIO_ADDR_536871783 = union_bio_addr_st ## Generated based on /usr/include/openssl/bio.h:213:27
  ssl_ct_validation_cb_536871785 = proc (a0: ptr CT_POLICY_EVAL_CTX_536871788;
      a1: ptr struct_stack_st_SCT; a2: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:2340:15
  CT_POLICY_EVAL_CTX_536871787 = struct_ct_policy_eval_ctx_st ## Generated based on /usr/include/openssl/types.h:210:38
  CTLOG_STORE_536871789 = struct_ctlog_store_st ## Generated based on /usr/include/openssl/types.h:209:31
  SSL_TICKET_STATUS_536871791 = cint ## Generated based on /usr/include/openssl/ssl.h:2534:13
  SSL_TICKET_RETURN_536871793 = cint ## Generated based on /usr/include/openssl/ssl.h:2553:13
  SSL_CTX_generate_session_ticket_fn_536871795 = proc (a0: ptr SSL_536871704;
      a1: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:2566:15
  SSL_CTX_decrypt_session_ticket_fn_536871797 = proc (a0: ptr SSL_536871704;
      a1: ptr SSL_SESSION_536871684; a2: ptr uint8; a3: csize_t;
      a4: SSL_TICKET_STATUS_536871792; a5: pointer): SSL_TICKET_RETURN_536871794 {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:2567:29
  DTLS_timer_cb_536871799 = proc (a0: ptr SSL_536871704; a1: cuint): cuint {.
      cdecl.}                ## Generated based on /usr/include/openssl/ssl.h:2579:24
  SSL_allow_early_data_cb_fn_536871801 = proc (a0: ptr SSL_536871704;
      a1: pointer): cint {.cdecl.} ## Generated based on /usr/include/openssl/ssl.h:2584:15
  struct_rand_meth_st_536871803 {.pure, inheritable, bycopy.} = object
    seed*: proc (a0: pointer; a1: cint): cint {.cdecl.} ## Generated based on /usr/include/openssl/rand.h:40:8
    bytes*: proc (a0: ptr uint8; a1: cint): cint {.cdecl.}
    cleanup*: proc (): void {.cdecl.}
    add*: proc (a0: pointer; a1: cint; a2: cdouble): cint {.cdecl.}
    pseudorand*: proc (a0: ptr uint8; a1: cint): cint {.cdecl.}
    status*: proc (): cint {.cdecl.}
  RAND_METHOD_536871805 = struct_rand_meth_st_536871804 ## Generated based on /usr/include/openssl/types.h:153:29
  EVP_RAND_CTX_536871807 = struct_evp_rand_ctx_st ## Generated based on /usr/include/openssl/types.h:120:32
  compiler_ssize_t_536871812 = clong ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:194:27
  compiler_time_t_536871814 = clong ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:160:26
  struct_ossl_dispatch_st_536871816 {.pure, inheritable, bycopy.} = object
    function_id*: cint       ## Generated based on /usr/include/openssl/core.h:40:8
    function*: proc (): void {.cdecl.}
  struct_X509_algor_st_536871818 {.pure, inheritable, bycopy.} = object
    algorithm*: ptr ASN1_OBJECT_536871582 ## Generated based on /usr/include/openssl/x509.h:176:8
    parameter*: ptr ASN1_TYPE_536871614
  struct_IO_FILE_536871820 {.pure, inheritable, bycopy.} = object
    internal_flags*: cint    ## Generated based on /usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h:49:8
    internal_IO_read_ptr*: cstring
    internal_IO_read_end*: cstring
    internal_IO_read_base*: cstring
    internal_IO_write_base*: cstring
    internal_IO_write_ptr*: cstring
    internal_IO_write_end*: cstring
    internal_IO_buf_base*: cstring
    internal_IO_buf_end*: cstring
    internal_IO_save_base*: cstring
    internal_IO_backup_base*: cstring
    internal_IO_save_end*: cstring
    internal_markers*: ptr struct_IO_marker
    internal_chain*: ptr struct_IO_FILE_536871821
    internal_fileno*: cint
    internal_flags2*: cint
    internal_old_offset*: compiler_off_t_536871825
    internal_cur_column*: cushort
    internal_vtable_offset*: cschar
    internal_shortbuf*: array[1'i64, cschar]
    internal_lock*: pointer
    internal_offset*: compiler_off64_t_536871829
    internal_codecvt*: ptr struct_IO_codecvt
    internal_wide_data*: ptr struct_IO_wide_data
    internal_freeres_list*: ptr struct_IO_FILE_536871821
    internal_freeres_buf*: pointer
    compiler_pad5*: csize_t
    internal_mode*: cint
    internal_unused2*: array[20'i64, cschar]
  struct_conf_st_536871822 {.pure, inheritable, bycopy.} = object
    meth*: ptr CONF_METHOD_536871831 ## Generated based on /usr/include/openssl/conftypes.h:34:8
    meth_data*: pointer
    data*: ptr struct_lhash_st_CONF_VALUE_536871833
    flag_dollarid*: cint
    flag_abspath*: cint
    includedir*: cstring
    libctx*: ptr OSSL_LIB_CTX_536871484
  compiler_off_t_536871824 = clong ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:152:25
  compiler_off64_t_536871828 = clong ## Generated based on /usr/include/x86_64-linux-gnu/bits/types.h:153:27
  CONF_METHOD_536871830 = struct_conf_method_st_536871835 ## Generated based on /usr/include/openssl/conf.h:86:31
  struct_lhash_st_CONF_VALUE_dummy_t {.union, bycopy.} = object
    d1*: pointer
    d2*: culong
    d3*: cint
  struct_lhash_st_CONF_VALUE_536871832 {.pure, inheritable, bycopy.} = object
    dummy*: struct_lhash_st_CONF_VALUE_dummy_t ## Generated based on /usr/include/openssl/conf.h:67:1
  struct_conf_method_st_536871834 {.pure, inheritable, bycopy.} = object
    name*: cstring           ## Generated based on /usr/include/openssl/conftypes.h:21:8
    create*: proc (a0: ptr CONF_METHOD_536871831): ptr CONF_536871664 {.cdecl.}
    init*: proc (a0: ptr CONF_536871664): cint {.cdecl.}
    destroy*: proc (a0: ptr CONF_536871664): cint {.cdecl.}
    destroy_data*: proc (a0: ptr CONF_536871664): cint {.cdecl.}
    load_bio*: proc (a0: ptr CONF_536871664; a1: ptr BIO_536871632;
                     a2: ptr clong): cint {.cdecl.}
    dump*: proc (a0: ptr CONF_536871664; a1: ptr BIO_536871632): cint {.cdecl.}
    is_number*: proc (a0: ptr CONF_536871664; a1: cschar): cint {.cdecl.}
    to_int*: proc (a0: ptr CONF_536871664; a1: cschar): cint {.cdecl.}
    load*: proc (a0: ptr CONF_536871664; a1: cstring; a2: ptr clong): cint {.
        cdecl.}
  CRYPTO_EX_new_536871500 = (when declared(CRYPTO_EX_new):
    when ownSizeof(CRYPTO_EX_new) != ownSizeof(CRYPTO_EX_new_536871499):
      static :
        warning("Declaration of " & "CRYPTO_EX_new" &
            " exists but with different size")
    CRYPTO_EX_new
  else:
    CRYPTO_EX_new_536871499)
  sk_X509_ALGOR_freefunc_536871542 = (when declared(sk_X509_ALGOR_freefunc):
    when ownSizeof(sk_X509_ALGOR_freefunc) != ownSizeof(sk_X509_ALGOR_freefunc_536871541):
      static :
        warning("Declaration of " & "sk_X509_ALGOR_freefunc" &
            " exists but with different size")
    sk_X509_ALGOR_freefunc
  else:
    sk_X509_ALGOR_freefunc_536871541)
  tls_session_ticket_ext_cb_fn_536871702 = (when declared(
      tls_session_ticket_ext_cb_fn):
    when ownSizeof(tls_session_ticket_ext_cb_fn) !=
        ownSizeof(tls_session_ticket_ext_cb_fn_536871701):
      static :
        warning("Declaration of " & "tls_session_ticket_ext_cb_fn" &
            " exists but with different size")
    tls_session_ticket_ext_cb_fn
  else:
    tls_session_ticket_ext_cb_fn_536871701)
  SSL_CTX_npn_select_cb_func_536871736 = (when declared(
      SSL_CTX_npn_select_cb_func):
    when ownSizeof(SSL_CTX_npn_select_cb_func) !=
        ownSizeof(SSL_CTX_npn_select_cb_func_536871735):
      static :
        warning("Declaration of " & "SSL_CTX_npn_select_cb_func" &
            " exists but with different size")
    SSL_CTX_npn_select_cb_func
  else:
    SSL_CTX_npn_select_cb_func_536871735)
  struct_ossl_dispatch_st_536871817 = (when declared(struct_ossl_dispatch_st):
    when ownSizeof(struct_ossl_dispatch_st) !=
        ownSizeof(struct_ossl_dispatch_st_536871816):
      static :
        warning("Declaration of " & "struct_ossl_dispatch_st" &
            " exists but with different size")
    struct_ossl_dispatch_st
  else:
    struct_ossl_dispatch_st_536871816)
  CRYPTO_dynlock_536871478 = (when declared(CRYPTO_dynlock):
    when ownSizeof(CRYPTO_dynlock) != ownSizeof(CRYPTO_dynlock_536871477):
      static :
        warning("Declaration of " & "CRYPTO_dynlock" &
            " exists but with different size")
    CRYPTO_dynlock
  else:
    CRYPTO_dynlock_536871477)
  struct_IO_FILE_536871821 = (when declared(struct_IO_FILE):
    when ownSizeof(struct_IO_FILE) != ownSizeof(struct_IO_FILE_536871820):
      static :
        warning("Declaration of " & "struct_IO_FILE" &
            " exists but with different size")
    struct_IO_FILE
  else:
    struct_IO_FILE_536871820)
  struct_conf_st_536871823 = (when declared(struct_conf_st):
    when ownSizeof(struct_conf_st) != ownSizeof(struct_conf_st_536871822):
      static :
        warning("Declaration of " & "struct_conf_st" &
            " exists but with different size")
    struct_conf_st
  else:
    struct_conf_st_536871822)
  SSL_COMP_536871690 = (when declared(SSL_COMP):
    when ownSizeof(SSL_COMP) != ownSizeof(SSL_COMP_536871689):
      static :
        warning("Declaration of " & "SSL_COMP" &
            " exists but with different size")
    SSL_COMP
  else:
    SSL_COMP_536871689)
  CRYPTO_EX_free_536871504 = (when declared(CRYPTO_EX_free):
    when ownSizeof(CRYPTO_EX_free) != ownSizeof(CRYPTO_EX_free_536871503):
      static :
        warning("Declaration of " & "CRYPTO_EX_free" &
            " exists but with different size")
    CRYPTO_EX_free
  else:
    CRYPTO_EX_free_536871503)
  ASN1_SCTX_536871670 = (when declared(ASN1_SCTX):
    when ownSizeof(ASN1_SCTX) != ownSizeof(ASN1_SCTX_536871669):
      static :
        warning("Declaration of " & "ASN1_SCTX" &
            " exists but with different size")
    ASN1_SCTX
  else:
    ASN1_SCTX_536871669)
  SSL_CTX_decrypt_session_ticket_fn_536871798 = (when declared(
      SSL_CTX_decrypt_session_ticket_fn):
    when ownSizeof(SSL_CTX_decrypt_session_ticket_fn) !=
        ownSizeof(SSL_CTX_decrypt_session_ticket_fn_536871797):
      static :
        warning("Declaration of " & "SSL_CTX_decrypt_session_ticket_fn" &
            " exists but with different size")
    SSL_CTX_decrypt_session_ticket_fn
  else:
    SSL_CTX_decrypt_session_ticket_fn_536871797)
  sk_ASN1_STRING_TABLE_compfunc_536871554 = (when declared(
      sk_ASN1_STRING_TABLE_compfunc):
    when ownSizeof(sk_ASN1_STRING_TABLE_compfunc) !=
        ownSizeof(sk_ASN1_STRING_TABLE_compfunc_536871553):
      static :
        warning("Declaration of " & "sk_ASN1_STRING_TABLE_compfunc" &
            " exists but with different size")
    sk_ASN1_STRING_TABLE_compfunc
  else:
    sk_ASN1_STRING_TABLE_compfunc_536871553)
  SSL_custom_ext_add_cb_ex_536871714 = (when declared(SSL_custom_ext_add_cb_ex):
    when ownSizeof(SSL_custom_ext_add_cb_ex) !=
        ownSizeof(SSL_custom_ext_add_cb_ex_536871713):
      static :
        warning("Declaration of " & "SSL_custom_ext_add_cb_ex" &
            " exists but with different size")
    SSL_custom_ext_add_cb_ex
  else:
    SSL_custom_ext_add_cb_ex_536871713)
  ASN1_BMPSTRING_536871600 = (when declared(ASN1_BMPSTRING):
    when ownSizeof(ASN1_BMPSTRING) != ownSizeof(ASN1_BMPSTRING_536871599):
      static :
        warning("Declaration of " & "ASN1_BMPSTRING" &
            " exists but with different size")
    ASN1_BMPSTRING
  else:
    ASN1_BMPSTRING_536871599)
  sk_ASN1_GENERALSTRING_copyfunc_536871654 = (when declared(
      sk_ASN1_GENERALSTRING_copyfunc):
    when ownSizeof(sk_ASN1_GENERALSTRING_copyfunc) !=
        ownSizeof(sk_ASN1_GENERALSTRING_copyfunc_536871653):
      static :
        warning("Declaration of " & "sk_ASN1_GENERALSTRING_copyfunc" &
            " exists but with different size")
    sk_ASN1_GENERALSTRING_copyfunc
  else:
    sk_ASN1_GENERALSTRING_copyfunc_536871653)
  SSL_custom_ext_free_cb_ex_536871718 = (when declared(SSL_custom_ext_free_cb_ex):
    when ownSizeof(SSL_custom_ext_free_cb_ex) !=
        ownSizeof(SSL_custom_ext_free_cb_ex_536871717):
      static :
        warning("Declaration of " & "SSL_custom_ext_free_cb_ex" &
            " exists but with different size")
    SSL_custom_ext_free_cb_ex
  else:
    SSL_custom_ext_free_cb_ex_536871717)
  SSL_CTX_536871728 = (when declared(SSL_CTX):
    when ownSizeof(SSL_CTX) != ownSizeof(SSL_CTX_536871727):
      static :
        warning("Declaration of " & "SSL_CTX" &
            " exists but with different size")
    SSL_CTX
  else:
    SSL_CTX_536871727)
  SSL_536871704 = (when declared(SSL):
    when ownSizeof(SSL) != ownSizeof(SSL_536871703):
      static :
        warning("Declaration of " & "SSL" & " exists but with different size")
    SSL
  else:
    SSL_536871703)
  lsquic_stream_id_t_536871407 = (when declared(lsquic_stream_id_t):
    when ownSizeof(lsquic_stream_id_t) != ownSizeof(lsquic_stream_id_t_536871406):
      static :
        warning("Declaration of " & "lsquic_stream_id_t" &
            " exists but with different size")
    lsquic_stream_id_t
  else:
    lsquic_stream_id_t_536871406)
  struct_iovec_536871437 = (when declared(struct_iovec):
    when ownSizeof(struct_iovec) != ownSizeof(struct_iovec_536871436):
      static :
        warning("Declaration of " & "struct_iovec" &
            " exists but with different size")
    struct_iovec
  else:
    struct_iovec_536871436)
  struct_lsquic_engine_api_536871460 = (when declared(struct_lsquic_engine_api):
    when ownSizeof(struct_lsquic_engine_api) !=
        ownSizeof(struct_lsquic_engine_api_536871459):
      static :
        warning("Declaration of " & "struct_lsquic_engine_api" &
            " exists but with different size")
    struct_lsquic_engine_api
  else:
    struct_lsquic_engine_api_536871459)
  sk_ASN1_UTF8STRING_freefunc_536871644 = (when declared(
      sk_ASN1_UTF8STRING_freefunc):
    when ownSizeof(sk_ASN1_UTF8STRING_freefunc) !=
        ownSizeof(sk_ASN1_UTF8STRING_freefunc_536871643):
      static :
        warning("Declaration of " & "sk_ASN1_UTF8STRING_freefunc" &
            " exists but with different size")
    sk_ASN1_UTF8STRING_freefunc
  else:
    sk_ASN1_UTF8STRING_freefunc_536871643)
  SSL_async_callback_fn_536871726 = (when declared(SSL_async_callback_fn):
    when ownSizeof(SSL_async_callback_fn) != ownSizeof(SSL_async_callback_fn_536871725):
      static :
        warning("Declaration of " & "SSL_async_callback_fn" &
            " exists but with different size")
    SSL_async_callback_fn
  else:
    SSL_async_callback_fn_536871725)
  struct_tm_536871518 = (when declared(struct_tm):
    when ownSizeof(struct_tm) != ownSizeof(struct_tm_536871517):
      static :
        warning("Declaration of " & "struct_tm" &
            " exists but with different size")
    struct_tm
  else:
    struct_tm_536871517)
  SSL_CIPHER_536871682 = (when declared(SSL_CIPHER):
    when ownSizeof(SSL_CIPHER) != ownSizeof(SSL_CIPHER_536871681):
      static :
        warning("Declaration of " & "SSL_CIPHER" &
            " exists but with different size")
    SSL_CIPHER
  else:
    SSL_CIPHER_536871681)
  CRYPTO_ONCE_536871522 = (when declared(CRYPTO_ONCE):
    when ownSizeof(CRYPTO_ONCE) != ownSizeof(CRYPTO_ONCE_536871521):
      static :
        warning("Declaration of " & "CRYPTO_ONCE" &
            " exists but with different size")
    CRYPTO_ONCE
  else:
    CRYPTO_ONCE_536871521)
  SSL_verify_cb_536871722 = (when declared(SSL_verify_cb):
    when ownSizeof(SSL_verify_cb) != ownSizeof(SSL_verify_cb_536871721):
      static :
        warning("Declaration of " & "SSL_verify_cb" &
            " exists but with different size")
    SSL_verify_cb
  else:
    SSL_verify_cb_536871721)
  struct_lhash_st_CONF_VALUE_536871833 = (when declared(
      struct_lhash_st_CONF_VALUE):
    when ownSizeof(struct_lhash_st_CONF_VALUE) !=
        ownSizeof(struct_lhash_st_CONF_VALUE_536871832):
      static :
        warning("Declaration of " & "struct_lhash_st_CONF_VALUE" &
            " exists but with different size")
    struct_lhash_st_CONF_VALUE
  else:
    struct_lhash_st_CONF_VALUE_536871832)
  enum_lsquic_crypto_ver_536871470 = (when declared(enum_lsquic_crypto_ver):
    when ownSizeof(enum_lsquic_crypto_ver) != ownSizeof(enum_lsquic_crypto_ver_536871469):
      static :
        warning("Declaration of " & "enum_lsquic_crypto_ver" &
            " exists but with different size")
    enum_lsquic_crypto_ver
  else:
    enum_lsquic_crypto_ver_536871469)
  uint_fast8_t_536871403 = (when declared(uint_fast8_t):
    when ownSizeof(uint_fast8_t) != ownSizeof(uint_fast8_t_536871402):
      static :
        warning("Declaration of " & "uint_fast8_t" &
            " exists but with different size")
    uint_fast8_t
  else:
    uint_fast8_t_536871402)
  ASN1_SEQUENCE_ANY_536871620 = (when declared(ASN1_SEQUENCE_ANY):
    when ownSizeof(ASN1_SEQUENCE_ANY) != ownSizeof(ASN1_SEQUENCE_ANY_536871619):
      static :
        warning("Declaration of " & "ASN1_SEQUENCE_ANY" &
            " exists but with different size")
    ASN1_SEQUENCE_ANY
  else:
    ASN1_SEQUENCE_ANY_536871619)
  sk_void_freefunc_536871488 = (when declared(sk_void_freefunc):
    when ownSizeof(sk_void_freefunc) != ownSizeof(sk_void_freefunc_536871487):
      static :
        warning("Declaration of " & "sk_void_freefunc" &
            " exists but with different size")
    sk_void_freefunc
  else:
    sk_void_freefunc_536871487)
  i2d_of_void_536871570 = (when declared(i2d_of_void):
    when ownSizeof(i2d_of_void) != ownSizeof(i2d_of_void_536871569):
      static :
        warning("Declaration of " & "i2d_of_void" &
            " exists but with different size")
    i2d_of_void
  else:
    i2d_of_void_536871569)
  struct_lsquic_logger_if_536871466 = (when declared(struct_lsquic_logger_if):
    when ownSizeof(struct_lsquic_logger_if) !=
        ownSizeof(struct_lsquic_logger_if_536871465):
      static :
        warning("Declaration of " & "struct_lsquic_logger_if" &
            " exists but with different size")
    struct_lsquic_logger_if
  else:
    struct_lsquic_logger_if_536871465)
  SSL_CTX_keylog_cb_func_536871748 = (when declared(SSL_CTX_keylog_cb_func):
    when ownSizeof(SSL_CTX_keylog_cb_func) != ownSizeof(SSL_CTX_keylog_cb_func_536871747):
      static :
        warning("Declaration of " & "SSL_CTX_keylog_cb_func" &
            " exists but with different size")
    SSL_CTX_keylog_cb_func
  else:
    SSL_CTX_keylog_cb_func_536871747)
  X509_536871716 = (when declared(X509):
    when ownSizeof(X509) != ownSizeof(X509_536871715):
      static :
        warning("Declaration of " & "X509" & " exists but with different size")
    X509
  else:
    X509_536871715)
  pthread_key_t_536871528 = (when declared(pthread_key_t):
    when ownSizeof(pthread_key_t) != ownSizeof(pthread_key_t_536871527):
      static :
        warning("Declaration of " & "pthread_key_t" &
            " exists but with different size")
    pthread_key_t
  else:
    pthread_key_t_536871527)
  pthread_t_536871532 = (when declared(pthread_t):
    when ownSizeof(pthread_t) != ownSizeof(pthread_t_536871531):
      static :
        warning("Declaration of " & "pthread_t" &
            " exists but with different size")
    pthread_t
  else:
    pthread_t_536871531)
  GEN_SESSION_CB_536871730 = (when declared(GEN_SESSION_CB):
    when ownSizeof(GEN_SESSION_CB) != ownSizeof(GEN_SESSION_CB_536871729):
      static :
        warning("Declaration of " & "GEN_SESSION_CB" &
            " exists but with different size")
    GEN_SESSION_CB
  else:
    GEN_SESSION_CB_536871729)
  sk_ASN1_INTEGER_freefunc_536871636 = (when declared(sk_ASN1_INTEGER_freefunc):
    when ownSizeof(sk_ASN1_INTEGER_freefunc) !=
        ownSizeof(sk_ASN1_INTEGER_freefunc_536871635):
      static :
        warning("Declaration of " & "sk_ASN1_INTEGER_freefunc" &
            " exists but with different size")
    sk_ASN1_INTEGER_freefunc
  else:
    sk_ASN1_INTEGER_freefunc_536871635)
  enum_LSQUIC_CONN_STATUS_536871474 = (when declared(enum_LSQUIC_CONN_STATUS):
    when ownSizeof(enum_LSQUIC_CONN_STATUS) !=
        ownSizeof(enum_LSQUIC_CONN_STATUS_536871473):
      static :
        warning("Declaration of " & "enum_LSQUIC_CONN_STATUS" &
            " exists but with different size")
    enum_LSQUIC_CONN_STATUS
  else:
    enum_LSQUIC_CONN_STATUS_536871473)
  struct_ASN1_ENCODING_st_536871548 = (when declared(struct_ASN1_ENCODING_st):
    when ownSizeof(struct_ASN1_ENCODING_st) !=
        ownSizeof(struct_ASN1_ENCODING_st_536871547):
      static :
        warning("Declaration of " & "struct_ASN1_ENCODING_st" &
            " exists but with different size")
    struct_ASN1_ENCODING_st
  else:
    struct_ASN1_ENCODING_st_536871547)
  CRYPTO_THREADID_536871510 = (when declared(CRYPTO_THREADID):
    when ownSizeof(CRYPTO_THREADID) != ownSizeof(CRYPTO_THREADID_536871509):
      static :
        warning("Declaration of " & "CRYPTO_THREADID" &
            " exists but with different size")
    CRYPTO_THREADID
  else:
    CRYPTO_THREADID_536871509)
  struct_CRYPTO_dynlock_536871476 = (when declared(struct_CRYPTO_dynlock):
    when ownSizeof(struct_CRYPTO_dynlock) != ownSizeof(struct_CRYPTO_dynlock_536871475):
      static :
        warning("Declaration of " & "struct_CRYPTO_dynlock" &
            " exists but with different size")
    struct_CRYPTO_dynlock
  else:
    struct_CRYPTO_dynlock_536871475)
  sk_ASN1_OBJECT_freefunc_536871628 = (when declared(sk_ASN1_OBJECT_freefunc):
    when ownSizeof(sk_ASN1_OBJECT_freefunc) !=
        ownSizeof(sk_ASN1_OBJECT_freefunc_536871627):
      static :
        warning("Declaration of " & "sk_ASN1_OBJECT_freefunc" &
            " exists but with different size")
    sk_ASN1_OBJECT_freefunc
  else:
    sk_ASN1_OBJECT_freefunc_536871627)
  sk_SSL_CIPHER_copyfunc_536871754 = (when declared(sk_SSL_CIPHER_copyfunc):
    when ownSizeof(sk_SSL_CIPHER_copyfunc) != ownSizeof(sk_SSL_CIPHER_copyfunc_536871753):
      static :
        warning("Declaration of " & "sk_SSL_CIPHER_copyfunc" &
            " exists but with different size")
    sk_SSL_CIPHER_copyfunc
  else:
    sk_SSL_CIPHER_copyfunc_536871753)
  CONF_METHOD_536871831 = (when declared(CONF_METHOD):
    when ownSizeof(CONF_METHOD) != ownSizeof(CONF_METHOD_536871830):
      static :
        warning("Declaration of " & "CONF_METHOD" &
            " exists but with different size")
    CONF_METHOD
  else:
    CONF_METHOD_536871830)
  struct_lsquic_shared_hash_if_536871441 = (when declared(
      struct_lsquic_shared_hash_if):
    when ownSizeof(struct_lsquic_shared_hash_if) !=
        ownSizeof(struct_lsquic_shared_hash_if_536871440):
      static :
        warning("Declaration of " & "struct_lsquic_shared_hash_if" &
            " exists but with different size")
    struct_lsquic_shared_hash_if
  else:
    struct_lsquic_shared_hash_if_536871440)
  struct_lsquic_out_spec_536871435 = (when declared(struct_lsquic_out_spec):
    when ownSizeof(struct_lsquic_out_spec) != ownSizeof(struct_lsquic_out_spec_536871434):
      static :
        warning("Declaration of " & "struct_lsquic_out_spec" &
            " exists but with different size")
    struct_lsquic_out_spec
  else:
    struct_lsquic_out_spec_536871434)
  CONF_536871664 = (when declared(CONF):
    when ownSizeof(CONF) != ownSizeof(CONF_536871663):
      static :
        warning("Declaration of " & "CONF" & " exists but with different size")
    CONF
  else:
    CONF_536871663)
  SSL_SESSION_536871684 = (when declared(SSL_SESSION):
    when ownSizeof(SSL_SESSION) != ownSizeof(SSL_SESSION_536871683):
      static :
        warning("Declaration of " & "SSL_SESSION" &
            " exists but with different size")
    SSL_SESSION
  else:
    SSL_SESSION_536871683)
  sk_ASN1_UTF8STRING_copyfunc_536871646 = (when declared(
      sk_ASN1_UTF8STRING_copyfunc):
    when ownSizeof(sk_ASN1_UTF8STRING_copyfunc) !=
        ownSizeof(sk_ASN1_UTF8STRING_copyfunc_536871645):
      static :
        warning("Declaration of " & "sk_ASN1_UTF8STRING_copyfunc" &
            " exists but with different size")
    sk_ASN1_UTF8STRING_copyfunc
  else:
    sk_ASN1_UTF8STRING_copyfunc_536871645)
  sk_X509_ALGOR_copyfunc_536871544 = (when declared(sk_X509_ALGOR_copyfunc):
    when ownSizeof(sk_X509_ALGOR_copyfunc) != ownSizeof(sk_X509_ALGOR_copyfunc_536871543):
      static :
        warning("Declaration of " & "sk_X509_ALGOR_copyfunc" &
            " exists but with different size")
    sk_X509_ALGOR_copyfunc
  else:
    sk_X509_ALGOR_copyfunc_536871543)
  struct_crypto_threadid_st_536871508 = (when declared(struct_crypto_threadid_st):
    when ownSizeof(struct_crypto_threadid_st) !=
        ownSizeof(struct_crypto_threadid_st_536871507):
      static :
        warning("Declaration of " & "struct_crypto_threadid_st" &
            " exists but with different size")
    struct_crypto_threadid_st
  else:
    struct_crypto_threadid_st_536871507)
  lsquic_http_headers_t_536871419 = (when declared(lsquic_http_headers_t):
    when ownSizeof(lsquic_http_headers_t) != ownSizeof(lsquic_http_headers_t_536871418):
      static :
        warning("Declaration of " & "lsquic_http_headers_t" &
            " exists but with different size")
    lsquic_http_headers_t
  else:
    lsquic_http_headers_t_536871418)
  custom_ext_free_cb_536871710 = (when declared(custom_ext_free_cb):
    when ownSizeof(custom_ext_free_cb) != ownSizeof(custom_ext_free_cb_536871709):
      static :
        warning("Declaration of " & "custom_ext_free_cb" &
            " exists but with different size")
    custom_ext_free_cb
  else:
    custom_ext_free_cb_536871709)
  ASN1_UTCTIME_536871604 = (when declared(ASN1_UTCTIME):
    when ownSizeof(ASN1_UTCTIME) != ownSizeof(ASN1_UTCTIME_536871603):
      static :
        warning("Declaration of " & "ASN1_UTCTIME" &
            " exists but with different size")
    ASN1_UTCTIME
  else:
    ASN1_UTCTIME_536871603)
  CRYPTO_EX_DATA_536871502 = (when declared(CRYPTO_EX_DATA):
    when ownSizeof(CRYPTO_EX_DATA) != ownSizeof(CRYPTO_EX_DATA_536871501):
      static :
        warning("Declaration of " & "CRYPTO_EX_DATA" &
            " exists but with different size")
    CRYPTO_EX_DATA
  else:
    CRYPTO_EX_DATA_536871501)
  OSSL_HANDSHAKE_STATE_536871764 = (when declared(OSSL_HANDSHAKE_STATE):
    when ownSizeof(OSSL_HANDSHAKE_STATE) != ownSizeof(OSSL_HANDSHAKE_STATE_536871763):
      static :
        warning("Declaration of " & "OSSL_HANDSHAKE_STATE" &
            " exists but with different size")
    OSSL_HANDSHAKE_STATE
  else:
    OSSL_HANDSHAKE_STATE_536871763)
  compiler_off_t_536871825 = (when declared(compiler_off_t):
    when ownSizeof(compiler_off_t) != ownSizeof(compiler_off_t_536871824):
      static :
        warning("Declaration of " & "compiler_off_t" &
            " exists but with different size")
    compiler_off_t
  else:
    compiler_off_t_536871824)
  SSL_METHOD_536871680 = (when declared(SSL_METHOD):
    when ownSizeof(SSL_METHOD) != ownSizeof(SSL_METHOD_536871679):
      static :
        warning("Declaration of " & "SSL_METHOD" &
            " exists but with different size")
    SSL_METHOD
  else:
    SSL_METHOD_536871679)
  custom_ext_parse_cb_536871712 = (when declared(custom_ext_parse_cb):
    when ownSizeof(custom_ext_parse_cb) != ownSizeof(custom_ext_parse_cb_536871711):
      static :
        warning("Declaration of " & "custom_ext_parse_cb" &
            " exists but with different size")
    custom_ext_parse_cb
  else:
    custom_ext_parse_cb_536871711)
  CRYPTO_THREAD_LOCAL_536871526 = (when declared(CRYPTO_THREAD_LOCAL):
    when ownSizeof(CRYPTO_THREAD_LOCAL) != ownSizeof(CRYPTO_THREAD_LOCAL_536871525):
      static :
        warning("Declaration of " & "CRYPTO_THREAD_LOCAL" &
            " exists but with different size")
    CRYPTO_THREAD_LOCAL
  else:
    CRYPTO_THREAD_LOCAL_536871525)
  struct_lsquic_http_headers_536871421 = (when declared(
      struct_lsquic_http_headers):
    when ownSizeof(struct_lsquic_http_headers) !=
        ownSizeof(struct_lsquic_http_headers_536871420):
      static :
        warning("Declaration of " & "struct_lsquic_http_headers" &
            " exists but with different size")
    struct_lsquic_http_headers
  else:
    struct_lsquic_http_headers_536871420)
  ASN1_PRINTABLESTRING_536871592 = (when declared(ASN1_PRINTABLESTRING):
    when ownSizeof(ASN1_PRINTABLESTRING) != ownSizeof(ASN1_PRINTABLESTRING_536871591):
      static :
        warning("Declaration of " & "ASN1_PRINTABLESTRING" &
            " exists but with different size")
    ASN1_PRINTABLESTRING
  else:
    ASN1_PRINTABLESTRING_536871591)
  CRYPTO_free_fn_536871516 = (when declared(CRYPTO_free_fn):
    when ownSizeof(CRYPTO_free_fn) != ownSizeof(CRYPTO_free_fn_536871515):
      static :
        warning("Declaration of " & "CRYPTO_free_fn" &
            " exists but with different size")
    CRYPTO_free_fn
  else:
    CRYPTO_free_fn_536871515)
  ASN1_T61STRING_536871594 = (when declared(ASN1_T61STRING):
    when ownSizeof(ASN1_T61STRING) != ownSizeof(ASN1_T61STRING_536871593):
      static :
        warning("Declaration of " & "ASN1_T61STRING" &
            " exists but with different size")
    ASN1_T61STRING
  else:
    ASN1_T61STRING_536871593)
  struct_lsquic_hset_if_536871458 = (when declared(struct_lsquic_hset_if):
    when ownSizeof(struct_lsquic_hset_if) != ownSizeof(struct_lsquic_hset_if_536871457):
      static :
        warning("Declaration of " & "struct_lsquic_hset_if" &
            " exists but with different size")
    struct_lsquic_hset_if
  else:
    struct_lsquic_hset_if_536871457)
  lsquic_conn_t_536871411 = (when declared(lsquic_conn_t):
    when ownSizeof(lsquic_conn_t) != ownSizeof(lsquic_conn_t_536871410):
      static :
        warning("Declaration of " & "lsquic_conn_t" &
            " exists but with different size")
    lsquic_conn_t
  else:
    lsquic_conn_t_536871410)
  CRYPTO_EX_dup_536871506 = (when declared(CRYPTO_EX_dup):
    when ownSizeof(CRYPTO_EX_dup) != ownSizeof(CRYPTO_EX_dup_536871505):
      static :
        warning("Declaration of " & "CRYPTO_EX_dup" &
            " exists but with different size")
    CRYPTO_EX_dup
  else:
    CRYPTO_EX_dup_536871505)
  ASN1_GENERALIZEDTIME_536871606 = (when declared(ASN1_GENERALIZEDTIME):
    when ownSizeof(ASN1_GENERALIZEDTIME) != ownSizeof(ASN1_GENERALIZEDTIME_536871605):
      static :
        warning("Declaration of " & "ASN1_GENERALIZEDTIME" &
            " exists but with different size")
    ASN1_GENERALIZEDTIME
  else:
    ASN1_GENERALIZEDTIME_536871605)
  sk_ASN1_STRING_TABLE_copyfunc_536871560 = (when declared(
      sk_ASN1_STRING_TABLE_copyfunc):
    when ownSizeof(sk_ASN1_STRING_TABLE_copyfunc) !=
        ownSizeof(sk_ASN1_STRING_TABLE_copyfunc_536871559):
      static :
        warning("Declaration of " & "sk_ASN1_STRING_TABLE_copyfunc" &
            " exists but with different size")
    sk_ASN1_STRING_TABLE_copyfunc
  else:
    sk_ASN1_STRING_TABLE_copyfunc_536871559)
  OSSL_LIB_CTX_536871484 = (when declared(OSSL_LIB_CTX):
    when ownSizeof(OSSL_LIB_CTX) != ownSizeof(OSSL_LIB_CTX_536871483):
      static :
        warning("Declaration of " & "OSSL_LIB_CTX" &
            " exists but with different size")
    OSSL_LIB_CTX
  else:
    OSSL_LIB_CTX_536871483)
  ASN1_OBJECT_536871582 = (when declared(ASN1_OBJECT):
    when ownSizeof(ASN1_OBJECT) != ownSizeof(ASN1_OBJECT_536871581):
      static :
        warning("Declaration of " & "ASN1_OBJECT" &
            " exists but with different size")
    ASN1_OBJECT
  else:
    ASN1_OBJECT_536871581)
  sk_ASN1_OBJECT_compfunc_536871626 = (when declared(sk_ASN1_OBJECT_compfunc):
    when ownSizeof(sk_ASN1_OBJECT_compfunc) !=
        ownSizeof(sk_ASN1_OBJECT_compfunc_536871625):
      static :
        warning("Declaration of " & "sk_ASN1_OBJECT_compfunc" &
            " exists but with different size")
    sk_ASN1_OBJECT_compfunc
  else:
    sk_ASN1_OBJECT_compfunc_536871625)
  sk_SSL_COMP_freefunc_536871758 = (when declared(sk_SSL_COMP_freefunc):
    when ownSizeof(sk_SSL_COMP_freefunc) != ownSizeof(sk_SSL_COMP_freefunc_536871757):
      static :
        warning("Declaration of " & "sk_SSL_COMP_freefunc" &
            " exists but with different size")
    sk_SSL_COMP_freefunc
  else:
    sk_SSL_COMP_freefunc_536871757)
  OSSL_CORE_HANDLE_536871534 = (when declared(OSSL_CORE_HANDLE):
    when ownSizeof(OSSL_CORE_HANDLE) != ownSizeof(OSSL_CORE_HANDLE_536871533):
      static :
        warning("Declaration of " & "OSSL_CORE_HANDLE" &
            " exists but with different size")
    OSSL_CORE_HANDLE
  else:
    OSSL_CORE_HANDLE_536871533)
  ASN1_TYPE_536871614 = (when declared(ASN1_TYPE):
    when ownSizeof(ASN1_TYPE) != ownSizeof(ASN1_TYPE_536871613):
      static :
        warning("Declaration of " & "ASN1_TYPE" &
            " exists but with different size")
    ASN1_TYPE
  else:
    ASN1_TYPE_536871613)
  X509_STORE_536871768 = (when declared(X509_STORE):
    when ownSizeof(X509_STORE) != ownSizeof(X509_STORE_536871767):
      static :
        warning("Declaration of " & "X509_STORE" &
            " exists but with different size")
    X509_STORE
  else:
    X509_STORE_536871767)
  ASN1_BOOLEAN_536871578 = (when declared(ASN1_BOOLEAN):
    when ownSizeof(ASN1_BOOLEAN) != ownSizeof(ASN1_BOOLEAN_536871577):
      static :
        warning("Declaration of " & "ASN1_BOOLEAN" &
            " exists but with different size")
    ASN1_BOOLEAN
  else:
    ASN1_BOOLEAN_536871577)
  sk_ASN1_GENERALSTRING_compfunc_536871650 = (when declared(
      sk_ASN1_GENERALSTRING_compfunc):
    when ownSizeof(sk_ASN1_GENERALSTRING_compfunc) !=
        ownSizeof(sk_ASN1_GENERALSTRING_compfunc_536871649):
      static :
        warning("Declaration of " & "sk_ASN1_GENERALSTRING_compfunc" &
            " exists but with different size")
    sk_ASN1_GENERALSTRING_compfunc
  else:
    sk_ASN1_GENERALSTRING_compfunc_536871649)
  custom_ext_add_cb_536871708 = (when declared(custom_ext_add_cb):
    when ownSizeof(custom_ext_add_cb) != ownSizeof(custom_ext_add_cb_536871707):
      static :
        warning("Declaration of " & "custom_ext_add_cb" &
            " exists but with different size")
    custom_ext_add_cb
  else:
    custom_ext_add_cb_536871707)
  lsquic_cid_t_536871405 = (when declared(lsquic_cid_t):
    when ownSizeof(lsquic_cid_t) != ownSizeof(lsquic_cid_t_536871404):
      static :
        warning("Declaration of " & "lsquic_cid_t" &
            " exists but with different size")
    lsquic_cid_t
  else:
    lsquic_cid_t_536871404)
  SSL_psk_use_session_cb_func_536871746 = (when declared(
      SSL_psk_use_session_cb_func):
    when ownSizeof(SSL_psk_use_session_cb_func) !=
        ownSizeof(SSL_psk_use_session_cb_func_536871745):
      static :
        warning("Declaration of " & "SSL_psk_use_session_cb_func" &
            " exists but with different size")
    SSL_psk_use_session_cb_func
  else:
    SSL_psk_use_session_cb_func_536871745)
  struct_asn1_type_st_536871576 = (when declared(struct_asn1_type_st):
    when ownSizeof(struct_asn1_type_st) != ownSizeof(struct_asn1_type_st_536871575):
      static :
        warning("Declaration of " & "struct_asn1_type_st" &
            " exists but with different size")
    struct_asn1_type_st
  else:
    struct_asn1_type_st_536871575)
  OSSL_DISPATCH_536871536 = (when declared(OSSL_DISPATCH):
    when ownSizeof(OSSL_DISPATCH) != ownSizeof(OSSL_DISPATCH_536871535):
      static :
        warning("Declaration of " & "OSSL_DISPATCH" &
            " exists but with different size")
    OSSL_DISPATCH
  else:
    OSSL_DISPATCH_536871535)
  sk_ASN1_INTEGER_copyfunc_536871638 = (when declared(sk_ASN1_INTEGER_copyfunc):
    when ownSizeof(sk_ASN1_INTEGER_copyfunc) !=
        ownSizeof(sk_ASN1_INTEGER_copyfunc_536871637):
      static :
        warning("Declaration of " & "sk_ASN1_INTEGER_copyfunc" &
            " exists but with different size")
    sk_ASN1_INTEGER_copyfunc
  else:
    sk_ASN1_INTEGER_copyfunc_536871637)
  SSL_psk_server_cb_func_536871742 = (when declared(SSL_psk_server_cb_func):
    when ownSizeof(SSL_psk_server_cb_func) != ownSizeof(SSL_psk_server_cb_func_536871741):
      static :
        warning("Declaration of " & "SSL_psk_server_cb_func" &
            " exists but with different size")
    SSL_psk_server_cb_func
  else:
    SSL_psk_server_cb_func_536871741)
  sk_ASN1_TYPE_freefunc_536871616 = (when declared(sk_ASN1_TYPE_freefunc):
    when ownSizeof(sk_ASN1_TYPE_freefunc) != ownSizeof(sk_ASN1_TYPE_freefunc_536871615):
      static :
        warning("Declaration of " & "sk_ASN1_TYPE_freefunc" &
            " exists but with different size")
    sk_ASN1_TYPE_freefunc
  else:
    sk_ASN1_TYPE_freefunc_536871615)
  sk_ASN1_INTEGER_compfunc_536871634 = (when declared(sk_ASN1_INTEGER_compfunc):
    when ownSizeof(sk_ASN1_INTEGER_compfunc) !=
        ownSizeof(sk_ASN1_INTEGER_compfunc_536871633):
      static :
        warning("Declaration of " & "sk_ASN1_INTEGER_compfunc" &
            " exists but with different size")
    sk_ASN1_INTEGER_compfunc
  else:
    sk_ASN1_INTEGER_compfunc_536871633)
  SSL_CTX_npn_advertised_cb_func_536871734 = (when declared(
      SSL_CTX_npn_advertised_cb_func):
    when ownSizeof(SSL_CTX_npn_advertised_cb_func) !=
        ownSizeof(SSL_CTX_npn_advertised_cb_func_536871733):
      static :
        warning("Declaration of " & "SSL_CTX_npn_advertised_cb_func" &
            " exists but with different size")
    SSL_CTX_npn_advertised_cb_func
  else:
    SSL_CTX_npn_advertised_cb_func_536871733)
  sk_ASN1_GENERALSTRING_freefunc_536871652 = (when declared(
      sk_ASN1_GENERALSTRING_freefunc):
    when ownSizeof(sk_ASN1_GENERALSTRING_freefunc) !=
        ownSizeof(sk_ASN1_GENERALSTRING_freefunc_536871651):
      static :
        warning("Declaration of " & "sk_ASN1_GENERALSTRING_freefunc" &
            " exists but with different size")
    sk_ASN1_GENERALSTRING_freefunc
  else:
    sk_ASN1_GENERALSTRING_freefunc_536871651)
  struct_crypto_ex_data_st_536871482 = (when declared(struct_crypto_ex_data_st):
    when ownSizeof(struct_crypto_ex_data_st) !=
        ownSizeof(struct_crypto_ex_data_st_536871481):
      static :
        warning("Declaration of " & "struct_crypto_ex_data_st" &
            " exists but with different size")
    struct_crypto_ex_data_st
  else:
    struct_crypto_ex_data_st_536871481)
  ASN1_ITEM_536871574 = (when declared(ASN1_ITEM):
    when ownSizeof(ASN1_ITEM) != ownSizeof(ASN1_ITEM_536871573):
      static :
        warning("Declaration of " & "ASN1_ITEM" &
            " exists but with different size")
    ASN1_ITEM
  else:
    ASN1_ITEM_536871573)
  lsquic_cids_update_f_536871447 = (when declared(lsquic_cids_update_f):
    when ownSizeof(lsquic_cids_update_f) != ownSizeof(lsquic_cids_update_f_536871446):
      static :
        warning("Declaration of " & "lsquic_cids_update_f" &
            " exists but with different size")
    lsquic_cids_update_f
  else:
    lsquic_cids_update_f_536871446)
  SSL_CONF_CTX_536871688 = (when declared(SSL_CONF_CTX):
    when ownSizeof(SSL_CONF_CTX) != ownSizeof(SSL_CONF_CTX_536871687):
      static :
        warning("Declaration of " & "SSL_CONF_CTX" &
            " exists but with different size")
    SSL_CONF_CTX
  else:
    SSL_CONF_CTX_536871687)
  sk_void_copyfunc_536871490 = (when declared(sk_void_copyfunc):
    when ownSizeof(sk_void_copyfunc) != ownSizeof(sk_void_copyfunc_536871489):
      static :
        warning("Declaration of " & "sk_void_copyfunc" &
            " exists but with different size")
    sk_void_copyfunc
  else:
    sk_void_copyfunc_536871489)
  struct_lsquic_conn_info_536871472 = (when declared(struct_lsquic_conn_info):
    when ownSizeof(struct_lsquic_conn_info) !=
        ownSizeof(struct_lsquic_conn_info_536871471):
      static :
        warning("Declaration of " & "struct_lsquic_conn_info" &
            " exists but with different size")
    struct_lsquic_conn_info
  else:
    struct_lsquic_conn_info_536871471)
  sk_ASN1_TYPE_compfunc_536871612 = (when declared(sk_ASN1_TYPE_compfunc):
    when ownSizeof(sk_ASN1_TYPE_compfunc) != ownSizeof(sk_ASN1_TYPE_compfunc_536871611):
      static :
        warning("Declaration of " & "sk_ASN1_TYPE_compfunc" &
            " exists but with different size")
    sk_ASN1_TYPE_compfunc
  else:
    sk_ASN1_TYPE_compfunc_536871611)
  lsquic_stream_ctx_t_536871417 = (when declared(lsquic_stream_ctx_t):
    when ownSizeof(lsquic_stream_ctx_t) != ownSizeof(lsquic_stream_ctx_t_536871416):
      static :
        warning("Declaration of " & "lsquic_stream_ctx_t" &
            " exists but with different size")
    lsquic_stream_ctx_t
  else:
    lsquic_stream_ctx_t_536871416)
  BIO_536871632 = (when declared(BIO):
    when ownSizeof(BIO) != ownSizeof(BIO_536871631):
      static :
        warning("Declaration of " & "BIO" & " exists but with different size")
    BIO
  else:
    BIO_536871631)
  ASN1_PCTX_536871668 = (when declared(ASN1_PCTX):
    when ownSizeof(ASN1_PCTX) != ownSizeof(ASN1_PCTX_536871667):
      static :
        warning("Declaration of " & "ASN1_PCTX" &
            " exists but with different size")
    ASN1_PCTX
  else:
    ASN1_PCTX_536871667)
  RAND_METHOD_536871806 = (when declared(RAND_METHOD):
    when ownSizeof(RAND_METHOD) != ownSizeof(RAND_METHOD_536871805):
      static :
        warning("Declaration of " & "RAND_METHOD" &
            " exists but with different size")
    RAND_METHOD
  else:
    RAND_METHOD_536871805)
  SSL_CTX_generate_session_ticket_fn_536871796 = (when declared(
      SSL_CTX_generate_session_ticket_fn):
    when ownSizeof(SSL_CTX_generate_session_ticket_fn) !=
        ownSizeof(SSL_CTX_generate_session_ticket_fn_536871795):
      static :
        warning("Declaration of " & "SSL_CTX_generate_session_ticket_fn" &
            " exists but with different size")
    SSL_CTX_generate_session_ticket_fn
  else:
    SSL_CTX_generate_session_ticket_fn_536871795)
  ASN1_VALUE_536871566 = (when declared(ASN1_VALUE):
    when ownSizeof(ASN1_VALUE) != ownSizeof(ASN1_VALUE_536871565):
      static :
        warning("Declaration of " & "ASN1_VALUE" &
            " exists but with different size")
    ASN1_VALUE
  else:
    ASN1_VALUE_536871565)
  pthread_once_t_536871524 = (when declared(pthread_once_t):
    when ownSizeof(pthread_once_t) != ownSizeof(pthread_once_t_536871523):
      static :
        warning("Declaration of " & "pthread_once_t" &
            " exists but with different size")
    pthread_once_t
  else:
    pthread_once_t_536871523)
  ASN1_STRING_TABLE_536871556 = (when declared(ASN1_STRING_TABLE):
    when ownSizeof(ASN1_STRING_TABLE) != ownSizeof(ASN1_STRING_TABLE_536871555):
      static :
        warning("Declaration of " & "ASN1_STRING_TABLE" &
            " exists but with different size")
    ASN1_STRING_TABLE
  else:
    ASN1_STRING_TABLE_536871555)
  SSL_custom_ext_parse_cb_ex_536871720 = (when declared(
      SSL_custom_ext_parse_cb_ex):
    when ownSizeof(SSL_custom_ext_parse_cb_ex) !=
        ownSizeof(SSL_custom_ext_parse_cb_ex_536871719):
      static :
        warning("Declaration of " & "SSL_custom_ext_parse_cb_ex" &
            " exists but with different size")
    SSL_custom_ext_parse_cb_ex
  else:
    SSL_custom_ext_parse_cb_ex_536871719)
  X509_VERIFY_PARAM_536871774 = (when declared(X509_VERIFY_PARAM):
    when ownSizeof(X509_VERIFY_PARAM) != ownSizeof(X509_VERIFY_PARAM_536871773):
      static :
        warning("Declaration of " & "X509_VERIFY_PARAM" &
            " exists but with different size")
    X509_VERIFY_PARAM
  else:
    X509_VERIFY_PARAM_536871773)
  compiler_off64_t_536871829 = (when declared(compiler_off64_t):
    when ownSizeof(compiler_off64_t) != ownSizeof(compiler_off64_t_536871828):
      static :
        warning("Declaration of " & "compiler_off64_t" &
            " exists but with different size")
    compiler_off64_t
  else:
    compiler_off64_t_536871828)
  struct_lsquic_stream_if_536871427 = (when declared(struct_lsquic_stream_if):
    when ownSizeof(struct_lsquic_stream_if) !=
        ownSizeof(struct_lsquic_stream_if_536871426):
      static :
        warning("Declaration of " & "struct_lsquic_stream_if" &
            " exists but with different size")
    struct_lsquic_stream_if
  else:
    struct_lsquic_stream_if_536871426)
  enum_lsquic_logger_timestamp_style_536871468 = (when declared(
      enum_lsquic_logger_timestamp_style):
    when ownSizeof(enum_lsquic_logger_timestamp_style) !=
        ownSizeof(enum_lsquic_logger_timestamp_style_536871467):
      static :
        warning("Declaration of " & "enum_lsquic_logger_timestamp_style" &
            " exists but with different size")
    enum_lsquic_logger_timestamp_style
  else:
    enum_lsquic_logger_timestamp_style_536871467)
  SSL_psk_find_session_cb_func_536871744 = (when declared(
      SSL_psk_find_session_cb_func):
    when ownSizeof(SSL_psk_find_session_cb_func) !=
        ownSizeof(SSL_psk_find_session_cb_func_536871743):
      static :
        warning("Declaration of " & "SSL_psk_find_session_cb_func" &
            " exists but with different size")
    SSL_psk_find_session_cb_func
  else:
    SSL_psk_find_session_cb_func_536871743)
  struct_lsquic_cid_536871401 = (when declared(struct_lsquic_cid):
    when ownSizeof(struct_lsquic_cid) != ownSizeof(struct_lsquic_cid_536871400):
      static :
        warning("Declaration of " & "struct_lsquic_cid" &
            " exists but with different size")
    struct_lsquic_cid
  else:
    struct_lsquic_cid_536871400)
  enum_lsquic_hsi_flag_536871449 = (when declared(enum_lsquic_hsi_flag):
    when ownSizeof(enum_lsquic_hsi_flag) != ownSizeof(enum_lsquic_hsi_flag_536871448):
      static :
        warning("Declaration of " & "enum_lsquic_hsi_flag" &
            " exists but with different size")
    enum_lsquic_hsi_flag
  else:
    enum_lsquic_hsi_flag_536871448)
  sk_SSL_CIPHER_freefunc_536871752 = (when declared(sk_SSL_CIPHER_freefunc):
    when ownSizeof(sk_SSL_CIPHER_freefunc) != ownSizeof(sk_SSL_CIPHER_freefunc_536871751):
      static :
        warning("Declaration of " & "sk_SSL_CIPHER_freefunc" &
            " exists but with different size")
    sk_SSL_CIPHER_freefunc
  else:
    sk_SSL_CIPHER_freefunc_536871751)
  COMP_METHOD_536871782 = (when declared(COMP_METHOD):
    when ownSizeof(COMP_METHOD) != ownSizeof(COMP_METHOD_536871781):
      static :
        warning("Declaration of " & "COMP_METHOD" &
            " exists but with different size")
    COMP_METHOD
  else:
    COMP_METHOD_536871781)
  CRYPTO_malloc_fn_536871512 = (when declared(CRYPTO_malloc_fn):
    when ownSizeof(CRYPTO_malloc_fn) != ownSizeof(CRYPTO_malloc_fn_536871511):
      static :
        warning("Declaration of " & "CRYPTO_malloc_fn" &
            " exists but with different size")
    CRYPTO_malloc_fn
  else:
    CRYPTO_malloc_fn_536871511)
  DTLS_timer_cb_536871800 = (when declared(DTLS_timer_cb):
    when ownSizeof(DTLS_timer_cb) != ownSizeof(DTLS_timer_cb_536871799):
      static :
        warning("Declaration of " & "DTLS_timer_cb" &
            " exists but with different size")
    DTLS_timer_cb
  else:
    DTLS_timer_cb_536871799)
  EVP_MD_536871660 = (when declared(EVP_MD):
    when ownSizeof(EVP_MD) != ownSizeof(EVP_MD_536871659):
      static :
        warning("Declaration of " & "EVP_MD" & " exists but with different size")
    EVP_MD
  else:
    EVP_MD_536871659)
  X509V3_CTX_536871666 = (when declared(X509V3_CTX):
    when ownSizeof(X509V3_CTX) != ownSizeof(X509V3_CTX_536871665):
      static :
        warning("Declaration of " & "X509V3_CTX" &
            " exists but with different size")
    X509V3_CTX
  else:
    X509V3_CTX_536871665)
  sk_ASN1_STRING_TABLE_freefunc_536871558 = (when declared(
      sk_ASN1_STRING_TABLE_freefunc):
    when ownSizeof(sk_ASN1_STRING_TABLE_freefunc) !=
        ownSizeof(sk_ASN1_STRING_TABLE_freefunc_536871557):
      static :
        warning("Declaration of " & "sk_ASN1_STRING_TABLE_freefunc" &
            " exists but with different size")
    sk_ASN1_STRING_TABLE_freefunc
  else:
    sk_ASN1_STRING_TABLE_freefunc_536871557)
  time_t_536871443 = (when declared(time_t):
    when ownSizeof(time_t) != ownSizeof(time_t_536871442):
      static :
        warning("Declaration of " & "time_t" & " exists but with different size")
    time_t
  else:
    time_t_536871442)
  struct_tls_session_ticket_ext_st_536871678 = (when declared(
      struct_tls_session_ticket_ext_st):
    when ownSizeof(struct_tls_session_ticket_ext_st) !=
        ownSizeof(struct_tls_session_ticket_ext_st_536871677):
      static :
        warning("Declaration of " & "struct_tls_session_ticket_ext_st" &
            " exists but with different size")
    struct_tls_session_ticket_ext_st
  else:
    struct_tls_session_ticket_ext_st_536871677)
  struct_rand_meth_st_536871804 = (when declared(struct_rand_meth_st):
    when ownSizeof(struct_rand_meth_st) != ownSizeof(struct_rand_meth_st_536871803):
      static :
        warning("Declaration of " & "struct_rand_meth_st" &
            " exists but with different size")
    struct_rand_meth_st
  else:
    struct_rand_meth_st_536871803)
  SSL_client_hello_cb_fn_536871776 = (when declared(SSL_client_hello_cb_fn):
    when ownSizeof(SSL_client_hello_cb_fn) != ownSizeof(SSL_client_hello_cb_fn_536871775):
      static :
        warning("Declaration of " & "SSL_client_hello_cb_fn" &
            " exists but with different size")
    SSL_client_hello_cb_fn
  else:
    SSL_client_hello_cb_fn_536871775)
  BIO_METHOD_536871672 = (when declared(BIO_METHOD):
    when ownSizeof(BIO_METHOD) != ownSizeof(BIO_METHOD_536871671):
      static :
        warning("Declaration of " & "BIO_METHOD" &
            " exists but with different size")
    BIO_METHOD
  else:
    BIO_METHOD_536871671)
  pem_password_cb_536871766 = (when declared(pem_password_cb):
    when ownSizeof(pem_password_cb) != ownSizeof(pem_password_cb_536871765):
      static :
        warning("Declaration of " & "pem_password_cb" &
            " exists but with different size")
    pem_password_cb
  else:
    pem_password_cb_536871765)
  EVP_RAND_CTX_536871808 = (when declared(EVP_RAND_CTX):
    when ownSizeof(EVP_RAND_CTX) != ownSizeof(EVP_RAND_CTX_536871807):
      static :
        warning("Declaration of " & "EVP_RAND_CTX" &
            " exists but with different size")
    EVP_RAND_CTX
  else:
    EVP_RAND_CTX_536871807)
  tls_session_secret_cb_fn_536871706 = (when declared(tls_session_secret_cb_fn):
    when ownSizeof(tls_session_secret_cb_fn) !=
        ownSizeof(tls_session_secret_cb_fn_536871705):
      static :
        warning("Declaration of " & "tls_session_secret_cb_fn" &
            " exists but with different size")
    tls_session_secret_cb_fn
  else:
    tls_session_secret_cb_fn_536871705)
  X509_STORE_CTX_536871724 = (when declared(X509_STORE_CTX):
    when ownSizeof(X509_STORE_CTX) != ownSizeof(X509_STORE_CTX_536871723):
      static :
        warning("Declaration of " & "X509_STORE_CTX" &
            " exists but with different size")
    X509_STORE_CTX
  else:
    X509_STORE_CTX_536871723)
  struct_lsquic_engine_settings_536871433 = (when declared(
      struct_lsquic_engine_settings):
    when ownSizeof(struct_lsquic_engine_settings) !=
        ownSizeof(struct_lsquic_engine_settings_536871432):
      static :
        warning("Declaration of " & "struct_lsquic_engine_settings" &
            " exists but with different size")
    struct_lsquic_engine_settings
  else:
    struct_lsquic_engine_settings_536871432)
  lsquic_lookup_cert_f_536871431 = (when declared(lsquic_lookup_cert_f):
    when ownSizeof(lsquic_lookup_cert_f) != ownSizeof(lsquic_lookup_cert_f_536871430):
      static :
        warning("Declaration of " & "lsquic_lookup_cert_f" &
            " exists but with different size")
    lsquic_lookup_cert_f
  else:
    lsquic_lookup_cert_f_536871430)
  compiler_ssize_t_536871813 = (when declared(compiler_ssize_t):
    when ownSizeof(compiler_ssize_t) != ownSizeof(compiler_ssize_t_536871812):
      static :
        warning("Declaration of " & "compiler_ssize_t" &
            " exists but with different size")
    compiler_ssize_t
  else:
    compiler_ssize_t_536871812)
  sk_ASN1_UTF8STRING_compfunc_536871642 = (when declared(
      sk_ASN1_UTF8STRING_compfunc):
    when ownSizeof(sk_ASN1_UTF8STRING_compfunc) !=
        ownSizeof(sk_ASN1_UTF8STRING_compfunc_536871641):
      static :
        warning("Declaration of " & "sk_ASN1_UTF8STRING_compfunc" &
            " exists but with different size")
    sk_ASN1_UTF8STRING_compfunc
  else:
    sk_ASN1_UTF8STRING_compfunc_536871641)
  TLS_SESSION_TICKET_EXT_536871676 = (when declared(TLS_SESSION_TICKET_EXT):
    when ownSizeof(TLS_SESSION_TICKET_EXT) != ownSizeof(TLS_SESSION_TICKET_EXT_536871675):
      static :
        warning("Declaration of " & "TLS_SESSION_TICKET_EXT" &
            " exists but with different size")
    TLS_SESSION_TICKET_EXT
  else:
    TLS_SESSION_TICKET_EXT_536871675)
  lsquic_engine_t_536871409 = (when declared(lsquic_engine_t):
    when ownSizeof(lsquic_engine_t) != ownSizeof(lsquic_engine_t_536871408):
      static :
        warning("Declaration of " & "lsquic_engine_t" &
            " exists but with different size")
    lsquic_engine_t
  else:
    lsquic_engine_t_536871408)
  d2i_of_void_536871568 = (when declared(d2i_of_void):
    when ownSizeof(d2i_of_void) != ownSizeof(d2i_of_void_536871567):
      static :
        warning("Declaration of " & "d2i_of_void" &
            " exists but with different size")
    d2i_of_void
  else:
    d2i_of_void_536871567)
  ASN1_INTEGER_536871584 = (when declared(ASN1_INTEGER):
    when ownSizeof(ASN1_INTEGER) != ownSizeof(ASN1_INTEGER_536871583):
      static :
        warning("Declaration of " & "ASN1_INTEGER" &
            " exists but with different size")
    ASN1_INTEGER
  else:
    ASN1_INTEGER_536871583)
  ASN1_VISIBLESTRING_536871608 = (when declared(ASN1_VISIBLESTRING):
    when ownSizeof(ASN1_VISIBLESTRING) != ownSizeof(ASN1_VISIBLESTRING_536871607):
      static :
        warning("Declaration of " & "ASN1_VISIBLESTRING" &
            " exists but with different size")
    ASN1_VISIBLESTRING
  else:
    ASN1_VISIBLESTRING_536871607)
  sk_SRTP_PROTECTION_PROFILE_freefunc_536871698 = (when declared(
      sk_SRTP_PROTECTION_PROFILE_freefunc):
    when ownSizeof(sk_SRTP_PROTECTION_PROFILE_freefunc) !=
        ownSizeof(sk_SRTP_PROTECTION_PROFILE_freefunc_536871697):
      static :
        warning("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_freefunc" &
            " exists but with different size")
    sk_SRTP_PROTECTION_PROFILE_freefunc
  else:
    sk_SRTP_PROTECTION_PROFILE_freefunc_536871697)
  OPENSSL_sk_compfunc_536871494 = (when declared(OPENSSL_sk_compfunc):
    when ownSizeof(OPENSSL_sk_compfunc) != ownSizeof(OPENSSL_sk_compfunc_536871493):
      static :
        warning("Declaration of " & "OPENSSL_sk_compfunc" &
            " exists but with different size")
    OPENSSL_sk_compfunc
  else:
    OPENSSL_sk_compfunc_536871493)
  ASN1_BIT_STRING_536871588 = (when declared(ASN1_BIT_STRING):
    when ownSizeof(ASN1_BIT_STRING) != ownSizeof(ASN1_BIT_STRING_536871587):
      static :
        warning("Declaration of " & "ASN1_BIT_STRING" &
            " exists but with different size")
    ASN1_BIT_STRING
  else:
    ASN1_BIT_STRING_536871587)
  ASN1_ENCODING_536871550 = (when declared(ASN1_ENCODING):
    when ownSizeof(ASN1_ENCODING) != ownSizeof(ASN1_ENCODING_536871549):
      static :
        warning("Declaration of " & "ASN1_ENCODING" &
            " exists but with different size")
    ASN1_ENCODING
  else:
    ASN1_ENCODING_536871549)
  ASN1_GENERALSTRING_536871598 = (when declared(ASN1_GENERALSTRING):
    when ownSizeof(ASN1_GENERALSTRING) != ownSizeof(ASN1_GENERALSTRING_536871597):
      static :
        warning("Declaration of " & "ASN1_GENERALSTRING" &
            " exists but with different size")
    ASN1_GENERALSTRING
  else:
    ASN1_GENERALSTRING_536871597)
  lsquic_stream_t_536871415 = (when declared(lsquic_stream_t):
    when ownSizeof(lsquic_stream_t) != ownSizeof(lsquic_stream_t_536871414):
      static :
        warning("Declaration of " & "lsquic_stream_t" &
            " exists but with different size")
    lsquic_stream_t
  else:
    lsquic_stream_t_536871414)
  ASN1_TLC_536871564 = (when declared(ASN1_TLC):
    when ownSizeof(ASN1_TLC) != ownSizeof(ASN1_TLC_536871563):
      static :
        warning("Declaration of " & "ASN1_TLC" &
            " exists but with different size")
    ASN1_TLC
  else:
    ASN1_TLC_536871563)
  struct_BIT_STRING_BITNAME_st_536871622 = (when declared(
      struct_BIT_STRING_BITNAME_st):
    when ownSizeof(struct_BIT_STRING_BITNAME_st) !=
        ownSizeof(struct_BIT_STRING_BITNAME_st_536871621):
      static :
        warning("Declaration of " & "struct_BIT_STRING_BITNAME_st" &
            " exists but with different size")
    struct_BIT_STRING_BITNAME_st
  else:
    struct_BIT_STRING_BITNAME_st_536871621)
  ASN1_TIME_536871640 = (when declared(ASN1_TIME):
    when ownSizeof(ASN1_TIME) != ownSizeof(ASN1_TIME_536871639):
      static :
        warning("Declaration of " & "ASN1_TIME" &
            " exists but with different size")
    ASN1_TIME
  else:
    ASN1_TIME_536871639)
  SSL_DANE_536871772 = (when declared(SSL_DANE):
    when ownSizeof(SSL_DANE) != ownSizeof(SSL_DANE_536871771):
      static :
        warning("Declaration of " & "SSL_DANE" &
            " exists but with different size")
    SSL_DANE
  else:
    SSL_DANE_536871771)
  off_t_536871778 = (when declared(off_t):
    when ownSizeof(off_t) != ownSizeof(off_t_536871777):
      static :
        warning("Declaration of " & "off_t" & " exists but with different size")
    off_t
  else:
    off_t_536871777)
  SSL_TICKET_STATUS_536871792 = (when declared(SSL_TICKET_STATUS):
    when ownSizeof(SSL_TICKET_STATUS) != ownSizeof(SSL_TICKET_STATUS_536871791):
      static :
        warning("Declaration of " & "SSL_TICKET_STATUS" &
            " exists but with different size")
    SSL_TICKET_STATUS
  else:
    SSL_TICKET_STATUS_536871791)
  struct_srtp_protection_profile_st_536871692 = (when declared(
      struct_srtp_protection_profile_st):
    when ownSizeof(struct_srtp_protection_profile_st) !=
        ownSizeof(struct_srtp_protection_profile_st_536871691):
      static :
        warning("Declaration of " & "struct_srtp_protection_profile_st" &
            " exists but with different size")
    struct_srtp_protection_profile_st
  else:
    struct_srtp_protection_profile_st_536871691)
  compiler_time_t_536871815 = (when declared(compiler_time_t):
    when ownSizeof(compiler_time_t) != ownSizeof(compiler_time_t_536871814):
      static :
        warning("Declaration of " & "compiler_time_t" &
            " exists but with different size")
    compiler_time_t
  else:
    compiler_time_t_536871814)
  TLS_SIGALGS_536871686 = (when declared(TLS_SIGALGS):
    when ownSizeof(TLS_SIGALGS) != ownSizeof(TLS_SIGALGS_536871685):
      static :
        warning("Declaration of " & "TLS_SIGALGS" &
            " exists but with different size")
    TLS_SIGALGS
  else:
    TLS_SIGALGS_536871685)
  OPENSSL_sk_copyfunc_536871496 = (when declared(OPENSSL_sk_copyfunc):
    when ownSizeof(OPENSSL_sk_copyfunc) != ownSizeof(OPENSSL_sk_copyfunc_536871495):
      static :
        warning("Declaration of " & "OPENSSL_sk_copyfunc" &
            " exists but with different size")
    OPENSSL_sk_copyfunc
  else:
    OPENSSL_sk_copyfunc_536871495)
  sk_SSL_COMP_compfunc_536871756 = (when declared(sk_SSL_COMP_compfunc):
    when ownSizeof(sk_SSL_COMP_compfunc) != ownSizeof(sk_SSL_COMP_compfunc_536871755):
      static :
        warning("Declaration of " & "sk_SSL_COMP_compfunc" &
            " exists but with different size")
    sk_SSL_COMP_compfunc
  else:
    sk_SSL_COMP_compfunc_536871755)
  ssize_t_536871429 = (when declared(ssize_t):
    when ownSizeof(ssize_t) != ownSizeof(ssize_t_536871428):
      static :
        warning("Declaration of " & "ssize_t" &
            " exists but with different size")
    ssize_t
  else:
    ssize_t_536871428)
  ssl_ct_validation_cb_536871786 = (when declared(ssl_ct_validation_cb):
    when ownSizeof(ssl_ct_validation_cb) != ownSizeof(ssl_ct_validation_cb_536871785):
      static :
        warning("Declaration of " & "ssl_ct_validation_cb" &
            " exists but with different size")
    ssl_ct_validation_cb
  else:
    ssl_ct_validation_cb_536871785)
  BIT_STRING_BITNAME_536871624 = (when declared(BIT_STRING_BITNAME):
    when ownSizeof(BIT_STRING_BITNAME) != ownSizeof(BIT_STRING_BITNAME_536871623):
      static :
        warning("Declaration of " & "BIT_STRING_BITNAME" &
            " exists but with different size")
    BIT_STRING_BITNAME
  else:
    BIT_STRING_BITNAME_536871623)
  SSL_CTX_alpn_select_cb_func_536871738 = (when declared(
      SSL_CTX_alpn_select_cb_func):
    when ownSizeof(SSL_CTX_alpn_select_cb_func) !=
        ownSizeof(SSL_CTX_alpn_select_cb_func_536871737):
      static :
        warning("Declaration of " & "SSL_CTX_alpn_select_cb_func" &
            " exists but with different size")
    SSL_CTX_alpn_select_cb_func
  else:
    SSL_CTX_alpn_select_cb_func_536871737)
  OPENSSL_INIT_SETTINGS_536871520 = (when declared(OPENSSL_INIT_SETTINGS):
    when ownSizeof(OPENSSL_INIT_SETTINGS) != ownSizeof(OPENSSL_INIT_SETTINGS_536871519):
      static :
        warning("Declaration of " & "OPENSSL_INIT_SETTINGS" &
            " exists but with different size")
    OPENSSL_INIT_SETTINGS
  else:
    OPENSSL_INIT_SETTINGS_536871519)
  struct_asn1_string_st_536871546 = (when declared(struct_asn1_string_st):
    when ownSizeof(struct_asn1_string_st) != ownSizeof(struct_asn1_string_st_536871545):
      static :
        warning("Declaration of " & "struct_asn1_string_st" &
            " exists but with different size")
    struct_asn1_string_st
  else:
    struct_asn1_string_st_536871545)
  enum_OSSL_HANDSHAKE_STATE_536871762 = (when declared(enum_OSSL_HANDSHAKE_STATE):
    when ownSizeof(enum_OSSL_HANDSHAKE_STATE) !=
        ownSizeof(enum_OSSL_HANDSHAKE_STATE_536871761):
      static :
        warning("Declaration of " & "enum_OSSL_HANDSHAKE_STATE" &
            " exists but with different size")
    enum_OSSL_HANDSHAKE_STATE
  else:
    enum_OSSL_HANDSHAKE_STATE_536871761)
  sk_ASN1_OBJECT_copyfunc_536871630 = (when declared(sk_ASN1_OBJECT_copyfunc):
    when ownSizeof(sk_ASN1_OBJECT_copyfunc) !=
        ownSizeof(sk_ASN1_OBJECT_copyfunc_536871629):
      static :
        warning("Declaration of " & "sk_ASN1_OBJECT_copyfunc" &
            " exists but with different size")
    sk_ASN1_OBJECT_copyfunc
  else:
    sk_ASN1_OBJECT_copyfunc_536871629)
  lsquic_conn_ctx_t_536871413 = (when declared(lsquic_conn_ctx_t):
    when ownSizeof(lsquic_conn_ctx_t) != ownSizeof(lsquic_conn_ctx_t_536871412):
      static :
        warning("Declaration of " & "lsquic_conn_ctx_t" &
            " exists but with different size")
    lsquic_conn_ctx_t
  else:
    lsquic_conn_ctx_t_536871412)
  sk_ASN1_TYPE_copyfunc_536871618 = (when declared(sk_ASN1_TYPE_copyfunc):
    when ownSizeof(sk_ASN1_TYPE_copyfunc) != ownSizeof(sk_ASN1_TYPE_copyfunc_536871617):
      static :
        warning("Declaration of " & "sk_ASN1_TYPE_copyfunc" &
            " exists but with different size")
    sk_ASN1_TYPE_copyfunc
  else:
    sk_ASN1_TYPE_copyfunc_536871617)
  enum_lsquic_version_536871423 = (when declared(enum_lsquic_version):
    when ownSizeof(enum_lsquic_version) != ownSizeof(enum_lsquic_version_536871422):
      static :
        warning("Declaration of " & "enum_lsquic_version" &
            " exists but with different size")
    enum_lsquic_version
  else:
    enum_lsquic_version_536871422)
  BIGNUM_536871656 = (when declared(BIGNUM):
    when ownSizeof(BIGNUM) != ownSizeof(BIGNUM_536871655):
      static :
        warning("Declaration of " & "BIGNUM" & " exists but with different size")
    BIGNUM
  else:
    BIGNUM_536871655)
  CTLOG_STORE_536871790 = (when declared(CTLOG_STORE):
    when ownSizeof(CTLOG_STORE) != ownSizeof(CTLOG_STORE_536871789):
      static :
        warning("Declaration of " & "CTLOG_STORE" &
            " exists but with different size")
    CTLOG_STORE
  else:
    CTLOG_STORE_536871789)
  OPENSSL_STACK_536871492 = (when declared(OPENSSL_STACK):
    when ownSizeof(OPENSSL_STACK) != ownSizeof(OPENSSL_STACK_536871491):
      static :
        warning("Declaration of " & "OPENSSL_STACK" &
            " exists but with different size")
    OPENSSL_STACK
  else:
    OPENSSL_STACK_536871491)
  ENGINE_536871732 = (when declared(ENGINE):
    when ownSizeof(ENGINE) != ownSizeof(ENGINE_536871731):
      static :
        warning("Declaration of " & "ENGINE" & " exists but with different size")
    ENGINE
  else:
    ENGINE_536871731)
  SSL_psk_client_cb_func_536871740 = (when declared(SSL_psk_client_cb_func):
    when ownSizeof(SSL_psk_client_cb_func) != ownSizeof(SSL_psk_client_cb_func_536871739):
      static :
        warning("Declaration of " & "SSL_psk_client_cb_func" &
            " exists but with different size")
    SSL_psk_client_cb_func
  else:
    SSL_psk_client_cb_func_536871739)
  DH_536871780 = (when declared(DH):
    when ownSizeof(DH) != ownSizeof(DH_536871779):
      static :
        warning("Declaration of " & "DH" & " exists but with different size")
    DH
  else:
    DH_536871779)
  SSL_TICKET_RETURN_536871794 = (when declared(SSL_TICKET_RETURN):
    when ownSizeof(SSL_TICKET_RETURN) != ownSizeof(SSL_TICKET_RETURN_536871793):
      static :
        warning("Declaration of " & "SSL_TICKET_RETURN" &
            " exists but with different size")
    SSL_TICKET_RETURN
  else:
    SSL_TICKET_RETURN_536871793)
  ASN1_TEMPLATE_536871562 = (when declared(ASN1_TEMPLATE):
    when ownSizeof(ASN1_TEMPLATE) != ownSizeof(ASN1_TEMPLATE_536871561):
      static :
        warning("Declaration of " & "ASN1_TEMPLATE" &
            " exists but with different size")
    ASN1_TEMPLATE
  else:
    ASN1_TEMPLATE_536871561)
  ASN1_ITEM_EXP_536871572 = (when declared(ASN1_ITEM_EXP):
    when ownSizeof(ASN1_ITEM_EXP) != ownSizeof(ASN1_ITEM_EXP_536871571):
      static :
        warning("Declaration of " & "ASN1_ITEM_EXP" &
            " exists but with different size")
    ASN1_ITEM_EXP
  else:
    ASN1_ITEM_EXP_536871571)
  SSL_allow_early_data_cb_fn_536871802 = (when declared(
      SSL_allow_early_data_cb_fn):
    when ownSizeof(SSL_allow_early_data_cb_fn) !=
        ownSizeof(SSL_allow_early_data_cb_fn_536871801):
      static :
        warning("Declaration of " & "SSL_allow_early_data_cb_fn" &
            " exists but with different size")
    SSL_allow_early_data_cb_fn
  else:
    SSL_allow_early_data_cb_fn_536871801)
  enum_lsquic_hsk_status_536871425 = (when declared(enum_lsquic_hsk_status):
    when ownSizeof(enum_lsquic_hsk_status) != ownSizeof(enum_lsquic_hsk_status_536871424):
      static :
        warning("Declaration of " & "enum_lsquic_hsk_status" &
            " exists but with different size")
    enum_lsquic_hsk_status
  else:
    enum_lsquic_hsk_status_536871424)
  struct_lsquic_packout_mem_if_536871445 = (when declared(
      struct_lsquic_packout_mem_if):
    when ownSizeof(struct_lsquic_packout_mem_if) !=
        ownSizeof(struct_lsquic_packout_mem_if_536871444):
      static :
        warning("Declaration of " & "struct_lsquic_packout_mem_if" &
            " exists but with different size")
    struct_lsquic_packout_mem_if
  else:
    struct_lsquic_packout_mem_if_536871444)
  EVP_PKEY_536871658 = (when declared(EVP_PKEY):
    when ownSizeof(EVP_PKEY) != ownSizeof(EVP_PKEY_536871657):
      static :
        warning("Declaration of " & "EVP_PKEY" &
            " exists but with different size")
    EVP_PKEY
  else:
    EVP_PKEY_536871657)
  sk_void_compfunc_536871486 = (when declared(sk_void_compfunc):
    when ownSizeof(sk_void_compfunc) != ownSizeof(sk_void_compfunc_536871485):
      static :
        warning("Declaration of " & "sk_void_compfunc" &
            " exists but with different size")
    sk_void_compfunc
  else:
    sk_void_compfunc_536871485)
  ASN1_IA5STRING_536871596 = (when declared(ASN1_IA5STRING):
    when ownSizeof(ASN1_IA5STRING) != ownSizeof(ASN1_IA5STRING_536871595):
      static :
        warning("Declaration of " & "ASN1_IA5STRING" &
            " exists but with different size")
    ASN1_IA5STRING
  else:
    ASN1_IA5STRING_536871595)
  sk_SSL_COMP_copyfunc_536871760 = (when declared(sk_SSL_COMP_copyfunc):
    when ownSizeof(sk_SSL_COMP_copyfunc) != ownSizeof(sk_SSL_COMP_copyfunc_536871759):
      static :
        warning("Declaration of " & "sk_SSL_COMP_copyfunc" &
            " exists but with different size")
    sk_SSL_COMP_copyfunc
  else:
    sk_SSL_COMP_copyfunc_536871759)
  SRTP_PROTECTION_PROFILE_536871694 = (when declared(SRTP_PROTECTION_PROFILE):
    when ownSizeof(SRTP_PROTECTION_PROFILE) !=
        ownSizeof(SRTP_PROTECTION_PROFILE_536871693):
      static :
        warning("Declaration of " & "SRTP_PROTECTION_PROFILE" &
            " exists but with different size")
    SRTP_PROTECTION_PROFILE
  else:
    SRTP_PROTECTION_PROFILE_536871693)
  sk_SRTP_PROTECTION_PROFILE_copyfunc_536871700 = (when declared(
      sk_SRTP_PROTECTION_PROFILE_copyfunc):
    when ownSizeof(sk_SRTP_PROTECTION_PROFILE_copyfunc) !=
        ownSizeof(sk_SRTP_PROTECTION_PROFILE_copyfunc_536871699):
      static :
        warning("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_copyfunc" &
            " exists but with different size")
    sk_SRTP_PROTECTION_PROFILE_copyfunc
  else:
    sk_SRTP_PROTECTION_PROFILE_copyfunc_536871699)
  BIO_ADDR_536871784 = (when declared(BIO_ADDR):
    when ownSizeof(BIO_ADDR) != ownSizeof(BIO_ADDR_536871783):
      static :
        warning("Declaration of " & "BIO_ADDR" &
            " exists but with different size")
    BIO_ADDR
  else:
    BIO_ADDR_536871783)
  sk_X509_ALGOR_compfunc_536871538 = (when declared(sk_X509_ALGOR_compfunc):
    when ownSizeof(sk_X509_ALGOR_compfunc) != ownSizeof(sk_X509_ALGOR_compfunc_536871537):
      static :
        warning("Declaration of " & "sk_X509_ALGOR_compfunc" &
            " exists but with different size")
    sk_X509_ALGOR_compfunc
  else:
    sk_X509_ALGOR_compfunc_536871537)
  CRYPTO_THREAD_ID_typedef_536871530 = (when declared(CRYPTO_THREAD_ID_typedef):
    when ownSizeof(CRYPTO_THREAD_ID_typedef) !=
        ownSizeof(CRYPTO_THREAD_ID_typedef_536871529):
      static :
        warning("Declaration of " & "CRYPTO_THREAD_ID_typedef" &
            " exists but with different size")
    CRYPTO_THREAD_ID_typedef
  else:
    CRYPTO_THREAD_ID_typedef_536871529)
  struct_lsquic_ext_http_prio_536871464 = (when declared(
      struct_lsquic_ext_http_prio):
    when ownSizeof(struct_lsquic_ext_http_prio) !=
        ownSizeof(struct_lsquic_ext_http_prio_536871463):
      static :
        warning("Declaration of " & "struct_lsquic_ext_http_prio" &
            " exists but with different size")
    struct_lsquic_ext_http_prio
  else:
    struct_lsquic_ext_http_prio_536871463)
  CT_POLICY_EVAL_CTX_536871788 = (when declared(CT_POLICY_EVAL_CTX):
    when ownSizeof(CT_POLICY_EVAL_CTX) != ownSizeof(CT_POLICY_EVAL_CTX_536871787):
      static :
        warning("Declaration of " & "CT_POLICY_EVAL_CTX" &
            " exists but with different size")
    CT_POLICY_EVAL_CTX
  else:
    CT_POLICY_EVAL_CTX_536871787)
  ASN1_ENUMERATED_536871586 = (when declared(ASN1_ENUMERATED):
    when ownSizeof(ASN1_ENUMERATED) != ownSizeof(ASN1_ENUMERATED_536871585):
      static :
        warning("Declaration of " & "ASN1_ENUMERATED" &
            " exists but with different size")
    ASN1_ENUMERATED
  else:
    ASN1_ENUMERATED_536871585)
  ASN1_UNIVERSALSTRING_536871602 = (when declared(ASN1_UNIVERSALSTRING):
    when ownSizeof(ASN1_UNIVERSALSTRING) != ownSizeof(ASN1_UNIVERSALSTRING_536871601):
      static :
        warning("Declaration of " & "ASN1_UNIVERSALSTRING" &
            " exists but with different size")
    ASN1_UNIVERSALSTRING
  else:
    ASN1_UNIVERSALSTRING_536871601)
  Cfile_536871662 = (when declared(Cfile):
    when ownSizeof(Cfile) != ownSizeof(Cfile_536871661):
      static :
        warning("Declaration of " & "Cfile" & " exists but with different size")
    Cfile
  else:
    Cfile_536871661)
  struct_lsquic_reader_536871462 = (when declared(struct_lsquic_reader):
    when ownSizeof(struct_lsquic_reader) != ownSizeof(struct_lsquic_reader_536871461):
      static :
        warning("Declaration of " & "struct_lsquic_reader" &
            " exists but with different size")
    struct_lsquic_reader
  else:
    struct_lsquic_reader_536871461)
  sk_SRTP_PROTECTION_PROFILE_compfunc_536871696 = (when declared(
      sk_SRTP_PROTECTION_PROFILE_compfunc):
    when ownSizeof(sk_SRTP_PROTECTION_PROFILE_compfunc) !=
        ownSizeof(sk_SRTP_PROTECTION_PROFILE_compfunc_536871695):
      static :
        warning("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_compfunc" &
            " exists but with different size")
    sk_SRTP_PROTECTION_PROFILE_compfunc
  else:
    sk_SRTP_PROTECTION_PROFILE_compfunc_536871695)
  X509_ALGOR_536871540 = (when declared(X509_ALGOR):
    when ownSizeof(X509_ALGOR) != ownSizeof(X509_ALGOR_536871539):
      static :
        warning("Declaration of " & "X509_ALGOR" &
            " exists but with different size")
    X509_ALGOR
  else:
    X509_ALGOR_536871539)
  OPENSSL_sk_freefunc_536871498 = (when declared(OPENSSL_sk_freefunc):
    when ownSizeof(OPENSSL_sk_freefunc) != ownSizeof(OPENSSL_sk_freefunc_536871497):
      static :
        warning("Declaration of " & "OPENSSL_sk_freefunc" &
            " exists but with different size")
    OPENSSL_sk_freefunc
  else:
    OPENSSL_sk_freefunc_536871497)
  lsquic_packets_out_f_536871439 = (when declared(lsquic_packets_out_f):
    when ownSizeof(lsquic_packets_out_f) != ownSizeof(lsquic_packets_out_f_536871438):
      static :
        warning("Declaration of " & "lsquic_packets_out_f" &
            " exists but with different size")
    lsquic_packets_out_f
  else:
    lsquic_packets_out_f_536871438)
  ASN1_OCTET_STRING_536871590 = (when declared(ASN1_OCTET_STRING):
    when ownSizeof(ASN1_OCTET_STRING) != ownSizeof(ASN1_OCTET_STRING_536871589):
      static :
        warning("Declaration of " & "ASN1_OCTET_STRING" &
            " exists but with different size")
    ASN1_OCTET_STRING
  else:
    ASN1_OCTET_STRING_536871589)
  CRYPTO_realloc_fn_536871514 = (when declared(CRYPTO_realloc_fn):
    when ownSizeof(CRYPTO_realloc_fn) != ownSizeof(CRYPTO_realloc_fn_536871513):
      static :
        warning("Declaration of " & "CRYPTO_realloc_fn" &
            " exists but with different size")
    CRYPTO_realloc_fn
  else:
    CRYPTO_realloc_fn_536871513)
  ssl_crock_st_536871674 = (when declared(ssl_crock_st):
    when ownSizeof(ssl_crock_st) != ownSizeof(ssl_crock_st_536871673):
      static :
        warning("Declaration of " & "ssl_crock_st" &
            " exists but with different size")
    ssl_crock_st
  else:
    ssl_crock_st_536871673)
  RSA_536871770 = (when declared(RSA):
    when ownSizeof(RSA) != ownSizeof(RSA_536871769):
      static :
        warning("Declaration of " & "RSA" & " exists but with different size")
    RSA
  else:
    RSA_536871769)
  struct_X509_algor_st_536871819 = (when declared(struct_X509_algor_st):
    when ownSizeof(struct_X509_algor_st) != ownSizeof(struct_X509_algor_st_536871818):
      static :
        warning("Declaration of " & "struct_X509_algor_st" &
            " exists but with different size")
    struct_X509_algor_st
  else:
    struct_X509_algor_st_536871818)
  struct_asn1_string_table_st_536871552 = (when declared(
      struct_asn1_string_table_st):
    when ownSizeof(struct_asn1_string_table_st) !=
        ownSizeof(struct_asn1_string_table_st_536871551):
      static :
        warning("Declaration of " & "struct_asn1_string_table_st" &
            " exists but with different size")
    struct_asn1_string_table_st
  else:
    struct_asn1_string_table_st_536871551)
  sk_SSL_CIPHER_compfunc_536871750 = (when declared(sk_SSL_CIPHER_compfunc):
    when ownSizeof(sk_SSL_CIPHER_compfunc) != ownSizeof(sk_SSL_CIPHER_compfunc_536871749):
      static :
        warning("Declaration of " & "sk_SSL_CIPHER_compfunc" &
            " exists but with different size")
    sk_SSL_CIPHER_compfunc
  else:
    sk_SSL_CIPHER_compfunc_536871749)
  ASN1_STRING_536871580 = (when declared(ASN1_STRING):
    when ownSizeof(ASN1_STRING) != ownSizeof(ASN1_STRING_536871579):
      static :
        warning("Declaration of " & "ASN1_STRING" &
            " exists but with different size")
    ASN1_STRING
  else:
    ASN1_STRING_536871579)
  ASN1_UTF8STRING_536871610 = (when declared(ASN1_UTF8STRING):
    when ownSizeof(ASN1_UTF8STRING) != ownSizeof(ASN1_UTF8STRING_536871609):
      static :
        warning("Declaration of " & "ASN1_UTF8STRING" &
            " exists but with different size")
    ASN1_UTF8STRING
  else:
    ASN1_UTF8STRING_536871609)
  struct_conf_method_st_536871835 = (when declared(struct_conf_method_st):
    when ownSizeof(struct_conf_method_st) != ownSizeof(struct_conf_method_st_536871834):
      static :
        warning("Declaration of " & "struct_conf_method_st" &
            " exists but with different size")
    struct_conf_method_st
  else:
    struct_conf_method_st_536871834)
  ASN1_NULL_536871648 = (when declared(ASN1_NULL):
    when ownSizeof(ASN1_NULL) != ownSizeof(ASN1_NULL_536871647):
      static :
        warning("Declaration of " & "ASN1_NULL" &
            " exists but with different size")
    ASN1_NULL
  else:
    ASN1_NULL_536871647)
when not declared(CRYPTO_EX_new):
  type
    CRYPTO_EX_new* = CRYPTO_EX_new_536871499
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_new" &
        " already exists, not redeclaring")
when not declared(sk_X509_ALGOR_freefunc):
  type
    sk_X509_ALGOR_freefunc* = sk_X509_ALGOR_freefunc_536871541
else:
  static :
    hint("Declaration of " & "sk_X509_ALGOR_freefunc" &
        " already exists, not redeclaring")
when not declared(tls_session_ticket_ext_cb_fn):
  type
    tls_session_ticket_ext_cb_fn* = tls_session_ticket_ext_cb_fn_536871701
else:
  static :
    hint("Declaration of " & "tls_session_ticket_ext_cb_fn" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_npn_select_cb_func):
  type
    SSL_CTX_npn_select_cb_func* = SSL_CTX_npn_select_cb_func_536871735
else:
  static :
    hint("Declaration of " & "SSL_CTX_npn_select_cb_func" &
        " already exists, not redeclaring")
when not declared(struct_ossl_dispatch_st):
  type
    struct_ossl_dispatch_st* = struct_ossl_dispatch_st_536871816
else:
  static :
    hint("Declaration of " & "struct_ossl_dispatch_st" &
        " already exists, not redeclaring")
when not declared(CRYPTO_dynlock):
  type
    CRYPTO_dynlock* = CRYPTO_dynlock_536871477
else:
  static :
    hint("Declaration of " & "CRYPTO_dynlock" &
        " already exists, not redeclaring")
when not declared(struct_IO_FILE):
  type
    struct_IO_FILE* = struct_IO_FILE_536871820
else:
  static :
    hint("Declaration of " & "struct_IO_FILE" &
        " already exists, not redeclaring")
when not declared(struct_conf_st):
  type
    struct_conf_st* = struct_conf_st_536871822
else:
  static :
    hint("Declaration of " & "struct_conf_st" &
        " already exists, not redeclaring")
when not declared(SSL_COMP):
  type
    SSL_COMP* = SSL_COMP_536871689
else:
  static :
    hint("Declaration of " & "SSL_COMP" & " already exists, not redeclaring")
when not declared(CRYPTO_EX_free):
  type
    CRYPTO_EX_free* = CRYPTO_EX_free_536871503
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_free" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX):
  type
    ASN1_SCTX* = ASN1_SCTX_536871669
else:
  static :
    hint("Declaration of " & "ASN1_SCTX" & " already exists, not redeclaring")
when not declared(SSL_CTX_decrypt_session_ticket_fn):
  type
    SSL_CTX_decrypt_session_ticket_fn* = SSL_CTX_decrypt_session_ticket_fn_536871797
else:
  static :
    hint("Declaration of " & "SSL_CTX_decrypt_session_ticket_fn" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_STRING_TABLE_compfunc):
  type
    sk_ASN1_STRING_TABLE_compfunc* = sk_ASN1_STRING_TABLE_compfunc_536871553
else:
  static :
    hint("Declaration of " & "sk_ASN1_STRING_TABLE_compfunc" &
        " already exists, not redeclaring")
when not declared(SSL_custom_ext_add_cb_ex):
  type
    SSL_custom_ext_add_cb_ex* = SSL_custom_ext_add_cb_ex_536871713
else:
  static :
    hint("Declaration of " & "SSL_custom_ext_add_cb_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_BMPSTRING):
  type
    ASN1_BMPSTRING* = ASN1_BMPSTRING_536871599
else:
  static :
    hint("Declaration of " & "ASN1_BMPSTRING" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_GENERALSTRING_copyfunc):
  type
    sk_ASN1_GENERALSTRING_copyfunc* = sk_ASN1_GENERALSTRING_copyfunc_536871653
else:
  static :
    hint("Declaration of " & "sk_ASN1_GENERALSTRING_copyfunc" &
        " already exists, not redeclaring")
when not declared(SSL_custom_ext_free_cb_ex):
  type
    SSL_custom_ext_free_cb_ex* = SSL_custom_ext_free_cb_ex_536871717
else:
  static :
    hint("Declaration of " & "SSL_custom_ext_free_cb_ex" &
        " already exists, not redeclaring")
when not declared(SSL_CTX):
  type
    SSL_CTX* = SSL_CTX_536871727
else:
  static :
    hint("Declaration of " & "SSL_CTX" & " already exists, not redeclaring")
when not declared(SSL):
  type
    SSL* = SSL_536871703
else:
  static :
    hint("Declaration of " & "SSL" & " already exists, not redeclaring")
when not declared(lsquic_stream_id_t):
  type
    lsquic_stream_id_t* = lsquic_stream_id_t_536871406
else:
  static :
    hint("Declaration of " & "lsquic_stream_id_t" &
        " already exists, not redeclaring")
when not declared(struct_iovec):
  type
    struct_iovec* = struct_iovec_536871436
else:
  static :
    hint("Declaration of " & "struct_iovec" & " already exists, not redeclaring")
when not declared(struct_lsquic_engine_api):
  type
    struct_lsquic_engine_api* = struct_lsquic_engine_api_536871459
else:
  static :
    hint("Declaration of " & "struct_lsquic_engine_api" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_UTF8STRING_freefunc):
  type
    sk_ASN1_UTF8STRING_freefunc* = sk_ASN1_UTF8STRING_freefunc_536871643
else:
  static :
    hint("Declaration of " & "sk_ASN1_UTF8STRING_freefunc" &
        " already exists, not redeclaring")
when not declared(SSL_async_callback_fn):
  type
    SSL_async_callback_fn* = SSL_async_callback_fn_536871725
else:
  static :
    hint("Declaration of " & "SSL_async_callback_fn" &
        " already exists, not redeclaring")
when not declared(struct_tm):
  type
    struct_tm* = struct_tm_536871517
else:
  static :
    hint("Declaration of " & "struct_tm" & " already exists, not redeclaring")
when not declared(SSL_CIPHER):
  type
    SSL_CIPHER* = SSL_CIPHER_536871681
else:
  static :
    hint("Declaration of " & "SSL_CIPHER" & " already exists, not redeclaring")
when not declared(CRYPTO_ONCE):
  type
    CRYPTO_ONCE* = CRYPTO_ONCE_536871521
else:
  static :
    hint("Declaration of " & "CRYPTO_ONCE" & " already exists, not redeclaring")
when not declared(SSL_verify_cb):
  type
    SSL_verify_cb* = SSL_verify_cb_536871721
else:
  static :
    hint("Declaration of " & "SSL_verify_cb" &
        " already exists, not redeclaring")
when not declared(struct_lhash_st_CONF_VALUE):
  type
    struct_lhash_st_CONF_VALUE* = struct_lhash_st_CONF_VALUE_536871832
else:
  static :
    hint("Declaration of " & "struct_lhash_st_CONF_VALUE" &
        " already exists, not redeclaring")
when not declared(enum_lsquic_crypto_ver):
  type
    enum_lsquic_crypto_ver* = enum_lsquic_crypto_ver_536871469
else:
  static :
    hint("Declaration of " & "enum_lsquic_crypto_ver" &
        " already exists, not redeclaring")
when not declared(uint_fast8_t):
  type
    uint_fast8_t* = uint_fast8_t_536871402
else:
  static :
    hint("Declaration of " & "uint_fast8_t" & " already exists, not redeclaring")
when not declared(ASN1_SEQUENCE_ANY):
  type
    ASN1_SEQUENCE_ANY* = ASN1_SEQUENCE_ANY_536871619
else:
  static :
    hint("Declaration of " & "ASN1_SEQUENCE_ANY" &
        " already exists, not redeclaring")
when not declared(sk_void_freefunc):
  type
    sk_void_freefunc* = sk_void_freefunc_536871487
else:
  static :
    hint("Declaration of " & "sk_void_freefunc" &
        " already exists, not redeclaring")
when not declared(i2d_of_void):
  type
    i2d_of_void* = i2d_of_void_536871569
else:
  static :
    hint("Declaration of " & "i2d_of_void" & " already exists, not redeclaring")
when not declared(struct_lsquic_logger_if):
  type
    struct_lsquic_logger_if* = struct_lsquic_logger_if_536871465
else:
  static :
    hint("Declaration of " & "struct_lsquic_logger_if" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_keylog_cb_func):
  type
    SSL_CTX_keylog_cb_func* = SSL_CTX_keylog_cb_func_536871747
else:
  static :
    hint("Declaration of " & "SSL_CTX_keylog_cb_func" &
        " already exists, not redeclaring")
when not declared(X509):
  type
    X509* = X509_536871715
else:
  static :
    hint("Declaration of " & "X509" & " already exists, not redeclaring")
when not declared(pthread_key_t):
  type
    pthread_key_t* = pthread_key_t_536871527
else:
  static :
    hint("Declaration of " & "pthread_key_t" &
        " already exists, not redeclaring")
when not declared(pthread_t):
  type
    pthread_t* = pthread_t_536871531
else:
  static :
    hint("Declaration of " & "pthread_t" & " already exists, not redeclaring")
when not declared(GEN_SESSION_CB):
  type
    GEN_SESSION_CB* = GEN_SESSION_CB_536871729
else:
  static :
    hint("Declaration of " & "GEN_SESSION_CB" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_INTEGER_freefunc):
  type
    sk_ASN1_INTEGER_freefunc* = sk_ASN1_INTEGER_freefunc_536871635
else:
  static :
    hint("Declaration of " & "sk_ASN1_INTEGER_freefunc" &
        " already exists, not redeclaring")
when not declared(enum_LSQUIC_CONN_STATUS):
  type
    enum_LSQUIC_CONN_STATUS* = enum_LSQUIC_CONN_STATUS_536871473
else:
  static :
    hint("Declaration of " & "enum_LSQUIC_CONN_STATUS" &
        " already exists, not redeclaring")
when not declared(struct_ASN1_ENCODING_st):
  type
    struct_ASN1_ENCODING_st* = struct_ASN1_ENCODING_st_536871547
else:
  static :
    hint("Declaration of " & "struct_ASN1_ENCODING_st" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREADID):
  type
    CRYPTO_THREADID* = CRYPTO_THREADID_536871509
else:
  static :
    hint("Declaration of " & "CRYPTO_THREADID" &
        " already exists, not redeclaring")
when not declared(struct_CRYPTO_dynlock):
  type
    struct_CRYPTO_dynlock* = struct_CRYPTO_dynlock_536871475
else:
  static :
    hint("Declaration of " & "struct_CRYPTO_dynlock" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_OBJECT_freefunc):
  type
    sk_ASN1_OBJECT_freefunc* = sk_ASN1_OBJECT_freefunc_536871627
else:
  static :
    hint("Declaration of " & "sk_ASN1_OBJECT_freefunc" &
        " already exists, not redeclaring")
when not declared(sk_SSL_CIPHER_copyfunc):
  type
    sk_SSL_CIPHER_copyfunc* = sk_SSL_CIPHER_copyfunc_536871753
else:
  static :
    hint("Declaration of " & "sk_SSL_CIPHER_copyfunc" &
        " already exists, not redeclaring")
when not declared(CONF_METHOD):
  type
    CONF_METHOD* = CONF_METHOD_536871830
else:
  static :
    hint("Declaration of " & "CONF_METHOD" & " already exists, not redeclaring")
when not declared(struct_lsquic_shared_hash_if):
  type
    struct_lsquic_shared_hash_if* = struct_lsquic_shared_hash_if_536871440
else:
  static :
    hint("Declaration of " & "struct_lsquic_shared_hash_if" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_out_spec):
  type
    struct_lsquic_out_spec* = struct_lsquic_out_spec_536871434
else:
  static :
    hint("Declaration of " & "struct_lsquic_out_spec" &
        " already exists, not redeclaring")
when not declared(CONF):
  type
    CONF* = CONF_536871663
else:
  static :
    hint("Declaration of " & "CONF" & " already exists, not redeclaring")
when not declared(SSL_SESSION):
  type
    SSL_SESSION* = SSL_SESSION_536871683
else:
  static :
    hint("Declaration of " & "SSL_SESSION" & " already exists, not redeclaring")
when not declared(sk_ASN1_UTF8STRING_copyfunc):
  type
    sk_ASN1_UTF8STRING_copyfunc* = sk_ASN1_UTF8STRING_copyfunc_536871645
else:
  static :
    hint("Declaration of " & "sk_ASN1_UTF8STRING_copyfunc" &
        " already exists, not redeclaring")
when not declared(sk_X509_ALGOR_copyfunc):
  type
    sk_X509_ALGOR_copyfunc* = sk_X509_ALGOR_copyfunc_536871543
else:
  static :
    hint("Declaration of " & "sk_X509_ALGOR_copyfunc" &
        " already exists, not redeclaring")
when not declared(struct_crypto_threadid_st):
  type
    struct_crypto_threadid_st* = struct_crypto_threadid_st_536871507
else:
  static :
    hint("Declaration of " & "struct_crypto_threadid_st" &
        " already exists, not redeclaring")
when not declared(lsquic_http_headers_t):
  type
    lsquic_http_headers_t* = lsquic_http_headers_t_536871418
else:
  static :
    hint("Declaration of " & "lsquic_http_headers_t" &
        " already exists, not redeclaring")
when not declared(custom_ext_free_cb):
  type
    custom_ext_free_cb* = custom_ext_free_cb_536871709
else:
  static :
    hint("Declaration of " & "custom_ext_free_cb" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME):
  type
    ASN1_UTCTIME* = ASN1_UTCTIME_536871603
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME" & " already exists, not redeclaring")
when not declared(CRYPTO_EX_DATA):
  type
    CRYPTO_EX_DATA* = CRYPTO_EX_DATA_536871501
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_DATA" &
        " already exists, not redeclaring")
when not declared(OSSL_HANDSHAKE_STATE):
  type
    OSSL_HANDSHAKE_STATE* = OSSL_HANDSHAKE_STATE_536871763
else:
  static :
    hint("Declaration of " & "OSSL_HANDSHAKE_STATE" &
        " already exists, not redeclaring")
when not declared(compiler_off_t):
  type
    compiler_off_t* = compiler_off_t_536871824
else:
  static :
    hint("Declaration of " & "compiler_off_t" &
        " already exists, not redeclaring")
when not declared(SSL_METHOD):
  type
    SSL_METHOD* = SSL_METHOD_536871679
else:
  static :
    hint("Declaration of " & "SSL_METHOD" & " already exists, not redeclaring")
when not declared(custom_ext_parse_cb):
  type
    custom_ext_parse_cb* = custom_ext_parse_cb_536871711
else:
  static :
    hint("Declaration of " & "custom_ext_parse_cb" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_LOCAL):
  type
    CRYPTO_THREAD_LOCAL* = CRYPTO_THREAD_LOCAL_536871525
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_LOCAL" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_http_headers):
  type
    struct_lsquic_http_headers* = struct_lsquic_http_headers_536871420
else:
  static :
    hint("Declaration of " & "struct_lsquic_http_headers" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLESTRING):
  type
    ASN1_PRINTABLESTRING* = ASN1_PRINTABLESTRING_536871591
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(CRYPTO_free_fn):
  type
    CRYPTO_free_fn* = CRYPTO_free_fn_536871515
else:
  static :
    hint("Declaration of " & "CRYPTO_free_fn" &
        " already exists, not redeclaring")
when not declared(ASN1_T61STRING):
  type
    ASN1_T61STRING* = ASN1_T61STRING_536871593
else:
  static :
    hint("Declaration of " & "ASN1_T61STRING" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_hset_if):
  type
    struct_lsquic_hset_if* = struct_lsquic_hset_if_536871457
else:
  static :
    hint("Declaration of " & "struct_lsquic_hset_if" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_t):
  type
    lsquic_conn_t* = lsquic_conn_t_536871410
else:
  static :
    hint("Declaration of " & "lsquic_conn_t" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_dup):
  type
    CRYPTO_EX_dup* = CRYPTO_EX_dup_536871505
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME):
  type
    ASN1_GENERALIZEDTIME* = ASN1_GENERALIZEDTIME_536871605
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_STRING_TABLE_copyfunc):
  type
    sk_ASN1_STRING_TABLE_copyfunc* = sk_ASN1_STRING_TABLE_copyfunc_536871559
else:
  static :
    hint("Declaration of " & "sk_ASN1_STRING_TABLE_copyfunc" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX):
  type
    OSSL_LIB_CTX* = OSSL_LIB_CTX_536871483
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX" & " already exists, not redeclaring")
when not declared(ASN1_OBJECT):
  type
    ASN1_OBJECT* = ASN1_OBJECT_536871581
else:
  static :
    hint("Declaration of " & "ASN1_OBJECT" & " already exists, not redeclaring")
when not declared(sk_ASN1_OBJECT_compfunc):
  type
    sk_ASN1_OBJECT_compfunc* = sk_ASN1_OBJECT_compfunc_536871625
else:
  static :
    hint("Declaration of " & "sk_ASN1_OBJECT_compfunc" &
        " already exists, not redeclaring")
when not declared(sk_SSL_COMP_freefunc):
  type
    sk_SSL_COMP_freefunc* = sk_SSL_COMP_freefunc_536871757
else:
  static :
    hint("Declaration of " & "sk_SSL_COMP_freefunc" &
        " already exists, not redeclaring")
when not declared(OSSL_CORE_HANDLE):
  type
    OSSL_CORE_HANDLE* = OSSL_CORE_HANDLE_536871533
else:
  static :
    hint("Declaration of " & "OSSL_CORE_HANDLE" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE):
  type
    ASN1_TYPE* = ASN1_TYPE_536871613
else:
  static :
    hint("Declaration of " & "ASN1_TYPE" & " already exists, not redeclaring")
when not declared(X509_STORE):
  type
    X509_STORE* = X509_STORE_536871767
else:
  static :
    hint("Declaration of " & "X509_STORE" & " already exists, not redeclaring")
when not declared(ASN1_BOOLEAN):
  type
    ASN1_BOOLEAN* = ASN1_BOOLEAN_536871577
else:
  static :
    hint("Declaration of " & "ASN1_BOOLEAN" & " already exists, not redeclaring")
when not declared(sk_ASN1_GENERALSTRING_compfunc):
  type
    sk_ASN1_GENERALSTRING_compfunc* = sk_ASN1_GENERALSTRING_compfunc_536871649
else:
  static :
    hint("Declaration of " & "sk_ASN1_GENERALSTRING_compfunc" &
        " already exists, not redeclaring")
when not declared(custom_ext_add_cb):
  type
    custom_ext_add_cb* = custom_ext_add_cb_536871707
else:
  static :
    hint("Declaration of " & "custom_ext_add_cb" &
        " already exists, not redeclaring")
when not declared(lsquic_cid_t):
  type
    lsquic_cid_t* = lsquic_cid_t_536871404
else:
  static :
    hint("Declaration of " & "lsquic_cid_t" & " already exists, not redeclaring")
when not declared(SSL_psk_use_session_cb_func):
  type
    SSL_psk_use_session_cb_func* = SSL_psk_use_session_cb_func_536871745
else:
  static :
    hint("Declaration of " & "SSL_psk_use_session_cb_func" &
        " already exists, not redeclaring")
when not declared(struct_asn1_type_st):
  type
    struct_asn1_type_st* = struct_asn1_type_st_536871575
else:
  static :
    hint("Declaration of " & "struct_asn1_type_st" &
        " already exists, not redeclaring")
when not declared(OSSL_DISPATCH):
  type
    OSSL_DISPATCH* = OSSL_DISPATCH_536871535
else:
  static :
    hint("Declaration of " & "OSSL_DISPATCH" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_INTEGER_copyfunc):
  type
    sk_ASN1_INTEGER_copyfunc* = sk_ASN1_INTEGER_copyfunc_536871637
else:
  static :
    hint("Declaration of " & "sk_ASN1_INTEGER_copyfunc" &
        " already exists, not redeclaring")
when not declared(SSL_psk_server_cb_func):
  type
    SSL_psk_server_cb_func* = SSL_psk_server_cb_func_536871741
else:
  static :
    hint("Declaration of " & "SSL_psk_server_cb_func" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_TYPE_freefunc):
  type
    sk_ASN1_TYPE_freefunc* = sk_ASN1_TYPE_freefunc_536871615
else:
  static :
    hint("Declaration of " & "sk_ASN1_TYPE_freefunc" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_INTEGER_compfunc):
  type
    sk_ASN1_INTEGER_compfunc* = sk_ASN1_INTEGER_compfunc_536871633
else:
  static :
    hint("Declaration of " & "sk_ASN1_INTEGER_compfunc" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_npn_advertised_cb_func):
  type
    SSL_CTX_npn_advertised_cb_func* = SSL_CTX_npn_advertised_cb_func_536871733
else:
  static :
    hint("Declaration of " & "SSL_CTX_npn_advertised_cb_func" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_GENERALSTRING_freefunc):
  type
    sk_ASN1_GENERALSTRING_freefunc* = sk_ASN1_GENERALSTRING_freefunc_536871651
else:
  static :
    hint("Declaration of " & "sk_ASN1_GENERALSTRING_freefunc" &
        " already exists, not redeclaring")
when not declared(struct_crypto_ex_data_st):
  type
    struct_crypto_ex_data_st* = struct_crypto_ex_data_st_536871481
else:
  static :
    hint("Declaration of " & "struct_crypto_ex_data_st" &
        " already exists, not redeclaring")
when not declared(ASN1_ITEM):
  type
    ASN1_ITEM* = ASN1_ITEM_536871573
else:
  static :
    hint("Declaration of " & "ASN1_ITEM" & " already exists, not redeclaring")
when not declared(lsquic_cids_update_f):
  type
    lsquic_cids_update_f* = lsquic_cids_update_f_536871446
else:
  static :
    hint("Declaration of " & "lsquic_cids_update_f" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX):
  type
    SSL_CONF_CTX* = SSL_CONF_CTX_536871687
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX" & " already exists, not redeclaring")
when not declared(sk_void_copyfunc):
  type
    sk_void_copyfunc* = sk_void_copyfunc_536871489
else:
  static :
    hint("Declaration of " & "sk_void_copyfunc" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_conn_info):
  type
    struct_lsquic_conn_info* = struct_lsquic_conn_info_536871471
else:
  static :
    hint("Declaration of " & "struct_lsquic_conn_info" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_TYPE_compfunc):
  type
    sk_ASN1_TYPE_compfunc* = sk_ASN1_TYPE_compfunc_536871611
else:
  static :
    hint("Declaration of " & "sk_ASN1_TYPE_compfunc" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_ctx_t):
  type
    lsquic_stream_ctx_t* = lsquic_stream_ctx_t_536871416
else:
  static :
    hint("Declaration of " & "lsquic_stream_ctx_t" &
        " already exists, not redeclaring")
when not declared(BIO):
  type
    BIO* = BIO_536871631
else:
  static :
    hint("Declaration of " & "BIO" & " already exists, not redeclaring")
when not declared(ASN1_PCTX):
  type
    ASN1_PCTX* = ASN1_PCTX_536871667
else:
  static :
    hint("Declaration of " & "ASN1_PCTX" & " already exists, not redeclaring")
when not declared(RAND_METHOD):
  type
    RAND_METHOD* = RAND_METHOD_536871805
else:
  static :
    hint("Declaration of " & "RAND_METHOD" & " already exists, not redeclaring")
when not declared(SSL_CTX_generate_session_ticket_fn):
  type
    SSL_CTX_generate_session_ticket_fn* = SSL_CTX_generate_session_ticket_fn_536871795
else:
  static :
    hint("Declaration of " & "SSL_CTX_generate_session_ticket_fn" &
        " already exists, not redeclaring")
when not declared(ASN1_VALUE):
  type
    ASN1_VALUE* = ASN1_VALUE_536871565
else:
  static :
    hint("Declaration of " & "ASN1_VALUE" & " already exists, not redeclaring")
when not declared(pthread_once_t):
  type
    pthread_once_t* = pthread_once_t_536871523
else:
  static :
    hint("Declaration of " & "pthread_once_t" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_TABLE):
  type
    ASN1_STRING_TABLE* = ASN1_STRING_TABLE_536871555
else:
  static :
    hint("Declaration of " & "ASN1_STRING_TABLE" &
        " already exists, not redeclaring")
when not declared(SSL_custom_ext_parse_cb_ex):
  type
    SSL_custom_ext_parse_cb_ex* = SSL_custom_ext_parse_cb_ex_536871719
else:
  static :
    hint("Declaration of " & "SSL_custom_ext_parse_cb_ex" &
        " already exists, not redeclaring")
when not declared(X509_VERIFY_PARAM):
  type
    X509_VERIFY_PARAM* = X509_VERIFY_PARAM_536871773
else:
  static :
    hint("Declaration of " & "X509_VERIFY_PARAM" &
        " already exists, not redeclaring")
when not declared(compiler_off64_t):
  type
    compiler_off64_t* = compiler_off64_t_536871828
else:
  static :
    hint("Declaration of " & "compiler_off64_t" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_stream_if):
  type
    struct_lsquic_stream_if* = struct_lsquic_stream_if_536871426
else:
  static :
    hint("Declaration of " & "struct_lsquic_stream_if" &
        " already exists, not redeclaring")
when not declared(enum_lsquic_logger_timestamp_style):
  type
    enum_lsquic_logger_timestamp_style* = enum_lsquic_logger_timestamp_style_536871467
else:
  static :
    hint("Declaration of " & "enum_lsquic_logger_timestamp_style" &
        " already exists, not redeclaring")
when not declared(SSL_psk_find_session_cb_func):
  type
    SSL_psk_find_session_cb_func* = SSL_psk_find_session_cb_func_536871743
else:
  static :
    hint("Declaration of " & "SSL_psk_find_session_cb_func" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_cid):
  type
    struct_lsquic_cid* = struct_lsquic_cid_536871400
else:
  static :
    hint("Declaration of " & "struct_lsquic_cid" &
        " already exists, not redeclaring")
when not declared(enum_lsquic_hsi_flag):
  type
    enum_lsquic_hsi_flag* = enum_lsquic_hsi_flag_536871448
else:
  static :
    hint("Declaration of " & "enum_lsquic_hsi_flag" &
        " already exists, not redeclaring")
when not declared(sk_SSL_CIPHER_freefunc):
  type
    sk_SSL_CIPHER_freefunc* = sk_SSL_CIPHER_freefunc_536871751
else:
  static :
    hint("Declaration of " & "sk_SSL_CIPHER_freefunc" &
        " already exists, not redeclaring")
when not declared(COMP_METHOD):
  type
    COMP_METHOD* = COMP_METHOD_536871781
else:
  static :
    hint("Declaration of " & "COMP_METHOD" & " already exists, not redeclaring")
when not declared(CRYPTO_malloc_fn):
  type
    CRYPTO_malloc_fn* = CRYPTO_malloc_fn_536871511
else:
  static :
    hint("Declaration of " & "CRYPTO_malloc_fn" &
        " already exists, not redeclaring")
when not declared(DTLS_timer_cb):
  type
    DTLS_timer_cb* = DTLS_timer_cb_536871799
else:
  static :
    hint("Declaration of " & "DTLS_timer_cb" &
        " already exists, not redeclaring")
when not declared(EVP_MD):
  type
    EVP_MD* = EVP_MD_536871659
else:
  static :
    hint("Declaration of " & "EVP_MD" & " already exists, not redeclaring")
when not declared(X509V3_CTX):
  type
    X509V3_CTX* = X509V3_CTX_536871665
else:
  static :
    hint("Declaration of " & "X509V3_CTX" & " already exists, not redeclaring")
when not declared(sk_ASN1_STRING_TABLE_freefunc):
  type
    sk_ASN1_STRING_TABLE_freefunc* = sk_ASN1_STRING_TABLE_freefunc_536871557
else:
  static :
    hint("Declaration of " & "sk_ASN1_STRING_TABLE_freefunc" &
        " already exists, not redeclaring")
when not declared(time_t):
  type
    time_t* = time_t_536871442
else:
  static :
    hint("Declaration of " & "time_t" & " already exists, not redeclaring")
when not declared(struct_tls_session_ticket_ext_st):
  type
    struct_tls_session_ticket_ext_st* = struct_tls_session_ticket_ext_st_536871677
else:
  static :
    hint("Declaration of " & "struct_tls_session_ticket_ext_st" &
        " already exists, not redeclaring")
when not declared(struct_rand_meth_st):
  type
    struct_rand_meth_st* = struct_rand_meth_st_536871803
else:
  static :
    hint("Declaration of " & "struct_rand_meth_st" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_cb_fn):
  type
    SSL_client_hello_cb_fn* = SSL_client_hello_cb_fn_536871775
else:
  static :
    hint("Declaration of " & "SSL_client_hello_cb_fn" &
        " already exists, not redeclaring")
when not declared(BIO_METHOD):
  type
    BIO_METHOD* = BIO_METHOD_536871671
else:
  static :
    hint("Declaration of " & "BIO_METHOD" & " already exists, not redeclaring")
when not declared(pem_password_cb):
  type
    pem_password_cb* = pem_password_cb_536871765
else:
  static :
    hint("Declaration of " & "pem_password_cb" &
        " already exists, not redeclaring")
when not declared(EVP_RAND_CTX):
  type
    EVP_RAND_CTX* = EVP_RAND_CTX_536871807
else:
  static :
    hint("Declaration of " & "EVP_RAND_CTX" & " already exists, not redeclaring")
when not declared(tls_session_secret_cb_fn):
  type
    tls_session_secret_cb_fn* = tls_session_secret_cb_fn_536871705
else:
  static :
    hint("Declaration of " & "tls_session_secret_cb_fn" &
        " already exists, not redeclaring")
when not declared(X509_STORE_CTX):
  type
    X509_STORE_CTX* = X509_STORE_CTX_536871723
else:
  static :
    hint("Declaration of " & "X509_STORE_CTX" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_engine_settings):
  type
    struct_lsquic_engine_settings* = struct_lsquic_engine_settings_536871432
else:
  static :
    hint("Declaration of " & "struct_lsquic_engine_settings" &
        " already exists, not redeclaring")
when not declared(lsquic_lookup_cert_f):
  type
    lsquic_lookup_cert_f* = lsquic_lookup_cert_f_536871430
else:
  static :
    hint("Declaration of " & "lsquic_lookup_cert_f" &
        " already exists, not redeclaring")
when not declared(compiler_ssize_t):
  type
    compiler_ssize_t* = compiler_ssize_t_536871812
else:
  static :
    hint("Declaration of " & "compiler_ssize_t" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_UTF8STRING_compfunc):
  type
    sk_ASN1_UTF8STRING_compfunc* = sk_ASN1_UTF8STRING_compfunc_536871641
else:
  static :
    hint("Declaration of " & "sk_ASN1_UTF8STRING_compfunc" &
        " already exists, not redeclaring")
when not declared(TLS_SESSION_TICKET_EXT):
  type
    TLS_SESSION_TICKET_EXT* = TLS_SESSION_TICKET_EXT_536871675
else:
  static :
    hint("Declaration of " & "TLS_SESSION_TICKET_EXT" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_t):
  type
    lsquic_engine_t* = lsquic_engine_t_536871408
else:
  static :
    hint("Declaration of " & "lsquic_engine_t" &
        " already exists, not redeclaring")
when not declared(d2i_of_void):
  type
    d2i_of_void* = d2i_of_void_536871567
else:
  static :
    hint("Declaration of " & "d2i_of_void" & " already exists, not redeclaring")
when not declared(ASN1_INTEGER):
  type
    ASN1_INTEGER* = ASN1_INTEGER_536871583
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER" & " already exists, not redeclaring")
when not declared(ASN1_VISIBLESTRING):
  type
    ASN1_VISIBLESTRING* = ASN1_VISIBLESTRING_536871607
else:
  static :
    hint("Declaration of " & "ASN1_VISIBLESTRING" &
        " already exists, not redeclaring")
when not declared(sk_SRTP_PROTECTION_PROFILE_freefunc):
  type
    sk_SRTP_PROTECTION_PROFILE_freefunc* = sk_SRTP_PROTECTION_PROFILE_freefunc_536871697
else:
  static :
    hint("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_freefunc" &
        " already exists, not redeclaring")
when not declared(OPENSSL_sk_compfunc):
  type
    OPENSSL_sk_compfunc* = OPENSSL_sk_compfunc_536871493
else:
  static :
    hint("Declaration of " & "OPENSSL_sk_compfunc" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING):
  type
    ASN1_BIT_STRING* = ASN1_BIT_STRING_536871587
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_ENCODING):
  type
    ASN1_ENCODING* = ASN1_ENCODING_536871549
else:
  static :
    hint("Declaration of " & "ASN1_ENCODING" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALSTRING):
  type
    ASN1_GENERALSTRING* = ASN1_GENERALSTRING_536871597
else:
  static :
    hint("Declaration of " & "ASN1_GENERALSTRING" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_t):
  type
    lsquic_stream_t* = lsquic_stream_t_536871414
else:
  static :
    hint("Declaration of " & "lsquic_stream_t" &
        " already exists, not redeclaring")
when not declared(ASN1_TLC):
  type
    ASN1_TLC* = ASN1_TLC_536871563
else:
  static :
    hint("Declaration of " & "ASN1_TLC" & " already exists, not redeclaring")
when not declared(struct_BIT_STRING_BITNAME_st):
  type
    struct_BIT_STRING_BITNAME_st* = struct_BIT_STRING_BITNAME_st_536871621
else:
  static :
    hint("Declaration of " & "struct_BIT_STRING_BITNAME_st" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME):
  type
    ASN1_TIME* = ASN1_TIME_536871639
else:
  static :
    hint("Declaration of " & "ASN1_TIME" & " already exists, not redeclaring")
when not declared(SSL_DANE):
  type
    SSL_DANE* = SSL_DANE_536871771
else:
  static :
    hint("Declaration of " & "SSL_DANE" & " already exists, not redeclaring")
when not declared(off_t):
  type
    off_t* = off_t_536871777
else:
  static :
    hint("Declaration of " & "off_t" & " already exists, not redeclaring")
when not declared(SSL_TICKET_STATUS):
  type
    SSL_TICKET_STATUS* = SSL_TICKET_STATUS_536871791
else:
  static :
    hint("Declaration of " & "SSL_TICKET_STATUS" &
        " already exists, not redeclaring")
when not declared(struct_srtp_protection_profile_st):
  type
    struct_srtp_protection_profile_st* = struct_srtp_protection_profile_st_536871691
else:
  static :
    hint("Declaration of " & "struct_srtp_protection_profile_st" &
        " already exists, not redeclaring")
when not declared(compiler_time_t):
  type
    compiler_time_t* = compiler_time_t_536871814
else:
  static :
    hint("Declaration of " & "compiler_time_t" &
        " already exists, not redeclaring")
when not declared(TLS_SIGALGS):
  type
    TLS_SIGALGS* = TLS_SIGALGS_536871685
else:
  static :
    hint("Declaration of " & "TLS_SIGALGS" & " already exists, not redeclaring")
when not declared(OPENSSL_sk_copyfunc):
  type
    OPENSSL_sk_copyfunc* = OPENSSL_sk_copyfunc_536871495
else:
  static :
    hint("Declaration of " & "OPENSSL_sk_copyfunc" &
        " already exists, not redeclaring")
when not declared(sk_SSL_COMP_compfunc):
  type
    sk_SSL_COMP_compfunc* = sk_SSL_COMP_compfunc_536871755
else:
  static :
    hint("Declaration of " & "sk_SSL_COMP_compfunc" &
        " already exists, not redeclaring")
when not declared(ssize_t):
  type
    ssize_t* = ssize_t_536871428
else:
  static :
    hint("Declaration of " & "ssize_t" & " already exists, not redeclaring")
when not declared(ssl_ct_validation_cb):
  type
    ssl_ct_validation_cb* = ssl_ct_validation_cb_536871785
else:
  static :
    hint("Declaration of " & "ssl_ct_validation_cb" &
        " already exists, not redeclaring")
when not declared(BIT_STRING_BITNAME):
  type
    BIT_STRING_BITNAME* = BIT_STRING_BITNAME_536871623
else:
  static :
    hint("Declaration of " & "BIT_STRING_BITNAME" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_alpn_select_cb_func):
  type
    SSL_CTX_alpn_select_cb_func* = SSL_CTX_alpn_select_cb_func_536871737
else:
  static :
    hint("Declaration of " & "SSL_CTX_alpn_select_cb_func" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_SETTINGS):
  type
    OPENSSL_INIT_SETTINGS* = OPENSSL_INIT_SETTINGS_536871519
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_SETTINGS" &
        " already exists, not redeclaring")
when not declared(struct_asn1_string_st):
  type
    struct_asn1_string_st* = struct_asn1_string_st_536871545
else:
  static :
    hint("Declaration of " & "struct_asn1_string_st" &
        " already exists, not redeclaring")
when not declared(enum_OSSL_HANDSHAKE_STATE):
  type
    enum_OSSL_HANDSHAKE_STATE* = enum_OSSL_HANDSHAKE_STATE_536871761
else:
  static :
    hint("Declaration of " & "enum_OSSL_HANDSHAKE_STATE" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_OBJECT_copyfunc):
  type
    sk_ASN1_OBJECT_copyfunc* = sk_ASN1_OBJECT_copyfunc_536871629
else:
  static :
    hint("Declaration of " & "sk_ASN1_OBJECT_copyfunc" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_ctx_t):
  type
    lsquic_conn_ctx_t* = lsquic_conn_ctx_t_536871412
else:
  static :
    hint("Declaration of " & "lsquic_conn_ctx_t" &
        " already exists, not redeclaring")
when not declared(sk_ASN1_TYPE_copyfunc):
  type
    sk_ASN1_TYPE_copyfunc* = sk_ASN1_TYPE_copyfunc_536871617
else:
  static :
    hint("Declaration of " & "sk_ASN1_TYPE_copyfunc" &
        " already exists, not redeclaring")
when not declared(enum_lsquic_version):
  type
    enum_lsquic_version* = enum_lsquic_version_536871422
else:
  static :
    hint("Declaration of " & "enum_lsquic_version" &
        " already exists, not redeclaring")
when not declared(BIGNUM):
  type
    BIGNUM* = BIGNUM_536871655
else:
  static :
    hint("Declaration of " & "BIGNUM" & " already exists, not redeclaring")
when not declared(CTLOG_STORE):
  type
    CTLOG_STORE* = CTLOG_STORE_536871789
else:
  static :
    hint("Declaration of " & "CTLOG_STORE" & " already exists, not redeclaring")
when not declared(OPENSSL_STACK):
  type
    OPENSSL_STACK* = OPENSSL_STACK_536871491
else:
  static :
    hint("Declaration of " & "OPENSSL_STACK" &
        " already exists, not redeclaring")
when not declared(ENGINE):
  type
    ENGINE* = ENGINE_536871731
else:
  static :
    hint("Declaration of " & "ENGINE" & " already exists, not redeclaring")
when not declared(SSL_psk_client_cb_func):
  type
    SSL_psk_client_cb_func* = SSL_psk_client_cb_func_536871739
else:
  static :
    hint("Declaration of " & "SSL_psk_client_cb_func" &
        " already exists, not redeclaring")
when not declared(DH):
  type
    DH* = DH_536871779
else:
  static :
    hint("Declaration of " & "DH" & " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN):
  type
    SSL_TICKET_RETURN* = SSL_TICKET_RETURN_536871793
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN" &
        " already exists, not redeclaring")
when not declared(ASN1_TEMPLATE):
  type
    ASN1_TEMPLATE* = ASN1_TEMPLATE_536871561
else:
  static :
    hint("Declaration of " & "ASN1_TEMPLATE" &
        " already exists, not redeclaring")
when not declared(ASN1_ITEM_EXP):
  type
    ASN1_ITEM_EXP* = ASN1_ITEM_EXP_536871571
else:
  static :
    hint("Declaration of " & "ASN1_ITEM_EXP" &
        " already exists, not redeclaring")
when not declared(SSL_allow_early_data_cb_fn):
  type
    SSL_allow_early_data_cb_fn* = SSL_allow_early_data_cb_fn_536871801
else:
  static :
    hint("Declaration of " & "SSL_allow_early_data_cb_fn" &
        " already exists, not redeclaring")
when not declared(enum_lsquic_hsk_status):
  type
    enum_lsquic_hsk_status* = enum_lsquic_hsk_status_536871424
else:
  static :
    hint("Declaration of " & "enum_lsquic_hsk_status" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_packout_mem_if):
  type
    struct_lsquic_packout_mem_if* = struct_lsquic_packout_mem_if_536871444
else:
  static :
    hint("Declaration of " & "struct_lsquic_packout_mem_if" &
        " already exists, not redeclaring")
when not declared(EVP_PKEY):
  type
    EVP_PKEY* = EVP_PKEY_536871657
else:
  static :
    hint("Declaration of " & "EVP_PKEY" & " already exists, not redeclaring")
when not declared(sk_void_compfunc):
  type
    sk_void_compfunc* = sk_void_compfunc_536871485
else:
  static :
    hint("Declaration of " & "sk_void_compfunc" &
        " already exists, not redeclaring")
when not declared(ASN1_IA5STRING):
  type
    ASN1_IA5STRING* = ASN1_IA5STRING_536871595
else:
  static :
    hint("Declaration of " & "ASN1_IA5STRING" &
        " already exists, not redeclaring")
when not declared(sk_SSL_COMP_copyfunc):
  type
    sk_SSL_COMP_copyfunc* = sk_SSL_COMP_copyfunc_536871759
else:
  static :
    hint("Declaration of " & "sk_SSL_COMP_copyfunc" &
        " already exists, not redeclaring")
when not declared(SRTP_PROTECTION_PROFILE):
  type
    SRTP_PROTECTION_PROFILE* = SRTP_PROTECTION_PROFILE_536871693
else:
  static :
    hint("Declaration of " & "SRTP_PROTECTION_PROFILE" &
        " already exists, not redeclaring")
when not declared(sk_SRTP_PROTECTION_PROFILE_copyfunc):
  type
    sk_SRTP_PROTECTION_PROFILE_copyfunc* = sk_SRTP_PROTECTION_PROFILE_copyfunc_536871699
else:
  static :
    hint("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_copyfunc" &
        " already exists, not redeclaring")
when not declared(BIO_ADDR):
  type
    BIO_ADDR* = BIO_ADDR_536871783
else:
  static :
    hint("Declaration of " & "BIO_ADDR" & " already exists, not redeclaring")
when not declared(sk_X509_ALGOR_compfunc):
  type
    sk_X509_ALGOR_compfunc* = sk_X509_ALGOR_compfunc_536871537
else:
  static :
    hint("Declaration of " & "sk_X509_ALGOR_compfunc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_ID_typedef):
  type
    CRYPTO_THREAD_ID_typedef* = CRYPTO_THREAD_ID_typedef_536871529
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_ID_typedef" &
        " already exists, not redeclaring")
when not declared(struct_lsquic_ext_http_prio):
  type
    struct_lsquic_ext_http_prio* = struct_lsquic_ext_http_prio_536871463
else:
  static :
    hint("Declaration of " & "struct_lsquic_ext_http_prio" &
        " already exists, not redeclaring")
when not declared(CT_POLICY_EVAL_CTX):
  type
    CT_POLICY_EVAL_CTX* = CT_POLICY_EVAL_CTX_536871787
else:
  static :
    hint("Declaration of " & "CT_POLICY_EVAL_CTX" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED):
  type
    ASN1_ENUMERATED* = ASN1_ENUMERATED_536871585
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(ASN1_UNIVERSALSTRING):
  type
    ASN1_UNIVERSALSTRING* = ASN1_UNIVERSALSTRING_536871601
else:
  static :
    hint("Declaration of " & "ASN1_UNIVERSALSTRING" &
        " already exists, not redeclaring")
when not declared(Cfile):
  type
    Cfile* = Cfile_536871661
else:
  static :
    hint("Declaration of " & "Cfile" & " already exists, not redeclaring")
when not declared(struct_lsquic_reader):
  type
    struct_lsquic_reader* = struct_lsquic_reader_536871461
else:
  static :
    hint("Declaration of " & "struct_lsquic_reader" &
        " already exists, not redeclaring")
when not declared(sk_SRTP_PROTECTION_PROFILE_compfunc):
  type
    sk_SRTP_PROTECTION_PROFILE_compfunc* = sk_SRTP_PROTECTION_PROFILE_compfunc_536871695
else:
  static :
    hint("Declaration of " & "sk_SRTP_PROTECTION_PROFILE_compfunc" &
        " already exists, not redeclaring")
when not declared(X509_ALGOR):
  type
    X509_ALGOR* = X509_ALGOR_536871539
else:
  static :
    hint("Declaration of " & "X509_ALGOR" & " already exists, not redeclaring")
when not declared(OPENSSL_sk_freefunc):
  type
    OPENSSL_sk_freefunc* = OPENSSL_sk_freefunc_536871497
else:
  static :
    hint("Declaration of " & "OPENSSL_sk_freefunc" &
        " already exists, not redeclaring")
when not declared(lsquic_packets_out_f):
  type
    lsquic_packets_out_f* = lsquic_packets_out_f_536871438
else:
  static :
    hint("Declaration of " & "lsquic_packets_out_f" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING):
  type
    ASN1_OCTET_STRING* = ASN1_OCTET_STRING_536871589
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING" &
        " already exists, not redeclaring")
when not declared(CRYPTO_realloc_fn):
  type
    CRYPTO_realloc_fn* = CRYPTO_realloc_fn_536871513
else:
  static :
    hint("Declaration of " & "CRYPTO_realloc_fn" &
        " already exists, not redeclaring")
when not declared(ssl_crock_st):
  type
    ssl_crock_st* = ssl_crock_st_536871673
else:
  static :
    hint("Declaration of " & "ssl_crock_st" & " already exists, not redeclaring")
when not declared(RSA):
  type
    RSA* = RSA_536871769
else:
  static :
    hint("Declaration of " & "RSA" & " already exists, not redeclaring")
when not declared(struct_X509_algor_st):
  type
    struct_X509_algor_st* = struct_X509_algor_st_536871818
else:
  static :
    hint("Declaration of " & "struct_X509_algor_st" &
        " already exists, not redeclaring")
when not declared(struct_asn1_string_table_st):
  type
    struct_asn1_string_table_st* = struct_asn1_string_table_st_536871551
else:
  static :
    hint("Declaration of " & "struct_asn1_string_table_st" &
        " already exists, not redeclaring")
when not declared(sk_SSL_CIPHER_compfunc):
  type
    sk_SSL_CIPHER_compfunc* = sk_SSL_CIPHER_compfunc_536871749
else:
  static :
    hint("Declaration of " & "sk_SSL_CIPHER_compfunc" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING):
  type
    ASN1_STRING* = ASN1_STRING_536871579
else:
  static :
    hint("Declaration of " & "ASN1_STRING" & " already exists, not redeclaring")
when not declared(ASN1_UTF8STRING):
  type
    ASN1_UTF8STRING* = ASN1_UTF8STRING_536871609
else:
  static :
    hint("Declaration of " & "ASN1_UTF8STRING" &
        " already exists, not redeclaring")
when not declared(struct_conf_method_st):
  type
    struct_conf_method_st* = struct_conf_method_st_536871834
else:
  static :
    hint("Declaration of " & "struct_conf_method_st" &
        " already exists, not redeclaring")
when not declared(ASN1_NULL):
  type
    ASN1_NULL* = ASN1_NULL_536871647
else:
  static :
    hint("Declaration of " & "ASN1_NULL" & " already exists, not redeclaring")
when not declared(MAX_CID_LEN):
  when 20 is static:
    const
      MAX_CID_LEN* = 20      ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:13:9
  else:
    let MAX_CID_LEN* = 20    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:13:9
else:
  static :
    hint("Declaration of " & "MAX_CID_LEN" & " already exists, not redeclaring")
when not declared(GQUIC_CID_LEN):
  when 8 is static:
    const
      GQUIC_CID_LEN* = 8     ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:14:9
  else:
    let GQUIC_CID_LEN* = 8   ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:14:9
else:
  static :
    hint("Declaration of " & "GQUIC_CID_LEN" &
        " already exists, not redeclaring")
when not declared(idbuf):
  when buf is typedesc:
    type
      idbuf* = buf           ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9
  else:
    when buf is static:
      const
        idbuf* = buf         ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9
    else:
      let idbuf* = buf       ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic_types.h:30:9
else:
  static :
    hint("Declaration of " & "idbuf" & " already exists, not redeclaring")
when not declared(LSQUIC_MAJOR_VERSION):
  when 4 is static:
    const
      LSQUIC_MAJOR_VERSION* = 4 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:28:9
  else:
    let LSQUIC_MAJOR_VERSION* = 4 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:28:9
else:
  static :
    hint("Declaration of " & "LSQUIC_MAJOR_VERSION" &
        " already exists, not redeclaring")
when not declared(LSQUIC_MINOR_VERSION):
  when 3 is static:
    const
      LSQUIC_MINOR_VERSION* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:29:9
  else:
    let LSQUIC_MINOR_VERSION* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:29:9
else:
  static :
    hint("Declaration of " & "LSQUIC_MINOR_VERSION" &
        " already exists, not redeclaring")
when not declared(LSQUIC_PATCH_VERSION):
  when 2 is static:
    const
      LSQUIC_PATCH_VERSION* = 2 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:30:9
  else:
    let LSQUIC_PATCH_VERSION* = 2 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:30:9
else:
  static :
    hint("Declaration of " & "LSQUIC_PATCH_VERSION" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MAX_STREAMS_IN):
  when 100 is static:
    const
      LSQUIC_DF_MAX_STREAMS_IN* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:280:9
  else:
    let LSQUIC_DF_MAX_STREAMS_IN* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:280:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MAX_STREAMS_IN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_DATA_SERVER):
  when LSQUIC_DF_CFCW_SERVER is typedesc:
    type
      LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9
  else:
    when LSQUIC_DF_CFCW_SERVER is static:
      const
        LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9
    else:
      let LSQUIC_DF_INIT_MAX_DATA_SERVER* = LSQUIC_DF_CFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:283:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_DATA_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_DATA_CLIENT):
  when LSQUIC_DF_CFCW_CLIENT is typedesc:
    type
      LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9
  else:
    when LSQUIC_DF_CFCW_CLIENT is static:
      const
        LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9
    else:
      let LSQUIC_DF_INIT_MAX_DATA_CLIENT* = LSQUIC_DF_CFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:284:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_DATA_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER):
  when LSQUIC_DF_SFCW_SERVER is typedesc:
    type
      LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9
  else:
    when LSQUIC_DF_SFCW_SERVER is static:
      const
        LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER* = LSQUIC_DF_SFCW_SERVER ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:285:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER):
  when 0 is static:
    const
      LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:286:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:286:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT):
  when 0 is static:
    const
      LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:287:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:287:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT):
  when LSQUIC_DF_SFCW_CLIENT is typedesc:
    type
      LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9
  else:
    when LSQUIC_DF_SFCW_CLIENT is static:
      const
        LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT* = LSQUIC_DF_SFCW_CLIENT ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:288:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_BIDI):
  when LSQUIC_DF_MAX_STREAMS_IN is typedesc:
    type
      LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9
  else:
    when LSQUIC_DF_MAX_STREAMS_IN is static:
      const
        LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9
    else:
      let LSQUIC_DF_INIT_MAX_STREAMS_BIDI* = LSQUIC_DF_MAX_STREAMS_IN ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:289:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_BIDI" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT):
  when 100 is static:
    const
      LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:290:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:290:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER):
  when 3 is static:
    const
      LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:291:9
  else:
    let LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:291:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_IDLE_TIMEOUT):
  when 30 is static:
    const
      LSQUIC_DF_IDLE_TIMEOUT* = 30 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:299:9
  else:
    let LSQUIC_DF_IDLE_TIMEOUT* = 30 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:299:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_IDLE_TIMEOUT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PING_PERIOD):
  when 15 is static:
    const
      LSQUIC_DF_PING_PERIOD* = 15 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:304:9
  else:
    let LSQUIC_DF_PING_PERIOD* = 15 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:304:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PING_PERIOD" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SILENT_CLOSE):
  when 1 is static:
    const
      LSQUIC_DF_SILENT_CLOSE* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:312:9
  else:
    let LSQUIC_DF_SILENT_CLOSE* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:312:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SILENT_CLOSE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MAX_HEADER_LIST_SIZE):
  when 0 is static:
    const
      LSQUIC_DF_MAX_HEADER_LIST_SIZE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:318:9
  else:
    let LSQUIC_DF_MAX_HEADER_LIST_SIZE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:318:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MAX_HEADER_LIST_SIZE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_UA):
  when "LSQUIC" is static:
    const
      LSQUIC_DF_UA* = "LSQUIC" ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:321:9
  else:
    let LSQUIC_DF_UA* = "LSQUIC" ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:321:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_UA" & " already exists, not redeclaring")
when not declared(LSQUIC_DF_STTL):
  when 86400 is static:
    const
      LSQUIC_DF_STTL* = 86400 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:323:9
  else:
    let LSQUIC_DF_STTL* = 86400 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:323:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_STTL" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_SREJ_SERVER):
  when 1 is static:
    const
      LSQUIC_DF_SUPPORT_SREJ_SERVER* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:326:9
  else:
    let LSQUIC_DF_SUPPORT_SREJ_SERVER* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:326:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SUPPORT_SREJ_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_SREJ_CLIENT):
  when 0 is static:
    const
      LSQUIC_DF_SUPPORT_SREJ_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:327:9
  else:
    let LSQUIC_DF_SUPPORT_SREJ_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:327:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SUPPORT_SREJ_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_NSTP):
  when 0 is static:
    const
      LSQUIC_DF_SUPPORT_NSTP* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:330:9
  else:
    let LSQUIC_DF_SUPPORT_NSTP* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:330:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SUPPORT_NSTP" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_PUSH):
  when 1 is static:
    const
      LSQUIC_DF_SUPPORT_PUSH* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:332:9
  else:
    let LSQUIC_DF_SUPPORT_PUSH* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:332:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SUPPORT_PUSH" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SUPPORT_TCID0):
  when 1 is static:
    const
      LSQUIC_DF_SUPPORT_TCID0* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:333:9
  else:
    let LSQUIC_DF_SUPPORT_TCID0* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:333:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SUPPORT_TCID0" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_HONOR_PRST):
  when 0 is static:
    const
      LSQUIC_DF_HONOR_PRST* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:335:9
  else:
    let LSQUIC_DF_HONOR_PRST* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:335:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_HONOR_PRST" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SEND_PRST):
  when 0 is static:
    const
      LSQUIC_DF_SEND_PRST* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:341:9
  else:
    let LSQUIC_DF_SEND_PRST* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:341:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SEND_PRST" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SEND_VERNEG):
  when 1 is static:
    const
      LSQUIC_DF_SEND_VERNEG* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:347:9
  else:
    let LSQUIC_DF_SEND_VERNEG* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:347:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SEND_VERNEG" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PROGRESS_CHECK):
  when 1000 is static:
    const
      LSQUIC_DF_PROGRESS_CHECK* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:350:9
  else:
    let LSQUIC_DF_PROGRESS_CHECK* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:350:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PROGRESS_CHECK" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_RW_ONCE):
  when 0 is static:
    const
      LSQUIC_DF_RW_ONCE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:353:9
  else:
    let LSQUIC_DF_RW_ONCE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:353:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_RW_ONCE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PROC_TIME_THRESH):
  when 0 is static:
    const
      LSQUIC_DF_PROC_TIME_THRESH* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:356:9
  else:
    let LSQUIC_DF_PROC_TIME_THRESH* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:356:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PROC_TIME_THRESH" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PACE_PACKETS):
  when 1 is static:
    const
      LSQUIC_DF_PACE_PACKETS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:359:9
  else:
    let LSQUIC_DF_PACE_PACKETS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:359:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PACE_PACKETS" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CLOCK_GRANULARITY):
  when 1000 is static:
    const
      LSQUIC_DF_CLOCK_GRANULARITY* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:362:9
  else:
    let LSQUIC_DF_CLOCK_GRANULARITY* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:362:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CLOCK_GRANULARITY" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SCID_LEN):
  when 8 is static:
    const
      LSQUIC_DF_SCID_LEN* = 8 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:365:9
  else:
    let LSQUIC_DF_SCID_LEN* = 8 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:365:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SCID_LEN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SCID_ISS_RATE):
  when 60 is static:
    const
      LSQUIC_DF_SCID_ISS_RATE* = 60 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:368:9
  else:
    let LSQUIC_DF_SCID_ISS_RATE* = 60 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:368:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SCID_ISS_RATE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QPACK_DEC_MAX_BLOCKED):
  when 100 is static:
    const
      LSQUIC_DF_QPACK_DEC_MAX_BLOCKED* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:370:9
  else:
    let LSQUIC_DF_QPACK_DEC_MAX_BLOCKED* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:370:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QPACK_DEC_MAX_BLOCKED" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QPACK_DEC_MAX_SIZE):
  when 4096 is static:
    const
      LSQUIC_DF_QPACK_DEC_MAX_SIZE* = 4096 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:371:9
  else:
    let LSQUIC_DF_QPACK_DEC_MAX_SIZE* = 4096 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:371:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QPACK_DEC_MAX_SIZE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QPACK_ENC_MAX_BLOCKED):
  when 100 is static:
    const
      LSQUIC_DF_QPACK_ENC_MAX_BLOCKED* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:372:9
  else:
    let LSQUIC_DF_QPACK_ENC_MAX_BLOCKED* = 100 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:372:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QPACK_ENC_MAX_BLOCKED" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QPACK_ENC_MAX_SIZE):
  when 4096 is static:
    const
      LSQUIC_DF_QPACK_ENC_MAX_SIZE* = 4096 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:373:9
  else:
    let LSQUIC_DF_QPACK_ENC_MAX_SIZE* = 4096 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:373:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QPACK_ENC_MAX_SIZE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QPACK_EXPERIMENT):
  when 0 is static:
    const
      LSQUIC_DF_QPACK_EXPERIMENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:376:9
  else:
    let LSQUIC_DF_QPACK_EXPERIMENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:376:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QPACK_EXPERIMENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_ECN):
  when 0 is static:
    const
      LSQUIC_DF_ECN* = 0     ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:379:9
  else:
    let LSQUIC_DF_ECN* = 0   ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:379:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_ECN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_ALLOW_MIGRATION):
  when 1 is static:
    const
      LSQUIC_DF_ALLOW_MIGRATION* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:382:9
  else:
    let LSQUIC_DF_ALLOW_MIGRATION* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:382:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_ALLOW_MIGRATION" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_RETRY_TOKEN_DURATION):
  when 10 is static:
    const
      LSQUIC_DF_RETRY_TOKEN_DURATION* = 10 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:385:9
  else:
    let LSQUIC_DF_RETRY_TOKEN_DURATION* = 10 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:385:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_RETRY_TOKEN_DURATION" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_QL_BITS):
  when 2 is static:
    const
      LSQUIC_DF_QL_BITS* = 2 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:388:9
  else:
    let LSQUIC_DF_QL_BITS* = 2 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:388:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_QL_BITS" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_SPIN):
  when 1 is static:
    const
      LSQUIC_DF_SPIN* = 1    ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:391:9
  else:
    let LSQUIC_DF_SPIN* = 1  ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:391:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_SPIN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_DELAYED_ACKS):
  when 1 is static:
    const
      LSQUIC_DF_DELAYED_ACKS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:394:9
  else:
    let LSQUIC_DF_DELAYED_ACKS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:394:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_DELAYED_ACKS" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_PERIODICITY):
  when 3 is static:
    const
      LSQUIC_DF_PTPC_PERIODICITY* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:400:9
  else:
    let LSQUIC_DF_PTPC_PERIODICITY* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:400:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_PERIODICITY" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_MAX_PACKTOL):
  when 150 is static:
    const
      LSQUIC_DF_PTPC_MAX_PACKTOL* = 150 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:401:9
  else:
    let LSQUIC_DF_PTPC_MAX_PACKTOL* = 150 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:401:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_MAX_PACKTOL" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_DYN_TARGET):
  when 1 is static:
    const
      LSQUIC_DF_PTPC_DYN_TARGET* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:402:9
  else:
    let LSQUIC_DF_PTPC_DYN_TARGET* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:402:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_DYN_TARGET" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_TARGET):
  when 1.0 is static:
    const
      LSQUIC_DF_PTPC_TARGET* = 1.0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:403:9
  else:
    let LSQUIC_DF_PTPC_TARGET* = 1.0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:403:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_TARGET" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_PROP_GAIN):
  when 0.8 is static:
    const
      LSQUIC_DF_PTPC_PROP_GAIN* = 0.8 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:404:9
  else:
    let LSQUIC_DF_PTPC_PROP_GAIN* = 0.8 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:404:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_PROP_GAIN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_INT_GAIN):
  when 0.35 is static:
    const
      LSQUIC_DF_PTPC_INT_GAIN* = 0.35 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:405:9
  else:
    let LSQUIC_DF_PTPC_INT_GAIN* = 0.35 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:405:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_INT_GAIN" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_ERR_THRESH):
  when 0.05 is static:
    const
      LSQUIC_DF_PTPC_ERR_THRESH* = 0.05 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:406:9
  else:
    let LSQUIC_DF_PTPC_ERR_THRESH* = 0.05 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:406:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_ERR_THRESH" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_PTPC_ERR_DIVISOR):
  when 0.05 is static:
    const
      LSQUIC_DF_PTPC_ERR_DIVISOR* = 0.05 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:407:9
  else:
    let LSQUIC_DF_PTPC_ERR_DIVISOR* = 0.05 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:407:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_PTPC_ERR_DIVISOR" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_TIMESTAMPS):
  when 1 is static:
    const
      LSQUIC_DF_TIMESTAMPS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:410:9
  else:
    let LSQUIC_DF_TIMESTAMPS* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:410:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_TIMESTAMPS" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_AMP_FACTOR):
  when 3 is static:
    const
      LSQUIC_DF_AMP_FACTOR* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:413:9
  else:
    let LSQUIC_DF_AMP_FACTOR* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:413:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_AMP_FACTOR" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CC_ALGO):
  when 3 is static:
    const
      LSQUIC_DF_CC_ALGO* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:416:9
  else:
    let LSQUIC_DF_CC_ALGO* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:416:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CC_ALGO" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CC_RTT_THRESH):
  when 1500 is static:
    const
      LSQUIC_DF_CC_RTT_THRESH* = 1500 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:419:9
  else:
    let LSQUIC_DF_CC_RTT_THRESH* = 1500 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:419:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CC_RTT_THRESH" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_DATAGRAMS):
  when 0 is static:
    const
      LSQUIC_DF_DATAGRAMS* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:422:9
  else:
    let LSQUIC_DF_DATAGRAMS* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:422:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_DATAGRAMS" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_OPTIMISTIC_NAT):
  when 1 is static:
    const
      LSQUIC_DF_OPTIMISTIC_NAT* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:425:9
  else:
    let LSQUIC_DF_OPTIMISTIC_NAT* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:425:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_OPTIMISTIC_NAT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_EXT_HTTP_PRIO):
  when 1 is static:
    const
      LSQUIC_DF_EXT_HTTP_PRIO* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:428:9
  else:
    let LSQUIC_DF_EXT_HTTP_PRIO* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:428:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_EXT_HTTP_PRIO" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX):
  when 0 is static:
    const
      LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:431:9
  else:
    let LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:431:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MAX_UDP_PAYLOAD_SIZE_RX" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_GREASE_QUIC_BIT):
  when 1 is static:
    const
      LSQUIC_DF_GREASE_QUIC_BIT* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:437:9
  else:
    let LSQUIC_DF_GREASE_QUIC_BIT* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:437:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_GREASE_QUIC_BIT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_DPLPMTUD):
  when 1 is static:
    const
      LSQUIC_DF_DPLPMTUD* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:440:9
  else:
    let LSQUIC_DF_DPLPMTUD* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:440:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_DPLPMTUD" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_BASE_PLPMTU):
  when 0 is static:
    const
      LSQUIC_DF_BASE_PLPMTU* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:443:9
  else:
    let LSQUIC_DF_BASE_PLPMTU* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:443:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_BASE_PLPMTU" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MAX_PLPMTU):
  when 0 is static:
    const
      LSQUIC_DF_MAX_PLPMTU* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:446:9
  else:
    let LSQUIC_DF_MAX_PLPMTU* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:446:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MAX_PLPMTU" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER):
  when 60 is static:
    const
      LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER* = 60 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:449:9
  else:
    let LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER* = 60 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:449:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT):
  when 0 is static:
    const
      LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:452:9
  else:
    let LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:452:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_NOPROGRESS_TIMEOUT_CLIENT" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MTU_PROBE_TIMER):
  when 1000 is static:
    const
      LSQUIC_DF_MTU_PROBE_TIMER* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:455:9
  else:
    let LSQUIC_DF_MTU_PROBE_TIMER* = 1000 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:455:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MTU_PROBE_TIMER" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_DELAY_ONCLOSE):
  when 0 is static:
    const
      LSQUIC_DF_DELAY_ONCLOSE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:458:9
  else:
    let LSQUIC_DF_DELAY_ONCLOSE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:458:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_DELAY_ONCLOSE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_MAX_BATCH_SIZE):
  when 0 is static:
    const
      LSQUIC_DF_MAX_BATCH_SIZE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:464:9
  else:
    let LSQUIC_DF_MAX_BATCH_SIZE* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:464:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_MAX_BATCH_SIZE" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DF_CHECK_TP_SANITY):
  when 1 is static:
    const
      LSQUIC_DF_CHECK_TP_SANITY* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:467:9
  else:
    let LSQUIC_DF_CHECK_TP_SANITY* = 1 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:467:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DF_CHECK_TP_SANITY" &
        " already exists, not redeclaring")
when not declared(LSQUIC_MAX_HTTP_URGENCY):
  when 7 is static:
    const
      LSQUIC_MAX_HTTP_URGENCY* = 7 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1857:9
  else:
    let LSQUIC_MAX_HTTP_URGENCY* = 7 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1857:9
else:
  static :
    hint("Declaration of " & "LSQUIC_MAX_HTTP_URGENCY" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DEF_HTTP_URGENCY):
  when 3 is static:
    const
      LSQUIC_DEF_HTTP_URGENCY* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1858:9
  else:
    let LSQUIC_DEF_HTTP_URGENCY* = 3 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1858:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DEF_HTTP_URGENCY" &
        " already exists, not redeclaring")
when not declared(LSQUIC_DEF_HTTP_INCREMENTAL):
  when 0 is static:
    const
      LSQUIC_DEF_HTTP_INCREMENTAL* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1859:9
  else:
    let LSQUIC_DEF_HTTP_INCREMENTAL* = 0 ## Generated based on /home/r/vacp2p/nim-lsquic/libs/lsquic/include/lsquic.h:1859:9
else:
  static :
    hint("Declaration of " & "LSQUIC_DEF_HTTP_INCREMENTAL" &
        " already exists, not redeclaring")
when not declared(OpenSSL_version_num):
  proc OpenSSL_version_num*(): culong {.cdecl, importc: "OpenSSL_version_num".}
else:
  static :
    hint("Declaration of " & "OpenSSL_version_num" &
        " already exists, not redeclaring")
when not declared(OpenSSL_version):
  proc OpenSSL_version*(type_arg: cint): cstring {.cdecl,
      importc: "OpenSSL_version".}
else:
  static :
    hint("Declaration of " & "OpenSSL_version" &
        " already exists, not redeclaring")
when not declared(SSLEAY_VERSION_NUMBER):
  when OPENSSL_VERSION_NUMBER is typedesc:
    type
      SSLEAY_VERSION_NUMBER* = OPENSSL_VERSION_NUMBER ## Generated based on /usr/include/openssl/crypto.h:62:11
  else:
    when OPENSSL_VERSION_NUMBER is static:
      const
        SSLEAY_VERSION_NUMBER* = OPENSSL_VERSION_NUMBER ## Generated based on /usr/include/openssl/crypto.h:62:11
    else:
      let SSLEAY_VERSION_NUMBER* = OPENSSL_VERSION_NUMBER ## Generated based on /usr/include/openssl/crypto.h:62:11
else:
  static :
    hint("Declaration of " & "SSLEAY_VERSION_NUMBER" &
        " already exists, not redeclaring")
when not declared(OPENSSL_VERSION_const):
  when 0 is static:
    const
      OPENSSL_VERSION_const* = 0 ## Generated based on /usr/include/openssl/crypto.h:153:10
  else:
    let OPENSSL_VERSION_const* = 0 ## Generated based on /usr/include/openssl/crypto.h:153:10
else:
  static :
    hint("Declaration of " & "OPENSSL_VERSION_const" &
        " already exists, not redeclaring")
when not declared(OPENSSL_CFLAGS):
  when 1 is static:
    const
      OPENSSL_CFLAGS* = 1    ## Generated based on /usr/include/openssl/crypto.h:154:10
  else:
    let OPENSSL_CFLAGS* = 1  ## Generated based on /usr/include/openssl/crypto.h:154:10
else:
  static :
    hint("Declaration of " & "OPENSSL_CFLAGS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_BUILT_ON):
  when 2 is static:
    const
      OPENSSL_BUILT_ON* = 2  ## Generated based on /usr/include/openssl/crypto.h:155:10
  else:
    let OPENSSL_BUILT_ON* = 2 ## Generated based on /usr/include/openssl/crypto.h:155:10
else:
  static :
    hint("Declaration of " & "OPENSSL_BUILT_ON" &
        " already exists, not redeclaring")
when not declared(OPENSSL_PLATFORM):
  when 3 is static:
    const
      OPENSSL_PLATFORM* = 3  ## Generated based on /usr/include/openssl/crypto.h:156:10
  else:
    let OPENSSL_PLATFORM* = 3 ## Generated based on /usr/include/openssl/crypto.h:156:10
else:
  static :
    hint("Declaration of " & "OPENSSL_PLATFORM" &
        " already exists, not redeclaring")
when not declared(OPENSSL_DIR):
  when 4 is static:
    const
      OPENSSL_DIR* = 4       ## Generated based on /usr/include/openssl/crypto.h:157:10
  else:
    let OPENSSL_DIR* = 4     ## Generated based on /usr/include/openssl/crypto.h:157:10
else:
  static :
    hint("Declaration of " & "OPENSSL_DIR" & " already exists, not redeclaring")
when not declared(OPENSSL_ENGINES_DIR):
  when 5 is static:
    const
      OPENSSL_ENGINES_DIR* = 5 ## Generated based on /usr/include/openssl/crypto.h:158:10
  else:
    let OPENSSL_ENGINES_DIR* = 5 ## Generated based on /usr/include/openssl/crypto.h:158:10
else:
  static :
    hint("Declaration of " & "OPENSSL_ENGINES_DIR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_VERSION_STRING):
  when 6 is static:
    const
      OPENSSL_VERSION_STRING* = 6 ## Generated based on /usr/include/openssl/crypto.h:159:10
  else:
    let OPENSSL_VERSION_STRING* = 6 ## Generated based on /usr/include/openssl/crypto.h:159:10
else:
  static :
    hint("Declaration of " & "OPENSSL_VERSION_STRING" &
        " already exists, not redeclaring")
when not declared(OPENSSL_FULL_VERSION_STRING):
  when 7 is static:
    const
      OPENSSL_FULL_VERSION_STRING* = 7 ## Generated based on /usr/include/openssl/crypto.h:160:10
  else:
    let OPENSSL_FULL_VERSION_STRING* = 7 ## Generated based on /usr/include/openssl/crypto.h:160:10
else:
  static :
    hint("Declaration of " & "OPENSSL_FULL_VERSION_STRING" &
        " already exists, not redeclaring")
when not declared(OPENSSL_MODULES_DIR):
  when 8 is static:
    const
      OPENSSL_MODULES_DIR* = 8 ## Generated based on /usr/include/openssl/crypto.h:161:10
  else:
    let OPENSSL_MODULES_DIR* = 8 ## Generated based on /usr/include/openssl/crypto.h:161:10
else:
  static :
    hint("Declaration of " & "OPENSSL_MODULES_DIR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_CPU_INFO):
  when 9 is static:
    const
      OPENSSL_CPU_INFO* = 9  ## Generated based on /usr/include/openssl/crypto.h:162:10
  else:
    let OPENSSL_CPU_INFO* = 9 ## Generated based on /usr/include/openssl/crypto.h:162:10
else:
  static :
    hint("Declaration of " & "OPENSSL_CPU_INFO" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_CONFIG_DIR):
  when 1001 is static:
    const
      OPENSSL_INFO_CONFIG_DIR* = 1001 ## Generated based on /usr/include/openssl/crypto.h:169:10
  else:
    let OPENSSL_INFO_CONFIG_DIR* = 1001 ## Generated based on /usr/include/openssl/crypto.h:169:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_CONFIG_DIR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_ENGINES_DIR):
  when 1002 is static:
    const
      OPENSSL_INFO_ENGINES_DIR* = 1002 ## Generated based on /usr/include/openssl/crypto.h:170:10
  else:
    let OPENSSL_INFO_ENGINES_DIR* = 1002 ## Generated based on /usr/include/openssl/crypto.h:170:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_ENGINES_DIR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_MODULES_DIR):
  when 1003 is static:
    const
      OPENSSL_INFO_MODULES_DIR* = 1003 ## Generated based on /usr/include/openssl/crypto.h:171:10
  else:
    let OPENSSL_INFO_MODULES_DIR* = 1003 ## Generated based on /usr/include/openssl/crypto.h:171:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_MODULES_DIR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_DSO_EXTENSION):
  when 1004 is static:
    const
      OPENSSL_INFO_DSO_EXTENSION* = 1004 ## Generated based on /usr/include/openssl/crypto.h:172:10
  else:
    let OPENSSL_INFO_DSO_EXTENSION* = 1004 ## Generated based on /usr/include/openssl/crypto.h:172:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_DSO_EXTENSION" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_DIR_FILENAME_SEPARATOR):
  when 1005 is static:
    const
      OPENSSL_INFO_DIR_FILENAME_SEPARATOR* = 1005 ## Generated based on /usr/include/openssl/crypto.h:173:10
  else:
    let OPENSSL_INFO_DIR_FILENAME_SEPARATOR* = 1005 ## Generated based on /usr/include/openssl/crypto.h:173:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_DIR_FILENAME_SEPARATOR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_LIST_SEPARATOR):
  when 1006 is static:
    const
      OPENSSL_INFO_LIST_SEPARATOR* = 1006 ## Generated based on /usr/include/openssl/crypto.h:174:10
  else:
    let OPENSSL_INFO_LIST_SEPARATOR* = 1006 ## Generated based on /usr/include/openssl/crypto.h:174:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_LIST_SEPARATOR" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_SEED_SOURCE):
  when 1007 is static:
    const
      OPENSSL_INFO_SEED_SOURCE* = 1007 ## Generated based on /usr/include/openssl/crypto.h:175:10
  else:
    let OPENSSL_INFO_SEED_SOURCE* = 1007 ## Generated based on /usr/include/openssl/crypto.h:175:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_SEED_SOURCE" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INFO_CPU_SETTINGS):
  when 1008 is static:
    const
      OPENSSL_INFO_CPU_SETTINGS* = 1008 ## Generated based on /usr/include/openssl/crypto.h:176:10
  else:
    let OPENSSL_INFO_CPU_SETTINGS* = 1008 ## Generated based on /usr/include/openssl/crypto.h:176:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INFO_CPU_SETTINGS" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_SSL):
  when 0 is static:
    const
      CRYPTO_EX_INDEX_SSL* = 0 ## Generated based on /usr/include/openssl/crypto.h:217:10
  else:
    let CRYPTO_EX_INDEX_SSL* = 0 ## Generated based on /usr/include/openssl/crypto.h:217:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_SSL" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_SSL_CTX):
  when 1 is static:
    const
      CRYPTO_EX_INDEX_SSL_CTX* = 1 ## Generated based on /usr/include/openssl/crypto.h:218:10
  else:
    let CRYPTO_EX_INDEX_SSL_CTX* = 1 ## Generated based on /usr/include/openssl/crypto.h:218:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_SSL_CTX" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_SSL_SESSION):
  when 2 is static:
    const
      CRYPTO_EX_INDEX_SSL_SESSION* = 2 ## Generated based on /usr/include/openssl/crypto.h:219:10
  else:
    let CRYPTO_EX_INDEX_SSL_SESSION* = 2 ## Generated based on /usr/include/openssl/crypto.h:219:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_X509):
  when 3 is static:
    const
      CRYPTO_EX_INDEX_X509* = 3 ## Generated based on /usr/include/openssl/crypto.h:220:10
  else:
    let CRYPTO_EX_INDEX_X509* = 3 ## Generated based on /usr/include/openssl/crypto.h:220:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_X509" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_X509_STORE):
  when 4 is static:
    const
      CRYPTO_EX_INDEX_X509_STORE* = 4 ## Generated based on /usr/include/openssl/crypto.h:221:10
  else:
    let CRYPTO_EX_INDEX_X509_STORE* = 4 ## Generated based on /usr/include/openssl/crypto.h:221:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_X509_STORE" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_X509_STORE_CTX):
  when 5 is static:
    const
      CRYPTO_EX_INDEX_X509_STORE_CTX* = 5 ## Generated based on /usr/include/openssl/crypto.h:222:10
  else:
    let CRYPTO_EX_INDEX_X509_STORE_CTX* = 5 ## Generated based on /usr/include/openssl/crypto.h:222:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_X509_STORE_CTX" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_DH):
  when 6 is static:
    const
      CRYPTO_EX_INDEX_DH* = 6 ## Generated based on /usr/include/openssl/crypto.h:223:10
  else:
    let CRYPTO_EX_INDEX_DH* = 6 ## Generated based on /usr/include/openssl/crypto.h:223:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_DH" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_DSA):
  when 7 is static:
    const
      CRYPTO_EX_INDEX_DSA* = 7 ## Generated based on /usr/include/openssl/crypto.h:224:10
  else:
    let CRYPTO_EX_INDEX_DSA* = 7 ## Generated based on /usr/include/openssl/crypto.h:224:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_DSA" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_EC_KEY):
  when 8 is static:
    const
      CRYPTO_EX_INDEX_EC_KEY* = 8 ## Generated based on /usr/include/openssl/crypto.h:225:10
  else:
    let CRYPTO_EX_INDEX_EC_KEY* = 8 ## Generated based on /usr/include/openssl/crypto.h:225:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_EC_KEY" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_RSA):
  when 9 is static:
    const
      CRYPTO_EX_INDEX_RSA* = 9 ## Generated based on /usr/include/openssl/crypto.h:226:10
  else:
    let CRYPTO_EX_INDEX_RSA* = 9 ## Generated based on /usr/include/openssl/crypto.h:226:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_RSA" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_ENGINE):
  when 10 is static:
    const
      CRYPTO_EX_INDEX_ENGINE* = 10 ## Generated based on /usr/include/openssl/crypto.h:227:10
  else:
    let CRYPTO_EX_INDEX_ENGINE* = 10 ## Generated based on /usr/include/openssl/crypto.h:227:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_ENGINE" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_UI):
  when 11 is static:
    const
      CRYPTO_EX_INDEX_UI* = 11 ## Generated based on /usr/include/openssl/crypto.h:228:10
  else:
    let CRYPTO_EX_INDEX_UI* = 11 ## Generated based on /usr/include/openssl/crypto.h:228:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_UI" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_BIO):
  when 12 is static:
    const
      CRYPTO_EX_INDEX_BIO* = 12 ## Generated based on /usr/include/openssl/crypto.h:229:10
  else:
    let CRYPTO_EX_INDEX_BIO* = 12 ## Generated based on /usr/include/openssl/crypto.h:229:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_BIO" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_APP):
  when 13 is static:
    const
      CRYPTO_EX_INDEX_APP* = 13 ## Generated based on /usr/include/openssl/crypto.h:230:10
  else:
    let CRYPTO_EX_INDEX_APP* = 13 ## Generated based on /usr/include/openssl/crypto.h:230:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_APP" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_UI_METHOD):
  when 14 is static:
    const
      CRYPTO_EX_INDEX_UI_METHOD* = 14 ## Generated based on /usr/include/openssl/crypto.h:231:10
  else:
    let CRYPTO_EX_INDEX_UI_METHOD* = 14 ## Generated based on /usr/include/openssl/crypto.h:231:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_UI_METHOD" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_RAND_DRBG):
  when 15 is static:
    const
      CRYPTO_EX_INDEX_RAND_DRBG* = 15 ## Generated based on /usr/include/openssl/crypto.h:232:10
  else:
    let CRYPTO_EX_INDEX_RAND_DRBG* = 15 ## Generated based on /usr/include/openssl/crypto.h:232:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_RAND_DRBG" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_DRBG):
  when CRYPTO_EX_INDEX_RAND_DRBG is typedesc:
    type
      CRYPTO_EX_INDEX_DRBG* = CRYPTO_EX_INDEX_RAND_DRBG ## Generated based on /usr/include/openssl/crypto.h:233:10
  else:
    when CRYPTO_EX_INDEX_RAND_DRBG is static:
      const
        CRYPTO_EX_INDEX_DRBG* = CRYPTO_EX_INDEX_RAND_DRBG ## Generated based on /usr/include/openssl/crypto.h:233:10
    else:
      let CRYPTO_EX_INDEX_DRBG* = CRYPTO_EX_INDEX_RAND_DRBG ## Generated based on /usr/include/openssl/crypto.h:233:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_DRBG" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_OSSL_LIB_CTX):
  when 16 is static:
    const
      CRYPTO_EX_INDEX_OSSL_LIB_CTX* = 16 ## Generated based on /usr/include/openssl/crypto.h:234:10
  else:
    let CRYPTO_EX_INDEX_OSSL_LIB_CTX* = 16 ## Generated based on /usr/include/openssl/crypto.h:234:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_OSSL_LIB_CTX" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_EVP_PKEY):
  when 17 is static:
    const
      CRYPTO_EX_INDEX_EVP_PKEY* = 17 ## Generated based on /usr/include/openssl/crypto.h:235:10
  else:
    let CRYPTO_EX_INDEX_EVP_PKEY* = 17 ## Generated based on /usr/include/openssl/crypto.h:235:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_EVP_PKEY" &
        " already exists, not redeclaring")
when not declared(CRYPTO_EX_INDEX_COUNT):
  when 18 is static:
    const
      CRYPTO_EX_INDEX_COUNT* = 18 ## Generated based on /usr/include/openssl/crypto.h:236:10
  else:
    let CRYPTO_EX_INDEX_COUNT* = 18 ## Generated based on /usr/include/openssl/crypto.h:236:10
else:
  static :
    hint("Declaration of " & "CRYPTO_EX_INDEX_COUNT" &
        " already exists, not redeclaring")
when not declared(CRYPTO_LOCK):
  when 1 is static:
    const
      CRYPTO_LOCK* = 1       ## Generated based on /usr/include/openssl/crypto.h:300:11
  else:
    let CRYPTO_LOCK* = 1     ## Generated based on /usr/include/openssl/crypto.h:300:11
else:
  static :
    hint("Declaration of " & "CRYPTO_LOCK" & " already exists, not redeclaring")
when not declared(CRYPTO_UNLOCK):
  when 2 is static:
    const
      CRYPTO_UNLOCK* = 2     ## Generated based on /usr/include/openssl/crypto.h:301:11
  else:
    let CRYPTO_UNLOCK* = 2   ## Generated based on /usr/include/openssl/crypto.h:301:11
else:
  static :
    hint("Declaration of " & "CRYPTO_UNLOCK" &
        " already exists, not redeclaring")
when not declared(CRYPTO_READ):
  when 4 is static:
    const
      CRYPTO_READ* = 4       ## Generated based on /usr/include/openssl/crypto.h:302:11
  else:
    let CRYPTO_READ* = 4     ## Generated based on /usr/include/openssl/crypto.h:302:11
else:
  static :
    hint("Declaration of " & "CRYPTO_READ" & " already exists, not redeclaring")
when not declared(CRYPTO_WRITE):
  when 8 is static:
    const
      CRYPTO_WRITE* = 8      ## Generated based on /usr/include/openssl/crypto.h:303:11
  else:
    let CRYPTO_WRITE* = 8    ## Generated based on /usr/include/openssl/crypto.h:303:11
else:
  static :
    hint("Declaration of " & "CRYPTO_WRITE" & " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS):
  when cast[clong](1'i64) is static:
    const
      OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS* = cast[clong](1'i64) ## Generated based on /usr/include/openssl/crypto.h:448:10
  else:
    let OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS* = cast[clong](1'i64) ## Generated based on /usr/include/openssl/crypto.h:448:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_LOAD_CRYPTO_STRINGS):
  when cast[clong](2'i64) is static:
    const
      OPENSSL_INIT_LOAD_CRYPTO_STRINGS* = cast[clong](2'i64) ## Generated based on /usr/include/openssl/crypto.h:449:10
  else:
    let OPENSSL_INIT_LOAD_CRYPTO_STRINGS* = cast[clong](2'i64) ## Generated based on /usr/include/openssl/crypto.h:449:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_LOAD_CRYPTO_STRINGS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ADD_ALL_CIPHERS):
  when cast[clong](4'i64) is static:
    const
      OPENSSL_INIT_ADD_ALL_CIPHERS* = cast[clong](4'i64) ## Generated based on /usr/include/openssl/crypto.h:450:10
  else:
    let OPENSSL_INIT_ADD_ALL_CIPHERS* = cast[clong](4'i64) ## Generated based on /usr/include/openssl/crypto.h:450:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ADD_ALL_CIPHERS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ADD_ALL_DIGESTS):
  when cast[clong](8'i64) is static:
    const
      OPENSSL_INIT_ADD_ALL_DIGESTS* = cast[clong](8'i64) ## Generated based on /usr/include/openssl/crypto.h:451:10
  else:
    let OPENSSL_INIT_ADD_ALL_DIGESTS* = cast[clong](8'i64) ## Generated based on /usr/include/openssl/crypto.h:451:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ADD_ALL_DIGESTS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_ADD_ALL_CIPHERS):
  when cast[clong](16'i64) is static:
    const
      OPENSSL_INIT_NO_ADD_ALL_CIPHERS* = cast[clong](16'i64) ## Generated based on /usr/include/openssl/crypto.h:452:10
  else:
    let OPENSSL_INIT_NO_ADD_ALL_CIPHERS* = cast[clong](16'i64) ## Generated based on /usr/include/openssl/crypto.h:452:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_ADD_ALL_CIPHERS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_ADD_ALL_DIGESTS):
  when cast[clong](32'i64) is static:
    const
      OPENSSL_INIT_NO_ADD_ALL_DIGESTS* = cast[clong](32'i64) ## Generated based on /usr/include/openssl/crypto.h:453:10
  else:
    let OPENSSL_INIT_NO_ADD_ALL_DIGESTS* = cast[clong](32'i64) ## Generated based on /usr/include/openssl/crypto.h:453:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_ADD_ALL_DIGESTS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_LOAD_CONFIG):
  when cast[clong](64'i64) is static:
    const
      OPENSSL_INIT_LOAD_CONFIG* = cast[clong](64'i64) ## Generated based on /usr/include/openssl/crypto.h:454:10
  else:
    let OPENSSL_INIT_LOAD_CONFIG* = cast[clong](64'i64) ## Generated based on /usr/include/openssl/crypto.h:454:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_LOAD_CONFIG" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_LOAD_CONFIG):
  when cast[clong](128'i64) is static:
    const
      OPENSSL_INIT_NO_LOAD_CONFIG* = cast[clong](128'i64) ## Generated based on /usr/include/openssl/crypto.h:455:10
  else:
    let OPENSSL_INIT_NO_LOAD_CONFIG* = cast[clong](128'i64) ## Generated based on /usr/include/openssl/crypto.h:455:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_LOAD_CONFIG" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ASYNC):
  when cast[clong](256'i64) is static:
    const
      OPENSSL_INIT_ASYNC* = cast[clong](256'i64) ## Generated based on /usr/include/openssl/crypto.h:456:10
  else:
    let OPENSSL_INIT_ASYNC* = cast[clong](256'i64) ## Generated based on /usr/include/openssl/crypto.h:456:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ASYNC" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_RDRAND):
  when cast[clong](512'i64) is static:
    const
      OPENSSL_INIT_ENGINE_RDRAND* = cast[clong](512'i64) ## Generated based on /usr/include/openssl/crypto.h:457:10
  else:
    let OPENSSL_INIT_ENGINE_RDRAND* = cast[clong](512'i64) ## Generated based on /usr/include/openssl/crypto.h:457:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_RDRAND" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_DYNAMIC):
  when cast[clong](1024'i64) is static:
    const
      OPENSSL_INIT_ENGINE_DYNAMIC* = cast[clong](1024'i64) ## Generated based on /usr/include/openssl/crypto.h:458:10
  else:
    let OPENSSL_INIT_ENGINE_DYNAMIC* = cast[clong](1024'i64) ## Generated based on /usr/include/openssl/crypto.h:458:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_DYNAMIC" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_OPENSSL):
  when cast[clong](2048'i64) is static:
    const
      OPENSSL_INIT_ENGINE_OPENSSL* = cast[clong](2048'i64) ## Generated based on /usr/include/openssl/crypto.h:459:10
  else:
    let OPENSSL_INIT_ENGINE_OPENSSL* = cast[clong](2048'i64) ## Generated based on /usr/include/openssl/crypto.h:459:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_OPENSSL" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_CRYPTODEV):
  when cast[clong](4096'i64) is static:
    const
      OPENSSL_INIT_ENGINE_CRYPTODEV* = cast[clong](4096'i64) ## Generated based on /usr/include/openssl/crypto.h:460:10
  else:
    let OPENSSL_INIT_ENGINE_CRYPTODEV* = cast[clong](4096'i64) ## Generated based on /usr/include/openssl/crypto.h:460:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_CRYPTODEV" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_CAPI):
  when cast[clong](8192'i64) is static:
    const
      OPENSSL_INIT_ENGINE_CAPI* = cast[clong](8192'i64) ## Generated based on /usr/include/openssl/crypto.h:461:10
  else:
    let OPENSSL_INIT_ENGINE_CAPI* = cast[clong](8192'i64) ## Generated based on /usr/include/openssl/crypto.h:461:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_CAPI" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_PADLOCK):
  when cast[clong](16384'i64) is static:
    const
      OPENSSL_INIT_ENGINE_PADLOCK* = cast[clong](16384'i64) ## Generated based on /usr/include/openssl/crypto.h:462:10
  else:
    let OPENSSL_INIT_ENGINE_PADLOCK* = cast[clong](16384'i64) ## Generated based on /usr/include/openssl/crypto.h:462:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_PADLOCK" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ENGINE_AFALG):
  when cast[clong](32768'i64) is static:
    const
      OPENSSL_INIT_ENGINE_AFALG* = cast[clong](32768'i64) ## Generated based on /usr/include/openssl/crypto.h:463:10
  else:
    let OPENSSL_INIT_ENGINE_AFALG* = cast[clong](32768'i64) ## Generated based on /usr/include/openssl/crypto.h:463:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ENGINE_AFALG" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_ATFORK):
  when cast[clong](131072'i64) is static:
    const
      OPENSSL_INIT_ATFORK* = cast[clong](131072'i64) ## Generated based on /usr/include/openssl/crypto.h:465:10
  else:
    let OPENSSL_INIT_ATFORK* = cast[clong](131072'i64) ## Generated based on /usr/include/openssl/crypto.h:465:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_ATFORK" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_ATEXIT):
  when cast[clong](524288'i64) is static:
    const
      OPENSSL_INIT_NO_ATEXIT* = cast[clong](524288'i64) ## Generated based on /usr/include/openssl/crypto.h:467:10
  else:
    let OPENSSL_INIT_NO_ATEXIT* = cast[clong](524288'i64) ## Generated based on /usr/include/openssl/crypto.h:467:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_ATEXIT" &
        " already exists, not redeclaring")
when not declared(PTHREAD_ONCE_INIT):
  when 0 is static:
    const
      PTHREAD_ONCE_INIT* = 0 ## Generated based on /usr/include/pthread.h:186:9
  else:
    let PTHREAD_ONCE_INIT* = 0 ## Generated based on /usr/include/pthread.h:186:9
else:
  static :
    hint("Declaration of " & "PTHREAD_ONCE_INIT" &
        " already exists, not redeclaring")
when not declared(V_ASN1_UNIVERSAL):
  when 0 is static:
    const
      V_ASN1_UNIVERSAL* = 0  ## Generated based on /usr/include/openssl/asn1.h:44:10
  else:
    let V_ASN1_UNIVERSAL* = 0 ## Generated based on /usr/include/openssl/asn1.h:44:10
else:
  static :
    hint("Declaration of " & "V_ASN1_UNIVERSAL" &
        " already exists, not redeclaring")
when not declared(V_ASN1_APPLICATION):
  when 64 is static:
    const
      V_ASN1_APPLICATION* = 64 ## Generated based on /usr/include/openssl/asn1.h:45:10
  else:
    let V_ASN1_APPLICATION* = 64 ## Generated based on /usr/include/openssl/asn1.h:45:10
else:
  static :
    hint("Declaration of " & "V_ASN1_APPLICATION" &
        " already exists, not redeclaring")
when not declared(V_ASN1_CONTEXT_SPECIFIC):
  when 128 is static:
    const
      V_ASN1_CONTEXT_SPECIFIC* = 128 ## Generated based on /usr/include/openssl/asn1.h:46:10
  else:
    let V_ASN1_CONTEXT_SPECIFIC* = 128 ## Generated based on /usr/include/openssl/asn1.h:46:10
else:
  static :
    hint("Declaration of " & "V_ASN1_CONTEXT_SPECIFIC" &
        " already exists, not redeclaring")
when not declared(V_ASN1_PRIVATE):
  when 192 is static:
    const
      V_ASN1_PRIVATE* = 192  ## Generated based on /usr/include/openssl/asn1.h:47:10
  else:
    let V_ASN1_PRIVATE* = 192 ## Generated based on /usr/include/openssl/asn1.h:47:10
else:
  static :
    hint("Declaration of " & "V_ASN1_PRIVATE" &
        " already exists, not redeclaring")
when not declared(V_ASN1_CONSTRUCTED):
  when 32 is static:
    const
      V_ASN1_CONSTRUCTED* = 32 ## Generated based on /usr/include/openssl/asn1.h:49:10
  else:
    let V_ASN1_CONSTRUCTED* = 32 ## Generated based on /usr/include/openssl/asn1.h:49:10
else:
  static :
    hint("Declaration of " & "V_ASN1_CONSTRUCTED" &
        " already exists, not redeclaring")
when not declared(V_ASN1_PRIMITIVE_TAG):
  when 31 is static:
    const
      V_ASN1_PRIMITIVE_TAG* = 31 ## Generated based on /usr/include/openssl/asn1.h:50:10
  else:
    let V_ASN1_PRIMITIVE_TAG* = 31 ## Generated based on /usr/include/openssl/asn1.h:50:10
else:
  static :
    hint("Declaration of " & "V_ASN1_PRIMITIVE_TAG" &
        " already exists, not redeclaring")
when not declared(V_ASN1_APP_CHOOSE):
  when -2 is static:
    const
      V_ASN1_APP_CHOOSE* = -2 ## Generated based on /usr/include/openssl/asn1.h:53:10
  else:
    let V_ASN1_APP_CHOOSE* = -2 ## Generated based on /usr/include/openssl/asn1.h:53:10
else:
  static :
    hint("Declaration of " & "V_ASN1_APP_CHOOSE" &
        " already exists, not redeclaring")
when not declared(V_ASN1_OTHER):
  when -3 is static:
    const
      V_ASN1_OTHER* = -3     ## Generated based on /usr/include/openssl/asn1.h:54:10
  else:
    let V_ASN1_OTHER* = -3   ## Generated based on /usr/include/openssl/asn1.h:54:10
else:
  static :
    hint("Declaration of " & "V_ASN1_OTHER" & " already exists, not redeclaring")
when not declared(V_ASN1_ANY):
  when -4 is static:
    const
      V_ASN1_ANY* = -4       ## Generated based on /usr/include/openssl/asn1.h:55:10
  else:
    let V_ASN1_ANY* = -4     ## Generated based on /usr/include/openssl/asn1.h:55:10
else:
  static :
    hint("Declaration of " & "V_ASN1_ANY" & " already exists, not redeclaring")
when not declared(V_ASN1_UNDEF):
  when -1 is static:
    const
      V_ASN1_UNDEF* = -1     ## Generated based on /usr/include/openssl/asn1.h:57:10
  else:
    let V_ASN1_UNDEF* = -1   ## Generated based on /usr/include/openssl/asn1.h:57:10
else:
  static :
    hint("Declaration of " & "V_ASN1_UNDEF" & " already exists, not redeclaring")
when not declared(V_ASN1_EOC):
  when 0 is static:
    const
      V_ASN1_EOC* = 0        ## Generated based on /usr/include/openssl/asn1.h:59:10
  else:
    let V_ASN1_EOC* = 0      ## Generated based on /usr/include/openssl/asn1.h:59:10
else:
  static :
    hint("Declaration of " & "V_ASN1_EOC" & " already exists, not redeclaring")
when not declared(V_ASN1_BOOLEAN):
  when 1 is static:
    const
      V_ASN1_BOOLEAN* = 1    ## Generated based on /usr/include/openssl/asn1.h:60:10
  else:
    let V_ASN1_BOOLEAN* = 1  ## Generated based on /usr/include/openssl/asn1.h:60:10
else:
  static :
    hint("Declaration of " & "V_ASN1_BOOLEAN" &
        " already exists, not redeclaring")
when not declared(V_ASN1_INTEGER):
  when 2 is static:
    const
      V_ASN1_INTEGER* = 2    ## Generated based on /usr/include/openssl/asn1.h:61:10
  else:
    let V_ASN1_INTEGER* = 2  ## Generated based on /usr/include/openssl/asn1.h:61:10
else:
  static :
    hint("Declaration of " & "V_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(V_ASN1_BIT_STRING):
  when 3 is static:
    const
      V_ASN1_BIT_STRING* = 3 ## Generated based on /usr/include/openssl/asn1.h:62:10
  else:
    let V_ASN1_BIT_STRING* = 3 ## Generated based on /usr/include/openssl/asn1.h:62:10
else:
  static :
    hint("Declaration of " & "V_ASN1_BIT_STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_OCTET_STRING):
  when 4 is static:
    const
      V_ASN1_OCTET_STRING* = 4 ## Generated based on /usr/include/openssl/asn1.h:63:10
  else:
    let V_ASN1_OCTET_STRING* = 4 ## Generated based on /usr/include/openssl/asn1.h:63:10
else:
  static :
    hint("Declaration of " & "V_ASN1_OCTET_STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_NULL):
  when 5 is static:
    const
      V_ASN1_NULL* = 5       ## Generated based on /usr/include/openssl/asn1.h:64:10
  else:
    let V_ASN1_NULL* = 5     ## Generated based on /usr/include/openssl/asn1.h:64:10
else:
  static :
    hint("Declaration of " & "V_ASN1_NULL" & " already exists, not redeclaring")
when not declared(V_ASN1_OBJECT):
  when 6 is static:
    const
      V_ASN1_OBJECT* = 6     ## Generated based on /usr/include/openssl/asn1.h:65:10
  else:
    let V_ASN1_OBJECT* = 6   ## Generated based on /usr/include/openssl/asn1.h:65:10
else:
  static :
    hint("Declaration of " & "V_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(V_ASN1_OBJECT_DESCRIPTOR):
  when 7 is static:
    const
      V_ASN1_OBJECT_DESCRIPTOR* = 7 ## Generated based on /usr/include/openssl/asn1.h:66:10
  else:
    let V_ASN1_OBJECT_DESCRIPTOR* = 7 ## Generated based on /usr/include/openssl/asn1.h:66:10
else:
  static :
    hint("Declaration of " & "V_ASN1_OBJECT_DESCRIPTOR" &
        " already exists, not redeclaring")
when not declared(V_ASN1_EXTERNAL):
  when 8 is static:
    const
      V_ASN1_EXTERNAL* = 8   ## Generated based on /usr/include/openssl/asn1.h:67:10
  else:
    let V_ASN1_EXTERNAL* = 8 ## Generated based on /usr/include/openssl/asn1.h:67:10
else:
  static :
    hint("Declaration of " & "V_ASN1_EXTERNAL" &
        " already exists, not redeclaring")
when not declared(V_ASN1_REAL):
  when 9 is static:
    const
      V_ASN1_REAL* = 9       ## Generated based on /usr/include/openssl/asn1.h:68:10
  else:
    let V_ASN1_REAL* = 9     ## Generated based on /usr/include/openssl/asn1.h:68:10
else:
  static :
    hint("Declaration of " & "V_ASN1_REAL" & " already exists, not redeclaring")
when not declared(V_ASN1_ENUMERATED):
  when 10 is static:
    const
      V_ASN1_ENUMERATED* = 10 ## Generated based on /usr/include/openssl/asn1.h:69:10
  else:
    let V_ASN1_ENUMERATED* = 10 ## Generated based on /usr/include/openssl/asn1.h:69:10
else:
  static :
    hint("Declaration of " & "V_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(V_ASN1_UTF8STRING):
  when 12 is static:
    const
      V_ASN1_UTF8STRING* = 12 ## Generated based on /usr/include/openssl/asn1.h:70:10
  else:
    let V_ASN1_UTF8STRING* = 12 ## Generated based on /usr/include/openssl/asn1.h:70:10
else:
  static :
    hint("Declaration of " & "V_ASN1_UTF8STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_SEQUENCE):
  when 16 is static:
    const
      V_ASN1_SEQUENCE* = 16  ## Generated based on /usr/include/openssl/asn1.h:71:10
  else:
    let V_ASN1_SEQUENCE* = 16 ## Generated based on /usr/include/openssl/asn1.h:71:10
else:
  static :
    hint("Declaration of " & "V_ASN1_SEQUENCE" &
        " already exists, not redeclaring")
when not declared(V_ASN1_SET):
  when 17 is static:
    const
      V_ASN1_SET* = 17       ## Generated based on /usr/include/openssl/asn1.h:72:10
  else:
    let V_ASN1_SET* = 17     ## Generated based on /usr/include/openssl/asn1.h:72:10
else:
  static :
    hint("Declaration of " & "V_ASN1_SET" & " already exists, not redeclaring")
when not declared(V_ASN1_NUMERICSTRING):
  when 18 is static:
    const
      V_ASN1_NUMERICSTRING* = 18 ## Generated based on /usr/include/openssl/asn1.h:73:10
  else:
    let V_ASN1_NUMERICSTRING* = 18 ## Generated based on /usr/include/openssl/asn1.h:73:10
else:
  static :
    hint("Declaration of " & "V_ASN1_NUMERICSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_PRINTABLESTRING):
  when 19 is static:
    const
      V_ASN1_PRINTABLESTRING* = 19 ## Generated based on /usr/include/openssl/asn1.h:74:10
  else:
    let V_ASN1_PRINTABLESTRING* = 19 ## Generated based on /usr/include/openssl/asn1.h:74:10
else:
  static :
    hint("Declaration of " & "V_ASN1_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_T61STRING):
  when 20 is static:
    const
      V_ASN1_T61STRING* = 20 ## Generated based on /usr/include/openssl/asn1.h:75:10
  else:
    let V_ASN1_T61STRING* = 20 ## Generated based on /usr/include/openssl/asn1.h:75:10
else:
  static :
    hint("Declaration of " & "V_ASN1_T61STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_TELETEXSTRING):
  when 20 is static:
    const
      V_ASN1_TELETEXSTRING* = 20 ## Generated based on /usr/include/openssl/asn1.h:76:10
  else:
    let V_ASN1_TELETEXSTRING* = 20 ## Generated based on /usr/include/openssl/asn1.h:76:10
else:
  static :
    hint("Declaration of " & "V_ASN1_TELETEXSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_VIDEOTEXSTRING):
  when 21 is static:
    const
      V_ASN1_VIDEOTEXSTRING* = 21 ## Generated based on /usr/include/openssl/asn1.h:77:10
  else:
    let V_ASN1_VIDEOTEXSTRING* = 21 ## Generated based on /usr/include/openssl/asn1.h:77:10
else:
  static :
    hint("Declaration of " & "V_ASN1_VIDEOTEXSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_IA5STRING):
  when 22 is static:
    const
      V_ASN1_IA5STRING* = 22 ## Generated based on /usr/include/openssl/asn1.h:78:10
  else:
    let V_ASN1_IA5STRING* = 22 ## Generated based on /usr/include/openssl/asn1.h:78:10
else:
  static :
    hint("Declaration of " & "V_ASN1_IA5STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_UTCTIME):
  when 23 is static:
    const
      V_ASN1_UTCTIME* = 23   ## Generated based on /usr/include/openssl/asn1.h:79:10
  else:
    let V_ASN1_UTCTIME* = 23 ## Generated based on /usr/include/openssl/asn1.h:79:10
else:
  static :
    hint("Declaration of " & "V_ASN1_UTCTIME" &
        " already exists, not redeclaring")
when not declared(V_ASN1_GENERALIZEDTIME):
  when 24 is static:
    const
      V_ASN1_GENERALIZEDTIME* = 24 ## Generated based on /usr/include/openssl/asn1.h:80:10
  else:
    let V_ASN1_GENERALIZEDTIME* = 24 ## Generated based on /usr/include/openssl/asn1.h:80:10
else:
  static :
    hint("Declaration of " & "V_ASN1_GENERALIZEDTIME" &
        " already exists, not redeclaring")
when not declared(V_ASN1_GRAPHICSTRING):
  when 25 is static:
    const
      V_ASN1_GRAPHICSTRING* = 25 ## Generated based on /usr/include/openssl/asn1.h:81:10
  else:
    let V_ASN1_GRAPHICSTRING* = 25 ## Generated based on /usr/include/openssl/asn1.h:81:10
else:
  static :
    hint("Declaration of " & "V_ASN1_GRAPHICSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_ISO64STRING):
  when 26 is static:
    const
      V_ASN1_ISO64STRING* = 26 ## Generated based on /usr/include/openssl/asn1.h:82:10
  else:
    let V_ASN1_ISO64STRING* = 26 ## Generated based on /usr/include/openssl/asn1.h:82:10
else:
  static :
    hint("Declaration of " & "V_ASN1_ISO64STRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_VISIBLESTRING):
  when 26 is static:
    const
      V_ASN1_VISIBLESTRING* = 26 ## Generated based on /usr/include/openssl/asn1.h:83:10
  else:
    let V_ASN1_VISIBLESTRING* = 26 ## Generated based on /usr/include/openssl/asn1.h:83:10
else:
  static :
    hint("Declaration of " & "V_ASN1_VISIBLESTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_GENERALSTRING):
  when 27 is static:
    const
      V_ASN1_GENERALSTRING* = 27 ## Generated based on /usr/include/openssl/asn1.h:84:10
  else:
    let V_ASN1_GENERALSTRING* = 27 ## Generated based on /usr/include/openssl/asn1.h:84:10
else:
  static :
    hint("Declaration of " & "V_ASN1_GENERALSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_UNIVERSALSTRING):
  when 28 is static:
    const
      V_ASN1_UNIVERSALSTRING* = 28 ## Generated based on /usr/include/openssl/asn1.h:85:10
  else:
    let V_ASN1_UNIVERSALSTRING* = 28 ## Generated based on /usr/include/openssl/asn1.h:85:10
else:
  static :
    hint("Declaration of " & "V_ASN1_UNIVERSALSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_BMPSTRING):
  when 30 is static:
    const
      V_ASN1_BMPSTRING* = 30 ## Generated based on /usr/include/openssl/asn1.h:86:10
  else:
    let V_ASN1_BMPSTRING* = 30 ## Generated based on /usr/include/openssl/asn1.h:86:10
else:
  static :
    hint("Declaration of " & "V_ASN1_BMPSTRING" &
        " already exists, not redeclaring")
when not declared(V_ASN1_NEG):
  when 256 is static:
    const
      V_ASN1_NEG* = 256      ## Generated based on /usr/include/openssl/asn1.h:94:10
  else:
    let V_ASN1_NEG* = 256    ## Generated based on /usr/include/openssl/asn1.h:94:10
else:
  static :
    hint("Declaration of " & "V_ASN1_NEG" & " already exists, not redeclaring")
when not declared(B_ASN1_NUMERICSTRING):
  when 1 is static:
    const
      B_ASN1_NUMERICSTRING* = 1 ## Generated based on /usr/include/openssl/asn1.h:99:10
  else:
    let B_ASN1_NUMERICSTRING* = 1 ## Generated based on /usr/include/openssl/asn1.h:99:10
else:
  static :
    hint("Declaration of " & "B_ASN1_NUMERICSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_PRINTABLESTRING):
  when 2 is static:
    const
      B_ASN1_PRINTABLESTRING* = 2 ## Generated based on /usr/include/openssl/asn1.h:100:10
  else:
    let B_ASN1_PRINTABLESTRING* = 2 ## Generated based on /usr/include/openssl/asn1.h:100:10
else:
  static :
    hint("Declaration of " & "B_ASN1_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_T61STRING):
  when 4 is static:
    const
      B_ASN1_T61STRING* = 4  ## Generated based on /usr/include/openssl/asn1.h:101:10
  else:
    let B_ASN1_T61STRING* = 4 ## Generated based on /usr/include/openssl/asn1.h:101:10
else:
  static :
    hint("Declaration of " & "B_ASN1_T61STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_TELETEXSTRING):
  when 4 is static:
    const
      B_ASN1_TELETEXSTRING* = 4 ## Generated based on /usr/include/openssl/asn1.h:102:10
  else:
    let B_ASN1_TELETEXSTRING* = 4 ## Generated based on /usr/include/openssl/asn1.h:102:10
else:
  static :
    hint("Declaration of " & "B_ASN1_TELETEXSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_VIDEOTEXSTRING):
  when 8 is static:
    const
      B_ASN1_VIDEOTEXSTRING* = 8 ## Generated based on /usr/include/openssl/asn1.h:103:10
  else:
    let B_ASN1_VIDEOTEXSTRING* = 8 ## Generated based on /usr/include/openssl/asn1.h:103:10
else:
  static :
    hint("Declaration of " & "B_ASN1_VIDEOTEXSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_IA5STRING):
  when 16 is static:
    const
      B_ASN1_IA5STRING* = 16 ## Generated based on /usr/include/openssl/asn1.h:104:10
  else:
    let B_ASN1_IA5STRING* = 16 ## Generated based on /usr/include/openssl/asn1.h:104:10
else:
  static :
    hint("Declaration of " & "B_ASN1_IA5STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_GRAPHICSTRING):
  when 32 is static:
    const
      B_ASN1_GRAPHICSTRING* = 32 ## Generated based on /usr/include/openssl/asn1.h:105:10
  else:
    let B_ASN1_GRAPHICSTRING* = 32 ## Generated based on /usr/include/openssl/asn1.h:105:10
else:
  static :
    hint("Declaration of " & "B_ASN1_GRAPHICSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_ISO64STRING):
  when 64 is static:
    const
      B_ASN1_ISO64STRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:106:10
  else:
    let B_ASN1_ISO64STRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:106:10
else:
  static :
    hint("Declaration of " & "B_ASN1_ISO64STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_VISIBLESTRING):
  when 64 is static:
    const
      B_ASN1_VISIBLESTRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:107:10
  else:
    let B_ASN1_VISIBLESTRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:107:10
else:
  static :
    hint("Declaration of " & "B_ASN1_VISIBLESTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_GENERALSTRING):
  when 128 is static:
    const
      B_ASN1_GENERALSTRING* = 128 ## Generated based on /usr/include/openssl/asn1.h:108:10
  else:
    let B_ASN1_GENERALSTRING* = 128 ## Generated based on /usr/include/openssl/asn1.h:108:10
else:
  static :
    hint("Declaration of " & "B_ASN1_GENERALSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_UNIVERSALSTRING):
  when 256 is static:
    const
      B_ASN1_UNIVERSALSTRING* = 256 ## Generated based on /usr/include/openssl/asn1.h:109:10
  else:
    let B_ASN1_UNIVERSALSTRING* = 256 ## Generated based on /usr/include/openssl/asn1.h:109:10
else:
  static :
    hint("Declaration of " & "B_ASN1_UNIVERSALSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_OCTET_STRING):
  when 512 is static:
    const
      B_ASN1_OCTET_STRING* = 512 ## Generated based on /usr/include/openssl/asn1.h:110:10
  else:
    let B_ASN1_OCTET_STRING* = 512 ## Generated based on /usr/include/openssl/asn1.h:110:10
else:
  static :
    hint("Declaration of " & "B_ASN1_OCTET_STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_BIT_STRING):
  when 1024 is static:
    const
      B_ASN1_BIT_STRING* = 1024 ## Generated based on /usr/include/openssl/asn1.h:111:10
  else:
    let B_ASN1_BIT_STRING* = 1024 ## Generated based on /usr/include/openssl/asn1.h:111:10
else:
  static :
    hint("Declaration of " & "B_ASN1_BIT_STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_BMPSTRING):
  when 2048 is static:
    const
      B_ASN1_BMPSTRING* = 2048 ## Generated based on /usr/include/openssl/asn1.h:112:10
  else:
    let B_ASN1_BMPSTRING* = 2048 ## Generated based on /usr/include/openssl/asn1.h:112:10
else:
  static :
    hint("Declaration of " & "B_ASN1_BMPSTRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_UNKNOWN):
  when 4096 is static:
    const
      B_ASN1_UNKNOWN* = 4096 ## Generated based on /usr/include/openssl/asn1.h:113:10
  else:
    let B_ASN1_UNKNOWN* = 4096 ## Generated based on /usr/include/openssl/asn1.h:113:10
else:
  static :
    hint("Declaration of " & "B_ASN1_UNKNOWN" &
        " already exists, not redeclaring")
when not declared(B_ASN1_UTF8STRING):
  when 8192 is static:
    const
      B_ASN1_UTF8STRING* = 8192 ## Generated based on /usr/include/openssl/asn1.h:114:10
  else:
    let B_ASN1_UTF8STRING* = 8192 ## Generated based on /usr/include/openssl/asn1.h:114:10
else:
  static :
    hint("Declaration of " & "B_ASN1_UTF8STRING" &
        " already exists, not redeclaring")
when not declared(B_ASN1_UTCTIME):
  when 16384 is static:
    const
      B_ASN1_UTCTIME* = 16384 ## Generated based on /usr/include/openssl/asn1.h:115:10
  else:
    let B_ASN1_UTCTIME* = 16384 ## Generated based on /usr/include/openssl/asn1.h:115:10
else:
  static :
    hint("Declaration of " & "B_ASN1_UTCTIME" &
        " already exists, not redeclaring")
when not declared(B_ASN1_GENERALIZEDTIME):
  when 32768 is static:
    const
      B_ASN1_GENERALIZEDTIME* = 32768 ## Generated based on /usr/include/openssl/asn1.h:116:10
  else:
    let B_ASN1_GENERALIZEDTIME* = 32768 ## Generated based on /usr/include/openssl/asn1.h:116:10
else:
  static :
    hint("Declaration of " & "B_ASN1_GENERALIZEDTIME" &
        " already exists, not redeclaring")
when not declared(B_ASN1_SEQUENCE):
  when 65536 is static:
    const
      B_ASN1_SEQUENCE* = 65536 ## Generated based on /usr/include/openssl/asn1.h:117:10
  else:
    let B_ASN1_SEQUENCE* = 65536 ## Generated based on /usr/include/openssl/asn1.h:117:10
else:
  static :
    hint("Declaration of " & "B_ASN1_SEQUENCE" &
        " already exists, not redeclaring")
when not declared(MBSTRING_FLAG):
  when 4096 is static:
    const
      MBSTRING_FLAG* = 4096  ## Generated based on /usr/include/openssl/asn1.h:119:10
  else:
    let MBSTRING_FLAG* = 4096 ## Generated based on /usr/include/openssl/asn1.h:119:10
else:
  static :
    hint("Declaration of " & "MBSTRING_FLAG" &
        " already exists, not redeclaring")
when not declared(MBSTRING_UTF8):
  when MBSTRING_FLAG is typedesc:
    type
      MBSTRING_UTF8* = MBSTRING_FLAG ## Generated based on /usr/include/openssl/asn1.h:120:10
  else:
    when MBSTRING_FLAG is static:
      const
        MBSTRING_UTF8* = MBSTRING_FLAG ## Generated based on /usr/include/openssl/asn1.h:120:10
    else:
      let MBSTRING_UTF8* = MBSTRING_FLAG ## Generated based on /usr/include/openssl/asn1.h:120:10
else:
  static :
    hint("Declaration of " & "MBSTRING_UTF8" &
        " already exists, not redeclaring")
when not declared(SMIME_OLDMIME):
  when 1024 is static:
    const
      SMIME_OLDMIME* = 1024  ## Generated based on /usr/include/openssl/asn1.h:124:10
  else:
    let SMIME_OLDMIME* = 1024 ## Generated based on /usr/include/openssl/asn1.h:124:10
else:
  static :
    hint("Declaration of " & "SMIME_OLDMIME" &
        " already exists, not redeclaring")
when not declared(SMIME_CRLFEOL):
  when 2048 is static:
    const
      SMIME_CRLFEOL* = 2048  ## Generated based on /usr/include/openssl/asn1.h:125:10
  else:
    let SMIME_CRLFEOL* = 2048 ## Generated based on /usr/include/openssl/asn1.h:125:10
else:
  static :
    hint("Declaration of " & "SMIME_CRLFEOL" &
        " already exists, not redeclaring")
when not declared(SMIME_STREAM):
  when 4096 is static:
    const
      SMIME_STREAM* = 4096   ## Generated based on /usr/include/openssl/asn1.h:126:10
  else:
    let SMIME_STREAM* = 4096 ## Generated based on /usr/include/openssl/asn1.h:126:10
else:
  static :
    hint("Declaration of " & "SMIME_STREAM" & " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_BITS_LEFT):
  when 8 is static:
    const
      ASN1_STRING_FLAG_BITS_LEFT* = 8 ## Generated based on /usr/include/openssl/asn1.h:158:10
  else:
    let ASN1_STRING_FLAG_BITS_LEFT* = 8 ## Generated based on /usr/include/openssl/asn1.h:158:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_BITS_LEFT" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_NDEF):
  when 16 is static:
    const
      ASN1_STRING_FLAG_NDEF* = 16 ## Generated based on /usr/include/openssl/asn1.h:164:10
  else:
    let ASN1_STRING_FLAG_NDEF* = 16 ## Generated based on /usr/include/openssl/asn1.h:164:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_NDEF" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_CONT):
  when 32 is static:
    const
      ASN1_STRING_FLAG_CONT* = 32 ## Generated based on /usr/include/openssl/asn1.h:172:10
  else:
    let ASN1_STRING_FLAG_CONT* = 32 ## Generated based on /usr/include/openssl/asn1.h:172:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_CONT" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_MSTRING):
  when 64 is static:
    const
      ASN1_STRING_FLAG_MSTRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:177:10
  else:
    let ASN1_STRING_FLAG_MSTRING* = 64 ## Generated based on /usr/include/openssl/asn1.h:177:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_MSTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_EMBED):
  when 128 is static:
    const
      ASN1_STRING_FLAG_EMBED* = 128 ## Generated based on /usr/include/openssl/asn1.h:179:10
  else:
    let ASN1_STRING_FLAG_EMBED* = 128 ## Generated based on /usr/include/openssl/asn1.h:179:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_EMBED" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_FLAG_X509_TIME):
  when 256 is static:
    const
      ASN1_STRING_FLAG_X509_TIME* = 256 ## Generated based on /usr/include/openssl/asn1.h:181:10
  else:
    let ASN1_STRING_FLAG_X509_TIME* = 256 ## Generated based on /usr/include/openssl/asn1.h:181:10
else:
  static :
    hint("Declaration of " & "ASN1_STRING_FLAG_X509_TIME" &
        " already exists, not redeclaring")
when not declared(ASN1_LONG_UNDEF):
  when cast[clong](2147483647'i64) is static:
    const
      ASN1_LONG_UNDEF* = cast[clong](2147483647'i64) ## Generated based on /usr/include/openssl/asn1.h:208:10
  else:
    let ASN1_LONG_UNDEF* = cast[clong](2147483647'i64) ## Generated based on /usr/include/openssl/asn1.h:208:10
else:
  static :
    hint("Declaration of " & "ASN1_LONG_UNDEF" &
        " already exists, not redeclaring")
when not declared(STABLE_FLAGS_MALLOC):
  when 1 is static:
    const
      STABLE_FLAGS_MALLOC* = 1 ## Generated based on /usr/include/openssl/asn1.h:210:10
  else:
    let STABLE_FLAGS_MALLOC* = 1 ## Generated based on /usr/include/openssl/asn1.h:210:10
else:
  static :
    hint("Declaration of " & "STABLE_FLAGS_MALLOC" &
        " already exists, not redeclaring")
when not declared(STABLE_FLAGS_CLEAR):
  when STABLE_FLAGS_MALLOC is typedesc:
    type
      STABLE_FLAGS_CLEAR* = STABLE_FLAGS_MALLOC ## Generated based on /usr/include/openssl/asn1.h:217:10
  else:
    when STABLE_FLAGS_MALLOC is static:
      const
        STABLE_FLAGS_CLEAR* = STABLE_FLAGS_MALLOC ## Generated based on /usr/include/openssl/asn1.h:217:10
    else:
      let STABLE_FLAGS_CLEAR* = STABLE_FLAGS_MALLOC ## Generated based on /usr/include/openssl/asn1.h:217:10
else:
  static :
    hint("Declaration of " & "STABLE_FLAGS_CLEAR" &
        " already exists, not redeclaring")
when not declared(STABLE_NO_MASK):
  when 2 is static:
    const
      STABLE_NO_MASK* = 2    ## Generated based on /usr/include/openssl/asn1.h:218:10
  else:
    let STABLE_NO_MASK* = 2  ## Generated based on /usr/include/openssl/asn1.h:218:10
else:
  static :
    hint("Declaration of " & "STABLE_NO_MASK" &
        " already exists, not redeclaring")
when not declared(ub_name):
  when 32768 is static:
    const
      ub_name* = 32768       ## Generated based on /usr/include/openssl/asn1.h:261:10
  else:
    let ub_name* = 32768     ## Generated based on /usr/include/openssl/asn1.h:261:10
else:
  static :
    hint("Declaration of " & "ub_name" & " already exists, not redeclaring")
when not declared(ub_common_name):
  when 64 is static:
    const
      ub_common_name* = 64   ## Generated based on /usr/include/openssl/asn1.h:262:10
  else:
    let ub_common_name* = 64 ## Generated based on /usr/include/openssl/asn1.h:262:10
else:
  static :
    hint("Declaration of " & "ub_common_name" &
        " already exists, not redeclaring")
when not declared(ub_locality_name):
  when 128 is static:
    const
      ub_locality_name* = 128 ## Generated based on /usr/include/openssl/asn1.h:263:10
  else:
    let ub_locality_name* = 128 ## Generated based on /usr/include/openssl/asn1.h:263:10
else:
  static :
    hint("Declaration of " & "ub_locality_name" &
        " already exists, not redeclaring")
when not declared(ub_state_name):
  when 128 is static:
    const
      ub_state_name* = 128   ## Generated based on /usr/include/openssl/asn1.h:264:10
  else:
    let ub_state_name* = 128 ## Generated based on /usr/include/openssl/asn1.h:264:10
else:
  static :
    hint("Declaration of " & "ub_state_name" &
        " already exists, not redeclaring")
when not declared(ub_organization_name):
  when 64 is static:
    const
      ub_organization_name* = 64 ## Generated based on /usr/include/openssl/asn1.h:265:10
  else:
    let ub_organization_name* = 64 ## Generated based on /usr/include/openssl/asn1.h:265:10
else:
  static :
    hint("Declaration of " & "ub_organization_name" &
        " already exists, not redeclaring")
when not declared(ub_organization_unit_name):
  when 64 is static:
    const
      ub_organization_unit_name* = 64 ## Generated based on /usr/include/openssl/asn1.h:266:10
  else:
    let ub_organization_unit_name* = 64 ## Generated based on /usr/include/openssl/asn1.h:266:10
else:
  static :
    hint("Declaration of " & "ub_organization_unit_name" &
        " already exists, not redeclaring")
when not declared(ub_title):
  when 64 is static:
    const
      ub_title* = 64         ## Generated based on /usr/include/openssl/asn1.h:267:10
  else:
    let ub_title* = 64       ## Generated based on /usr/include/openssl/asn1.h:267:10
else:
  static :
    hint("Declaration of " & "ub_title" & " already exists, not redeclaring")
when not declared(ub_email_address):
  when 128 is static:
    const
      ub_email_address* = 128 ## Generated based on /usr/include/openssl/asn1.h:268:10
  else:
    let ub_email_address* = 128 ## Generated based on /usr/include/openssl/asn1.h:268:10
else:
  static :
    hint("Declaration of " & "ub_email_address" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_ESC_2253):
  when 1 is static:
    const
      ASN1_STRFLGS_ESC_2253* = 1 ## Generated based on /usr/include/openssl/asn1.h:437:10
  else:
    let ASN1_STRFLGS_ESC_2253* = 1 ## Generated based on /usr/include/openssl/asn1.h:437:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_ESC_2253" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_ESC_CTRL):
  when 2 is static:
    const
      ASN1_STRFLGS_ESC_CTRL* = 2 ## Generated based on /usr/include/openssl/asn1.h:438:10
  else:
    let ASN1_STRFLGS_ESC_CTRL* = 2 ## Generated based on /usr/include/openssl/asn1.h:438:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_ESC_CTRL" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_ESC_MSB):
  when 4 is static:
    const
      ASN1_STRFLGS_ESC_MSB* = 4 ## Generated based on /usr/include/openssl/asn1.h:439:10
  else:
    let ASN1_STRFLGS_ESC_MSB* = 4 ## Generated based on /usr/include/openssl/asn1.h:439:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_ESC_MSB" &
        " already exists, not redeclaring")
when not declared(ASN1_DTFLGS_TYPE_MASK):
  when cast[culong](15'i64) is static:
    const
      ASN1_DTFLGS_TYPE_MASK* = cast[culong](15'i64) ## Generated based on /usr/include/openssl/asn1.h:442:10
  else:
    let ASN1_DTFLGS_TYPE_MASK* = cast[culong](15'i64) ## Generated based on /usr/include/openssl/asn1.h:442:10
else:
  static :
    hint("Declaration of " & "ASN1_DTFLGS_TYPE_MASK" &
        " already exists, not redeclaring")
when not declared(ASN1_DTFLGS_RFC822):
  when cast[culong](0'i64) is static:
    const
      ASN1_DTFLGS_RFC822* = cast[culong](0'i64) ## Generated based on /usr/include/openssl/asn1.h:443:10
  else:
    let ASN1_DTFLGS_RFC822* = cast[culong](0'i64) ## Generated based on /usr/include/openssl/asn1.h:443:10
else:
  static :
    hint("Declaration of " & "ASN1_DTFLGS_RFC822" &
        " already exists, not redeclaring")
when not declared(ASN1_DTFLGS_ISO8601):
  when cast[culong](1'i64) is static:
    const
      ASN1_DTFLGS_ISO8601* = cast[culong](1'i64) ## Generated based on /usr/include/openssl/asn1.h:444:10
  else:
    let ASN1_DTFLGS_ISO8601* = cast[culong](1'i64) ## Generated based on /usr/include/openssl/asn1.h:444:10
else:
  static :
    hint("Declaration of " & "ASN1_DTFLGS_ISO8601" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_ESC_QUOTE):
  when 8 is static:
    const
      ASN1_STRFLGS_ESC_QUOTE* = 8 ## Generated based on /usr/include/openssl/asn1.h:451:10
  else:
    let ASN1_STRFLGS_ESC_QUOTE* = 8 ## Generated based on /usr/include/openssl/asn1.h:451:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_ESC_QUOTE" &
        " already exists, not redeclaring")
when not declared(CHARTYPE_PRINTABLESTRING):
  when 16 is static:
    const
      CHARTYPE_PRINTABLESTRING* = 16 ## Generated based on /usr/include/openssl/asn1.h:456:10
  else:
    let CHARTYPE_PRINTABLESTRING* = 16 ## Generated based on /usr/include/openssl/asn1.h:456:10
else:
  static :
    hint("Declaration of " & "CHARTYPE_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(CHARTYPE_FIRST_ESC_2253):
  when 32 is static:
    const
      CHARTYPE_FIRST_ESC_2253* = 32 ## Generated based on /usr/include/openssl/asn1.h:458:10
  else:
    let CHARTYPE_FIRST_ESC_2253* = 32 ## Generated based on /usr/include/openssl/asn1.h:458:10
else:
  static :
    hint("Declaration of " & "CHARTYPE_FIRST_ESC_2253" &
        " already exists, not redeclaring")
when not declared(CHARTYPE_LAST_ESC_2253):
  when 64 is static:
    const
      CHARTYPE_LAST_ESC_2253* = 64 ## Generated based on /usr/include/openssl/asn1.h:460:10
  else:
    let CHARTYPE_LAST_ESC_2253* = 64 ## Generated based on /usr/include/openssl/asn1.h:460:10
else:
  static :
    hint("Declaration of " & "CHARTYPE_LAST_ESC_2253" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_UTF8_CONVERT):
  when 16 is static:
    const
      ASN1_STRFLGS_UTF8_CONVERT* = 16 ## Generated based on /usr/include/openssl/asn1.h:471:10
  else:
    let ASN1_STRFLGS_UTF8_CONVERT* = 16 ## Generated based on /usr/include/openssl/asn1.h:471:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_UTF8_CONVERT" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_IGNORE_TYPE):
  when 32 is static:
    const
      ASN1_STRFLGS_IGNORE_TYPE* = 32 ## Generated based on /usr/include/openssl/asn1.h:479:10
  else:
    let ASN1_STRFLGS_IGNORE_TYPE* = 32 ## Generated based on /usr/include/openssl/asn1.h:479:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_IGNORE_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_SHOW_TYPE):
  when 64 is static:
    const
      ASN1_STRFLGS_SHOW_TYPE* = 64 ## Generated based on /usr/include/openssl/asn1.h:482:10
  else:
    let ASN1_STRFLGS_SHOW_TYPE* = 64 ## Generated based on /usr/include/openssl/asn1.h:482:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_SHOW_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_DUMP_ALL):
  when 128 is static:
    const
      ASN1_STRFLGS_DUMP_ALL* = 128 ## Generated based on /usr/include/openssl/asn1.h:492:10
  else:
    let ASN1_STRFLGS_DUMP_ALL* = 128 ## Generated based on /usr/include/openssl/asn1.h:492:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_DUMP_ALL" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_DUMP_UNKNOWN):
  when 256 is static:
    const
      ASN1_STRFLGS_DUMP_UNKNOWN* = 256 ## Generated based on /usr/include/openssl/asn1.h:493:10
  else:
    let ASN1_STRFLGS_DUMP_UNKNOWN* = 256 ## Generated based on /usr/include/openssl/asn1.h:493:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_DUMP_UNKNOWN" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_DUMP_DER):
  when 512 is static:
    const
      ASN1_STRFLGS_DUMP_DER* = 512 ## Generated based on /usr/include/openssl/asn1.h:500:10
  else:
    let ASN1_STRFLGS_DUMP_DER* = 512 ## Generated based on /usr/include/openssl/asn1.h:500:10
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_DUMP_DER" &
        " already exists, not redeclaring")
when not declared(ASN1_STRFLGS_ESC_2254):
  when 1024 is static:
    const
      ASN1_STRFLGS_ESC_2254* = 1024 ## Generated based on /usr/include/openssl/asn1.h:505:9
  else:
    let ASN1_STRFLGS_ESC_2254* = 1024 ## Generated based on /usr/include/openssl/asn1.h:505:9
else:
  static :
    hint("Declaration of " & "ASN1_STRFLGS_ESC_2254" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_SHOW_ABSENT):
  when 1 is static:
    const
      ASN1_PCTX_FLAGS_SHOW_ABSENT* = 1 ## Generated based on /usr/include/openssl/asn1.h:1045:10
  else:
    let ASN1_PCTX_FLAGS_SHOW_ABSENT* = 1 ## Generated based on /usr/include/openssl/asn1.h:1045:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_SHOW_ABSENT" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_SHOW_SEQUENCE):
  when 2 is static:
    const
      ASN1_PCTX_FLAGS_SHOW_SEQUENCE* = 2 ## Generated based on /usr/include/openssl/asn1.h:1047:10
  else:
    let ASN1_PCTX_FLAGS_SHOW_SEQUENCE* = 2 ## Generated based on /usr/include/openssl/asn1.h:1047:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_SHOW_SEQUENCE" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_SHOW_SSOF):
  when 4 is static:
    const
      ASN1_PCTX_FLAGS_SHOW_SSOF* = 4 ## Generated based on /usr/include/openssl/asn1.h:1049:10
  else:
    let ASN1_PCTX_FLAGS_SHOW_SSOF* = 4 ## Generated based on /usr/include/openssl/asn1.h:1049:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_SHOW_SSOF" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_SHOW_TYPE):
  when 8 is static:
    const
      ASN1_PCTX_FLAGS_SHOW_TYPE* = 8 ## Generated based on /usr/include/openssl/asn1.h:1051:10
  else:
    let ASN1_PCTX_FLAGS_SHOW_TYPE* = 8 ## Generated based on /usr/include/openssl/asn1.h:1051:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_SHOW_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_NO_ANY_TYPE):
  when 16 is static:
    const
      ASN1_PCTX_FLAGS_NO_ANY_TYPE* = 16 ## Generated based on /usr/include/openssl/asn1.h:1053:10
  else:
    let ASN1_PCTX_FLAGS_NO_ANY_TYPE* = 16 ## Generated based on /usr/include/openssl/asn1.h:1053:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_NO_ANY_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_NO_MSTRING_TYPE):
  when 32 is static:
    const
      ASN1_PCTX_FLAGS_NO_MSTRING_TYPE* = 32 ## Generated based on /usr/include/openssl/asn1.h:1055:10
  else:
    let ASN1_PCTX_FLAGS_NO_MSTRING_TYPE* = 32 ## Generated based on /usr/include/openssl/asn1.h:1055:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_NO_MSTRING_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_NO_FIELD_NAME):
  when 64 is static:
    const
      ASN1_PCTX_FLAGS_NO_FIELD_NAME* = 64 ## Generated based on /usr/include/openssl/asn1.h:1057:10
  else:
    let ASN1_PCTX_FLAGS_NO_FIELD_NAME* = 64 ## Generated based on /usr/include/openssl/asn1.h:1057:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_NO_FIELD_NAME" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME):
  when 128 is static:
    const
      ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME* = 128 ## Generated based on /usr/include/openssl/asn1.h:1059:10
  else:
    let ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME* = 128 ## Generated based on /usr/include/openssl/asn1.h:1059:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_FLAGS_NO_STRUCT_NAME):
  when 256 is static:
    const
      ASN1_PCTX_FLAGS_NO_STRUCT_NAME* = 256 ## Generated based on /usr/include/openssl/asn1.h:1061:10
  else:
    let ASN1_PCTX_FLAGS_NO_STRUCT_NAME* = 256 ## Generated based on /usr/include/openssl/asn1.h:1061:10
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_FLAGS_NO_STRUCT_NAME" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_ASN1_VERSION):
  when 1 is static:
    const
      SSL_SESSION_ASN1_VERSION* = 1 ## Generated based on /usr/include/openssl/ssl.h:55:10
  else:
    let SSL_SESSION_ASN1_VERSION* = 1 ## Generated based on /usr/include/openssl/ssl.h:55:10
else:
  static :
    hint("Declaration of " & "SSL_SESSION_ASN1_VERSION" &
        " already exists, not redeclaring")
when not declared(SSL_MAX_SSL_SESSION_ID_LENGTH):
  when 32 is static:
    const
      SSL_MAX_SSL_SESSION_ID_LENGTH* = 32 ## Generated based on /usr/include/openssl/ssl.h:57:10
  else:
    let SSL_MAX_SSL_SESSION_ID_LENGTH* = 32 ## Generated based on /usr/include/openssl/ssl.h:57:10
else:
  static :
    hint("Declaration of " & "SSL_MAX_SSL_SESSION_ID_LENGTH" &
        " already exists, not redeclaring")
when not declared(SSL_MAX_SID_CTX_LENGTH):
  when 32 is static:
    const
      SSL_MAX_SID_CTX_LENGTH* = 32 ## Generated based on /usr/include/openssl/ssl.h:58:10
  else:
    let SSL_MAX_SID_CTX_LENGTH* = 32 ## Generated based on /usr/include/openssl/ssl.h:58:10
else:
  static :
    hint("Declaration of " & "SSL_MAX_SID_CTX_LENGTH" &
        " already exists, not redeclaring")
when not declared(SSL_MAX_KEY_ARG_LENGTH):
  when 8 is static:
    const
      SSL_MAX_KEY_ARG_LENGTH* = 8 ## Generated based on /usr/include/openssl/ssl.h:61:10
  else:
    let SSL_MAX_KEY_ARG_LENGTH* = 8 ## Generated based on /usr/include/openssl/ssl.h:61:10
else:
  static :
    hint("Declaration of " & "SSL_MAX_KEY_ARG_LENGTH" &
        " already exists, not redeclaring")
when not declared(SSL_MAX_PIPELINES):
  when 32 is static:
    const
      SSL_MAX_PIPELINES* = 32 ## Generated based on /usr/include/openssl/ssl.h:65:10
  else:
    let SSL_MAX_PIPELINES* = 32 ## Generated based on /usr/include/openssl/ssl.h:65:10
else:
  static :
    hint("Declaration of " & "SSL_MAX_PIPELINES" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_LOW):
  when "LOW" is static:
    const
      SSL_TXT_LOW* = "LOW"   ## Generated based on /usr/include/openssl/ssl.h:71:10
  else:
    let SSL_TXT_LOW* = "LOW" ## Generated based on /usr/include/openssl/ssl.h:71:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_LOW" & " already exists, not redeclaring")
when not declared(SSL_TXT_MEDIUM):
  when "MEDIUM" is static:
    const
      SSL_TXT_MEDIUM* = "MEDIUM" ## Generated based on /usr/include/openssl/ssl.h:72:10
  else:
    let SSL_TXT_MEDIUM* = "MEDIUM" ## Generated based on /usr/include/openssl/ssl.h:72:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_MEDIUM" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_HIGH):
  when "HIGH" is static:
    const
      SSL_TXT_HIGH* = "HIGH" ## Generated based on /usr/include/openssl/ssl.h:73:10
  else:
    let SSL_TXT_HIGH* = "HIGH" ## Generated based on /usr/include/openssl/ssl.h:73:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_HIGH" & " already exists, not redeclaring")
when not declared(SSL_TXT_FIPS):
  when "FIPS" is static:
    const
      SSL_TXT_FIPS* = "FIPS" ## Generated based on /usr/include/openssl/ssl.h:74:10
  else:
    let SSL_TXT_FIPS* = "FIPS" ## Generated based on /usr/include/openssl/ssl.h:74:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_FIPS" & " already exists, not redeclaring")
when not declared(SSL_TXT_aNULL):
  when "aNULL" is static:
    const
      SSL_TXT_aNULL* = "aNULL" ## Generated based on /usr/include/openssl/ssl.h:76:10
  else:
    let SSL_TXT_aNULL* = "aNULL" ## Generated based on /usr/include/openssl/ssl.h:76:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aNULL" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_eNULL):
  when "eNULL" is static:
    const
      SSL_TXT_eNULL* = "eNULL" ## Generated based on /usr/include/openssl/ssl.h:77:10
  else:
    let SSL_TXT_eNULL* = "eNULL" ## Generated based on /usr/include/openssl/ssl.h:77:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_eNULL" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_NULL):
  when "NULL" is static:
    const
      SSL_TXT_NULL* = "NULL" ## Generated based on /usr/include/openssl/ssl.h:78:10
  else:
    let SSL_TXT_NULL* = "NULL" ## Generated based on /usr/include/openssl/ssl.h:78:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_NULL" & " already exists, not redeclaring")
when not declared(SSL_TXT_kRSA):
  when "kRSA" is static:
    const
      SSL_TXT_kRSA* = "kRSA" ## Generated based on /usr/include/openssl/ssl.h:80:10
  else:
    let SSL_TXT_kRSA* = "kRSA" ## Generated based on /usr/include/openssl/ssl.h:80:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kRSA" & " already exists, not redeclaring")
when not declared(SSL_TXT_kDHr):
  when "kDHr" is static:
    const
      SSL_TXT_kDHr* = "kDHr" ## Generated based on /usr/include/openssl/ssl.h:81:10
  else:
    let SSL_TXT_kDHr* = "kDHr" ## Generated based on /usr/include/openssl/ssl.h:81:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kDHr" & " already exists, not redeclaring")
when not declared(SSL_TXT_kDHd):
  when "kDHd" is static:
    const
      SSL_TXT_kDHd* = "kDHd" ## Generated based on /usr/include/openssl/ssl.h:82:10
  else:
    let SSL_TXT_kDHd* = "kDHd" ## Generated based on /usr/include/openssl/ssl.h:82:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kDHd" & " already exists, not redeclaring")
when not declared(SSL_TXT_kDH):
  when "kDH" is static:
    const
      SSL_TXT_kDH* = "kDH"   ## Generated based on /usr/include/openssl/ssl.h:83:10
  else:
    let SSL_TXT_kDH* = "kDH" ## Generated based on /usr/include/openssl/ssl.h:83:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kDH" & " already exists, not redeclaring")
when not declared(SSL_TXT_kEDH):
  when "kEDH" is static:
    const
      SSL_TXT_kEDH* = "kEDH" ## Generated based on /usr/include/openssl/ssl.h:84:10
  else:
    let SSL_TXT_kEDH* = "kEDH" ## Generated based on /usr/include/openssl/ssl.h:84:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kEDH" & " already exists, not redeclaring")
when not declared(SSL_TXT_kDHE):
  when "kDHE" is static:
    const
      SSL_TXT_kDHE* = "kDHE" ## Generated based on /usr/include/openssl/ssl.h:85:10
  else:
    let SSL_TXT_kDHE* = "kDHE" ## Generated based on /usr/include/openssl/ssl.h:85:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kDHE" & " already exists, not redeclaring")
when not declared(SSL_TXT_kECDHr):
  when "kECDHr" is static:
    const
      SSL_TXT_kECDHr* = "kECDHr" ## Generated based on /usr/include/openssl/ssl.h:86:10
  else:
    let SSL_TXT_kECDHr* = "kECDHr" ## Generated based on /usr/include/openssl/ssl.h:86:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kECDHr" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kECDHe):
  when "kECDHe" is static:
    const
      SSL_TXT_kECDHe* = "kECDHe" ## Generated based on /usr/include/openssl/ssl.h:87:10
  else:
    let SSL_TXT_kECDHe* = "kECDHe" ## Generated based on /usr/include/openssl/ssl.h:87:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kECDHe" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kECDH):
  when "kECDH" is static:
    const
      SSL_TXT_kECDH* = "kECDH" ## Generated based on /usr/include/openssl/ssl.h:88:10
  else:
    let SSL_TXT_kECDH* = "kECDH" ## Generated based on /usr/include/openssl/ssl.h:88:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kECDH" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kEECDH):
  when "kEECDH" is static:
    const
      SSL_TXT_kEECDH* = "kEECDH" ## Generated based on /usr/include/openssl/ssl.h:89:10
  else:
    let SSL_TXT_kEECDH* = "kEECDH" ## Generated based on /usr/include/openssl/ssl.h:89:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kEECDH" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kECDHE_const):
  when "kECDHE" is static:
    const
      SSL_TXT_kECDHE_const* = "kECDHE" ## Generated based on /usr/include/openssl/ssl.h:90:10
  else:
    let SSL_TXT_kECDHE_const* = "kECDHE" ## Generated based on /usr/include/openssl/ssl.h:90:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kECDHE_const" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kPSK):
  when "kPSK" is static:
    const
      SSL_TXT_kPSK* = "kPSK" ## Generated based on /usr/include/openssl/ssl.h:91:10
  else:
    let SSL_TXT_kPSK* = "kPSK" ## Generated based on /usr/include/openssl/ssl.h:91:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kPSK" & " already exists, not redeclaring")
when not declared(SSL_TXT_kRSAPSK):
  when "kRSAPSK" is static:
    const
      SSL_TXT_kRSAPSK* = "kRSAPSK" ## Generated based on /usr/include/openssl/ssl.h:92:10
  else:
    let SSL_TXT_kRSAPSK* = "kRSAPSK" ## Generated based on /usr/include/openssl/ssl.h:92:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kRSAPSK" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kECDHEPSK):
  when "kECDHEPSK" is static:
    const
      SSL_TXT_kECDHEPSK* = "kECDHEPSK" ## Generated based on /usr/include/openssl/ssl.h:93:10
  else:
    let SSL_TXT_kECDHEPSK* = "kECDHEPSK" ## Generated based on /usr/include/openssl/ssl.h:93:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kECDHEPSK" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kDHEPSK):
  when "kDHEPSK" is static:
    const
      SSL_TXT_kDHEPSK* = "kDHEPSK" ## Generated based on /usr/include/openssl/ssl.h:94:10
  else:
    let SSL_TXT_kDHEPSK* = "kDHEPSK" ## Generated based on /usr/include/openssl/ssl.h:94:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kDHEPSK" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kGOST):
  when "kGOST" is static:
    const
      SSL_TXT_kGOST* = "kGOST" ## Generated based on /usr/include/openssl/ssl.h:95:10
  else:
    let SSL_TXT_kGOST* = "kGOST" ## Generated based on /usr/include/openssl/ssl.h:95:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kGOST" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kGOST18):
  when "kGOST18" is static:
    const
      SSL_TXT_kGOST18* = "kGOST18" ## Generated based on /usr/include/openssl/ssl.h:96:10
  else:
    let SSL_TXT_kGOST18* = "kGOST18" ## Generated based on /usr/include/openssl/ssl.h:96:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kGOST18" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_kSRP):
  when "kSRP" is static:
    const
      SSL_TXT_kSRP* = "kSRP" ## Generated based on /usr/include/openssl/ssl.h:97:10
  else:
    let SSL_TXT_kSRP* = "kSRP" ## Generated based on /usr/include/openssl/ssl.h:97:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_kSRP" & " already exists, not redeclaring")
when not declared(SSL_TXT_aRSA):
  when "aRSA" is static:
    const
      SSL_TXT_aRSA* = "aRSA" ## Generated based on /usr/include/openssl/ssl.h:99:10
  else:
    let SSL_TXT_aRSA* = "aRSA" ## Generated based on /usr/include/openssl/ssl.h:99:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aRSA" & " already exists, not redeclaring")
when not declared(SSL_TXT_aDSS):
  when "aDSS" is static:
    const
      SSL_TXT_aDSS* = "aDSS" ## Generated based on /usr/include/openssl/ssl.h:100:10
  else:
    let SSL_TXT_aDSS* = "aDSS" ## Generated based on /usr/include/openssl/ssl.h:100:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aDSS" & " already exists, not redeclaring")
when not declared(SSL_TXT_aDH):
  when "aDH" is static:
    const
      SSL_TXT_aDH* = "aDH"   ## Generated based on /usr/include/openssl/ssl.h:101:10
  else:
    let SSL_TXT_aDH* = "aDH" ## Generated based on /usr/include/openssl/ssl.h:101:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aDH" & " already exists, not redeclaring")
when not declared(SSL_TXT_aECDH):
  when "aECDH" is static:
    const
      SSL_TXT_aECDH* = "aECDH" ## Generated based on /usr/include/openssl/ssl.h:102:10
  else:
    let SSL_TXT_aECDH* = "aECDH" ## Generated based on /usr/include/openssl/ssl.h:102:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aECDH" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aECDSA):
  when "aECDSA" is static:
    const
      SSL_TXT_aECDSA* = "aECDSA" ## Generated based on /usr/include/openssl/ssl.h:103:10
  else:
    let SSL_TXT_aECDSA* = "aECDSA" ## Generated based on /usr/include/openssl/ssl.h:103:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aECDSA" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aPSK):
  when "aPSK" is static:
    const
      SSL_TXT_aPSK* = "aPSK" ## Generated based on /usr/include/openssl/ssl.h:104:10
  else:
    let SSL_TXT_aPSK* = "aPSK" ## Generated based on /usr/include/openssl/ssl.h:104:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aPSK" & " already exists, not redeclaring")
when not declared(SSL_TXT_aGOST94):
  when "aGOST94" is static:
    const
      SSL_TXT_aGOST94* = "aGOST94" ## Generated based on /usr/include/openssl/ssl.h:105:10
  else:
    let SSL_TXT_aGOST94* = "aGOST94" ## Generated based on /usr/include/openssl/ssl.h:105:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aGOST94" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aGOST01):
  when "aGOST01" is static:
    const
      SSL_TXT_aGOST01* = "aGOST01" ## Generated based on /usr/include/openssl/ssl.h:106:10
  else:
    let SSL_TXT_aGOST01* = "aGOST01" ## Generated based on /usr/include/openssl/ssl.h:106:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aGOST01" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aGOST12):
  when "aGOST12" is static:
    const
      SSL_TXT_aGOST12* = "aGOST12" ## Generated based on /usr/include/openssl/ssl.h:107:10
  else:
    let SSL_TXT_aGOST12* = "aGOST12" ## Generated based on /usr/include/openssl/ssl.h:107:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aGOST12" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aGOST):
  when "aGOST" is static:
    const
      SSL_TXT_aGOST* = "aGOST" ## Generated based on /usr/include/openssl/ssl.h:108:10
  else:
    let SSL_TXT_aGOST* = "aGOST" ## Generated based on /usr/include/openssl/ssl.h:108:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aGOST" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_aSRP):
  when "aSRP" is static:
    const
      SSL_TXT_aSRP* = "aSRP" ## Generated based on /usr/include/openssl/ssl.h:109:10
  else:
    let SSL_TXT_aSRP* = "aSRP" ## Generated based on /usr/include/openssl/ssl.h:109:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_aSRP" & " already exists, not redeclaring")
when not declared(SSL_TXT_DSS):
  when "DSS" is static:
    const
      SSL_TXT_DSS* = "DSS"   ## Generated based on /usr/include/openssl/ssl.h:111:10
  else:
    let SSL_TXT_DSS* = "DSS" ## Generated based on /usr/include/openssl/ssl.h:111:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_DSS" & " already exists, not redeclaring")
when not declared(SSL_TXT_DH):
  when "DH" is static:
    const
      SSL_TXT_DH* = "DH"     ## Generated based on /usr/include/openssl/ssl.h:112:10
  else:
    let SSL_TXT_DH* = "DH"   ## Generated based on /usr/include/openssl/ssl.h:112:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_DH" & " already exists, not redeclaring")
when not declared(SSL_TXT_DHE):
  when "DHE" is static:
    const
      SSL_TXT_DHE* = "DHE"   ## Generated based on /usr/include/openssl/ssl.h:113:10
  else:
    let SSL_TXT_DHE* = "DHE" ## Generated based on /usr/include/openssl/ssl.h:113:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_DHE" & " already exists, not redeclaring")
when not declared(SSL_TXT_EDH):
  when "EDH" is static:
    const
      SSL_TXT_EDH* = "EDH"   ## Generated based on /usr/include/openssl/ssl.h:114:10
  else:
    let SSL_TXT_EDH* = "EDH" ## Generated based on /usr/include/openssl/ssl.h:114:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_EDH" & " already exists, not redeclaring")
when not declared(SSL_TXT_ADH_const):
  when "ADH" is static:
    const
      SSL_TXT_ADH_const* = "ADH" ## Generated based on /usr/include/openssl/ssl.h:115:10
  else:
    let SSL_TXT_ADH_const* = "ADH" ## Generated based on /usr/include/openssl/ssl.h:115:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ADH_const" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_RSA):
  when "RSA" is static:
    const
      SSL_TXT_RSA* = "RSA"   ## Generated based on /usr/include/openssl/ssl.h:116:10
  else:
    let SSL_TXT_RSA* = "RSA" ## Generated based on /usr/include/openssl/ssl.h:116:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_RSA" & " already exists, not redeclaring")
when not declared(SSL_TXT_ECDH):
  when "ECDH" is static:
    const
      SSL_TXT_ECDH* = "ECDH" ## Generated based on /usr/include/openssl/ssl.h:117:10
  else:
    let SSL_TXT_ECDH* = "ECDH" ## Generated based on /usr/include/openssl/ssl.h:117:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ECDH" & " already exists, not redeclaring")
when not declared(SSL_TXT_EECDH):
  when "EECDH" is static:
    const
      SSL_TXT_EECDH* = "EECDH" ## Generated based on /usr/include/openssl/ssl.h:118:10
  else:
    let SSL_TXT_EECDH* = "EECDH" ## Generated based on /usr/include/openssl/ssl.h:118:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_EECDH" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_ECDHE):
  when "ECDHE" is static:
    const
      SSL_TXT_ECDHE* = "ECDHE" ## Generated based on /usr/include/openssl/ssl.h:119:10
  else:
    let SSL_TXT_ECDHE* = "ECDHE" ## Generated based on /usr/include/openssl/ssl.h:119:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ECDHE" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_AECDH_const):
  when "AECDH" is static:
    const
      SSL_TXT_AECDH_const* = "AECDH" ## Generated based on /usr/include/openssl/ssl.h:120:10
  else:
    let SSL_TXT_AECDH_const* = "AECDH" ## Generated based on /usr/include/openssl/ssl.h:120:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AECDH_const" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_ECDSA):
  when "ECDSA" is static:
    const
      SSL_TXT_ECDSA* = "ECDSA" ## Generated based on /usr/include/openssl/ssl.h:121:10
  else:
    let SSL_TXT_ECDSA* = "ECDSA" ## Generated based on /usr/include/openssl/ssl.h:121:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ECDSA" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_PSK):
  when "PSK" is static:
    const
      SSL_TXT_PSK* = "PSK"   ## Generated based on /usr/include/openssl/ssl.h:122:10
  else:
    let SSL_TXT_PSK* = "PSK" ## Generated based on /usr/include/openssl/ssl.h:122:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_PSK" & " already exists, not redeclaring")
when not declared(SSL_TXT_SRP):
  when "SRP" is static:
    const
      SSL_TXT_SRP* = "SRP"   ## Generated based on /usr/include/openssl/ssl.h:123:10
  else:
    let SSL_TXT_SRP* = "SRP" ## Generated based on /usr/include/openssl/ssl.h:123:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SRP" & " already exists, not redeclaring")
when not declared(SSL_TXT_DES):
  when "DES" is static:
    const
      SSL_TXT_DES* = "DES"   ## Generated based on /usr/include/openssl/ssl.h:125:10
  else:
    let SSL_TXT_DES* = "DES" ## Generated based on /usr/include/openssl/ssl.h:125:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_DES" & " already exists, not redeclaring")
when not declared(SSL_TXT_3DES):
  when "3DES" is static:
    const
      SSL_TXT_3DES* = "3DES" ## Generated based on /usr/include/openssl/ssl.h:126:10
  else:
    let SSL_TXT_3DES* = "3DES" ## Generated based on /usr/include/openssl/ssl.h:126:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_3DES" & " already exists, not redeclaring")
when not declared(SSL_TXT_RC4):
  when "RC4" is static:
    const
      SSL_TXT_RC4* = "RC4"   ## Generated based on /usr/include/openssl/ssl.h:127:10
  else:
    let SSL_TXT_RC4* = "RC4" ## Generated based on /usr/include/openssl/ssl.h:127:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_RC4" & " already exists, not redeclaring")
when not declared(SSL_TXT_RC2):
  when "RC2" is static:
    const
      SSL_TXT_RC2* = "RC2"   ## Generated based on /usr/include/openssl/ssl.h:128:10
  else:
    let SSL_TXT_RC2* = "RC2" ## Generated based on /usr/include/openssl/ssl.h:128:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_RC2" & " already exists, not redeclaring")
when not declared(SSL_TXT_IDEA):
  when "IDEA" is static:
    const
      SSL_TXT_IDEA* = "IDEA" ## Generated based on /usr/include/openssl/ssl.h:129:10
  else:
    let SSL_TXT_IDEA* = "IDEA" ## Generated based on /usr/include/openssl/ssl.h:129:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_IDEA" & " already exists, not redeclaring")
when not declared(SSL_TXT_SEED):
  when "SEED" is static:
    const
      SSL_TXT_SEED* = "SEED" ## Generated based on /usr/include/openssl/ssl.h:130:10
  else:
    let SSL_TXT_SEED* = "SEED" ## Generated based on /usr/include/openssl/ssl.h:130:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SEED" & " already exists, not redeclaring")
when not declared(SSL_TXT_AES128):
  when "AES128" is static:
    const
      SSL_TXT_AES128* = "AES128" ## Generated based on /usr/include/openssl/ssl.h:131:10
  else:
    let SSL_TXT_AES128* = "AES128" ## Generated based on /usr/include/openssl/ssl.h:131:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES128" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_AES256):
  when "AES256" is static:
    const
      SSL_TXT_AES256* = "AES256" ## Generated based on /usr/include/openssl/ssl.h:132:10
  else:
    let SSL_TXT_AES256* = "AES256" ## Generated based on /usr/include/openssl/ssl.h:132:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES256" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_AES):
  when "AES" is static:
    const
      SSL_TXT_AES* = "AES"   ## Generated based on /usr/include/openssl/ssl.h:133:10
  else:
    let SSL_TXT_AES* = "AES" ## Generated based on /usr/include/openssl/ssl.h:133:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES" & " already exists, not redeclaring")
when not declared(SSL_TXT_AES_GCM):
  when "AESGCM" is static:
    const
      SSL_TXT_AES_GCM* = "AESGCM" ## Generated based on /usr/include/openssl/ssl.h:134:10
  else:
    let SSL_TXT_AES_GCM* = "AESGCM" ## Generated based on /usr/include/openssl/ssl.h:134:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES_GCM" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_AES_CCM):
  when "AESCCM" is static:
    const
      SSL_TXT_AES_CCM* = "AESCCM" ## Generated based on /usr/include/openssl/ssl.h:135:10
  else:
    let SSL_TXT_AES_CCM* = "AESCCM" ## Generated based on /usr/include/openssl/ssl.h:135:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES_CCM" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_AES_CCM_8):
  when "AESCCM8" is static:
    const
      SSL_TXT_AES_CCM_8* = "AESCCM8" ## Generated based on /usr/include/openssl/ssl.h:136:10
  else:
    let SSL_TXT_AES_CCM_8* = "AESCCM8" ## Generated based on /usr/include/openssl/ssl.h:136:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_AES_CCM_8" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CAMELLIA128):
  when "CAMELLIA128" is static:
    const
      SSL_TXT_CAMELLIA128* = "CAMELLIA128" ## Generated based on /usr/include/openssl/ssl.h:137:10
  else:
    let SSL_TXT_CAMELLIA128* = "CAMELLIA128" ## Generated based on /usr/include/openssl/ssl.h:137:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CAMELLIA128" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CAMELLIA256):
  when "CAMELLIA256" is static:
    const
      SSL_TXT_CAMELLIA256* = "CAMELLIA256" ## Generated based on /usr/include/openssl/ssl.h:138:10
  else:
    let SSL_TXT_CAMELLIA256* = "CAMELLIA256" ## Generated based on /usr/include/openssl/ssl.h:138:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CAMELLIA256" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CAMELLIA):
  when "CAMELLIA" is static:
    const
      SSL_TXT_CAMELLIA* = "CAMELLIA" ## Generated based on /usr/include/openssl/ssl.h:139:10
  else:
    let SSL_TXT_CAMELLIA* = "CAMELLIA" ## Generated based on /usr/include/openssl/ssl.h:139:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CAMELLIA" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CHACHA20):
  when "CHACHA20" is static:
    const
      SSL_TXT_CHACHA20* = "CHACHA20" ## Generated based on /usr/include/openssl/ssl.h:140:10
  else:
    let SSL_TXT_CHACHA20* = "CHACHA20" ## Generated based on /usr/include/openssl/ssl.h:140:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CHACHA20" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_GOST):
  when "GOST89" is static:
    const
      SSL_TXT_GOST* = "GOST89" ## Generated based on /usr/include/openssl/ssl.h:141:10
  else:
    let SSL_TXT_GOST* = "GOST89" ## Generated based on /usr/include/openssl/ssl.h:141:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST" & " already exists, not redeclaring")
when not declared(SSL_TXT_ARIA):
  when "ARIA" is static:
    const
      SSL_TXT_ARIA* = "ARIA" ## Generated based on /usr/include/openssl/ssl.h:142:10
  else:
    let SSL_TXT_ARIA* = "ARIA" ## Generated based on /usr/include/openssl/ssl.h:142:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ARIA" & " already exists, not redeclaring")
when not declared(SSL_TXT_ARIA_GCM):
  when "ARIAGCM" is static:
    const
      SSL_TXT_ARIA_GCM* = "ARIAGCM" ## Generated based on /usr/include/openssl/ssl.h:143:10
  else:
    let SSL_TXT_ARIA_GCM* = "ARIAGCM" ## Generated based on /usr/include/openssl/ssl.h:143:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ARIA_GCM" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_ARIA128):
  when "ARIA128" is static:
    const
      SSL_TXT_ARIA128* = "ARIA128" ## Generated based on /usr/include/openssl/ssl.h:144:10
  else:
    let SSL_TXT_ARIA128* = "ARIA128" ## Generated based on /usr/include/openssl/ssl.h:144:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ARIA128" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_ARIA256):
  when "ARIA256" is static:
    const
      SSL_TXT_ARIA256* = "ARIA256" ## Generated based on /usr/include/openssl/ssl.h:145:10
  else:
    let SSL_TXT_ARIA256* = "ARIA256" ## Generated based on /usr/include/openssl/ssl.h:145:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ARIA256" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_GOST2012_GOST8912_GOST8912):
  when "GOST2012-GOST8912-GOST8912" is static:
    const
      SSL_TXT_GOST2012_GOST8912_GOST8912* = "GOST2012-GOST8912-GOST8912" ## Generated based on /usr/include/openssl/ssl.h:146:10
  else:
    let SSL_TXT_GOST2012_GOST8912_GOST8912* = "GOST2012-GOST8912-GOST8912" ## Generated based on /usr/include/openssl/ssl.h:146:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST2012_GOST8912_GOST8912" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CBC):
  when "CBC" is static:
    const
      SSL_TXT_CBC* = "CBC"   ## Generated based on /usr/include/openssl/ssl.h:147:10
  else:
    let SSL_TXT_CBC* = "CBC" ## Generated based on /usr/include/openssl/ssl.h:147:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CBC" & " already exists, not redeclaring")
when not declared(SSL_TXT_MD5):
  when "MD5" is static:
    const
      SSL_TXT_MD5* = "MD5"   ## Generated based on /usr/include/openssl/ssl.h:149:10
  else:
    let SSL_TXT_MD5* = "MD5" ## Generated based on /usr/include/openssl/ssl.h:149:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_MD5" & " already exists, not redeclaring")
when not declared(SSL_TXT_SHA1):
  when "SHA1" is static:
    const
      SSL_TXT_SHA1* = "SHA1" ## Generated based on /usr/include/openssl/ssl.h:150:10
  else:
    let SSL_TXT_SHA1* = "SHA1" ## Generated based on /usr/include/openssl/ssl.h:150:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SHA1" & " already exists, not redeclaring")
when not declared(SSL_TXT_SHA):
  when "SHA" is static:
    const
      SSL_TXT_SHA* = "SHA"   ## Generated based on /usr/include/openssl/ssl.h:151:10
  else:
    let SSL_TXT_SHA* = "SHA" ## Generated based on /usr/include/openssl/ssl.h:151:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SHA" & " already exists, not redeclaring")
when not declared(SSL_TXT_GOST94):
  when "GOST94" is static:
    const
      SSL_TXT_GOST94* = "GOST94" ## Generated based on /usr/include/openssl/ssl.h:152:10
  else:
    let SSL_TXT_GOST94* = "GOST94" ## Generated based on /usr/include/openssl/ssl.h:152:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST94" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_GOST89MAC):
  when "GOST89MAC" is static:
    const
      SSL_TXT_GOST89MAC* = "GOST89MAC" ## Generated based on /usr/include/openssl/ssl.h:153:10
  else:
    let SSL_TXT_GOST89MAC* = "GOST89MAC" ## Generated based on /usr/include/openssl/ssl.h:153:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST89MAC" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_GOST12):
  when "GOST12" is static:
    const
      SSL_TXT_GOST12* = "GOST12" ## Generated based on /usr/include/openssl/ssl.h:154:10
  else:
    let SSL_TXT_GOST12* = "GOST12" ## Generated based on /usr/include/openssl/ssl.h:154:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST12" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_GOST89MAC12):
  when "GOST89MAC12" is static:
    const
      SSL_TXT_GOST89MAC12* = "GOST89MAC12" ## Generated based on /usr/include/openssl/ssl.h:155:10
  else:
    let SSL_TXT_GOST89MAC12* = "GOST89MAC12" ## Generated based on /usr/include/openssl/ssl.h:155:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_GOST89MAC12" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_SHA256):
  when "SHA256" is static:
    const
      SSL_TXT_SHA256* = "SHA256" ## Generated based on /usr/include/openssl/ssl.h:156:10
  else:
    let SSL_TXT_SHA256* = "SHA256" ## Generated based on /usr/include/openssl/ssl.h:156:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SHA256" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_SHA384):
  when "SHA384" is static:
    const
      SSL_TXT_SHA384* = "SHA384" ## Generated based on /usr/include/openssl/ssl.h:157:10
  else:
    let SSL_TXT_SHA384* = "SHA384" ## Generated based on /usr/include/openssl/ssl.h:157:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SHA384" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_SSLV3):
  when "SSLv3" is static:
    const
      SSL_TXT_SSLV3* = "SSLv3" ## Generated based on /usr/include/openssl/ssl.h:159:10
  else:
    let SSL_TXT_SSLV3* = "SSLv3" ## Generated based on /usr/include/openssl/ssl.h:159:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_SSLV3" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_TLSV1):
  when "TLSv1" is static:
    const
      SSL_TXT_TLSV1* = "TLSv1" ## Generated based on /usr/include/openssl/ssl.h:160:10
  else:
    let SSL_TXT_TLSV1* = "TLSv1" ## Generated based on /usr/include/openssl/ssl.h:160:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_TLSV1" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_TLSV1_1):
  when "TLSv1.1" is static:
    const
      SSL_TXT_TLSV1_1* = "TLSv1.1" ## Generated based on /usr/include/openssl/ssl.h:161:10
  else:
    let SSL_TXT_TLSV1_1* = "TLSv1.1" ## Generated based on /usr/include/openssl/ssl.h:161:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_TLSV1_1" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_TLSV1_2):
  when "TLSv1.2" is static:
    const
      SSL_TXT_TLSV1_2* = "TLSv1.2" ## Generated based on /usr/include/openssl/ssl.h:162:10
  else:
    let SSL_TXT_TLSV1_2* = "TLSv1.2" ## Generated based on /usr/include/openssl/ssl.h:162:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_TLSV1_2" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_ALL):
  when "ALL" is static:
    const
      SSL_TXT_ALL* = "ALL"   ## Generated based on /usr/include/openssl/ssl.h:164:10
  else:
    let SSL_TXT_ALL* = "ALL" ## Generated based on /usr/include/openssl/ssl.h:164:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_ALL" & " already exists, not redeclaring")
when not declared(SSL_TXT_CMPALL):
  when "COMPLEMENTOFALL" is static:
    const
      SSL_TXT_CMPALL* = "COMPLEMENTOFALL" ## Generated based on /usr/include/openssl/ssl.h:180:10
  else:
    let SSL_TXT_CMPALL* = "COMPLEMENTOFALL" ## Generated based on /usr/include/openssl/ssl.h:180:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CMPALL" &
        " already exists, not redeclaring")
when not declared(SSL_TXT_CMPDEF):
  when "COMPLEMENTOFDEFAULT" is static:
    const
      SSL_TXT_CMPDEF* = "COMPLEMENTOFDEFAULT" ## Generated based on /usr/include/openssl/ssl.h:181:10
  else:
    let SSL_TXT_CMPDEF* = "COMPLEMENTOFDEFAULT" ## Generated based on /usr/include/openssl/ssl.h:181:10
else:
  static :
    hint("Declaration of " & "SSL_TXT_CMPDEF" &
        " already exists, not redeclaring")
when not declared(SSL_DEFAULT_CIPHER_LIST):
  when "ALL:!COMPLEMENTOFDEFAULT:!eNULL" is static:
    const
      SSL_DEFAULT_CIPHER_LIST* = "ALL:!COMPLEMENTOFDEFAULT:!eNULL" ## Generated based on /usr/include/openssl/ssl.h:191:11
  else:
    let SSL_DEFAULT_CIPHER_LIST* = "ALL:!COMPLEMENTOFDEFAULT:!eNULL" ## Generated based on /usr/include/openssl/ssl.h:191:11
else:
  static :
    hint("Declaration of " & "SSL_DEFAULT_CIPHER_LIST" &
        " already exists, not redeclaring")
when not declared(TLS_DEFAULT_CIPHERSUITES):
  when "TLS_AES_256_GCM_SHA384:\" \\\n                                   \"TLS_CHACHA20_POLY1305_SHA256:\" \\\n                                   \"TLS_AES_128_GCM_SHA256" is
      static:
    const
      TLS_DEFAULT_CIPHERSUITES* = "TLS_AES_256_GCM_SHA384:\" \\\n                                   \"TLS_CHACHA20_POLY1305_SHA256:\" \\\n                                   \"TLS_AES_128_GCM_SHA256" ## Generated based on /usr/include/openssl/ssl.h:197:11
  else:
    let TLS_DEFAULT_CIPHERSUITES* = "TLS_AES_256_GCM_SHA384:\" \\\n                                   \"TLS_CHACHA20_POLY1305_SHA256:\" \\\n                                   \"TLS_AES_128_GCM_SHA256" ## Generated based on /usr/include/openssl/ssl.h:197:11
else:
  static :
    hint("Declaration of " & "TLS_DEFAULT_CIPHERSUITES" &
        " already exists, not redeclaring")
when not declared(SSL_SENT_SHUTDOWN):
  when 1 is static:
    const
      SSL_SENT_SHUTDOWN* = 1 ## Generated based on /usr/include/openssl/ssl.h:209:10
  else:
    let SSL_SENT_SHUTDOWN* = 1 ## Generated based on /usr/include/openssl/ssl.h:209:10
else:
  static :
    hint("Declaration of " & "SSL_SENT_SHUTDOWN" &
        " already exists, not redeclaring")
when not declared(SSL_RECEIVED_SHUTDOWN):
  when 2 is static:
    const
      SSL_RECEIVED_SHUTDOWN* = 2 ## Generated based on /usr/include/openssl/ssl.h:210:10
  else:
    let SSL_RECEIVED_SHUTDOWN* = 2 ## Generated based on /usr/include/openssl/ssl.h:210:10
else:
  static :
    hint("Declaration of " & "SSL_RECEIVED_SHUTDOWN" &
        " already exists, not redeclaring")
when not declared(X509_FILETYPE_ASN1):
  when 2 is static:
    const
      X509_FILETYPE_ASN1* = 2 ## Generated based on /usr/include/openssl/x509.h:162:10
  else:
    let X509_FILETYPE_ASN1* = 2 ## Generated based on /usr/include/openssl/x509.h:162:10
else:
  static :
    hint("Declaration of " & "X509_FILETYPE_ASN1" &
        " already exists, not redeclaring")
when not declared(X509_FILETYPE_PEM):
  when 1 is static:
    const
      X509_FILETYPE_PEM* = 1 ## Generated based on /usr/include/openssl/x509.h:161:10
  else:
    let X509_FILETYPE_PEM* = 1 ## Generated based on /usr/include/openssl/x509.h:161:10
else:
  static :
    hint("Declaration of " & "X509_FILETYPE_PEM" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS_ONLY):
  when 1 is static:
    const
      SSL_EXT_TLS_ONLY* = 1  ## Generated based on /usr/include/openssl/ssl.h:281:9
  else:
    let SSL_EXT_TLS_ONLY* = 1 ## Generated based on /usr/include/openssl/ssl.h:281:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_DTLS_ONLY):
  when 2 is static:
    const
      SSL_EXT_DTLS_ONLY* = 2 ## Generated based on /usr/include/openssl/ssl.h:283:9
  else:
    let SSL_EXT_DTLS_ONLY* = 2 ## Generated based on /usr/include/openssl/ssl.h:283:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_DTLS_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS_IMPLEMENTATION_ONLY):
  when 4 is static:
    const
      SSL_EXT_TLS_IMPLEMENTATION_ONLY* = 4 ## Generated based on /usr/include/openssl/ssl.h:285:9
  else:
    let SSL_EXT_TLS_IMPLEMENTATION_ONLY* = 4 ## Generated based on /usr/include/openssl/ssl.h:285:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS_IMPLEMENTATION_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_SSL3_ALLOWED):
  when 8 is static:
    const
      SSL_EXT_SSL3_ALLOWED* = 8 ## Generated based on /usr/include/openssl/ssl.h:287:9
  else:
    let SSL_EXT_SSL3_ALLOWED* = 8 ## Generated based on /usr/include/openssl/ssl.h:287:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_SSL3_ALLOWED" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_2_AND_BELOW_ONLY):
  when 16 is static:
    const
      SSL_EXT_TLS1_2_AND_BELOW_ONLY* = 16 ## Generated based on /usr/include/openssl/ssl.h:289:9
  else:
    let SSL_EXT_TLS1_2_AND_BELOW_ONLY* = 16 ## Generated based on /usr/include/openssl/ssl.h:289:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_2_AND_BELOW_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_ONLY):
  when 32 is static:
    const
      SSL_EXT_TLS1_3_ONLY* = 32 ## Generated based on /usr/include/openssl/ssl.h:291:9
  else:
    let SSL_EXT_TLS1_3_ONLY* = 32 ## Generated based on /usr/include/openssl/ssl.h:291:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_IGNORE_ON_RESUMPTION):
  when 64 is static:
    const
      SSL_EXT_IGNORE_ON_RESUMPTION* = 64 ## Generated based on /usr/include/openssl/ssl.h:293:9
  else:
    let SSL_EXT_IGNORE_ON_RESUMPTION* = 64 ## Generated based on /usr/include/openssl/ssl.h:293:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_IGNORE_ON_RESUMPTION" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_CLIENT_HELLO):
  when 128 is static:
    const
      SSL_EXT_CLIENT_HELLO* = 128 ## Generated based on /usr/include/openssl/ssl.h:294:9
  else:
    let SSL_EXT_CLIENT_HELLO* = 128 ## Generated based on /usr/include/openssl/ssl.h:294:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_CLIENT_HELLO" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_2_SERVER_HELLO):
  when 256 is static:
    const
      SSL_EXT_TLS1_2_SERVER_HELLO* = 256 ## Generated based on /usr/include/openssl/ssl.h:296:9
  else:
    let SSL_EXT_TLS1_2_SERVER_HELLO* = 256 ## Generated based on /usr/include/openssl/ssl.h:296:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_2_SERVER_HELLO" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_SERVER_HELLO):
  when 512 is static:
    const
      SSL_EXT_TLS1_3_SERVER_HELLO* = 512 ## Generated based on /usr/include/openssl/ssl.h:297:9
  else:
    let SSL_EXT_TLS1_3_SERVER_HELLO* = 512 ## Generated based on /usr/include/openssl/ssl.h:297:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_SERVER_HELLO" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS):
  when 1024 is static:
    const
      SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS* = 1024 ## Generated based on /usr/include/openssl/ssl.h:298:9
  else:
    let SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS* = 1024 ## Generated based on /usr/include/openssl/ssl.h:298:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST):
  when 2048 is static:
    const
      SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST* = 2048 ## Generated based on /usr/include/openssl/ssl.h:299:9
  else:
    let SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST* = 2048 ## Generated based on /usr/include/openssl/ssl.h:299:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_CERTIFICATE):
  when 4096 is static:
    const
      SSL_EXT_TLS1_3_CERTIFICATE* = 4096 ## Generated based on /usr/include/openssl/ssl.h:300:9
  else:
    let SSL_EXT_TLS1_3_CERTIFICATE* = 4096 ## Generated based on /usr/include/openssl/ssl.h:300:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_CERTIFICATE" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_NEW_SESSION_TICKET):
  when 8192 is static:
    const
      SSL_EXT_TLS1_3_NEW_SESSION_TICKET* = 8192 ## Generated based on /usr/include/openssl/ssl.h:301:9
  else:
    let SSL_EXT_TLS1_3_NEW_SESSION_TICKET* = 8192 ## Generated based on /usr/include/openssl/ssl.h:301:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_NEW_SESSION_TICKET" &
        " already exists, not redeclaring")
when not declared(SSL_EXT_TLS1_3_CERTIFICATE_REQUEST):
  when 16384 is static:
    const
      SSL_EXT_TLS1_3_CERTIFICATE_REQUEST* = 16384 ## Generated based on /usr/include/openssl/ssl.h:302:9
  else:
    let SSL_EXT_TLS1_3_CERTIFICATE_REQUEST* = 16384 ## Generated based on /usr/include/openssl/ssl.h:302:9
else:
  static :
    hint("Declaration of " & "SSL_EXT_TLS1_3_CERTIFICATE_REQUEST" &
        " already exists, not redeclaring")
when not declared(SSL_OP_MICROSOFT_SESS_ID_BUG):
  when 0 is static:
    const
      SSL_OP_MICROSOFT_SESS_ID_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:452:10
  else:
    let SSL_OP_MICROSOFT_SESS_ID_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:452:10
else:
  static :
    hint("Declaration of " & "SSL_OP_MICROSOFT_SESS_ID_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_NETSCAPE_CHALLENGE_BUG):
  when 0 is static:
    const
      SSL_OP_NETSCAPE_CHALLENGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:453:10
  else:
    let SSL_OP_NETSCAPE_CHALLENGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:453:10
else:
  static :
    hint("Declaration of " & "SSL_OP_NETSCAPE_CHALLENGE_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG):
  when 0 is static:
    const
      SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:454:10
  else:
    let SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:454:10
else:
  static :
    hint("Declaration of " & "SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG):
  when 0 is static:
    const
      SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:455:10
  else:
    let SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:455:10
else:
  static :
    hint("Declaration of " & "SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER):
  when 0 is static:
    const
      SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER* = 0 ## Generated based on /usr/include/openssl/ssl.h:456:10
  else:
    let SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER* = 0 ## Generated based on /usr/include/openssl/ssl.h:456:10
else:
  static :
    hint("Declaration of " & "SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER" &
        " already exists, not redeclaring")
when not declared(SSL_OP_MSIE_SSLV2_RSA_PADDING):
  when 0 is static:
    const
      SSL_OP_MSIE_SSLV2_RSA_PADDING* = 0 ## Generated based on /usr/include/openssl/ssl.h:457:10
  else:
    let SSL_OP_MSIE_SSLV2_RSA_PADDING* = 0 ## Generated based on /usr/include/openssl/ssl.h:457:10
else:
  static :
    hint("Declaration of " & "SSL_OP_MSIE_SSLV2_RSA_PADDING" &
        " already exists, not redeclaring")
when not declared(SSL_OP_SSLEAY_080_CLIENT_DH_BUG):
  when 0 is static:
    const
      SSL_OP_SSLEAY_080_CLIENT_DH_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:458:10
  else:
    let SSL_OP_SSLEAY_080_CLIENT_DH_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:458:10
else:
  static :
    hint("Declaration of " & "SSL_OP_SSLEAY_080_CLIENT_DH_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_TLS_D5_BUG):
  when 0 is static:
    const
      SSL_OP_TLS_D5_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:459:10
  else:
    let SSL_OP_TLS_D5_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:459:10
else:
  static :
    hint("Declaration of " & "SSL_OP_TLS_D5_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_TLS_BLOCK_PADDING_BUG):
  when 0 is static:
    const
      SSL_OP_TLS_BLOCK_PADDING_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:460:10
  else:
    let SSL_OP_TLS_BLOCK_PADDING_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:460:10
else:
  static :
    hint("Declaration of " & "SSL_OP_TLS_BLOCK_PADDING_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_SINGLE_ECDH_USE):
  when 0 is static:
    const
      SSL_OP_SINGLE_ECDH_USE* = 0 ## Generated based on /usr/include/openssl/ssl.h:461:10
  else:
    let SSL_OP_SINGLE_ECDH_USE* = 0 ## Generated based on /usr/include/openssl/ssl.h:461:10
else:
  static :
    hint("Declaration of " & "SSL_OP_SINGLE_ECDH_USE" &
        " already exists, not redeclaring")
when not declared(SSL_OP_SINGLE_DH_USE):
  when 0 is static:
    const
      SSL_OP_SINGLE_DH_USE* = 0 ## Generated based on /usr/include/openssl/ssl.h:462:10
  else:
    let SSL_OP_SINGLE_DH_USE* = 0 ## Generated based on /usr/include/openssl/ssl.h:462:10
else:
  static :
    hint("Declaration of " & "SSL_OP_SINGLE_DH_USE" &
        " already exists, not redeclaring")
when not declared(SSL_OP_EPHEMERAL_RSA):
  when 0 is static:
    const
      SSL_OP_EPHEMERAL_RSA* = 0 ## Generated based on /usr/include/openssl/ssl.h:463:10
  else:
    let SSL_OP_EPHEMERAL_RSA* = 0 ## Generated based on /usr/include/openssl/ssl.h:463:10
else:
  static :
    hint("Declaration of " & "SSL_OP_EPHEMERAL_RSA" &
        " already exists, not redeclaring")
when not declared(SSL_OP_NO_SSLv2):
  when 0 is static:
    const
      SSL_OP_NO_SSLv2* = 0   ## Generated based on /usr/include/openssl/ssl.h:464:10
  else:
    let SSL_OP_NO_SSLv2* = 0 ## Generated based on /usr/include/openssl/ssl.h:464:10
else:
  static :
    hint("Declaration of " & "SSL_OP_NO_SSLv2" &
        " already exists, not redeclaring")
when not declared(SSL_OP_PKCS1_CHECK_1):
  when 0 is static:
    const
      SSL_OP_PKCS1_CHECK_1* = 0 ## Generated based on /usr/include/openssl/ssl.h:465:10
  else:
    let SSL_OP_PKCS1_CHECK_1* = 0 ## Generated based on /usr/include/openssl/ssl.h:465:10
else:
  static :
    hint("Declaration of " & "SSL_OP_PKCS1_CHECK_1" &
        " already exists, not redeclaring")
when not declared(SSL_OP_PKCS1_CHECK_2):
  when 0 is static:
    const
      SSL_OP_PKCS1_CHECK_2* = 0 ## Generated based on /usr/include/openssl/ssl.h:466:10
  else:
    let SSL_OP_PKCS1_CHECK_2* = 0 ## Generated based on /usr/include/openssl/ssl.h:466:10
else:
  static :
    hint("Declaration of " & "SSL_OP_PKCS1_CHECK_2" &
        " already exists, not redeclaring")
when not declared(SSL_OP_NETSCAPE_CA_DN_BUG):
  when 0 is static:
    const
      SSL_OP_NETSCAPE_CA_DN_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:467:10
  else:
    let SSL_OP_NETSCAPE_CA_DN_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:467:10
else:
  static :
    hint("Declaration of " & "SSL_OP_NETSCAPE_CA_DN_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG):
  when 0 is static:
    const
      SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:468:10
  else:
    let SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG* = 0 ## Generated based on /usr/include/openssl/ssl.h:468:10
else:
  static :
    hint("Declaration of " & "SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_ENABLE_PARTIAL_WRITE):
  when cast[cuint](1'i64) is static:
    const
      SSL_MODE_ENABLE_PARTIAL_WRITE* = cast[cuint](1'i64) ## Generated based on /usr/include/openssl/ssl.h:474:10
  else:
    let SSL_MODE_ENABLE_PARTIAL_WRITE* = cast[cuint](1'i64) ## Generated based on /usr/include/openssl/ssl.h:474:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_ENABLE_PARTIAL_WRITE" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER):
  when cast[cuint](2'i64) is static:
    const
      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER* = cast[cuint](2'i64) ## Generated based on /usr/include/openssl/ssl.h:481:10
  else:
    let SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER* = cast[cuint](2'i64) ## Generated based on /usr/include/openssl/ssl.h:481:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_AUTO_RETRY):
  when cast[cuint](4'i64) is static:
    const
      SSL_MODE_AUTO_RETRY* = cast[cuint](4'i64) ## Generated based on /usr/include/openssl/ssl.h:485:10
  else:
    let SSL_MODE_AUTO_RETRY* = cast[cuint](4'i64) ## Generated based on /usr/include/openssl/ssl.h:485:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_AUTO_RETRY" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_NO_AUTO_CHAIN):
  when cast[cuint](8'i64) is static:
    const
      SSL_MODE_NO_AUTO_CHAIN* = cast[cuint](8'i64) ## Generated based on /usr/include/openssl/ssl.h:487:10
  else:
    let SSL_MODE_NO_AUTO_CHAIN* = cast[cuint](8'i64) ## Generated based on /usr/include/openssl/ssl.h:487:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_NO_AUTO_CHAIN" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_RELEASE_BUFFERS):
  when cast[cuint](16'i64) is static:
    const
      SSL_MODE_RELEASE_BUFFERS* = cast[cuint](16'i64) ## Generated based on /usr/include/openssl/ssl.h:492:10
  else:
    let SSL_MODE_RELEASE_BUFFERS* = cast[cuint](16'i64) ## Generated based on /usr/include/openssl/ssl.h:492:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_RELEASE_BUFFERS" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_SEND_CLIENTHELLO_TIME):
  when cast[cuint](32'i64) is static:
    const
      SSL_MODE_SEND_CLIENTHELLO_TIME* = cast[cuint](32'i64) ## Generated based on /usr/include/openssl/ssl.h:498:10
  else:
    let SSL_MODE_SEND_CLIENTHELLO_TIME* = cast[cuint](32'i64) ## Generated based on /usr/include/openssl/ssl.h:498:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_SEND_CLIENTHELLO_TIME" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_SEND_SERVERHELLO_TIME):
  when cast[cuint](64'i64) is static:
    const
      SSL_MODE_SEND_SERVERHELLO_TIME* = cast[cuint](64'i64) ## Generated based on /usr/include/openssl/ssl.h:499:10
  else:
    let SSL_MODE_SEND_SERVERHELLO_TIME* = cast[cuint](64'i64) ## Generated based on /usr/include/openssl/ssl.h:499:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_SEND_SERVERHELLO_TIME" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_SEND_FALLBACK_SCSV):
  when cast[cuint](128'i64) is static:
    const
      SSL_MODE_SEND_FALLBACK_SCSV* = cast[cuint](128'i64) ## Generated based on /usr/include/openssl/ssl.h:508:10
  else:
    let SSL_MODE_SEND_FALLBACK_SCSV* = cast[cuint](128'i64) ## Generated based on /usr/include/openssl/ssl.h:508:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_SEND_FALLBACK_SCSV" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_ASYNC):
  when cast[cuint](256'i64) is static:
    const
      SSL_MODE_ASYNC* = cast[cuint](256'i64) ## Generated based on /usr/include/openssl/ssl.h:512:10
  else:
    let SSL_MODE_ASYNC* = cast[cuint](256'i64) ## Generated based on /usr/include/openssl/ssl.h:512:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_ASYNC" &
        " already exists, not redeclaring")
when not declared(SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG):
  when cast[cuint](1024'i64) is static:
    const
      SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG* = cast[cuint](1024'i64) ## Generated based on /usr/include/openssl/ssl.h:525:10
  else:
    let SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG* = cast[cuint](1024'i64) ## Generated based on /usr/include/openssl/ssl.h:525:10
else:
  static :
    hint("Declaration of " & "SSL_MODE_DTLS_SCTP_LABEL_LENGTH_BUG" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_FLAG_TLS_STRICT):
  when cast[cuint](1'i64) is static:
    const
      SSL_CERT_FLAG_TLS_STRICT* = cast[cuint](1'i64) ## Generated based on /usr/include/openssl/ssl.h:532:10
  else:
    let SSL_CERT_FLAG_TLS_STRICT* = cast[cuint](1'i64) ## Generated based on /usr/include/openssl/ssl.h:532:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_FLAG_TLS_STRICT" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_FLAG_SUITEB_128_LOS_ONLY):
  when 65536 is static:
    const
      SSL_CERT_FLAG_SUITEB_128_LOS_ONLY* = 65536 ## Generated based on /usr/include/openssl/ssl.h:535:10
  else:
    let SSL_CERT_FLAG_SUITEB_128_LOS_ONLY* = 65536 ## Generated based on /usr/include/openssl/ssl.h:535:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_FLAG_SUITEB_128_LOS_ONLY" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_FLAG_SUITEB_192_LOS):
  when 131072 is static:
    const
      SSL_CERT_FLAG_SUITEB_192_LOS* = 131072 ## Generated based on /usr/include/openssl/ssl.h:537:10
  else:
    let SSL_CERT_FLAG_SUITEB_192_LOS* = 131072 ## Generated based on /usr/include/openssl/ssl.h:537:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_FLAG_SUITEB_192_LOS" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_FLAG_SUITEB_128_LOS):
  when 196608 is static:
    const
      SSL_CERT_FLAG_SUITEB_128_LOS* = 196608 ## Generated based on /usr/include/openssl/ssl.h:539:10
  else:
    let SSL_CERT_FLAG_SUITEB_128_LOS* = 196608 ## Generated based on /usr/include/openssl/ssl.h:539:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_FLAG_SUITEB_128_LOS" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_FLAG_BROKEN_PROTOCOL):
  when 268435456 is static:
    const
      SSL_CERT_FLAG_BROKEN_PROTOCOL* = 268435456 ## Generated based on /usr/include/openssl/ssl.h:542:10
  else:
    let SSL_CERT_FLAG_BROKEN_PROTOCOL* = 268435456 ## Generated based on /usr/include/openssl/ssl.h:542:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_FLAG_BROKEN_PROTOCOL" &
        " already exists, not redeclaring")
when not declared(SSL_BUILD_CHAIN_FLAG_UNTRUSTED):
  when 1 is static:
    const
      SSL_BUILD_CHAIN_FLAG_UNTRUSTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:546:10
  else:
    let SSL_BUILD_CHAIN_FLAG_UNTRUSTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:546:10
else:
  static :
    hint("Declaration of " & "SSL_BUILD_CHAIN_FLAG_UNTRUSTED" &
        " already exists, not redeclaring")
when not declared(SSL_BUILD_CHAIN_FLAG_NO_ROOT):
  when 2 is static:
    const
      SSL_BUILD_CHAIN_FLAG_NO_ROOT* = 2 ## Generated based on /usr/include/openssl/ssl.h:548:10
  else:
    let SSL_BUILD_CHAIN_FLAG_NO_ROOT* = 2 ## Generated based on /usr/include/openssl/ssl.h:548:10
else:
  static :
    hint("Declaration of " & "SSL_BUILD_CHAIN_FLAG_NO_ROOT" &
        " already exists, not redeclaring")
when not declared(SSL_BUILD_CHAIN_FLAG_CHECK):
  when 4 is static:
    const
      SSL_BUILD_CHAIN_FLAG_CHECK* = 4 ## Generated based on /usr/include/openssl/ssl.h:550:10
  else:
    let SSL_BUILD_CHAIN_FLAG_CHECK* = 4 ## Generated based on /usr/include/openssl/ssl.h:550:10
else:
  static :
    hint("Declaration of " & "SSL_BUILD_CHAIN_FLAG_CHECK" &
        " already exists, not redeclaring")
when not declared(SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR):
  when 8 is static:
    const
      SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR* = 8 ## Generated based on /usr/include/openssl/ssl.h:552:10
  else:
    let SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR* = 8 ## Generated based on /usr/include/openssl/ssl.h:552:10
else:
  static :
    hint("Declaration of " & "SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR" &
        " already exists, not redeclaring")
when not declared(SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR):
  when 16 is static:
    const
      SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR* = 16 ## Generated based on /usr/include/openssl/ssl.h:554:10
  else:
    let SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR* = 16 ## Generated based on /usr/include/openssl/ssl.h:554:10
else:
  static :
    hint("Declaration of " & "SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_VALID):
  when 1 is static:
    const
      CERT_PKEY_VALID* = 1   ## Generated based on /usr/include/openssl/ssl.h:558:10
  else:
    let CERT_PKEY_VALID* = 1 ## Generated based on /usr/include/openssl/ssl.h:558:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_VALID" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_SIGN):
  when 2 is static:
    const
      CERT_PKEY_SIGN* = 2    ## Generated based on /usr/include/openssl/ssl.h:560:10
  else:
    let CERT_PKEY_SIGN* = 2  ## Generated based on /usr/include/openssl/ssl.h:560:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_SIGN" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_EE_SIGNATURE):
  when 16 is static:
    const
      CERT_PKEY_EE_SIGNATURE* = 16 ## Generated based on /usr/include/openssl/ssl.h:562:10
  else:
    let CERT_PKEY_EE_SIGNATURE* = 16 ## Generated based on /usr/include/openssl/ssl.h:562:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_EE_SIGNATURE" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_CA_SIGNATURE):
  when 32 is static:
    const
      CERT_PKEY_CA_SIGNATURE* = 32 ## Generated based on /usr/include/openssl/ssl.h:564:10
  else:
    let CERT_PKEY_CA_SIGNATURE* = 32 ## Generated based on /usr/include/openssl/ssl.h:564:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_CA_SIGNATURE" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_EE_PARAM):
  when 64 is static:
    const
      CERT_PKEY_EE_PARAM* = 64 ## Generated based on /usr/include/openssl/ssl.h:566:10
  else:
    let CERT_PKEY_EE_PARAM* = 64 ## Generated based on /usr/include/openssl/ssl.h:566:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_EE_PARAM" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_CA_PARAM):
  when 128 is static:
    const
      CERT_PKEY_CA_PARAM* = 128 ## Generated based on /usr/include/openssl/ssl.h:568:10
  else:
    let CERT_PKEY_CA_PARAM* = 128 ## Generated based on /usr/include/openssl/ssl.h:568:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_CA_PARAM" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_EXPLICIT_SIGN):
  when 256 is static:
    const
      CERT_PKEY_EXPLICIT_SIGN* = 256 ## Generated based on /usr/include/openssl/ssl.h:570:10
  else:
    let CERT_PKEY_EXPLICIT_SIGN* = 256 ## Generated based on /usr/include/openssl/ssl.h:570:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_EXPLICIT_SIGN" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_ISSUER_NAME):
  when 512 is static:
    const
      CERT_PKEY_ISSUER_NAME* = 512 ## Generated based on /usr/include/openssl/ssl.h:572:10
  else:
    let CERT_PKEY_ISSUER_NAME* = 512 ## Generated based on /usr/include/openssl/ssl.h:572:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_ISSUER_NAME" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_CERT_TYPE):
  when 1024 is static:
    const
      CERT_PKEY_CERT_TYPE* = 1024 ## Generated based on /usr/include/openssl/ssl.h:574:10
  else:
    let CERT_PKEY_CERT_TYPE* = 1024 ## Generated based on /usr/include/openssl/ssl.h:574:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_CERT_TYPE" &
        " already exists, not redeclaring")
when not declared(CERT_PKEY_SUITEB):
  when 2048 is static:
    const
      CERT_PKEY_SUITEB* = 2048 ## Generated based on /usr/include/openssl/ssl.h:576:10
  else:
    let CERT_PKEY_SUITEB* = 2048 ## Generated based on /usr/include/openssl/ssl.h:576:10
else:
  static :
    hint("Declaration of " & "CERT_PKEY_SUITEB" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_CMDLINE):
  when 1 is static:
    const
      SSL_CONF_FLAG_CMDLINE* = 1 ## Generated based on /usr/include/openssl/ssl.h:578:10
  else:
    let SSL_CONF_FLAG_CMDLINE* = 1 ## Generated based on /usr/include/openssl/ssl.h:578:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_CMDLINE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_FILE):
  when 2 is static:
    const
      SSL_CONF_FLAG_FILE* = 2 ## Generated based on /usr/include/openssl/ssl.h:579:10
  else:
    let SSL_CONF_FLAG_FILE* = 2 ## Generated based on /usr/include/openssl/ssl.h:579:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_FILE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_CLIENT):
  when 4 is static:
    const
      SSL_CONF_FLAG_CLIENT* = 4 ## Generated based on /usr/include/openssl/ssl.h:580:10
  else:
    let SSL_CONF_FLAG_CLIENT* = 4 ## Generated based on /usr/include/openssl/ssl.h:580:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_CLIENT" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_SERVER):
  when 8 is static:
    const
      SSL_CONF_FLAG_SERVER* = 8 ## Generated based on /usr/include/openssl/ssl.h:581:10
  else:
    let SSL_CONF_FLAG_SERVER* = 8 ## Generated based on /usr/include/openssl/ssl.h:581:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_SERVER" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_SHOW_ERRORS):
  when 16 is static:
    const
      SSL_CONF_FLAG_SHOW_ERRORS* = 16 ## Generated based on /usr/include/openssl/ssl.h:582:10
  else:
    let SSL_CONF_FLAG_SHOW_ERRORS* = 16 ## Generated based on /usr/include/openssl/ssl.h:582:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_SHOW_ERRORS" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_CERTIFICATE):
  when 32 is static:
    const
      SSL_CONF_FLAG_CERTIFICATE* = 32 ## Generated based on /usr/include/openssl/ssl.h:583:10
  else:
    let SSL_CONF_FLAG_CERTIFICATE* = 32 ## Generated based on /usr/include/openssl/ssl.h:583:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_CERTIFICATE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_FLAG_REQUIRE_PRIVATE):
  when 64 is static:
    const
      SSL_CONF_FLAG_REQUIRE_PRIVATE* = 64 ## Generated based on /usr/include/openssl/ssl.h:584:10
  else:
    let SSL_CONF_FLAG_REQUIRE_PRIVATE* = 64 ## Generated based on /usr/include/openssl/ssl.h:584:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_FLAG_REQUIRE_PRIVATE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_UNKNOWN):
  when 0 is static:
    const
      SSL_CONF_TYPE_UNKNOWN* = 0 ## Generated based on /usr/include/openssl/ssl.h:586:10
  else:
    let SSL_CONF_TYPE_UNKNOWN* = 0 ## Generated based on /usr/include/openssl/ssl.h:586:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_UNKNOWN" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_STRING):
  when 1 is static:
    const
      SSL_CONF_TYPE_STRING* = 1 ## Generated based on /usr/include/openssl/ssl.h:587:10
  else:
    let SSL_CONF_TYPE_STRING* = 1 ## Generated based on /usr/include/openssl/ssl.h:587:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_STRING" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_FILE):
  when 2 is static:
    const
      SSL_CONF_TYPE_FILE* = 2 ## Generated based on /usr/include/openssl/ssl.h:588:10
  else:
    let SSL_CONF_TYPE_FILE* = 2 ## Generated based on /usr/include/openssl/ssl.h:588:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_FILE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_DIR):
  when 3 is static:
    const
      SSL_CONF_TYPE_DIR* = 3 ## Generated based on /usr/include/openssl/ssl.h:589:10
  else:
    let SSL_CONF_TYPE_DIR* = 3 ## Generated based on /usr/include/openssl/ssl.h:589:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_DIR" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_NONE):
  when 4 is static:
    const
      SSL_CONF_TYPE_NONE* = 4 ## Generated based on /usr/include/openssl/ssl.h:590:10
  else:
    let SSL_CONF_TYPE_NONE* = 4 ## Generated based on /usr/include/openssl/ssl.h:590:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_TYPE_STORE):
  when 5 is static:
    const
      SSL_CONF_TYPE_STORE* = 5 ## Generated based on /usr/include/openssl/ssl.h:591:10
  else:
    let SSL_CONF_TYPE_STORE* = 5 ## Generated based on /usr/include/openssl/ssl.h:591:10
else:
  static :
    hint("Declaration of " & "SSL_CONF_TYPE_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_COOKIE_LENGTH):
  when 4096 is static:
    const
      SSL_COOKIE_LENGTH* = 4096 ## Generated based on /usr/include/openssl/ssl.h:594:10
  else:
    let SSL_COOKIE_LENGTH* = 4096 ## Generated based on /usr/include/openssl/ssl.h:594:10
else:
  static :
    hint("Declaration of " & "SSL_COOKIE_LENGTH" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_OFF):
  when 0 is static:
    const
      SSL_SESS_CACHE_OFF* = 0 ## Generated based on /usr/include/openssl/ssl.h:686:10
  else:
    let SSL_SESS_CACHE_OFF* = 0 ## Generated based on /usr/include/openssl/ssl.h:686:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_OFF" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_CLIENT):
  when 1 is static:
    const
      SSL_SESS_CACHE_CLIENT* = 1 ## Generated based on /usr/include/openssl/ssl.h:687:10
  else:
    let SSL_SESS_CACHE_CLIENT* = 1 ## Generated based on /usr/include/openssl/ssl.h:687:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_CLIENT" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_SERVER):
  when 2 is static:
    const
      SSL_SESS_CACHE_SERVER* = 2 ## Generated based on /usr/include/openssl/ssl.h:688:10
  else:
    let SSL_SESS_CACHE_SERVER* = 2 ## Generated based on /usr/include/openssl/ssl.h:688:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_SERVER" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_NO_AUTO_CLEAR):
  when 128 is static:
    const
      SSL_SESS_CACHE_NO_AUTO_CLEAR* = 128 ## Generated based on /usr/include/openssl/ssl.h:690:10
  else:
    let SSL_SESS_CACHE_NO_AUTO_CLEAR* = 128 ## Generated based on /usr/include/openssl/ssl.h:690:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_NO_AUTO_CLEAR" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_NO_INTERNAL_LOOKUP):
  when 256 is static:
    const
      SSL_SESS_CACHE_NO_INTERNAL_LOOKUP* = 256 ## Generated based on /usr/include/openssl/ssl.h:692:10
  else:
    let SSL_SESS_CACHE_NO_INTERNAL_LOOKUP* = 256 ## Generated based on /usr/include/openssl/ssl.h:692:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_NO_INTERNAL_LOOKUP" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_NO_INTERNAL_STORE):
  when 512 is static:
    const
      SSL_SESS_CACHE_NO_INTERNAL_STORE* = 512 ## Generated based on /usr/include/openssl/ssl.h:693:10
  else:
    let SSL_SESS_CACHE_NO_INTERNAL_STORE* = 512 ## Generated based on /usr/include/openssl/ssl.h:693:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_NO_INTERNAL_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_SESS_CACHE_UPDATE_TIME):
  when 1024 is static:
    const
      SSL_SESS_CACHE_UPDATE_TIME* = 1024 ## Generated based on /usr/include/openssl/ssl.h:696:10
  else:
    let SSL_SESS_CACHE_UPDATE_TIME* = 1024 ## Generated based on /usr/include/openssl/ssl.h:696:10
else:
  static :
    hint("Declaration of " & "SSL_SESS_CACHE_UPDATE_TIME" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_next_protos_advertised_cb):
  proc SSL_CTX_set_next_protos_advertised_cb*(s: ptr SSL_CTX_536871728;
      cb: SSL_CTX_npn_advertised_cb_func_536871734; arg: pointer): void {.cdecl,
      importc: "SSL_CTX_set_next_protos_advertised_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_next_protos_advertised_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_next_proto_select_cb):
  proc SSL_CTX_set_next_proto_select_cb*(s: ptr SSL_CTX_536871728;
      cb: SSL_CTX_npn_select_cb_func_536871736; arg: pointer): void {.cdecl,
      importc: "SSL_CTX_set_next_proto_select_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_next_proto_select_cb" &
        " already exists, not redeclaring")
when not declared(SSL_get0_next_proto_negotiated):
  proc SSL_get0_next_proto_negotiated*(s: ptr SSL_536871704;
                                       data: ptr ptr uint8; len: ptr cuint): void {.
      cdecl, importc: "SSL_get0_next_proto_negotiated".}
else:
  static :
    hint("Declaration of " & "SSL_get0_next_proto_negotiated" &
        " already exists, not redeclaring")
when not declared(OPENSSL_NPN_UNSUPPORTED):
  when 0 is static:
    const
      OPENSSL_NPN_UNSUPPORTED* = 0 ## Generated based on /usr/include/openssl/ssl.h:811:10
  else:
    let OPENSSL_NPN_UNSUPPORTED* = 0 ## Generated based on /usr/include/openssl/ssl.h:811:10
else:
  static :
    hint("Declaration of " & "OPENSSL_NPN_UNSUPPORTED" &
        " already exists, not redeclaring")
when not declared(OPENSSL_NPN_NEGOTIATED):
  when 1 is static:
    const
      OPENSSL_NPN_NEGOTIATED* = 1 ## Generated based on /usr/include/openssl/ssl.h:812:10
  else:
    let OPENSSL_NPN_NEGOTIATED* = 1 ## Generated based on /usr/include/openssl/ssl.h:812:10
else:
  static :
    hint("Declaration of " & "OPENSSL_NPN_NEGOTIATED" &
        " already exists, not redeclaring")
when not declared(OPENSSL_NPN_NO_OVERLAP):
  when 2 is static:
    const
      OPENSSL_NPN_NO_OVERLAP* = 2 ## Generated based on /usr/include/openssl/ssl.h:813:10
  else:
    let OPENSSL_NPN_NO_OVERLAP* = 2 ## Generated based on /usr/include/openssl/ssl.h:813:10
else:
  static :
    hint("Declaration of " & "OPENSSL_NPN_NO_OVERLAP" &
        " already exists, not redeclaring")
when not declared(PSK_MAX_IDENTITY_LEN):
  when 256 is static:
    const
      PSK_MAX_IDENTITY_LEN* = 256 ## Generated based on /usr/include/openssl/ssl.h:836:11
  else:
    let PSK_MAX_IDENTITY_LEN* = 256 ## Generated based on /usr/include/openssl/ssl.h:836:11
else:
  static :
    hint("Declaration of " & "PSK_MAX_IDENTITY_LEN" &
        " already exists, not redeclaring")
when not declared(PSK_MAX_PSK_LEN):
  when 512 is static:
    const
      PSK_MAX_PSK_LEN* = 512 ## Generated based on /usr/include/openssl/ssl.h:837:11
  else:
    let PSK_MAX_PSK_LEN* = 512 ## Generated based on /usr/include/openssl/ssl.h:837:11
else:
  static :
    hint("Declaration of " & "PSK_MAX_PSK_LEN" &
        " already exists, not redeclaring")
when not declared(SSL_NOTHING):
  when 1 is static:
    const
      SSL_NOTHING* = 1       ## Generated based on /usr/include/openssl/ssl.h:907:10
  else:
    let SSL_NOTHING* = 1     ## Generated based on /usr/include/openssl/ssl.h:907:10
else:
  static :
    hint("Declaration of " & "SSL_NOTHING" & " already exists, not redeclaring")
when not declared(SSL_WRITING):
  when 2 is static:
    const
      SSL_WRITING* = 2       ## Generated based on /usr/include/openssl/ssl.h:908:10
  else:
    let SSL_WRITING* = 2     ## Generated based on /usr/include/openssl/ssl.h:908:10
else:
  static :
    hint("Declaration of " & "SSL_WRITING" & " already exists, not redeclaring")
when not declared(SSL_READING):
  when 3 is static:
    const
      SSL_READING* = 3       ## Generated based on /usr/include/openssl/ssl.h:909:10
  else:
    let SSL_READING* = 3     ## Generated based on /usr/include/openssl/ssl.h:909:10
else:
  static :
    hint("Declaration of " & "SSL_READING" & " already exists, not redeclaring")
when not declared(SSL_X509_LOOKUP):
  when 4 is static:
    const
      SSL_X509_LOOKUP* = 4   ## Generated based on /usr/include/openssl/ssl.h:910:10
  else:
    let SSL_X509_LOOKUP* = 4 ## Generated based on /usr/include/openssl/ssl.h:910:10
else:
  static :
    hint("Declaration of " & "SSL_X509_LOOKUP" &
        " already exists, not redeclaring")
when not declared(SSL_ASYNC_PAUSED):
  when 5 is static:
    const
      SSL_ASYNC_PAUSED* = 5  ## Generated based on /usr/include/openssl/ssl.h:911:10
  else:
    let SSL_ASYNC_PAUSED* = 5 ## Generated based on /usr/include/openssl/ssl.h:911:10
else:
  static :
    hint("Declaration of " & "SSL_ASYNC_PAUSED" &
        " already exists, not redeclaring")
when not declared(SSL_ASYNC_NO_JOBS):
  when 6 is static:
    const
      SSL_ASYNC_NO_JOBS* = 6 ## Generated based on /usr/include/openssl/ssl.h:912:10
  else:
    let SSL_ASYNC_NO_JOBS* = 6 ## Generated based on /usr/include/openssl/ssl.h:912:10
else:
  static :
    hint("Declaration of " & "SSL_ASYNC_NO_JOBS" &
        " already exists, not redeclaring")
when not declared(SSL_CLIENT_HELLO_CB):
  when 7 is static:
    const
      SSL_CLIENT_HELLO_CB* = 7 ## Generated based on /usr/include/openssl/ssl.h:913:10
  else:
    let SSL_CLIENT_HELLO_CB* = 7 ## Generated based on /usr/include/openssl/ssl.h:913:10
else:
  static :
    hint("Declaration of " & "SSL_CLIENT_HELLO_CB" &
        " already exists, not redeclaring")
when not declared(SSL_RETRY_VERIFY):
  when 8 is static:
    const
      SSL_RETRY_VERIFY* = 8  ## Generated based on /usr/include/openssl/ssl.h:914:10
  else:
    let SSL_RETRY_VERIFY* = 8 ## Generated based on /usr/include/openssl/ssl.h:914:10
else:
  static :
    hint("Declaration of " & "SSL_RETRY_VERIFY" &
        " already exists, not redeclaring")
when not declared(SSL_MAC_FLAG_READ_MAC_STREAM):
  when 1 is static:
    const
      SSL_MAC_FLAG_READ_MAC_STREAM* = 1 ## Generated based on /usr/include/openssl/ssl.h:926:10
  else:
    let SSL_MAC_FLAG_READ_MAC_STREAM* = 1 ## Generated based on /usr/include/openssl/ssl.h:926:10
else:
  static :
    hint("Declaration of " & "SSL_MAC_FLAG_READ_MAC_STREAM" &
        " already exists, not redeclaring")
when not declared(SSL_MAC_FLAG_WRITE_MAC_STREAM):
  when 2 is static:
    const
      SSL_MAC_FLAG_WRITE_MAC_STREAM* = 2 ## Generated based on /usr/include/openssl/ssl.h:927:10
  else:
    let SSL_MAC_FLAG_WRITE_MAC_STREAM* = 2 ## Generated based on /usr/include/openssl/ssl.h:927:10
else:
  static :
    hint("Declaration of " & "SSL_MAC_FLAG_WRITE_MAC_STREAM" &
        " already exists, not redeclaring")
when not declared(SSL_MAC_FLAG_READ_MAC_TLSTREE):
  when 4 is static:
    const
      SSL_MAC_FLAG_READ_MAC_TLSTREE* = 4 ## Generated based on /usr/include/openssl/ssl.h:928:10
  else:
    let SSL_MAC_FLAG_READ_MAC_TLSTREE* = 4 ## Generated based on /usr/include/openssl/ssl.h:928:10
else:
  static :
    hint("Declaration of " & "SSL_MAC_FLAG_READ_MAC_TLSTREE" &
        " already exists, not redeclaring")
when not declared(SSL_MAC_FLAG_WRITE_MAC_TLSTREE):
  when 8 is static:
    const
      SSL_MAC_FLAG_WRITE_MAC_TLSTREE* = 8 ## Generated based on /usr/include/openssl/ssl.h:929:10
  else:
    let SSL_MAC_FLAG_WRITE_MAC_TLSTREE* = 8 ## Generated based on /usr/include/openssl/ssl.h:929:10
else:
  static :
    hint("Declaration of " & "SSL_MAC_FLAG_WRITE_MAC_TLSTREE" &
        " already exists, not redeclaring")
when not declared(SSL_KEY_UPDATE_NONE):
  when -1 is static:
    const
      SSL_KEY_UPDATE_NONE* = -1 ## Generated based on /usr/include/openssl/ssl.h:1046:9
  else:
    let SSL_KEY_UPDATE_NONE* = -1 ## Generated based on /usr/include/openssl/ssl.h:1046:9
else:
  static :
    hint("Declaration of " & "SSL_KEY_UPDATE_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_KEY_UPDATE_NOT_REQUESTED):
  when 0 is static:
    const
      SSL_KEY_UPDATE_NOT_REQUESTED* = 0 ## Generated based on /usr/include/openssl/ssl.h:1048:9
  else:
    let SSL_KEY_UPDATE_NOT_REQUESTED* = 0 ## Generated based on /usr/include/openssl/ssl.h:1048:9
else:
  static :
    hint("Declaration of " & "SSL_KEY_UPDATE_NOT_REQUESTED" &
        " already exists, not redeclaring")
when not declared(SSL_KEY_UPDATE_REQUESTED):
  when 1 is static:
    const
      SSL_KEY_UPDATE_REQUESTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:1049:9
  else:
    let SSL_KEY_UPDATE_REQUESTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:1049:9
else:
  static :
    hint("Declaration of " & "SSL_KEY_UPDATE_REQUESTED" &
        " already exists, not redeclaring")
when not declared(SSL_ST_CONNECT):
  when 4096 is static:
    const
      SSL_ST_CONNECT* = 4096 ## Generated based on /usr/include/openssl/ssl.h:1124:10
  else:
    let SSL_ST_CONNECT* = 4096 ## Generated based on /usr/include/openssl/ssl.h:1124:10
else:
  static :
    hint("Declaration of " & "SSL_ST_CONNECT" &
        " already exists, not redeclaring")
when not declared(SSL_ST_ACCEPT):
  when 8192 is static:
    const
      SSL_ST_ACCEPT* = 8192  ## Generated based on /usr/include/openssl/ssl.h:1125:10
  else:
    let SSL_ST_ACCEPT* = 8192 ## Generated based on /usr/include/openssl/ssl.h:1125:10
else:
  static :
    hint("Declaration of " & "SSL_ST_ACCEPT" &
        " already exists, not redeclaring")
when not declared(SSL_ST_MASK):
  when 4095 is static:
    const
      SSL_ST_MASK* = 4095    ## Generated based on /usr/include/openssl/ssl.h:1127:10
  else:
    let SSL_ST_MASK* = 4095  ## Generated based on /usr/include/openssl/ssl.h:1127:10
else:
  static :
    hint("Declaration of " & "SSL_ST_MASK" & " already exists, not redeclaring")
when not declared(SSL_CB_LOOP):
  when 1 is static:
    const
      SSL_CB_LOOP* = 1       ## Generated based on /usr/include/openssl/ssl.h:1129:10
  else:
    let SSL_CB_LOOP* = 1     ## Generated based on /usr/include/openssl/ssl.h:1129:10
else:
  static :
    hint("Declaration of " & "SSL_CB_LOOP" & " already exists, not redeclaring")
when not declared(SSL_CB_EXIT):
  when 2 is static:
    const
      SSL_CB_EXIT* = 2       ## Generated based on /usr/include/openssl/ssl.h:1130:10
  else:
    let SSL_CB_EXIT* = 2     ## Generated based on /usr/include/openssl/ssl.h:1130:10
else:
  static :
    hint("Declaration of " & "SSL_CB_EXIT" & " already exists, not redeclaring")
when not declared(SSL_CB_READ):
  when 4 is static:
    const
      SSL_CB_READ* = 4       ## Generated based on /usr/include/openssl/ssl.h:1131:10
  else:
    let SSL_CB_READ* = 4     ## Generated based on /usr/include/openssl/ssl.h:1131:10
else:
  static :
    hint("Declaration of " & "SSL_CB_READ" & " already exists, not redeclaring")
when not declared(SSL_CB_WRITE):
  when 8 is static:
    const
      SSL_CB_WRITE* = 8      ## Generated based on /usr/include/openssl/ssl.h:1132:10
  else:
    let SSL_CB_WRITE* = 8    ## Generated based on /usr/include/openssl/ssl.h:1132:10
else:
  static :
    hint("Declaration of " & "SSL_CB_WRITE" & " already exists, not redeclaring")
when not declared(SSL_CB_ALERT):
  when 16384 is static:
    const
      SSL_CB_ALERT* = 16384  ## Generated based on /usr/include/openssl/ssl.h:1133:10
  else:
    let SSL_CB_ALERT* = 16384 ## Generated based on /usr/include/openssl/ssl.h:1133:10
else:
  static :
    hint("Declaration of " & "SSL_CB_ALERT" & " already exists, not redeclaring")
when not declared(SSL_CB_HANDSHAKE_START):
  when 16 is static:
    const
      SSL_CB_HANDSHAKE_START* = 16 ## Generated based on /usr/include/openssl/ssl.h:1140:10
  else:
    let SSL_CB_HANDSHAKE_START* = 16 ## Generated based on /usr/include/openssl/ssl.h:1140:10
else:
  static :
    hint("Declaration of " & "SSL_CB_HANDSHAKE_START" &
        " already exists, not redeclaring")
when not declared(SSL_CB_HANDSHAKE_DONE):
  when 32 is static:
    const
      SSL_CB_HANDSHAKE_DONE* = 32 ## Generated based on /usr/include/openssl/ssl.h:1141:10
  else:
    let SSL_CB_HANDSHAKE_DONE* = 32 ## Generated based on /usr/include/openssl/ssl.h:1141:10
else:
  static :
    hint("Declaration of " & "SSL_CB_HANDSHAKE_DONE" &
        " already exists, not redeclaring")
when not declared(SSL_ST_READ_HEADER):
  when 240 is static:
    const
      SSL_ST_READ_HEADER* = 240 ## Generated based on /usr/include/openssl/ssl.h:1154:10
  else:
    let SSL_ST_READ_HEADER* = 240 ## Generated based on /usr/include/openssl/ssl.h:1154:10
else:
  static :
    hint("Declaration of " & "SSL_ST_READ_HEADER" &
        " already exists, not redeclaring")
when not declared(SSL_ST_READ_BODY):
  when 241 is static:
    const
      SSL_ST_READ_BODY* = 241 ## Generated based on /usr/include/openssl/ssl.h:1155:10
  else:
    let SSL_ST_READ_BODY* = 241 ## Generated based on /usr/include/openssl/ssl.h:1155:10
else:
  static :
    hint("Declaration of " & "SSL_ST_READ_BODY" &
        " already exists, not redeclaring")
when not declared(SSL_ST_READ_DONE):
  when 242 is static:
    const
      SSL_ST_READ_DONE* = 242 ## Generated based on /usr/include/openssl/ssl.h:1156:10
  else:
    let SSL_ST_READ_DONE* = 242 ## Generated based on /usr/include/openssl/ssl.h:1156:10
else:
  static :
    hint("Declaration of " & "SSL_ST_READ_DONE" &
        " already exists, not redeclaring")
when not declared(SSL_VERIFY_NONE):
  when 0 is static:
    const
      SSL_VERIFY_NONE* = 0   ## Generated based on /usr/include/openssl/ssl.h:1171:10
  else:
    let SSL_VERIFY_NONE* = 0 ## Generated based on /usr/include/openssl/ssl.h:1171:10
else:
  static :
    hint("Declaration of " & "SSL_VERIFY_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_VERIFY_PEER):
  when 1 is static:
    const
      SSL_VERIFY_PEER* = 1   ## Generated based on /usr/include/openssl/ssl.h:1172:10
  else:
    let SSL_VERIFY_PEER* = 1 ## Generated based on /usr/include/openssl/ssl.h:1172:10
else:
  static :
    hint("Declaration of " & "SSL_VERIFY_PEER" &
        " already exists, not redeclaring")
when not declared(SSL_VERIFY_FAIL_IF_NO_PEER_CERT):
  when 2 is static:
    const
      SSL_VERIFY_FAIL_IF_NO_PEER_CERT* = 2 ## Generated based on /usr/include/openssl/ssl.h:1173:10
  else:
    let SSL_VERIFY_FAIL_IF_NO_PEER_CERT* = 2 ## Generated based on /usr/include/openssl/ssl.h:1173:10
else:
  static :
    hint("Declaration of " & "SSL_VERIFY_FAIL_IF_NO_PEER_CERT" &
        " already exists, not redeclaring")
when not declared(SSL_VERIFY_CLIENT_ONCE):
  when 4 is static:
    const
      SSL_VERIFY_CLIENT_ONCE* = 4 ## Generated based on /usr/include/openssl/ssl.h:1174:10
  else:
    let SSL_VERIFY_CLIENT_ONCE* = 4 ## Generated based on /usr/include/openssl/ssl.h:1174:10
else:
  static :
    hint("Declaration of " & "SSL_VERIFY_CLIENT_ONCE" &
        " already exists, not redeclaring")
when not declared(SSL_VERIFY_POST_HANDSHAKE):
  when 8 is static:
    const
      SSL_VERIFY_POST_HANDSHAKE* = 8 ## Generated based on /usr/include/openssl/ssl.h:1175:10
  else:
    let SSL_VERIFY_POST_HANDSHAKE* = 8 ## Generated based on /usr/include/openssl/ssl.h:1175:10
else:
  static :
    hint("Declaration of " & "SSL_VERIFY_POST_HANDSHAKE" &
        " already exists, not redeclaring")
when not declared(SSL_AD_REASON_OFFSET):
  when 1000 is static:
    const
      SSL_AD_REASON_OFFSET* = 1000 ## Generated based on /usr/include/openssl/ssl.h:1200:10
  else:
    let SSL_AD_REASON_OFFSET* = 1000 ## Generated based on /usr/include/openssl/ssl.h:1200:10
else:
  static :
    hint("Declaration of " & "SSL_AD_REASON_OFFSET" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_CLOSE_NOTIFY):
  when 0 is static:
    const
      SSL3_AD_CLOSE_NOTIFY* = 0 ## Generated based on /usr/include/openssl/ssl3.h:245:10
  else:
    let SSL3_AD_CLOSE_NOTIFY* = 0 ## Generated based on /usr/include/openssl/ssl3.h:245:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_CLOSE_NOTIFY" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_UNEXPECTED_MESSAGE):
  when 10 is static:
    const
      SSL3_AD_UNEXPECTED_MESSAGE* = 10 ## Generated based on /usr/include/openssl/ssl3.h:246:10
  else:
    let SSL3_AD_UNEXPECTED_MESSAGE* = 10 ## Generated based on /usr/include/openssl/ssl3.h:246:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_UNEXPECTED_MESSAGE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_BAD_RECORD_MAC):
  when 20 is static:
    const
      SSL3_AD_BAD_RECORD_MAC* = 20 ## Generated based on /usr/include/openssl/ssl3.h:247:10
  else:
    let SSL3_AD_BAD_RECORD_MAC* = 20 ## Generated based on /usr/include/openssl/ssl3.h:247:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_BAD_RECORD_MAC" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_DECRYPTION_FAILED):
  when 21 is static:
    const
      TLS1_AD_DECRYPTION_FAILED* = 21 ## Generated based on /usr/include/openssl/tls1.h:57:10
  else:
    let TLS1_AD_DECRYPTION_FAILED* = 21 ## Generated based on /usr/include/openssl/tls1.h:57:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_DECRYPTION_FAILED" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_RECORD_OVERFLOW):
  when 22 is static:
    const
      TLS1_AD_RECORD_OVERFLOW* = 22 ## Generated based on /usr/include/openssl/tls1.h:58:10
  else:
    let TLS1_AD_RECORD_OVERFLOW* = 22 ## Generated based on /usr/include/openssl/tls1.h:58:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_RECORD_OVERFLOW" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_DECOMPRESSION_FAILURE):
  when 30 is static:
    const
      SSL3_AD_DECOMPRESSION_FAILURE* = 30 ## Generated based on /usr/include/openssl/ssl3.h:248:10
  else:
    let SSL3_AD_DECOMPRESSION_FAILURE* = 30 ## Generated based on /usr/include/openssl/ssl3.h:248:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_DECOMPRESSION_FAILURE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_HANDSHAKE_FAILURE):
  when 40 is static:
    const
      SSL3_AD_HANDSHAKE_FAILURE* = 40 ## Generated based on /usr/include/openssl/ssl3.h:249:10
  else:
    let SSL3_AD_HANDSHAKE_FAILURE* = 40 ## Generated based on /usr/include/openssl/ssl3.h:249:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_HANDSHAKE_FAILURE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_NO_CERTIFICATE):
  when 41 is static:
    const
      SSL3_AD_NO_CERTIFICATE* = 41 ## Generated based on /usr/include/openssl/ssl3.h:250:10
  else:
    let SSL3_AD_NO_CERTIFICATE* = 41 ## Generated based on /usr/include/openssl/ssl3.h:250:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_NO_CERTIFICATE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_BAD_CERTIFICATE):
  when 42 is static:
    const
      SSL3_AD_BAD_CERTIFICATE* = 42 ## Generated based on /usr/include/openssl/ssl3.h:251:10
  else:
    let SSL3_AD_BAD_CERTIFICATE* = 42 ## Generated based on /usr/include/openssl/ssl3.h:251:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_BAD_CERTIFICATE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_UNSUPPORTED_CERTIFICATE):
  when 43 is static:
    const
      SSL3_AD_UNSUPPORTED_CERTIFICATE* = 43 ## Generated based on /usr/include/openssl/ssl3.h:252:10
  else:
    let SSL3_AD_UNSUPPORTED_CERTIFICATE* = 43 ## Generated based on /usr/include/openssl/ssl3.h:252:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_UNSUPPORTED_CERTIFICATE" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_CERTIFICATE_REVOKED):
  when 44 is static:
    const
      SSL3_AD_CERTIFICATE_REVOKED* = 44 ## Generated based on /usr/include/openssl/ssl3.h:253:10
  else:
    let SSL3_AD_CERTIFICATE_REVOKED* = 44 ## Generated based on /usr/include/openssl/ssl3.h:253:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_CERTIFICATE_REVOKED" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_CERTIFICATE_EXPIRED):
  when 45 is static:
    const
      SSL3_AD_CERTIFICATE_EXPIRED* = 45 ## Generated based on /usr/include/openssl/ssl3.h:254:10
  else:
    let SSL3_AD_CERTIFICATE_EXPIRED* = 45 ## Generated based on /usr/include/openssl/ssl3.h:254:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_CERTIFICATE_EXPIRED" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_CERTIFICATE_UNKNOWN):
  when 46 is static:
    const
      SSL3_AD_CERTIFICATE_UNKNOWN* = 46 ## Generated based on /usr/include/openssl/ssl3.h:255:10
  else:
    let SSL3_AD_CERTIFICATE_UNKNOWN* = 46 ## Generated based on /usr/include/openssl/ssl3.h:255:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_CERTIFICATE_UNKNOWN" &
        " already exists, not redeclaring")
when not declared(SSL3_AD_ILLEGAL_PARAMETER):
  when 47 is static:
    const
      SSL3_AD_ILLEGAL_PARAMETER* = 47 ## Generated based on /usr/include/openssl/ssl3.h:256:10
  else:
    let SSL3_AD_ILLEGAL_PARAMETER* = 47 ## Generated based on /usr/include/openssl/ssl3.h:256:10
else:
  static :
    hint("Declaration of " & "SSL3_AD_ILLEGAL_PARAMETER" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_UNKNOWN_CA):
  when 48 is static:
    const
      TLS1_AD_UNKNOWN_CA* = 48 ## Generated based on /usr/include/openssl/tls1.h:59:10
  else:
    let TLS1_AD_UNKNOWN_CA* = 48 ## Generated based on /usr/include/openssl/tls1.h:59:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_UNKNOWN_CA" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_ACCESS_DENIED):
  when 49 is static:
    const
      TLS1_AD_ACCESS_DENIED* = 49 ## Generated based on /usr/include/openssl/tls1.h:60:10
  else:
    let TLS1_AD_ACCESS_DENIED* = 49 ## Generated based on /usr/include/openssl/tls1.h:60:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_ACCESS_DENIED" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_DECODE_ERROR):
  when 50 is static:
    const
      TLS1_AD_DECODE_ERROR* = 50 ## Generated based on /usr/include/openssl/tls1.h:61:10
  else:
    let TLS1_AD_DECODE_ERROR* = 50 ## Generated based on /usr/include/openssl/tls1.h:61:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_DECODE_ERROR" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_DECRYPT_ERROR):
  when 51 is static:
    const
      TLS1_AD_DECRYPT_ERROR* = 51 ## Generated based on /usr/include/openssl/tls1.h:62:10
  else:
    let TLS1_AD_DECRYPT_ERROR* = 51 ## Generated based on /usr/include/openssl/tls1.h:62:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_DECRYPT_ERROR" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_EXPORT_RESTRICTION):
  when 60 is static:
    const
      TLS1_AD_EXPORT_RESTRICTION* = 60 ## Generated based on /usr/include/openssl/tls1.h:63:10
  else:
    let TLS1_AD_EXPORT_RESTRICTION* = 60 ## Generated based on /usr/include/openssl/tls1.h:63:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_EXPORT_RESTRICTION" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_PROTOCOL_VERSION):
  when 70 is static:
    const
      TLS1_AD_PROTOCOL_VERSION* = 70 ## Generated based on /usr/include/openssl/tls1.h:64:10
  else:
    let TLS1_AD_PROTOCOL_VERSION* = 70 ## Generated based on /usr/include/openssl/tls1.h:64:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_PROTOCOL_VERSION" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_INSUFFICIENT_SECURITY):
  when 71 is static:
    const
      TLS1_AD_INSUFFICIENT_SECURITY* = 71 ## Generated based on /usr/include/openssl/tls1.h:65:10
  else:
    let TLS1_AD_INSUFFICIENT_SECURITY* = 71 ## Generated based on /usr/include/openssl/tls1.h:65:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_INSUFFICIENT_SECURITY" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_INTERNAL_ERROR):
  when 80 is static:
    const
      TLS1_AD_INTERNAL_ERROR* = 80 ## Generated based on /usr/include/openssl/tls1.h:66:10
  else:
    let TLS1_AD_INTERNAL_ERROR* = 80 ## Generated based on /usr/include/openssl/tls1.h:66:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_INTERNAL_ERROR" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_USER_CANCELLED):
  when 90 is static:
    const
      TLS1_AD_USER_CANCELLED* = 90 ## Generated based on /usr/include/openssl/tls1.h:68:10
  else:
    let TLS1_AD_USER_CANCELLED* = 90 ## Generated based on /usr/include/openssl/tls1.h:68:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_USER_CANCELLED" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_NO_RENEGOTIATION):
  when 100 is static:
    const
      TLS1_AD_NO_RENEGOTIATION* = 100 ## Generated based on /usr/include/openssl/tls1.h:69:10
  else:
    let TLS1_AD_NO_RENEGOTIATION* = 100 ## Generated based on /usr/include/openssl/tls1.h:69:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_NO_RENEGOTIATION" &
        " already exists, not redeclaring")
when not declared(TLS13_AD_MISSING_EXTENSION):
  when 109 is static:
    const
      TLS13_AD_MISSING_EXTENSION* = 109 ## Generated based on /usr/include/openssl/tls1.h:71:10
  else:
    let TLS13_AD_MISSING_EXTENSION* = 109 ## Generated based on /usr/include/openssl/tls1.h:71:10
else:
  static :
    hint("Declaration of " & "TLS13_AD_MISSING_EXTENSION" &
        " already exists, not redeclaring")
when not declared(TLS13_AD_CERTIFICATE_REQUIRED):
  when 116 is static:
    const
      TLS13_AD_CERTIFICATE_REQUIRED* = 116 ## Generated based on /usr/include/openssl/tls1.h:72:10
  else:
    let TLS13_AD_CERTIFICATE_REQUIRED* = 116 ## Generated based on /usr/include/openssl/tls1.h:72:10
else:
  static :
    hint("Declaration of " & "TLS13_AD_CERTIFICATE_REQUIRED" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_UNSUPPORTED_EXTENSION):
  when 110 is static:
    const
      TLS1_AD_UNSUPPORTED_EXTENSION* = 110 ## Generated based on /usr/include/openssl/tls1.h:74:10
  else:
    let TLS1_AD_UNSUPPORTED_EXTENSION* = 110 ## Generated based on /usr/include/openssl/tls1.h:74:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_UNSUPPORTED_EXTENSION" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_CERTIFICATE_UNOBTAINABLE):
  when 111 is static:
    const
      TLS1_AD_CERTIFICATE_UNOBTAINABLE* = 111 ## Generated based on /usr/include/openssl/tls1.h:75:10
  else:
    let TLS1_AD_CERTIFICATE_UNOBTAINABLE* = 111 ## Generated based on /usr/include/openssl/tls1.h:75:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_CERTIFICATE_UNOBTAINABLE" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_UNRECOGNIZED_NAME):
  when 112 is static:
    const
      TLS1_AD_UNRECOGNIZED_NAME* = 112 ## Generated based on /usr/include/openssl/tls1.h:76:10
  else:
    let TLS1_AD_UNRECOGNIZED_NAME* = 112 ## Generated based on /usr/include/openssl/tls1.h:76:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_UNRECOGNIZED_NAME" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE):
  when 113 is static:
    const
      TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE* = 113 ## Generated based on /usr/include/openssl/tls1.h:77:10
  else:
    let TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE* = 113 ## Generated based on /usr/include/openssl/tls1.h:77:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_BAD_CERTIFICATE_HASH_VALUE):
  when 114 is static:
    const
      TLS1_AD_BAD_CERTIFICATE_HASH_VALUE* = 114 ## Generated based on /usr/include/openssl/tls1.h:78:10
  else:
    let TLS1_AD_BAD_CERTIFICATE_HASH_VALUE* = 114 ## Generated based on /usr/include/openssl/tls1.h:78:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_BAD_CERTIFICATE_HASH_VALUE" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_UNKNOWN_PSK_IDENTITY):
  when 115 is static:
    const
      TLS1_AD_UNKNOWN_PSK_IDENTITY* = 115 ## Generated based on /usr/include/openssl/tls1.h:79:10
  else:
    let TLS1_AD_UNKNOWN_PSK_IDENTITY* = 115 ## Generated based on /usr/include/openssl/tls1.h:79:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_UNKNOWN_PSK_IDENTITY" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_INAPPROPRIATE_FALLBACK):
  when 86 is static:
    const
      TLS1_AD_INAPPROPRIATE_FALLBACK* = 86 ## Generated based on /usr/include/openssl/tls1.h:67:10
  else:
    let TLS1_AD_INAPPROPRIATE_FALLBACK* = 86 ## Generated based on /usr/include/openssl/tls1.h:67:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_INAPPROPRIATE_FALLBACK" &
        " already exists, not redeclaring")
when not declared(TLS1_AD_NO_APPLICATION_PROTOCOL):
  when 120 is static:
    const
      TLS1_AD_NO_APPLICATION_PROTOCOL* = 120 ## Generated based on /usr/include/openssl/tls1.h:80:10
  else:
    let TLS1_AD_NO_APPLICATION_PROTOCOL* = 120 ## Generated based on /usr/include/openssl/tls1.h:80:10
else:
  static :
    hint("Declaration of " & "TLS1_AD_NO_APPLICATION_PROTOCOL" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_NONE):
  when 0 is static:
    const
      SSL_ERROR_NONE* = 0    ## Generated based on /usr/include/openssl/ssl.h:1252:10
  else:
    let SSL_ERROR_NONE* = 0  ## Generated based on /usr/include/openssl/ssl.h:1252:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_SSL):
  when 1 is static:
    const
      SSL_ERROR_SSL* = 1     ## Generated based on /usr/include/openssl/ssl.h:1253:10
  else:
    let SSL_ERROR_SSL* = 1   ## Generated based on /usr/include/openssl/ssl.h:1253:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_SSL" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_READ):
  when 2 is static:
    const
      SSL_ERROR_WANT_READ* = 2 ## Generated based on /usr/include/openssl/ssl.h:1254:10
  else:
    let SSL_ERROR_WANT_READ* = 2 ## Generated based on /usr/include/openssl/ssl.h:1254:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_READ" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_WRITE):
  when 3 is static:
    const
      SSL_ERROR_WANT_WRITE* = 3 ## Generated based on /usr/include/openssl/ssl.h:1255:10
  else:
    let SSL_ERROR_WANT_WRITE* = 3 ## Generated based on /usr/include/openssl/ssl.h:1255:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_WRITE" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_X509_LOOKUP):
  when 4 is static:
    const
      SSL_ERROR_WANT_X509_LOOKUP* = 4 ## Generated based on /usr/include/openssl/ssl.h:1256:10
  else:
    let SSL_ERROR_WANT_X509_LOOKUP* = 4 ## Generated based on /usr/include/openssl/ssl.h:1256:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_X509_LOOKUP" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_SYSCALL):
  when 5 is static:
    const
      SSL_ERROR_SYSCALL* = 5 ## Generated based on /usr/include/openssl/ssl.h:1257:10
  else:
    let SSL_ERROR_SYSCALL* = 5 ## Generated based on /usr/include/openssl/ssl.h:1257:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_SYSCALL" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_ZERO_RETURN):
  when 6 is static:
    const
      SSL_ERROR_ZERO_RETURN* = 6 ## Generated based on /usr/include/openssl/ssl.h:1259:10
  else:
    let SSL_ERROR_ZERO_RETURN* = 6 ## Generated based on /usr/include/openssl/ssl.h:1259:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_ZERO_RETURN" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_CONNECT):
  when 7 is static:
    const
      SSL_ERROR_WANT_CONNECT* = 7 ## Generated based on /usr/include/openssl/ssl.h:1260:10
  else:
    let SSL_ERROR_WANT_CONNECT* = 7 ## Generated based on /usr/include/openssl/ssl.h:1260:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_CONNECT" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_ACCEPT):
  when 8 is static:
    const
      SSL_ERROR_WANT_ACCEPT* = 8 ## Generated based on /usr/include/openssl/ssl.h:1261:10
  else:
    let SSL_ERROR_WANT_ACCEPT* = 8 ## Generated based on /usr/include/openssl/ssl.h:1261:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_ACCEPT" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_ASYNC):
  when 9 is static:
    const
      SSL_ERROR_WANT_ASYNC* = 9 ## Generated based on /usr/include/openssl/ssl.h:1262:10
  else:
    let SSL_ERROR_WANT_ASYNC* = 9 ## Generated based on /usr/include/openssl/ssl.h:1262:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_ASYNC" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_ASYNC_JOB):
  when 10 is static:
    const
      SSL_ERROR_WANT_ASYNC_JOB* = 10 ## Generated based on /usr/include/openssl/ssl.h:1263:10
  else:
    let SSL_ERROR_WANT_ASYNC_JOB* = 10 ## Generated based on /usr/include/openssl/ssl.h:1263:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_ASYNC_JOB" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_CLIENT_HELLO_CB):
  when 11 is static:
    const
      SSL_ERROR_WANT_CLIENT_HELLO_CB* = 11 ## Generated based on /usr/include/openssl/ssl.h:1264:10
  else:
    let SSL_ERROR_WANT_CLIENT_HELLO_CB* = 11 ## Generated based on /usr/include/openssl/ssl.h:1264:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_CLIENT_HELLO_CB" &
        " already exists, not redeclaring")
when not declared(SSL_ERROR_WANT_RETRY_VERIFY):
  when 12 is static:
    const
      SSL_ERROR_WANT_RETRY_VERIFY* = 12 ## Generated based on /usr/include/openssl/ssl.h:1265:10
  else:
    let SSL_ERROR_WANT_RETRY_VERIFY* = 12 ## Generated based on /usr/include/openssl/ssl.h:1265:10
else:
  static :
    hint("Declaration of " & "SSL_ERROR_WANT_RETRY_VERIFY" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TMP_DH):
  when 3 is static:
    const
      SSL_CTRL_SET_TMP_DH* = 3 ## Generated based on /usr/include/openssl/ssl.h:1268:11
  else:
    let SSL_CTRL_SET_TMP_DH* = 3 ## Generated based on /usr/include/openssl/ssl.h:1268:11
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TMP_DH" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TMP_ECDH):
  when 4 is static:
    const
      SSL_CTRL_SET_TMP_ECDH* = 4 ## Generated based on /usr/include/openssl/ssl.h:1269:11
  else:
    let SSL_CTRL_SET_TMP_ECDH* = 4 ## Generated based on /usr/include/openssl/ssl.h:1269:11
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TMP_ECDH" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TMP_DH_CB):
  when 6 is static:
    const
      SSL_CTRL_SET_TMP_DH_CB* = 6 ## Generated based on /usr/include/openssl/ssl.h:1270:11
  else:
    let SSL_CTRL_SET_TMP_DH_CB* = 6 ## Generated based on /usr/include/openssl/ssl.h:1270:11
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TMP_DH_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_CLIENT_CERT_REQUEST):
  when 9 is static:
    const
      SSL_CTRL_GET_CLIENT_CERT_REQUEST* = 9 ## Generated based on /usr/include/openssl/ssl.h:1273:10
  else:
    let SSL_CTRL_GET_CLIENT_CERT_REQUEST* = 9 ## Generated based on /usr/include/openssl/ssl.h:1273:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_CLIENT_CERT_REQUEST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_NUM_RENEGOTIATIONS):
  when 10 is static:
    const
      SSL_CTRL_GET_NUM_RENEGOTIATIONS* = 10 ## Generated based on /usr/include/openssl/ssl.h:1274:10
  else:
    let SSL_CTRL_GET_NUM_RENEGOTIATIONS* = 10 ## Generated based on /usr/include/openssl/ssl.h:1274:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_NUM_RENEGOTIATIONS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS):
  when 11 is static:
    const
      SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS* = 11 ## Generated based on /usr/include/openssl/ssl.h:1275:10
  else:
    let SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS* = 11 ## Generated based on /usr/include/openssl/ssl.h:1275:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TOTAL_RENEGOTIATIONS):
  when 12 is static:
    const
      SSL_CTRL_GET_TOTAL_RENEGOTIATIONS* = 12 ## Generated based on /usr/include/openssl/ssl.h:1276:10
  else:
    let SSL_CTRL_GET_TOTAL_RENEGOTIATIONS* = 12 ## Generated based on /usr/include/openssl/ssl.h:1276:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TOTAL_RENEGOTIATIONS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_FLAGS):
  when 13 is static:
    const
      SSL_CTRL_GET_FLAGS* = 13 ## Generated based on /usr/include/openssl/ssl.h:1277:10
  else:
    let SSL_CTRL_GET_FLAGS* = 13 ## Generated based on /usr/include/openssl/ssl.h:1277:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_FLAGS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_EXTRA_CHAIN_CERT):
  when 14 is static:
    const
      SSL_CTRL_EXTRA_CHAIN_CERT* = 14 ## Generated based on /usr/include/openssl/ssl.h:1278:10
  else:
    let SSL_CTRL_EXTRA_CHAIN_CERT* = 14 ## Generated based on /usr/include/openssl/ssl.h:1278:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_EXTRA_CHAIN_CERT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MSG_CALLBACK):
  when 15 is static:
    const
      SSL_CTRL_SET_MSG_CALLBACK* = 15 ## Generated based on /usr/include/openssl/ssl.h:1279:10
  else:
    let SSL_CTRL_SET_MSG_CALLBACK* = 15 ## Generated based on /usr/include/openssl/ssl.h:1279:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MSG_CALLBACK" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MSG_CALLBACK_ARG):
  when 16 is static:
    const
      SSL_CTRL_SET_MSG_CALLBACK_ARG* = 16 ## Generated based on /usr/include/openssl/ssl.h:1280:10
  else:
    let SSL_CTRL_SET_MSG_CALLBACK_ARG* = 16 ## Generated based on /usr/include/openssl/ssl.h:1280:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MSG_CALLBACK_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MTU):
  when 17 is static:
    const
      SSL_CTRL_SET_MTU* = 17 ## Generated based on /usr/include/openssl/ssl.h:1282:10
  else:
    let SSL_CTRL_SET_MTU* = 17 ## Generated based on /usr/include/openssl/ssl.h:1282:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MTU" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_NUMBER):
  when 20 is static:
    const
      SSL_CTRL_SESS_NUMBER* = 20 ## Generated based on /usr/include/openssl/ssl.h:1284:10
  else:
    let SSL_CTRL_SESS_NUMBER* = 20 ## Generated based on /usr/include/openssl/ssl.h:1284:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_NUMBER" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_CONNECT):
  when 21 is static:
    const
      SSL_CTRL_SESS_CONNECT* = 21 ## Generated based on /usr/include/openssl/ssl.h:1285:10
  else:
    let SSL_CTRL_SESS_CONNECT* = 21 ## Generated based on /usr/include/openssl/ssl.h:1285:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_CONNECT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_CONNECT_GOOD):
  when 22 is static:
    const
      SSL_CTRL_SESS_CONNECT_GOOD* = 22 ## Generated based on /usr/include/openssl/ssl.h:1286:10
  else:
    let SSL_CTRL_SESS_CONNECT_GOOD* = 22 ## Generated based on /usr/include/openssl/ssl.h:1286:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_CONNECT_GOOD" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_CONNECT_RENEGOTIATE):
  when 23 is static:
    const
      SSL_CTRL_SESS_CONNECT_RENEGOTIATE* = 23 ## Generated based on /usr/include/openssl/ssl.h:1287:10
  else:
    let SSL_CTRL_SESS_CONNECT_RENEGOTIATE* = 23 ## Generated based on /usr/include/openssl/ssl.h:1287:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_CONNECT_RENEGOTIATE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_ACCEPT):
  when 24 is static:
    const
      SSL_CTRL_SESS_ACCEPT* = 24 ## Generated based on /usr/include/openssl/ssl.h:1288:10
  else:
    let SSL_CTRL_SESS_ACCEPT* = 24 ## Generated based on /usr/include/openssl/ssl.h:1288:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_ACCEPT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_ACCEPT_GOOD):
  when 25 is static:
    const
      SSL_CTRL_SESS_ACCEPT_GOOD* = 25 ## Generated based on /usr/include/openssl/ssl.h:1289:10
  else:
    let SSL_CTRL_SESS_ACCEPT_GOOD* = 25 ## Generated based on /usr/include/openssl/ssl.h:1289:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_ACCEPT_GOOD" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_ACCEPT_RENEGOTIATE):
  when 26 is static:
    const
      SSL_CTRL_SESS_ACCEPT_RENEGOTIATE* = 26 ## Generated based on /usr/include/openssl/ssl.h:1290:10
  else:
    let SSL_CTRL_SESS_ACCEPT_RENEGOTIATE* = 26 ## Generated based on /usr/include/openssl/ssl.h:1290:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_ACCEPT_RENEGOTIATE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_HIT):
  when 27 is static:
    const
      SSL_CTRL_SESS_HIT* = 27 ## Generated based on /usr/include/openssl/ssl.h:1291:10
  else:
    let SSL_CTRL_SESS_HIT* = 27 ## Generated based on /usr/include/openssl/ssl.h:1291:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_HIT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_CB_HIT):
  when 28 is static:
    const
      SSL_CTRL_SESS_CB_HIT* = 28 ## Generated based on /usr/include/openssl/ssl.h:1292:10
  else:
    let SSL_CTRL_SESS_CB_HIT* = 28 ## Generated based on /usr/include/openssl/ssl.h:1292:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_CB_HIT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_MISSES):
  when 29 is static:
    const
      SSL_CTRL_SESS_MISSES* = 29 ## Generated based on /usr/include/openssl/ssl.h:1293:10
  else:
    let SSL_CTRL_SESS_MISSES* = 29 ## Generated based on /usr/include/openssl/ssl.h:1293:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_MISSES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_TIMEOUTS):
  when 30 is static:
    const
      SSL_CTRL_SESS_TIMEOUTS* = 30 ## Generated based on /usr/include/openssl/ssl.h:1294:10
  else:
    let SSL_CTRL_SESS_TIMEOUTS* = 30 ## Generated based on /usr/include/openssl/ssl.h:1294:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_TIMEOUTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SESS_CACHE_FULL):
  when 31 is static:
    const
      SSL_CTRL_SESS_CACHE_FULL* = 31 ## Generated based on /usr/include/openssl/ssl.h:1295:10
  else:
    let SSL_CTRL_SESS_CACHE_FULL* = 31 ## Generated based on /usr/include/openssl/ssl.h:1295:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SESS_CACHE_FULL" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_MODE):
  when 33 is static:
    const
      SSL_CTRL_MODE* = 33    ## Generated based on /usr/include/openssl/ssl.h:1296:10
  else:
    let SSL_CTRL_MODE* = 33  ## Generated based on /usr/include/openssl/ssl.h:1296:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_MODE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_READ_AHEAD):
  when 40 is static:
    const
      SSL_CTRL_GET_READ_AHEAD* = 40 ## Generated based on /usr/include/openssl/ssl.h:1297:10
  else:
    let SSL_CTRL_GET_READ_AHEAD* = 40 ## Generated based on /usr/include/openssl/ssl.h:1297:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_READ_AHEAD" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_READ_AHEAD):
  when 41 is static:
    const
      SSL_CTRL_SET_READ_AHEAD* = 41 ## Generated based on /usr/include/openssl/ssl.h:1298:10
  else:
    let SSL_CTRL_SET_READ_AHEAD* = 41 ## Generated based on /usr/include/openssl/ssl.h:1298:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_READ_AHEAD" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SESS_CACHE_SIZE):
  when 42 is static:
    const
      SSL_CTRL_SET_SESS_CACHE_SIZE* = 42 ## Generated based on /usr/include/openssl/ssl.h:1299:10
  else:
    let SSL_CTRL_SET_SESS_CACHE_SIZE* = 42 ## Generated based on /usr/include/openssl/ssl.h:1299:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SESS_CACHE_SIZE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_SESS_CACHE_SIZE):
  when 43 is static:
    const
      SSL_CTRL_GET_SESS_CACHE_SIZE* = 43 ## Generated based on /usr/include/openssl/ssl.h:1300:10
  else:
    let SSL_CTRL_GET_SESS_CACHE_SIZE* = 43 ## Generated based on /usr/include/openssl/ssl.h:1300:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_SESS_CACHE_SIZE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SESS_CACHE_MODE):
  when 44 is static:
    const
      SSL_CTRL_SET_SESS_CACHE_MODE* = 44 ## Generated based on /usr/include/openssl/ssl.h:1301:10
  else:
    let SSL_CTRL_SET_SESS_CACHE_MODE* = 44 ## Generated based on /usr/include/openssl/ssl.h:1301:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SESS_CACHE_MODE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_SESS_CACHE_MODE):
  when 45 is static:
    const
      SSL_CTRL_GET_SESS_CACHE_MODE* = 45 ## Generated based on /usr/include/openssl/ssl.h:1302:10
  else:
    let SSL_CTRL_GET_SESS_CACHE_MODE* = 45 ## Generated based on /usr/include/openssl/ssl.h:1302:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_SESS_CACHE_MODE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_MAX_CERT_LIST):
  when 50 is static:
    const
      SSL_CTRL_GET_MAX_CERT_LIST* = 50 ## Generated based on /usr/include/openssl/ssl.h:1303:10
  else:
    let SSL_CTRL_GET_MAX_CERT_LIST* = 50 ## Generated based on /usr/include/openssl/ssl.h:1303:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_MAX_CERT_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MAX_CERT_LIST):
  when 51 is static:
    const
      SSL_CTRL_SET_MAX_CERT_LIST* = 51 ## Generated based on /usr/include/openssl/ssl.h:1304:10
  else:
    let SSL_CTRL_SET_MAX_CERT_LIST* = 51 ## Generated based on /usr/include/openssl/ssl.h:1304:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MAX_CERT_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MAX_SEND_FRAGMENT):
  when 52 is static:
    const
      SSL_CTRL_SET_MAX_SEND_FRAGMENT* = 52 ## Generated based on /usr/include/openssl/ssl.h:1305:10
  else:
    let SSL_CTRL_SET_MAX_SEND_FRAGMENT* = 52 ## Generated based on /usr/include/openssl/ssl.h:1305:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MAX_SEND_FRAGMENT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_SERVERNAME_CB):
  when 53 is static:
    const
      SSL_CTRL_SET_TLSEXT_SERVERNAME_CB* = 53 ## Generated based on /usr/include/openssl/ssl.h:1307:10
  else:
    let SSL_CTRL_SET_TLSEXT_SERVERNAME_CB* = 53 ## Generated based on /usr/include/openssl/ssl.h:1307:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_SERVERNAME_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG):
  when 54 is static:
    const
      SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG* = 54 ## Generated based on /usr/include/openssl/ssl.h:1308:10
  else:
    let SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG* = 54 ## Generated based on /usr/include/openssl/ssl.h:1308:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_HOSTNAME):
  when 55 is static:
    const
      SSL_CTRL_SET_TLSEXT_HOSTNAME* = 55 ## Generated based on /usr/include/openssl/ssl.h:1309:10
  else:
    let SSL_CTRL_SET_TLSEXT_HOSTNAME* = 55 ## Generated based on /usr/include/openssl/ssl.h:1309:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_HOSTNAME" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_DEBUG_CB):
  when 56 is static:
    const
      SSL_CTRL_SET_TLSEXT_DEBUG_CB* = 56 ## Generated based on /usr/include/openssl/ssl.h:1310:10
  else:
    let SSL_CTRL_SET_TLSEXT_DEBUG_CB* = 56 ## Generated based on /usr/include/openssl/ssl.h:1310:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_DEBUG_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_DEBUG_ARG):
  when 57 is static:
    const
      SSL_CTRL_SET_TLSEXT_DEBUG_ARG* = 57 ## Generated based on /usr/include/openssl/ssl.h:1311:10
  else:
    let SSL_CTRL_SET_TLSEXT_DEBUG_ARG* = 57 ## Generated based on /usr/include/openssl/ssl.h:1311:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_DEBUG_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_TICKET_KEYS):
  when 58 is static:
    const
      SSL_CTRL_GET_TLSEXT_TICKET_KEYS* = 58 ## Generated based on /usr/include/openssl/ssl.h:1312:10
  else:
    let SSL_CTRL_GET_TLSEXT_TICKET_KEYS* = 58 ## Generated based on /usr/include/openssl/ssl.h:1312:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_TICKET_KEYS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_TICKET_KEYS):
  when 59 is static:
    const
      SSL_CTRL_SET_TLSEXT_TICKET_KEYS* = 59 ## Generated based on /usr/include/openssl/ssl.h:1313:10
  else:
    let SSL_CTRL_SET_TLSEXT_TICKET_KEYS* = 59 ## Generated based on /usr/include/openssl/ssl.h:1313:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_TICKET_KEYS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB):
  when 63 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB* = 63 ## Generated based on /usr/include/openssl/ssl.h:1317:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB* = 63 ## Generated based on /usr/include/openssl/ssl.h:1317:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG):
  when 64 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG* = 64 ## Generated based on /usr/include/openssl/ssl.h:1318:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG* = 64 ## Generated based on /usr/include/openssl/ssl.h:1318:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE):
  when 65 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE* = 65 ## Generated based on /usr/include/openssl/ssl.h:1319:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE* = 65 ## Generated based on /usr/include/openssl/ssl.h:1319:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS):
  when 66 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS* = 66 ## Generated based on /usr/include/openssl/ssl.h:1320:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS* = 66 ## Generated based on /usr/include/openssl/ssl.h:1320:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS):
  when 67 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS* = 67 ## Generated based on /usr/include/openssl/ssl.h:1321:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS* = 67 ## Generated based on /usr/include/openssl/ssl.h:1321:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS):
  when 68 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS* = 68 ## Generated based on /usr/include/openssl/ssl.h:1322:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS* = 68 ## Generated based on /usr/include/openssl/ssl.h:1322:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS):
  when 69 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS* = 69 ## Generated based on /usr/include/openssl/ssl.h:1323:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS* = 69 ## Generated based on /usr/include/openssl/ssl.h:1323:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP):
  when 70 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP* = 70 ## Generated based on /usr/include/openssl/ssl.h:1324:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP* = 70 ## Generated based on /usr/include/openssl/ssl.h:1324:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP):
  when 71 is static:
    const
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP* = 71 ## Generated based on /usr/include/openssl/ssl.h:1325:10
  else:
    let SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP* = 71 ## Generated based on /usr/include/openssl/ssl.h:1325:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB):
  when 72 is static:
    const
      SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB* = 72 ## Generated based on /usr/include/openssl/ssl.h:1327:11
  else:
    let SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB* = 72 ## Generated based on /usr/include/openssl/ssl.h:1327:11
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB):
  when 75 is static:
    const
      SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB* = 75 ## Generated based on /usr/include/openssl/ssl.h:1329:10
  else:
    let SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB* = 75 ## Generated based on /usr/include/openssl/ssl.h:1329:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SRP_VERIFY_PARAM_CB):
  when 76 is static:
    const
      SSL_CTRL_SET_SRP_VERIFY_PARAM_CB* = 76 ## Generated based on /usr/include/openssl/ssl.h:1330:10
  else:
    let SSL_CTRL_SET_SRP_VERIFY_PARAM_CB* = 76 ## Generated based on /usr/include/openssl/ssl.h:1330:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SRP_VERIFY_PARAM_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB):
  when 77 is static:
    const
      SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB* = 77 ## Generated based on /usr/include/openssl/ssl.h:1331:10
  else:
    let SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB* = 77 ## Generated based on /usr/include/openssl/ssl.h:1331:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SRP_ARG):
  when 78 is static:
    const
      SSL_CTRL_SET_SRP_ARG* = 78 ## Generated based on /usr/include/openssl/ssl.h:1332:10
  else:
    let SSL_CTRL_SET_SRP_ARG* = 78 ## Generated based on /usr/include/openssl/ssl.h:1332:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SRP_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLS_EXT_SRP_USERNAME):
  when 79 is static:
    const
      SSL_CTRL_SET_TLS_EXT_SRP_USERNAME* = 79 ## Generated based on /usr/include/openssl/ssl.h:1333:10
  else:
    let SSL_CTRL_SET_TLS_EXT_SRP_USERNAME* = 79 ## Generated based on /usr/include/openssl/ssl.h:1333:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLS_EXT_SRP_USERNAME" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH):
  when 80 is static:
    const
      SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH* = 80 ## Generated based on /usr/include/openssl/ssl.h:1334:10
  else:
    let SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH* = 80 ## Generated based on /usr/include/openssl/ssl.h:1334:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD):
  when 81 is static:
    const
      SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD* = 81 ## Generated based on /usr/include/openssl/ssl.h:1335:10
  else:
    let SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD* = 81 ## Generated based on /usr/include/openssl/ssl.h:1335:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD" &
        " already exists, not redeclaring")
when not declared(DTLS_CTRL_GET_TIMEOUT):
  when 73 is static:
    const
      DTLS_CTRL_GET_TIMEOUT* = 73 ## Generated based on /usr/include/openssl/ssl.h:1336:10
  else:
    let DTLS_CTRL_GET_TIMEOUT* = 73 ## Generated based on /usr/include/openssl/ssl.h:1336:10
else:
  static :
    hint("Declaration of " & "DTLS_CTRL_GET_TIMEOUT" &
        " already exists, not redeclaring")
when not declared(DTLS_CTRL_HANDLE_TIMEOUT):
  when 74 is static:
    const
      DTLS_CTRL_HANDLE_TIMEOUT* = 74 ## Generated based on /usr/include/openssl/ssl.h:1337:10
  else:
    let DTLS_CTRL_HANDLE_TIMEOUT* = 74 ## Generated based on /usr/include/openssl/ssl.h:1337:10
else:
  static :
    hint("Declaration of " & "DTLS_CTRL_HANDLE_TIMEOUT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_RI_SUPPORT):
  when 76 is static:
    const
      SSL_CTRL_GET_RI_SUPPORT* = 76 ## Generated based on /usr/include/openssl/ssl.h:1338:10
  else:
    let SSL_CTRL_GET_RI_SUPPORT* = 76 ## Generated based on /usr/include/openssl/ssl.h:1338:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_RI_SUPPORT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CLEAR_MODE):
  when 78 is static:
    const
      SSL_CTRL_CLEAR_MODE* = 78 ## Generated based on /usr/include/openssl/ssl.h:1339:10
  else:
    let SSL_CTRL_CLEAR_MODE* = 78 ## Generated based on /usr/include/openssl/ssl.h:1339:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CLEAR_MODE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB):
  when 79 is static:
    const
      SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB* = 79 ## Generated based on /usr/include/openssl/ssl.h:1340:10
  else:
    let SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB* = 79 ## Generated based on /usr/include/openssl/ssl.h:1340:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_EXTRA_CHAIN_CERTS):
  when 82 is static:
    const
      SSL_CTRL_GET_EXTRA_CHAIN_CERTS* = 82 ## Generated based on /usr/include/openssl/ssl.h:1341:10
  else:
    let SSL_CTRL_GET_EXTRA_CHAIN_CERTS* = 82 ## Generated based on /usr/include/openssl/ssl.h:1341:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_EXTRA_CHAIN_CERTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS):
  when 83 is static:
    const
      SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS* = 83 ## Generated based on /usr/include/openssl/ssl.h:1342:10
  else:
    let SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS* = 83 ## Generated based on /usr/include/openssl/ssl.h:1342:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CHAIN):
  when 88 is static:
    const
      SSL_CTRL_CHAIN* = 88   ## Generated based on /usr/include/openssl/ssl.h:1343:10
  else:
    let SSL_CTRL_CHAIN* = 88 ## Generated based on /usr/include/openssl/ssl.h:1343:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CHAIN" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CHAIN_CERT):
  when 89 is static:
    const
      SSL_CTRL_CHAIN_CERT* = 89 ## Generated based on /usr/include/openssl/ssl.h:1344:10
  else:
    let SSL_CTRL_CHAIN_CERT* = 89 ## Generated based on /usr/include/openssl/ssl.h:1344:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CHAIN_CERT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_GROUPS):
  when 90 is static:
    const
      SSL_CTRL_GET_GROUPS* = 90 ## Generated based on /usr/include/openssl/ssl.h:1345:10
  else:
    let SSL_CTRL_GET_GROUPS* = 90 ## Generated based on /usr/include/openssl/ssl.h:1345:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_GROUPS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_GROUPS):
  when 91 is static:
    const
      SSL_CTRL_SET_GROUPS* = 91 ## Generated based on /usr/include/openssl/ssl.h:1346:10
  else:
    let SSL_CTRL_SET_GROUPS* = 91 ## Generated based on /usr/include/openssl/ssl.h:1346:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_GROUPS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_GROUPS_LIST):
  when 92 is static:
    const
      SSL_CTRL_SET_GROUPS_LIST* = 92 ## Generated based on /usr/include/openssl/ssl.h:1347:10
  else:
    let SSL_CTRL_SET_GROUPS_LIST* = 92 ## Generated based on /usr/include/openssl/ssl.h:1347:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_GROUPS_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_SHARED_GROUP):
  when 93 is static:
    const
      SSL_CTRL_GET_SHARED_GROUP* = 93 ## Generated based on /usr/include/openssl/ssl.h:1348:10
  else:
    let SSL_CTRL_GET_SHARED_GROUP* = 93 ## Generated based on /usr/include/openssl/ssl.h:1348:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_SHARED_GROUP" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SIGALGS):
  when 97 is static:
    const
      SSL_CTRL_SET_SIGALGS* = 97 ## Generated based on /usr/include/openssl/ssl.h:1349:10
  else:
    let SSL_CTRL_SET_SIGALGS* = 97 ## Generated based on /usr/include/openssl/ssl.h:1349:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SIGALGS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SIGALGS_LIST):
  when 98 is static:
    const
      SSL_CTRL_SET_SIGALGS_LIST* = 98 ## Generated based on /usr/include/openssl/ssl.h:1350:10
  else:
    let SSL_CTRL_SET_SIGALGS_LIST* = 98 ## Generated based on /usr/include/openssl/ssl.h:1350:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SIGALGS_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CERT_FLAGS):
  when 99 is static:
    const
      SSL_CTRL_CERT_FLAGS* = 99 ## Generated based on /usr/include/openssl/ssl.h:1351:10
  else:
    let SSL_CTRL_CERT_FLAGS* = 99 ## Generated based on /usr/include/openssl/ssl.h:1351:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CERT_FLAGS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_CLEAR_CERT_FLAGS):
  when 100 is static:
    const
      SSL_CTRL_CLEAR_CERT_FLAGS* = 100 ## Generated based on /usr/include/openssl/ssl.h:1352:10
  else:
    let SSL_CTRL_CLEAR_CERT_FLAGS* = 100 ## Generated based on /usr/include/openssl/ssl.h:1352:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_CLEAR_CERT_FLAGS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CLIENT_SIGALGS):
  when 101 is static:
    const
      SSL_CTRL_SET_CLIENT_SIGALGS* = 101 ## Generated based on /usr/include/openssl/ssl.h:1353:10
  else:
    let SSL_CTRL_SET_CLIENT_SIGALGS* = 101 ## Generated based on /usr/include/openssl/ssl.h:1353:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CLIENT_SIGALGS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CLIENT_SIGALGS_LIST):
  when 102 is static:
    const
      SSL_CTRL_SET_CLIENT_SIGALGS_LIST* = 102 ## Generated based on /usr/include/openssl/ssl.h:1354:10
  else:
    let SSL_CTRL_SET_CLIENT_SIGALGS_LIST* = 102 ## Generated based on /usr/include/openssl/ssl.h:1354:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CLIENT_SIGALGS_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_CLIENT_CERT_TYPES):
  when 103 is static:
    const
      SSL_CTRL_GET_CLIENT_CERT_TYPES* = 103 ## Generated based on /usr/include/openssl/ssl.h:1355:10
  else:
    let SSL_CTRL_GET_CLIENT_CERT_TYPES* = 103 ## Generated based on /usr/include/openssl/ssl.h:1355:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_CLIENT_CERT_TYPES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CLIENT_CERT_TYPES):
  when 104 is static:
    const
      SSL_CTRL_SET_CLIENT_CERT_TYPES* = 104 ## Generated based on /usr/include/openssl/ssl.h:1356:10
  else:
    let SSL_CTRL_SET_CLIENT_CERT_TYPES* = 104 ## Generated based on /usr/include/openssl/ssl.h:1356:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CLIENT_CERT_TYPES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_BUILD_CERT_CHAIN):
  when 105 is static:
    const
      SSL_CTRL_BUILD_CERT_CHAIN* = 105 ## Generated based on /usr/include/openssl/ssl.h:1357:10
  else:
    let SSL_CTRL_BUILD_CERT_CHAIN* = 105 ## Generated based on /usr/include/openssl/ssl.h:1357:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_BUILD_CERT_CHAIN" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_VERIFY_CERT_STORE):
  when 106 is static:
    const
      SSL_CTRL_SET_VERIFY_CERT_STORE* = 106 ## Generated based on /usr/include/openssl/ssl.h:1358:10
  else:
    let SSL_CTRL_SET_VERIFY_CERT_STORE* = 106 ## Generated based on /usr/include/openssl/ssl.h:1358:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_VERIFY_CERT_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CHAIN_CERT_STORE):
  when 107 is static:
    const
      SSL_CTRL_SET_CHAIN_CERT_STORE* = 107 ## Generated based on /usr/include/openssl/ssl.h:1359:10
  else:
    let SSL_CTRL_SET_CHAIN_CERT_STORE* = 107 ## Generated based on /usr/include/openssl/ssl.h:1359:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CHAIN_CERT_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_PEER_SIGNATURE_NID):
  when 108 is static:
    const
      SSL_CTRL_GET_PEER_SIGNATURE_NID* = 108 ## Generated based on /usr/include/openssl/ssl.h:1360:10
  else:
    let SSL_CTRL_GET_PEER_SIGNATURE_NID* = 108 ## Generated based on /usr/include/openssl/ssl.h:1360:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_PEER_SIGNATURE_NID" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_PEER_TMP_KEY):
  when 109 is static:
    const
      SSL_CTRL_GET_PEER_TMP_KEY* = 109 ## Generated based on /usr/include/openssl/ssl.h:1361:10
  else:
    let SSL_CTRL_GET_PEER_TMP_KEY* = 109 ## Generated based on /usr/include/openssl/ssl.h:1361:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_PEER_TMP_KEY" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_RAW_CIPHERLIST):
  when 110 is static:
    const
      SSL_CTRL_GET_RAW_CIPHERLIST* = 110 ## Generated based on /usr/include/openssl/ssl.h:1362:10
  else:
    let SSL_CTRL_GET_RAW_CIPHERLIST* = 110 ## Generated based on /usr/include/openssl/ssl.h:1362:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_RAW_CIPHERLIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_EC_POINT_FORMATS):
  when 111 is static:
    const
      SSL_CTRL_GET_EC_POINT_FORMATS* = 111 ## Generated based on /usr/include/openssl/ssl.h:1363:10
  else:
    let SSL_CTRL_GET_EC_POINT_FORMATS* = 111 ## Generated based on /usr/include/openssl/ssl.h:1363:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_EC_POINT_FORMATS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_CHAIN_CERTS):
  when 115 is static:
    const
      SSL_CTRL_GET_CHAIN_CERTS* = 115 ## Generated based on /usr/include/openssl/ssl.h:1364:10
  else:
    let SSL_CTRL_GET_CHAIN_CERTS* = 115 ## Generated based on /usr/include/openssl/ssl.h:1364:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_CHAIN_CERTS" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SELECT_CURRENT_CERT):
  when 116 is static:
    const
      SSL_CTRL_SELECT_CURRENT_CERT* = 116 ## Generated based on /usr/include/openssl/ssl.h:1365:10
  else:
    let SSL_CTRL_SELECT_CURRENT_CERT* = 116 ## Generated based on /usr/include/openssl/ssl.h:1365:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SELECT_CURRENT_CERT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CURRENT_CERT):
  when 117 is static:
    const
      SSL_CTRL_SET_CURRENT_CERT* = 117 ## Generated based on /usr/include/openssl/ssl.h:1366:10
  else:
    let SSL_CTRL_SET_CURRENT_CERT* = 117 ## Generated based on /usr/include/openssl/ssl.h:1366:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CURRENT_CERT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_DH_AUTO):
  when 118 is static:
    const
      SSL_CTRL_SET_DH_AUTO* = 118 ## Generated based on /usr/include/openssl/ssl.h:1367:10
  else:
    let SSL_CTRL_SET_DH_AUTO* = 118 ## Generated based on /usr/include/openssl/ssl.h:1367:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_DH_AUTO" &
        " already exists, not redeclaring")
when not declared(DTLS_CTRL_SET_LINK_MTU):
  when 120 is static:
    const
      DTLS_CTRL_SET_LINK_MTU* = 120 ## Generated based on /usr/include/openssl/ssl.h:1368:10
  else:
    let DTLS_CTRL_SET_LINK_MTU* = 120 ## Generated based on /usr/include/openssl/ssl.h:1368:10
else:
  static :
    hint("Declaration of " & "DTLS_CTRL_SET_LINK_MTU" &
        " already exists, not redeclaring")
when not declared(DTLS_CTRL_GET_LINK_MIN_MTU):
  when 121 is static:
    const
      DTLS_CTRL_GET_LINK_MIN_MTU* = 121 ## Generated based on /usr/include/openssl/ssl.h:1369:10
  else:
    let DTLS_CTRL_GET_LINK_MIN_MTU* = 121 ## Generated based on /usr/include/openssl/ssl.h:1369:10
else:
  static :
    hint("Declaration of " & "DTLS_CTRL_GET_LINK_MIN_MTU" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_EXTMS_SUPPORT):
  when 122 is static:
    const
      SSL_CTRL_GET_EXTMS_SUPPORT* = 122 ## Generated based on /usr/include/openssl/ssl.h:1370:10
  else:
    let SSL_CTRL_GET_EXTMS_SUPPORT* = 122 ## Generated based on /usr/include/openssl/ssl.h:1370:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_EXTMS_SUPPORT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MIN_PROTO_VERSION):
  when 123 is static:
    const
      SSL_CTRL_SET_MIN_PROTO_VERSION* = 123 ## Generated based on /usr/include/openssl/ssl.h:1371:10
  else:
    let SSL_CTRL_SET_MIN_PROTO_VERSION* = 123 ## Generated based on /usr/include/openssl/ssl.h:1371:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MIN_PROTO_VERSION" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MAX_PROTO_VERSION):
  when 124 is static:
    const
      SSL_CTRL_SET_MAX_PROTO_VERSION* = 124 ## Generated based on /usr/include/openssl/ssl.h:1372:10
  else:
    let SSL_CTRL_SET_MAX_PROTO_VERSION* = 124 ## Generated based on /usr/include/openssl/ssl.h:1372:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MAX_PROTO_VERSION" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_SPLIT_SEND_FRAGMENT):
  when 125 is static:
    const
      SSL_CTRL_SET_SPLIT_SEND_FRAGMENT* = 125 ## Generated based on /usr/include/openssl/ssl.h:1373:10
  else:
    let SSL_CTRL_SET_SPLIT_SEND_FRAGMENT* = 125 ## Generated based on /usr/include/openssl/ssl.h:1373:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_SPLIT_SEND_FRAGMENT" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_MAX_PIPELINES):
  when 126 is static:
    const
      SSL_CTRL_SET_MAX_PIPELINES* = 126 ## Generated based on /usr/include/openssl/ssl.h:1374:10
  else:
    let SSL_CTRL_SET_MAX_PIPELINES* = 126 ## Generated based on /usr/include/openssl/ssl.h:1374:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_MAX_PIPELINES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE):
  when 127 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE* = 127 ## Generated based on /usr/include/openssl/ssl.h:1375:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE* = 127 ## Generated based on /usr/include/openssl/ssl.h:1375:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB):
  when 128 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB* = 128 ## Generated based on /usr/include/openssl/ssl.h:1376:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB* = 128 ## Generated based on /usr/include/openssl/ssl.h:1376:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG):
  when 129 is static:
    const
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG* = 129 ## Generated based on /usr/include/openssl/ssl.h:1377:10
  else:
    let SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG* = 129 ## Generated based on /usr/include/openssl/ssl.h:1377:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_MIN_PROTO_VERSION):
  when 130 is static:
    const
      SSL_CTRL_GET_MIN_PROTO_VERSION* = 130 ## Generated based on /usr/include/openssl/ssl.h:1378:10
  else:
    let SSL_CTRL_GET_MIN_PROTO_VERSION* = 130 ## Generated based on /usr/include/openssl/ssl.h:1378:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_MIN_PROTO_VERSION" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_MAX_PROTO_VERSION):
  when 131 is static:
    const
      SSL_CTRL_GET_MAX_PROTO_VERSION* = 131 ## Generated based on /usr/include/openssl/ssl.h:1379:10
  else:
    let SSL_CTRL_GET_MAX_PROTO_VERSION* = 131 ## Generated based on /usr/include/openssl/ssl.h:1379:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_MAX_PROTO_VERSION" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_SIGNATURE_NID):
  when 132 is static:
    const
      SSL_CTRL_GET_SIGNATURE_NID* = 132 ## Generated based on /usr/include/openssl/ssl.h:1380:10
  else:
    let SSL_CTRL_GET_SIGNATURE_NID* = 132 ## Generated based on /usr/include/openssl/ssl.h:1380:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_SIGNATURE_NID" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_TMP_KEY):
  when 133 is static:
    const
      SSL_CTRL_GET_TMP_KEY* = 133 ## Generated based on /usr/include/openssl/ssl.h:1381:10
  else:
    let SSL_CTRL_GET_TMP_KEY* = 133 ## Generated based on /usr/include/openssl/ssl.h:1381:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_TMP_KEY" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_NEGOTIATED_GROUP):
  when 134 is static:
    const
      SSL_CTRL_GET_NEGOTIATED_GROUP* = 134 ## Generated based on /usr/include/openssl/ssl.h:1382:10
  else:
    let SSL_CTRL_GET_NEGOTIATED_GROUP* = 134 ## Generated based on /usr/include/openssl/ssl.h:1382:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_NEGOTIATED_GROUP" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_RETRY_VERIFY):
  when 136 is static:
    const
      SSL_CTRL_SET_RETRY_VERIFY* = 136 ## Generated based on /usr/include/openssl/ssl.h:1383:10
  else:
    let SSL_CTRL_SET_RETRY_VERIFY* = 136 ## Generated based on /usr/include/openssl/ssl.h:1383:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_RETRY_VERIFY" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_VERIFY_CERT_STORE):
  when 137 is static:
    const
      SSL_CTRL_GET_VERIFY_CERT_STORE* = 137 ## Generated based on /usr/include/openssl/ssl.h:1384:10
  else:
    let SSL_CTRL_GET_VERIFY_CERT_STORE* = 137 ## Generated based on /usr/include/openssl/ssl.h:1384:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_VERIFY_CERT_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_CHAIN_CERT_STORE):
  when 138 is static:
    const
      SSL_CTRL_GET_CHAIN_CERT_STORE* = 138 ## Generated based on /usr/include/openssl/ssl.h:1385:10
  else:
    let SSL_CTRL_GET_CHAIN_CERT_STORE* = 138 ## Generated based on /usr/include/openssl/ssl.h:1385:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_CHAIN_CERT_STORE" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_SET_FIRST):
  when 1 is static:
    const
      SSL_CERT_SET_FIRST* = 1 ## Generated based on /usr/include/openssl/ssl.h:1386:10
  else:
    let SSL_CERT_SET_FIRST* = 1 ## Generated based on /usr/include/openssl/ssl.h:1386:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_SET_FIRST" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_SET_NEXT):
  when 2 is static:
    const
      SSL_CERT_SET_NEXT* = 2 ## Generated based on /usr/include/openssl/ssl.h:1387:10
  else:
    let SSL_CERT_SET_NEXT* = 2 ## Generated based on /usr/include/openssl/ssl.h:1387:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_SET_NEXT" &
        " already exists, not redeclaring")
when not declared(SSL_CERT_SET_SERVER):
  when 3 is static:
    const
      SSL_CERT_SET_SERVER* = 3 ## Generated based on /usr/include/openssl/ssl.h:1388:10
  else:
    let SSL_CERT_SET_SERVER* = 3 ## Generated based on /usr/include/openssl/ssl.h:1388:10
else:
  static :
    hint("Declaration of " & "SSL_CERT_SET_SERVER" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_CURVES):
  when SSL_CTRL_GET_GROUPS is typedesc:
    type
      SSL_CTRL_GET_CURVES* = SSL_CTRL_GET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1567:10
  else:
    when SSL_CTRL_GET_GROUPS is static:
      const
        SSL_CTRL_GET_CURVES* = SSL_CTRL_GET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1567:10
    else:
      let SSL_CTRL_GET_CURVES* = SSL_CTRL_GET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1567:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_CURVES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CURVES):
  when SSL_CTRL_SET_GROUPS is typedesc:
    type
      SSL_CTRL_SET_CURVES* = SSL_CTRL_SET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1568:10
  else:
    when SSL_CTRL_SET_GROUPS is static:
      const
        SSL_CTRL_SET_CURVES* = SSL_CTRL_SET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1568:10
    else:
      let SSL_CTRL_SET_CURVES* = SSL_CTRL_SET_GROUPS ## Generated based on /usr/include/openssl/ssl.h:1568:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CURVES" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_SET_CURVES_LIST):
  when SSL_CTRL_SET_GROUPS_LIST is typedesc:
    type
      SSL_CTRL_SET_CURVES_LIST* = SSL_CTRL_SET_GROUPS_LIST ## Generated based on /usr/include/openssl/ssl.h:1569:10
  else:
    when SSL_CTRL_SET_GROUPS_LIST is static:
      const
        SSL_CTRL_SET_CURVES_LIST* = SSL_CTRL_SET_GROUPS_LIST ## Generated based on /usr/include/openssl/ssl.h:1569:10
    else:
      let SSL_CTRL_SET_CURVES_LIST* = SSL_CTRL_SET_GROUPS_LIST ## Generated based on /usr/include/openssl/ssl.h:1569:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_SET_CURVES_LIST" &
        " already exists, not redeclaring")
when not declared(SSL_CTRL_GET_SHARED_CURVE):
  when SSL_CTRL_GET_SHARED_GROUP is typedesc:
    type
      SSL_CTRL_GET_SHARED_CURVE* = SSL_CTRL_GET_SHARED_GROUP ## Generated based on /usr/include/openssl/ssl.h:1570:10
  else:
    when SSL_CTRL_GET_SHARED_GROUP is static:
      const
        SSL_CTRL_GET_SHARED_CURVE* = SSL_CTRL_GET_SHARED_GROUP ## Generated based on /usr/include/openssl/ssl.h:1570:10
    else:
      let SSL_CTRL_GET_SHARED_CURVE* = SSL_CTRL_GET_SHARED_GROUP ## Generated based on /usr/include/openssl/ssl.h:1570:10
else:
  static :
    hint("Declaration of " & "SSL_CTRL_GET_SHARED_CURVE" &
        " already exists, not redeclaring")
when not declared(SSL_get1_curves):
  when SSL_get1_groups is typedesc:
    type
      SSL_get1_curves* = SSL_get1_groups ## Generated based on /usr/include/openssl/ssl.h:1572:10
  else:
    when SSL_get1_groups is static:
      const
        SSL_get1_curves* = SSL_get1_groups ## Generated based on /usr/include/openssl/ssl.h:1572:10
    else:
      let SSL_get1_curves* = SSL_get1_groups ## Generated based on /usr/include/openssl/ssl.h:1572:10
else:
  static :
    hint("Declaration of " & "SSL_get1_curves" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_curves):
  when SSL_CTX_set1_groups is typedesc:
    type
      SSL_CTX_set1_curves* = SSL_CTX_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1573:10
  else:
    when SSL_CTX_set1_groups is static:
      const
        SSL_CTX_set1_curves* = SSL_CTX_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1573:10
    else:
      let SSL_CTX_set1_curves* = SSL_CTX_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1573:10
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_curves" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_curves_list):
  when SSL_CTX_set1_groups_list is typedesc:
    type
      SSL_CTX_set1_curves_list* = SSL_CTX_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1574:10
  else:
    when SSL_CTX_set1_groups_list is static:
      const
        SSL_CTX_set1_curves_list* = SSL_CTX_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1574:10
    else:
      let SSL_CTX_set1_curves_list* = SSL_CTX_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1574:10
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_curves_list" &
        " already exists, not redeclaring")
when not declared(SSL_set1_curves):
  when SSL_set1_groups is typedesc:
    type
      SSL_set1_curves* = SSL_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1575:10
  else:
    when SSL_set1_groups is static:
      const
        SSL_set1_curves* = SSL_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1575:10
    else:
      let SSL_set1_curves* = SSL_set1_groups ## Generated based on /usr/include/openssl/ssl.h:1575:10
else:
  static :
    hint("Declaration of " & "SSL_set1_curves" &
        " already exists, not redeclaring")
when not declared(SSL_set1_curves_list):
  when SSL_set1_groups_list is typedesc:
    type
      SSL_set1_curves_list* = SSL_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1576:10
  else:
    when SSL_set1_groups_list is static:
      const
        SSL_set1_curves_list* = SSL_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1576:10
    else:
      let SSL_set1_curves_list* = SSL_set1_groups_list ## Generated based on /usr/include/openssl/ssl.h:1576:10
else:
  static :
    hint("Declaration of " & "SSL_set1_curves_list" &
        " already exists, not redeclaring")
when not declared(SSL_get_shared_curve):
  when SSL_get_shared_group is typedesc:
    type
      SSL_get_shared_curve* = SSL_get_shared_group ## Generated based on /usr/include/openssl/ssl.h:1577:10
  else:
    when SSL_get_shared_group is static:
      const
        SSL_get_shared_curve* = SSL_get_shared_group ## Generated based on /usr/include/openssl/ssl.h:1577:10
    else:
      let SSL_get_shared_curve* = SSL_get_shared_group ## Generated based on /usr/include/openssl/ssl.h:1577:10
else:
  static :
    hint("Declaration of " & "SSL_get_shared_curve" &
        " already exists, not redeclaring")
when not declared(SSL_SERVERINFOV1):
  when 1 is static:
    const
      SSL_SERVERINFOV1* = 1  ## Generated based on /usr/include/openssl/ssl.h:1676:10
  else:
    let SSL_SERVERINFOV1* = 1 ## Generated based on /usr/include/openssl/ssl.h:1676:10
else:
  static :
    hint("Declaration of " & "SSL_SERVERINFOV1" &
        " already exists, not redeclaring")
when not declared(SSL_SERVERINFOV2):
  when 2 is static:
    const
      SSL_SERVERINFOV2* = 2  ## Generated based on /usr/include/openssl/ssl.h:1677:10
  else:
    let SSL_SERVERINFOV2* = 2 ## Generated based on /usr/include/openssl/ssl.h:1677:10
else:
  static :
    hint("Declaration of " & "SSL_SERVERINFOV2" &
        " already exists, not redeclaring")
when not declared(SSL_get1_peer_certificate):
  proc SSL_get1_peer_certificate*(s: ptr SSL_536871704): ptr X509_536871716 {.
      cdecl, importc: "SSL_get1_peer_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_get1_peer_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_CLIENT_HELLO_SUCCESS):
  when 1 is static:
    const
      SSL_CLIENT_HELLO_SUCCESS* = 1 ## Generated based on /usr/include/openssl/ssl.h:1920:10
  else:
    let SSL_CLIENT_HELLO_SUCCESS* = 1 ## Generated based on /usr/include/openssl/ssl.h:1920:10
else:
  static :
    hint("Declaration of " & "SSL_CLIENT_HELLO_SUCCESS" &
        " already exists, not redeclaring")
when not declared(SSL_CLIENT_HELLO_ERROR):
  when 0 is static:
    const
      SSL_CLIENT_HELLO_ERROR* = 0 ## Generated based on /usr/include/openssl/ssl.h:1921:10
  else:
    let SSL_CLIENT_HELLO_ERROR* = 0 ## Generated based on /usr/include/openssl/ssl.h:1921:10
else:
  static :
    hint("Declaration of " & "SSL_CLIENT_HELLO_ERROR" &
        " already exists, not redeclaring")
when not declared(SSL_CLIENT_HELLO_RETRY):
  when -1 is static:
    const
      SSL_CLIENT_HELLO_RETRY* = -1 ## Generated based on /usr/include/openssl/ssl.h:1922:10
  else:
    let SSL_CLIENT_HELLO_RETRY* = -1 ## Generated based on /usr/include/openssl/ssl.h:1922:10
else:
  static :
    hint("Declaration of " & "SSL_CLIENT_HELLO_RETRY" &
        " already exists, not redeclaring")
when not declared(SSL_READ_EARLY_DATA_ERROR):
  when 0 is static:
    const
      SSL_READ_EARLY_DATA_ERROR* = 0 ## Generated based on /usr/include/openssl/ssl.h:1962:10
  else:
    let SSL_READ_EARLY_DATA_ERROR* = 0 ## Generated based on /usr/include/openssl/ssl.h:1962:10
else:
  static :
    hint("Declaration of " & "SSL_READ_EARLY_DATA_ERROR" &
        " already exists, not redeclaring")
when not declared(SSL_READ_EARLY_DATA_SUCCESS):
  when 1 is static:
    const
      SSL_READ_EARLY_DATA_SUCCESS* = 1 ## Generated based on /usr/include/openssl/ssl.h:1963:10
  else:
    let SSL_READ_EARLY_DATA_SUCCESS* = 1 ## Generated based on /usr/include/openssl/ssl.h:1963:10
else:
  static :
    hint("Declaration of " & "SSL_READ_EARLY_DATA_SUCCESS" &
        " already exists, not redeclaring")
when not declared(SSL_READ_EARLY_DATA_FINISH):
  when 2 is static:
    const
      SSL_READ_EARLY_DATA_FINISH* = 2 ## Generated based on /usr/include/openssl/ssl.h:1964:10
  else:
    let SSL_READ_EARLY_DATA_FINISH* = 2 ## Generated based on /usr/include/openssl/ssl.h:1964:10
else:
  static :
    hint("Declaration of " & "SSL_READ_EARLY_DATA_FINISH" &
        " already exists, not redeclaring")
when not declared(SSL_EARLY_DATA_NOT_SENT):
  when 0 is static:
    const
      SSL_EARLY_DATA_NOT_SENT* = 0 ## Generated based on /usr/include/openssl/ssl.h:1981:10
  else:
    let SSL_EARLY_DATA_NOT_SENT* = 0 ## Generated based on /usr/include/openssl/ssl.h:1981:10
else:
  static :
    hint("Declaration of " & "SSL_EARLY_DATA_NOT_SENT" &
        " already exists, not redeclaring")
when not declared(SSL_EARLY_DATA_REJECTED):
  when 1 is static:
    const
      SSL_EARLY_DATA_REJECTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:1982:10
  else:
    let SSL_EARLY_DATA_REJECTED* = 1 ## Generated based on /usr/include/openssl/ssl.h:1982:10
else:
  static :
    hint("Declaration of " & "SSL_EARLY_DATA_REJECTED" &
        " already exists, not redeclaring")
when not declared(SSL_EARLY_DATA_ACCEPTED):
  when 2 is static:
    const
      SSL_EARLY_DATA_ACCEPTED* = 2 ## Generated based on /usr/include/openssl/ssl.h:1983:10
  else:
    let SSL_EARLY_DATA_ACCEPTED* = 2 ## Generated based on /usr/include/openssl/ssl.h:1983:10
else:
  static :
    hint("Declaration of " & "SSL_EARLY_DATA_ACCEPTED" &
        " already exists, not redeclaring")
when not declared(TLS_method):
  proc TLS_method*(): ptr SSL_METHOD_536871680 {.cdecl, importc: "TLS_method".}
else:
  static :
    hint("Declaration of " & "TLS_method" & " already exists, not redeclaring")
when not declared(TLS_server_method):
  proc TLS_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLS_server_method".}
else:
  static :
    hint("Declaration of " & "TLS_server_method" &
        " already exists, not redeclaring")
when not declared(TLS_client_method):
  proc TLS_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLS_client_method".}
else:
  static :
    hint("Declaration of " & "TLS_client_method" &
        " already exists, not redeclaring")
when not declared(SSL_get_session):
  proc SSL_get_session*(ssl: ptr SSL_536871704): ptr SSL_SESSION_536871684 {.
      cdecl, importc: "SSL_get_session".}
else:
  static :
    hint("Declaration of " & "SSL_get_session" &
        " already exists, not redeclaring")
when not declared(SSL_SECOP_OTHER_TYPE):
  when 4294901760 is static:
    const
      SSL_SECOP_OTHER_TYPE* = 4294901760'i64 ## Generated based on /usr/include/openssl/ssl.h:2432:10
  else:
    let SSL_SECOP_OTHER_TYPE* = 4294901760'i64 ## Generated based on /usr/include/openssl/ssl.h:2432:10
else:
  static :
    hint("Declaration of " & "SSL_SECOP_OTHER_TYPE" &
        " already exists, not redeclaring")
when not declared(SSL_SECOP_OTHER_NONE):
  when 0 is static:
    const
      SSL_SECOP_OTHER_NONE* = 0 ## Generated based on /usr/include/openssl/ssl.h:2433:10
  else:
    let SSL_SECOP_OTHER_NONE* = 0 ## Generated based on /usr/include/openssl/ssl.h:2433:10
else:
  static :
    hint("Declaration of " & "SSL_SECOP_OTHER_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_SECOP_PEER):
  when 4096 is static:
    const
      SSL_SECOP_PEER* = 4096 ## Generated based on /usr/include/openssl/ssl.h:2442:10
  else:
    let SSL_SECOP_PEER* = 4096 ## Generated based on /usr/include/openssl/ssl.h:2442:10
else:
  static :
    hint("Declaration of " & "SSL_SECOP_PEER" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_NO_LOAD_SSL_STRINGS):
  when cast[clong](1048576'i64) is static:
    const
      OPENSSL_INIT_NO_LOAD_SSL_STRINGS* = cast[clong](1048576'i64) ## Generated based on /usr/include/openssl/ssl.h:2517:10
  else:
    let OPENSSL_INIT_NO_LOAD_SSL_STRINGS* = cast[clong](1048576'i64) ## Generated based on /usr/include/openssl/ssl.h:2517:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_NO_LOAD_SSL_STRINGS" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_LOAD_SSL_STRINGS):
  when cast[clong](2097152'i64) is static:
    const
      OPENSSL_INIT_LOAD_SSL_STRINGS* = cast[clong](2097152'i64) ## Generated based on /usr/include/openssl/ssl.h:2518:10
  else:
    let OPENSSL_INIT_LOAD_SSL_STRINGS* = cast[clong](2097152'i64) ## Generated based on /usr/include/openssl/ssl.h:2518:10
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_LOAD_SSL_STRINGS" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_FATAL_ERR_MALLOC):
  when 0 is static:
    const
      SSL_TICKET_FATAL_ERR_MALLOC* = 0 ## Generated based on /usr/include/openssl/ssl.h:2538:10
  else:
    let SSL_TICKET_FATAL_ERR_MALLOC* = 0 ## Generated based on /usr/include/openssl/ssl.h:2538:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_FATAL_ERR_MALLOC" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_FATAL_ERR_OTHER):
  when 1 is static:
    const
      SSL_TICKET_FATAL_ERR_OTHER* = 1 ## Generated based on /usr/include/openssl/ssl.h:2540:10
  else:
    let SSL_TICKET_FATAL_ERR_OTHER* = 1 ## Generated based on /usr/include/openssl/ssl.h:2540:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_FATAL_ERR_OTHER" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_NONE):
  when 2 is static:
    const
      SSL_TICKET_NONE* = 2   ## Generated based on /usr/include/openssl/ssl.h:2542:10
  else:
    let SSL_TICKET_NONE* = 2 ## Generated based on /usr/include/openssl/ssl.h:2542:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_NONE" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_EMPTY):
  when 3 is static:
    const
      SSL_TICKET_EMPTY* = 3  ## Generated based on /usr/include/openssl/ssl.h:2544:10
  else:
    let SSL_TICKET_EMPTY* = 3 ## Generated based on /usr/include/openssl/ssl.h:2544:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_EMPTY" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_NO_DECRYPT):
  when 4 is static:
    const
      SSL_TICKET_NO_DECRYPT* = 4 ## Generated based on /usr/include/openssl/ssl.h:2546:10
  else:
    let SSL_TICKET_NO_DECRYPT* = 4 ## Generated based on /usr/include/openssl/ssl.h:2546:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_NO_DECRYPT" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_SUCCESS):
  when 5 is static:
    const
      SSL_TICKET_SUCCESS* = 5 ## Generated based on /usr/include/openssl/ssl.h:2548:10
  else:
    let SSL_TICKET_SUCCESS* = 5 ## Generated based on /usr/include/openssl/ssl.h:2548:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_SUCCESS" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_SUCCESS_RENEW):
  when 6 is static:
    const
      SSL_TICKET_SUCCESS_RENEW* = 6 ## Generated based on /usr/include/openssl/ssl.h:2550:10
  else:
    let SSL_TICKET_SUCCESS_RENEW* = 6 ## Generated based on /usr/include/openssl/ssl.h:2550:10
else:
  static :
    hint("Declaration of " & "SSL_TICKET_SUCCESS_RENEW" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN_ABORT):
  when 0 is static:
    const
      SSL_TICKET_RETURN_ABORT* = 0 ## Generated based on /usr/include/openssl/ssl.h:2556:9
  else:
    let SSL_TICKET_RETURN_ABORT* = 0 ## Generated based on /usr/include/openssl/ssl.h:2556:9
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN_ABORT" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN_IGNORE):
  when 1 is static:
    const
      SSL_TICKET_RETURN_IGNORE* = 1 ## Generated based on /usr/include/openssl/ssl.h:2558:9
  else:
    let SSL_TICKET_RETURN_IGNORE* = 1 ## Generated based on /usr/include/openssl/ssl.h:2558:9
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN_IGNORE" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN_IGNORE_RENEW):
  when 2 is static:
    const
      SSL_TICKET_RETURN_IGNORE_RENEW* = 2 ## Generated based on /usr/include/openssl/ssl.h:2560:9
  else:
    let SSL_TICKET_RETURN_IGNORE_RENEW* = 2 ## Generated based on /usr/include/openssl/ssl.h:2560:9
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN_IGNORE_RENEW" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN_USE):
  when 3 is static:
    const
      SSL_TICKET_RETURN_USE* = 3 ## Generated based on /usr/include/openssl/ssl.h:2562:9
  else:
    let SSL_TICKET_RETURN_USE* = 3 ## Generated based on /usr/include/openssl/ssl.h:2562:9
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN_USE" &
        " already exists, not redeclaring")
when not declared(SSL_TICKET_RETURN_USE_RENEW):
  when 4 is static:
    const
      SSL_TICKET_RETURN_USE_RENEW* = 4 ## Generated based on /usr/include/openssl/ssl.h:2564:9
  else:
    let SSL_TICKET_RETURN_USE_RENEW* = 4 ## Generated based on /usr/include/openssl/ssl.h:2564:9
else:
  static :
    hint("Declaration of " & "SSL_TICKET_RETURN_USE_RENEW" &
        " already exists, not redeclaring")
when not declared(RAND_DRBG_STRENGTH):
  when 256 is static:
    const
      RAND_DRBG_STRENGTH* = 256 ## Generated based on /usr/include/openssl/rand.h:37:10
  else:
    let RAND_DRBG_STRENGTH* = 256 ## Generated based on /usr/include/openssl/rand.h:37:10
else:
  static :
    hint("Declaration of " & "RAND_DRBG_STRENGTH" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_init_settings):
  proc lsquic_engine_init_settings*(a0: ptr struct_lsquic_engine_settings_536871433;
                                    lsquic_engine_flags: cuint): void {.cdecl,
      importc: "lsquic_engine_init_settings".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_init_settings" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_check_settings):
  proc lsquic_engine_check_settings*(settings: ptr struct_lsquic_engine_settings_536871433;
                                     lsquic_engine_flags: cuint;
                                     err_buf: cstring; err_buf_sz: csize_t): cint {.
      cdecl, importc: "lsquic_engine_check_settings".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_check_settings" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_get_conns_count):
  proc lsquic_engine_get_conns_count*(engine: ptr lsquic_engine_t_536871409): cuint {.
      cdecl, importc: "lsquic_engine_get_conns_count".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_get_conns_count" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_new):
  proc lsquic_engine_new*(lsquic_engine_flags: cuint;
                          api: ptr struct_lsquic_engine_api_536871460): ptr lsquic_engine_t_536871409 {.
      cdecl, importc: "lsquic_engine_new".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_new" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_connect):
  proc lsquic_engine_connect*(a0: ptr lsquic_engine_t_536871409;
                              a1: enum_lsquic_version_536871423;
                              local_sa: ptr struct_sockaddr;
                              peer_sa: ptr struct_sockaddr; peer_ctx: pointer;
                              conn_ctx: ptr lsquic_conn_ctx_t_536871413;
                              hostname: cstring; base_plpmtu: cushort;
                              sess_resume: ptr uint8; sess_resume_len: csize_t;
                              token: ptr uint8; token_sz: csize_t): ptr lsquic_conn_t_536871411 {.
      cdecl, importc: "lsquic_engine_connect".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_connect" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_packet_in):
  proc lsquic_engine_packet_in*(a0: ptr lsquic_engine_t_536871409;
                                packet_in_data: ptr uint8;
                                packet_in_size: csize_t;
                                sa_local: ptr struct_sockaddr;
                                sa_peer: ptr struct_sockaddr; peer_ctx: pointer;
                                ecn: cint): cint {.cdecl,
      importc: "lsquic_engine_packet_in".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_packet_in" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_process_conns):
  proc lsquic_engine_process_conns*(engine: ptr lsquic_engine_t_536871409): void {.
      cdecl, importc: "lsquic_engine_process_conns".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_process_conns" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_has_unsent_packets):
  proc lsquic_engine_has_unsent_packets*(engine: ptr lsquic_engine_t_536871409): cint {.
      cdecl, importc: "lsquic_engine_has_unsent_packets".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_has_unsent_packets" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_send_unsent_packets):
  proc lsquic_engine_send_unsent_packets*(engine: ptr lsquic_engine_t_536871409): void {.
      cdecl, importc: "lsquic_engine_send_unsent_packets".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_send_unsent_packets" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_destroy):
  proc lsquic_engine_destroy*(a0: ptr lsquic_engine_t_536871409): void {.cdecl,
      importc: "lsquic_engine_destroy".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_destroy" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_n_avail_streams):
  proc lsquic_conn_n_avail_streams*(a0: ptr lsquic_conn_t_536871411): cuint {.
      cdecl, importc: "lsquic_conn_n_avail_streams".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_n_avail_streams" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_make_stream):
  proc lsquic_conn_make_stream*(a0: ptr lsquic_conn_t_536871411): void {.cdecl,
      importc: "lsquic_conn_make_stream".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_make_stream" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_n_pending_streams):
  proc lsquic_conn_n_pending_streams*(a0: ptr lsquic_conn_t_536871411): cuint {.
      cdecl, importc: "lsquic_conn_n_pending_streams".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_n_pending_streams" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_cancel_pending_streams):
  proc lsquic_conn_cancel_pending_streams*(a0: ptr lsquic_conn_t_536871411;
      n: cuint): cuint {.cdecl, importc: "lsquic_conn_cancel_pending_streams".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_cancel_pending_streams" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_going_away):
  proc lsquic_conn_going_away*(a0: ptr lsquic_conn_t_536871411): void {.cdecl,
      importc: "lsquic_conn_going_away".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_going_away" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_close):
  proc lsquic_conn_close*(a0: ptr lsquic_conn_t_536871411): void {.cdecl,
      importc: "lsquic_conn_close".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_close" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_wantread):
  proc lsquic_stream_wantread*(s: ptr lsquic_stream_t_536871415; is_want: cint): cint {.
      cdecl, importc: "lsquic_stream_wantread".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_wantread" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_read):
  proc lsquic_stream_read*(s: ptr lsquic_stream_t_536871415; buf: pointer;
                           len: csize_t): ssize_t_536871429 {.cdecl,
      importc: "lsquic_stream_read".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_read" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_readv):
  proc lsquic_stream_readv*(s: ptr lsquic_stream_t_536871415;
                            vec: ptr struct_iovec_536871437; iovcnt: cint): ssize_t_536871429 {.
      cdecl, importc: "lsquic_stream_readv".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_readv" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_readf):
  proc lsquic_stream_readf*(s: ptr lsquic_stream_t_536871415; readf: proc (
      a0: pointer; a1: ptr uint8; a2: csize_t; a3: cint): csize_t {.cdecl.};
                            ctx: pointer): ssize_t_536871429 {.cdecl,
      importc: "lsquic_stream_readf".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_readf" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_wantwrite):
  proc lsquic_stream_wantwrite*(s: ptr lsquic_stream_t_536871415; is_want: cint): cint {.
      cdecl, importc: "lsquic_stream_wantwrite".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_wantwrite" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_write):
  proc lsquic_stream_write*(s: ptr lsquic_stream_t_536871415; buf: pointer;
                            len: csize_t): ssize_t_536871429 {.cdecl,
      importc: "lsquic_stream_write".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_write" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_writev):
  proc lsquic_stream_writev*(s: ptr lsquic_stream_t_536871415;
                             vec: ptr struct_iovec_536871437; count: cint): ssize_t_536871429 {.
      cdecl, importc: "lsquic_stream_writev".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_writev" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_pwritev):
  proc lsquic_stream_pwritev*(s: ptr lsquic_stream_t_536871415; preadv: proc (
      a0: pointer; a1: ptr struct_iovec_536871437; a2: cint): ssize_t_536871429 {.
      cdecl.}; user_data: pointer; n_to_write: csize_t): ssize_t_536871429 {.
      cdecl, importc: "lsquic_stream_pwritev".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_pwritev" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_writef):
  proc lsquic_stream_writef*(a0: ptr lsquic_stream_t_536871415;
                             a1: ptr struct_lsquic_reader_536871462): ssize_t_536871429 {.
      cdecl, importc: "lsquic_stream_writef".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_writef" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_flush):
  proc lsquic_stream_flush*(s: ptr lsquic_stream_t_536871415): cint {.cdecl,
      importc: "lsquic_stream_flush".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_flush" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_send_headers):
  proc lsquic_stream_send_headers*(s: ptr lsquic_stream_t_536871415;
                                   headers: ptr lsquic_http_headers_t_536871419;
                                   eos: cint): cint {.cdecl,
      importc: "lsquic_stream_send_headers".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_send_headers" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_get_hset):
  proc lsquic_stream_get_hset*(a0: ptr lsquic_stream_t_536871415): pointer {.
      cdecl, importc: "lsquic_stream_get_hset".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_get_hset" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_push_stream):
  proc lsquic_conn_push_stream*(c: ptr lsquic_conn_t_536871411;
                                hdr_set: pointer; s: ptr lsquic_stream_t_536871415;
                                headers: ptr lsquic_http_headers_t_536871419): cint {.
      cdecl, importc: "lsquic_conn_push_stream".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_push_stream" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_is_push_enabled):
  proc lsquic_conn_is_push_enabled*(a0: ptr lsquic_conn_t_536871411): cint {.
      cdecl, importc: "lsquic_conn_is_push_enabled".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_is_push_enabled" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_shutdown):
  proc lsquic_stream_shutdown*(s: ptr lsquic_stream_t_536871415; how: cint): cint {.
      cdecl, importc: "lsquic_stream_shutdown".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_shutdown" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_close):
  proc lsquic_stream_close*(s: ptr lsquic_stream_t_536871415): cint {.cdecl,
      importc: "lsquic_stream_close".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_close" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_has_unacked_data):
  proc lsquic_stream_has_unacked_data*(s: ptr lsquic_stream_t_536871415): cint {.
      cdecl, importc: "lsquic_stream_has_unacked_data".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_has_unacked_data" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_server_cert_chain):
  proc lsquic_conn_get_server_cert_chain*(a0: ptr lsquic_conn_t_536871411): ptr struct_stack_st_X509 {.
      cdecl, importc: "lsquic_conn_get_server_cert_chain".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_server_cert_chain" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_id):
  proc lsquic_stream_id*(s: ptr lsquic_stream_t_536871415): lsquic_stream_id_t_536871407 {.
      cdecl, importc: "lsquic_stream_id".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_id" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_get_ctx):
  proc lsquic_stream_get_ctx*(s: ptr lsquic_stream_t_536871415): ptr lsquic_stream_ctx_t_536871417 {.
      cdecl, importc: "lsquic_stream_get_ctx".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_get_ctx" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_set_ctx):
  proc lsquic_stream_set_ctx*(stream: ptr lsquic_stream_t_536871415;
                              ctx: ptr lsquic_stream_ctx_t_536871417): void {.
      cdecl, importc: "lsquic_stream_set_ctx".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_set_ctx" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_is_pushed):
  proc lsquic_stream_is_pushed*(s: ptr lsquic_stream_t_536871415): cint {.cdecl,
      importc: "lsquic_stream_is_pushed".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_is_pushed" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_is_rejected):
  proc lsquic_stream_is_rejected*(s: ptr lsquic_stream_t_536871415): cint {.
      cdecl, importc: "lsquic_stream_is_rejected".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_is_rejected" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_refuse_push):
  proc lsquic_stream_refuse_push*(s: ptr lsquic_stream_t_536871415): cint {.
      cdecl, importc: "lsquic_stream_refuse_push".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_refuse_push" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_push_info):
  proc lsquic_stream_push_info*(a0: ptr lsquic_stream_t_536871415;
                                ref_stream_id: ptr lsquic_stream_id_t_536871407;
                                hdr_set: ptr pointer): cint {.cdecl,
      importc: "lsquic_stream_push_info".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_push_info" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_priority):
  proc lsquic_stream_priority*(s: ptr lsquic_stream_t_536871415): cuint {.cdecl,
      importc: "lsquic_stream_priority".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_priority" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_set_priority):
  proc lsquic_stream_set_priority*(s: ptr lsquic_stream_t_536871415;
                                   priority: cuint): cint {.cdecl,
      importc: "lsquic_stream_set_priority".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_set_priority" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_get_http_prio):
  proc lsquic_stream_get_http_prio*(a0: ptr lsquic_stream_t_536871415;
                                    a1: ptr struct_lsquic_ext_http_prio_536871464): cint {.
      cdecl, importc: "lsquic_stream_get_http_prio".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_get_http_prio" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_set_http_prio):
  proc lsquic_stream_set_http_prio*(a0: ptr lsquic_stream_t_536871415;
                                    a1: ptr struct_lsquic_ext_http_prio_536871464): cint {.
      cdecl, importc: "lsquic_stream_set_http_prio".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_set_http_prio" &
        " already exists, not redeclaring")
when not declared(lsquic_stream_conn):
  proc lsquic_stream_conn*(s: ptr lsquic_stream_t_536871415): ptr lsquic_conn_t_536871411 {.
      cdecl, importc: "lsquic_stream_conn".}
else:
  static :
    hint("Declaration of " & "lsquic_stream_conn" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_id):
  proc lsquic_conn_id*(c: ptr lsquic_conn_t_536871411): ptr lsquic_cid_t_536871405 {.
      cdecl, importc: "lsquic_conn_id".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_id" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_engine):
  proc lsquic_conn_get_engine*(c: ptr lsquic_conn_t_536871411): ptr lsquic_engine_t_536871409 {.
      cdecl, importc: "lsquic_conn_get_engine".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_engine" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_sockaddr):
  proc lsquic_conn_get_sockaddr*(c: ptr lsquic_conn_t_536871411;
                                 local: ptr ptr struct_sockaddr;
                                 peer: ptr ptr struct_sockaddr): cint {.cdecl,
      importc: "lsquic_conn_get_sockaddr".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_sockaddr" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_want_datagram_write):
  proc lsquic_conn_want_datagram_write*(a0: ptr lsquic_conn_t_536871411;
                                        is_want: cint): cint {.cdecl,
      importc: "lsquic_conn_want_datagram_write".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_want_datagram_write" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_min_datagram_size):
  proc lsquic_conn_get_min_datagram_size*(a0: ptr lsquic_conn_t_536871411): csize_t {.
      cdecl, importc: "lsquic_conn_get_min_datagram_size".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_min_datagram_size" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_set_min_datagram_size):
  proc lsquic_conn_set_min_datagram_size*(a0: ptr lsquic_conn_t_536871411;
      sz: csize_t): cint {.cdecl, importc: "lsquic_conn_set_min_datagram_size".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_set_min_datagram_size" &
        " already exists, not redeclaring")
when not declared(lsquic_logger_init):
  proc lsquic_logger_init*(a0: ptr struct_lsquic_logger_if_536871466;
                           logger_ctx: pointer;
                           a2: enum_lsquic_logger_timestamp_style_536871468): void {.
      cdecl, importc: "lsquic_logger_init".}
else:
  static :
    hint("Declaration of " & "lsquic_logger_init" &
        " already exists, not redeclaring")
when not declared(lsquic_set_log_level):
  proc lsquic_set_log_level*(log_level: cstring): cint {.cdecl,
      importc: "lsquic_set_log_level".}
else:
  static :
    hint("Declaration of " & "lsquic_set_log_level" &
        " already exists, not redeclaring")
when not declared(lsquic_logger_lopt):
  proc lsquic_logger_lopt*(optarg: cstring): cint {.cdecl,
      importc: "lsquic_logger_lopt".}
else:
  static :
    hint("Declaration of " & "lsquic_logger_lopt" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_quic_versions):
  proc lsquic_engine_quic_versions*(a0: ptr lsquic_engine_t_536871409): cuint {.
      cdecl, importc: "lsquic_engine_quic_versions".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_quic_versions" &
        " already exists, not redeclaring")
when not declared(lsquic_global_init):
  proc lsquic_global_init*(flags: cint): cint {.cdecl,
      importc: "lsquic_global_init".}
else:
  static :
    hint("Declaration of " & "lsquic_global_init" &
        " already exists, not redeclaring")
when not declared(lsquic_global_cleanup):
  proc lsquic_global_cleanup*(): void {.cdecl, importc: "lsquic_global_cleanup".}
else:
  static :
    hint("Declaration of " & "lsquic_global_cleanup" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_quic_version):
  proc lsquic_conn_quic_version*(c: ptr lsquic_conn_t_536871411): enum_lsquic_version_536871423 {.
      cdecl, importc: "lsquic_conn_quic_version".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_quic_version" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_crypto_keysize):
  proc lsquic_conn_crypto_keysize*(c: ptr lsquic_conn_t_536871411): cint {.
      cdecl, importc: "lsquic_conn_crypto_keysize".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_crypto_keysize" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_crypto_alg_keysize):
  proc lsquic_conn_crypto_alg_keysize*(c: ptr lsquic_conn_t_536871411): cint {.
      cdecl, importc: "lsquic_conn_crypto_alg_keysize".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_crypto_alg_keysize" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_crypto_ver):
  proc lsquic_conn_crypto_ver*(c: ptr lsquic_conn_t_536871411): enum_lsquic_crypto_ver_536871470 {.
      cdecl, importc: "lsquic_conn_crypto_ver".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_crypto_ver" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_crypto_cipher):
  proc lsquic_conn_crypto_cipher*(c: ptr lsquic_conn_t_536871411): cstring {.
      cdecl, importc: "lsquic_conn_crypto_cipher".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_crypto_cipher" &
        " already exists, not redeclaring")
when not declared(lsquic_str2ver):
  proc lsquic_str2ver*(str: cstring; len: csize_t): enum_lsquic_version_536871423 {.
      cdecl, importc: "lsquic_str2ver".}
else:
  static :
    hint("Declaration of " & "lsquic_str2ver" &
        " already exists, not redeclaring")
when not declared(lsquic_alpn2ver):
  proc lsquic_alpn2ver*(alpn: cstring; len: csize_t): enum_lsquic_version_536871423 {.
      cdecl, importc: "lsquic_alpn2ver".}
else:
  static :
    hint("Declaration of " & "lsquic_alpn2ver" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_cooldown):
  proc lsquic_engine_cooldown*(a0: ptr lsquic_engine_t_536871409): void {.cdecl,
      importc: "lsquic_engine_cooldown".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_cooldown" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_ctx):
  proc lsquic_conn_get_ctx*(a0: ptr lsquic_conn_t_536871411): ptr lsquic_conn_ctx_t_536871413 {.
      cdecl, importc: "lsquic_conn_get_ctx".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_ctx" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_set_ctx):
  proc lsquic_conn_set_ctx*(a0: ptr lsquic_conn_t_536871411;
                            a1: ptr lsquic_conn_ctx_t_536871413): void {.cdecl,
      importc: "lsquic_conn_set_ctx".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_set_ctx" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_peer_ctx):
  proc lsquic_conn_get_peer_ctx*(a0: ptr lsquic_conn_t_536871411;
                                 local_sa: ptr struct_sockaddr): pointer {.
      cdecl, importc: "lsquic_conn_get_peer_ctx".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_peer_ctx" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_sni):
  proc lsquic_conn_get_sni*(a0: ptr lsquic_conn_t_536871411): cstring {.cdecl,
      importc: "lsquic_conn_get_sni".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_sni" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_abort):
  proc lsquic_conn_abort*(a0: ptr lsquic_conn_t_536871411): void {.cdecl,
      importc: "lsquic_conn_abort".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_abort" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_get_info):
  proc lsquic_conn_get_info*(conn: ptr lsquic_conn_t_536871411;
                             info: ptr struct_lsquic_conn_info_536871472): cint {.
      cdecl, importc: "lsquic_conn_get_info".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_get_info" &
        " already exists, not redeclaring")
when not declared(lsquic_get_alt_svc_versions):
  proc lsquic_get_alt_svc_versions*(versions: cuint): cstring {.cdecl,
      importc: "lsquic_get_alt_svc_versions".}
else:
  static :
    hint("Declaration of " & "lsquic_get_alt_svc_versions" &
        " already exists, not redeclaring")
when not declared(lsquic_get_h3_alpns):
  proc lsquic_get_h3_alpns*(versions: cuint): ptr cstring {.cdecl,
      importc: "lsquic_get_h3_alpns".}
else:
  static :
    hint("Declaration of " & "lsquic_get_h3_alpns" &
        " already exists, not redeclaring")
when not declared(lsquic_is_valid_hs_packet):
  proc lsquic_is_valid_hs_packet*(a0: ptr lsquic_engine_t_536871409;
                                  a1: ptr uint8; a2: csize_t): cint {.cdecl,
      importc: "lsquic_is_valid_hs_packet".}
else:
  static :
    hint("Declaration of " & "lsquic_is_valid_hs_packet" &
        " already exists, not redeclaring")
when not declared(lsquic_cid_from_packet):
  proc lsquic_cid_from_packet*(a0: ptr uint8; bufsz: csize_t;
                               cid: ptr lsquic_cid_t_536871405): cint {.cdecl,
      importc: "lsquic_cid_from_packet".}
else:
  static :
    hint("Declaration of " & "lsquic_cid_from_packet" &
        " already exists, not redeclaring")
when not declared(lsquic_dcid_from_packet):
  proc lsquic_dcid_from_packet*(a0: ptr uint8; bufsz: csize_t;
                                server_cid_len: cuint; cid_len: ptr uint8): cint {.
      cdecl, importc: "lsquic_dcid_from_packet".}
else:
  static :
    hint("Declaration of " & "lsquic_dcid_from_packet" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_earliest_adv_tick):
  proc lsquic_engine_earliest_adv_tick*(engine: ptr lsquic_engine_t_536871409;
                                        diff: ptr cint): cint {.cdecl,
      importc: "lsquic_engine_earliest_adv_tick".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_earliest_adv_tick" &
        " already exists, not redeclaring")
when not declared(lsquic_engine_count_attq):
  proc lsquic_engine_count_attq*(engine: ptr lsquic_engine_t_536871409;
                                 from_now: cint): cuint {.cdecl,
      importc: "lsquic_engine_count_attq".}
else:
  static :
    hint("Declaration of " & "lsquic_engine_count_attq" &
        " already exists, not redeclaring")
when not declared(lsquic_conn_status):
  proc lsquic_conn_status*(a0: ptr lsquic_conn_t_536871411; errbuf: cstring;
                           bufsz: csize_t): enum_LSQUIC_CONN_STATUS_536871474 {.
      cdecl, importc: "lsquic_conn_status".}
else:
  static :
    hint("Declaration of " & "lsquic_conn_status" &
        " already exists, not redeclaring")
when not declared(lsquic_ver2str):
  var lsquic_ver2str* {.importc: "lsquic_ver2str".}: array[8'i64, cstring]
else:
  static :
    hint("Declaration of " & "lsquic_ver2str" &
        " already exists, not redeclaring")
when not declared(lsquic_ssl_to_conn):
  proc lsquic_ssl_to_conn*(a0: ptr struct_ssl_st): ptr lsquic_conn_t_536871411 {.
      cdecl, importc: "lsquic_ssl_to_conn".}
else:
  static :
    hint("Declaration of " & "lsquic_ssl_to_conn" &
        " already exists, not redeclaring")
when not declared(lsquic_ssl_sess_to_resume_info):
  proc lsquic_ssl_sess_to_resume_info*(a0: ptr struct_ssl_st;
                                       a1: ptr struct_ssl_session_st;
                                       buf: ptr ptr uint8; buf_sz: ptr csize_t): cint {.
      cdecl, importc: "lsquic_ssl_sess_to_resume_info".}
else:
  static :
    hint("Declaration of " & "lsquic_ssl_sess_to_resume_info" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_lock_new):
  proc CRYPTO_THREAD_lock_new*(): pointer {.cdecl,
      importc: "CRYPTO_THREAD_lock_new".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_lock_new" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_read_lock):
  proc CRYPTO_THREAD_read_lock*(lock: pointer): cint {.cdecl,
      importc: "CRYPTO_THREAD_read_lock".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_read_lock" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_write_lock):
  proc CRYPTO_THREAD_write_lock*(lock: pointer): cint {.cdecl,
      importc: "CRYPTO_THREAD_write_lock".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_write_lock" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_unlock):
  proc CRYPTO_THREAD_unlock*(lock: pointer): cint {.cdecl,
      importc: "CRYPTO_THREAD_unlock".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_unlock" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_lock_free):
  proc CRYPTO_THREAD_lock_free*(lock: pointer): void {.cdecl,
      importc: "CRYPTO_THREAD_lock_free".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_lock_free" &
        " already exists, not redeclaring")
when not declared(CRYPTO_atomic_add):
  proc CRYPTO_atomic_add*(val: ptr cint; amount: cint; ret: ptr cint;
                          lock: pointer): cint {.cdecl,
      importc: "CRYPTO_atomic_add".}
else:
  static :
    hint("Declaration of " & "CRYPTO_atomic_add" &
        " already exists, not redeclaring")
when not declared(CRYPTO_atomic_or):
  proc CRYPTO_atomic_or*(val: ptr uint64; op: uint64; ret: ptr uint64;
                         lock: pointer): cint {.cdecl,
      importc: "CRYPTO_atomic_or".}
else:
  static :
    hint("Declaration of " & "CRYPTO_atomic_or" &
        " already exists, not redeclaring")
when not declared(CRYPTO_atomic_load):
  proc CRYPTO_atomic_load*(val: ptr uint64; ret: ptr uint64; lock: pointer): cint {.
      cdecl, importc: "CRYPTO_atomic_load".}
else:
  static :
    hint("Declaration of " & "CRYPTO_atomic_load" &
        " already exists, not redeclaring")
when not declared(OPENSSL_strlcpy):
  proc OPENSSL_strlcpy*(dst: cstring; src: cstring; siz: csize_t): csize_t {.
      cdecl, importc: "OPENSSL_strlcpy".}
else:
  static :
    hint("Declaration of " & "OPENSSL_strlcpy" &
        " already exists, not redeclaring")
when not declared(OPENSSL_strlcat):
  proc OPENSSL_strlcat*(dst: cstring; src: cstring; siz: csize_t): csize_t {.
      cdecl, importc: "OPENSSL_strlcat".}
else:
  static :
    hint("Declaration of " & "OPENSSL_strlcat" &
        " already exists, not redeclaring")
when not declared(OPENSSL_strnlen):
  proc OPENSSL_strnlen*(str: cstring; maxlen: csize_t): csize_t {.cdecl,
      importc: "OPENSSL_strnlen".}
else:
  static :
    hint("Declaration of " & "OPENSSL_strnlen" &
        " already exists, not redeclaring")
when not declared(OPENSSL_buf2hexstr_ex):
  proc OPENSSL_buf2hexstr_ex*(str: cstring; str_n: csize_t;
                              strlength: ptr csize_t; buf: ptr uint8;
                              buflen: csize_t; sep: cschar): cint {.cdecl,
      importc: "OPENSSL_buf2hexstr_ex".}
else:
  static :
    hint("Declaration of " & "OPENSSL_buf2hexstr_ex" &
        " already exists, not redeclaring")
when not declared(OPENSSL_buf2hexstr):
  proc OPENSSL_buf2hexstr*(buf: ptr uint8; buflen: clong): cstring {.cdecl,
      importc: "OPENSSL_buf2hexstr".}
else:
  static :
    hint("Declaration of " & "OPENSSL_buf2hexstr" &
        " already exists, not redeclaring")
when not declared(OPENSSL_hexstr2buf_ex):
  proc OPENSSL_hexstr2buf_ex*(buf: ptr uint8; buf_n: csize_t;
                              buflen: ptr csize_t; str: cstring; sep: cschar): cint {.
      cdecl, importc: "OPENSSL_hexstr2buf_ex".}
else:
  static :
    hint("Declaration of " & "OPENSSL_hexstr2buf_ex" &
        " already exists, not redeclaring")
when not declared(OPENSSL_hexstr2buf):
  proc OPENSSL_hexstr2buf*(str: cstring; buflen: ptr clong): ptr uint8 {.cdecl,
      importc: "OPENSSL_hexstr2buf".}
else:
  static :
    hint("Declaration of " & "OPENSSL_hexstr2buf" &
        " already exists, not redeclaring")
when not declared(OPENSSL_hexchar2int):
  proc OPENSSL_hexchar2int*(c: uint8): cint {.cdecl,
      importc: "OPENSSL_hexchar2int".}
else:
  static :
    hint("Declaration of " & "OPENSSL_hexchar2int" &
        " already exists, not redeclaring")
when not declared(OPENSSL_strcasecmp):
  proc OPENSSL_strcasecmp*(s1: cstring; s2: cstring): cint {.cdecl,
      importc: "OPENSSL_strcasecmp".}
else:
  static :
    hint("Declaration of " & "OPENSSL_strcasecmp" &
        " already exists, not redeclaring")
when not declared(OPENSSL_strncasecmp):
  proc OPENSSL_strncasecmp*(s1: cstring; s2: cstring; n: csize_t): cint {.cdecl,
      importc: "OPENSSL_strncasecmp".}
else:
  static :
    hint("Declaration of " & "OPENSSL_strncasecmp" &
        " already exists, not redeclaring")
when not declared(OPENSSL_version_major):
  proc OPENSSL_version_major*(): cuint {.cdecl, importc: "OPENSSL_version_major".}
else:
  static :
    hint("Declaration of " & "OPENSSL_version_major" &
        " already exists, not redeclaring")
when not declared(OPENSSL_version_minor):
  proc OPENSSL_version_minor*(): cuint {.cdecl, importc: "OPENSSL_version_minor".}
else:
  static :
    hint("Declaration of " & "OPENSSL_version_minor" &
        " already exists, not redeclaring")
when not declared(OPENSSL_version_patch):
  proc OPENSSL_version_patch*(): cuint {.cdecl, importc: "OPENSSL_version_patch".}
else:
  static :
    hint("Declaration of " & "OPENSSL_version_patch" &
        " already exists, not redeclaring")
when not declared(OPENSSL_version_pre_release):
  proc OPENSSL_version_pre_release*(): cstring {.cdecl,
      importc: "OPENSSL_version_pre_release".}
else:
  static :
    hint("Declaration of " & "OPENSSL_version_pre_release" &
        " already exists, not redeclaring")
when not declared(OPENSSL_version_build_metadata):
  proc OPENSSL_version_build_metadata*(): cstring {.cdecl,
      importc: "OPENSSL_version_build_metadata".}
else:
  static :
    hint("Declaration of " & "OPENSSL_version_build_metadata" &
        " already exists, not redeclaring")
when not declared(OPENSSL_info):
  proc OPENSSL_info*(type_arg: cint): cstring {.cdecl, importc: "OPENSSL_info".}
else:
  static :
    hint("Declaration of " & "OPENSSL_info" & " already exists, not redeclaring")
when not declared(OPENSSL_issetugid):
  proc OPENSSL_issetugid*(): cint {.cdecl, importc: "OPENSSL_issetugid".}
else:
  static :
    hint("Declaration of " & "OPENSSL_issetugid" &
        " already exists, not redeclaring")
when not declared(CRYPTO_get_ex_new_index):
  proc CRYPTO_get_ex_new_index*(class_index: cint; argl: clong; argp: pointer;
                                new_func: CRYPTO_EX_new_536871500;
                                dup_func: CRYPTO_EX_dup_536871506;
                                free_func: CRYPTO_EX_free_536871504): cint {.
      cdecl, importc: "CRYPTO_get_ex_new_index".}
else:
  static :
    hint("Declaration of " & "CRYPTO_get_ex_new_index" &
        " already exists, not redeclaring")
when not declared(CRYPTO_free_ex_index):
  proc CRYPTO_free_ex_index*(class_index: cint; idx: cint): cint {.cdecl,
      importc: "CRYPTO_free_ex_index".}
else:
  static :
    hint("Declaration of " & "CRYPTO_free_ex_index" &
        " already exists, not redeclaring")
when not declared(CRYPTO_new_ex_data):
  proc CRYPTO_new_ex_data*(class_index: cint; obj: pointer;
                           ad: ptr CRYPTO_EX_DATA_536871502): cint {.cdecl,
      importc: "CRYPTO_new_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_new_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_dup_ex_data):
  proc CRYPTO_dup_ex_data*(class_index: cint; to: ptr CRYPTO_EX_DATA_536871502;
                           from_arg: ptr CRYPTO_EX_DATA_536871502): cint {.
      cdecl, importc: "CRYPTO_dup_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_dup_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_free_ex_data):
  proc CRYPTO_free_ex_data*(class_index: cint; obj: pointer;
                            ad: ptr CRYPTO_EX_DATA_536871502): void {.cdecl,
      importc: "CRYPTO_free_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_free_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_alloc_ex_data):
  proc CRYPTO_alloc_ex_data*(class_index: cint; obj: pointer;
                             ad: ptr CRYPTO_EX_DATA_536871502; idx: cint): cint {.
      cdecl, importc: "CRYPTO_alloc_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_alloc_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_set_ex_data):
  proc CRYPTO_set_ex_data*(ad: ptr CRYPTO_EX_DATA_536871502; idx: cint;
                           val: pointer): cint {.cdecl,
      importc: "CRYPTO_set_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_set_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_get_ex_data):
  proc CRYPTO_get_ex_data*(ad: ptr CRYPTO_EX_DATA_536871502; idx: cint): pointer {.
      cdecl, importc: "CRYPTO_get_ex_data".}
else:
  static :
    hint("Declaration of " & "CRYPTO_get_ex_data" &
        " already exists, not redeclaring")
when not declared(CRYPTO_set_mem_functions):
  proc CRYPTO_set_mem_functions*(malloc_fn: CRYPTO_malloc_fn_536871512;
                                 realloc_fn: CRYPTO_realloc_fn_536871514;
                                 free_fn: CRYPTO_free_fn_536871516): cint {.
      cdecl, importc: "CRYPTO_set_mem_functions".}
else:
  static :
    hint("Declaration of " & "CRYPTO_set_mem_functions" &
        " already exists, not redeclaring")
when not declared(CRYPTO_get_mem_functions):
  proc CRYPTO_get_mem_functions*(malloc_fn: CRYPTO_malloc_fn_536871512;
                                 realloc_fn: CRYPTO_realloc_fn_536871514;
                                 free_fn: CRYPTO_free_fn_536871516): void {.
      cdecl, importc: "CRYPTO_get_mem_functions".}
else:
  static :
    hint("Declaration of " & "CRYPTO_get_mem_functions" &
        " already exists, not redeclaring")
when not declared(CRYPTO_malloc):
  proc CRYPTO_malloc*(num: csize_t; file: cstring; line: cint): pointer {.cdecl,
      importc: "CRYPTO_malloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_malloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_zalloc):
  proc CRYPTO_zalloc*(num: csize_t; file: cstring; line: cint): pointer {.cdecl,
      importc: "CRYPTO_zalloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_zalloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_memdup):
  proc CRYPTO_memdup*(str: pointer; siz: csize_t; file: cstring; line: cint): pointer {.
      cdecl, importc: "CRYPTO_memdup".}
else:
  static :
    hint("Declaration of " & "CRYPTO_memdup" &
        " already exists, not redeclaring")
when not declared(CRYPTO_strdup):
  proc CRYPTO_strdup*(str: cstring; file: cstring; line: cint): cstring {.cdecl,
      importc: "CRYPTO_strdup".}
else:
  static :
    hint("Declaration of " & "CRYPTO_strdup" &
        " already exists, not redeclaring")
when not declared(CRYPTO_strndup):
  proc CRYPTO_strndup*(str: cstring; s: csize_t; file: cstring; line: cint): cstring {.
      cdecl, importc: "CRYPTO_strndup".}
else:
  static :
    hint("Declaration of " & "CRYPTO_strndup" &
        " already exists, not redeclaring")
when not declared(CRYPTO_free):
  proc CRYPTO_free*(ptr_arg: pointer; file: cstring; line: cint): void {.cdecl,
      importc: "CRYPTO_free".}
else:
  static :
    hint("Declaration of " & "CRYPTO_free" & " already exists, not redeclaring")
when not declared(CRYPTO_clear_free):
  proc CRYPTO_clear_free*(ptr_arg: pointer; num: csize_t; file: cstring;
                          line: cint): void {.cdecl,
      importc: "CRYPTO_clear_free".}
else:
  static :
    hint("Declaration of " & "CRYPTO_clear_free" &
        " already exists, not redeclaring")
when not declared(CRYPTO_realloc):
  proc CRYPTO_realloc*(addr_arg: pointer; num: csize_t; file: cstring;
                       line: cint): pointer {.cdecl, importc: "CRYPTO_realloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_realloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_clear_realloc):
  proc CRYPTO_clear_realloc*(addr_arg: pointer; old_num: csize_t; num: csize_t;
                             file: cstring; line: cint): pointer {.cdecl,
      importc: "CRYPTO_clear_realloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_clear_realloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_malloc_init):
  proc CRYPTO_secure_malloc_init*(sz: csize_t; minsize: csize_t): cint {.cdecl,
      importc: "CRYPTO_secure_malloc_init".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_malloc_init" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_malloc_done):
  proc CRYPTO_secure_malloc_done*(): cint {.cdecl,
      importc: "CRYPTO_secure_malloc_done".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_malloc_done" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_malloc):
  proc CRYPTO_secure_malloc*(num: csize_t; file: cstring; line: cint): pointer {.
      cdecl, importc: "CRYPTO_secure_malloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_malloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_zalloc):
  proc CRYPTO_secure_zalloc*(num: csize_t; file: cstring; line: cint): pointer {.
      cdecl, importc: "CRYPTO_secure_zalloc".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_zalloc" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_free):
  proc CRYPTO_secure_free*(ptr_arg: pointer; file: cstring; line: cint): void {.
      cdecl, importc: "CRYPTO_secure_free".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_free" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_clear_free):
  proc CRYPTO_secure_clear_free*(ptr_arg: pointer; num: csize_t; file: cstring;
                                 line: cint): void {.cdecl,
      importc: "CRYPTO_secure_clear_free".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_clear_free" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_allocated):
  proc CRYPTO_secure_allocated*(ptr_arg: pointer): cint {.cdecl,
      importc: "CRYPTO_secure_allocated".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_allocated" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_malloc_initialized):
  proc CRYPTO_secure_malloc_initialized*(): cint {.cdecl,
      importc: "CRYPTO_secure_malloc_initialized".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_malloc_initialized" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_actual_size):
  proc CRYPTO_secure_actual_size*(ptr_arg: pointer): csize_t {.cdecl,
      importc: "CRYPTO_secure_actual_size".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_actual_size" &
        " already exists, not redeclaring")
when not declared(CRYPTO_secure_used):
  proc CRYPTO_secure_used*(): csize_t {.cdecl, importc: "CRYPTO_secure_used".}
else:
  static :
    hint("Declaration of " & "CRYPTO_secure_used" &
        " already exists, not redeclaring")
when not declared(OPENSSL_cleanse):
  proc OPENSSL_cleanse*(ptr_arg: pointer; len: csize_t): void {.cdecl,
      importc: "OPENSSL_cleanse".}
else:
  static :
    hint("Declaration of " & "OPENSSL_cleanse" &
        " already exists, not redeclaring")
when not declared(OPENSSL_die):
  proc OPENSSL_die*(assertion: cstring; file: cstring; line: cint): void {.
      cdecl, importc: "OPENSSL_die".}
else:
  static :
    hint("Declaration of " & "OPENSSL_die" & " already exists, not redeclaring")
when not declared(OPENSSL_isservice):
  proc OPENSSL_isservice*(): cint {.cdecl, importc: "OPENSSL_isservice".}
else:
  static :
    hint("Declaration of " & "OPENSSL_isservice" &
        " already exists, not redeclaring")
when not declared(OPENSSL_init):
  proc OPENSSL_init*(): void {.cdecl, importc: "OPENSSL_init".}
else:
  static :
    hint("Declaration of " & "OPENSSL_init" & " already exists, not redeclaring")
when not declared(OPENSSL_fork_prepare):
  proc OPENSSL_fork_prepare*(): void {.cdecl, importc: "OPENSSL_fork_prepare".}
else:
  static :
    hint("Declaration of " & "OPENSSL_fork_prepare" &
        " already exists, not redeclaring")
when not declared(OPENSSL_fork_parent):
  proc OPENSSL_fork_parent*(): void {.cdecl, importc: "OPENSSL_fork_parent".}
else:
  static :
    hint("Declaration of " & "OPENSSL_fork_parent" &
        " already exists, not redeclaring")
when not declared(OPENSSL_fork_child):
  proc OPENSSL_fork_child*(): void {.cdecl, importc: "OPENSSL_fork_child".}
else:
  static :
    hint("Declaration of " & "OPENSSL_fork_child" &
        " already exists, not redeclaring")
when not declared(OPENSSL_gmtime):
  proc OPENSSL_gmtime*(timer: ptr time_t_536871443; result: ptr struct_tm_536871518): ptr struct_tm_536871518 {.
      cdecl, importc: "OPENSSL_gmtime".}
else:
  static :
    hint("Declaration of " & "OPENSSL_gmtime" &
        " already exists, not redeclaring")
when not declared(OPENSSL_gmtime_adj):
  proc OPENSSL_gmtime_adj*(tm: ptr struct_tm_536871518; offset_day: cint;
                           offset_sec: clong): cint {.cdecl,
      importc: "OPENSSL_gmtime_adj".}
else:
  static :
    hint("Declaration of " & "OPENSSL_gmtime_adj" &
        " already exists, not redeclaring")
when not declared(OPENSSL_gmtime_diff):
  proc OPENSSL_gmtime_diff*(pday: ptr cint; psec: ptr cint;
                            from_arg: ptr struct_tm_536871518; to: ptr struct_tm_536871518): cint {.
      cdecl, importc: "OPENSSL_gmtime_diff".}
else:
  static :
    hint("Declaration of " & "OPENSSL_gmtime_diff" &
        " already exists, not redeclaring")
when not declared(CRYPTO_memcmp):
  proc CRYPTO_memcmp*(in_a: pointer; in_b: pointer; len: csize_t): cint {.cdecl,
      importc: "CRYPTO_memcmp".}
else:
  static :
    hint("Declaration of " & "CRYPTO_memcmp" &
        " already exists, not redeclaring")
when not declared(OPENSSL_cleanup):
  proc OPENSSL_cleanup*(): void {.cdecl, importc: "OPENSSL_cleanup".}
else:
  static :
    hint("Declaration of " & "OPENSSL_cleanup" &
        " already exists, not redeclaring")
when not declared(OPENSSL_init_crypto):
  proc OPENSSL_init_crypto*(opts: uint64; settings: ptr OPENSSL_INIT_SETTINGS_536871520): cint {.
      cdecl, importc: "OPENSSL_init_crypto".}
else:
  static :
    hint("Declaration of " & "OPENSSL_init_crypto" &
        " already exists, not redeclaring")
when not declared(OPENSSL_atexit):
  proc OPENSSL_atexit*(handler: proc (): void {.cdecl.}): cint {.cdecl,
      importc: "OPENSSL_atexit".}
else:
  static :
    hint("Declaration of " & "OPENSSL_atexit" &
        " already exists, not redeclaring")
when not declared(OPENSSL_thread_stop):
  proc OPENSSL_thread_stop*(): void {.cdecl, importc: "OPENSSL_thread_stop".}
else:
  static :
    hint("Declaration of " & "OPENSSL_thread_stop" &
        " already exists, not redeclaring")
when not declared(OPENSSL_thread_stop_ex):
  proc OPENSSL_thread_stop_ex*(ctx: ptr OSSL_LIB_CTX_536871484): void {.cdecl,
      importc: "OPENSSL_thread_stop_ex".}
else:
  static :
    hint("Declaration of " & "OPENSSL_thread_stop_ex" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_new):
  proc OPENSSL_INIT_new*(): ptr OPENSSL_INIT_SETTINGS_536871520 {.cdecl,
      importc: "OPENSSL_INIT_new".}
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_new" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_set_config_filename):
  proc OPENSSL_INIT_set_config_filename*(settings: ptr OPENSSL_INIT_SETTINGS_536871520;
      config_filename: cstring): cint {.cdecl, importc: "OPENSSL_INIT_set_config_filename".}
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_set_config_filename" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_set_config_file_flags):
  proc OPENSSL_INIT_set_config_file_flags*(settings: ptr OPENSSL_INIT_SETTINGS_536871520;
      flags: culong): void {.cdecl,
                             importc: "OPENSSL_INIT_set_config_file_flags".}
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_set_config_file_flags" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_set_config_appname):
  proc OPENSSL_INIT_set_config_appname*(settings: ptr OPENSSL_INIT_SETTINGS_536871520;
                                        config_appname: cstring): cint {.cdecl,
      importc: "OPENSSL_INIT_set_config_appname".}
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_set_config_appname" &
        " already exists, not redeclaring")
when not declared(OPENSSL_INIT_free):
  proc OPENSSL_INIT_free*(settings: ptr OPENSSL_INIT_SETTINGS_536871520): void {.
      cdecl, importc: "OPENSSL_INIT_free".}
else:
  static :
    hint("Declaration of " & "OPENSSL_INIT_free" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_run_once):
  proc CRYPTO_THREAD_run_once*(once: ptr CRYPTO_ONCE_536871522;
                               init: proc (): void {.cdecl.}): cint {.cdecl,
      importc: "CRYPTO_THREAD_run_once".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_run_once" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_init_local):
  proc CRYPTO_THREAD_init_local*(key: ptr CRYPTO_THREAD_LOCAL_536871526;
                                 cleanup: proc (a0: pointer): void {.cdecl.}): cint {.
      cdecl, importc: "CRYPTO_THREAD_init_local".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_init_local" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_get_local):
  proc CRYPTO_THREAD_get_local*(key: ptr CRYPTO_THREAD_LOCAL_536871526): pointer {.
      cdecl, importc: "CRYPTO_THREAD_get_local".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_get_local" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_set_local):
  proc CRYPTO_THREAD_set_local*(key: ptr CRYPTO_THREAD_LOCAL_536871526;
                                val: pointer): cint {.cdecl,
      importc: "CRYPTO_THREAD_set_local".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_set_local" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_cleanup_local):
  proc CRYPTO_THREAD_cleanup_local*(key: ptr CRYPTO_THREAD_LOCAL_536871526): cint {.
      cdecl, importc: "CRYPTO_THREAD_cleanup_local".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_cleanup_local" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_get_current_id):
  proc CRYPTO_THREAD_get_current_id*(): CRYPTO_THREAD_ID_typedef_536871530 {.
      cdecl, importc: "CRYPTO_THREAD_get_current_id".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_get_current_id" &
        " already exists, not redeclaring")
when not declared(CRYPTO_THREAD_compare_id):
  proc CRYPTO_THREAD_compare_id*(a: CRYPTO_THREAD_ID_typedef_536871530;
                                 b: CRYPTO_THREAD_ID_typedef_536871530): cint {.
      cdecl, importc: "CRYPTO_THREAD_compare_id".}
else:
  static :
    hint("Declaration of " & "CRYPTO_THREAD_compare_id" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_new):
  proc OSSL_LIB_CTX_new*(): ptr OSSL_LIB_CTX_536871484 {.cdecl,
      importc: "OSSL_LIB_CTX_new".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_new" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_new_from_dispatch):
  proc OSSL_LIB_CTX_new_from_dispatch*(handle: ptr OSSL_CORE_HANDLE_536871534;
                                       in_arg: ptr OSSL_DISPATCH_536871536): ptr OSSL_LIB_CTX_536871484 {.
      cdecl, importc: "OSSL_LIB_CTX_new_from_dispatch".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_new_from_dispatch" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_new_child):
  proc OSSL_LIB_CTX_new_child*(handle: ptr OSSL_CORE_HANDLE_536871534;
                               in_arg: ptr OSSL_DISPATCH_536871536): ptr OSSL_LIB_CTX_536871484 {.
      cdecl, importc: "OSSL_LIB_CTX_new_child".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_new_child" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_load_config):
  proc OSSL_LIB_CTX_load_config*(ctx: ptr OSSL_LIB_CTX_536871484;
                                 config_file: cstring): cint {.cdecl,
      importc: "OSSL_LIB_CTX_load_config".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_load_config" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_free):
  proc OSSL_LIB_CTX_free*(a0: ptr OSSL_LIB_CTX_536871484): void {.cdecl,
      importc: "OSSL_LIB_CTX_free".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_free" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_get0_global_default):
  proc OSSL_LIB_CTX_get0_global_default*(): ptr OSSL_LIB_CTX_536871484 {.cdecl,
      importc: "OSSL_LIB_CTX_get0_global_default".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_get0_global_default" &
        " already exists, not redeclaring")
when not declared(OSSL_LIB_CTX_set0_default):
  proc OSSL_LIB_CTX_set0_default*(libctx: ptr OSSL_LIB_CTX_536871484): ptr OSSL_LIB_CTX_536871484 {.
      cdecl, importc: "OSSL_LIB_CTX_set0_default".}
else:
  static :
    hint("Declaration of " & "OSSL_LIB_CTX_set0_default" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_SEQUENCE_ANY):
  proc d2i_ASN1_SEQUENCE_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY_536871620;
                              in_arg: ptr ptr uint8; len: clong): ptr ASN1_SEQUENCE_ANY_536871620 {.
      cdecl, importc: "d2i_ASN1_SEQUENCE_ANY".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_SEQUENCE_ANY" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_SEQUENCE_ANY):
  proc i2d_ASN1_SEQUENCE_ANY*(a: ptr ASN1_SEQUENCE_ANY_536871620;
                              out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_SEQUENCE_ANY".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_SEQUENCE_ANY" &
        " already exists, not redeclaring")
when not declared(ASN1_SEQUENCE_ANY_it):
  proc ASN1_SEQUENCE_ANY_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_SEQUENCE_ANY_it".}
else:
  static :
    hint("Declaration of " & "ASN1_SEQUENCE_ANY_it" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_SET_ANY):
  proc d2i_ASN1_SET_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY_536871620;
                         in_arg: ptr ptr uint8; len: clong): ptr ASN1_SEQUENCE_ANY_536871620 {.
      cdecl, importc: "d2i_ASN1_SET_ANY".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_SET_ANY" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_SET_ANY):
  proc i2d_ASN1_SET_ANY*(a: ptr ASN1_SEQUENCE_ANY_536871620;
                         out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_SET_ANY".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_SET_ANY" &
        " already exists, not redeclaring")
when not declared(ASN1_SET_ANY_it):
  proc ASN1_SET_ANY_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_SET_ANY_it".}
else:
  static :
    hint("Declaration of " & "ASN1_SET_ANY_it" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_new):
  proc ASN1_TYPE_new*(): ptr ASN1_TYPE_536871614 {.cdecl,
      importc: "ASN1_TYPE_new".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_new" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_free):
  proc ASN1_TYPE_free*(a: ptr ASN1_TYPE_536871614): void {.cdecl,
      importc: "ASN1_TYPE_free".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_TYPE):
  proc d2i_ASN1_TYPE*(a: ptr ptr ASN1_TYPE_536871614; in_arg: ptr ptr uint8;
                      len: clong): ptr ASN1_TYPE_536871614 {.cdecl,
      importc: "d2i_ASN1_TYPE".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_TYPE" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_TYPE):
  proc i2d_ASN1_TYPE*(a: ptr ASN1_TYPE_536871614; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_TYPE".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_TYPE" &
        " already exists, not redeclaring")
when not declared(ASN1_ANY_it):
  proc ASN1_ANY_it*(): ptr ASN1_ITEM_536871574 {.cdecl, importc: "ASN1_ANY_it".}
else:
  static :
    hint("Declaration of " & "ASN1_ANY_it" & " already exists, not redeclaring")
when not declared(ASN1_TYPE_get):
  proc ASN1_TYPE_get*(a: ptr ASN1_TYPE_536871614): cint {.cdecl,
      importc: "ASN1_TYPE_get".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_get" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_set):
  proc ASN1_TYPE_set*(a: ptr ASN1_TYPE_536871614; type_arg: cint; value: pointer): void {.
      cdecl, importc: "ASN1_TYPE_set".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_set" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_set1):
  proc ASN1_TYPE_set1*(a: ptr ASN1_TYPE_536871614; type_arg: cint;
                       value: pointer): cint {.cdecl, importc: "ASN1_TYPE_set1".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_set1" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_cmp):
  proc ASN1_TYPE_cmp*(a: ptr ASN1_TYPE_536871614; b: ptr ASN1_TYPE_536871614): cint {.
      cdecl, importc: "ASN1_TYPE_cmp".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_cmp" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_pack_sequence):
  proc ASN1_TYPE_pack_sequence*(it: ptr ASN1_ITEM_536871574; s: pointer;
                                t: ptr ptr ASN1_TYPE_536871614): ptr ASN1_TYPE_536871614 {.
      cdecl, importc: "ASN1_TYPE_pack_sequence".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_pack_sequence" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_unpack_sequence):
  proc ASN1_TYPE_unpack_sequence*(it: ptr ASN1_ITEM_536871574; t: ptr ASN1_TYPE_536871614): pointer {.
      cdecl, importc: "ASN1_TYPE_unpack_sequence".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_unpack_sequence" &
        " already exists, not redeclaring")
when not declared(ASN1_OBJECT_new):
  proc ASN1_OBJECT_new*(): ptr ASN1_OBJECT_536871582 {.cdecl,
      importc: "ASN1_OBJECT_new".}
else:
  static :
    hint("Declaration of " & "ASN1_OBJECT_new" &
        " already exists, not redeclaring")
when not declared(ASN1_OBJECT_free):
  proc ASN1_OBJECT_free*(a: ptr ASN1_OBJECT_536871582): void {.cdecl,
      importc: "ASN1_OBJECT_free".}
else:
  static :
    hint("Declaration of " & "ASN1_OBJECT_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_OBJECT):
  proc d2i_ASN1_OBJECT*(a: ptr ptr ASN1_OBJECT_536871582; in_arg: ptr ptr uint8;
                        len: clong): ptr ASN1_OBJECT_536871582 {.cdecl,
      importc: "d2i_ASN1_OBJECT".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_OBJECT):
  proc i2d_ASN1_OBJECT*(a: ptr ASN1_OBJECT_536871582; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_OBJECT".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(ASN1_OBJECT_it):
  proc ASN1_OBJECT_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_OBJECT_it".}
else:
  static :
    hint("Declaration of " & "ASN1_OBJECT_it" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_new):
  proc ASN1_STRING_new*(): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "ASN1_STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_free):
  proc ASN1_STRING_free*(a: ptr ASN1_STRING_536871580): void {.cdecl,
      importc: "ASN1_STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_free" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_clear_free):
  proc ASN1_STRING_clear_free*(a: ptr ASN1_STRING_536871580): void {.cdecl,
      importc: "ASN1_STRING_clear_free".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_clear_free" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_copy):
  proc ASN1_STRING_copy*(dst: ptr ASN1_STRING_536871580; str: ptr ASN1_STRING_536871580): cint {.
      cdecl, importc: "ASN1_STRING_copy".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_copy" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_dup):
  proc ASN1_STRING_dup*(a: ptr ASN1_STRING_536871580): ptr ASN1_STRING_536871580 {.
      cdecl, importc: "ASN1_STRING_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_type_new):
  proc ASN1_STRING_type_new*(type_arg: cint): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "ASN1_STRING_type_new".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_type_new" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_cmp):
  proc ASN1_STRING_cmp*(a: ptr ASN1_STRING_536871580; b: ptr ASN1_STRING_536871580): cint {.
      cdecl, importc: "ASN1_STRING_cmp".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_cmp" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_set):
  proc ASN1_STRING_set*(str: ptr ASN1_STRING_536871580; data: pointer; len: cint): cint {.
      cdecl, importc: "ASN1_STRING_set".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_set" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_set0):
  proc ASN1_STRING_set0*(str: ptr ASN1_STRING_536871580; data: pointer;
                         len: cint): void {.cdecl, importc: "ASN1_STRING_set0".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_set0" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_length):
  proc ASN1_STRING_length*(x: ptr ASN1_STRING_536871580): cint {.cdecl,
      importc: "ASN1_STRING_length".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_length" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_length_set):
  proc ASN1_STRING_length_set*(x: ptr ASN1_STRING_536871580; n: cint): void {.
      cdecl, importc: "ASN1_STRING_length_set".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_length_set" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_type):
  proc ASN1_STRING_type*(x: ptr ASN1_STRING_536871580): cint {.cdecl,
      importc: "ASN1_STRING_type".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_type" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_data):
  proc ASN1_STRING_data*(x: ptr ASN1_STRING_536871580): ptr uint8 {.cdecl,
      importc: "ASN1_STRING_data".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_data" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_get0_data):
  proc ASN1_STRING_get0_data*(x: ptr ASN1_STRING_536871580): ptr uint8 {.cdecl,
      importc: "ASN1_STRING_get0_data".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_get0_data" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_new):
  proc ASN1_BIT_STRING_new*(): ptr ASN1_BIT_STRING_536871588 {.cdecl,
      importc: "ASN1_BIT_STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_free):
  proc ASN1_BIT_STRING_free*(a: ptr ASN1_BIT_STRING_536871588): void {.cdecl,
      importc: "ASN1_BIT_STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_BIT_STRING):
  proc d2i_ASN1_BIT_STRING*(a: ptr ptr ASN1_BIT_STRING_536871588;
                            in_arg: ptr ptr uint8; len: clong): ptr ASN1_BIT_STRING_536871588 {.
      cdecl, importc: "d2i_ASN1_BIT_STRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_BIT_STRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_BIT_STRING):
  proc i2d_ASN1_BIT_STRING*(a: ptr ASN1_BIT_STRING_536871588;
                            out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_BIT_STRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_BIT_STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_it):
  proc ASN1_BIT_STRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_BIT_STRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_set):
  proc ASN1_BIT_STRING_set*(a: ptr ASN1_BIT_STRING_536871588; d: ptr uint8;
                            length: cint): cint {.cdecl,
      importc: "ASN1_BIT_STRING_set".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_set" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_set_bit):
  proc ASN1_BIT_STRING_set_bit*(a: ptr ASN1_BIT_STRING_536871588; n: cint;
                                value: cint): cint {.cdecl,
      importc: "ASN1_BIT_STRING_set_bit".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_set_bit" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_get_bit):
  proc ASN1_BIT_STRING_get_bit*(a: ptr ASN1_BIT_STRING_536871588; n: cint): cint {.
      cdecl, importc: "ASN1_BIT_STRING_get_bit".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_get_bit" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_check):
  proc ASN1_BIT_STRING_check*(a: ptr ASN1_BIT_STRING_536871588;
                              flags: ptr uint8; flags_len: cint): cint {.cdecl,
      importc: "ASN1_BIT_STRING_check".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_check" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_name_print):
  proc ASN1_BIT_STRING_name_print*(out_arg: ptr BIO_536871632;
                                   bs: ptr ASN1_BIT_STRING_536871588;
                                   tbl: ptr BIT_STRING_BITNAME_536871624;
                                   indent: cint): cint {.cdecl,
      importc: "ASN1_BIT_STRING_name_print".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_name_print" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_num_asc):
  proc ASN1_BIT_STRING_num_asc*(name: cstring; tbl: ptr BIT_STRING_BITNAME_536871624): cint {.
      cdecl, importc: "ASN1_BIT_STRING_num_asc".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_num_asc" &
        " already exists, not redeclaring")
when not declared(ASN1_BIT_STRING_set_asc):
  proc ASN1_BIT_STRING_set_asc*(bs: ptr ASN1_BIT_STRING_536871588;
                                name: cstring; value: cint;
                                tbl: ptr BIT_STRING_BITNAME_536871624): cint {.
      cdecl, importc: "ASN1_BIT_STRING_set_asc".}
else:
  static :
    hint("Declaration of " & "ASN1_BIT_STRING_set_asc" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_new):
  proc ASN1_INTEGER_new*(): ptr ASN1_INTEGER_536871584 {.cdecl,
      importc: "ASN1_INTEGER_new".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_new" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_free):
  proc ASN1_INTEGER_free*(a: ptr ASN1_INTEGER_536871584): void {.cdecl,
      importc: "ASN1_INTEGER_free".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_INTEGER):
  proc d2i_ASN1_INTEGER*(a: ptr ptr ASN1_INTEGER_536871584;
                         in_arg: ptr ptr uint8; len: clong): ptr ASN1_INTEGER_536871584 {.
      cdecl, importc: "d2i_ASN1_INTEGER".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_INTEGER):
  proc i2d_ASN1_INTEGER*(a: ptr ASN1_INTEGER_536871584; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_INTEGER".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_it):
  proc ASN1_INTEGER_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_INTEGER_it".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_it" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_UINTEGER):
  proc d2i_ASN1_UINTEGER*(a: ptr ptr ASN1_INTEGER_536871584; pp: ptr ptr uint8;
                          length: clong): ptr ASN1_INTEGER_536871584 {.cdecl,
      importc: "d2i_ASN1_UINTEGER".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_UINTEGER" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_dup):
  proc ASN1_INTEGER_dup*(a: ptr ASN1_INTEGER_536871584): ptr ASN1_INTEGER_536871584 {.
      cdecl, importc: "ASN1_INTEGER_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_cmp):
  proc ASN1_INTEGER_cmp*(x: ptr ASN1_INTEGER_536871584; y: ptr ASN1_INTEGER_536871584): cint {.
      cdecl, importc: "ASN1_INTEGER_cmp".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_cmp" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_new):
  proc ASN1_ENUMERATED_new*(): ptr ASN1_ENUMERATED_536871586 {.cdecl,
      importc: "ASN1_ENUMERATED_new".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_new" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_free):
  proc ASN1_ENUMERATED_free*(a: ptr ASN1_ENUMERATED_536871586): void {.cdecl,
      importc: "ASN1_ENUMERATED_free".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_ENUMERATED):
  proc d2i_ASN1_ENUMERATED*(a: ptr ptr ASN1_ENUMERATED_536871586;
                            in_arg: ptr ptr uint8; len: clong): ptr ASN1_ENUMERATED_536871586 {.
      cdecl, importc: "d2i_ASN1_ENUMERATED".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_ENUMERATED):
  proc i2d_ASN1_ENUMERATED*(a: ptr ASN1_ENUMERATED_536871586;
                            out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_ENUMERATED".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_it):
  proc ASN1_ENUMERATED_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_ENUMERATED_it".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_it" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_check):
  proc ASN1_UTCTIME_check*(a: ptr ASN1_UTCTIME_536871604): cint {.cdecl,
      importc: "ASN1_UTCTIME_check".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_check" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_set):
  proc ASN1_UTCTIME_set*(s: ptr ASN1_UTCTIME_536871604; t: time_t_536871443): ptr ASN1_UTCTIME_536871604 {.
      cdecl, importc: "ASN1_UTCTIME_set".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_set" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_adj):
  proc ASN1_UTCTIME_adj*(s: ptr ASN1_UTCTIME_536871604; t: time_t_536871443;
                         offset_day: cint; offset_sec: clong): ptr ASN1_UTCTIME_536871604 {.
      cdecl, importc: "ASN1_UTCTIME_adj".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_adj" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_set_string):
  proc ASN1_UTCTIME_set_string*(s: ptr ASN1_UTCTIME_536871604; str: cstring): cint {.
      cdecl, importc: "ASN1_UTCTIME_set_string".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_set_string" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_cmp_time_t):
  proc ASN1_UTCTIME_cmp_time_t*(s: ptr ASN1_UTCTIME_536871604; t: time_t_536871443): cint {.
      cdecl, importc: "ASN1_UTCTIME_cmp_time_t".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_cmp_time_t" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_check):
  proc ASN1_GENERALIZEDTIME_check*(a: ptr ASN1_GENERALIZEDTIME_536871606): cint {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_check".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_check" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_set):
  proc ASN1_GENERALIZEDTIME_set*(s: ptr ASN1_GENERALIZEDTIME_536871606;
                                 t: time_t_536871443): ptr ASN1_GENERALIZEDTIME_536871606 {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_set".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_set" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_adj):
  proc ASN1_GENERALIZEDTIME_adj*(s: ptr ASN1_GENERALIZEDTIME_536871606;
                                 t: time_t_536871443; offset_day: cint;
                                 offset_sec: clong): ptr ASN1_GENERALIZEDTIME_536871606 {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_adj".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_adj" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_set_string):
  proc ASN1_GENERALIZEDTIME_set_string*(s: ptr ASN1_GENERALIZEDTIME_536871606;
                                        str: cstring): cint {.cdecl,
      importc: "ASN1_GENERALIZEDTIME_set_string".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_set_string" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_diff):
  proc ASN1_TIME_diff*(pday: ptr cint; psec: ptr cint; from_arg: ptr ASN1_TIME_536871640;
                       to: ptr ASN1_TIME_536871640): cint {.cdecl,
      importc: "ASN1_TIME_diff".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_diff" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_new):
  proc ASN1_OCTET_STRING_new*(): ptr ASN1_OCTET_STRING_536871590 {.cdecl,
      importc: "ASN1_OCTET_STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_free):
  proc ASN1_OCTET_STRING_free*(a: ptr ASN1_OCTET_STRING_536871590): void {.
      cdecl, importc: "ASN1_OCTET_STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_OCTET_STRING):
  proc d2i_ASN1_OCTET_STRING*(a: ptr ptr ASN1_OCTET_STRING_536871590;
                              in_arg: ptr ptr uint8; len: clong): ptr ASN1_OCTET_STRING_536871590 {.
      cdecl, importc: "d2i_ASN1_OCTET_STRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_OCTET_STRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_OCTET_STRING):
  proc i2d_ASN1_OCTET_STRING*(a: ptr ASN1_OCTET_STRING_536871590;
                              out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_OCTET_STRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_OCTET_STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_it):
  proc ASN1_OCTET_STRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_OCTET_STRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_dup):
  proc ASN1_OCTET_STRING_dup*(a: ptr ASN1_OCTET_STRING_536871590): ptr ASN1_OCTET_STRING_536871590 {.
      cdecl, importc: "ASN1_OCTET_STRING_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_cmp):
  proc ASN1_OCTET_STRING_cmp*(a: ptr ASN1_OCTET_STRING_536871590;
                              b: ptr ASN1_OCTET_STRING_536871590): cint {.cdecl,
      importc: "ASN1_OCTET_STRING_cmp".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_cmp" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_set):
  proc ASN1_OCTET_STRING_set*(str: ptr ASN1_OCTET_STRING_536871590;
                              data: ptr uint8; len: cint): cint {.cdecl,
      importc: "ASN1_OCTET_STRING_set".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_set" &
        " already exists, not redeclaring")
when not declared(ASN1_VISIBLESTRING_new):
  proc ASN1_VISIBLESTRING_new*(): ptr ASN1_VISIBLESTRING_536871608 {.cdecl,
      importc: "ASN1_VISIBLESTRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_VISIBLESTRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_VISIBLESTRING_free):
  proc ASN1_VISIBLESTRING_free*(a: ptr ASN1_VISIBLESTRING_536871608): void {.
      cdecl, importc: "ASN1_VISIBLESTRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_VISIBLESTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_VISIBLESTRING):
  proc d2i_ASN1_VISIBLESTRING*(a: ptr ptr ASN1_VISIBLESTRING_536871608;
                               in_arg: ptr ptr uint8; len: clong): ptr ASN1_VISIBLESTRING_536871608 {.
      cdecl, importc: "d2i_ASN1_VISIBLESTRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_VISIBLESTRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_VISIBLESTRING):
  proc i2d_ASN1_VISIBLESTRING*(a: ptr ASN1_VISIBLESTRING_536871608;
                               out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_VISIBLESTRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_VISIBLESTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_VISIBLESTRING_it):
  proc ASN1_VISIBLESTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_VISIBLESTRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_VISIBLESTRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_UNIVERSALSTRING_new):
  proc ASN1_UNIVERSALSTRING_new*(): ptr ASN1_UNIVERSALSTRING_536871602 {.cdecl,
      importc: "ASN1_UNIVERSALSTRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_UNIVERSALSTRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_UNIVERSALSTRING_free):
  proc ASN1_UNIVERSALSTRING_free*(a: ptr ASN1_UNIVERSALSTRING_536871602): void {.
      cdecl, importc: "ASN1_UNIVERSALSTRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_UNIVERSALSTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_UNIVERSALSTRING):
  proc d2i_ASN1_UNIVERSALSTRING*(a: ptr ptr ASN1_UNIVERSALSTRING_536871602;
                                 in_arg: ptr ptr uint8; len: clong): ptr ASN1_UNIVERSALSTRING_536871602 {.
      cdecl, importc: "d2i_ASN1_UNIVERSALSTRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_UNIVERSALSTRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_UNIVERSALSTRING):
  proc i2d_ASN1_UNIVERSALSTRING*(a: ptr ASN1_UNIVERSALSTRING_536871602;
                                 out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_UNIVERSALSTRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_UNIVERSALSTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_UNIVERSALSTRING_it):
  proc ASN1_UNIVERSALSTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_UNIVERSALSTRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_UNIVERSALSTRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_UTF8STRING_new):
  proc ASN1_UTF8STRING_new*(): ptr ASN1_UTF8STRING_536871610 {.cdecl,
      importc: "ASN1_UTF8STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_UTF8STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_UTF8STRING_free):
  proc ASN1_UTF8STRING_free*(a: ptr ASN1_UTF8STRING_536871610): void {.cdecl,
      importc: "ASN1_UTF8STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_UTF8STRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_UTF8STRING):
  proc d2i_ASN1_UTF8STRING*(a: ptr ptr ASN1_UTF8STRING_536871610;
                            in_arg: ptr ptr uint8; len: clong): ptr ASN1_UTF8STRING_536871610 {.
      cdecl, importc: "d2i_ASN1_UTF8STRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_UTF8STRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_UTF8STRING):
  proc i2d_ASN1_UTF8STRING*(a: ptr ASN1_UTF8STRING_536871610;
                            out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_UTF8STRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_UTF8STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_UTF8STRING_it):
  proc ASN1_UTF8STRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_UTF8STRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_UTF8STRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_NULL_new):
  proc ASN1_NULL_new*(): ptr ASN1_NULL_536871648 {.cdecl,
      importc: "ASN1_NULL_new".}
else:
  static :
    hint("Declaration of " & "ASN1_NULL_new" &
        " already exists, not redeclaring")
when not declared(ASN1_NULL_free):
  proc ASN1_NULL_free*(a: ptr ASN1_NULL_536871648): void {.cdecl,
      importc: "ASN1_NULL_free".}
else:
  static :
    hint("Declaration of " & "ASN1_NULL_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_NULL):
  proc d2i_ASN1_NULL*(a: ptr ptr ASN1_NULL_536871648; in_arg: ptr ptr uint8;
                      len: clong): ptr ASN1_NULL_536871648 {.cdecl,
      importc: "d2i_ASN1_NULL".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_NULL" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_NULL):
  proc i2d_ASN1_NULL*(a: ptr ASN1_NULL_536871648; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_NULL".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_NULL" &
        " already exists, not redeclaring")
when not declared(ASN1_NULL_it):
  proc ASN1_NULL_it*(): ptr ASN1_ITEM_536871574 {.cdecl, importc: "ASN1_NULL_it".}
else:
  static :
    hint("Declaration of " & "ASN1_NULL_it" & " already exists, not redeclaring")
when not declared(ASN1_BMPSTRING_new):
  proc ASN1_BMPSTRING_new*(): ptr ASN1_BMPSTRING_536871600 {.cdecl,
      importc: "ASN1_BMPSTRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_BMPSTRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_BMPSTRING_free):
  proc ASN1_BMPSTRING_free*(a: ptr ASN1_BMPSTRING_536871600): void {.cdecl,
      importc: "ASN1_BMPSTRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_BMPSTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_BMPSTRING):
  proc d2i_ASN1_BMPSTRING*(a: ptr ptr ASN1_BMPSTRING_536871600;
                           in_arg: ptr ptr uint8; len: clong): ptr ASN1_BMPSTRING_536871600 {.
      cdecl, importc: "d2i_ASN1_BMPSTRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_BMPSTRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_BMPSTRING):
  proc i2d_ASN1_BMPSTRING*(a: ptr ASN1_BMPSTRING_536871600;
                           out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_BMPSTRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_BMPSTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_BMPSTRING_it):
  proc ASN1_BMPSTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_BMPSTRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_BMPSTRING_it" &
        " already exists, not redeclaring")
when not declared(UTF8_getc):
  proc UTF8_getc*(str: ptr uint8; len: cint; val: ptr culong): cint {.cdecl,
      importc: "UTF8_getc".}
else:
  static :
    hint("Declaration of " & "UTF8_getc" & " already exists, not redeclaring")
when not declared(UTF8_putc):
  proc UTF8_putc*(str: ptr uint8; len: cint; value: culong): cint {.cdecl,
      importc: "UTF8_putc".}
else:
  static :
    hint("Declaration of " & "UTF8_putc" & " already exists, not redeclaring")
when not declared(ASN1_PRINTABLE_new):
  proc ASN1_PRINTABLE_new*(): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "ASN1_PRINTABLE_new".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLE_new" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLE_free):
  proc ASN1_PRINTABLE_free*(a: ptr ASN1_STRING_536871580): void {.cdecl,
      importc: "ASN1_PRINTABLE_free".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLE_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_PRINTABLE):
  proc d2i_ASN1_PRINTABLE*(a: ptr ptr ASN1_STRING_536871580;
                           in_arg: ptr ptr uint8; len: clong): ptr ASN1_STRING_536871580 {.
      cdecl, importc: "d2i_ASN1_PRINTABLE".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_PRINTABLE" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_PRINTABLE):
  proc i2d_ASN1_PRINTABLE*(a: ptr ASN1_STRING_536871580; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_PRINTABLE".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_PRINTABLE" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLE_it):
  proc ASN1_PRINTABLE_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_PRINTABLE_it".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLE_it" &
        " already exists, not redeclaring")
when not declared(DIRECTORYSTRING_new):
  proc DIRECTORYSTRING_new*(): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "DIRECTORYSTRING_new".}
else:
  static :
    hint("Declaration of " & "DIRECTORYSTRING_new" &
        " already exists, not redeclaring")
when not declared(DIRECTORYSTRING_free):
  proc DIRECTORYSTRING_free*(a: ptr ASN1_STRING_536871580): void {.cdecl,
      importc: "DIRECTORYSTRING_free".}
else:
  static :
    hint("Declaration of " & "DIRECTORYSTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_DIRECTORYSTRING):
  proc d2i_DIRECTORYSTRING*(a: ptr ptr ASN1_STRING_536871580;
                            in_arg: ptr ptr uint8; len: clong): ptr ASN1_STRING_536871580 {.
      cdecl, importc: "d2i_DIRECTORYSTRING".}
else:
  static :
    hint("Declaration of " & "d2i_DIRECTORYSTRING" &
        " already exists, not redeclaring")
when not declared(i2d_DIRECTORYSTRING):
  proc i2d_DIRECTORYSTRING*(a: ptr ASN1_STRING_536871580; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_DIRECTORYSTRING".}
else:
  static :
    hint("Declaration of " & "i2d_DIRECTORYSTRING" &
        " already exists, not redeclaring")
when not declared(DIRECTORYSTRING_it):
  proc DIRECTORYSTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "DIRECTORYSTRING_it".}
else:
  static :
    hint("Declaration of " & "DIRECTORYSTRING_it" &
        " already exists, not redeclaring")
when not declared(DISPLAYTEXT_new):
  proc DISPLAYTEXT_new*(): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "DISPLAYTEXT_new".}
else:
  static :
    hint("Declaration of " & "DISPLAYTEXT_new" &
        " already exists, not redeclaring")
when not declared(DISPLAYTEXT_free):
  proc DISPLAYTEXT_free*(a: ptr ASN1_STRING_536871580): void {.cdecl,
      importc: "DISPLAYTEXT_free".}
else:
  static :
    hint("Declaration of " & "DISPLAYTEXT_free" &
        " already exists, not redeclaring")
when not declared(d2i_DISPLAYTEXT):
  proc d2i_DISPLAYTEXT*(a: ptr ptr ASN1_STRING_536871580; in_arg: ptr ptr uint8;
                        len: clong): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "d2i_DISPLAYTEXT".}
else:
  static :
    hint("Declaration of " & "d2i_DISPLAYTEXT" &
        " already exists, not redeclaring")
when not declared(i2d_DISPLAYTEXT):
  proc i2d_DISPLAYTEXT*(a: ptr ASN1_STRING_536871580; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_DISPLAYTEXT".}
else:
  static :
    hint("Declaration of " & "i2d_DISPLAYTEXT" &
        " already exists, not redeclaring")
when not declared(DISPLAYTEXT_it):
  proc DISPLAYTEXT_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "DISPLAYTEXT_it".}
else:
  static :
    hint("Declaration of " & "DISPLAYTEXT_it" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLESTRING_new):
  proc ASN1_PRINTABLESTRING_new*(): ptr ASN1_PRINTABLESTRING_536871592 {.cdecl,
      importc: "ASN1_PRINTABLESTRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLESTRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLESTRING_free):
  proc ASN1_PRINTABLESTRING_free*(a: ptr ASN1_PRINTABLESTRING_536871592): void {.
      cdecl, importc: "ASN1_PRINTABLESTRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLESTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_PRINTABLESTRING):
  proc d2i_ASN1_PRINTABLESTRING*(a: ptr ptr ASN1_PRINTABLESTRING_536871592;
                                 in_arg: ptr ptr uint8; len: clong): ptr ASN1_PRINTABLESTRING_536871592 {.
      cdecl, importc: "d2i_ASN1_PRINTABLESTRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_PRINTABLESTRING):
  proc i2d_ASN1_PRINTABLESTRING*(a: ptr ASN1_PRINTABLESTRING_536871592;
                                 out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_PRINTABLESTRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_PRINTABLESTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLESTRING_it):
  proc ASN1_PRINTABLESTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_PRINTABLESTRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLESTRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_T61STRING_new):
  proc ASN1_T61STRING_new*(): ptr ASN1_T61STRING_536871594 {.cdecl,
      importc: "ASN1_T61STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_T61STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_T61STRING_free):
  proc ASN1_T61STRING_free*(a: ptr ASN1_T61STRING_536871594): void {.cdecl,
      importc: "ASN1_T61STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_T61STRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_T61STRING):
  proc d2i_ASN1_T61STRING*(a: ptr ptr ASN1_T61STRING_536871594;
                           in_arg: ptr ptr uint8; len: clong): ptr ASN1_T61STRING_536871594 {.
      cdecl, importc: "d2i_ASN1_T61STRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_T61STRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_T61STRING):
  proc i2d_ASN1_T61STRING*(a: ptr ASN1_T61STRING_536871594;
                           out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_T61STRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_T61STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_T61STRING_it):
  proc ASN1_T61STRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_T61STRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_T61STRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_IA5STRING_new):
  proc ASN1_IA5STRING_new*(): ptr ASN1_IA5STRING_536871596 {.cdecl,
      importc: "ASN1_IA5STRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_IA5STRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_IA5STRING_free):
  proc ASN1_IA5STRING_free*(a: ptr ASN1_IA5STRING_536871596): void {.cdecl,
      importc: "ASN1_IA5STRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_IA5STRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_IA5STRING):
  proc d2i_ASN1_IA5STRING*(a: ptr ptr ASN1_IA5STRING_536871596;
                           in_arg: ptr ptr uint8; len: clong): ptr ASN1_IA5STRING_536871596 {.
      cdecl, importc: "d2i_ASN1_IA5STRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_IA5STRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_IA5STRING):
  proc i2d_ASN1_IA5STRING*(a: ptr ASN1_IA5STRING_536871596;
                           out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_IA5STRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_IA5STRING" &
        " already exists, not redeclaring")
when not declared(ASN1_IA5STRING_it):
  proc ASN1_IA5STRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_IA5STRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_IA5STRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALSTRING_new):
  proc ASN1_GENERALSTRING_new*(): ptr ASN1_GENERALSTRING_536871598 {.cdecl,
      importc: "ASN1_GENERALSTRING_new".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALSTRING_new" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALSTRING_free):
  proc ASN1_GENERALSTRING_free*(a: ptr ASN1_GENERALSTRING_536871598): void {.
      cdecl, importc: "ASN1_GENERALSTRING_free".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALSTRING_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_GENERALSTRING):
  proc d2i_ASN1_GENERALSTRING*(a: ptr ptr ASN1_GENERALSTRING_536871598;
                               in_arg: ptr ptr uint8; len: clong): ptr ASN1_GENERALSTRING_536871598 {.
      cdecl, importc: "d2i_ASN1_GENERALSTRING".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_GENERALSTRING" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_GENERALSTRING):
  proc i2d_ASN1_GENERALSTRING*(a: ptr ASN1_GENERALSTRING_536871598;
                               out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_GENERALSTRING".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_GENERALSTRING" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALSTRING_it):
  proc ASN1_GENERALSTRING_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_GENERALSTRING_it".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALSTRING_it" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_new):
  proc ASN1_UTCTIME_new*(): ptr ASN1_UTCTIME_536871604 {.cdecl,
      importc: "ASN1_UTCTIME_new".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_new" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_free):
  proc ASN1_UTCTIME_free*(a: ptr ASN1_UTCTIME_536871604): void {.cdecl,
      importc: "ASN1_UTCTIME_free".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_UTCTIME):
  proc d2i_ASN1_UTCTIME*(a: ptr ptr ASN1_UTCTIME_536871604;
                         in_arg: ptr ptr uint8; len: clong): ptr ASN1_UTCTIME_536871604 {.
      cdecl, importc: "d2i_ASN1_UTCTIME".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_UTCTIME" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_UTCTIME):
  proc i2d_ASN1_UTCTIME*(a: ptr ASN1_UTCTIME_536871604; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_UTCTIME".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_UTCTIME" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_it):
  proc ASN1_UTCTIME_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_UTCTIME_it".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_it" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_new):
  proc ASN1_GENERALIZEDTIME_new*(): ptr ASN1_GENERALIZEDTIME_536871606 {.cdecl,
      importc: "ASN1_GENERALIZEDTIME_new".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_new" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_free):
  proc ASN1_GENERALIZEDTIME_free*(a: ptr ASN1_GENERALIZEDTIME_536871606): void {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_free".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_GENERALIZEDTIME):
  proc d2i_ASN1_GENERALIZEDTIME*(a: ptr ptr ASN1_GENERALIZEDTIME_536871606;
                                 in_arg: ptr ptr uint8; len: clong): ptr ASN1_GENERALIZEDTIME_536871606 {.
      cdecl, importc: "d2i_ASN1_GENERALIZEDTIME".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_GENERALIZEDTIME" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_GENERALIZEDTIME):
  proc i2d_ASN1_GENERALIZEDTIME*(a: ptr ASN1_GENERALIZEDTIME_536871606;
                                 out_arg: ptr ptr uint8): cint {.cdecl,
      importc: "i2d_ASN1_GENERALIZEDTIME".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_GENERALIZEDTIME" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_it):
  proc ASN1_GENERALIZEDTIME_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_GENERALIZEDTIME_it".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_it" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_new):
  proc ASN1_TIME_new*(): ptr ASN1_TIME_536871640 {.cdecl,
      importc: "ASN1_TIME_new".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_new" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_free):
  proc ASN1_TIME_free*(a: ptr ASN1_TIME_536871640): void {.cdecl,
      importc: "ASN1_TIME_free".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_free" &
        " already exists, not redeclaring")
when not declared(d2i_ASN1_TIME):
  proc d2i_ASN1_TIME*(a: ptr ptr ASN1_TIME_536871640; in_arg: ptr ptr uint8;
                      len: clong): ptr ASN1_TIME_536871640 {.cdecl,
      importc: "d2i_ASN1_TIME".}
else:
  static :
    hint("Declaration of " & "d2i_ASN1_TIME" &
        " already exists, not redeclaring")
when not declared(i2d_ASN1_TIME):
  proc i2d_ASN1_TIME*(a: ptr ASN1_TIME_536871640; out_arg: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_ASN1_TIME".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_TIME" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_it):
  proc ASN1_TIME_it*(): ptr ASN1_ITEM_536871574 {.cdecl, importc: "ASN1_TIME_it".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_it" & " already exists, not redeclaring")
when not declared(ASN1_TIME_dup):
  proc ASN1_TIME_dup*(a: ptr ASN1_TIME_536871640): ptr ASN1_TIME_536871640 {.
      cdecl, importc: "ASN1_TIME_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_dup):
  proc ASN1_UTCTIME_dup*(a: ptr ASN1_UTCTIME_536871604): ptr ASN1_UTCTIME_536871604 {.
      cdecl, importc: "ASN1_UTCTIME_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_dup):
  proc ASN1_GENERALIZEDTIME_dup*(a: ptr ASN1_GENERALIZEDTIME_536871606): ptr ASN1_GENERALIZEDTIME_536871606 {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_OCTET_STRING_NDEF_it):
  proc ASN1_OCTET_STRING_NDEF_it*(): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_OCTET_STRING_NDEF_it".}
else:
  static :
    hint("Declaration of " & "ASN1_OCTET_STRING_NDEF_it" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_set):
  proc ASN1_TIME_set*(s: ptr ASN1_TIME_536871640; t: time_t_536871443): ptr ASN1_TIME_536871640 {.
      cdecl, importc: "ASN1_TIME_set".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_set" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_adj):
  proc ASN1_TIME_adj*(s: ptr ASN1_TIME_536871640; t: time_t_536871443;
                      offset_day: cint; offset_sec: clong): ptr ASN1_TIME_536871640 {.
      cdecl, importc: "ASN1_TIME_adj".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_adj" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_check):
  proc ASN1_TIME_check*(t: ptr ASN1_TIME_536871640): cint {.cdecl,
      importc: "ASN1_TIME_check".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_check" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_to_generalizedtime):
  proc ASN1_TIME_to_generalizedtime*(t: ptr ASN1_TIME_536871640;
                                     out_arg: ptr ptr ASN1_GENERALIZEDTIME_536871606): ptr ASN1_GENERALIZEDTIME_536871606 {.
      cdecl, importc: "ASN1_TIME_to_generalizedtime".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_to_generalizedtime" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_set_string):
  proc ASN1_TIME_set_string*(s: ptr ASN1_TIME_536871640; str: cstring): cint {.
      cdecl, importc: "ASN1_TIME_set_string".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_set_string" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_set_string_X509):
  proc ASN1_TIME_set_string_X509*(s: ptr ASN1_TIME_536871640; str: cstring): cint {.
      cdecl, importc: "ASN1_TIME_set_string_X509".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_set_string_X509" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_to_tm):
  proc ASN1_TIME_to_tm*(s: ptr ASN1_TIME_536871640; tm: ptr struct_tm_536871518): cint {.
      cdecl, importc: "ASN1_TIME_to_tm".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_to_tm" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_normalize):
  proc ASN1_TIME_normalize*(s: ptr ASN1_TIME_536871640): cint {.cdecl,
      importc: "ASN1_TIME_normalize".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_normalize" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_cmp_time_t):
  proc ASN1_TIME_cmp_time_t*(s: ptr ASN1_TIME_536871640; t: time_t_536871443): cint {.
      cdecl, importc: "ASN1_TIME_cmp_time_t".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_cmp_time_t" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_compare):
  proc ASN1_TIME_compare*(a: ptr ASN1_TIME_536871640; b: ptr ASN1_TIME_536871640): cint {.
      cdecl, importc: "ASN1_TIME_compare".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_compare" &
        " already exists, not redeclaring")
when not declared(i2a_ASN1_INTEGER):
  proc i2a_ASN1_INTEGER*(bp: ptr BIO_536871632; a: ptr ASN1_INTEGER_536871584): cint {.
      cdecl, importc: "i2a_ASN1_INTEGER".}
else:
  static :
    hint("Declaration of " & "i2a_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(a2i_ASN1_INTEGER):
  proc a2i_ASN1_INTEGER*(bp: ptr BIO_536871632; bs: ptr ASN1_INTEGER_536871584;
                         buf: cstring; size: cint): cint {.cdecl,
      importc: "a2i_ASN1_INTEGER".}
else:
  static :
    hint("Declaration of " & "a2i_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(i2a_ASN1_ENUMERATED):
  proc i2a_ASN1_ENUMERATED*(bp: ptr BIO_536871632; a: ptr ASN1_ENUMERATED_536871586): cint {.
      cdecl, importc: "i2a_ASN1_ENUMERATED".}
else:
  static :
    hint("Declaration of " & "i2a_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(a2i_ASN1_ENUMERATED):
  proc a2i_ASN1_ENUMERATED*(bp: ptr BIO_536871632; bs: ptr ASN1_ENUMERATED_536871586;
                            buf: cstring; size: cint): cint {.cdecl,
      importc: "a2i_ASN1_ENUMERATED".}
else:
  static :
    hint("Declaration of " & "a2i_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(i2a_ASN1_OBJECT):
  proc i2a_ASN1_OBJECT*(bp: ptr BIO_536871632; a: ptr ASN1_OBJECT_536871582): cint {.
      cdecl, importc: "i2a_ASN1_OBJECT".}
else:
  static :
    hint("Declaration of " & "i2a_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(a2i_ASN1_STRING):
  proc a2i_ASN1_STRING*(bp: ptr BIO_536871632; bs: ptr ASN1_STRING_536871580;
                        buf: cstring; size: cint): cint {.cdecl,
      importc: "a2i_ASN1_STRING".}
else:
  static :
    hint("Declaration of " & "a2i_ASN1_STRING" &
        " already exists, not redeclaring")
when not declared(i2a_ASN1_STRING):
  proc i2a_ASN1_STRING*(bp: ptr BIO_536871632; a: ptr ASN1_STRING_536871580;
                        type_arg: cint): cint {.cdecl,
      importc: "i2a_ASN1_STRING".}
else:
  static :
    hint("Declaration of " & "i2a_ASN1_STRING" &
        " already exists, not redeclaring")
when not declared(i2t_ASN1_OBJECT):
  proc i2t_ASN1_OBJECT*(buf: cstring; buf_len: cint; a: ptr ASN1_OBJECT_536871582): cint {.
      cdecl, importc: "i2t_ASN1_OBJECT".}
else:
  static :
    hint("Declaration of " & "i2t_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(a2d_ASN1_OBJECT):
  proc a2d_ASN1_OBJECT*(out_arg: ptr uint8; olen: cint; buf: cstring; num: cint): cint {.
      cdecl, importc: "a2d_ASN1_OBJECT".}
else:
  static :
    hint("Declaration of " & "a2d_ASN1_OBJECT" &
        " already exists, not redeclaring")
when not declared(ASN1_OBJECT_create):
  proc ASN1_OBJECT_create*(nid: cint; data: ptr uint8; len: cint; sn: cstring;
                           ln: cstring): ptr ASN1_OBJECT_536871582 {.cdecl,
      importc: "ASN1_OBJECT_create".}
else:
  static :
    hint("Declaration of " & "ASN1_OBJECT_create" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_get_int64):
  proc ASN1_INTEGER_get_int64*(pr: ptr int64; a: ptr ASN1_INTEGER_536871584): cint {.
      cdecl, importc: "ASN1_INTEGER_get_int64".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_get_int64" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_set_int64):
  proc ASN1_INTEGER_set_int64*(a: ptr ASN1_INTEGER_536871584; r: int64): cint {.
      cdecl, importc: "ASN1_INTEGER_set_int64".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_set_int64" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_get_uint64):
  proc ASN1_INTEGER_get_uint64*(pr: ptr uint64; a: ptr ASN1_INTEGER_536871584): cint {.
      cdecl, importc: "ASN1_INTEGER_get_uint64".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_get_uint64" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_set_uint64):
  proc ASN1_INTEGER_set_uint64*(a: ptr ASN1_INTEGER_536871584; r: uint64): cint {.
      cdecl, importc: "ASN1_INTEGER_set_uint64".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_set_uint64" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_set):
  proc ASN1_INTEGER_set*(a: ptr ASN1_INTEGER_536871584; v: clong): cint {.cdecl,
      importc: "ASN1_INTEGER_set".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_set" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_get):
  proc ASN1_INTEGER_get*(a: ptr ASN1_INTEGER_536871584): clong {.cdecl,
      importc: "ASN1_INTEGER_get".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_get" &
        " already exists, not redeclaring")
when not declared(BN_to_ASN1_INTEGER):
  proc BN_to_ASN1_INTEGER*(bn: ptr BIGNUM_536871656; ai: ptr ASN1_INTEGER_536871584): ptr ASN1_INTEGER_536871584 {.
      cdecl, importc: "BN_to_ASN1_INTEGER".}
else:
  static :
    hint("Declaration of " & "BN_to_ASN1_INTEGER" &
        " already exists, not redeclaring")
when not declared(ASN1_INTEGER_to_BN):
  proc ASN1_INTEGER_to_BN*(ai: ptr ASN1_INTEGER_536871584; bn: ptr BIGNUM_536871656): ptr BIGNUM_536871656 {.
      cdecl, importc: "ASN1_INTEGER_to_BN".}
else:
  static :
    hint("Declaration of " & "ASN1_INTEGER_to_BN" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_get_int64):
  proc ASN1_ENUMERATED_get_int64*(pr: ptr int64; a: ptr ASN1_ENUMERATED_536871586): cint {.
      cdecl, importc: "ASN1_ENUMERATED_get_int64".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_get_int64" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_set_int64):
  proc ASN1_ENUMERATED_set_int64*(a: ptr ASN1_ENUMERATED_536871586; r: int64): cint {.
      cdecl, importc: "ASN1_ENUMERATED_set_int64".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_set_int64" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_set):
  proc ASN1_ENUMERATED_set*(a: ptr ASN1_ENUMERATED_536871586; v: clong): cint {.
      cdecl, importc: "ASN1_ENUMERATED_set".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_set" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_get):
  proc ASN1_ENUMERATED_get*(a: ptr ASN1_ENUMERATED_536871586): clong {.cdecl,
      importc: "ASN1_ENUMERATED_get".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_get" &
        " already exists, not redeclaring")
when not declared(BN_to_ASN1_ENUMERATED):
  proc BN_to_ASN1_ENUMERATED*(bn: ptr BIGNUM_536871656; ai: ptr ASN1_ENUMERATED_536871586): ptr ASN1_ENUMERATED_536871586 {.
      cdecl, importc: "BN_to_ASN1_ENUMERATED".}
else:
  static :
    hint("Declaration of " & "BN_to_ASN1_ENUMERATED" &
        " already exists, not redeclaring")
when not declared(ASN1_ENUMERATED_to_BN):
  proc ASN1_ENUMERATED_to_BN*(ai: ptr ASN1_ENUMERATED_536871586; bn: ptr BIGNUM_536871656): ptr BIGNUM_536871656 {.
      cdecl, importc: "ASN1_ENUMERATED_to_BN".}
else:
  static :
    hint("Declaration of " & "ASN1_ENUMERATED_to_BN" &
        " already exists, not redeclaring")
when not declared(ASN1_PRINTABLE_type):
  proc ASN1_PRINTABLE_type*(s: ptr uint8; max: cint): cint {.cdecl,
      importc: "ASN1_PRINTABLE_type".}
else:
  static :
    hint("Declaration of " & "ASN1_PRINTABLE_type" &
        " already exists, not redeclaring")
when not declared(ASN1_tag2bit):
  proc ASN1_tag2bit*(tag: cint): culong {.cdecl, importc: "ASN1_tag2bit".}
else:
  static :
    hint("Declaration of " & "ASN1_tag2bit" & " already exists, not redeclaring")
when not declared(ASN1_get_object):
  proc ASN1_get_object*(pp: ptr ptr uint8; plength: ptr clong; ptag: ptr cint;
                        pclass: ptr cint; omax: clong): cint {.cdecl,
      importc: "ASN1_get_object".}
else:
  static :
    hint("Declaration of " & "ASN1_get_object" &
        " already exists, not redeclaring")
when not declared(ASN1_check_infinite_end):
  proc ASN1_check_infinite_end*(p: ptr ptr uint8; len: clong): cint {.cdecl,
      importc: "ASN1_check_infinite_end".}
else:
  static :
    hint("Declaration of " & "ASN1_check_infinite_end" &
        " already exists, not redeclaring")
when not declared(ASN1_const_check_infinite_end):
  proc ASN1_const_check_infinite_end*(p: ptr ptr uint8; len: clong): cint {.
      cdecl, importc: "ASN1_const_check_infinite_end".}
else:
  static :
    hint("Declaration of " & "ASN1_const_check_infinite_end" &
        " already exists, not redeclaring")
when not declared(ASN1_put_object):
  proc ASN1_put_object*(pp: ptr ptr uint8; constructed: cint; length: cint;
                        tag: cint; xclass: cint): void {.cdecl,
      importc: "ASN1_put_object".}
else:
  static :
    hint("Declaration of " & "ASN1_put_object" &
        " already exists, not redeclaring")
when not declared(ASN1_put_eoc):
  proc ASN1_put_eoc*(pp: ptr ptr uint8): cint {.cdecl, importc: "ASN1_put_eoc".}
else:
  static :
    hint("Declaration of " & "ASN1_put_eoc" & " already exists, not redeclaring")
when not declared(ASN1_object_size):
  proc ASN1_object_size*(constructed: cint; length: cint; tag: cint): cint {.
      cdecl, importc: "ASN1_object_size".}
else:
  static :
    hint("Declaration of " & "ASN1_object_size" &
        " already exists, not redeclaring")
when not declared(ASN1_dup):
  proc ASN1_dup*(i2d: i2d_of_void_536871570; d2i: d2i_of_void_536871568;
                 x: pointer): pointer {.cdecl, importc: "ASN1_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_dup" & " already exists, not redeclaring")
when not declared(ASN1_item_dup):
  proc ASN1_item_dup*(it: ptr ASN1_ITEM_536871574; x: pointer): pointer {.cdecl,
      importc: "ASN1_item_dup".}
else:
  static :
    hint("Declaration of " & "ASN1_item_dup" &
        " already exists, not redeclaring")
when not declared(ASN1_item_sign_ex):
  proc ASN1_item_sign_ex*(it: ptr ASN1_ITEM_536871574; algor1: ptr X509_ALGOR_536871540;
                          algor2: ptr X509_ALGOR_536871540;
                          signature: ptr ASN1_BIT_STRING_536871588;
                          data: pointer; id: ptr ASN1_OCTET_STRING_536871590;
                          pkey: ptr EVP_PKEY_536871658; md: ptr EVP_MD_536871660;
                          libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring): cint {.
      cdecl, importc: "ASN1_item_sign_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_sign_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_item_verify_ex):
  proc ASN1_item_verify_ex*(it: ptr ASN1_ITEM_536871574; alg: ptr X509_ALGOR_536871540;
                            signature: ptr ASN1_BIT_STRING_536871588;
                            data: pointer; id: ptr ASN1_OCTET_STRING_536871590;
                            pkey: ptr EVP_PKEY_536871658;
                            libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring): cint {.
      cdecl, importc: "ASN1_item_verify_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_verify_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_d2i_fp):
  proc ASN1_d2i_fp*(xnew: proc (): pointer {.cdecl.}; d2i: d2i_of_void_536871568;
                    in_arg: ptr Cfile_536871662; x: ptr pointer): pointer {.
      cdecl, importc: "ASN1_d2i_fp".}
else:
  static :
    hint("Declaration of " & "ASN1_d2i_fp" & " already exists, not redeclaring")
when not declared(ASN1_item_d2i_fp_ex):
  proc ASN1_item_d2i_fp_ex*(it: ptr ASN1_ITEM_536871574; in_arg: ptr Cfile_536871662;
                            x: pointer; libctx: ptr OSSL_LIB_CTX_536871484;
                            propq: cstring): pointer {.cdecl,
      importc: "ASN1_item_d2i_fp_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i_fp_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_item_d2i_fp):
  proc ASN1_item_d2i_fp*(it: ptr ASN1_ITEM_536871574; in_arg: ptr Cfile_536871662;
                         x: pointer): pointer {.cdecl,
      importc: "ASN1_item_d2i_fp".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i_fp" &
        " already exists, not redeclaring")
when not declared(ASN1_i2d_fp):
  proc ASN1_i2d_fp*(i2d: i2d_of_void_536871570; out_arg: ptr Cfile_536871662;
                    x: pointer): cint {.cdecl, importc: "ASN1_i2d_fp".}
else:
  static :
    hint("Declaration of " & "ASN1_i2d_fp" & " already exists, not redeclaring")
when not declared(ASN1_item_i2d_fp):
  proc ASN1_item_i2d_fp*(it: ptr ASN1_ITEM_536871574; out_arg: ptr Cfile_536871662;
                         x: pointer): cint {.cdecl, importc: "ASN1_item_i2d_fp".}
else:
  static :
    hint("Declaration of " & "ASN1_item_i2d_fp" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_print_ex_fp):
  proc ASN1_STRING_print_ex_fp*(fp: ptr Cfile_536871662; str: ptr ASN1_STRING_536871580;
                                flags: culong): cint {.cdecl,
      importc: "ASN1_STRING_print_ex_fp".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_print_ex_fp" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_to_UTF8):
  proc ASN1_STRING_to_UTF8*(out_arg: ptr ptr uint8; in_arg: ptr ASN1_STRING_536871580): cint {.
      cdecl, importc: "ASN1_STRING_to_UTF8".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_to_UTF8" &
        " already exists, not redeclaring")
when not declared(ASN1_d2i_bio):
  proc ASN1_d2i_bio*(xnew: proc (): pointer {.cdecl.}; d2i: d2i_of_void_536871568;
                     in_arg: ptr BIO_536871632; x: ptr pointer): pointer {.
      cdecl, importc: "ASN1_d2i_bio".}
else:
  static :
    hint("Declaration of " & "ASN1_d2i_bio" & " already exists, not redeclaring")
when not declared(ASN1_item_d2i_bio_ex):
  proc ASN1_item_d2i_bio_ex*(it: ptr ASN1_ITEM_536871574; in_arg: ptr BIO_536871632;
                             pval: pointer; libctx: ptr OSSL_LIB_CTX_536871484;
                             propq: cstring): pointer {.cdecl,
      importc: "ASN1_item_d2i_bio_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i_bio_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_item_d2i_bio):
  proc ASN1_item_d2i_bio*(it: ptr ASN1_ITEM_536871574; in_arg: ptr BIO_536871632;
                          pval: pointer): pointer {.cdecl,
      importc: "ASN1_item_d2i_bio".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i_bio" &
        " already exists, not redeclaring")
when not declared(ASN1_i2d_bio):
  proc ASN1_i2d_bio*(i2d: i2d_of_void_536871570; out_arg: ptr BIO_536871632;
                     x: pointer): cint {.cdecl, importc: "ASN1_i2d_bio".}
else:
  static :
    hint("Declaration of " & "ASN1_i2d_bio" & " already exists, not redeclaring")
when not declared(ASN1_item_i2d_bio):
  proc ASN1_item_i2d_bio*(it: ptr ASN1_ITEM_536871574; out_arg: ptr BIO_536871632;
                          x: pointer): cint {.cdecl,
      importc: "ASN1_item_i2d_bio".}
else:
  static :
    hint("Declaration of " & "ASN1_item_i2d_bio" &
        " already exists, not redeclaring")
when not declared(ASN1_item_i2d_mem_bio):
  proc ASN1_item_i2d_mem_bio*(it: ptr ASN1_ITEM_536871574; val: ptr ASN1_VALUE_536871566): ptr BIO_536871632 {.
      cdecl, importc: "ASN1_item_i2d_mem_bio".}
else:
  static :
    hint("Declaration of " & "ASN1_item_i2d_mem_bio" &
        " already exists, not redeclaring")
when not declared(ASN1_UTCTIME_print):
  proc ASN1_UTCTIME_print*(fp: ptr BIO_536871632; a: ptr ASN1_UTCTIME_536871604): cint {.
      cdecl, importc: "ASN1_UTCTIME_print".}
else:
  static :
    hint("Declaration of " & "ASN1_UTCTIME_print" &
        " already exists, not redeclaring")
when not declared(ASN1_GENERALIZEDTIME_print):
  proc ASN1_GENERALIZEDTIME_print*(fp: ptr BIO_536871632;
                                   a: ptr ASN1_GENERALIZEDTIME_536871606): cint {.
      cdecl, importc: "ASN1_GENERALIZEDTIME_print".}
else:
  static :
    hint("Declaration of " & "ASN1_GENERALIZEDTIME_print" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_print):
  proc ASN1_TIME_print*(bp: ptr BIO_536871632; tm: ptr ASN1_TIME_536871640): cint {.
      cdecl, importc: "ASN1_TIME_print".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_print" &
        " already exists, not redeclaring")
when not declared(ASN1_TIME_print_ex):
  proc ASN1_TIME_print_ex*(bp: ptr BIO_536871632; tm: ptr ASN1_TIME_536871640;
                           flags: culong): cint {.cdecl,
      importc: "ASN1_TIME_print_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_TIME_print_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_print):
  proc ASN1_STRING_print*(bp: ptr BIO_536871632; v: ptr ASN1_STRING_536871580): cint {.
      cdecl, importc: "ASN1_STRING_print".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_print" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_print_ex):
  proc ASN1_STRING_print_ex*(out_arg: ptr BIO_536871632; str: ptr ASN1_STRING_536871580;
                             flags: culong): cint {.cdecl,
      importc: "ASN1_STRING_print_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_print_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_buf_print):
  proc ASN1_buf_print*(bp: ptr BIO_536871632; buf: ptr uint8; buflen: csize_t;
                       off: cint): cint {.cdecl, importc: "ASN1_buf_print".}
else:
  static :
    hint("Declaration of " & "ASN1_buf_print" &
        " already exists, not redeclaring")
when not declared(ASN1_bn_print):
  proc ASN1_bn_print*(bp: ptr BIO_536871632; number: cstring; num: ptr BIGNUM_536871656;
                      buf: ptr uint8; off: cint): cint {.cdecl,
      importc: "ASN1_bn_print".}
else:
  static :
    hint("Declaration of " & "ASN1_bn_print" &
        " already exists, not redeclaring")
when not declared(ASN1_parse):
  proc ASN1_parse*(bp: ptr BIO_536871632; pp: ptr uint8; len: clong;
                   indent: cint): cint {.cdecl, importc: "ASN1_parse".}
else:
  static :
    hint("Declaration of " & "ASN1_parse" & " already exists, not redeclaring")
when not declared(ASN1_parse_dump):
  proc ASN1_parse_dump*(bp: ptr BIO_536871632; pp: ptr uint8; len: clong;
                        indent: cint; dump: cint): cint {.cdecl,
      importc: "ASN1_parse_dump".}
else:
  static :
    hint("Declaration of " & "ASN1_parse_dump" &
        " already exists, not redeclaring")
when not declared(ASN1_tag2str):
  proc ASN1_tag2str*(tag: cint): cstring {.cdecl, importc: "ASN1_tag2str".}
else:
  static :
    hint("Declaration of " & "ASN1_tag2str" & " already exists, not redeclaring")
when not declared(ASN1_UNIVERSALSTRING_to_string):
  proc ASN1_UNIVERSALSTRING_to_string*(s: ptr ASN1_UNIVERSALSTRING_536871602): cint {.
      cdecl, importc: "ASN1_UNIVERSALSTRING_to_string".}
else:
  static :
    hint("Declaration of " & "ASN1_UNIVERSALSTRING_to_string" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_set_octetstring):
  proc ASN1_TYPE_set_octetstring*(a: ptr ASN1_TYPE_536871614; data: ptr uint8;
                                  len: cint): cint {.cdecl,
      importc: "ASN1_TYPE_set_octetstring".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_set_octetstring" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_get_octetstring):
  proc ASN1_TYPE_get_octetstring*(a: ptr ASN1_TYPE_536871614; data: ptr uint8;
                                  max_len: cint): cint {.cdecl,
      importc: "ASN1_TYPE_get_octetstring".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_get_octetstring" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_set_int_octetstring):
  proc ASN1_TYPE_set_int_octetstring*(a: ptr ASN1_TYPE_536871614; num: clong;
                                      data: ptr uint8; len: cint): cint {.cdecl,
      importc: "ASN1_TYPE_set_int_octetstring".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_set_int_octetstring" &
        " already exists, not redeclaring")
when not declared(ASN1_TYPE_get_int_octetstring):
  proc ASN1_TYPE_get_int_octetstring*(a: ptr ASN1_TYPE_536871614;
                                      num: ptr clong; data: ptr uint8;
                                      max_len: cint): cint {.cdecl,
      importc: "ASN1_TYPE_get_int_octetstring".}
else:
  static :
    hint("Declaration of " & "ASN1_TYPE_get_int_octetstring" &
        " already exists, not redeclaring")
when not declared(ASN1_item_unpack):
  proc ASN1_item_unpack*(oct: ptr ASN1_STRING_536871580; it: ptr ASN1_ITEM_536871574): pointer {.
      cdecl, importc: "ASN1_item_unpack".}
else:
  static :
    hint("Declaration of " & "ASN1_item_unpack" &
        " already exists, not redeclaring")
when not declared(ASN1_item_pack):
  proc ASN1_item_pack*(obj: pointer; it: ptr ASN1_ITEM_536871574;
                       oct: ptr ptr ASN1_OCTET_STRING_536871590): ptr ASN1_STRING_536871580 {.
      cdecl, importc: "ASN1_item_pack".}
else:
  static :
    hint("Declaration of " & "ASN1_item_pack" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_set_default_mask):
  proc ASN1_STRING_set_default_mask*(mask: culong): void {.cdecl,
      importc: "ASN1_STRING_set_default_mask".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_set_default_mask" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_set_default_mask_asc):
  proc ASN1_STRING_set_default_mask_asc*(p: cstring): cint {.cdecl,
      importc: "ASN1_STRING_set_default_mask_asc".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_set_default_mask_asc" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_get_default_mask):
  proc ASN1_STRING_get_default_mask*(): culong {.cdecl,
      importc: "ASN1_STRING_get_default_mask".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_get_default_mask" &
        " already exists, not redeclaring")
when not declared(ASN1_mbstring_copy):
  proc ASN1_mbstring_copy*(out_arg: ptr ptr ASN1_STRING_536871580;
                           in_arg: ptr uint8; len: cint; inform: cint;
                           mask: culong): cint {.cdecl,
      importc: "ASN1_mbstring_copy".}
else:
  static :
    hint("Declaration of " & "ASN1_mbstring_copy" &
        " already exists, not redeclaring")
when not declared(ASN1_mbstring_ncopy):
  proc ASN1_mbstring_ncopy*(out_arg: ptr ptr ASN1_STRING_536871580;
                            in_arg: ptr uint8; len: cint; inform: cint;
                            mask: culong; minsize: clong; maxsize: clong): cint {.
      cdecl, importc: "ASN1_mbstring_ncopy".}
else:
  static :
    hint("Declaration of " & "ASN1_mbstring_ncopy" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_set_by_NID):
  proc ASN1_STRING_set_by_NID*(out_arg: ptr ptr ASN1_STRING_536871580;
                               in_arg: ptr uint8; inlen: cint; inform: cint;
                               nid: cint): ptr ASN1_STRING_536871580 {.cdecl,
      importc: "ASN1_STRING_set_by_NID".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_set_by_NID" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_TABLE_get):
  proc ASN1_STRING_TABLE_get*(nid: cint): ptr ASN1_STRING_TABLE_536871556 {.
      cdecl, importc: "ASN1_STRING_TABLE_get".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_TABLE_get" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_TABLE_add):
  proc ASN1_STRING_TABLE_add*(a0: cint; a1: clong; a2: clong; a3: culong;
                              a4: culong): cint {.cdecl,
      importc: "ASN1_STRING_TABLE_add".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_TABLE_add" &
        " already exists, not redeclaring")
when not declared(ASN1_STRING_TABLE_cleanup):
  proc ASN1_STRING_TABLE_cleanup*(): void {.cdecl,
      importc: "ASN1_STRING_TABLE_cleanup".}
else:
  static :
    hint("Declaration of " & "ASN1_STRING_TABLE_cleanup" &
        " already exists, not redeclaring")
when not declared(ASN1_item_new):
  proc ASN1_item_new*(it: ptr ASN1_ITEM_536871574): ptr ASN1_VALUE_536871566 {.
      cdecl, importc: "ASN1_item_new".}
else:
  static :
    hint("Declaration of " & "ASN1_item_new" &
        " already exists, not redeclaring")
when not declared(ASN1_item_new_ex):
  proc ASN1_item_new_ex*(it: ptr ASN1_ITEM_536871574; libctx: ptr OSSL_LIB_CTX_536871484;
                         propq: cstring): ptr ASN1_VALUE_536871566 {.cdecl,
      importc: "ASN1_item_new_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_new_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_item_free):
  proc ASN1_item_free*(val: ptr ASN1_VALUE_536871566; it: ptr ASN1_ITEM_536871574): void {.
      cdecl, importc: "ASN1_item_free".}
else:
  static :
    hint("Declaration of " & "ASN1_item_free" &
        " already exists, not redeclaring")
when not declared(ASN1_item_d2i_ex):
  proc ASN1_item_d2i_ex*(val: ptr ptr ASN1_VALUE_536871566;
                         in_arg: ptr ptr uint8; len: clong; it: ptr ASN1_ITEM_536871574;
                         libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring): ptr ASN1_VALUE_536871566 {.
      cdecl, importc: "ASN1_item_d2i_ex".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i_ex" &
        " already exists, not redeclaring")
when not declared(ASN1_item_d2i):
  proc ASN1_item_d2i*(val: ptr ptr ASN1_VALUE_536871566; in_arg: ptr ptr uint8;
                      len: clong; it: ptr ASN1_ITEM_536871574): ptr ASN1_VALUE_536871566 {.
      cdecl, importc: "ASN1_item_d2i".}
else:
  static :
    hint("Declaration of " & "ASN1_item_d2i" &
        " already exists, not redeclaring")
when not declared(ASN1_item_i2d):
  proc ASN1_item_i2d*(val: ptr ASN1_VALUE_536871566; out_arg: ptr ptr uint8;
                      it: ptr ASN1_ITEM_536871574): cint {.cdecl,
      importc: "ASN1_item_i2d".}
else:
  static :
    hint("Declaration of " & "ASN1_item_i2d" &
        " already exists, not redeclaring")
when not declared(ASN1_item_ndef_i2d):
  proc ASN1_item_ndef_i2d*(val: ptr ASN1_VALUE_536871566;
                           out_arg: ptr ptr uint8; it: ptr ASN1_ITEM_536871574): cint {.
      cdecl, importc: "ASN1_item_ndef_i2d".}
else:
  static :
    hint("Declaration of " & "ASN1_item_ndef_i2d" &
        " already exists, not redeclaring")
when not declared(ASN1_add_oid_module):
  proc ASN1_add_oid_module*(): void {.cdecl, importc: "ASN1_add_oid_module".}
else:
  static :
    hint("Declaration of " & "ASN1_add_oid_module" &
        " already exists, not redeclaring")
when not declared(ASN1_add_stable_module):
  proc ASN1_add_stable_module*(): void {.cdecl,
      importc: "ASN1_add_stable_module".}
else:
  static :
    hint("Declaration of " & "ASN1_add_stable_module" &
        " already exists, not redeclaring")
when not declared(ASN1_generate_nconf):
  proc ASN1_generate_nconf*(str: cstring; nconf: ptr CONF_536871664): ptr ASN1_TYPE_536871614 {.
      cdecl, importc: "ASN1_generate_nconf".}
else:
  static :
    hint("Declaration of " & "ASN1_generate_nconf" &
        " already exists, not redeclaring")
when not declared(ASN1_generate_v3):
  proc ASN1_generate_v3*(str: cstring; cnf: ptr X509V3_CTX_536871666): ptr ASN1_TYPE_536871614 {.
      cdecl, importc: "ASN1_generate_v3".}
else:
  static :
    hint("Declaration of " & "ASN1_generate_v3" &
        " already exists, not redeclaring")
when not declared(ASN1_str2mask):
  proc ASN1_str2mask*(str: cstring; pmask: ptr culong): cint {.cdecl,
      importc: "ASN1_str2mask".}
else:
  static :
    hint("Declaration of " & "ASN1_str2mask" &
        " already exists, not redeclaring")
when not declared(ASN1_item_print):
  proc ASN1_item_print*(out_arg: ptr BIO_536871632; ifld: ptr ASN1_VALUE_536871566;
                        indent: cint; it: ptr ASN1_ITEM_536871574;
                        pctx: ptr ASN1_PCTX_536871668): cint {.cdecl,
      importc: "ASN1_item_print".}
else:
  static :
    hint("Declaration of " & "ASN1_item_print" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_new):
  proc ASN1_PCTX_new*(): ptr ASN1_PCTX_536871668 {.cdecl,
      importc: "ASN1_PCTX_new".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_new" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_free):
  proc ASN1_PCTX_free*(p: ptr ASN1_PCTX_536871668): void {.cdecl,
      importc: "ASN1_PCTX_free".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_free" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_get_flags):
  proc ASN1_PCTX_get_flags*(p: ptr ASN1_PCTX_536871668): culong {.cdecl,
      importc: "ASN1_PCTX_get_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_get_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_set_flags):
  proc ASN1_PCTX_set_flags*(p: ptr ASN1_PCTX_536871668; flags: culong): void {.
      cdecl, importc: "ASN1_PCTX_set_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_set_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_get_nm_flags):
  proc ASN1_PCTX_get_nm_flags*(p: ptr ASN1_PCTX_536871668): culong {.cdecl,
      importc: "ASN1_PCTX_get_nm_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_get_nm_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_set_nm_flags):
  proc ASN1_PCTX_set_nm_flags*(p: ptr ASN1_PCTX_536871668; flags: culong): void {.
      cdecl, importc: "ASN1_PCTX_set_nm_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_set_nm_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_get_cert_flags):
  proc ASN1_PCTX_get_cert_flags*(p: ptr ASN1_PCTX_536871668): culong {.cdecl,
      importc: "ASN1_PCTX_get_cert_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_get_cert_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_set_cert_flags):
  proc ASN1_PCTX_set_cert_flags*(p: ptr ASN1_PCTX_536871668; flags: culong): void {.
      cdecl, importc: "ASN1_PCTX_set_cert_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_set_cert_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_get_oid_flags):
  proc ASN1_PCTX_get_oid_flags*(p: ptr ASN1_PCTX_536871668): culong {.cdecl,
      importc: "ASN1_PCTX_get_oid_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_get_oid_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_set_oid_flags):
  proc ASN1_PCTX_set_oid_flags*(p: ptr ASN1_PCTX_536871668; flags: culong): void {.
      cdecl, importc: "ASN1_PCTX_set_oid_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_set_oid_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_get_str_flags):
  proc ASN1_PCTX_get_str_flags*(p: ptr ASN1_PCTX_536871668): culong {.cdecl,
      importc: "ASN1_PCTX_get_str_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_get_str_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_PCTX_set_str_flags):
  proc ASN1_PCTX_set_str_flags*(p: ptr ASN1_PCTX_536871668; flags: culong): void {.
      cdecl, importc: "ASN1_PCTX_set_str_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_PCTX_set_str_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_new):
  proc ASN1_SCTX_new*(scan_cb: proc (a0: ptr ASN1_SCTX_536871670): cint {.cdecl.}): ptr ASN1_SCTX_536871670 {.
      cdecl, importc: "ASN1_SCTX_new".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_new" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_free):
  proc ASN1_SCTX_free*(p: ptr ASN1_SCTX_536871670): void {.cdecl,
      importc: "ASN1_SCTX_free".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_free" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_get_item):
  proc ASN1_SCTX_get_item*(p: ptr ASN1_SCTX_536871670): ptr ASN1_ITEM_536871574 {.
      cdecl, importc: "ASN1_SCTX_get_item".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_get_item" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_get_template):
  proc ASN1_SCTX_get_template*(p: ptr ASN1_SCTX_536871670): ptr ASN1_TEMPLATE_536871562 {.
      cdecl, importc: "ASN1_SCTX_get_template".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_get_template" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_get_flags):
  proc ASN1_SCTX_get_flags*(p: ptr ASN1_SCTX_536871670): culong {.cdecl,
      importc: "ASN1_SCTX_get_flags".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_get_flags" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_set_app_data):
  proc ASN1_SCTX_set_app_data*(p: ptr ASN1_SCTX_536871670; data: pointer): void {.
      cdecl, importc: "ASN1_SCTX_set_app_data".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_set_app_data" &
        " already exists, not redeclaring")
when not declared(ASN1_SCTX_get_app_data):
  proc ASN1_SCTX_get_app_data*(p: ptr ASN1_SCTX_536871670): pointer {.cdecl,
      importc: "ASN1_SCTX_get_app_data".}
else:
  static :
    hint("Declaration of " & "ASN1_SCTX_get_app_data" &
        " already exists, not redeclaring")
when not declared(BIO_f_asn1):
  proc BIO_f_asn1*(): ptr BIO_METHOD_536871672 {.cdecl, importc: "BIO_f_asn1".}
else:
  static :
    hint("Declaration of " & "BIO_f_asn1" & " already exists, not redeclaring")
when not declared(BIO_new_NDEF):
  proc BIO_new_NDEF*(out_arg: ptr BIO_536871632; val: ptr ASN1_VALUE_536871566;
                     it: ptr ASN1_ITEM_536871574): ptr BIO_536871632 {.cdecl,
      importc: "BIO_new_NDEF".}
else:
  static :
    hint("Declaration of " & "BIO_new_NDEF" & " already exists, not redeclaring")
when not declared(i2d_ASN1_bio_stream):
  proc i2d_ASN1_bio_stream*(out_arg: ptr BIO_536871632; val: ptr ASN1_VALUE_536871566;
                            in_arg: ptr BIO_536871632; flags: cint;
                            it: ptr ASN1_ITEM_536871574): cint {.cdecl,
      importc: "i2d_ASN1_bio_stream".}
else:
  static :
    hint("Declaration of " & "i2d_ASN1_bio_stream" &
        " already exists, not redeclaring")
when not declared(PEM_write_bio_ASN1_stream):
  proc PEM_write_bio_ASN1_stream*(out_arg: ptr BIO_536871632;
                                  val: ptr ASN1_VALUE_536871566;
                                  in_arg: ptr BIO_536871632; flags: cint;
                                  hdr: cstring; it: ptr ASN1_ITEM_536871574): cint {.
      cdecl, importc: "PEM_write_bio_ASN1_stream".}
else:
  static :
    hint("Declaration of " & "PEM_write_bio_ASN1_stream" &
        " already exists, not redeclaring")
when not declared(SMIME_write_ASN1):
  proc SMIME_write_ASN1*(bio: ptr BIO_536871632; val: ptr ASN1_VALUE_536871566;
                         data: ptr BIO_536871632; flags: cint; ctype_nid: cint;
                         econt_nid: cint;
                         mdalgs: ptr struct_stack_st_X509_ALGOR;
                         it: ptr ASN1_ITEM_536871574): cint {.cdecl,
      importc: "SMIME_write_ASN1".}
else:
  static :
    hint("Declaration of " & "SMIME_write_ASN1" &
        " already exists, not redeclaring")
when not declared(SMIME_write_ASN1_ex):
  proc SMIME_write_ASN1_ex*(bio: ptr BIO_536871632; val: ptr ASN1_VALUE_536871566;
                            data: ptr BIO_536871632; flags: cint;
                            ctype_nid: cint; econt_nid: cint;
                            mdalgs: ptr struct_stack_st_X509_ALGOR;
                            it: ptr ASN1_ITEM_536871574;
                            libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring): cint {.
      cdecl, importc: "SMIME_write_ASN1_ex".}
else:
  static :
    hint("Declaration of " & "SMIME_write_ASN1_ex" &
        " already exists, not redeclaring")
when not declared(SMIME_read_ASN1):
  proc SMIME_read_ASN1*(bio: ptr BIO_536871632; bcont: ptr ptr BIO_536871632;
                        it: ptr ASN1_ITEM_536871574): ptr ASN1_VALUE_536871566 {.
      cdecl, importc: "SMIME_read_ASN1".}
else:
  static :
    hint("Declaration of " & "SMIME_read_ASN1" &
        " already exists, not redeclaring")
when not declared(SMIME_read_ASN1_ex):
  proc SMIME_read_ASN1_ex*(bio: ptr BIO_536871632; flags: cint;
                           bcont: ptr ptr BIO_536871632; it: ptr ASN1_ITEM_536871574;
                           x: ptr ptr ASN1_VALUE_536871566;
                           libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring): ptr ASN1_VALUE_536871566 {.
      cdecl, importc: "SMIME_read_ASN1_ex".}
else:
  static :
    hint("Declaration of " & "SMIME_read_ASN1_ex" &
        " already exists, not redeclaring")
when not declared(SMIME_crlf_copy):
  proc SMIME_crlf_copy*(in_arg: ptr BIO_536871632; out_arg: ptr BIO_536871632;
                        flags: cint): cint {.cdecl, importc: "SMIME_crlf_copy".}
else:
  static :
    hint("Declaration of " & "SMIME_crlf_copy" &
        " already exists, not redeclaring")
when not declared(SMIME_text):
  proc SMIME_text*(in_arg: ptr BIO_536871632; out_arg: ptr BIO_536871632): cint {.
      cdecl, importc: "SMIME_text".}
else:
  static :
    hint("Declaration of " & "SMIME_text" & " already exists, not redeclaring")
when not declared(ASN1_ITEM_lookup):
  proc ASN1_ITEM_lookup*(name: cstring): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_ITEM_lookup".}
else:
  static :
    hint("Declaration of " & "ASN1_ITEM_lookup" &
        " already exists, not redeclaring")
when not declared(ASN1_ITEM_get):
  proc ASN1_ITEM_get*(i: csize_t): ptr ASN1_ITEM_536871574 {.cdecl,
      importc: "ASN1_ITEM_get".}
else:
  static :
    hint("Declaration of " & "ASN1_ITEM_get" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_options):
  proc SSL_CTX_get_options*(ctx: ptr SSL_CTX_536871728): uint64 {.cdecl,
      importc: "SSL_CTX_get_options".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_options" &
        " already exists, not redeclaring")
when not declared(SSL_get_options):
  proc SSL_get_options*(s: ptr SSL_536871704): uint64 {.cdecl,
      importc: "SSL_get_options".}
else:
  static :
    hint("Declaration of " & "SSL_get_options" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_clear_options):
  proc SSL_CTX_clear_options*(ctx: ptr SSL_CTX_536871728; op: uint64): uint64 {.
      cdecl, importc: "SSL_CTX_clear_options".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_clear_options" &
        " already exists, not redeclaring")
when not declared(SSL_clear_options):
  proc SSL_clear_options*(s: ptr SSL_536871704; op: uint64): uint64 {.cdecl,
      importc: "SSL_clear_options".}
else:
  static :
    hint("Declaration of " & "SSL_clear_options" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_options):
  proc SSL_CTX_set_options*(ctx: ptr SSL_CTX_536871728; op: uint64): uint64 {.
      cdecl, importc: "SSL_CTX_set_options".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_options" &
        " already exists, not redeclaring")
when not declared(SSL_set_options):
  proc SSL_set_options*(s: ptr SSL_536871704; op: uint64): uint64 {.cdecl,
      importc: "SSL_set_options".}
else:
  static :
    hint("Declaration of " & "SSL_set_options" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_msg_callback):
  proc SSL_CTX_set_msg_callback*(ctx: ptr SSL_CTX_536871728; cb: proc (a0: cint;
      a1: cint; a2: cint; a3: pointer; a4: csize_t; a5: ptr SSL_536871704;
      a6: pointer): void {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_msg_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_msg_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_msg_callback):
  proc SSL_set_msg_callback*(ssl: ptr SSL_536871704; cb: proc (a0: cint;
      a1: cint; a2: cint; a3: pointer; a4: csize_t; a5: ptr SSL_536871704;
      a6: pointer): void {.cdecl.}): void {.cdecl,
      importc: "SSL_set_msg_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_msg_callback" &
        " already exists, not redeclaring")
when not declared(SSL_SRP_CTX_init):
  proc SSL_SRP_CTX_init*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_SRP_CTX_init".}
else:
  static :
    hint("Declaration of " & "SSL_SRP_CTX_init" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_SRP_CTX_init):
  proc SSL_CTX_SRP_CTX_init*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_SRP_CTX_init".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_SRP_CTX_init" &
        " already exists, not redeclaring")
when not declared(SSL_SRP_CTX_free):
  proc SSL_SRP_CTX_free*(ctx: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_SRP_CTX_free".}
else:
  static :
    hint("Declaration of " & "SSL_SRP_CTX_free" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_SRP_CTX_free):
  proc SSL_CTX_SRP_CTX_free*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_SRP_CTX_free".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_SRP_CTX_free" &
        " already exists, not redeclaring")
when not declared(SSL_srp_server_param_with_username):
  proc SSL_srp_server_param_with_username*(s: ptr SSL_536871704; ad: ptr cint): cint {.
      cdecl, importc: "SSL_srp_server_param_with_username".}
else:
  static :
    hint("Declaration of " & "SSL_srp_server_param_with_username" &
        " already exists, not redeclaring")
when not declared(SRP_Calc_A_param):
  proc SRP_Calc_A_param*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SRP_Calc_A_param".}
else:
  static :
    hint("Declaration of " & "SRP_Calc_A_param" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sessions):
  proc SSL_CTX_sessions*(ctx: ptr SSL_CTX_536871728): ptr struct_lhash_st_SSL_SESSION {.
      cdecl, importc: "SSL_CTX_sessions".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sessions" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_set_new_cb):
  proc SSL_CTX_sess_set_new_cb*(ctx: ptr SSL_CTX_536871728; new_session_cb: proc (
      a0: ptr struct_ssl_st; a1: ptr SSL_SESSION_536871684): cint {.cdecl.}): void {.
      cdecl, importc: "SSL_CTX_sess_set_new_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_set_new_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_get_new_cb):
  proc SSL_CTX_sess_get_new_cb*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr struct_ssl_st; a1: ptr SSL_SESSION_536871684): cint {.cdecl.} {.
      cdecl, importc: "SSL_CTX_sess_get_new_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_get_new_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_set_remove_cb):
  proc SSL_CTX_sess_set_remove_cb*(ctx: ptr SSL_CTX_536871728; remove_session_cb: proc (
      a0: ptr struct_ssl_ctx_st; a1: ptr SSL_SESSION_536871684): void {.cdecl.}): void {.
      cdecl, importc: "SSL_CTX_sess_set_remove_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_set_remove_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_get_remove_cb):
  proc SSL_CTX_sess_get_remove_cb*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr struct_ssl_ctx_st; a1: ptr SSL_SESSION_536871684): void {.cdecl.} {.
      cdecl, importc: "SSL_CTX_sess_get_remove_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_get_remove_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_set_get_cb):
  proc SSL_CTX_sess_set_get_cb*(ctx: ptr SSL_CTX_536871728; get_session_cb: proc (
      a0: ptr struct_ssl_st; a1: ptr uint8; a2: cint; a3: ptr cint): ptr SSL_SESSION_536871684 {.
      cdecl.}): void {.cdecl, importc: "SSL_CTX_sess_set_get_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_set_get_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_sess_get_get_cb):
  proc SSL_CTX_sess_get_get_cb*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr struct_ssl_st; a1: ptr uint8; a2: cint; a3: ptr cint): ptr SSL_SESSION_536871684 {.
      cdecl.} {.cdecl, importc: "SSL_CTX_sess_get_get_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_sess_get_get_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_info_callback):
  proc SSL_CTX_set_info_callback*(ctx: ptr SSL_CTX_536871728; cb: proc (
      a0: ptr SSL_536871704; a1: cint; a2: cint): void {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_info_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_info_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_info_callback):
  proc SSL_CTX_get_info_callback*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr SSL_536871704; a1: cint; a2: cint): void {.cdecl.} {.cdecl,
      importc: "SSL_CTX_get_info_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_info_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_client_cert_cb):
  proc SSL_CTX_set_client_cert_cb*(ctx: ptr SSL_CTX_536871728; client_cert_cb: proc (
      a0: ptr SSL_536871704; a1: ptr ptr X509_536871716; a2: ptr ptr EVP_PKEY_536871658): cint {.
      cdecl.}): void {.cdecl, importc: "SSL_CTX_set_client_cert_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_client_cert_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_client_cert_cb):
  proc SSL_CTX_get_client_cert_cb*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr SSL_536871704; a1: ptr ptr X509_536871716; a2: ptr ptr EVP_PKEY_536871658): cint {.
      cdecl.} {.cdecl, importc: "SSL_CTX_get_client_cert_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_client_cert_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_client_cert_engine):
  proc SSL_CTX_set_client_cert_engine*(ctx: ptr SSL_CTX_536871728; e: ptr ENGINE_536871732): cint {.
      cdecl, importc: "SSL_CTX_set_client_cert_engine".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_client_cert_engine" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cookie_generate_cb):
  proc SSL_CTX_set_cookie_generate_cb*(ctx: ptr SSL_CTX_536871728;
      app_gen_cookie_cb: proc (a0: ptr SSL_536871704; a1: ptr uint8;
                               a2: ptr cuint): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_cookie_generate_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cookie_generate_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cookie_verify_cb):
  proc SSL_CTX_set_cookie_verify_cb*(ctx: ptr SSL_CTX_536871728;
      app_verify_cookie_cb: proc (a0: ptr SSL_536871704; a1: ptr uint8;
                                  a2: cuint): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_cookie_verify_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cookie_verify_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_stateless_cookie_generate_cb):
  proc SSL_CTX_set_stateless_cookie_generate_cb*(ctx: ptr SSL_CTX_536871728;
      gen_stateless_cookie_cb: proc (a0: ptr SSL_536871704; a1: ptr uint8;
                                     a2: ptr csize_t): cint {.cdecl.}): void {.
      cdecl, importc: "SSL_CTX_set_stateless_cookie_generate_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_stateless_cookie_generate_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_stateless_cookie_verify_cb):
  proc SSL_CTX_set_stateless_cookie_verify_cb*(ctx: ptr SSL_CTX_536871728;
      verify_stateless_cookie_cb: proc (a0: ptr SSL_536871704; a1: ptr uint8;
                                        a2: csize_t): cint {.cdecl.}): void {.
      cdecl, importc: "SSL_CTX_set_stateless_cookie_verify_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_stateless_cookie_verify_cb" &
        " already exists, not redeclaring")
when not declared(SSL_select_next_proto):
  proc SSL_select_next_proto*(out_arg: ptr ptr uint8; outlen: ptr uint8;
                              in_arg: ptr uint8; inlen: cuint;
                              client: ptr uint8; client_len: cuint): cint {.
      cdecl, importc: "SSL_select_next_proto".}
else:
  static :
    hint("Declaration of " & "SSL_select_next_proto" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_alpn_protos):
  proc SSL_CTX_set_alpn_protos*(ctx: ptr SSL_CTX_536871728; protos: ptr uint8;
                                protos_len: cuint): cint {.cdecl,
      importc: "SSL_CTX_set_alpn_protos".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_alpn_protos" &
        " already exists, not redeclaring")
when not declared(SSL_set_alpn_protos):
  proc SSL_set_alpn_protos*(ssl: ptr SSL_536871704; protos: ptr uint8;
                            protos_len: cuint): cint {.cdecl,
      importc: "SSL_set_alpn_protos".}
else:
  static :
    hint("Declaration of " & "SSL_set_alpn_protos" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_alpn_select_cb):
  proc SSL_CTX_set_alpn_select_cb*(ctx: ptr SSL_CTX_536871728;
                                   cb: SSL_CTX_alpn_select_cb_func_536871738;
                                   arg: pointer): void {.cdecl,
      importc: "SSL_CTX_set_alpn_select_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_alpn_select_cb" &
        " already exists, not redeclaring")
when not declared(SSL_get0_alpn_selected):
  proc SSL_get0_alpn_selected*(ssl: ptr SSL_536871704; data: ptr ptr uint8;
                               len: ptr cuint): void {.cdecl,
      importc: "SSL_get0_alpn_selected".}
else:
  static :
    hint("Declaration of " & "SSL_get0_alpn_selected" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_psk_client_callback):
  proc SSL_CTX_set_psk_client_callback*(ctx: ptr SSL_CTX_536871728;
                                        cb: SSL_psk_client_cb_func_536871740): void {.
      cdecl, importc: "SSL_CTX_set_psk_client_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_psk_client_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_psk_client_callback):
  proc SSL_set_psk_client_callback*(ssl: ptr SSL_536871704;
                                    cb: SSL_psk_client_cb_func_536871740): void {.
      cdecl, importc: "SSL_set_psk_client_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_psk_client_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_psk_server_callback):
  proc SSL_CTX_set_psk_server_callback*(ctx: ptr SSL_CTX_536871728;
                                        cb: SSL_psk_server_cb_func_536871742): void {.
      cdecl, importc: "SSL_CTX_set_psk_server_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_psk_server_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_psk_server_callback):
  proc SSL_set_psk_server_callback*(ssl: ptr SSL_536871704;
                                    cb: SSL_psk_server_cb_func_536871742): void {.
      cdecl, importc: "SSL_set_psk_server_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_psk_server_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_psk_identity_hint):
  proc SSL_CTX_use_psk_identity_hint*(ctx: ptr SSL_CTX_536871728;
                                      identity_hint: cstring): cint {.cdecl,
      importc: "SSL_CTX_use_psk_identity_hint".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_psk_identity_hint" &
        " already exists, not redeclaring")
when not declared(SSL_use_psk_identity_hint):
  proc SSL_use_psk_identity_hint*(s: ptr SSL_536871704; identity_hint: cstring): cint {.
      cdecl, importc: "SSL_use_psk_identity_hint".}
else:
  static :
    hint("Declaration of " & "SSL_use_psk_identity_hint" &
        " already exists, not redeclaring")
when not declared(SSL_get_psk_identity_hint):
  proc SSL_get_psk_identity_hint*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get_psk_identity_hint".}
else:
  static :
    hint("Declaration of " & "SSL_get_psk_identity_hint" &
        " already exists, not redeclaring")
when not declared(SSL_get_psk_identity):
  proc SSL_get_psk_identity*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get_psk_identity".}
else:
  static :
    hint("Declaration of " & "SSL_get_psk_identity" &
        " already exists, not redeclaring")
when not declared(SSL_set_psk_find_session_callback):
  proc SSL_set_psk_find_session_callback*(s: ptr SSL_536871704;
      cb: SSL_psk_find_session_cb_func_536871744): void {.cdecl,
      importc: "SSL_set_psk_find_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_psk_find_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_psk_find_session_callback):
  proc SSL_CTX_set_psk_find_session_callback*(ctx: ptr SSL_CTX_536871728;
      cb: SSL_psk_find_session_cb_func_536871744): void {.cdecl,
      importc: "SSL_CTX_set_psk_find_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_psk_find_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_psk_use_session_callback):
  proc SSL_set_psk_use_session_callback*(s: ptr SSL_536871704;
      cb: SSL_psk_use_session_cb_func_536871746): void {.cdecl,
      importc: "SSL_set_psk_use_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_psk_use_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_psk_use_session_callback):
  proc SSL_CTX_set_psk_use_session_callback*(ctx: ptr SSL_CTX_536871728;
      cb: SSL_psk_use_session_cb_func_536871746): void {.cdecl,
      importc: "SSL_CTX_set_psk_use_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_psk_use_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_has_client_custom_ext):
  proc SSL_CTX_has_client_custom_ext*(ctx: ptr SSL_CTX_536871728;
                                      ext_type: cuint): cint {.cdecl,
      importc: "SSL_CTX_has_client_custom_ext".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_has_client_custom_ext" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add_client_custom_ext):
  proc SSL_CTX_add_client_custom_ext*(ctx: ptr SSL_CTX_536871728;
                                      ext_type: cuint;
                                      add_cb: custom_ext_add_cb_536871708;
                                      free_cb: custom_ext_free_cb_536871710;
                                      add_arg: pointer;
                                      parse_cb: custom_ext_parse_cb_536871712;
                                      parse_arg: pointer): cint {.cdecl,
      importc: "SSL_CTX_add_client_custom_ext".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add_client_custom_ext" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add_server_custom_ext):
  proc SSL_CTX_add_server_custom_ext*(ctx: ptr SSL_CTX_536871728;
                                      ext_type: cuint;
                                      add_cb: custom_ext_add_cb_536871708;
                                      free_cb: custom_ext_free_cb_536871710;
                                      add_arg: pointer;
                                      parse_cb: custom_ext_parse_cb_536871712;
                                      parse_arg: pointer): cint {.cdecl,
      importc: "SSL_CTX_add_server_custom_ext".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add_server_custom_ext" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add_custom_ext):
  proc SSL_CTX_add_custom_ext*(ctx: ptr SSL_CTX_536871728; ext_type: cuint;
                               context: cuint; add_cb: SSL_custom_ext_add_cb_ex_536871714;
                               free_cb: SSL_custom_ext_free_cb_ex_536871718;
                               add_arg: pointer;
                               parse_cb: SSL_custom_ext_parse_cb_ex_536871720;
                               parse_arg: pointer): cint {.cdecl,
      importc: "SSL_CTX_add_custom_ext".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add_custom_ext" &
        " already exists, not redeclaring")
when not declared(SSL_extension_supported):
  proc SSL_extension_supported*(ext_type: cuint): cint {.cdecl,
      importc: "SSL_extension_supported".}
else:
  static :
    hint("Declaration of " & "SSL_extension_supported" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_keylog_callback):
  proc SSL_CTX_set_keylog_callback*(ctx: ptr SSL_CTX_536871728;
                                    cb: SSL_CTX_keylog_cb_func_536871748): void {.
      cdecl, importc: "SSL_CTX_set_keylog_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_keylog_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_keylog_callback):
  proc SSL_CTX_get_keylog_callback*(ctx: ptr SSL_CTX_536871728): SSL_CTX_keylog_cb_func_536871748 {.
      cdecl, importc: "SSL_CTX_get_keylog_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_keylog_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_max_early_data):
  proc SSL_CTX_set_max_early_data*(ctx: ptr SSL_CTX_536871728;
                                   max_early_data: uint32): cint {.cdecl,
      importc: "SSL_CTX_set_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_max_early_data):
  proc SSL_CTX_get_max_early_data*(ctx: ptr SSL_CTX_536871728): uint32 {.cdecl,
      importc: "SSL_CTX_get_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_set_max_early_data):
  proc SSL_set_max_early_data*(s: ptr SSL_536871704; max_early_data: uint32): cint {.
      cdecl, importc: "SSL_set_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_set_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_get_max_early_data):
  proc SSL_get_max_early_data*(s: ptr SSL_536871704): uint32 {.cdecl,
      importc: "SSL_get_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_get_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_recv_max_early_data):
  proc SSL_CTX_set_recv_max_early_data*(ctx: ptr SSL_CTX_536871728;
                                        recv_max_early_data: uint32): cint {.
      cdecl, importc: "SSL_CTX_set_recv_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_recv_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_recv_max_early_data):
  proc SSL_CTX_get_recv_max_early_data*(ctx: ptr SSL_CTX_536871728): uint32 {.
      cdecl, importc: "SSL_CTX_get_recv_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_recv_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_set_recv_max_early_data):
  proc SSL_set_recv_max_early_data*(s: ptr SSL_536871704;
                                    recv_max_early_data: uint32): cint {.cdecl,
      importc: "SSL_set_recv_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_set_recv_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_get_recv_max_early_data):
  proc SSL_get_recv_max_early_data*(s: ptr SSL_536871704): uint32 {.cdecl,
      importc: "SSL_get_recv_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_get_recv_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_set_debug):
  proc SSL_set_debug*(s: ptr SSL_536871704; debug: cint): void {.cdecl,
      importc: "SSL_set_debug".}
else:
  static :
    hint("Declaration of " & "SSL_set_debug" &
        " already exists, not redeclaring")
when not declared(SSL_in_init):
  proc SSL_in_init*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_in_init".}
else:
  static :
    hint("Declaration of " & "SSL_in_init" & " already exists, not redeclaring")
when not declared(SSL_in_before):
  proc SSL_in_before*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_in_before".}
else:
  static :
    hint("Declaration of " & "SSL_in_before" &
        " already exists, not redeclaring")
when not declared(SSL_is_init_finished):
  proc SSL_is_init_finished*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_is_init_finished".}
else:
  static :
    hint("Declaration of " & "SSL_is_init_finished" &
        " already exists, not redeclaring")
when not declared(SSL_get_finished):
  proc SSL_get_finished*(s: ptr SSL_536871704; buf: pointer; count: csize_t): csize_t {.
      cdecl, importc: "SSL_get_finished".}
else:
  static :
    hint("Declaration of " & "SSL_get_finished" &
        " already exists, not redeclaring")
when not declared(SSL_get_peer_finished):
  proc SSL_get_peer_finished*(s: ptr SSL_536871704; buf: pointer; count: csize_t): csize_t {.
      cdecl, importc: "SSL_get_peer_finished".}
else:
  static :
    hint("Declaration of " & "SSL_get_peer_finished" &
        " already exists, not redeclaring")
when not declared(PEM_read_bio_SSL_SESSION):
  proc PEM_read_bio_SSL_SESSION*(out_arg: ptr BIO_536871632;
                                 x: ptr ptr SSL_SESSION_536871684;
                                 cb: pem_password_cb_536871766; u: pointer): ptr SSL_SESSION_536871684 {.
      cdecl, importc: "PEM_read_bio_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "PEM_read_bio_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(PEM_read_SSL_SESSION):
  proc PEM_read_SSL_SESSION*(out_arg: ptr Cfile_536871662;
                             x: ptr ptr SSL_SESSION_536871684;
                             cb: pem_password_cb_536871766; u: pointer): ptr SSL_SESSION_536871684 {.
      cdecl, importc: "PEM_read_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "PEM_read_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(PEM_write_bio_SSL_SESSION):
  proc PEM_write_bio_SSL_SESSION*(out_arg: ptr BIO_536871632; x: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "PEM_write_bio_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "PEM_write_bio_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(PEM_write_SSL_SESSION):
  proc PEM_write_SSL_SESSION*(out_arg: ptr Cfile_536871662; x: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "PEM_write_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "PEM_write_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(SSL_group_to_name):
  proc SSL_group_to_name*(s: ptr SSL_536871704; id: cint): cstring {.cdecl,
      importc: "SSL_group_to_name".}
else:
  static :
    hint("Declaration of " & "SSL_group_to_name" &
        " already exists, not redeclaring")
when not declared(SSL_set0_tmp_dh_pkey):
  proc SSL_set0_tmp_dh_pkey*(s: ptr SSL_536871704; dhpkey: ptr EVP_PKEY_536871658): cint {.
      cdecl, importc: "SSL_set0_tmp_dh_pkey".}
else:
  static :
    hint("Declaration of " & "SSL_set0_tmp_dh_pkey" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set0_tmp_dh_pkey):
  proc SSL_CTX_set0_tmp_dh_pkey*(ctx: ptr SSL_CTX_536871728;
                                 dhpkey: ptr EVP_PKEY_536871658): cint {.cdecl,
      importc: "SSL_CTX_set0_tmp_dh_pkey".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set0_tmp_dh_pkey" &
        " already exists, not redeclaring")
when not declared(BIO_f_ssl):
  proc BIO_f_ssl*(): ptr BIO_METHOD_536871672 {.cdecl, importc: "BIO_f_ssl".}
else:
  static :
    hint("Declaration of " & "BIO_f_ssl" & " already exists, not redeclaring")
when not declared(BIO_new_ssl):
  proc BIO_new_ssl*(ctx: ptr SSL_CTX_536871728; client: cint): ptr BIO_536871632 {.
      cdecl, importc: "BIO_new_ssl".}
else:
  static :
    hint("Declaration of " & "BIO_new_ssl" & " already exists, not redeclaring")
when not declared(BIO_new_ssl_connect):
  proc BIO_new_ssl_connect*(ctx: ptr SSL_CTX_536871728): ptr BIO_536871632 {.
      cdecl, importc: "BIO_new_ssl_connect".}
else:
  static :
    hint("Declaration of " & "BIO_new_ssl_connect" &
        " already exists, not redeclaring")
when not declared(BIO_new_buffer_ssl_connect):
  proc BIO_new_buffer_ssl_connect*(ctx: ptr SSL_CTX_536871728): ptr BIO_536871632 {.
      cdecl, importc: "BIO_new_buffer_ssl_connect".}
else:
  static :
    hint("Declaration of " & "BIO_new_buffer_ssl_connect" &
        " already exists, not redeclaring")
when not declared(BIO_ssl_copy_session_id):
  proc BIO_ssl_copy_session_id*(to: ptr BIO_536871632; from_arg: ptr BIO_536871632): cint {.
      cdecl, importc: "BIO_ssl_copy_session_id".}
else:
  static :
    hint("Declaration of " & "BIO_ssl_copy_session_id" &
        " already exists, not redeclaring")
when not declared(BIO_ssl_shutdown):
  proc BIO_ssl_shutdown*(ssl_bio: ptr BIO_536871632): void {.cdecl,
      importc: "BIO_ssl_shutdown".}
else:
  static :
    hint("Declaration of " & "BIO_ssl_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cipher_list):
  proc SSL_CTX_set_cipher_list*(a0: ptr SSL_CTX_536871728; str: cstring): cint {.
      cdecl, importc: "SSL_CTX_set_cipher_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cipher_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_new):
  proc SSL_CTX_new*(meth: ptr SSL_METHOD_536871680): ptr SSL_CTX_536871728 {.
      cdecl, importc: "SSL_CTX_new".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_new" & " already exists, not redeclaring")
when not declared(SSL_CTX_new_ex):
  proc SSL_CTX_new_ex*(libctx: ptr OSSL_LIB_CTX_536871484; propq: cstring;
                       meth: ptr SSL_METHOD_536871680): ptr SSL_CTX_536871728 {.
      cdecl, importc: "SSL_CTX_new_ex".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_new_ex" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_up_ref):
  proc SSL_CTX_up_ref*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_up_ref".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_up_ref" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_free):
  proc SSL_CTX_free*(a0: ptr SSL_CTX_536871728): void {.cdecl,
      importc: "SSL_CTX_free".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_free" & " already exists, not redeclaring")
when not declared(SSL_CTX_set_timeout):
  proc SSL_CTX_set_timeout*(ctx: ptr SSL_CTX_536871728; t: clong): clong {.
      cdecl, importc: "SSL_CTX_set_timeout".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_timeout" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_timeout):
  proc SSL_CTX_get_timeout*(ctx: ptr SSL_CTX_536871728): clong {.cdecl,
      importc: "SSL_CTX_get_timeout".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_timeout" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_cert_store):
  proc SSL_CTX_get_cert_store*(a0: ptr SSL_CTX_536871728): ptr X509_STORE_536871768 {.
      cdecl, importc: "SSL_CTX_get_cert_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_cert_store" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cert_store):
  proc SSL_CTX_set_cert_store*(a0: ptr SSL_CTX_536871728; a1: ptr X509_STORE_536871768): void {.
      cdecl, importc: "SSL_CTX_set_cert_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cert_store" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_cert_store):
  proc SSL_CTX_set1_cert_store*(a0: ptr SSL_CTX_536871728; a1: ptr X509_STORE_536871768): void {.
      cdecl, importc: "SSL_CTX_set1_cert_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_cert_store" &
        " already exists, not redeclaring")
when not declared(SSL_want):
  proc SSL_want*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_want".}
else:
  static :
    hint("Declaration of " & "SSL_want" & " already exists, not redeclaring")
when not declared(SSL_clear):
  proc SSL_clear*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_clear".}
else:
  static :
    hint("Declaration of " & "SSL_clear" & " already exists, not redeclaring")
when not declared(SSL_CTX_flush_sessions):
  proc SSL_CTX_flush_sessions*(ctx: ptr SSL_CTX_536871728; tm: clong): void {.
      cdecl, importc: "SSL_CTX_flush_sessions".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_flush_sessions" &
        " already exists, not redeclaring")
when not declared(SSL_get_current_cipher):
  proc SSL_get_current_cipher*(s: ptr SSL_536871704): ptr SSL_CIPHER_536871682 {.
      cdecl, importc: "SSL_get_current_cipher".}
else:
  static :
    hint("Declaration of " & "SSL_get_current_cipher" &
        " already exists, not redeclaring")
when not declared(SSL_get_pending_cipher):
  proc SSL_get_pending_cipher*(s: ptr SSL_536871704): ptr SSL_CIPHER_536871682 {.
      cdecl, importc: "SSL_get_pending_cipher".}
else:
  static :
    hint("Declaration of " & "SSL_get_pending_cipher" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_bits):
  proc SSL_CIPHER_get_bits*(c: ptr SSL_CIPHER_536871682; alg_bits: ptr cint): cint {.
      cdecl, importc: "SSL_CIPHER_get_bits".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_bits" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_version):
  proc SSL_CIPHER_get_version*(c: ptr SSL_CIPHER_536871682): cstring {.cdecl,
      importc: "SSL_CIPHER_get_version".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_version" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_name):
  proc SSL_CIPHER_get_name*(c: ptr SSL_CIPHER_536871682): cstring {.cdecl,
      importc: "SSL_CIPHER_get_name".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_name" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_standard_name):
  proc SSL_CIPHER_standard_name*(c: ptr SSL_CIPHER_536871682): cstring {.cdecl,
      importc: "SSL_CIPHER_standard_name".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_standard_name" &
        " already exists, not redeclaring")
when not declared(OPENSSL_cipher_name):
  proc OPENSSL_cipher_name*(rfc_name: cstring): cstring {.cdecl,
      importc: "OPENSSL_cipher_name".}
else:
  static :
    hint("Declaration of " & "OPENSSL_cipher_name" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_id):
  proc SSL_CIPHER_get_id*(c: ptr SSL_CIPHER_536871682): uint32 {.cdecl,
      importc: "SSL_CIPHER_get_id".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_id" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_protocol_id):
  proc SSL_CIPHER_get_protocol_id*(c: ptr SSL_CIPHER_536871682): uint16 {.cdecl,
      importc: "SSL_CIPHER_get_protocol_id".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_protocol_id" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_kx_nid):
  proc SSL_CIPHER_get_kx_nid*(c: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_CIPHER_get_kx_nid".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_kx_nid" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_auth_nid):
  proc SSL_CIPHER_get_auth_nid*(c: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_CIPHER_get_auth_nid".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_auth_nid" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_handshake_digest):
  proc SSL_CIPHER_get_handshake_digest*(c: ptr SSL_CIPHER_536871682): ptr EVP_MD_536871660 {.
      cdecl, importc: "SSL_CIPHER_get_handshake_digest".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_handshake_digest" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_is_aead):
  proc SSL_CIPHER_is_aead*(c: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_CIPHER_is_aead".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_is_aead" &
        " already exists, not redeclaring")
when not declared(SSL_get_fd):
  proc SSL_get_fd*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_get_fd".}
else:
  static :
    hint("Declaration of " & "SSL_get_fd" & " already exists, not redeclaring")
when not declared(SSL_get_rfd):
  proc SSL_get_rfd*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_get_rfd".}
else:
  static :
    hint("Declaration of " & "SSL_get_rfd" & " already exists, not redeclaring")
when not declared(SSL_get_wfd):
  proc SSL_get_wfd*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_get_wfd".}
else:
  static :
    hint("Declaration of " & "SSL_get_wfd" & " already exists, not redeclaring")
when not declared(SSL_get_cipher_list):
  proc SSL_get_cipher_list*(s: ptr SSL_536871704; n: cint): cstring {.cdecl,
      importc: "SSL_get_cipher_list".}
else:
  static :
    hint("Declaration of " & "SSL_get_cipher_list" &
        " already exists, not redeclaring")
when not declared(SSL_get_shared_ciphers):
  proc SSL_get_shared_ciphers*(s: ptr SSL_536871704; buf: cstring; size: cint): cstring {.
      cdecl, importc: "SSL_get_shared_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_get_shared_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_get_read_ahead):
  proc SSL_get_read_ahead*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_read_ahead".}
else:
  static :
    hint("Declaration of " & "SSL_get_read_ahead" &
        " already exists, not redeclaring")
when not declared(SSL_pending):
  proc SSL_pending*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_pending".}
else:
  static :
    hint("Declaration of " & "SSL_pending" & " already exists, not redeclaring")
when not declared(SSL_has_pending):
  proc SSL_has_pending*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_has_pending".}
else:
  static :
    hint("Declaration of " & "SSL_has_pending" &
        " already exists, not redeclaring")
when not declared(SSL_set_fd):
  proc SSL_set_fd*(s: ptr SSL_536871704; fd: cint): cint {.cdecl,
      importc: "SSL_set_fd".}
else:
  static :
    hint("Declaration of " & "SSL_set_fd" & " already exists, not redeclaring")
when not declared(SSL_set_rfd):
  proc SSL_set_rfd*(s: ptr SSL_536871704; fd: cint): cint {.cdecl,
      importc: "SSL_set_rfd".}
else:
  static :
    hint("Declaration of " & "SSL_set_rfd" & " already exists, not redeclaring")
when not declared(SSL_set_wfd):
  proc SSL_set_wfd*(s: ptr SSL_536871704; fd: cint): cint {.cdecl,
      importc: "SSL_set_wfd".}
else:
  static :
    hint("Declaration of " & "SSL_set_wfd" & " already exists, not redeclaring")
when not declared(SSL_set0_rbio):
  proc SSL_set0_rbio*(s: ptr SSL_536871704; rbio: ptr BIO_536871632): void {.
      cdecl, importc: "SSL_set0_rbio".}
else:
  static :
    hint("Declaration of " & "SSL_set0_rbio" &
        " already exists, not redeclaring")
when not declared(SSL_set0_wbio):
  proc SSL_set0_wbio*(s: ptr SSL_536871704; wbio: ptr BIO_536871632): void {.
      cdecl, importc: "SSL_set0_wbio".}
else:
  static :
    hint("Declaration of " & "SSL_set0_wbio" &
        " already exists, not redeclaring")
when not declared(SSL_set_bio):
  proc SSL_set_bio*(s: ptr SSL_536871704; rbio: ptr BIO_536871632; wbio: ptr BIO_536871632): void {.
      cdecl, importc: "SSL_set_bio".}
else:
  static :
    hint("Declaration of " & "SSL_set_bio" & " already exists, not redeclaring")
when not declared(SSL_get_rbio):
  proc SSL_get_rbio*(s: ptr SSL_536871704): ptr BIO_536871632 {.cdecl,
      importc: "SSL_get_rbio".}
else:
  static :
    hint("Declaration of " & "SSL_get_rbio" & " already exists, not redeclaring")
when not declared(SSL_get_wbio):
  proc SSL_get_wbio*(s: ptr SSL_536871704): ptr BIO_536871632 {.cdecl,
      importc: "SSL_get_wbio".}
else:
  static :
    hint("Declaration of " & "SSL_get_wbio" & " already exists, not redeclaring")
when not declared(SSL_set_cipher_list):
  proc SSL_set_cipher_list*(s: ptr SSL_536871704; str: cstring): cint {.cdecl,
      importc: "SSL_set_cipher_list".}
else:
  static :
    hint("Declaration of " & "SSL_set_cipher_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_ciphersuites):
  proc SSL_CTX_set_ciphersuites*(ctx: ptr SSL_CTX_536871728; str: cstring): cint {.
      cdecl, importc: "SSL_CTX_set_ciphersuites".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_ciphersuites" &
        " already exists, not redeclaring")
when not declared(SSL_set_ciphersuites):
  proc SSL_set_ciphersuites*(s: ptr SSL_536871704; str: cstring): cint {.cdecl,
      importc: "SSL_set_ciphersuites".}
else:
  static :
    hint("Declaration of " & "SSL_set_ciphersuites" &
        " already exists, not redeclaring")
when not declared(SSL_set_read_ahead):
  proc SSL_set_read_ahead*(s: ptr SSL_536871704; yes: cint): void {.cdecl,
      importc: "SSL_set_read_ahead".}
else:
  static :
    hint("Declaration of " & "SSL_set_read_ahead" &
        " already exists, not redeclaring")
when not declared(SSL_get_verify_mode):
  proc SSL_get_verify_mode*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_verify_mode".}
else:
  static :
    hint("Declaration of " & "SSL_get_verify_mode" &
        " already exists, not redeclaring")
when not declared(SSL_get_verify_depth):
  proc SSL_get_verify_depth*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_verify_depth".}
else:
  static :
    hint("Declaration of " & "SSL_get_verify_depth" &
        " already exists, not redeclaring")
when not declared(SSL_get_verify_callback):
  proc SSL_get_verify_callback*(s: ptr SSL_536871704): SSL_verify_cb_536871722 {.
      cdecl, importc: "SSL_get_verify_callback".}
else:
  static :
    hint("Declaration of " & "SSL_get_verify_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_verify):
  proc SSL_set_verify*(s: ptr SSL_536871704; mode: cint; callback: SSL_verify_cb_536871722): void {.
      cdecl, importc: "SSL_set_verify".}
else:
  static :
    hint("Declaration of " & "SSL_set_verify" &
        " already exists, not redeclaring")
when not declared(SSL_set_verify_depth):
  proc SSL_set_verify_depth*(s: ptr SSL_536871704; depth: cint): void {.cdecl,
      importc: "SSL_set_verify_depth".}
else:
  static :
    hint("Declaration of " & "SSL_set_verify_depth" &
        " already exists, not redeclaring")
when not declared(SSL_set_cert_cb):
  proc SSL_set_cert_cb*(s: ptr SSL_536871704;
                        cb: proc (a0: ptr SSL_536871704; a1: pointer): cint {.
      cdecl.}; arg: pointer): void {.cdecl, importc: "SSL_set_cert_cb".}
else:
  static :
    hint("Declaration of " & "SSL_set_cert_cb" &
        " already exists, not redeclaring")
when not declared(SSL_use_RSAPrivateKey):
  proc SSL_use_RSAPrivateKey*(ssl: ptr SSL_536871704; rsa: ptr RSA_536871770): cint {.
      cdecl, importc: "SSL_use_RSAPrivateKey".}
else:
  static :
    hint("Declaration of " & "SSL_use_RSAPrivateKey" &
        " already exists, not redeclaring")
when not declared(SSL_use_RSAPrivateKey_ASN1):
  proc SSL_use_RSAPrivateKey_ASN1*(ssl: ptr SSL_536871704; d: ptr uint8;
                                   len: clong): cint {.cdecl,
      importc: "SSL_use_RSAPrivateKey_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_use_RSAPrivateKey_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_use_PrivateKey):
  proc SSL_use_PrivateKey*(ssl: ptr SSL_536871704; pkey: ptr EVP_PKEY_536871658): cint {.
      cdecl, importc: "SSL_use_PrivateKey".}
else:
  static :
    hint("Declaration of " & "SSL_use_PrivateKey" &
        " already exists, not redeclaring")
when not declared(SSL_use_PrivateKey_ASN1):
  proc SSL_use_PrivateKey_ASN1*(pk: cint; ssl: ptr SSL_536871704; d: ptr uint8;
                                len: clong): cint {.cdecl,
      importc: "SSL_use_PrivateKey_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_use_PrivateKey_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_use_certificate):
  proc SSL_use_certificate*(ssl: ptr SSL_536871704; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_use_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_use_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_use_certificate_ASN1):
  proc SSL_use_certificate_ASN1*(ssl: ptr SSL_536871704; d: ptr uint8; len: cint): cint {.
      cdecl, importc: "SSL_use_certificate_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_use_certificate_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_use_cert_and_key):
  proc SSL_use_cert_and_key*(ssl: ptr SSL_536871704; x509: ptr X509_536871716;
                             privatekey: ptr EVP_PKEY_536871658;
                             chain: ptr struct_stack_st_X509; override: cint): cint {.
      cdecl, importc: "SSL_use_cert_and_key".}
else:
  static :
    hint("Declaration of " & "SSL_use_cert_and_key" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_serverinfo):
  proc SSL_CTX_use_serverinfo*(ctx: ptr SSL_CTX_536871728;
                               serverinfo: ptr uint8; serverinfo_length: csize_t): cint {.
      cdecl, importc: "SSL_CTX_use_serverinfo".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_serverinfo" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_serverinfo_ex):
  proc SSL_CTX_use_serverinfo_ex*(ctx: ptr SSL_CTX_536871728; version: cuint;
                                  serverinfo: ptr uint8;
                                  serverinfo_length: csize_t): cint {.cdecl,
      importc: "SSL_CTX_use_serverinfo_ex".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_serverinfo_ex" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_serverinfo_file):
  proc SSL_CTX_use_serverinfo_file*(ctx: ptr SSL_CTX_536871728; file: cstring): cint {.
      cdecl, importc: "SSL_CTX_use_serverinfo_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_serverinfo_file" &
        " already exists, not redeclaring")
when not declared(SSL_use_RSAPrivateKey_file):
  proc SSL_use_RSAPrivateKey_file*(ssl: ptr SSL_536871704; file: cstring;
                                   type_arg: cint): cint {.cdecl,
      importc: "SSL_use_RSAPrivateKey_file".}
else:
  static :
    hint("Declaration of " & "SSL_use_RSAPrivateKey_file" &
        " already exists, not redeclaring")
when not declared(SSL_use_PrivateKey_file):
  proc SSL_use_PrivateKey_file*(ssl: ptr SSL_536871704; file: cstring;
                                type_arg: cint): cint {.cdecl,
      importc: "SSL_use_PrivateKey_file".}
else:
  static :
    hint("Declaration of " & "SSL_use_PrivateKey_file" &
        " already exists, not redeclaring")
when not declared(SSL_use_certificate_file):
  proc SSL_use_certificate_file*(ssl: ptr SSL_536871704; file: cstring;
                                 type_arg: cint): cint {.cdecl,
      importc: "SSL_use_certificate_file".}
else:
  static :
    hint("Declaration of " & "SSL_use_certificate_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_RSAPrivateKey_file):
  proc SSL_CTX_use_RSAPrivateKey_file*(ctx: ptr SSL_CTX_536871728;
                                       file: cstring; type_arg: cint): cint {.
      cdecl, importc: "SSL_CTX_use_RSAPrivateKey_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_RSAPrivateKey_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_PrivateKey_file):
  proc SSL_CTX_use_PrivateKey_file*(ctx: ptr SSL_CTX_536871728; file: cstring;
                                    type_arg: cint): cint {.cdecl,
      importc: "SSL_CTX_use_PrivateKey_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_PrivateKey_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_certificate_file):
  proc SSL_CTX_use_certificate_file*(ctx: ptr SSL_CTX_536871728; file: cstring;
                                     type_arg: cint): cint {.cdecl,
      importc: "SSL_CTX_use_certificate_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_certificate_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_certificate_chain_file):
  proc SSL_CTX_use_certificate_chain_file*(ctx: ptr SSL_CTX_536871728;
      file: cstring): cint {.cdecl,
                             importc: "SSL_CTX_use_certificate_chain_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_certificate_chain_file" &
        " already exists, not redeclaring")
when not declared(SSL_use_certificate_chain_file):
  proc SSL_use_certificate_chain_file*(ssl: ptr SSL_536871704; file: cstring): cint {.
      cdecl, importc: "SSL_use_certificate_chain_file".}
else:
  static :
    hint("Declaration of " & "SSL_use_certificate_chain_file" &
        " already exists, not redeclaring")
when not declared(SSL_load_client_CA_file):
  proc SSL_load_client_CA_file*(file: cstring): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_load_client_CA_file".}
else:
  static :
    hint("Declaration of " & "SSL_load_client_CA_file" &
        " already exists, not redeclaring")
when not declared(SSL_load_client_CA_file_ex):
  proc SSL_load_client_CA_file_ex*(file: cstring; libctx: ptr OSSL_LIB_CTX_536871484;
                                   propq: cstring): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_load_client_CA_file_ex".}
else:
  static :
    hint("Declaration of " & "SSL_load_client_CA_file_ex" &
        " already exists, not redeclaring")
when not declared(SSL_add_file_cert_subjects_to_stack):
  proc SSL_add_file_cert_subjects_to_stack*(
      stackCAs: ptr struct_stack_st_X509_NAME; file: cstring): cint {.cdecl,
      importc: "SSL_add_file_cert_subjects_to_stack".}
else:
  static :
    hint("Declaration of " & "SSL_add_file_cert_subjects_to_stack" &
        " already exists, not redeclaring")
when not declared(SSL_add_dir_cert_subjects_to_stack):
  proc SSL_add_dir_cert_subjects_to_stack*(
      stackCAs: ptr struct_stack_st_X509_NAME; dir: cstring): cint {.cdecl,
      importc: "SSL_add_dir_cert_subjects_to_stack".}
else:
  static :
    hint("Declaration of " & "SSL_add_dir_cert_subjects_to_stack" &
        " already exists, not redeclaring")
when not declared(SSL_add_store_cert_subjects_to_stack):
  proc SSL_add_store_cert_subjects_to_stack*(
      stackCAs: ptr struct_stack_st_X509_NAME; uri: cstring): cint {.cdecl,
      importc: "SSL_add_store_cert_subjects_to_stack".}
else:
  static :
    hint("Declaration of " & "SSL_add_store_cert_subjects_to_stack" &
        " already exists, not redeclaring")
when not declared(SSL_state_string):
  proc SSL_state_string*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_state_string".}
else:
  static :
    hint("Declaration of " & "SSL_state_string" &
        " already exists, not redeclaring")
when not declared(SSL_rstate_string):
  proc SSL_rstate_string*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_rstate_string".}
else:
  static :
    hint("Declaration of " & "SSL_rstate_string" &
        " already exists, not redeclaring")
when not declared(SSL_state_string_long):
  proc SSL_state_string_long*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_state_string_long".}
else:
  static :
    hint("Declaration of " & "SSL_state_string_long" &
        " already exists, not redeclaring")
when not declared(SSL_rstate_string_long):
  proc SSL_rstate_string_long*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_rstate_string_long".}
else:
  static :
    hint("Declaration of " & "SSL_rstate_string_long" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_time):
  proc SSL_SESSION_get_time*(s: ptr SSL_SESSION_536871684): clong {.cdecl,
      importc: "SSL_SESSION_get_time".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_time" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_time):
  proc SSL_SESSION_set_time*(s: ptr SSL_SESSION_536871684; t: clong): clong {.
      cdecl, importc: "SSL_SESSION_set_time".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_time" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_timeout):
  proc SSL_SESSION_get_timeout*(s: ptr SSL_SESSION_536871684): clong {.cdecl,
      importc: "SSL_SESSION_get_timeout".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_timeout" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_timeout):
  proc SSL_SESSION_set_timeout*(s: ptr SSL_SESSION_536871684; t: clong): clong {.
      cdecl, importc: "SSL_SESSION_set_timeout".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_timeout" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_protocol_version):
  proc SSL_SESSION_get_protocol_version*(s: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_SESSION_get_protocol_version".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_protocol_version" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_protocol_version):
  proc SSL_SESSION_set_protocol_version*(s: ptr SSL_SESSION_536871684;
      version: cint): cint {.cdecl, importc: "SSL_SESSION_set_protocol_version".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_protocol_version" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_hostname):
  proc SSL_SESSION_get0_hostname*(s: ptr SSL_SESSION_536871684): cstring {.
      cdecl, importc: "SSL_SESSION_get0_hostname".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_hostname" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_hostname):
  proc SSL_SESSION_set1_hostname*(s: ptr SSL_SESSION_536871684;
                                  hostname: cstring): cint {.cdecl,
      importc: "SSL_SESSION_set1_hostname".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_hostname" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_alpn_selected):
  proc SSL_SESSION_get0_alpn_selected*(s: ptr SSL_SESSION_536871684;
                                       alpn: ptr ptr uint8; len: ptr csize_t): void {.
      cdecl, importc: "SSL_SESSION_get0_alpn_selected".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_alpn_selected" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_alpn_selected):
  proc SSL_SESSION_set1_alpn_selected*(s: ptr SSL_SESSION_536871684;
                                       alpn: ptr uint8; len: csize_t): cint {.
      cdecl, importc: "SSL_SESSION_set1_alpn_selected".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_alpn_selected" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_cipher):
  proc SSL_SESSION_get0_cipher*(s: ptr SSL_SESSION_536871684): ptr SSL_CIPHER_536871682 {.
      cdecl, importc: "SSL_SESSION_get0_cipher".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_cipher" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_cipher):
  proc SSL_SESSION_set_cipher*(s: ptr SSL_SESSION_536871684;
                               cipher: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_SESSION_set_cipher".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_cipher" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_has_ticket):
  proc SSL_SESSION_has_ticket*(s: ptr SSL_SESSION_536871684): cint {.cdecl,
      importc: "SSL_SESSION_has_ticket".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_has_ticket" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_ticket_lifetime_hint):
  proc SSL_SESSION_get_ticket_lifetime_hint*(s: ptr SSL_SESSION_536871684): culong {.
      cdecl, importc: "SSL_SESSION_get_ticket_lifetime_hint".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_ticket_lifetime_hint" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_ticket):
  proc SSL_SESSION_get0_ticket*(s: ptr SSL_SESSION_536871684;
                                tick: ptr ptr uint8; len: ptr csize_t): void {.
      cdecl, importc: "SSL_SESSION_get0_ticket".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_ticket" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_max_early_data):
  proc SSL_SESSION_get_max_early_data*(s: ptr SSL_SESSION_536871684): uint32 {.
      cdecl, importc: "SSL_SESSION_get_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_max_early_data):
  proc SSL_SESSION_set_max_early_data*(s: ptr SSL_SESSION_536871684;
                                       max_early_data: uint32): cint {.cdecl,
      importc: "SSL_SESSION_set_max_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_max_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_copy_session_id):
  proc SSL_copy_session_id*(to: ptr SSL_536871704; from_arg: ptr SSL_536871704): cint {.
      cdecl, importc: "SSL_copy_session_id".}
else:
  static :
    hint("Declaration of " & "SSL_copy_session_id" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_peer):
  proc SSL_SESSION_get0_peer*(s: ptr SSL_SESSION_536871684): ptr X509_536871716 {.
      cdecl, importc: "SSL_SESSION_get0_peer".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_peer" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_id_context):
  proc SSL_SESSION_set1_id_context*(s: ptr SSL_SESSION_536871684;
                                    sid_ctx: ptr uint8; sid_ctx_len: cuint): cint {.
      cdecl, importc: "SSL_SESSION_set1_id_context".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_id_context" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_id):
  proc SSL_SESSION_set1_id*(s: ptr SSL_SESSION_536871684; sid: ptr uint8;
                            sid_len: cuint): cint {.cdecl,
      importc: "SSL_SESSION_set1_id".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_id" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_is_resumable):
  proc SSL_SESSION_is_resumable*(s: ptr SSL_SESSION_536871684): cint {.cdecl,
      importc: "SSL_SESSION_is_resumable".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_is_resumable" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_new):
  proc SSL_SESSION_new*(): ptr SSL_SESSION_536871684 {.cdecl,
      importc: "SSL_SESSION_new".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_new" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_dup):
  proc SSL_SESSION_dup*(src: ptr SSL_SESSION_536871684): ptr SSL_SESSION_536871684 {.
      cdecl, importc: "SSL_SESSION_dup".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_dup" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_id):
  proc SSL_SESSION_get_id*(s: ptr SSL_SESSION_536871684; len: ptr cuint): ptr uint8 {.
      cdecl, importc: "SSL_SESSION_get_id".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_id" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_id_context):
  proc SSL_SESSION_get0_id_context*(s: ptr SSL_SESSION_536871684; len: ptr cuint): ptr uint8 {.
      cdecl, importc: "SSL_SESSION_get0_id_context".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_id_context" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_compress_id):
  proc SSL_SESSION_get_compress_id*(s: ptr SSL_SESSION_536871684): cuint {.
      cdecl, importc: "SSL_SESSION_get_compress_id".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_compress_id" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_print_fp):
  proc SSL_SESSION_print_fp*(fp: ptr Cfile_536871662; ses: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_SESSION_print_fp".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_print_fp" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_print):
  proc SSL_SESSION_print*(fp: ptr BIO_536871632; ses: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_SESSION_print".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_print" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_print_keylog):
  proc SSL_SESSION_print_keylog*(bp: ptr BIO_536871632; x: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_SESSION_print_keylog".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_print_keylog" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_up_ref):
  proc SSL_SESSION_up_ref*(ses: ptr SSL_SESSION_536871684): cint {.cdecl,
      importc: "SSL_SESSION_up_ref".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_up_ref" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_free):
  proc SSL_SESSION_free*(ses: ptr SSL_SESSION_536871684): void {.cdecl,
      importc: "SSL_SESSION_free".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_free" &
        " already exists, not redeclaring")
when not declared(i2d_SSL_SESSION):
  proc i2d_SSL_SESSION*(in_arg: ptr SSL_SESSION_536871684; pp: ptr ptr uint8): cint {.
      cdecl, importc: "i2d_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "i2d_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(SSL_set_session):
  proc SSL_set_session*(to: ptr SSL_536871704; session: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_set_session".}
else:
  static :
    hint("Declaration of " & "SSL_set_session" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add_session):
  proc SSL_CTX_add_session*(ctx: ptr SSL_CTX_536871728; session: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_CTX_add_session".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add_session" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_remove_session):
  proc SSL_CTX_remove_session*(ctx: ptr SSL_CTX_536871728;
                               session: ptr SSL_SESSION_536871684): cint {.
      cdecl, importc: "SSL_CTX_remove_session".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_remove_session" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_generate_session_id):
  proc SSL_CTX_set_generate_session_id*(ctx: ptr SSL_CTX_536871728;
                                        cb: GEN_SESSION_CB_536871730): cint {.
      cdecl, importc: "SSL_CTX_set_generate_session_id".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_generate_session_id" &
        " already exists, not redeclaring")
when not declared(SSL_set_generate_session_id):
  proc SSL_set_generate_session_id*(s: ptr SSL_536871704; cb: GEN_SESSION_CB_536871730): cint {.
      cdecl, importc: "SSL_set_generate_session_id".}
else:
  static :
    hint("Declaration of " & "SSL_set_generate_session_id" &
        " already exists, not redeclaring")
when not declared(SSL_has_matching_session_id):
  proc SSL_has_matching_session_id*(s: ptr SSL_536871704; id: ptr uint8;
                                    id_len: cuint): cint {.cdecl,
      importc: "SSL_has_matching_session_id".}
else:
  static :
    hint("Declaration of " & "SSL_has_matching_session_id" &
        " already exists, not redeclaring")
when not declared(d2i_SSL_SESSION):
  proc d2i_SSL_SESSION*(a: ptr ptr SSL_SESSION_536871684; pp: ptr ptr uint8;
                        length: clong): ptr SSL_SESSION_536871684 {.cdecl,
      importc: "d2i_SSL_SESSION".}
else:
  static :
    hint("Declaration of " & "d2i_SSL_SESSION" &
        " already exists, not redeclaring")
when not declared(SSL_get0_peer_certificate):
  proc SSL_get0_peer_certificate*(s: ptr SSL_536871704): ptr X509_536871716 {.
      cdecl, importc: "SSL_get0_peer_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_get0_peer_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_get_peer_cert_chain):
  proc SSL_get_peer_cert_chain*(s: ptr SSL_536871704): ptr struct_stack_st_X509 {.
      cdecl, importc: "SSL_get_peer_cert_chain".}
else:
  static :
    hint("Declaration of " & "SSL_get_peer_cert_chain" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_verify_mode):
  proc SSL_CTX_get_verify_mode*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_get_verify_mode".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_verify_mode" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_verify_depth):
  proc SSL_CTX_get_verify_depth*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_get_verify_depth".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_verify_depth" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_verify_callback):
  proc SSL_CTX_get_verify_callback*(ctx: ptr SSL_CTX_536871728): SSL_verify_cb_536871722 {.
      cdecl, importc: "SSL_CTX_get_verify_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_verify_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_verify):
  proc SSL_CTX_set_verify*(ctx: ptr SSL_CTX_536871728; mode: cint;
                           callback: SSL_verify_cb_536871722): void {.cdecl,
      importc: "SSL_CTX_set_verify".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_verify" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_verify_depth):
  proc SSL_CTX_set_verify_depth*(ctx: ptr SSL_CTX_536871728; depth: cint): void {.
      cdecl, importc: "SSL_CTX_set_verify_depth".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_verify_depth" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cert_verify_callback):
  proc SSL_CTX_set_cert_verify_callback*(ctx: ptr SSL_CTX_536871728;
      cb: proc (a0: ptr X509_STORE_CTX_536871724; a1: pointer): cint {.cdecl.};
      arg: pointer): void {.cdecl, importc: "SSL_CTX_set_cert_verify_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cert_verify_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_cert_cb):
  proc SSL_CTX_set_cert_cb*(c: ptr SSL_CTX_536871728;
                            cb: proc (a0: ptr SSL_536871704; a1: pointer): cint {.
      cdecl.}; arg: pointer): void {.cdecl, importc: "SSL_CTX_set_cert_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_cert_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_RSAPrivateKey):
  proc SSL_CTX_use_RSAPrivateKey*(ctx: ptr SSL_CTX_536871728; rsa: ptr RSA_536871770): cint {.
      cdecl, importc: "SSL_CTX_use_RSAPrivateKey".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_RSAPrivateKey" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_RSAPrivateKey_ASN1):
  proc SSL_CTX_use_RSAPrivateKey_ASN1*(ctx: ptr SSL_CTX_536871728; d: ptr uint8;
                                       len: clong): cint {.cdecl,
      importc: "SSL_CTX_use_RSAPrivateKey_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_RSAPrivateKey_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_PrivateKey):
  proc SSL_CTX_use_PrivateKey*(ctx: ptr SSL_CTX_536871728; pkey: ptr EVP_PKEY_536871658): cint {.
      cdecl, importc: "SSL_CTX_use_PrivateKey".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_PrivateKey" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_PrivateKey_ASN1):
  proc SSL_CTX_use_PrivateKey_ASN1*(pk: cint; ctx: ptr SSL_CTX_536871728;
                                    d: ptr uint8; len: clong): cint {.cdecl,
      importc: "SSL_CTX_use_PrivateKey_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_PrivateKey_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_certificate):
  proc SSL_CTX_use_certificate*(ctx: ptr SSL_CTX_536871728; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_CTX_use_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_certificate_ASN1):
  proc SSL_CTX_use_certificate_ASN1*(ctx: ptr SSL_CTX_536871728; len: cint;
                                     d: ptr uint8): cint {.cdecl,
      importc: "SSL_CTX_use_certificate_ASN1".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_certificate_ASN1" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_use_cert_and_key):
  proc SSL_CTX_use_cert_and_key*(ctx: ptr SSL_CTX_536871728; x509: ptr X509_536871716;
                                 privatekey: ptr EVP_PKEY_536871658;
                                 chain: ptr struct_stack_st_X509; override: cint): cint {.
      cdecl, importc: "SSL_CTX_use_cert_and_key".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_use_cert_and_key" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_passwd_cb):
  proc SSL_CTX_set_default_passwd_cb*(ctx: ptr SSL_CTX_536871728;
                                      cb: pem_password_cb_536871766): void {.
      cdecl, importc: "SSL_CTX_set_default_passwd_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_passwd_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_passwd_cb_userdata):
  proc SSL_CTX_set_default_passwd_cb_userdata*(ctx: ptr SSL_CTX_536871728;
      u: pointer): void {.cdecl,
                          importc: "SSL_CTX_set_default_passwd_cb_userdata".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_passwd_cb_userdata" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_default_passwd_cb):
  proc SSL_CTX_get_default_passwd_cb*(ctx: ptr SSL_CTX_536871728): pem_password_cb_536871766 {.
      cdecl, importc: "SSL_CTX_get_default_passwd_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_default_passwd_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_default_passwd_cb_userdata):
  proc SSL_CTX_get_default_passwd_cb_userdata*(ctx: ptr SSL_CTX_536871728): pointer {.
      cdecl, importc: "SSL_CTX_get_default_passwd_cb_userdata".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_default_passwd_cb_userdata" &
        " already exists, not redeclaring")
when not declared(SSL_set_default_passwd_cb):
  proc SSL_set_default_passwd_cb*(s: ptr SSL_536871704; cb: pem_password_cb_536871766): void {.
      cdecl, importc: "SSL_set_default_passwd_cb".}
else:
  static :
    hint("Declaration of " & "SSL_set_default_passwd_cb" &
        " already exists, not redeclaring")
when not declared(SSL_set_default_passwd_cb_userdata):
  proc SSL_set_default_passwd_cb_userdata*(s: ptr SSL_536871704; u: pointer): void {.
      cdecl, importc: "SSL_set_default_passwd_cb_userdata".}
else:
  static :
    hint("Declaration of " & "SSL_set_default_passwd_cb_userdata" &
        " already exists, not redeclaring")
when not declared(SSL_get_default_passwd_cb):
  proc SSL_get_default_passwd_cb*(s: ptr SSL_536871704): pem_password_cb_536871766 {.
      cdecl, importc: "SSL_get_default_passwd_cb".}
else:
  static :
    hint("Declaration of " & "SSL_get_default_passwd_cb" &
        " already exists, not redeclaring")
when not declared(SSL_get_default_passwd_cb_userdata):
  proc SSL_get_default_passwd_cb_userdata*(s: ptr SSL_536871704): pointer {.
      cdecl, importc: "SSL_get_default_passwd_cb_userdata".}
else:
  static :
    hint("Declaration of " & "SSL_get_default_passwd_cb_userdata" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_check_private_key):
  proc SSL_CTX_check_private_key*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_check_private_key".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_check_private_key" &
        " already exists, not redeclaring")
when not declared(SSL_check_private_key):
  proc SSL_check_private_key*(ctx: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_check_private_key".}
else:
  static :
    hint("Declaration of " & "SSL_check_private_key" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_session_id_context):
  proc SSL_CTX_set_session_id_context*(ctx: ptr SSL_CTX_536871728;
                                       sid_ctx: ptr uint8; sid_ctx_len: cuint): cint {.
      cdecl, importc: "SSL_CTX_set_session_id_context".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_session_id_context" &
        " already exists, not redeclaring")
when not declared(SSL_new):
  proc SSL_new*(ctx: ptr SSL_CTX_536871728): ptr SSL_536871704 {.cdecl,
      importc: "SSL_new".}
else:
  static :
    hint("Declaration of " & "SSL_new" & " already exists, not redeclaring")
when not declared(SSL_up_ref):
  proc SSL_up_ref*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_up_ref".}
else:
  static :
    hint("Declaration of " & "SSL_up_ref" & " already exists, not redeclaring")
when not declared(SSL_is_dtls):
  proc SSL_is_dtls*(s: ptr SSL_536871704): cint {.cdecl, importc: "SSL_is_dtls".}
else:
  static :
    hint("Declaration of " & "SSL_is_dtls" & " already exists, not redeclaring")
when not declared(SSL_set_session_id_context):
  proc SSL_set_session_id_context*(ssl: ptr SSL_536871704; sid_ctx: ptr uint8;
                                   sid_ctx_len: cuint): cint {.cdecl,
      importc: "SSL_set_session_id_context".}
else:
  static :
    hint("Declaration of " & "SSL_set_session_id_context" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_purpose):
  proc SSL_CTX_set_purpose*(ctx: ptr SSL_CTX_536871728; purpose: cint): cint {.
      cdecl, importc: "SSL_CTX_set_purpose".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_purpose" &
        " already exists, not redeclaring")
when not declared(SSL_set_purpose):
  proc SSL_set_purpose*(ssl: ptr SSL_536871704; purpose: cint): cint {.cdecl,
      importc: "SSL_set_purpose".}
else:
  static :
    hint("Declaration of " & "SSL_set_purpose" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_trust):
  proc SSL_CTX_set_trust*(ctx: ptr SSL_CTX_536871728; trust: cint): cint {.
      cdecl, importc: "SSL_CTX_set_trust".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_trust" &
        " already exists, not redeclaring")
when not declared(SSL_set_trust):
  proc SSL_set_trust*(ssl: ptr SSL_536871704; trust: cint): cint {.cdecl,
      importc: "SSL_set_trust".}
else:
  static :
    hint("Declaration of " & "SSL_set_trust" &
        " already exists, not redeclaring")
when not declared(SSL_set1_host):
  proc SSL_set1_host*(s: ptr SSL_536871704; hostname: cstring): cint {.cdecl,
      importc: "SSL_set1_host".}
else:
  static :
    hint("Declaration of " & "SSL_set1_host" &
        " already exists, not redeclaring")
when not declared(SSL_add1_host):
  proc SSL_add1_host*(s: ptr SSL_536871704; hostname: cstring): cint {.cdecl,
      importc: "SSL_add1_host".}
else:
  static :
    hint("Declaration of " & "SSL_add1_host" &
        " already exists, not redeclaring")
when not declared(SSL_get0_peername):
  proc SSL_get0_peername*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get0_peername".}
else:
  static :
    hint("Declaration of " & "SSL_get0_peername" &
        " already exists, not redeclaring")
when not declared(SSL_set_hostflags):
  proc SSL_set_hostflags*(s: ptr SSL_536871704; flags: cuint): void {.cdecl,
      importc: "SSL_set_hostflags".}
else:
  static :
    hint("Declaration of " & "SSL_set_hostflags" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_dane_enable):
  proc SSL_CTX_dane_enable*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_dane_enable".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_dane_enable" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_dane_mtype_set):
  proc SSL_CTX_dane_mtype_set*(ctx: ptr SSL_CTX_536871728; md: ptr EVP_MD_536871660;
                               mtype: uint8; ord: uint8): cint {.cdecl,
      importc: "SSL_CTX_dane_mtype_set".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_dane_mtype_set" &
        " already exists, not redeclaring")
when not declared(SSL_dane_enable):
  proc SSL_dane_enable*(s: ptr SSL_536871704; basedomain: cstring): cint {.
      cdecl, importc: "SSL_dane_enable".}
else:
  static :
    hint("Declaration of " & "SSL_dane_enable" &
        " already exists, not redeclaring")
when not declared(SSL_dane_tlsa_add):
  proc SSL_dane_tlsa_add*(s: ptr SSL_536871704; usage: uint8; selector: uint8;
                          mtype: uint8; data: ptr uint8; dlen: csize_t): cint {.
      cdecl, importc: "SSL_dane_tlsa_add".}
else:
  static :
    hint("Declaration of " & "SSL_dane_tlsa_add" &
        " already exists, not redeclaring")
when not declared(SSL_get0_dane_authority):
  proc SSL_get0_dane_authority*(s: ptr SSL_536871704; mcert: ptr ptr X509_536871716;
                                mspki: ptr ptr EVP_PKEY_536871658): cint {.
      cdecl, importc: "SSL_get0_dane_authority".}
else:
  static :
    hint("Declaration of " & "SSL_get0_dane_authority" &
        " already exists, not redeclaring")
when not declared(SSL_get0_dane_tlsa):
  proc SSL_get0_dane_tlsa*(s: ptr SSL_536871704; usage: ptr uint8;
                           selector: ptr uint8; mtype: ptr uint8;
                           data: ptr ptr uint8; dlen: ptr csize_t): cint {.
      cdecl, importc: "SSL_get0_dane_tlsa".}
else:
  static :
    hint("Declaration of " & "SSL_get0_dane_tlsa" &
        " already exists, not redeclaring")
when not declared(SSL_get0_dane):
  proc SSL_get0_dane*(ssl: ptr SSL_536871704): ptr SSL_DANE_536871772 {.cdecl,
      importc: "SSL_get0_dane".}
else:
  static :
    hint("Declaration of " & "SSL_get0_dane" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_dane_set_flags):
  proc SSL_CTX_dane_set_flags*(ctx: ptr SSL_CTX_536871728; flags: culong): culong {.
      cdecl, importc: "SSL_CTX_dane_set_flags".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_dane_set_flags" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_dane_clear_flags):
  proc SSL_CTX_dane_clear_flags*(ctx: ptr SSL_CTX_536871728; flags: culong): culong {.
      cdecl, importc: "SSL_CTX_dane_clear_flags".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_dane_clear_flags" &
        " already exists, not redeclaring")
when not declared(SSL_dane_set_flags):
  proc SSL_dane_set_flags*(ssl: ptr SSL_536871704; flags: culong): culong {.
      cdecl, importc: "SSL_dane_set_flags".}
else:
  static :
    hint("Declaration of " & "SSL_dane_set_flags" &
        " already exists, not redeclaring")
when not declared(SSL_dane_clear_flags):
  proc SSL_dane_clear_flags*(ssl: ptr SSL_536871704; flags: culong): culong {.
      cdecl, importc: "SSL_dane_clear_flags".}
else:
  static :
    hint("Declaration of " & "SSL_dane_clear_flags" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set1_param):
  proc SSL_CTX_set1_param*(ctx: ptr SSL_CTX_536871728;
                           vpm: ptr X509_VERIFY_PARAM_536871774): cint {.cdecl,
      importc: "SSL_CTX_set1_param".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set1_param" &
        " already exists, not redeclaring")
when not declared(SSL_set1_param):
  proc SSL_set1_param*(ssl: ptr SSL_536871704; vpm: ptr X509_VERIFY_PARAM_536871774): cint {.
      cdecl, importc: "SSL_set1_param".}
else:
  static :
    hint("Declaration of " & "SSL_set1_param" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_param):
  proc SSL_CTX_get0_param*(ctx: ptr SSL_CTX_536871728): ptr X509_VERIFY_PARAM_536871774 {.
      cdecl, importc: "SSL_CTX_get0_param".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_param" &
        " already exists, not redeclaring")
when not declared(SSL_get0_param):
  proc SSL_get0_param*(ssl: ptr SSL_536871704): ptr X509_VERIFY_PARAM_536871774 {.
      cdecl, importc: "SSL_get0_param".}
else:
  static :
    hint("Declaration of " & "SSL_get0_param" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_username):
  proc SSL_CTX_set_srp_username*(ctx: ptr SSL_CTX_536871728; name: cstring): cint {.
      cdecl, importc: "SSL_CTX_set_srp_username".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_username" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_password):
  proc SSL_CTX_set_srp_password*(ctx: ptr SSL_CTX_536871728; password: cstring): cint {.
      cdecl, importc: "SSL_CTX_set_srp_password".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_password" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_strength):
  proc SSL_CTX_set_srp_strength*(ctx: ptr SSL_CTX_536871728; strength: cint): cint {.
      cdecl, importc: "SSL_CTX_set_srp_strength".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_strength" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_client_pwd_callback):
  proc SSL_CTX_set_srp_client_pwd_callback*(ctx: ptr SSL_CTX_536871728;
      cb: proc (a0: ptr SSL_536871704; a1: pointer): cstring {.cdecl.}): cint {.
      cdecl, importc: "SSL_CTX_set_srp_client_pwd_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_client_pwd_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_verify_param_callback):
  proc SSL_CTX_set_srp_verify_param_callback*(ctx: ptr SSL_CTX_536871728;
      cb: proc (a0: ptr SSL_536871704; a1: pointer): cint {.cdecl.}): cint {.
      cdecl, importc: "SSL_CTX_set_srp_verify_param_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_verify_param_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_username_callback):
  proc SSL_CTX_set_srp_username_callback*(ctx: ptr SSL_CTX_536871728;
      cb: proc (a0: ptr SSL_536871704; a1: ptr cint; a2: pointer): cint {.cdecl.}): cint {.
      cdecl, importc: "SSL_CTX_set_srp_username_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_username_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_srp_cb_arg):
  proc SSL_CTX_set_srp_cb_arg*(ctx: ptr SSL_CTX_536871728; arg: pointer): cint {.
      cdecl, importc: "SSL_CTX_set_srp_cb_arg".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_srp_cb_arg" &
        " already exists, not redeclaring")
when not declared(SSL_set_srp_server_param):
  proc SSL_set_srp_server_param*(s: ptr SSL_536871704; N: ptr BIGNUM_536871656;
                                 g: ptr BIGNUM_536871656; sa: ptr BIGNUM_536871656;
                                 v: ptr BIGNUM_536871656; info: cstring): cint {.
      cdecl, importc: "SSL_set_srp_server_param".}
else:
  static :
    hint("Declaration of " & "SSL_set_srp_server_param" &
        " already exists, not redeclaring")
when not declared(SSL_set_srp_server_param_pw):
  proc SSL_set_srp_server_param_pw*(s: ptr SSL_536871704; user: cstring;
                                    pass: cstring; grp: cstring): cint {.cdecl,
      importc: "SSL_set_srp_server_param_pw".}
else:
  static :
    hint("Declaration of " & "SSL_set_srp_server_param_pw" &
        " already exists, not redeclaring")
when not declared(SSL_get_srp_g):
  proc SSL_get_srp_g*(s: ptr SSL_536871704): ptr BIGNUM_536871656 {.cdecl,
      importc: "SSL_get_srp_g".}
else:
  static :
    hint("Declaration of " & "SSL_get_srp_g" &
        " already exists, not redeclaring")
when not declared(SSL_get_srp_N):
  proc SSL_get_srp_N*(s: ptr SSL_536871704): ptr BIGNUM_536871656 {.cdecl,
      importc: "SSL_get_srp_N".}
else:
  static :
    hint("Declaration of " & "SSL_get_srp_N" &
        " already exists, not redeclaring")
when not declared(SSL_get_srp_username):
  proc SSL_get_srp_username*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get_srp_username".}
else:
  static :
    hint("Declaration of " & "SSL_get_srp_username" &
        " already exists, not redeclaring")
when not declared(SSL_get_srp_userinfo):
  proc SSL_get_srp_userinfo*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get_srp_userinfo".}
else:
  static :
    hint("Declaration of " & "SSL_get_srp_userinfo" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_client_hello_cb):
  proc SSL_CTX_set_client_hello_cb*(c: ptr SSL_CTX_536871728;
                                    cb: SSL_client_hello_cb_fn_536871776;
                                    arg: pointer): void {.cdecl,
      importc: "SSL_CTX_set_client_hello_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_client_hello_cb" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_isv2):
  proc SSL_client_hello_isv2*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_client_hello_isv2".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_isv2" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_legacy_version):
  proc SSL_client_hello_get0_legacy_version*(s: ptr SSL_536871704): cuint {.
      cdecl, importc: "SSL_client_hello_get0_legacy_version".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_legacy_version" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_random):
  proc SSL_client_hello_get0_random*(s: ptr SSL_536871704;
                                     out_arg: ptr ptr uint8): csize_t {.cdecl,
      importc: "SSL_client_hello_get0_random".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_random" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_session_id):
  proc SSL_client_hello_get0_session_id*(s: ptr SSL_536871704;
      out_arg: ptr ptr uint8): csize_t {.cdecl,
      importc: "SSL_client_hello_get0_session_id".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_session_id" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_ciphers):
  proc SSL_client_hello_get0_ciphers*(s: ptr SSL_536871704;
                                      out_arg: ptr ptr uint8): csize_t {.cdecl,
      importc: "SSL_client_hello_get0_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_compression_methods):
  proc SSL_client_hello_get0_compression_methods*(s: ptr SSL_536871704;
      out_arg: ptr ptr uint8): csize_t {.cdecl,
      importc: "SSL_client_hello_get0_compression_methods".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_compression_methods" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get1_extensions_present):
  proc SSL_client_hello_get1_extensions_present*(s: ptr SSL_536871704;
      out_arg: ptr ptr cint; outlen: ptr csize_t): cint {.cdecl,
      importc: "SSL_client_hello_get1_extensions_present".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get1_extensions_present" &
        " already exists, not redeclaring")
when not declared(SSL_client_hello_get0_ext):
  proc SSL_client_hello_get0_ext*(s: ptr SSL_536871704; type_arg: cuint;
                                  out_arg: ptr ptr uint8; outlen: ptr csize_t): cint {.
      cdecl, importc: "SSL_client_hello_get0_ext".}
else:
  static :
    hint("Declaration of " & "SSL_client_hello_get0_ext" &
        " already exists, not redeclaring")
when not declared(SSL_certs_clear):
  proc SSL_certs_clear*(s: ptr SSL_536871704): void {.cdecl,
      importc: "SSL_certs_clear".}
else:
  static :
    hint("Declaration of " & "SSL_certs_clear" &
        " already exists, not redeclaring")
when not declared(SSL_free):
  proc SSL_free*(ssl: ptr SSL_536871704): void {.cdecl, importc: "SSL_free".}
else:
  static :
    hint("Declaration of " & "SSL_free" & " already exists, not redeclaring")
when not declared(SSL_waiting_for_async):
  proc SSL_waiting_for_async*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_waiting_for_async".}
else:
  static :
    hint("Declaration of " & "SSL_waiting_for_async" &
        " already exists, not redeclaring")
when not declared(SSL_get_all_async_fds):
  proc SSL_get_all_async_fds*(s: ptr SSL_536871704; fds: ptr cint;
                              numfds: ptr csize_t): cint {.cdecl,
      importc: "SSL_get_all_async_fds".}
else:
  static :
    hint("Declaration of " & "SSL_get_all_async_fds" &
        " already exists, not redeclaring")
when not declared(SSL_get_changed_async_fds):
  proc SSL_get_changed_async_fds*(s: ptr SSL_536871704; addfd: ptr cint;
                                  numaddfds: ptr csize_t; delfd: ptr cint;
                                  numdelfds: ptr csize_t): cint {.cdecl,
      importc: "SSL_get_changed_async_fds".}
else:
  static :
    hint("Declaration of " & "SSL_get_changed_async_fds" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_async_callback):
  proc SSL_CTX_set_async_callback*(ctx: ptr SSL_CTX_536871728;
                                   callback: SSL_async_callback_fn_536871726): cint {.
      cdecl, importc: "SSL_CTX_set_async_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_async_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_async_callback_arg):
  proc SSL_CTX_set_async_callback_arg*(ctx: ptr SSL_CTX_536871728; arg: pointer): cint {.
      cdecl, importc: "SSL_CTX_set_async_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_async_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_set_async_callback):
  proc SSL_set_async_callback*(s: ptr SSL_536871704;
                               callback: SSL_async_callback_fn_536871726): cint {.
      cdecl, importc: "SSL_set_async_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_async_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_async_callback_arg):
  proc SSL_set_async_callback_arg*(s: ptr SSL_536871704; arg: pointer): cint {.
      cdecl, importc: "SSL_set_async_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_set_async_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_get_async_status):
  proc SSL_get_async_status*(s: ptr SSL_536871704; status: ptr cint): cint {.
      cdecl, importc: "SSL_get_async_status".}
else:
  static :
    hint("Declaration of " & "SSL_get_async_status" &
        " already exists, not redeclaring")
when not declared(SSL_accept):
  proc SSL_accept*(ssl: ptr SSL_536871704): cint {.cdecl, importc: "SSL_accept".}
else:
  static :
    hint("Declaration of " & "SSL_accept" & " already exists, not redeclaring")
when not declared(SSL_stateless):
  proc SSL_stateless*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_stateless".}
else:
  static :
    hint("Declaration of " & "SSL_stateless" &
        " already exists, not redeclaring")
when not declared(SSL_connect):
  proc SSL_connect*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_connect".}
else:
  static :
    hint("Declaration of " & "SSL_connect" & " already exists, not redeclaring")
when not declared(SSL_read):
  proc SSL_read*(ssl: ptr SSL_536871704; buf: pointer; num: cint): cint {.cdecl,
      importc: "SSL_read".}
else:
  static :
    hint("Declaration of " & "SSL_read" & " already exists, not redeclaring")
when not declared(SSL_read_ex):
  proc SSL_read_ex*(ssl: ptr SSL_536871704; buf: pointer; num: csize_t;
                    readbytes: ptr csize_t): cint {.cdecl,
      importc: "SSL_read_ex".}
else:
  static :
    hint("Declaration of " & "SSL_read_ex" & " already exists, not redeclaring")
when not declared(SSL_read_early_data):
  proc SSL_read_early_data*(s: ptr SSL_536871704; buf: pointer; num: csize_t;
                            readbytes: ptr csize_t): cint {.cdecl,
      importc: "SSL_read_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_read_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_peek):
  proc SSL_peek*(ssl: ptr SSL_536871704; buf: pointer; num: cint): cint {.cdecl,
      importc: "SSL_peek".}
else:
  static :
    hint("Declaration of " & "SSL_peek" & " already exists, not redeclaring")
when not declared(SSL_peek_ex):
  proc SSL_peek_ex*(ssl: ptr SSL_536871704; buf: pointer; num: csize_t;
                    readbytes: ptr csize_t): cint {.cdecl,
      importc: "SSL_peek_ex".}
else:
  static :
    hint("Declaration of " & "SSL_peek_ex" & " already exists, not redeclaring")
when not declared(SSL_sendfile):
  proc SSL_sendfile*(s: ptr SSL_536871704; fd: cint; offset: off_t_536871778;
                     size: csize_t; flags: cint): ssize_t_536871429 {.cdecl,
      importc: "SSL_sendfile".}
else:
  static :
    hint("Declaration of " & "SSL_sendfile" & " already exists, not redeclaring")
when not declared(SSL_write):
  proc SSL_write*(ssl: ptr SSL_536871704; buf: pointer; num: cint): cint {.
      cdecl, importc: "SSL_write".}
else:
  static :
    hint("Declaration of " & "SSL_write" & " already exists, not redeclaring")
when not declared(SSL_write_ex):
  proc SSL_write_ex*(s: ptr SSL_536871704; buf: pointer; num: csize_t;
                     written: ptr csize_t): cint {.cdecl,
      importc: "SSL_write_ex".}
else:
  static :
    hint("Declaration of " & "SSL_write_ex" & " already exists, not redeclaring")
when not declared(SSL_write_early_data):
  proc SSL_write_early_data*(s: ptr SSL_536871704; buf: pointer; num: csize_t;
                             written: ptr csize_t): cint {.cdecl,
      importc: "SSL_write_early_data".}
else:
  static :
    hint("Declaration of " & "SSL_write_early_data" &
        " already exists, not redeclaring")
when not declared(SSL_ctrl):
  proc SSL_ctrl*(ssl: ptr SSL_536871704; cmd: cint; larg: clong; parg: pointer): clong {.
      cdecl, importc: "SSL_ctrl".}
else:
  static :
    hint("Declaration of " & "SSL_ctrl" & " already exists, not redeclaring")
when not declared(SSL_callback_ctrl):
  proc SSL_callback_ctrl*(a0: ptr SSL_536871704; a1: cint;
                          a2: proc (): void {.cdecl.}): clong {.cdecl,
      importc: "SSL_callback_ctrl".}
else:
  static :
    hint("Declaration of " & "SSL_callback_ctrl" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_ctrl):
  proc SSL_CTX_ctrl*(ctx: ptr SSL_CTX_536871728; cmd: cint; larg: clong;
                     parg: pointer): clong {.cdecl, importc: "SSL_CTX_ctrl".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_ctrl" & " already exists, not redeclaring")
when not declared(SSL_CTX_callback_ctrl):
  proc SSL_CTX_callback_ctrl*(a0: ptr SSL_CTX_536871728; a1: cint;
                              a2: proc (): void {.cdecl.}): clong {.cdecl,
      importc: "SSL_CTX_callback_ctrl".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_callback_ctrl" &
        " already exists, not redeclaring")
when not declared(SSL_get_early_data_status):
  proc SSL_get_early_data_status*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_early_data_status".}
else:
  static :
    hint("Declaration of " & "SSL_get_early_data_status" &
        " already exists, not redeclaring")
when not declared(SSL_get_error):
  proc SSL_get_error*(s: ptr SSL_536871704; ret_code: cint): cint {.cdecl,
      importc: "SSL_get_error".}
else:
  static :
    hint("Declaration of " & "SSL_get_error" &
        " already exists, not redeclaring")
when not declared(SSL_get_version):
  proc SSL_get_version*(s: ptr SSL_536871704): cstring {.cdecl,
      importc: "SSL_get_version".}
else:
  static :
    hint("Declaration of " & "SSL_get_version" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_ssl_version):
  proc SSL_CTX_set_ssl_version*(ctx: ptr SSL_CTX_536871728; meth: ptr SSL_METHOD_536871680): cint {.
      cdecl, importc: "SSL_CTX_set_ssl_version".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_ssl_version" &
        " already exists, not redeclaring")
when not declared(TLSv1_method):
  proc TLSv1_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_method" & " already exists, not redeclaring")
when not declared(TLSv1_server_method):
  proc TLSv1_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_server_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_server_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_client_method):
  proc TLSv1_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_client_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_client_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_1_method):
  proc TLSv1_1_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_1_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_1_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_1_server_method):
  proc TLSv1_1_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_1_server_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_1_server_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_1_client_method):
  proc TLSv1_1_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_1_client_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_1_client_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_2_method):
  proc TLSv1_2_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_2_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_2_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_2_server_method):
  proc TLSv1_2_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_2_server_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_2_server_method" &
        " already exists, not redeclaring")
when not declared(TLSv1_2_client_method):
  proc TLSv1_2_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "TLSv1_2_client_method".}
else:
  static :
    hint("Declaration of " & "TLSv1_2_client_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_method):
  proc DTLSv1_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_server_method):
  proc DTLSv1_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_server_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_server_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_client_method):
  proc DTLSv1_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_client_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_client_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_2_method):
  proc DTLSv1_2_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_2_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_2_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_2_server_method):
  proc DTLSv1_2_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_2_server_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_2_server_method" &
        " already exists, not redeclaring")
when not declared(DTLSv1_2_client_method):
  proc DTLSv1_2_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLSv1_2_client_method".}
else:
  static :
    hint("Declaration of " & "DTLSv1_2_client_method" &
        " already exists, not redeclaring")
when not declared(DTLS_method):
  proc DTLS_method*(): ptr SSL_METHOD_536871680 {.cdecl, importc: "DTLS_method".}
else:
  static :
    hint("Declaration of " & "DTLS_method" & " already exists, not redeclaring")
when not declared(DTLS_server_method):
  proc DTLS_server_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLS_server_method".}
else:
  static :
    hint("Declaration of " & "DTLS_server_method" &
        " already exists, not redeclaring")
when not declared(DTLS_client_method):
  proc DTLS_client_method*(): ptr SSL_METHOD_536871680 {.cdecl,
      importc: "DTLS_client_method".}
else:
  static :
    hint("Declaration of " & "DTLS_client_method" &
        " already exists, not redeclaring")
when not declared(DTLS_get_data_mtu):
  proc DTLS_get_data_mtu*(s: ptr SSL_536871704): csize_t {.cdecl,
      importc: "DTLS_get_data_mtu".}
else:
  static :
    hint("Declaration of " & "DTLS_get_data_mtu" &
        " already exists, not redeclaring")
when not declared(SSL_get_ciphers):
  proc SSL_get_ciphers*(s: ptr SSL_536871704): ptr struct_stack_st_SSL_CIPHER {.
      cdecl, importc: "SSL_get_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_get_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_ciphers):
  proc SSL_CTX_get_ciphers*(ctx: ptr SSL_CTX_536871728): ptr struct_stack_st_SSL_CIPHER {.
      cdecl, importc: "SSL_CTX_get_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_get_client_ciphers):
  proc SSL_get_client_ciphers*(s: ptr SSL_536871704): ptr struct_stack_st_SSL_CIPHER {.
      cdecl, importc: "SSL_get_client_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_get_client_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_get1_supported_ciphers):
  proc SSL_get1_supported_ciphers*(s: ptr SSL_536871704): ptr struct_stack_st_SSL_CIPHER {.
      cdecl, importc: "SSL_get1_supported_ciphers".}
else:
  static :
    hint("Declaration of " & "SSL_get1_supported_ciphers" &
        " already exists, not redeclaring")
when not declared(SSL_do_handshake):
  proc SSL_do_handshake*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_do_handshake".}
else:
  static :
    hint("Declaration of " & "SSL_do_handshake" &
        " already exists, not redeclaring")
when not declared(SSL_key_update):
  proc SSL_key_update*(s: ptr SSL_536871704; updatetype: cint): cint {.cdecl,
      importc: "SSL_key_update".}
else:
  static :
    hint("Declaration of " & "SSL_key_update" &
        " already exists, not redeclaring")
when not declared(SSL_get_key_update_type):
  proc SSL_get_key_update_type*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_key_update_type".}
else:
  static :
    hint("Declaration of " & "SSL_get_key_update_type" &
        " already exists, not redeclaring")
when not declared(SSL_renegotiate):
  proc SSL_renegotiate*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_renegotiate".}
else:
  static :
    hint("Declaration of " & "SSL_renegotiate" &
        " already exists, not redeclaring")
when not declared(SSL_renegotiate_abbreviated):
  proc SSL_renegotiate_abbreviated*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_renegotiate_abbreviated".}
else:
  static :
    hint("Declaration of " & "SSL_renegotiate_abbreviated" &
        " already exists, not redeclaring")
when not declared(SSL_renegotiate_pending):
  proc SSL_renegotiate_pending*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_renegotiate_pending".}
else:
  static :
    hint("Declaration of " & "SSL_renegotiate_pending" &
        " already exists, not redeclaring")
when not declared(SSL_new_session_ticket):
  proc SSL_new_session_ticket*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_new_session_ticket".}
else:
  static :
    hint("Declaration of " & "SSL_new_session_ticket" &
        " already exists, not redeclaring")
when not declared(SSL_shutdown):
  proc SSL_shutdown*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_shutdown" & " already exists, not redeclaring")
when not declared(SSL_verify_client_post_handshake):
  proc SSL_verify_client_post_handshake*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_verify_client_post_handshake".}
else:
  static :
    hint("Declaration of " & "SSL_verify_client_post_handshake" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_post_handshake_auth):
  proc SSL_CTX_set_post_handshake_auth*(ctx: ptr SSL_CTX_536871728; val: cint): void {.
      cdecl, importc: "SSL_CTX_set_post_handshake_auth".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_post_handshake_auth" &
        " already exists, not redeclaring")
when not declared(SSL_set_post_handshake_auth):
  proc SSL_set_post_handshake_auth*(s: ptr SSL_536871704; val: cint): void {.
      cdecl, importc: "SSL_set_post_handshake_auth".}
else:
  static :
    hint("Declaration of " & "SSL_set_post_handshake_auth" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_ssl_method):
  proc SSL_CTX_get_ssl_method*(ctx: ptr SSL_CTX_536871728): ptr SSL_METHOD_536871680 {.
      cdecl, importc: "SSL_CTX_get_ssl_method".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_ssl_method" &
        " already exists, not redeclaring")
when not declared(SSL_get_ssl_method):
  proc SSL_get_ssl_method*(s: ptr SSL_536871704): ptr SSL_METHOD_536871680 {.
      cdecl, importc: "SSL_get_ssl_method".}
else:
  static :
    hint("Declaration of " & "SSL_get_ssl_method" &
        " already exists, not redeclaring")
when not declared(SSL_set_ssl_method):
  proc SSL_set_ssl_method*(s: ptr SSL_536871704; method_arg: ptr SSL_METHOD_536871680): cint {.
      cdecl, importc: "SSL_set_ssl_method".}
else:
  static :
    hint("Declaration of " & "SSL_set_ssl_method" &
        " already exists, not redeclaring")
when not declared(SSL_alert_type_string_long):
  proc SSL_alert_type_string_long*(value: cint): cstring {.cdecl,
      importc: "SSL_alert_type_string_long".}
else:
  static :
    hint("Declaration of " & "SSL_alert_type_string_long" &
        " already exists, not redeclaring")
when not declared(SSL_alert_type_string):
  proc SSL_alert_type_string*(value: cint): cstring {.cdecl,
      importc: "SSL_alert_type_string".}
else:
  static :
    hint("Declaration of " & "SSL_alert_type_string" &
        " already exists, not redeclaring")
when not declared(SSL_alert_desc_string_long):
  proc SSL_alert_desc_string_long*(value: cint): cstring {.cdecl,
      importc: "SSL_alert_desc_string_long".}
else:
  static :
    hint("Declaration of " & "SSL_alert_desc_string_long" &
        " already exists, not redeclaring")
when not declared(SSL_alert_desc_string):
  proc SSL_alert_desc_string*(value: cint): cstring {.cdecl,
      importc: "SSL_alert_desc_string".}
else:
  static :
    hint("Declaration of " & "SSL_alert_desc_string" &
        " already exists, not redeclaring")
when not declared(SSL_set0_CA_list):
  proc SSL_set0_CA_list*(s: ptr SSL_536871704;
                         name_list: ptr struct_stack_st_X509_NAME): void {.
      cdecl, importc: "SSL_set0_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_set0_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set0_CA_list):
  proc SSL_CTX_set0_CA_list*(ctx: ptr SSL_CTX_536871728;
                             name_list: ptr struct_stack_st_X509_NAME): void {.
      cdecl, importc: "SSL_CTX_set0_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set0_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_get0_CA_list):
  proc SSL_get0_CA_list*(s: ptr SSL_536871704): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_get0_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_get0_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_CA_list):
  proc SSL_CTX_get0_CA_list*(ctx: ptr SSL_CTX_536871728): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_CTX_get0_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_add1_to_CA_list):
  proc SSL_add1_to_CA_list*(ssl: ptr SSL_536871704; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_add1_to_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_add1_to_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add1_to_CA_list):
  proc SSL_CTX_add1_to_CA_list*(ctx: ptr SSL_CTX_536871728; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_CTX_add1_to_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add1_to_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_get0_peer_CA_list):
  proc SSL_get0_peer_CA_list*(s: ptr SSL_536871704): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_get0_peer_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_get0_peer_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_set_client_CA_list):
  proc SSL_set_client_CA_list*(s: ptr SSL_536871704;
                               name_list: ptr struct_stack_st_X509_NAME): void {.
      cdecl, importc: "SSL_set_client_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_set_client_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_client_CA_list):
  proc SSL_CTX_set_client_CA_list*(ctx: ptr SSL_CTX_536871728;
                                   name_list: ptr struct_stack_st_X509_NAME): void {.
      cdecl, importc: "SSL_CTX_set_client_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_client_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_get_client_CA_list):
  proc SSL_get_client_CA_list*(s: ptr SSL_536871704): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_get_client_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_get_client_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_client_CA_list):
  proc SSL_CTX_get_client_CA_list*(s: ptr SSL_CTX_536871728): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_CTX_get_client_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_client_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_add_client_CA):
  proc SSL_add_client_CA*(ssl: ptr SSL_536871704; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_add_client_CA".}
else:
  static :
    hint("Declaration of " & "SSL_add_client_CA" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_add_client_CA):
  proc SSL_CTX_add_client_CA*(ctx: ptr SSL_CTX_536871728; x: ptr X509_536871716): cint {.
      cdecl, importc: "SSL_CTX_add_client_CA".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_add_client_CA" &
        " already exists, not redeclaring")
when not declared(SSL_set_connect_state):
  proc SSL_set_connect_state*(s: ptr SSL_536871704): void {.cdecl,
      importc: "SSL_set_connect_state".}
else:
  static :
    hint("Declaration of " & "SSL_set_connect_state" &
        " already exists, not redeclaring")
when not declared(SSL_set_accept_state):
  proc SSL_set_accept_state*(s: ptr SSL_536871704): void {.cdecl,
      importc: "SSL_set_accept_state".}
else:
  static :
    hint("Declaration of " & "SSL_set_accept_state" &
        " already exists, not redeclaring")
when not declared(SSL_get_default_timeout):
  proc SSL_get_default_timeout*(s: ptr SSL_536871704): clong {.cdecl,
      importc: "SSL_get_default_timeout".}
else:
  static :
    hint("Declaration of " & "SSL_get_default_timeout" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_description):
  proc SSL_CIPHER_description*(a0: ptr SSL_CIPHER_536871682; buf: cstring;
                               size: cint): cstring {.cdecl,
      importc: "SSL_CIPHER_description".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_description" &
        " already exists, not redeclaring")
when not declared(SSL_dup_CA_list):
  proc SSL_dup_CA_list*(sk: ptr struct_stack_st_X509_NAME): ptr struct_stack_st_X509_NAME {.
      cdecl, importc: "SSL_dup_CA_list".}
else:
  static :
    hint("Declaration of " & "SSL_dup_CA_list" &
        " already exists, not redeclaring")
when not declared(SSL_dup):
  proc SSL_dup*(ssl: ptr SSL_536871704): ptr SSL_536871704 {.cdecl,
      importc: "SSL_dup".}
else:
  static :
    hint("Declaration of " & "SSL_dup" & " already exists, not redeclaring")
when not declared(SSL_get_certificate):
  proc SSL_get_certificate*(ssl: ptr SSL_536871704): ptr X509_536871716 {.cdecl,
      importc: "SSL_get_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_get_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_get_privatekey):
  proc SSL_get_privatekey*(ssl: ptr SSL_536871704): ptr struct_evp_pkey_st {.
      cdecl, importc: "SSL_get_privatekey".}
else:
  static :
    hint("Declaration of " & "SSL_get_privatekey" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_certificate):
  proc SSL_CTX_get0_certificate*(ctx: ptr SSL_CTX_536871728): ptr X509_536871716 {.
      cdecl, importc: "SSL_CTX_get0_certificate".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_certificate" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_privatekey):
  proc SSL_CTX_get0_privatekey*(ctx: ptr SSL_CTX_536871728): ptr EVP_PKEY_536871658 {.
      cdecl, importc: "SSL_CTX_get0_privatekey".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_privatekey" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_quiet_shutdown):
  proc SSL_CTX_set_quiet_shutdown*(ctx: ptr SSL_CTX_536871728; mode: cint): void {.
      cdecl, importc: "SSL_CTX_set_quiet_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_quiet_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_quiet_shutdown):
  proc SSL_CTX_get_quiet_shutdown*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_get_quiet_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_quiet_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_set_quiet_shutdown):
  proc SSL_set_quiet_shutdown*(ssl: ptr SSL_536871704; mode: cint): void {.
      cdecl, importc: "SSL_set_quiet_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_set_quiet_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_get_quiet_shutdown):
  proc SSL_get_quiet_shutdown*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_quiet_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_get_quiet_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_set_shutdown):
  proc SSL_set_shutdown*(ssl: ptr SSL_536871704; mode: cint): void {.cdecl,
      importc: "SSL_set_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_set_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_get_shutdown):
  proc SSL_get_shutdown*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_shutdown".}
else:
  static :
    hint("Declaration of " & "SSL_get_shutdown" &
        " already exists, not redeclaring")
when not declared(SSL_version):
  proc SSL_version*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_version".}
else:
  static :
    hint("Declaration of " & "SSL_version" & " already exists, not redeclaring")
when not declared(SSL_client_version):
  proc SSL_client_version*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_client_version".}
else:
  static :
    hint("Declaration of " & "SSL_client_version" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_verify_paths):
  proc SSL_CTX_set_default_verify_paths*(ctx: ptr SSL_CTX_536871728): cint {.
      cdecl, importc: "SSL_CTX_set_default_verify_paths".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_verify_paths" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_verify_dir):
  proc SSL_CTX_set_default_verify_dir*(ctx: ptr SSL_CTX_536871728): cint {.
      cdecl, importc: "SSL_CTX_set_default_verify_dir".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_verify_dir" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_verify_file):
  proc SSL_CTX_set_default_verify_file*(ctx: ptr SSL_CTX_536871728): cint {.
      cdecl, importc: "SSL_CTX_set_default_verify_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_verify_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_verify_store):
  proc SSL_CTX_set_default_verify_store*(ctx: ptr SSL_CTX_536871728): cint {.
      cdecl, importc: "SSL_CTX_set_default_verify_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_verify_store" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_load_verify_file):
  proc SSL_CTX_load_verify_file*(ctx: ptr SSL_CTX_536871728; CAfile: cstring): cint {.
      cdecl, importc: "SSL_CTX_load_verify_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_load_verify_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_load_verify_dir):
  proc SSL_CTX_load_verify_dir*(ctx: ptr SSL_CTX_536871728; CApath: cstring): cint {.
      cdecl, importc: "SSL_CTX_load_verify_dir".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_load_verify_dir" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_load_verify_store):
  proc SSL_CTX_load_verify_store*(ctx: ptr SSL_CTX_536871728; CAstore: cstring): cint {.
      cdecl, importc: "SSL_CTX_load_verify_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_load_verify_store" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_load_verify_locations):
  proc SSL_CTX_load_verify_locations*(ctx: ptr SSL_CTX_536871728;
                                      CAfile: cstring; CApath: cstring): cint {.
      cdecl, importc: "SSL_CTX_load_verify_locations".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_load_verify_locations" &
        " already exists, not redeclaring")
when not declared(SSL_get1_session):
  proc SSL_get1_session*(ssl: ptr SSL_536871704): ptr SSL_SESSION_536871684 {.
      cdecl, importc: "SSL_get1_session".}
else:
  static :
    hint("Declaration of " & "SSL_get1_session" &
        " already exists, not redeclaring")
when not declared(SSL_get_SSL_CTX):
  proc SSL_get_SSL_CTX*(ssl: ptr SSL_536871704): ptr SSL_CTX_536871728 {.cdecl,
      importc: "SSL_get_SSL_CTX".}
else:
  static :
    hint("Declaration of " & "SSL_get_SSL_CTX" &
        " already exists, not redeclaring")
when not declared(SSL_set_SSL_CTX):
  proc SSL_set_SSL_CTX*(ssl: ptr SSL_536871704; ctx: ptr SSL_CTX_536871728): ptr SSL_CTX_536871728 {.
      cdecl, importc: "SSL_set_SSL_CTX".}
else:
  static :
    hint("Declaration of " & "SSL_set_SSL_CTX" &
        " already exists, not redeclaring")
when not declared(SSL_set_info_callback):
  proc SSL_set_info_callback*(ssl: ptr SSL_536871704; cb: proc (a0: ptr SSL_536871704;
      a1: cint; a2: cint): void {.cdecl.}): void {.cdecl,
      importc: "SSL_set_info_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_info_callback" &
        " already exists, not redeclaring")
when not declared(SSL_get_info_callback):
  proc SSL_get_info_callback*(ssl: ptr SSL_536871704): proc (a0: ptr SSL_536871704;
      a1: cint; a2: cint): void {.cdecl.} {.cdecl,
      importc: "SSL_get_info_callback".}
else:
  static :
    hint("Declaration of " & "SSL_get_info_callback" &
        " already exists, not redeclaring")
when not declared(SSL_get_state):
  proc SSL_get_state*(ssl: ptr SSL_536871704): OSSL_HANDSHAKE_STATE_536871764 {.
      cdecl, importc: "SSL_get_state".}
else:
  static :
    hint("Declaration of " & "SSL_get_state" &
        " already exists, not redeclaring")
when not declared(SSL_set_verify_result):
  proc SSL_set_verify_result*(ssl: ptr SSL_536871704; v: clong): void {.cdecl,
      importc: "SSL_set_verify_result".}
else:
  static :
    hint("Declaration of " & "SSL_set_verify_result" &
        " already exists, not redeclaring")
when not declared(SSL_get_verify_result):
  proc SSL_get_verify_result*(ssl: ptr SSL_536871704): clong {.cdecl,
      importc: "SSL_get_verify_result".}
else:
  static :
    hint("Declaration of " & "SSL_get_verify_result" &
        " already exists, not redeclaring")
when not declared(SSL_get0_verified_chain):
  proc SSL_get0_verified_chain*(s: ptr SSL_536871704): ptr struct_stack_st_X509 {.
      cdecl, importc: "SSL_get0_verified_chain".}
else:
  static :
    hint("Declaration of " & "SSL_get0_verified_chain" &
        " already exists, not redeclaring")
when not declared(SSL_get_client_random):
  proc SSL_get_client_random*(ssl: ptr SSL_536871704; out_arg: ptr uint8;
                              outlen: csize_t): csize_t {.cdecl,
      importc: "SSL_get_client_random".}
else:
  static :
    hint("Declaration of " & "SSL_get_client_random" &
        " already exists, not redeclaring")
when not declared(SSL_get_server_random):
  proc SSL_get_server_random*(ssl: ptr SSL_536871704; out_arg: ptr uint8;
                              outlen: csize_t): csize_t {.cdecl,
      importc: "SSL_get_server_random".}
else:
  static :
    hint("Declaration of " & "SSL_get_server_random" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_master_key):
  proc SSL_SESSION_get_master_key*(sess: ptr SSL_SESSION_536871684;
                                   out_arg: ptr uint8; outlen: csize_t): csize_t {.
      cdecl, importc: "SSL_SESSION_get_master_key".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_master_key" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_master_key):
  proc SSL_SESSION_set1_master_key*(sess: ptr SSL_SESSION_536871684;
                                    in_arg: ptr uint8; len: csize_t): cint {.
      cdecl, importc: "SSL_SESSION_set1_master_key".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_master_key" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_max_fragment_length):
  proc SSL_SESSION_get_max_fragment_length*(sess: ptr SSL_SESSION_536871684): uint8 {.
      cdecl, importc: "SSL_SESSION_get_max_fragment_length".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_max_fragment_length" &
        " already exists, not redeclaring")
when not declared(SSL_set_ex_data):
  proc SSL_set_ex_data*(ssl: ptr SSL_536871704; idx: cint; data: pointer): cint {.
      cdecl, importc: "SSL_set_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_set_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_get_ex_data):
  proc SSL_get_ex_data*(ssl: ptr SSL_536871704; idx: cint): pointer {.cdecl,
      importc: "SSL_get_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_get_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set_ex_data):
  proc SSL_SESSION_set_ex_data*(ss: ptr SSL_SESSION_536871684; idx: cint;
                                data: pointer): cint {.cdecl,
      importc: "SSL_SESSION_set_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get_ex_data):
  proc SSL_SESSION_get_ex_data*(ss: ptr SSL_SESSION_536871684; idx: cint): pointer {.
      cdecl, importc: "SSL_SESSION_get_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_ex_data):
  proc SSL_CTX_set_ex_data*(ssl: ptr SSL_CTX_536871728; idx: cint; data: pointer): cint {.
      cdecl, importc: "SSL_CTX_set_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_ex_data):
  proc SSL_CTX_get_ex_data*(ssl: ptr SSL_CTX_536871728; idx: cint): pointer {.
      cdecl, importc: "SSL_CTX_get_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_get_ex_data_X509_STORE_CTX_idx):
  proc SSL_get_ex_data_X509_STORE_CTX_idx*(): cint {.cdecl,
      importc: "SSL_get_ex_data_X509_STORE_CTX_idx".}
else:
  static :
    hint("Declaration of " & "SSL_get_ex_data_X509_STORE_CTX_idx" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_read_buffer_len):
  proc SSL_CTX_set_default_read_buffer_len*(ctx: ptr SSL_CTX_536871728;
      len: csize_t): void {.cdecl,
                            importc: "SSL_CTX_set_default_read_buffer_len".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_read_buffer_len" &
        " already exists, not redeclaring")
when not declared(SSL_set_default_read_buffer_len):
  proc SSL_set_default_read_buffer_len*(s: ptr SSL_536871704; len: csize_t): void {.
      cdecl, importc: "SSL_set_default_read_buffer_len".}
else:
  static :
    hint("Declaration of " & "SSL_set_default_read_buffer_len" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_tmp_dh_callback):
  proc SSL_CTX_set_tmp_dh_callback*(ctx: ptr SSL_CTX_536871728; dh: proc (
      a0: ptr SSL_536871704; a1: cint; a2: cint): ptr DH_536871780 {.cdecl.}): void {.
      cdecl, importc: "SSL_CTX_set_tmp_dh_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_tmp_dh_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_tmp_dh_callback):
  proc SSL_set_tmp_dh_callback*(ssl: ptr SSL_536871704; dh: proc (a0: ptr SSL_536871704;
      a1: cint; a2: cint): ptr DH_536871780 {.cdecl.}): void {.cdecl,
      importc: "SSL_set_tmp_dh_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_tmp_dh_callback" &
        " already exists, not redeclaring")
when not declared(SSL_get_current_compression):
  proc SSL_get_current_compression*(s: ptr SSL_536871704): ptr COMP_METHOD_536871782 {.
      cdecl, importc: "SSL_get_current_compression".}
else:
  static :
    hint("Declaration of " & "SSL_get_current_compression" &
        " already exists, not redeclaring")
when not declared(SSL_get_current_expansion):
  proc SSL_get_current_expansion*(s: ptr SSL_536871704): ptr COMP_METHOD_536871782 {.
      cdecl, importc: "SSL_get_current_expansion".}
else:
  static :
    hint("Declaration of " & "SSL_get_current_expansion" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_get_name):
  proc SSL_COMP_get_name*(comp: ptr COMP_METHOD_536871782): cstring {.cdecl,
      importc: "SSL_COMP_get_name".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_get_name" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_get0_name):
  proc SSL_COMP_get0_name*(comp: ptr SSL_COMP_536871690): cstring {.cdecl,
      importc: "SSL_COMP_get0_name".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_get0_name" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_get_id):
  proc SSL_COMP_get_id*(comp: ptr SSL_COMP_536871690): cint {.cdecl,
      importc: "SSL_COMP_get_id".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_get_id" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_get_compression_methods):
  proc SSL_COMP_get_compression_methods*(): ptr struct_stack_st_SSL_COMP {.
      cdecl, importc: "SSL_COMP_get_compression_methods".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_get_compression_methods" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_set0_compression_methods):
  proc SSL_COMP_set0_compression_methods*(meths: ptr struct_stack_st_SSL_COMP): ptr struct_stack_st_SSL_COMP {.
      cdecl, importc: "SSL_COMP_set0_compression_methods".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_set0_compression_methods" &
        " already exists, not redeclaring")
when not declared(SSL_COMP_add_compression_method):
  proc SSL_COMP_add_compression_method*(id: cint; cm: ptr COMP_METHOD_536871782): cint {.
      cdecl, importc: "SSL_COMP_add_compression_method".}
else:
  static :
    hint("Declaration of " & "SSL_COMP_add_compression_method" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_find):
  proc SSL_CIPHER_find*(ssl: ptr SSL_536871704; ptr_arg: ptr uint8): ptr SSL_CIPHER_536871682 {.
      cdecl, importc: "SSL_CIPHER_find".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_find" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_cipher_nid):
  proc SSL_CIPHER_get_cipher_nid*(c: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_CIPHER_get_cipher_nid".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_cipher_nid" &
        " already exists, not redeclaring")
when not declared(SSL_CIPHER_get_digest_nid):
  proc SSL_CIPHER_get_digest_nid*(c: ptr SSL_CIPHER_536871682): cint {.cdecl,
      importc: "SSL_CIPHER_get_digest_nid".}
else:
  static :
    hint("Declaration of " & "SSL_CIPHER_get_digest_nid" &
        " already exists, not redeclaring")
when not declared(SSL_bytes_to_cipher_list):
  proc SSL_bytes_to_cipher_list*(s: ptr SSL_536871704; bytes: ptr uint8;
                                 len: csize_t; isv2format: cint;
                                 sk: ptr ptr struct_stack_st_SSL_CIPHER;
                                 scsvs: ptr ptr struct_stack_st_SSL_CIPHER): cint {.
      cdecl, importc: "SSL_bytes_to_cipher_list".}
else:
  static :
    hint("Declaration of " & "SSL_bytes_to_cipher_list" &
        " already exists, not redeclaring")
when not declared(SSL_set_session_ticket_ext):
  proc SSL_set_session_ticket_ext*(s: ptr SSL_536871704; ext_data: pointer;
                                   ext_len: cint): cint {.cdecl,
      importc: "SSL_set_session_ticket_ext".}
else:
  static :
    hint("Declaration of " & "SSL_set_session_ticket_ext" &
        " already exists, not redeclaring")
when not declared(SSL_set_session_ticket_ext_cb):
  proc SSL_set_session_ticket_ext_cb*(s: ptr SSL_536871704;
                                      cb: tls_session_ticket_ext_cb_fn_536871702;
                                      arg: pointer): cint {.cdecl,
      importc: "SSL_set_session_ticket_ext_cb".}
else:
  static :
    hint("Declaration of " & "SSL_set_session_ticket_ext_cb" &
        " already exists, not redeclaring")
when not declared(SSL_set_session_secret_cb):
  proc SSL_set_session_secret_cb*(s: ptr SSL_536871704;
                                  session_secret_cb: tls_session_secret_cb_fn_536871706;
                                  arg: pointer): cint {.cdecl,
      importc: "SSL_set_session_secret_cb".}
else:
  static :
    hint("Declaration of " & "SSL_set_session_secret_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_not_resumable_session_callback):
  proc SSL_CTX_set_not_resumable_session_callback*(ctx: ptr SSL_CTX_536871728;
      cb: proc (a0: ptr SSL_536871704; a1: cint): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_not_resumable_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_not_resumable_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_not_resumable_session_callback):
  proc SSL_set_not_resumable_session_callback*(ssl: ptr SSL_536871704;
      cb: proc (a0: ptr SSL_536871704; a1: cint): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_set_not_resumable_session_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_not_resumable_session_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_record_padding_callback):
  proc SSL_CTX_set_record_padding_callback*(ctx: ptr SSL_CTX_536871728; cb: proc (
      a0: ptr SSL_536871704; a1: cint; a2: csize_t; a3: pointer): csize_t {.
      cdecl.}): void {.cdecl, importc: "SSL_CTX_set_record_padding_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_record_padding_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_record_padding_callback_arg):
  proc SSL_CTX_set_record_padding_callback_arg*(ctx: ptr SSL_CTX_536871728;
      arg: pointer): void {.cdecl,
                            importc: "SSL_CTX_set_record_padding_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_record_padding_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_record_padding_callback_arg):
  proc SSL_CTX_get_record_padding_callback_arg*(ctx: ptr SSL_CTX_536871728): pointer {.
      cdecl, importc: "SSL_CTX_get_record_padding_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_record_padding_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_block_padding):
  proc SSL_CTX_set_block_padding*(ctx: ptr SSL_CTX_536871728;
                                  block_size: csize_t): cint {.cdecl,
      importc: "SSL_CTX_set_block_padding".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_block_padding" &
        " already exists, not redeclaring")
when not declared(SSL_set_record_padding_callback):
  proc SSL_set_record_padding_callback*(ssl: ptr SSL_536871704; cb: proc (
      a0: ptr SSL_536871704; a1: cint; a2: csize_t; a3: pointer): csize_t {.
      cdecl.}): cint {.cdecl, importc: "SSL_set_record_padding_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_record_padding_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set_record_padding_callback_arg):
  proc SSL_set_record_padding_callback_arg*(ssl: ptr SSL_536871704; arg: pointer): void {.
      cdecl, importc: "SSL_set_record_padding_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_set_record_padding_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_get_record_padding_callback_arg):
  proc SSL_get_record_padding_callback_arg*(ssl: ptr SSL_536871704): pointer {.
      cdecl, importc: "SSL_get_record_padding_callback_arg".}
else:
  static :
    hint("Declaration of " & "SSL_get_record_padding_callback_arg" &
        " already exists, not redeclaring")
when not declared(SSL_set_block_padding):
  proc SSL_set_block_padding*(ssl: ptr SSL_536871704; block_size: csize_t): cint {.
      cdecl, importc: "SSL_set_block_padding".}
else:
  static :
    hint("Declaration of " & "SSL_set_block_padding" &
        " already exists, not redeclaring")
when not declared(SSL_set_num_tickets):
  proc SSL_set_num_tickets*(s: ptr SSL_536871704; num_tickets: csize_t): cint {.
      cdecl, importc: "SSL_set_num_tickets".}
else:
  static :
    hint("Declaration of " & "SSL_set_num_tickets" &
        " already exists, not redeclaring")
when not declared(SSL_get_num_tickets):
  proc SSL_get_num_tickets*(s: ptr SSL_536871704): csize_t {.cdecl,
      importc: "SSL_get_num_tickets".}
else:
  static :
    hint("Declaration of " & "SSL_get_num_tickets" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_num_tickets):
  proc SSL_CTX_set_num_tickets*(ctx: ptr SSL_CTX_536871728; num_tickets: csize_t): cint {.
      cdecl, importc: "SSL_CTX_set_num_tickets".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_num_tickets" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_num_tickets):
  proc SSL_CTX_get_num_tickets*(ctx: ptr SSL_CTX_536871728): csize_t {.cdecl,
      importc: "SSL_CTX_get_num_tickets".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_num_tickets" &
        " already exists, not redeclaring")
when not declared(SSL_session_reused):
  proc SSL_session_reused*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_session_reused".}
else:
  static :
    hint("Declaration of " & "SSL_session_reused" &
        " already exists, not redeclaring")
when not declared(SSL_is_server):
  proc SSL_is_server*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_is_server".}
else:
  static :
    hint("Declaration of " & "SSL_is_server" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_new):
  proc SSL_CONF_CTX_new*(): ptr SSL_CONF_CTX_536871688 {.cdecl,
      importc: "SSL_CONF_CTX_new".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_new" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_finish):
  proc SSL_CONF_CTX_finish*(cctx: ptr SSL_CONF_CTX_536871688): cint {.cdecl,
      importc: "SSL_CONF_CTX_finish".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_finish" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_free):
  proc SSL_CONF_CTX_free*(cctx: ptr SSL_CONF_CTX_536871688): void {.cdecl,
      importc: "SSL_CONF_CTX_free".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_free" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_set_flags):
  proc SSL_CONF_CTX_set_flags*(cctx: ptr SSL_CONF_CTX_536871688; flags: cuint): cuint {.
      cdecl, importc: "SSL_CONF_CTX_set_flags".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_set_flags" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_clear_flags):
  proc SSL_CONF_CTX_clear_flags*(cctx: ptr SSL_CONF_CTX_536871688; flags: cuint): cuint {.
      cdecl, importc: "SSL_CONF_CTX_clear_flags".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_clear_flags" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_set1_prefix):
  proc SSL_CONF_CTX_set1_prefix*(cctx: ptr SSL_CONF_CTX_536871688; pre: cstring): cint {.
      cdecl, importc: "SSL_CONF_CTX_set1_prefix".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_set1_prefix" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_set_ssl):
  proc SSL_CONF_CTX_set_ssl*(cctx: ptr SSL_CONF_CTX_536871688; ssl: ptr SSL_536871704): void {.
      cdecl, importc: "SSL_CONF_CTX_set_ssl".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_set_ssl" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_CTX_set_ssl_ctx):
  proc SSL_CONF_CTX_set_ssl_ctx*(cctx: ptr SSL_CONF_CTX_536871688;
                                 ctx: ptr SSL_CTX_536871728): void {.cdecl,
      importc: "SSL_CONF_CTX_set_ssl_ctx".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_CTX_set_ssl_ctx" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_cmd):
  proc SSL_CONF_cmd*(cctx: ptr SSL_CONF_CTX_536871688; cmd: cstring;
                     value: cstring): cint {.cdecl, importc: "SSL_CONF_cmd".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_cmd" & " already exists, not redeclaring")
when not declared(SSL_CONF_cmd_argv):
  proc SSL_CONF_cmd_argv*(cctx: ptr SSL_CONF_CTX_536871688; pargc: ptr cint;
                          pargv: ptr ptr cstring): cint {.cdecl,
      importc: "SSL_CONF_cmd_argv".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_cmd_argv" &
        " already exists, not redeclaring")
when not declared(SSL_CONF_cmd_value_type):
  proc SSL_CONF_cmd_value_type*(cctx: ptr SSL_CONF_CTX_536871688; cmd: cstring): cint {.
      cdecl, importc: "SSL_CONF_cmd_value_type".}
else:
  static :
    hint("Declaration of " & "SSL_CONF_cmd_value_type" &
        " already exists, not redeclaring")
when not declared(SSL_add_ssl_module):
  proc SSL_add_ssl_module*(): void {.cdecl, importc: "SSL_add_ssl_module".}
else:
  static :
    hint("Declaration of " & "SSL_add_ssl_module" &
        " already exists, not redeclaring")
when not declared(SSL_config):
  proc SSL_config*(s: ptr SSL_536871704; name: cstring): cint {.cdecl,
      importc: "SSL_config".}
else:
  static :
    hint("Declaration of " & "SSL_config" & " already exists, not redeclaring")
when not declared(SSL_CTX_config):
  proc SSL_CTX_config*(ctx: ptr SSL_CTX_536871728; name: cstring): cint {.cdecl,
      importc: "SSL_CTX_config".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_config" &
        " already exists, not redeclaring")
when not declared(SSL_trace):
  proc SSL_trace*(write_p: cint; version: cint; content_type: cint;
                  buf: pointer; len: csize_t; ssl: ptr SSL_536871704;
                  arg: pointer): void {.cdecl, importc: "SSL_trace".}
else:
  static :
    hint("Declaration of " & "SSL_trace" & " already exists, not redeclaring")
when not declared(DTLSv1_listen):
  proc DTLSv1_listen*(s: ptr SSL_536871704; client: ptr BIO_ADDR_536871784): cint {.
      cdecl, importc: "DTLSv1_listen".}
else:
  static :
    hint("Declaration of " & "DTLSv1_listen" &
        " already exists, not redeclaring")
when not declared(SSL_set_ct_validation_callback):
  proc SSL_set_ct_validation_callback*(s: ptr SSL_536871704;
                                       callback: ssl_ct_validation_cb_536871786;
                                       arg: pointer): cint {.cdecl,
      importc: "SSL_set_ct_validation_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_ct_validation_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_ct_validation_callback):
  proc SSL_CTX_set_ct_validation_callback*(ctx: ptr SSL_CTX_536871728;
      callback: ssl_ct_validation_cb_536871786; arg: pointer): cint {.cdecl,
      importc: "SSL_CTX_set_ct_validation_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_ct_validation_callback" &
        " already exists, not redeclaring")
when not declared(SSL_enable_ct):
  proc SSL_enable_ct*(s: ptr SSL_536871704; validation_mode: cint): cint {.
      cdecl, importc: "SSL_enable_ct".}
else:
  static :
    hint("Declaration of " & "SSL_enable_ct" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_enable_ct):
  proc SSL_CTX_enable_ct*(ctx: ptr SSL_CTX_536871728; validation_mode: cint): cint {.
      cdecl, importc: "SSL_CTX_enable_ct".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_enable_ct" &
        " already exists, not redeclaring")
when not declared(SSL_ct_is_enabled):
  proc SSL_ct_is_enabled*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_ct_is_enabled".}
else:
  static :
    hint("Declaration of " & "SSL_ct_is_enabled" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_ct_is_enabled):
  proc SSL_CTX_ct_is_enabled*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_ct_is_enabled".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_ct_is_enabled" &
        " already exists, not redeclaring")
when not declared(SSL_get0_peer_scts):
  proc SSL_get0_peer_scts*(s: ptr SSL_536871704): ptr struct_stack_st_SCT {.
      cdecl, importc: "SSL_get0_peer_scts".}
else:
  static :
    hint("Declaration of " & "SSL_get0_peer_scts" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_default_ctlog_list_file):
  proc SSL_CTX_set_default_ctlog_list_file*(ctx: ptr SSL_CTX_536871728): cint {.
      cdecl, importc: "SSL_CTX_set_default_ctlog_list_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_default_ctlog_list_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_ctlog_list_file):
  proc SSL_CTX_set_ctlog_list_file*(ctx: ptr SSL_CTX_536871728; path: cstring): cint {.
      cdecl, importc: "SSL_CTX_set_ctlog_list_file".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_ctlog_list_file" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set0_ctlog_store):
  proc SSL_CTX_set0_ctlog_store*(ctx: ptr SSL_CTX_536871728;
                                 logs: ptr CTLOG_STORE_536871790): void {.cdecl,
      importc: "SSL_CTX_set0_ctlog_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set0_ctlog_store" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_ctlog_store):
  proc SSL_CTX_get0_ctlog_store*(ctx: ptr SSL_CTX_536871728): ptr CTLOG_STORE_536871790 {.
      cdecl, importc: "SSL_CTX_get0_ctlog_store".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_ctlog_store" &
        " already exists, not redeclaring")
when not declared(SSL_set_security_level):
  proc SSL_set_security_level*(s: ptr SSL_536871704; level: cint): void {.cdecl,
      importc: "SSL_set_security_level".}
else:
  static :
    hint("Declaration of " & "SSL_set_security_level" &
        " already exists, not redeclaring")
when not declared(SSL_get_security_level):
  proc SSL_get_security_level*(s: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_get_security_level".}
else:
  static :
    hint("Declaration of " & "SSL_get_security_level" &
        " already exists, not redeclaring")
when not declared(SSL_set_security_callback):
  proc SSL_set_security_callback*(s: ptr SSL_536871704; cb: proc (a0: ptr SSL_536871704;
      a1: ptr SSL_CTX_536871728; a2: cint; a3: cint; a4: cint; a5: pointer;
      a6: pointer): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_set_security_callback".}
else:
  static :
    hint("Declaration of " & "SSL_set_security_callback" &
        " already exists, not redeclaring")
when not declared(SSL_get_security_callback):
  proc SSL_get_security_callback*(s: ptr SSL_536871704): proc (a0: ptr SSL_536871704;
      a1: ptr SSL_CTX_536871728; a2: cint; a3: cint; a4: cint; a5: pointer;
      a6: pointer): cint {.cdecl.} {.cdecl, importc: "SSL_get_security_callback".}
else:
  static :
    hint("Declaration of " & "SSL_get_security_callback" &
        " already exists, not redeclaring")
when not declared(SSL_set0_security_ex_data):
  proc SSL_set0_security_ex_data*(s: ptr SSL_536871704; ex: pointer): void {.
      cdecl, importc: "SSL_set0_security_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_set0_security_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_get0_security_ex_data):
  proc SSL_get0_security_ex_data*(s: ptr SSL_536871704): pointer {.cdecl,
      importc: "SSL_get0_security_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_get0_security_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_security_level):
  proc SSL_CTX_set_security_level*(ctx: ptr SSL_CTX_536871728; level: cint): void {.
      cdecl, importc: "SSL_CTX_set_security_level".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_security_level" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_security_level):
  proc SSL_CTX_get_security_level*(ctx: ptr SSL_CTX_536871728): cint {.cdecl,
      importc: "SSL_CTX_get_security_level".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_security_level" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_security_callback):
  proc SSL_CTX_set_security_callback*(ctx: ptr SSL_CTX_536871728; cb: proc (
      a0: ptr SSL_536871704; a1: ptr SSL_CTX_536871728; a2: cint; a3: cint;
      a4: cint; a5: pointer; a6: pointer): cint {.cdecl.}): void {.cdecl,
      importc: "SSL_CTX_set_security_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_security_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get_security_callback):
  proc SSL_CTX_get_security_callback*(ctx: ptr SSL_CTX_536871728): proc (
      a0: ptr SSL_536871704; a1: ptr SSL_CTX_536871728; a2: cint; a3: cint;
      a4: cint; a5: pointer; a6: pointer): cint {.cdecl.} {.cdecl,
      importc: "SSL_CTX_get_security_callback".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get_security_callback" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set0_security_ex_data):
  proc SSL_CTX_set0_security_ex_data*(ctx: ptr SSL_CTX_536871728; ex: pointer): void {.
      cdecl, importc: "SSL_CTX_set0_security_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set0_security_ex_data" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_get0_security_ex_data):
  proc SSL_CTX_get0_security_ex_data*(ctx: ptr SSL_CTX_536871728): pointer {.
      cdecl, importc: "SSL_CTX_get0_security_ex_data".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_get0_security_ex_data" &
        " already exists, not redeclaring")
when not declared(OPENSSL_init_ssl):
  proc OPENSSL_init_ssl*(opts: uint64; settings: ptr OPENSSL_INIT_SETTINGS_536871520): cint {.
      cdecl, importc: "OPENSSL_init_ssl".}
else:
  static :
    hint("Declaration of " & "OPENSSL_init_ssl" &
        " already exists, not redeclaring")
when not declared(SSL_test_functions):
  proc SSL_test_functions*(): ptr struct_openssl_ssl_test_functions {.cdecl,
      importc: "SSL_test_functions".}
else:
  static :
    hint("Declaration of " & "SSL_test_functions" &
        " already exists, not redeclaring")
when not declared(SSL_free_buffers):
  proc SSL_free_buffers*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_free_buffers".}
else:
  static :
    hint("Declaration of " & "SSL_free_buffers" &
        " already exists, not redeclaring")
when not declared(SSL_alloc_buffers):
  proc SSL_alloc_buffers*(ssl: ptr SSL_536871704): cint {.cdecl,
      importc: "SSL_alloc_buffers".}
else:
  static :
    hint("Declaration of " & "SSL_alloc_buffers" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_session_ticket_cb):
  proc SSL_CTX_set_session_ticket_cb*(ctx: ptr SSL_CTX_536871728; gen_cb: SSL_CTX_generate_session_ticket_fn_536871796;
      dec_cb: SSL_CTX_decrypt_session_ticket_fn_536871798; arg: pointer): cint {.
      cdecl, importc: "SSL_CTX_set_session_ticket_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_session_ticket_cb" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_set1_ticket_appdata):
  proc SSL_SESSION_set1_ticket_appdata*(ss: ptr SSL_SESSION_536871684;
                                        data: pointer; len: csize_t): cint {.
      cdecl, importc: "SSL_SESSION_set1_ticket_appdata".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_set1_ticket_appdata" &
        " already exists, not redeclaring")
when not declared(SSL_SESSION_get0_ticket_appdata):
  proc SSL_SESSION_get0_ticket_appdata*(ss: ptr SSL_SESSION_536871684;
                                        data: ptr pointer; len: ptr csize_t): cint {.
      cdecl, importc: "SSL_SESSION_get0_ticket_appdata".}
else:
  static :
    hint("Declaration of " & "SSL_SESSION_get0_ticket_appdata" &
        " already exists, not redeclaring")
when not declared(DTLS_set_timer_cb):
  proc DTLS_set_timer_cb*(s: ptr SSL_536871704; cb: DTLS_timer_cb_536871800): void {.
      cdecl, importc: "DTLS_set_timer_cb".}
else:
  static :
    hint("Declaration of " & "DTLS_set_timer_cb" &
        " already exists, not redeclaring")
when not declared(SSL_CTX_set_allow_early_data_cb):
  proc SSL_CTX_set_allow_early_data_cb*(ctx: ptr SSL_CTX_536871728;
                                        cb: SSL_allow_early_data_cb_fn_536871802;
                                        arg: pointer): void {.cdecl,
      importc: "SSL_CTX_set_allow_early_data_cb".}
else:
  static :
    hint("Declaration of " & "SSL_CTX_set_allow_early_data_cb" &
        " already exists, not redeclaring")
when not declared(SSL_set_allow_early_data_cb):
  proc SSL_set_allow_early_data_cb*(s: ptr SSL_536871704;
                                    cb: SSL_allow_early_data_cb_fn_536871802;
                                    arg: pointer): void {.cdecl,
      importc: "SSL_set_allow_early_data_cb".}
else:
  static :
    hint("Declaration of " & "SSL_set_allow_early_data_cb" &
        " already exists, not redeclaring")
when not declared(OSSL_default_cipher_list):
  proc OSSL_default_cipher_list*(): cstring {.cdecl,
      importc: "OSSL_default_cipher_list".}
else:
  static :
    hint("Declaration of " & "OSSL_default_cipher_list" &
        " already exists, not redeclaring")
when not declared(OSSL_default_ciphersuites):
  proc OSSL_default_ciphersuites*(): cstring {.cdecl,
      importc: "OSSL_default_ciphersuites".}
else:
  static :
    hint("Declaration of " & "OSSL_default_ciphersuites" &
        " already exists, not redeclaring")
when not declared(RAND_set_rand_method):
  proc RAND_set_rand_method*(meth: ptr RAND_METHOD_536871806): cint {.cdecl,
      importc: "RAND_set_rand_method".}
else:
  static :
    hint("Declaration of " & "RAND_set_rand_method" &
        " already exists, not redeclaring")
when not declared(RAND_get_rand_method):
  proc RAND_get_rand_method*(): ptr RAND_METHOD_536871806 {.cdecl,
      importc: "RAND_get_rand_method".}
else:
  static :
    hint("Declaration of " & "RAND_get_rand_method" &
        " already exists, not redeclaring")
when not declared(RAND_set_rand_engine):
  proc RAND_set_rand_engine*(engine: ptr ENGINE_536871732): cint {.cdecl,
      importc: "RAND_set_rand_engine".}
else:
  static :
    hint("Declaration of " & "RAND_set_rand_engine" &
        " already exists, not redeclaring")
when not declared(RAND_OpenSSL):
  proc RAND_OpenSSL*(): ptr RAND_METHOD_536871806 {.cdecl,
      importc: "RAND_OpenSSL".}
else:
  static :
    hint("Declaration of " & "RAND_OpenSSL" & " already exists, not redeclaring")
when not declared(RAND_bytes):
  proc RAND_bytes*(buf: ptr uint8; num: cint): cint {.cdecl,
      importc: "RAND_bytes".}
else:
  static :
    hint("Declaration of " & "RAND_bytes" & " already exists, not redeclaring")
when not declared(RAND_priv_bytes):
  proc RAND_priv_bytes*(buf: ptr uint8; num: cint): cint {.cdecl,
      importc: "RAND_priv_bytes".}
else:
  static :
    hint("Declaration of " & "RAND_priv_bytes" &
        " already exists, not redeclaring")
when not declared(RAND_priv_bytes_ex):
  proc RAND_priv_bytes_ex*(ctx: ptr OSSL_LIB_CTX_536871484; buf: ptr uint8;
                           num: csize_t; strength: cuint): cint {.cdecl,
      importc: "RAND_priv_bytes_ex".}
else:
  static :
    hint("Declaration of " & "RAND_priv_bytes_ex" &
        " already exists, not redeclaring")
when not declared(RAND_bytes_ex):
  proc RAND_bytes_ex*(ctx: ptr OSSL_LIB_CTX_536871484; buf: ptr uint8;
                      num: csize_t; strength: cuint): cint {.cdecl,
      importc: "RAND_bytes_ex".}
else:
  static :
    hint("Declaration of " & "RAND_bytes_ex" &
        " already exists, not redeclaring")
when not declared(RAND_pseudo_bytes):
  proc RAND_pseudo_bytes*(buf: ptr uint8; num: cint): cint {.cdecl,
      importc: "RAND_pseudo_bytes".}
else:
  static :
    hint("Declaration of " & "RAND_pseudo_bytes" &
        " already exists, not redeclaring")
when not declared(RAND_get0_primary):
  proc RAND_get0_primary*(ctx: ptr OSSL_LIB_CTX_536871484): ptr EVP_RAND_CTX_536871808 {.
      cdecl, importc: "RAND_get0_primary".}
else:
  static :
    hint("Declaration of " & "RAND_get0_primary" &
        " already exists, not redeclaring")
when not declared(RAND_get0_public):
  proc RAND_get0_public*(ctx: ptr OSSL_LIB_CTX_536871484): ptr EVP_RAND_CTX_536871808 {.
      cdecl, importc: "RAND_get0_public".}
else:
  static :
    hint("Declaration of " & "RAND_get0_public" &
        " already exists, not redeclaring")
when not declared(RAND_get0_private):
  proc RAND_get0_private*(ctx: ptr OSSL_LIB_CTX_536871484): ptr EVP_RAND_CTX_536871808 {.
      cdecl, importc: "RAND_get0_private".}
else:
  static :
    hint("Declaration of " & "RAND_get0_private" &
        " already exists, not redeclaring")
when not declared(RAND_set_DRBG_type):
  proc RAND_set_DRBG_type*(ctx: ptr OSSL_LIB_CTX_536871484; drbg: cstring;
                           propq: cstring; cipher: cstring; digest: cstring): cint {.
      cdecl, importc: "RAND_set_DRBG_type".}
else:
  static :
    hint("Declaration of " & "RAND_set_DRBG_type" &
        " already exists, not redeclaring")
when not declared(RAND_set_seed_source_type):
  proc RAND_set_seed_source_type*(ctx: ptr OSSL_LIB_CTX_536871484;
                                  seed: cstring; propq: cstring): cint {.cdecl,
      importc: "RAND_set_seed_source_type".}
else:
  static :
    hint("Declaration of " & "RAND_set_seed_source_type" &
        " already exists, not redeclaring")
when not declared(RAND_seed):
  proc RAND_seed*(buf: pointer; num: cint): void {.cdecl, importc: "RAND_seed".}
else:
  static :
    hint("Declaration of " & "RAND_seed" & " already exists, not redeclaring")
when not declared(RAND_keep_random_devices_open):
  proc RAND_keep_random_devices_open*(keep: cint): void {.cdecl,
      importc: "RAND_keep_random_devices_open".}
else:
  static :
    hint("Declaration of " & "RAND_keep_random_devices_open" &
        " already exists, not redeclaring")
when not declared(RAND_add):
  proc RAND_add*(buf: pointer; num: cint; randomness: cdouble): void {.cdecl,
      importc: "RAND_add".}
else:
  static :
    hint("Declaration of " & "RAND_add" & " already exists, not redeclaring")
when not declared(RAND_load_file):
  proc RAND_load_file*(file: cstring; max_bytes: clong): cint {.cdecl,
      importc: "RAND_load_file".}
else:
  static :
    hint("Declaration of " & "RAND_load_file" &
        " already exists, not redeclaring")
when not declared(RAND_write_file):
  proc RAND_write_file*(file: cstring): cint {.cdecl, importc: "RAND_write_file".}
else:
  static :
    hint("Declaration of " & "RAND_write_file" &
        " already exists, not redeclaring")
when not declared(RAND_file_name):
  proc RAND_file_name*(file: cstring; num: csize_t): cstring {.cdecl,
      importc: "RAND_file_name".}
else:
  static :
    hint("Declaration of " & "RAND_file_name" &
        " already exists, not redeclaring")
when not declared(RAND_status):
  proc RAND_status*(): cint {.cdecl, importc: "RAND_status".}
else:
  static :
    hint("Declaration of " & "RAND_status" & " already exists, not redeclaring")
when not declared(RAND_poll):
  proc RAND_poll*(): cint {.cdecl, importc: "RAND_poll".}
else:
  static :
    hint("Declaration of " & "RAND_poll" & " already exists, not redeclaring")
const
  LSQUIC_GLOBAL_CLIENT* = (1 shl 0)
  LSQUIC_GLOBAL_SERVER* = (1 shl 1)