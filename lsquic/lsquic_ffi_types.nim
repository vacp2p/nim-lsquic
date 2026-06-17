# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

type
  ptrdiff_t* {.importc: "ptrdiff_t", header: "<stddef.h>".} = int
  uint_fast8_t* {.importc: "uint_fast8_t", header: "<stdint.h>".} = uint8

# enums are generated manually to avoid issue described in
# https://github.com/PMunch/futhark/issues/152
template borrowCEnumOps(T: typedesc) =
  proc `==`*(a, b: T): bool {.borrow.}
  proc `<`*(a, b: T): bool {.borrow.}
  proc `<=`*(a, b: T): bool {.borrow.}
  proc `or`*(a, b: T): T {.borrow.}
  proc `and`*(a, b: T): T {.borrow.}
  proc `xor`*(a, b: T): T {.borrow.}
  proc `not`*(a: T): T {.borrow.}
  proc `$`*(a: T): string {.borrow.}

type
  enum_lsquic_version* = distinct cuint
  enum_lsquic_hsk_status* = distinct cuint
  enum_lsquic_hsi_flag* = distinct cuint
  enum_lsquic_logger_timestamp_style* = distinct cuint
  enum_lsquic_crypto_ver* = distinct cuint
  enum_lsquic_conn_param* = distinct cuint
  enum_LSQUIC_CONN_STATUS* = distinct cuint

borrowCEnumOps(enum_lsquic_version)
borrowCEnumOps(enum_lsquic_hsk_status)
borrowCEnumOps(enum_lsquic_hsi_flag)
borrowCEnumOps(enum_lsquic_logger_timestamp_style)
borrowCEnumOps(enum_lsquic_crypto_ver)
borrowCEnumOps(enum_lsquic_conn_param)
borrowCEnumOps(enum_LSQUIC_CONN_STATUS)

const
  MAX_CID_LEN* = 20
  GQUIC_CID_LEN* = 8

  LSQVER_043* = enum_lsquic_version(0)
  LSQVER_046* = enum_lsquic_version(1)
  LSQVER_050* = enum_lsquic_version(2)
  LSQVER_ID27* = enum_lsquic_version(3)
  LSQVER_ID29* = enum_lsquic_version(4)
  LSQVER_I001* = enum_lsquic_version(5)
  LSQVER_I002* = enum_lsquic_version(6)
  LSQVER_RESVED* = enum_lsquic_version(7)
  N_LSQVER* = enum_lsquic_version(8)
  LSQVER_VERNEG* = enum_lsquic_version(9)

  LSQ_HSK_FAIL* = enum_lsquic_hsk_status(0)
  LSQ_HSK_OK* = enum_lsquic_hsk_status(1)
  LSQ_HSK_RESUMED_OK* = enum_lsquic_hsk_status(2)
  LSQ_HSK_RESUMED_FAIL* = enum_lsquic_hsk_status(3)

  LSQUIC_HSI_HTTP1X* = enum_lsquic_hsi_flag(2)
  LSQUIC_HSI_HASH_NAME* = enum_lsquic_hsi_flag(4)
  LSQUIC_HSI_HASH_NAMEVAL* = enum_lsquic_hsi_flag(8)

  LLTS_NONE* = enum_lsquic_logger_timestamp_style(0)
  LLTS_HHMMSSMS* = enum_lsquic_logger_timestamp_style(1)
  LLTS_YYYYMMDD_HHMMSSMS* = enum_lsquic_logger_timestamp_style(2)
  LLTS_CHROMELIKE* = enum_lsquic_logger_timestamp_style(3)
  LLTS_HHMMSSUS* = enum_lsquic_logger_timestamp_style(4)
  LLTS_YYYYMMDD_HHMMSSUS* = enum_lsquic_logger_timestamp_style(5)
  N_LLTS* = enum_lsquic_logger_timestamp_style(6)

  LSQ_CRY_QUIC* = enum_lsquic_crypto_ver(0)
  LSQ_CRY_TLSv13* = enum_lsquic_crypto_ver(1)

  LSQCP_MAX_PACING_RATE* = enum_lsquic_conn_param(1)
  LSQCP_ENABLE_BW_SAMPLER* = enum_lsquic_conn_param(2)

  LSCONN_ST_HSK_IN_PROGRESS* = enum_LSQUIC_CONN_STATUS(0)
  LSCONN_ST_CONNECTED* = enum_LSQUIC_CONN_STATUS(1)
  LSCONN_ST_HSK_FAILURE* = enum_LSQUIC_CONN_STATUS(2)
  LSCONN_ST_GOING_AWAY* = enum_LSQUIC_CONN_STATUS(3)
  LSCONN_ST_TIMED_OUT* = enum_LSQUIC_CONN_STATUS(4)
  LSCONN_ST_RESET* = enum_LSQUIC_CONN_STATUS(5)
  LSCONN_ST_USER_ABORTED* = enum_LSQUIC_CONN_STATUS(6)
  LSCONN_ST_ERROR* = enum_LSQUIC_CONN_STATUS(7)
  LSCONN_ST_CLOSED* = enum_LSQUIC_CONN_STATUS(8)
  LSCONN_ST_PEER_GOING_AWAY* = enum_LSQUIC_CONN_STATUS(9)
  LSCONN_ST_VERNEG_FAILURE* = enum_LSQUIC_CONN_STATUS(10)

type
  struct_lsquic_cid* {.
    importc: "struct lsquic_cid", header: "lsquic_types.h", bycopy, completeStruct
  .} = object
    buf* {.importc: "buf".}: array[MAX_CID_LEN, uint8]
    len* {.importc: "len".}: uint_fast8_t
    padding: array[3, uint8]

  lsquic_cid_t* = struct_lsquic_cid
