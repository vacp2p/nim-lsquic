/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Keep LSQUIC source files independent when they are included into a unity
 * translation unit.  These macros are file-local in the original build.
 */

#undef LSQUIC_LOGGER_MODULE
#undef LSQUIC_LOG_CONN_ID
#undef LSQUIC_LOG_STREAM_ID
#undef LSQUIC_LOG_PACKET_IN
#undef LSQUIC_LOG_PACKET_OUT
#undef MIN
#undef MAX
#undef STATIC
#undef FALL_THROUGH
#undef DATA
#undef RETURN_ERROR
#undef RIC
#undef DELB
#undef WINR
#undef WONR
#undef DUPL
#undef SDTC
