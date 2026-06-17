/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * Re-select LSQUIC logging macros for each source file included in a unity
 * translation unit.  LSQUIC normally gets a fresh preprocessor environment per
 * C file; unity builds do not.
 */

#ifndef LSQUIC_UNIT_LOG
#error "LSQUIC_UNIT_LOG must be defined to 0, 1, 2, or 3"
#endif

#include "../libs/lsquic/include/lsquic_types.h"
struct lsquic_conn;
#include "../libs/lsquic/src/liblsquic/lsquic_logger.h"

#undef LSQ_LOG
#undef LSQ_LOGC
#undef LSQ_DEBUG
#undef LSQ_WARN
#undef LSQ_ALERT
#undef LSQ_CRIT
#undef LSQ_ERROR
#undef LSQ_NOTICE
#undef LSQ_INFO
#undef LSQ_EMERG
#undef LSQ_DEBUGC
#undef LSQ_WARNC
#undef LSQ_ALERTC
#undef LSQ_CRITC
#undef LSQ_ERRORC
#undef LSQ_NOTICEC
#undef LSQ_INFOC

#if LSQUIC_UNIT_LOG == 0
#ifndef LSQUIC_LOGGER_MODULE
#define LSQUIC_LOGGER_MODULE LSQLM_NOMODULE
#endif
#define LSQ_LOG LSQ_LOG0
#define LSQ_LOGC LSQ_LOG0C
#elif LSQUIC_UNIT_LOG == 1
#define LSQ_LOG LSQ_LOG1
#define LSQ_LOGC LSQ_LOG1C
#elif LSQUIC_UNIT_LOG == 2
#define LSQ_LOG LSQ_LOG2
#define LSQ_LOGC LSQ_LOG2C
#elif LSQUIC_UNIT_LOG == 3
#define LSQ_LOG LSQ_LOG3
#else
#error "LSQUIC_UNIT_LOG must be defined to 0, 1, 2, or 3"
#endif

#define LSQ_DEBUG(...)   LSQ_LOG(LSQ_LOG_DEBUG,  __VA_ARGS__)
#define LSQ_WARN(...)    LSQ_LOG(LSQ_LOG_WARN,   __VA_ARGS__)
#define LSQ_ALERT(...)   LSQ_LOG(LSQ_LOG_ALERT,  __VA_ARGS__)
#define LSQ_CRIT(...)    LSQ_LOG(LSQ_LOG_CRIT,   __VA_ARGS__)
#define LSQ_ERROR(...)   LSQ_LOG(LSQ_LOG_ERROR,  __VA_ARGS__)
#define LSQ_NOTICE(...)  LSQ_LOG(LSQ_LOG_NOTICE, __VA_ARGS__)
#define LSQ_INFO(...)    LSQ_LOG(LSQ_LOG_INFO,   __VA_ARGS__)
#define LSQ_EMERG(...)   LSQ_LOG(LSQ_LOG_EMERG,  __VA_ARGS__)

#ifdef LSQ_LOGC
#define LSQ_DEBUGC(...)  LSQ_LOGC(LSQ_LOG_DEBUG,  __VA_ARGS__)
#define LSQ_WARNC(...)   LSQ_LOGC(LSQ_LOG_WARN,   __VA_ARGS__)
#define LSQ_ALERTC(...)  LSQ_LOGC(LSQ_LOG_ALERT,  __VA_ARGS__)
#define LSQ_CRITC(...)   LSQ_LOGC(LSQ_LOG_CRIT,   __VA_ARGS__)
#define LSQ_ERRORC(...)  LSQ_LOGC(LSQ_LOG_ERROR,  __VA_ARGS__)
#define LSQ_NOTICEC(...) LSQ_LOGC(LSQ_LOG_NOTICE, __VA_ARGS__)
#define LSQ_INFOC(...)   LSQ_LOGC(LSQ_LOG_INFO,   __VA_ARGS__)
#endif

#undef LSQUIC_UNIT_LOG
