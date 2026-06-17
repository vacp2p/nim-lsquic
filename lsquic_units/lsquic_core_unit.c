/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_adaptive_cc.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_alarmset.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_arr.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_attq.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_bbr.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_bw_sampler.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_cfcw.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_chsk_stream.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 0
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_conn.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_crand.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_crt_compress.c"
#include "lsquic_unit_cleanup.h"

#ifndef HAVE_BORINGSSL
#define HAVE_BORINGSSL 1
#endif
#define LSQUIC_UNIT_LOG 1
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_crypto.c"
#include "lsquic_unit_cleanup.h"
#undef HAVE_BORINGSSL
