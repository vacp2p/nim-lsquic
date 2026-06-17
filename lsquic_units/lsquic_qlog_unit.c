/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#define LSQUIC_UNIT_LOG 1
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_pr_queue.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_qdec_hdl.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_qenc_hdl.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 1
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_qlog.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_qpack_exp.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_rechist.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_rtt.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_send_ctl.c"
#include "lsquic_unit_cleanup.h"
