/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#include "../libs/lsquic/src/liblsquic/lsquic_packet_in.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 0
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_packet_out.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 2
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_packet_resize.c"
#include "lsquic_unit_cleanup.h"

#include "../libs/lsquic/src/liblsquic/lsquic_parse_common.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 1
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_parse_gquic_common.c"
#include "lsquic_unit_cleanup.h"

#define LSQUIC_UNIT_LOG 0
#include "lsquic_unit_log.h"
#include "../libs/lsquic/src/liblsquic/lsquic_parse_iquic_common.c"
#include "lsquic_unit_cleanup.h"
