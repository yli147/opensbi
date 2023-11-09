/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Intel Corporation.
 *
 * Authors:
 *   Yong Li <yong.li@intel.com>
 */

#ifndef __FDT_IPI_H__
#define __FDT_IPI_H__

#include <sbi/sbi_types.h>

#define SECURE          UL(0x0)
#define NON_SECURE      UL(0x1)
#define NUM_STATES      UL(0x2)
#define sec_state_is_valid(s)	(((s) == SECURE) ||	\
				((s) == NON_SECURE))

int cm_context_switch(uint32_t security_state);

#endif