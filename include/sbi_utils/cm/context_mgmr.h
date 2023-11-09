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

void cm_context_switch(uint32_t security_state);

#endif