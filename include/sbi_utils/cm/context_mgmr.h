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

void cm_entry_from_secure(int rc);
int cm_exit_to_secure(void);

#endif