/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Intel Corporation.
 *
 * Authors:
 *   Yong Li <yong.li@intel.com>
 */

#ifndef __SBI_TEST_H__
#define __SBI_TEST_H__

#include <sbi/sbi_list.h>

struct sbi_scratch;

/** Initialize test subsystem */
int sbi_test_init(struct sbi_scratch *scratch);

#endif