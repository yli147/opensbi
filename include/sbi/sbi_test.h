/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ventana Micro Systems Inc.
 *
 * Authors:
 *   Anup Patel <apatel@ventanamicro.com>
 */

#ifndef __SBI_RPXY_H__
#define __SBI_RPXY_H__

#include <sbi/sbi_list.h>

struct sbi_scratch;

/** Initialize test subsystem */
int sbi_test_init(struct sbi_scratch *scratch);

#endif
