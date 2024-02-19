/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#ifndef __FDT_RPXY_H__
#define __FDT_RPXY_H__

#include <sbi/sbi_types.h>

#ifdef CONFIG_FDT_RPXY

/** RPMI ServiceGroups IDs */
enum rpxy_protocol_id {
	RPXY_PROT_RPMI = 0,
	RPXY_PROT_SPD_TEE = 0x00001,
	RPXY_PROT_ID_MAX_COUNT,
};

struct fdt_rpxy {
	const struct fdt_match *match_table;
	int (*init)(void *fdt, int nodeoff, const struct fdt_match *match);
	void (*exit)(void);
};

int fdt_rpxy_init(void);

#else

static inline int fdt_rpxy_init(void) { return 0; }

#endif

#endif
