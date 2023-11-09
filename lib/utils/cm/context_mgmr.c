/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) IPADS@SJTU 2023. All rights reserved.
 */

#include <libfdt.h>
#include <libfdt_env.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_error.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_console.h>
#include <sbi_utils/cm/context_mgmr.h>

#define SECURE          UL(0x0)
#define NON_SECURE      UL(0x1)
#define NUM_STATES      UL(0x2)
#define sec_state_is_valid(s)	(((s) == SECURE) ||	\
				((s) == NON_SECURE))

typedef struct cpu_context {
	/** secure context for all general registers */
	struct sbi_trap_regs regs;
	/** secure context for S mode CSR registers */
	uint64_t csr_stvec;
	uint64_t csr_sscratch;
	uint64_t csr_sie;
	uint64_t csr_satp;
	/**
	 * stack address to restore C runtime context from after
	 * returning from a synchronous entry into Secure Partition.
	 */
	uintptr_t c_rt_ctx;
} cpu_context_t;

static void *cpu_context_ptr[NUM_STATES];

static void *cm_get_context(uint32_t security_state)
{
	/* assert(sec_state_is_valid(security_state)); */
	return cpu_context_ptr[security_state];
}

static void cm_set_context(void *context, uint32_t security_state)
{
	/* assert(sec_state_is_valid(security_state)); */
	cpu_context_ptr[security_state] = context;
}

int cm_entry_from_secure(void)
{
	cpu_context_t *ctx = cm_get_context(NON_SECURE);
	cm_set_context(ctx, SECURE);
	return 0;
}

int cm_exit_to_secure(void)
{
	cpu_context_t *ctx = cm_get_context(SECURE);
	cm_set_context(ctx, NON_SECURE);
	return 0;
}