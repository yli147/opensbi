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

int cm_context_switch(uint32_t security_state)
{
	cpu_context_t *ctx = cm_get_context(security_state);
	if (security_state == SECURE) {
		sbi_printf("cm_context_switch to secure world %p\n", ctx);
		cm_set_context(ctx, SECURE);
		#if 0
		struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
		/* Switch to SP domain*/
		pmp_disable_all(scratch);
		spm_sp_pmp_configure(scratch, ctx->dom);
		/* Save current CSR context and setup Secure Partition's CSR context */
		save_restore_csr_context(ctx);

		save_restore_csr_context(ctx);
		context_enter(&ctx->regs, &ctx->c_rt_ctx);

		#endif
	} else {
		sbi_printf("cm_context_switch to normal world %p\n", ctx);
		cm_set_context(ctx, NON_SECURE);
	}
	return 0;
}