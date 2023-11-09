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
#include <sbi/sbi_hart.h>
#include <sbi/sbi_console.h>

#define SECURE		UL(0x0)
#define NON_SECURE	UL(0x1)
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

static void *cpu_context_ptr[2];

static void *cm_get_context(uint32_t security_state)
{
	assert(sec_state_is_valid(security_state));
	return cpu_context_ptr[security_state];
}

static void cm_set_context(void *context, uint32_t security_state)
{
	assert(sec_state_is_valid(security_state));
	cpu_context_ptr[security_state] = context;
}

static void spm_sp_pmp_configure(struct sbi_scratch *scratch, struct sbi_domain *dom)
{
	unsigned int pmp_bits, pmp_gran_log2;
	unsigned int pmp_count = sbi_hart_pmp_count(scratch);
	unsigned long pmp_addr_max;

	pmp_gran_log2 = log2roundup(sbi_hart_pmp_granularity(scratch));
	pmp_bits = sbi_hart_pmp_addrbits(scratch) - 1;
	pmp_addr_max = (1UL << pmp_bits) | ((1UL << pmp_bits) - 1);

	spm_sp_oldpmp_configure(scratch, pmp_count,
						pmp_gran_log2, pmp_addr_max, dom);

	__asm__ __volatile__("sfence.vma");
}

void cm_context_switch(uint32_t security_state)
{
	cpu_context_t *ctx = cm_get_context(security_state);
	if (security_state == SECURE) {
		sbi_printf("cm_context_switch to secure world\n");
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
		sbi_printf("cm_context_switch to normal world\n");
	}
	return;
}