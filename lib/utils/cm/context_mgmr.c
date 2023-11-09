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
#include <sbi/sbi_scratch.h>
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

/** Assembly helpers */
uint64_t secure_context_enter(struct sbi_trap_regs *regs, uintptr_t *c_rt_ctx);
void secure_context_exit(uint64_t c_rt_ctx, uint64_t ret);

static cpu_context_t cpu_secure_context;

/*
 * Save current CSR registers context and restore original context.
 */
static void save_restore_csr_context(cpu_context_t *ctx)
{
	uint64_t tmp;

	tmp = ctx->csr_stvec;
	ctx->csr_stvec = csr_read(CSR_STVEC);
	csr_write(CSR_STVEC, tmp);

	tmp = ctx->csr_sscratch;
	ctx->csr_sscratch = csr_read(CSR_SSCRATCH);
	csr_write(CSR_SSCRATCH, tmp);

	tmp = ctx->csr_sie;
	ctx->csr_sie = csr_read(CSR_SIE);
	csr_write(CSR_SIE, tmp);

	tmp = ctx->csr_satp;
	ctx->csr_satp = csr_read(CSR_SATP);
	csr_write(CSR_SATP, tmp);
}

static void pmp_disable_all(struct sbi_scratch *scratch)
{
	unsigned int pmp_count = sbi_hart_pmp_count(scratch);
	for (int i = 0; i < pmp_count; i++) {
		pmp_disable(i);
	}
}

int cm_exit_to_secure(void)
{
	uint64_t rc;
	cpu_context_t *ctx = &cpu_secure_context;
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();

	/* Switch to SP domain*/
	pmp_disable_all(scratch);
	//spm_sp_pmp_configure(scratch, ctx->dom);

	/* Save current CSR context and setup Secure Partition's CSR context */
	save_restore_csr_context(ctx);

	/* Enter Secure Partition */
	rc = secure_context_enter(&ctx->regs, &ctx->c_rt_ctx);

	/* Restore original domain */
	pmp_disable_all(scratch);
	sbi_hart_pmp_configure(scratch);
	return rc;
}

void cm_entry_from_secure(int rc)
{
	cpu_context_t *ctx = &cpu_secure_context;
	/* Save secure state */
	uintptr_t *prev = (uintptr_t *)&ctx->regs;
	uintptr_t *trap_regs = (uintptr_t *)(csr_read(CSR_MSCRATCH) - SBI_TRAP_REGS_SIZE);
	for (int i = 0; i < SBI_TRAP_REGS_SIZE / __SIZEOF_POINTER__; ++i) {
		prev[i] = trap_regs[i];
	}

	/* Set SBI Err and Ret */
	ctx->regs.a0 = SBI_SUCCESS;
	ctx->regs.a1 = 0;

	/* Set MEPC to next instruction */
	ctx->regs.mepc = ctx->regs.mepc + 4;

	/* Save Secure Partition's CSR context and restore original CSR context */
	save_restore_csr_context(ctx);

	/*
	 * The SPM must have initiated the original request through a
	 * synchronous entry into the secure partition. Jump back to the
	 * original C runtime context with the value of rc in a0;
	 */
	secure_context_exit(ctx->c_rt_ctx, rc);
}

