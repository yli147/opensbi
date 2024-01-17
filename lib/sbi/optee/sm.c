//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm.h"
#include "pmp.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_ecall.h>
#include <opteed_private.h>

extern struct sbi_ecall_extension ecall_optee;
static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;
int tee_region_id = 0, shm_region_id = 0;
int plicm_region_id = 0,timer_region_id = 0;

int osm_pmp_set(uint8_t perm)
{
	/* in case of OSM, PMP cfg is exactly the opposite.*/
	return pmp_set_keystone(os_region_id, perm);
}

int teem_pmp_set(uint8_t perm)
{
	/* in case of TEE, PMP cfg is exactly the opposite.*/
	return pmp_set_keystone(tee_region_id, perm);
}

int shm_pmp_set(uint8_t perm)
{
	/* in case of TEE SHARE MEM, PMP cfg is exactly the opposite.*/
	return pmp_set_keystone(shm_region_id, perm);
}

int plicm_pmp_set(uint8_t perm)
{
	/* in case of TEE SHARE MEM, PMP cfg is exactly the opposite.*/
	return pmp_set_keystone(plicm_region_id, perm);
}

int timerm_pmp_set(uint8_t perm)
{
	/* in case of TEE SHARE MEM, PMP cfg is exactly the opposite.*/
	return pmp_set_keystone(timer_region_id, perm);
}

int smm_init()
{
	int region = -1;
	int ret	   = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP,
					    &region, 0);
	if (ret)
		return -1;

	return region;
}

int osm_init()
{
	int region = -1;
	int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
	if (ret)
		return -1;

	return region;
}

int teem_init()
{
	int region = -1;
	int ret = pmp_region_init_atomic(OPTEE_TZDRAM_BASE, OPTEE_TZDRAM_SIZE,
					 PMP_PRI_ANY, &region, 0);
	if (ret)
		return -1;

	return region;
}

int shm_init()
{
	int region = -1;
	int ret	   = pmp_region_init_atomic(OPTEE_SHMEM_BASE, OPTEE_SHMEM_SIZE,
					    PMP_PRI_BOTTOM, &region, 0);
	if (ret)
		return -1;

	return region;
}

int plicm_init()
{
	int region = -1;
	int ret = pmp_region_init_atomic(OPTEE_PLIC_BASE, OPTEE_PLIC_SIZE,
					 PMP_PRI_ANY, &region, 0);
	if (ret)
		return -1;

	return region;
}

int timerm_init()
{
	int region = -1;
	int ret = pmp_region_init_atomic(OPTEE_TIMER_BASE, OPTEE_TIMER_SIZE,
					 PMP_PRI_ANY, &region, 0);
	if (ret)
		return -1;

	return region;
}

void sm_init(bool cold_boot)
{
	// initialize SMM
	if (cold_boot) {
		/* only the cold-booting hart will execute these */
		sbi_printf("[SM] Initializing ... hart [%lx]\n",
			   csr_read(mhartid));

		sbi_ecall_register_extension(&ecall_optee);

		sm_region_id = smm_init();
		if (sm_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize SM memory");
			sbi_hart_hang();
		}

		os_region_id = osm_init();
		if (os_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize OS memory");
			sbi_hart_hang();
		}

		tee_region_id = teem_init();
		if (tee_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize TEE memory");
			sbi_hart_hang();
		}

		shm_region_id = shm_init();
		if (shm_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize TEE SHARE memory");
			sbi_hart_hang();
		}

		plicm_region_id = plicm_init();
		if (plicm_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize PLIC memory");
			sbi_hart_hang();
		}
		timer_region_id = timerm_init();
		if (timer_region_id < 0) {
			sbi_printf(
				"[SM] intolerable error - failed to initialize PLIC memory");
			sbi_hart_hang();
		}

		sm_init_done = 1;
		mb();
	}

	/* wait until cold-boot hart finishes */
	while (!sm_init_done) {
		mb();
	}

	/* below are executed by all harts */
	pmp_init();
	pmp_set_keystone(sm_region_id, PMP_NO_PERM);
	pmp_set_keystone(os_region_id, PMP_ALL_PERM);
	pmp_set_keystone(tee_region_id, PMP_NO_PERM);

	if (cold_boot) {
		opteed_init();
	}
	sbi_printf("[SM] security monitor has been initialized!\n");

	return;
}

/*
 * plic_secure_int fill with  hartid and secure interrupt number,
 * secure int format as (hartid | intr), hartid and intr are 16bit width.
 * plic_secure_int[0] indicate total secure interrupt counter
 */
#define MAX_SECURE_INT	16

/* high16:cpu id,low16:interrupt number */
static unsigned int plic_secure_int[MAX_SECURE_INT + 1];

unsigned int *plic_get_sec_interrupt_tab(void)
{
	return plic_secure_int;
}

int plic_is_sec_interrupt(int intr)
{
	int i;

	for(i = 0; i < (plic_secure_int[0] & 0xFFFF); i++)
		if (intr == (plic_secure_int[i+1] & 0xFFFF))
			return true;
	return false;
}

int plic_register_sec_interrupt(unsigned int intr)
{
	unsigned long offset;
	int cnt;
	int hartid;
	int i;

	hartid = current_hartid();
	cnt = plic_secure_int[0] & 0xFFFF;
	if (cnt > MAX_SECURE_INT)
		return false;
	/* check if intr have been registered */
	for (i = 0 ; i < cnt ; i++)
		if ((plic_secure_int[i + 1] & 0xFFFF) == intr)
			return true;
	/* register a new secure interrupt */
	plic_secure_int[cnt + 1] = (hartid << 16) | intr;
	/* update secure total number */
	plic_secure_int[0] = (0xFFFF << 16) | (cnt + 1);

	/* set priotity */
	offset = 4 * intr;
	*(volatile unsigned int *)(OPTEE_PLIC_BASE + offset) = 1;

	/* set Priority threshold for current M/S context */
	offset = 0x200000 + 0x2000 * hartid;
	*(volatile unsigned int *)(OPTEE_PLIC_BASE + offset) = 0;
	offset = 0x201000 + 0x2000 * hartid;
	*(volatile unsigned int *)(OPTEE_PLIC_BASE + offset) = 0;

	/*
	 * set enable mode to S mode, because this function
	 * only should be called by OPTEE
	 */
	offset = 0x2080 + 0x100 * hartid + 4 * (intr >> 5);
	*(volatile unsigned int *)(OPTEE_PLIC_BASE + offset) |=
		(1 << (intr - (intr >> 5) * 32));

	return true;
}
