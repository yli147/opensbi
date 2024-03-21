/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Intel Corporation. All rights reserved.
 */

#include <sbi/sbi_error.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_rpxy.h>
#include <libfdt.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/rpxy/fdt_rpxy.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_console.h>

#define MM_VERSION_MAJOR        1
#define MM_VERSION_MAJOR_SHIFT  16
#define MM_VERSION_MAJOR_MASK   0x7FFF
#define MM_VERSION_MINOR        0
#define MM_VERSION_MINOR_SHIFT  0
#define MM_VERSION_MINOR_MASK   0xFFFF
#define MM_VERSION_FORM(major, minor) ((major << MM_VERSION_MAJOR_SHIFT) | \
                                       (minor))
#define MM_VERSION_COMPILED     MM_VERSION_FORM(MM_VERSION_MAJOR, \
                                                MM_VERSION_MINOR)

/** STMM ServiceGroups IDs */
enum rpmi_mm_servicegroup_id {
	RPMI_SRVGRP_ID_MIN = 0,
	RPMI_SRVGRP_MM = 0x000A,
	RPMI_SRVGRP_ID_MAX_COUNT,
};

/** STMM ServiceGroup Service IDs */
enum rpmi_mm_service_id {
	RPMI_MM_SRV_VERSION = 0x01,
	RPMI_MM_SRV_COMMUNICATE = 0x02,
	RPMI_MM_SRV_COMPLETE = 0x03,
};

struct efi_param_header {
	uint8_t type;	 /* type of the structure */
	uint8_t version; /* version of this structure */
	uint16_t size;	 /* size of this structure in bytes */
	uint32_t attr;	 /* attributes: unused bits SBZ */
};

struct efi_secure_partition_cpu_info {
	uint64_t mpidr;
	uint32_t linear_id;
	uint32_t flags;
};

struct efi_secure_partition_boot_info {
	struct efi_param_header header;
	uint64_t mm_mem_base;
	uint64_t mm_mem_limit;
	uint64_t mm_image_base;
	uint64_t mm_stack_base;
	uint64_t mm_heap_base;
	uint64_t mm_ns_comm_buf_base;
	uint64_t mm_shared_buf_base;
	uint64_t mm_image_size;
	uint64_t mm_pcpu_stack_size;
	uint64_t mm_heap_size;
	uint64_t mm_ns_comm_buf_size;
	uint64_t mm_shared_buf_size;
	uint32_t num_mem_region;
	uint32_t num_cpus;
	struct efi_secure_partition_cpu_info *cpu_info;
};

struct efi_secure_shared_buffer {
	struct efi_secure_partition_boot_info mm_payload_boot_info;
	struct efi_secure_partition_cpu_info mm_cpu_info[1];
};

static void mm_setup_boot_info(uint64_t a1)
{
	struct efi_secure_shared_buffer *mm_shared_buffer = (void *)a1;
	struct efi_secure_partition_boot_info *mm_boot_info =
		&mm_shared_buffer->mm_payload_boot_info;
	mm_boot_info->header.version	= 0x01;
	mm_boot_info->mm_mem_base	= 0x80C00000;
	mm_boot_info->mm_mem_limit	= 0x82000000;
	mm_boot_info->mm_image_base	= 0x80C00000;
	/* Stack from (mm_heap_base + mm_heap_size) to mm_shared_buf_base */
	mm_boot_info->mm_stack_base	= 0x81D7FFFF;
	mm_boot_info->mm_heap_base	= 0x80F00000;
	//mm_boot_info->mm_ns_comm_buf_base	= 0xFFE00000;
	mm_boot_info->mm_ns_comm_buf_base	= 0x81E00000;
	mm_boot_info->mm_shared_buf_base	= 0x81D80000;
	mm_boot_info->mm_image_size	= 0x300000;
	mm_boot_info->mm_pcpu_stack_size	= 0x10000;
	mm_boot_info->mm_heap_size			= 0x800000;
	mm_boot_info->mm_ns_comm_buf_size	= 0x200000;
	mm_boot_info->mm_shared_buf_size	= 0x80000;
	mm_boot_info->num_mem_region		= 0x6;
	mm_boot_info->num_cpus				= 1;
	mm_shared_buffer->mm_cpu_info[0].linear_id = 0;
	mm_shared_buffer->mm_cpu_info[0].flags	   = 0;
	mm_boot_info->cpu_info = mm_shared_buffer->mm_cpu_info;
}

struct rpxy_mm_data {
	u32 service_group_id;
	int num_services;
	struct sbi_rpxy_service *services;
};

static char mm_domain_name[64];

static struct sbi_domain *__get_tdomain(void)
{
	int i;
	struct sbi_domain *dom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, mm_domain_name)) {
			return dom;
		}
	}

	return NULL;
}

static struct sbi_domain *__get_udomain(void)
{
	int i;
	struct sbi_domain *dom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, "untrusted-domain")) {
			return dom;
		}
	}

	return NULL;
}


int mm_srv_setup(void *fdt, int nodeoff, const struct fdt_match *match)
{
	const u32 *prop_instance;
	int len, offset;

	prop_instance = fdt_getprop(fdt, nodeoff, "opensbi-domain-instance", &len);
	if (!prop_instance || len < 4) {
		return SBI_EINVAL;
	}
	offset = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*prop_instance));
	if (offset < 0) {
		return SBI_EINVAL;
	}

	strncpy(mm_domain_name, fdt_get_name(fdt, offset, NULL),
		sizeof(mm_domain_name));
	mm_domain_name[sizeof(mm_domain_name) - 1] = '\0';
	
	mm_setup_boot_info(__get_tdomain()->next_arg1);

	return 0;
}

static int sbi_ecall_mm_domain_enter(void)
{
	int i;
	struct sbi_domain *dom, *tdom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, mm_domain_name)) {
			tdom = dom;
			break;
		}
	}

	if (tdom) {
		sbi_domain_context_enter(tdom);
	}
	return 0;
}

static int sbi_ecall_mm_domain_exit(void)
{
	sbi_domain_context_exit();
	return 0;
}

static int mm_srv_handler(struct sbi_rpxy_service_group *grp,
				  struct sbi_rpxy_service *srv,
				  void *tx, u32 tx_len,
				  void *rx, u32 rx_len,
				  unsigned long *ack_len)
{
	int srv_id = srv->id;
	struct rpxy_state *rs;

	if (RPMI_MM_SRV_VERSION == srv_id) {
		*((uint32_t *)rx) = MM_VERSION_COMPILED;
	} else if (RPMI_MM_SRV_COMMUNICATE == srv_id) {
		/* Get per-hart RPXY share memory with tdomain */
		rs = sbi_hartindex_to_domain_rs(
			sbi_hartid_to_hartindex(current_hartid()), __get_tdomain());
		if (rs->shmem_addr) {
			sbi_memcpy((void *)rs->shmem_addr, tx, tx_len);
		}
		
		sbi_ecall_mm_domain_enter();
	} else if (RPMI_MM_SRV_COMPLETE == srv_id) {
		/* Get per-hart RPXY share memory with udomain */
		rs = sbi_hartindex_to_domain_rs(
			sbi_hartid_to_hartindex(current_hartid()), __get_udomain());
		if (rs->shmem_addr) {
			sbi_memcpy((void *)rs->shmem_addr, tx, tx_len);
		} 
		sbi_ecall_mm_domain_exit();
	}

	return 0;
}

static int rpxy_mm_init(void *fdt, int nodeoff,
			  const struct fdt_match *match)
{
	int rc;
	struct sbi_rpxy_service_group *group;
	const struct rpxy_mm_data *data = match->data;
	/* Allocate context for RPXY mbox client */
	group = sbi_zalloc(sizeof(*group));
	if (!group)
		return SBI_ENOMEM;

	/* Setup MM service group dispatcher */
	rc = mm_srv_setup(fdt, nodeoff, match);
	if (rc) {
		sbi_free(group);
		return 0;
	}

	/* Setup RPXY service group */
	group->transport_id = (RPXY_TRANS_PROT_RPMI << RPXY_TRANS_PROT_SHIFT)
		& RPXY_TRANS_PROT_MASK;
	group->service_group_id = data->service_group_id;
	group->max_message_data_len = -1;
	group->num_services = data->num_services;
	group->services = data->services;
	group->send_message = mm_srv_handler;
	/* Register RPXY service group */
	rc = sbi_rpxy_register_service_group(group);
	if (rc) {
		sbi_free(group);
		return rc;
	}

	return 0;
}

static struct sbi_rpxy_service mm_services[] = {
{
	.id = RPMI_MM_SRV_VERSION,
	.min_tx_len = 0,
	.max_tx_len = 0,
	.min_rx_len = sizeof(u32),
	.max_rx_len = sizeof(u32),
},
{
	.id = RPMI_MM_SRV_COMMUNICATE,
	.min_tx_len = 0,
	.max_tx_len = 0x8000,
	.min_rx_len = 0,
	.max_rx_len = 0x8000,
},
{
	.id = RPMI_MM_SRV_COMPLETE,
	.min_tx_len = 0,
	.max_tx_len = 0x8000,
	.min_rx_len = 0,
	.max_rx_len = 0x8000,
},
};

static struct rpxy_mm_data mm_data = {
	.service_group_id = RPMI_SRVGRP_MM,
	.num_services = array_size(mm_services),
	.services = mm_services,
};

static const struct fdt_match rpxy_mm_match[] = {
	{ .compatible = "riscv,sbi-rpxy-mm", .data = &mm_data }, 
	{},
};

struct fdt_rpxy fdt_rpxy_mm = {
	.match_table = rpxy_mm_match,
	.init = rpxy_mm_init,
};
