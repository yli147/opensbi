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
#include <sbi_utils/mailbox/rpmi_msgprot.h>

/** SPD TEE ServiceGroups IDs */
enum spd_servicegroup_id {
	SPD_SRVGRP_ID_MIN = 0,
	SPD_SRVGRP_BASE = 0x00001,
	SPD_SRVGRP_ID_MAX_COUNT,
};

/** SPD TEE Base ServiceGroup Service IDs */
enum spd_base_service_id {
	SPD_BASE_SRV_COMMUNICATE = 0x01,
	SPD_BASE_SRV_COMPLETE = 0x02,
};

struct rpxy_spd_data {
	u32 service_group_id;
	int num_services;
	struct sbi_rpxy_service *services;
    struct rpxy_spd_srv *dispatcher;
};

struct abi_entry_vectors {
	unsigned int yield_abi_entry;
	unsigned int fast_abi_entry;
};

struct abi_entry_vectors *entry_vector_table = NULL;

#define ABI_ENTRY_TYPE_FAST			1
#define ABI_ENTRY_TYPE_YIELD		0
#define FUNCID_TYPE_SHIFT			31
#define FUNCID_TYPE_MASK			0x1
#define GET_ABI_ENTRY_TYPE(id)		(((id) >> FUNCID_TYPE_SHIFT) & \
					 FUNCID_TYPE_MASK)

static char spd_domain_name[64];
static unsigned long spd_abi_addr;

int spd_srv_setup(void *fdt, int nodeoff, const struct fdt_match *match)
{
	const fdt32_t *prop_abiaddr;
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

	strncpy(spd_domain_name, fdt_get_name(fdt, offset, NULL),
		sizeof(spd_domain_name));
	spd_domain_name[sizeof(spd_domain_name) - 1] = '\0';

	prop_abiaddr = fdt_getprop(fdt, nodeoff, "opensbi-rpxy-tee-abi-addr", &len);
	if (!prop_abiaddr || len < 4)
		return SBI_EINVAL;
	spd_abi_addr = (unsigned long)fdt32_to_cpu(*prop_abiaddr);

	return 0;
}

static int sbi_ecall_tee_domain_enter(unsigned long entry_point)
{
	int i;
	struct sbi_domain *dom, *tdom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, spd_domain_name)) {
			tdom = dom;
			break;
		}
	}

	if (tdom) {
		sbi_domain_context_set_mepc(tdom, entry_point);
		sbi_domain_context_enter(tdom);
	}
	return 0;
}

static int sbi_ecall_tee_domain_exit(void)
{
	sbi_domain_context_exit();
	return 0;
}

static int spd_srv_handler(struct sbi_rpxy_service_group *grp,
				  struct sbi_rpxy_service *srv,
				  void *tx, u32 tx_len,
				  void *rx, u32 rx_len,
				  unsigned long *ack_len)
{
	int srv_id = srv->id;
	unsigned long *spd_abi_args = (void *)spd_abi_addr;
	unsigned long spd_abi_args_len = tx_len;

	if (SPD_BASE_SRV_COMMUNICATE == srv_id) {
		sbi_memcpy(spd_abi_args, tx, spd_abi_args_len);
		if (GET_ABI_ENTRY_TYPE(*spd_abi_args) == ABI_ENTRY_TYPE_FAST) {
			sbi_ecall_tee_domain_enter((unsigned long)
					&entry_vector_table->fast_abi_entry);
		} else {
			sbi_ecall_tee_domain_enter((unsigned long)
					&entry_vector_table->yield_abi_entry);
		}
	} else if (SPD_BASE_SRV_COMPLETE == srv_id) {
		if(rx && spd_abi_args_len <= rx_len) {
			sbi_memcpy(rx, spd_abi_args, spd_abi_args_len);
			*ack_len = spd_abi_args_len;
		} else {
			entry_vector_table = (struct abi_entry_vectors *) (*spd_abi_args);
		}
		sbi_ecall_tee_domain_exit();
	}

	return 0;
}

static int rpxy_spd_init(void *fdt, int nodeoff,
			  const struct fdt_match *match)
{
	int rc;
	struct sbi_rpxy_service_group *group;
	const struct rpxy_spd_data *data = match->data;

	/* Allocate context for RPXY mbox client */
	group = sbi_zalloc(sizeof(*group));
	if (!group)
		return SBI_ENOMEM;

	/* Setup TEE service group dispatcher */
	rc = spd_srv_setup(fdt, nodeoff, match);
	if (rc) {
		sbi_free(group);
		return 0;
	}

	/* Setup RPXY service group */
	group->protocol_id = RPXY_PROT_SPD_TEE;
	group->transport_id = 0;
	group->service_group_id = data->service_group_id;
	group->max_message_data_len = -1;
	group->num_services = data->num_services;
	group->services = data->services;
	group->send_message = spd_srv_handler;
	/* Register RPXY service group */
	rc = sbi_rpxy_register_service_group(group);
	if (rc) {
		sbi_free(group);
		return rc;
	}

	return 0;
}

static struct sbi_rpxy_service spd_services[] = {
{
	.id = SPD_BASE_SRV_COMMUNICATE,
	.min_tx_len = 0,
	.max_tx_len = 0x1000,
	.min_rx_len = 0,
	.max_rx_len = 0x1000,
},
{
	.id = SPD_BASE_SRV_COMPLETE,
	.min_tx_len = 0,
	.max_tx_len = 0x1000,
	.min_rx_len = 0,
	.max_rx_len = 0x1000,
}
};

static struct rpxy_spd_data spd_data = {
	.service_group_id = SPD_SRVGRP_BASE,
	.num_services = array_size(spd_services),
	.services = spd_services,
};

static const struct fdt_match rpxy_spd_match[] = {
	{ .compatible = "riscv,sbi-rpxy-tee", .data = &spd_data }, 
	{},
};

struct fdt_rpxy fdt_rpxy_spd = {
	.match_table = rpxy_spd_match,
	.init = rpxy_spd_init,
};
