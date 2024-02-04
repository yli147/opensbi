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

struct tee_rpxy_dispatcher {
	char tee_domain_name[64];
	char tee_os_name[64];
	unsigned long tee_abi_addr;
	int (*setup)(void *fdt, int nodeoff,
			const struct fdt_match *match);
	int (*dispatch)(struct sbi_rpxy_service_group *grp, 
            struct sbi_rpxy_service *srv,
			void *tx, u32 tx_len,
			void *rx, u32 rx_len,
			unsigned long *ack_len);
} tee_dispatcher;

int tee_setup(void *fdt, int nodeoff, const struct fdt_match *match)
{
	const fdt32_t *prop_abiaddr;
	const char *prop_name;
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

	strncpy(tee_dispatcher.tee_domain_name, fdt_get_name(fdt, offset, NULL),
		sizeof(tee_dispatcher.tee_domain_name));
	tee_dispatcher.tee_domain_name[sizeof(tee_dispatcher.tee_domain_name) - 1] = '\0';

	prop_abiaddr = fdt_getprop(fdt, nodeoff, "opensbi-rpxy-tee-abi-addr", &len);
	if (!prop_abiaddr || len < 4)
		return SBI_EINVAL;
	tee_dispatcher.tee_abi_addr = (unsigned long)fdt32_to_cpu(*prop_abiaddr);

	prop_name = fdt_getprop(fdt, nodeoff, "opensbi-rpxy-tee-name", &len);
	if (!prop_name || len < 4) {
		return SBI_EINVAL;
	}
	sbi_memset(tee_dispatcher.tee_os_name, 0, sizeof(tee_dispatcher.tee_os_name));
	strncpy(tee_dispatcher.tee_os_name, (const char *)prop_name,
		sizeof(tee_dispatcher.tee_os_name));
	return 0;
}

static int sbi_ecall_tee_domain_enter(void)
{
	int i;
	struct sbi_domain *dom, *tdom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, tee_dispatcher.tee_domain_name)) {
			tdom = dom;
			break;
		}
	}

	if (tdom)
		sbi_domain_context_enter(tdom);
	return 0;
}

static int sbi_ecall_tee_domain_exit(void)
{
	sbi_domain_context_exit();
	return 0;
}

static int tee_dispatch(struct sbi_rpxy_service_group *grp,
				  struct sbi_rpxy_service *srv,
				  void *tx, u32 tx_len,
				  void *rx, u32 rx_len,
				  unsigned long *ack_len)
{
	int srv_id = srv->id;
	unsigned long *tee_abi_args = (void *)tee_dispatcher.tee_abi_addr;
	unsigned long tee_abi_args_len = tx_len;
	if (RPMI_TEE_SRV_TEE_ATTR == srv_id) {
		if(rx && tee_abi_args_len <= rx_len) {
			sbi_memcpy(rx, tee_dispatcher.tee_os_name, sizeof(tee_dispatcher.tee_os_name));
			// More ATTR..
		}
	}else if (RPMI_TEE_SRV_TEE_COMMUNICATE == srv_id) {
		sbi_memcpy(tee_abi_args, tx, tee_abi_args_len);
		sbi_ecall_tee_domain_enter();
	} else if (RPMI_TEE_SRV_TEE_COMPLETE == srv_id) {
		if(rx && tee_abi_args_len <= rx_len) {
			sbi_memcpy(rx, tee_abi_args, tee_abi_args_len);
			*ack_len = tee_abi_args_len;
		}
		sbi_ecall_tee_domain_exit();
	}
	return 0;
}

struct tee_rpxy_dispatcher tee_dispatcher = {
	.setup = tee_setup,
	.dispatch = tee_dispatch,
};

struct rpxy_tee_data {
	u32 service_group_id;
	int num_services;
	struct sbi_rpxy_service *services;
    struct tee_rpxy_dispatcher *srv_dispatcher;
};

static int rpxy_tee_init(void *fdt, int nodeoff,
			  const struct fdt_match *match)
{
	int rc;
	struct sbi_rpxy_service_group *group;
	const struct rpxy_tee_data *data = match->data;
    const struct tee_rpxy_dispatcher *dispatcher = data->srv_dispatcher;
	/* Allocate context for RPXY mbox client */
	group = sbi_zalloc(sizeof(*group));
	if (!group)
		return SBI_ENOMEM;

	/* Setup TEE service group dispatcher */
	rc = dispatcher->setup(fdt, nodeoff, match);
	if (rc) {
		sbi_free(group);
		return 0;
	}

	/* Setup RPXY service group */
	group->transport_id = 0;
	group->service_group_id = data->service_group_id;
	group->max_message_data_len = -1;
	group->num_services = data->num_services;
	group->services = data->services;
	group->send_message = dispatcher->dispatch;
	/* Register RPXY service group */
	rc = sbi_rpxy_register_service_group(group);
	if (rc) {
		sbi_free(group);
		return rc;
	}

	return 0;
}

static struct sbi_rpxy_service tee_services[] = {
{
	.id = RPMI_TEE_SRV_TEE_ATTR,
	.min_tx_len = 0,
	.max_tx_len = 0,
	.min_rx_len = 0,
	.max_rx_len = 0x1000,  // TBD
},
{
	.id = RPMI_TEE_SRV_TEE_COMMUNICATE,
	.min_tx_len = 0,
	.max_tx_len = 0x1000,
	.min_rx_len = 0,
	.max_rx_len = 0x1000,
},
{
	.id = RPMI_TEE_SRV_TEE_COMPLETE,
	.min_tx_len = 0,
	.max_tx_len = 0x1000,
	.min_rx_len = 0,
	.max_rx_len = 0x1000,
},
};

static struct rpxy_tee_data tee_data = {
	.service_group_id = RPMI_SRVGRP_TEE,
	.num_services = array_size(tee_services),
	.services = tee_services,
    .srv_dispatcher = &tee_dispatcher,
};

static const struct fdt_match rpxy_tee_match[] = {
	{ .compatible = "riscv,sbi-rpxy-tee", .data = &tee_data }, 
	{},
};

struct fdt_rpxy fdt_rpxy_tee = {
	.match_table = rpxy_tee_match,
	.init = rpxy_tee_init,
};
