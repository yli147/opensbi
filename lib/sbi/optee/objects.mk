#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.
#
# Authors:
#   Anup Patel <anup.patel@wdc.com>
#

# carray-sbi_ecall_exts-$(CONFIG_SBI_ECALL_OPTEE) += ecall_optee
# libsbi-objs-$(CONFIG_SBI_ECALL_OPTEE) += optee/sbi_ecall_optee.o

libsbi-objs-y += optee/context_manage.o
libsbi-objs-y += optee/opteed_common.o
libsbi-objs-y += optee/opteed_helpers.o
libsbi-objs-y += optee/pmp.o
libsbi-objs-y += optee/sbi_ecall_optee.o
libsbi-objs-y += optee/sbi_trap_hack.o
libsbi-objs-y += optee/sm.o
libsbi-objs-y += optee/trap.o
