#
# Copyright (c) 2018 Western Digital Corporation or its affiliates.
#
# Authors:
#   Anup Patel <anup.patel@wdc.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#

# Compiler flags
platform-cppflags-y =
platform-cflags-y =-mabi=lp64 -march=rv64imafdc -mcmodel=medany
platform-asflags-y =-mabi=lp64 -march=rv64imafdc -mcmodel=medany
platform-ldflags-y =

# Common drivers to enable
PLATFORM_IRQCHIP_PLIC=y
PLATFORM_SYS_CLINT=y

# Blobs to build
FW_TEXT_START=0x80000000
FW_JUMP=n
FW_PAYLOAD=y
FW_PAYLOAD_OFFSET=0x10000
#FW_PAYLOAD_FDT_ADDR=0x80040000
