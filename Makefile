##############################################################################
#   BSD LICENSE
# 
#   Copyright(c) 2007-2017 Intel Corporation. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without 
#   modification, are permitted provided that the following conditions 
#   are met:
# 
#     * Redistributions of source code must retain the above copyright 
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright 
#       notice, this list of conditions and the following disclaimer in 
#       the documentation and/or other materials provided with the 
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its 
#       contributors may be used to endorse or promote products derived 
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#  version: RWPA_VNF.L.18.02.0-42
##############################################################################

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = rwpa_test_sim

# all source are stored in SRCS-y
SRCS-y := \
	main.c           \
	../rwpa_dp/gre.c \
	../rwpa_dp/parser.c

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

ifdef RWPA_VALIDATION_PLUS
	CFLAGS += -DRWPA_VALIDATION_PLUS
endif

RM_RESULT := $(shell rm -rf rwpa_dp)

include $(RTE_SDK)/mk/rte.extapp.mk

ifndef KW_TEAM_NAME
	KW_TEAM_NAME = R-WPA_TEST_SIM
endif

ifndef KW_URL
	KW_URL = https://klocwork.ir.intel.com:8070
endif

klocwork: clean
	@test -d tables_dir || mkdir -p tables_dir
	kwinject -o $(KW_TEAM_NAME).out make
	kwbuildproject -url $(KW_URL)/$(KW_TEAM_NAME) $(KW_TEAM_NAME).out -f -o tables_dir
	kwadmin -url $(KW_URL)/ load $(KW_TEAM_NAME) tables_dir
