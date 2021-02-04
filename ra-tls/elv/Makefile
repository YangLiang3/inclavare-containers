TOPDIR := $(shell readlink -f ..)

DEBUG ?=
EXTRA_FLAGS ?=

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_ARCH ?= x64
WOLFSSL_ROOT ?= $(shell readlink -f $(TOPDIR)/wolfssl)
SGX_WOLFSSL_LIB ?= $(shell readlink -f $(WOLFSSL_ROOT)/IDE/LINUX-SGX)
SGX_RA_TLS_ROOT ?= $(shell readlink -f $(TOPDIR)/sgx-ra-tls)

PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include

SGX_SDK ?= /opt/intel/sgxsdk
SGX_RA_TLS := $(TOPDIR)/sgx-ra-tls

CC ?= gcc
GO ?= go

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifdef ECDSA
	SGX_DCAP ?= SGXDataCenterAttestationPrimitives
	SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g -ggdb -DSGX_DEBUG
else
	SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL

Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif

App_Include_Paths := $(Wolfssl_Include_Paths) -I$(SGX_SDK)/include -I$(SGX_RA_TLS_ROOT) -I$(INCDIR) $(SGX_DCAP_INC) -I$(shell readlink -f .)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIE -Wno-attributes -Wall -Wno-unused-const-variable $(App_Include_Paths) $(Wolfssl_C_Extra_Flags)

all: elv

Wolfssl_Enclave_u.c Wolfssl_Enclave_u.h: $(SGX_EDGER8R) $(TOPDIR)/stub-enclave/Wolfssl_Enclave.edl
	@$(SGX_EDGER8R) --untrusted $(TOPDIR)/stub-enclave/Wolfssl_Enclave.edl --search-path $(TOPDIR)/stub-enclave --search-path $(SGX_SDK)/include --search-path $(SGX_RA_TLS_ROOT)
	@echo "GEN  =>  $@"

Wolfssl_Enclave_u.o: Wolfssl_Enclave_u.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

CFLAGS += -std=gnu99 $(App_C_Flags) -I$(SGX_RA_TLS) -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS += $(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS += -DSGX_GROUP_OUT_OF_DATE
ifdef ECDSA
	CFLAGS += -DRATLS_ECDSA
endif
ifdef LA
	CFLAGS += -DLA_REPORT
	Wolfssl_C_Objs := Wolfssl_Enclave_u.o App.o
endif


ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif
ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
# glibc-static is required for the static linkage, if elv depends on dynamic library, need to remove '-extldflags -static'
#GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) $(GCFLAGS) $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo" \
        -ldflags "-w -extldflags -static -X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"

elv: $(Wolfssl_C_Objs) ra-tls-client.a $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a
	$(GO_BUILD) -o $@ .

ra-tls-client.a: ra-tls-client.o
	$(AR) rcs "$@" $(filter %.o, $^)

install: elv
	cp -f elv $(BINDIR)

clean:
	rm -f *.o elv ra-tls-client.a Wolfssl_Enclave_u.c Wolfssl_Enclave_u.h

.PHONY: clean install
