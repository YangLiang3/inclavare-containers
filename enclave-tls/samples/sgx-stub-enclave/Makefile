# samples/sgx-stub-enclave/makefile
#

Topdir ?= $(shell readlink -f ../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/openssl_env.mk

App_Name := sgx_stub
include $(Topdir)/rules/sgx_env.mk

enclave_tls_sgx_enclave := $(Build_Libdir)/libenclave_tls_sgx.a
$(Build_Libdir)/libenclave_tls_sgx.a: FORCE
	make -C $(Enclave_Tls_Srcdir)/sgx $@

Enclave_Static_Lib := $(enclave_tls_sgx_enclave) 
include $(Topdir)/rules/sgx_rules.mk

install:
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(Build_Bindir)/$(App_Name)_enclave.signed.so $(Enclave_Tls_Bindir)

uninstall:
	@rm -f $(Enclave_Tls_Bindir)/$(App_Name)_enclave.signed.so

include $(Topdir)/rules/build_rules.mk
