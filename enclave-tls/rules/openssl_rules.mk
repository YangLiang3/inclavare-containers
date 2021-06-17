# rules/wolfssl_rule.mk
#
# This file should be gone becasuse libwolfssl* stuffs can be
# available through the installation of enclave-tls SDK.

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Openssl_Root),)
  $(error "Please define Openssl_Root first!")
else
  Openssl_Root := $(Enclave_Tls_Srcdir)/external/openssl
endif

#$(Build_Libdir)/libssl.so:
#	make -C $(Openssl_Root) $@
