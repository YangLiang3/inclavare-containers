#include "internal/enclave_quote.h"

enclave_quote_opts_t *enclave_quotes_opts[ENCLAVE_QUOTE_TYPE_MAX];
unsigned int registerd_enclave_quote_nums;

enclave_quote_ctx_t *enclave_quotes_ctx[ENCLAVE_QUOTE_TYPE_MAX];
unsigned int enclave_quote_nums;