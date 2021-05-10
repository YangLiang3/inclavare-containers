/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include "sgx_ecdsa.h"
#include "sgx_stub_u.h"

void getRandomNonce(uint8_t *nonce, uint32_t size)
{
    for(unsigned int i = 0; i < size; i ++)
        nonce[i] = (uint8_t)((rand() % 255) + 1);
}

enclave_quote_err_t sgx_ecdsa_qve_verify_evidence(enclave_quote_ctx_t *ctx,
					      attestation_evidence_t *evidence,
					      uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_quote_err_t err = -ENCLAVE_QUOTE_ERR_UNKNOWN;
	time_t current_time = 0;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	sgx_status_t sgx_ret = SGX_SUCCESS;
	quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qe_report_info_t qve_report_info;
	unsigned char rand_nonce[16];

	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->quote_private;

	sgx_quote3_t *pquote = (sgx_quote3_t *) malloc(8192);
	if (!pquote)
		return -ENCLAVE_QUOTE_ERR_NO_MEM;

	memcpy(pquote, evidence->ecdsa.quote, evidence->ecdsa.quote_len);

	uint32_t quote_size = 436 + pquote->signature_data_len;
	ETLS_DEBUG("quote size is %d, quote signature_data_len is %d\n",
		   quote_size, pquote->signature_data_len);

	ETLS_DEBUG("verify by trusted model.\n");

	getRandomNonce(rand_nonce, 16);
	memcpy(qve_report_info.nonce.rand, rand_nonce, 16);

	sgx_status_t get_target_info_ret;
	sgx_ret = ecall_get_target_info((sgx_enclave_id_t)ecdsa_ctx->eid, &get_target_info_ret,
				&qve_report_info.app_enclave_target_info);
	if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS)
		ETLS_ERR("failed to get target info sgx_ret is. %04x, %04x\n", get_target_info_ret, sgx_ret);
	else
		ETLS_INFO("get target info successfully.\n");

	dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
	if (dcap_ret == SGX_QL_SUCCESS)
		ETLS_INFO("sgx qv setting for enclave load policy succeeds.\n");
	else {
		ETLS_ERR("failed to set enclave load policy by sgx qv: %04x\n", dcap_ret);
		return SGX_ECDSA_ERR_CODE((int)dcap_ret);
	}

	dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS) {
		ETLS_INFO("sgx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *) malloc(supplemental_data_size);
	} else {
		ETLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		return SGX_ECDSA_ERR_CODE((int)dcap_ret);
	}

	current_time = time(NULL);

	dcap_ret = sgx_qv_verify_quote(evidence->ecdsa.quote,
				(uint32_t) quote_size, NULL,
				current_time,
				&collateral_expiration_status,
				&quote_verification_result,
				&qve_report_info,
				supplemental_data_size,
				p_supplemental_data);
	if (dcap_ret == SGX_QL_SUCCESS)
		ETLS_INFO("sgx qv verifies quote successfully.\n");
	else {
		ETLS_ERR("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		return SGX_ECDSA_ERR_CODE((int)dcap_ret);
	}

	sgx_isv_svn_t qve_isvsvn_threshold = 3;

	sgx_ret = sgx_tvl_verify_qve_report_and_identity((sgx_enclave_id_t)ecdsa_ctx->eid,
			&verify_qveid_ret,
			evidence->ecdsa.
			quote,
			(uint32_t)
			quote_size,
			&qve_report_info,
			current_time,
			collateral_expiration_status,
			quote_verification_result,
			p_supplemental_data,
			supplemental_data_size,
			qve_isvsvn_threshold);

	if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != SGX_QL_SUCCESS) {
		ETLS_ERR("verify QvE report and identity failed. %04x\n", verify_qveid_ret);
		return SGX_ECDSA_ERR_CODE((int)verify_qveid_ret);
	}
	else
		ETLS_INFO("verify QvE report and identity successfully.\n");

	if (memcmp(qve_report_info.nonce.rand, rand_nonce, 16) != 0) {
		ETLS_ERR("Nonce during SGX quote verification has been tampered with.\n");
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		ETLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_QUOTE_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		ETLS_WARN("verification completed with Non-terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		ETLS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_ERR_CODE((int)quote_verification_result);
		break;
	}

	free(p_supplemental_data);
	free(pquote);

	return err;
}
