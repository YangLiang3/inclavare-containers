/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "openssl.h"

/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */
static const int rsa_pub_3072_raw_der_len = 398;

int etls_memcpy_s(void* dst, size_t dst_size, const void* src, size_t num_bytes)
{
        int result = -1;

        if (dst == NULL)
                ETLS_ERR("null pointer in etls memcpy\n");

        if (src == NULL || dst_size < num_bytes)
        {
                memset(dst, 0, dst_size);
                ETLS_ERR("invalid parameters in etls memcpy\n");
        }

        /* Reject overlapping buffers. */
        if ((dst >= src && ((uint8_t*)dst < (uint8_t*)src + num_bytes)) ||
                        (dst < src && ((uint8_t*)dst + dst_size > (uint8_t*)src)))
        {
                memset(dst, 0, dst_size);
                ETLS_ERR("there is overlapping copy here\n");
        }

        memcpy(dst, src, num_bytes);
        result = 1;
done:

        return result;
}

crypto_wrapper_err_t sha256_rsa_pubkey(unsigned char hash[SHA256_HASH_SIZE], RSA *key)
{
	uint8_t buf[1024];

	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	//int pub_rsa_key_der_len = SetRsaPublicKey(buf, key, sizeof(buf), 0);
	//if (pub_rsa_key_der_len != rsa_pub_3072_raw_der_len)
	//	return -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
        int pub_rsa_key_der_len = i2d_RSA_PUBKEY(key, (unsigned char **)&buf);

        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, buf, pub_rsa_key_der_len);
        SHA256_Final(hash, &sha);

	return CRYPTO_WRAPPER_ERR_NONE;
}

static crypto_wrapper_err_t calc_pubkey_hash(EVP_PKEY *pkey, enclave_tls_cert_algo_t algo,
					     uint8_t *hash)
{
        if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
                return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;

        RSA * rsa;
        rsa = EVP_PKEY_get1_RSA(pkey);

        crypto_wrapper_err_t err = sha256_rsa_pubkey(hash, rsa);
        if (err != CRYPTO_WRAPPER_ERR_NONE)
                return err;

        EVP_PKEY_free(pkey);

        return CRYPTO_WRAPPER_ERR_NONE;
}

#ifdef WOLFSSL_SGX_WRAPPER
int verify_certificate(void *ctx, uint8_t *der_cert, uint32_t der_cert_len)
{
	tls_wrapper_ctx_t *tls_ctx = ctx;
#else
int verify_certificate(int preverify, X509_STORE_CTX *ctx)
{
	//const uint8_t *der_cert;
	//uint32_t der_cert_len;

        X509_STORE *cert_store = X509_STORE_CTX_get0_store(ctx);
	tls_wrapper_ctx_t *tls_ctx = X509_STORE_get_ex_data(cert_store, 0);
        ETLS_DEBUG("verify_certification's tls_ctx is %x\n", tls_ctx);
#endif

        X509 *cert;
        EVP_PKEY *publickey;
        
        cert = X509_STORE_CTX_get_current_cert(ctx);
        if (!cert) {
                ETLS_ERR("failed to get cert from x509 context!\n");
                return -1;
        }

        if (preverify == 0) {
                int err = X509_STORE_CTX_get_error(ctx);
                if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                        ETLS_ERR("This is not a self-signed cert\n");
                        return -1;
                }
        }

        //der_cert_len = i2d_X509(cert, NULL);
        //der_cert = malloc(der_cert_len);
        //if (!der_cert) {
          //      ETLS_ERR("failed to malloc cert in der format\n");
            //    return -1;
       // }

       // i2d_X509(cert, (unsigned char **)&der_cert);

        publickey = X509_get_pubkey(cert);

	/* FIXME: add the ability to define different hash_size acording to cert_algo */
	enclave_tls_cert_algo_t cert_algo = ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256;
	uint32_t hash_size;
	if (cert_algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		hash_size = SHA256_HASH_SIZE;
	else
		return 0;

	uint8_t hash[hash_size];
	calc_pubkey_hash(publickey, cert_algo, hash);

	/* Extract the Enclave TLS certificate extension from the TLS certificate
	 * extension and parse it into evidence
	 */
	attestation_evidence_t evidence;

	if (find_oid(cert, ecdsa_quote_oid) == 1)
		strncpy(evidence.type, "sgx_ecdsa", sizeof(evidence.type));
	else if (find_oid(cert, la_report_oid) == 1)
		strncpy(evidence.type, "sgx_la", sizeof(evidence.type));
	else
		strncpy(evidence.type, "nullverifier", sizeof(evidence.type));
        
	int rc = openssl_extract_x509_extensions(cert, &evidence);
	if (rc != 1) {
		ETLS_ERR("ERROR: extract_cert_extensions %d\n", rc);
		return 0;
	}

	tls_wrapper_err_t err =
		tls_wrapper_verify_certificate_extension(tls_ctx, &evidence, hash, hash_size);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("failed to verify certificate extension %#x\n", err);
		return 0;
	}

	return 1;
}

int find_oid(X509* crt, const unsigned char* oid)
{
        int result = 0;
        const STACK_OF(X509_EXTENSION) * extensions;
        int num_extensions;
        unsigned char oid_buf[128];

        /* Set a pointer to the stack of extensions (possibly NULL) */
        if (!(extensions = X509_get0_extensions(crt)))
                ETLS_DEBUG("failed to get extensions from X509\n");

        /* Get the number of extensions (possibly zero) */
        num_extensions = sk_X509_EXTENSION_num(extensions);

        /* Find the certificate with this OID */
        for (int i = 0; i < num_extensions; i++)
        {
                X509_EXTENSION* ext;
                ASN1_OBJECT* obj;
                unsigned char oid_buf[128];

                /* Get the i-th extension from the stack */
                if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
                        ETLS_ERR("failed to get X509 extension value\n");
                /* Get the OID */
                if (!(obj = X509_EXTENSION_get_object(ext)))
                        ETLS_ERR("failed to get the OID from object\n");

                /* Get the string name of the OID */
                if (!OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1))
                        ETLS_ERR("failed to get string name of the oid\n");

                /* If found then get the data */
                if (strcmp(oid_buf, oid) == 0)
                        return 1;
        }

        return 0;
}

int openssl_extract_x509_extensions(X509* crt, attestation_evidence_t *evidence)
{

        if (!strcmp(evidence->type, "sgx_epid")) {
		int rc = find_extension_from_cert(crt, ias_response_body_oid,
						evidence->epid.ias_report,
						&evidence->epid.ias_report_len);
		if (rc != 1)
			return rc;

		rc = find_extension_from_cert(crt, ias_root_cert_oid,
					    evidence->epid.ias_sign_ca_cert,
					    &evidence->epid.ias_sign_ca_cert_len);
		if (rc != 1)
			return rc;

		rc = find_extension_from_cert(crt, ias_leaf_cert_oid,
					    evidence->epid.ias_sign_cert,
					    &evidence->epid.ias_sign_cert_len);
		if (rc != 1)
			return rc;

		rc = find_extension_from_cert(crt, ias_report_signature_oid,
					    evidence->epid.ias_report_signature,
					    &evidence->epid.ias_report_signature_len);
		return rc;
	} else if (!strcmp(evidence->type, "sgx_ecdsa")) {
		return find_extension_from_cert(crt, ecdsa_quote_oid,
					      evidence->ecdsa.quote, &evidence->ecdsa.quote_len);
	} else if (!strcmp(evidence->type, "sgx_la")) {
		return find_extension_from_cert(crt, la_report_oid,
					      evidence->la.report, &evidence->la.report_len);
	}

	return 1;
}

int find_extension_from_cert(X509* cert, const char* oid, uint8_t* data, size_t* size)
{
        int result = 0;
        const STACK_OF(X509_EXTENSION) * extensions;
        int num_extensions;

        /* Set a pointer to the stack of extensions (possibly NULL) */
        if (!(extensions = X509_get0_extensions(cert)))
                ETLS_ERR("failed to get extensions from X509\n");

        /* Get the number of extensions (possibly zero) */
        num_extensions = sk_X509_EXTENSION_num(extensions);

        /* Find the certificate with this OID */
        for (int i = 0; i < num_extensions; i++)
        {
                X509_EXTENSION* ext;
                ASN1_OBJECT* obj;
                unsigned char oid_buf[128];

                /* Get the i-th extension from the stack */
                if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
                        ETLS_ERR("failed to get X509 extension value\n");
                /* Get the OID */
                if (!(obj = X509_EXTENSION_get_object(ext)))
                        ETLS_ERR("failed to get the OID from object\n");

                /* Get the string name of the OID */
                if (!OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1))
                        ETLS_ERR("failed to get string name of the oid\n");

                /* If found then get the data */
                if (strcmp(oid_buf, oid) == 0)
                {
                        ASN1_OCTET_STRING* str;

                        /* Get the data from the extension */
                        if (!(str = X509_EXTENSION_get_data(ext)))
                                ETLS_ERR("failed to get data from teh extension\n");

                        /* If the caller's buffer is too small, raise error */
                        if ((size_t)str->length > *size)
                        {
                                *size = (size_t)str->length;

                                if (data)
                                        ETLS_DEBUG("buffer is too small\n");
                        }
                        if (data)
                        {
                                etls_memcpy_s(data, *size, str->data, (size_t)str->length);
                                *size = (size_t)str->length;
                                result = 1;
                                goto done;
                        }
                }
        }

        result = -1;

done:
        return result;
}
