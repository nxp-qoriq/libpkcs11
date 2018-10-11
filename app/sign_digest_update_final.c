/*
 * Copyright 2017 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <dlfcn.h>

#include "cryptoki.h"
#include <tee_slot.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include "utils.h"

CK_FUNCTION_LIST  *funcs;

struct getOptValue_t {
	uint32_t main_option;
	uint32_t numOfMainOpt;
	uint8_t *libFileName;
	uint32_t num_of_times;
	uint8_t *label;
	CK_SLOT_ID slot_id;
	CK_KEY_TYPE key_type;
	CK_MECHANISM_TYPE mechanismID;
	uint8_t digest_sign;
	uint8_t *data;
	uint8_t *signed_data;
	uint32_t findCritCount;
};

int do_GetFuncList(void *lib_handle)
{
	int ret = APP_OK;
	CK_RV            rc;
	CK_RV  (*pfoo)();
	uint8_t    *d = NULL;

	d = lib_handle;
	pfoo = (CK_RV (*)())dlsym(d, "C_GetFunctionList");
	if (pfoo == NULL) {
		printf("C_GetFunctionList not found\n");
		ret = APP_CKR_ERR;
		goto out;
	}

	rc = pfoo(&funcs);
	if (rc != CKR_OK) {
		printf("C_GetFunctionList rc=%lu", rc);
		ret = APP_CKR_ERR;
		goto out;
	}
out:
	return ret;
}

int do_Sign_init_update_final(struct getOptValue_t *getOptValue)
{
	int ret =	APP_OK;
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id = getOptValue->slot_id;
	CK_RV             rc = 0;
	CK_SESSION_HANDLE h_session;

	CK_BYTE           false = FALSE;
	CK_ULONG i, j;

	CK_OBJECT_HANDLE  obj;
	CK_ULONG          num_existing_objects;

	CK_ATTRIBUTE ck_attr[3];
	CK_OBJECT_CLASS obj_type;
	CK_KEY_TYPE key_type;
	CK_ULONG count = 0;

	CK_MECHANISM mech = {0};
	CK_BYTE *data = NULL;
	CK_ULONG data_len = 0;
	CK_BYTE *data_array[] = {"111111111111111111111",
				 "222222222222222222222",
				 "333333333333333333333",
				 "444444444444444444444",
				 "555555555555555555555",
				 "666666666666666666666",
				 "777777777777777777777",
				 "888888888888888888888",
				 "999999999999999999999",
				 "aaaaaaaaaaaaaaaaaaaaa",
				};
	CK_BYTE *sig = NULL;
	CK_ULONG sig_bytes = 0;
	FILE *sigFile = NULL;
	uint8_t *label = getOptValue->label;

	if (getOptValue->key_type == UL_UNINTZD) {
		key_type = CKK_RSA;
		printf("No Key Type (-k option missing) is provided.\n");
		printf("Continuing with key type = CKK_RSA\n");
	} else
		key_type = getOptValue->key_type;

	/* Signature always done using Private Key */
	obj_type = CKO_PRIVATE_KEY;

	ck_attr[0].type = CKA_LABEL;
	ck_attr[0].pValue = label;
	ck_attr[0].ulValueLen = strlen(label);

	ck_attr[1].type = CKA_CLASS;
	ck_attr[1].pValue = &obj_type;
	ck_attr[1].ulValueLen = sizeof(CK_OBJECT_CLASS);

	ck_attr[2].type = CKA_KEY_TYPE;
	ck_attr[2].pValue = &key_type;
	ck_attr[2].ulValueLen = sizeof(CK_KEY_TYPE);

	/* create a USER R/W session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK) {
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, 3);
	if (rc != CKR_OK) {
		printf("C_FindObjectsInit handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjects(h_session, &obj, 1, &num_existing_objects);
	if (rc != CKR_OK) {
		printf("C_FindObjects handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		printf("C_FindObjectsFinal handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	if (num_existing_objects) {
		if (num_existing_objects > 1)
			printf("More than 1 Key with same label exists, continuing with first one.\n");
	} else {
		printf("No Object Found to Sign.\n");
		goto cleanup;
	}
	mech.mechanism = getOptValue->mechanismID;

	rc = funcs->C_SignInit(h_session, &mech, obj);
	if (rc != CKR_OK) {
		printf("C_SignInit() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	data = malloc(strlen(getOptValue->data) + strlen(data_array[0]));
	if (data == NULL) {
		printf("Digest Data malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}
	data_len = strlen(getOptValue->data);
	memcpy(data, getOptValue->data, data_len);

	j = 0;
	for (i = 0; i < getOptValue->num_of_times; i++) {
		memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
		printf("Sign Update count[%d].\n", i);
		rc = funcs->C_SignUpdate(h_session, data, strlen(data));
		if (rc != CKR_OK) {
			printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
			ret = APP_CKR_ERR;
			goto cleanup;
		}
		j++;
		j = j % 10;
	}

	rc = funcs->C_SignFinal(h_session, sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Signature size: %lu\n", sig_bytes);
	sig = (CK_BYTE *)malloc(sig_bytes);
	if (sig == NULL) {
		printf("Signature malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	rc = funcs->C_SignFinal(h_session, sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	sigFile = fopen("sig.data", "wb");
	if (sigFile == NULL) {
		printf("Error! opening file");
		ret = APP_FILE_ERR;
		goto cleanup;
	}
	fwrite((void *)sig, 1, sig_bytes, sigFile);
	fclose(sigFile);

	printf("Signature is saved in the file sig.data:\n");

cleanup:
	if (sig)
		free(sig);

	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK)
		ret = APP_CKR_ERR;

	return ret;
}

int do_Digest_init_update_final_Sign(struct getOptValue_t *getOptValue)
{
	int ret =	APP_OK;
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id = getOptValue->slot_id;
	CK_RV             rc = 0;
	CK_SESSION_HANDLE h_session;

	CK_BYTE           false = FALSE;
	CK_ULONG i, j;

	CK_OBJECT_HANDLE  obj;
	CK_ULONG          num_existing_objects;

	CK_ATTRIBUTE ck_attr[3];
	CK_OBJECT_CLASS obj_type;
	CK_KEY_TYPE key_type;
	CK_ULONG count = 0;

	CK_MECHANISM d_mech = {0};
	CK_MECHANISM s_mech = {0};
	CK_BYTE *data = NULL;
	CK_ULONG data_len = 0;
	CK_BYTE *data_array[] = {"111111111111111111111",
				 "222222222222222222222",
				 "333333333333333333333",
				 "444444444444444444444",
				 "555555555555555555555",
				 "666666666666666666666",
				 "777777777777777777777",
				 "888888888888888888888",
				 "999999999999999999999",
				 "aaaaaaaaaaaaaaaaaaaaa",
				};
	CK_BYTE *sig = NULL;
	CK_ULONG sig_bytes = 0;
	CK_BYTE *dig = NULL;
	CK_ULONG dig_bytes = 0;
	FILE *sigFile = NULL;
	uint8_t *label = getOptValue->label;

	if (getOptValue->key_type == UL_UNINTZD) {
		key_type = CKK_RSA;
		printf("No Key Type (-k option missing) is provided.\n");
		printf("Continuing with key type = CKK_RSA\n");
	} else
		key_type = getOptValue->key_type;

	/* Signature always done using Private Key */
	obj_type = CKO_PRIVATE_KEY;

	ck_attr[0].type = CKA_LABEL;
	ck_attr[0].pValue = label;
	ck_attr[0].ulValueLen = strlen(label);

	ck_attr[1].type = CKA_CLASS;
	ck_attr[1].pValue = &obj_type;
	ck_attr[1].ulValueLen = sizeof(CK_OBJECT_CLASS);

	ck_attr[2].type = CKA_KEY_TYPE;
	ck_attr[2].pValue = &key_type;
	ck_attr[2].ulValueLen = sizeof(CK_KEY_TYPE);

	/* create a USER R/W session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK) {
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, 3);
	if (rc != CKR_OK) {
		printf("C_FindObjectsInit handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjects(h_session, &obj, 1, &num_existing_objects);
	if (rc != CKR_OK) {
		printf("C_FindObjects handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		printf("C_FindObjectsFinal handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	if (num_existing_objects) {
		if (num_existing_objects > 1)
			printf("More than 1 Key with same label exists, continuing with first one.\n");
	} else {
		printf("No Object Found to Sign.\n");
		goto cleanup;
	}
	switch (getOptValue->mechanismID) {
	case CKM_MD5_RSA_PKCS:
		d_mech.mechanism = CKM_MD5;
		s_mech.mechanism = CKM_RSA_PKCS;
		break;
	case CKM_SHA1_RSA_PKCS:
		d_mech.mechanism = CKM_SHA_1;
		s_mech.mechanism = CKM_RSA_PKCS;
		break;
	case CKM_SHA256_RSA_PKCS:
		d_mech.mechanism = CKM_SHA256;
		s_mech.mechanism = CKM_RSA_PKCS;
		break;
	case CKM_SHA384_RSA_PKCS:
		d_mech.mechanism = CKM_SHA384;
		s_mech.mechanism = CKM_RSA_PKCS;
		break;
	case CKM_SHA512_RSA_PKCS:
		d_mech.mechanism = CKM_SHA512;
		s_mech.mechanism = CKM_RSA_PKCS;
		break;
	case CKM_ECDSA_SHA1:
		d_mech.mechanism = CKM_SHA_1;
		s_mech.mechanism = CKM_ECDSA;
		break;
	default:
		printf("Unsupported Key Type\n");
		goto cleanup;
	}

	rc = funcs->C_DigestInit(h_session, &d_mech);
	if (rc != CKR_OK) {
		printf("C_DigestInit() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}
	data = malloc(strlen(getOptValue->data) + strlen(data_array[0]));
	if (data == NULL) {
		printf("Malloc failed for Data to be digest.\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}
	data_len = strlen(getOptValue->data);
	memcpy(data, getOptValue->data, data_len);
	j = 0;
	for (i = 0; i < getOptValue->num_of_times; i++) {
		memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
		printf("Digest Update count[%d].\n", i);
		rc = funcs->C_DigestUpdate(h_session, data, strlen(data));
		if (rc != CKR_OK) {
			printf("C_DigestUpdate() rc = %s\n", p11_get_error_string(rc));
			ret = APP_CKR_ERR;
			goto cleanup;
		}
		j++;
		j = j % 10;
	}

	if (data)
		free(data);

	rc = funcs->C_DigestFinal(h_session, dig, &dig_bytes);
	if (rc != CKR_OK) {
		printf("C_DigestFinal() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Digest size: %lu\n", dig_bytes);
	dig = (CK_BYTE *)malloc(dig_bytes);
	if (dig == NULL) {
		printf("Digest malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	rc = funcs->C_DigestFinal(h_session, dig, &dig_bytes);
	if (rc != CKR_OK) {
		printf("C_DigestFinal() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}
	printf("Digest=");
		for (i = 0; i < dig_bytes; i++)
			printf("%x ", dig[i]);
	printf("\n");
	rc = funcs->C_SignInit(h_session, &s_mech, obj);
	if (rc != CKR_OK) {
		printf("C_SignInit() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_Sign(h_session, dig, dig_bytes, sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Signature size: %lu\n", sig_bytes);
	sig = (CK_BYTE *)malloc(sig_bytes);
	if (sig == NULL) {
		printf("Signature malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}
	rc = funcs->C_Sign(h_session, dig, dig_bytes, sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}
	sigFile = fopen("sig.data", "wb");
	if (sigFile == NULL) {
		printf("Error! opening file");
		ret = APP_FILE_ERR;
		goto cleanup;
	}
	fwrite((void *)sig, 1, sig_bytes, sigFile);
	fclose(sigFile);

	printf("Signature is saved in the file sig.data:\n");

cleanup:
	if (sig)
		free(sig);

	if (data)
		free(data);

	if (dig)
		free(dig);

	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK)
		ret = APP_CKR_ERR;

	return ret;
}

int do_Verify(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	uint8_t res = 0;
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id = getOptValue->slot_id;
	CK_ATTRIBUTE ck_attr[3];
	CK_RV             rc = 0;
	CK_SESSION_HANDLE h_session;
	CK_OBJECT_HANDLE  obj;
	CK_ULONG          num_existing_objects;

	CK_MECHANISM mech = {0};
	CK_BYTE data_out[512] = {0};
	CK_ULONG data_out_len = 0;
	CK_BYTE *data = NULL;
	CK_ULONG data_len = 0;
	CK_BYTE *data_array[] = {"111111111111111111111",
				 "222222222222222222222",
				 "333333333333333333333",
				 "444444444444444444444",
				 "555555555555555555555",
				 "666666666666666666666",
				 "777777777777777777777",
				 "888888888888888888888",
				 "999999999999999999999",
				 "aaaaaaaaaaaaaaaaaaaaa",
				};
	RSA *pub_key;
	EC_KEY *ec_pub_key;
	BIGNUM *bn_mod = NULL, *bn_exp = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL;
	CK_ULONG i, j;
	CK_OBJECT_CLASS obj_type;
	uint8_t *label = getOptValue->label;
	CK_KEY_TYPE key_type = 0;

	CK_BYTE hash[64] = {0};
	MD5_CTX c0;
	SHA_CTX c1;
	SHA256_CTX c2;
	SHA512_CTX c3;
	FILE *sigFile = NULL;
	uint8_t ch;
	CK_ULONG sig_bytes = 256;
	CK_BYTE sig[256];
	uint32_t attrCount = 0;
	int ec_curve_nist_id;
	ECDSA_SIG *ec_sig;

	key_type = getOptValue->key_type;

	/* Verify always done using Public Key */
	obj_type = CKO_PUBLIC_KEY;

	sigFile = fopen(getOptValue->signed_data, "rb");
	if (sigFile == NULL) {
		printf("Error! opening file");
		ret = APP_FILE_ERR;
		return ret;
	}

	sig_bytes = fread(sig, 1, sig_bytes, sigFile);
	printf("sig_bytes = %lu\n", sig_bytes);
	fclose(sigFile);

	ck_attr[0].type = CKA_LABEL;
	ck_attr[0].pValue = label;
	ck_attr[0].ulValueLen = strlen(label);

	ck_attr[1].type = CKA_CLASS;
	ck_attr[1].pValue = &obj_type;
	ck_attr[1].ulValueLen = sizeof(CK_OBJECT_CLASS);

	ck_attr[2].type = CKA_KEY_TYPE;
	ck_attr[2].pValue = &key_type;
	ck_attr[2].ulValueLen = sizeof(CK_KEY_TYPE);

	/* create a USER R/W session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK) {
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, 3);
	if (rc != CKR_OK) {
		printf("C_FindObjectsInit handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjects(h_session, &obj, 1, &num_existing_objects);
	if (rc != CKR_OK) {
		printf("C_FindObjects handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		printf("C_FindObjectsFinal handle failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	if (num_existing_objects) {
		if (num_existing_objects > 1)
			printf("More than 1 Key with same label exists, continuing with first one.\n");
	} else {
		printf("No Object Found to Verify.\n");
		goto cleanup;
	}

	memset(ck_attr, 0, sizeof(CK_ATTRIBUTE) * 2);
	switch (key_type) {
		case CKK_RSA:
			ck_attr[attrCount].type = CKA_MODULUS;
			ck_attr[attrCount].pValue = NULL;
			ck_attr[attrCount].ulValueLen = 0;
			attrCount++;

			ck_attr[attrCount].type = CKA_PUBLIC_EXPONENT;
			ck_attr[attrCount].pValue = NULL;
			ck_attr[attrCount].ulValueLen = 0;
			attrCount++;

			break;
		case CKK_EC:
			ck_attr[attrCount].type = CKA_EC_POINT;
			ck_attr[attrCount].pValue = NULL;
			ck_attr[attrCount].ulValueLen = 0;
			attrCount++;

			ck_attr[attrCount].type = CKA_EC_PARAMS;
			ck_attr[attrCount].pValue = NULL;
			ck_attr[attrCount].ulValueLen = 0;
			attrCount++;

			break;

		default:
			printf("Unsupported Key Type\n");
			goto cleanup;
	}

	rc = funcs->C_GetAttributeValue(h_session, obj, ck_attr, attrCount);
	if (rc != CKR_OK) {
		printf("C_GetAttributeValue() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}
#if 0
	for (i = 0; i < 2; i++) {
		printf("ck_attr[%lu].ulValueLen = %lu\n",
				i, ck_attr[i].ulValueLen);
	}
#endif

	attrCount = 0;
	ck_attr[attrCount].pValue = (void *)malloc(ck_attr[attrCount].ulValueLen);
	attrCount++;
	ck_attr[attrCount].pValue = (void *)malloc(ck_attr[attrCount].ulValueLen);
	attrCount++;

	rc = funcs->C_GetAttributeValue(h_session, obj, ck_attr, attrCount);
	if (rc != CKR_OK) {
		printf("C_GetAttributeValue() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	data = malloc(strlen(getOptValue->data) + strlen(data_array[0]));
	if (data == NULL) {
		printf("Digest Data malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}
	data_len = strlen(getOptValue->data);
	memcpy(data, getOptValue->data, data_len);

	switch (key_type) {
		case CKK_RSA:
			pub_key = RSA_new();
			RSA_blinding_off(pub_key);
			bn_mod = BN_new();
			bn_exp = BN_new();

			/* Convert from strings to BIGNUMs and stick them in the RSA struct */
			BN_bin2bn((uint8_t *)ck_attr[0].pValue, ck_attr[0].ulValueLen,
					bn_mod);
			BN_bin2bn((uint8_t *)ck_attr[1].pValue, ck_attr[1].ulValueLen,
					bn_exp);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
			pub_key->n = bn_mod;
			pub_key->e = bn_exp;
#else
			RSA_set0_key(pub_key, bn_mod, bn_exp, NULL);
#endif
			mech.mechanism = getOptValue->mechanismID;

			switch (mech.mechanism) {
				case CKM_MD5_RSA_PKCS:
					MD5_Init(&c0);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						MD5_Update(&c0, data, strlen(data));
						j++;
						j = j % 10;
					}

					MD5_Final(hash, &c0);
					printf("Digest = ");
					for (i = 0; i < strlen(hash); i++)
						printf("%x ", hash[i]);
					printf("\n");
					if (getOptValue->digest_sign == 1)
						break;

					res = RSA_verify(NID_md5, hash, 16, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_MD5_RSA_PKCS verification success\n");
					else
						printf("CKM_MD5_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA1_RSA_PKCS:
					SHA1_Init(&c1);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						SHA1_Update(&c1, data, strlen(data));
						j++;
						j = j % 10;
					}

					SHA1_Final(hash, &c1);
					printf("Digest = ");
					for (i = 0; i < strlen(hash); i++)
						printf("%x ", hash[i]);
					printf("\n");
					if (getOptValue->digest_sign == 1)
						break;

					res = RSA_verify(NID_sha1, hash, 20, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA1_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA1_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA256_RSA_PKCS:
					SHA256_Init(&c2);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						SHA256_Update(&c2, data, strlen(data));
						j++;
						j = j % 10;
					}

					SHA256_Final(hash, &c2);
					printf("Digest = ");
					for (i = 0; i < strlen(hash); i++)
						printf("%x ", hash[i]);
					printf("\n");
					if (getOptValue->digest_sign == 1)
						break;

					res = RSA_verify(NID_sha256, hash, 32, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA256_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA256_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA384_RSA_PKCS:
					SHA384_Init(&c3);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						SHA384_Update(&c3, data, strlen(data));
						j++;
						j = j % 10;
					}

					SHA384_Final(hash, &c3);
					printf("Digest = ");
					for (i = 0; i < strlen(hash); i++)
						printf("%x ", hash[i]);
					printf("\n");
					if (getOptValue->digest_sign == 1)
						break;

					res = RSA_verify(NID_sha384, hash, 48, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA384_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA384_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA512_RSA_PKCS:
					SHA512_Init(&c3);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						SHA512_Update(&c3, data, strlen(data));
						j++;
						j = j % 10;
					}

					SHA512_Final(hash, &c3);
					printf("Digest = ");
					for (i = 0; i < strlen(hash); i++)
						printf("%x ", hash[i]);
					printf("\n");
					if (getOptValue->digest_sign == 1)
						break;

					res = RSA_verify(NID_sha512, hash, 64, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA512_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA512_RSA_PKCS verification failure\n");
					break;
				default:
					rc = CKR_MECHANISM_INVALID;
			}
			if (getOptValue->digest_sign == 1) {
				data_out_len = RSA_public_decrypt(sig_bytes, sig, data_out,
						pub_key, RSA_PKCS1_PADDING);

				printf("Public Decrypted data[%d] =\n", data_out_len);
				for (i = 0; i < data_out_len; i++)
					printf("%x ", data_out[i]);
				printf("\n");

				if (!(memcmp(data_out, hash, strlen(data))))
					printf("CKM_RSA_PKCS verification success.\n");
				else
					printf("CKM_RSA_PKCS verification failure.\n");
			}
			break;

		case CKK_EC:
		{
			EC_GROUP *group;
			const unsigned char *ec_params_der = NULL;

			/* Attribute contains the der encoding of EC Parameters */
			ec_params_der = (unsigned char *)ck_attr[1].pValue;
			/* Need to convert it into the OpenSSL internal
			  * structure to verify
			  */
			group = d2i_ECPKParameters(NULL, &ec_params_der,
					ck_attr[1].ulValueLen);

			ec_curve_nist_id = EC_GROUP_get_curve_name(group);
			ec_pub_key = EC_KEY_new_by_curve_name(ec_curve_nist_id);

			/* Attribute contains the EC Point in Octet Format */
			const unsigned char *oct_pub = (char *)ck_attr[0].pValue;
			/* Need to convert it into the OpenSSL internal
			  * structure to verify
			  */
			ec_pub_key = o2i_ECPublicKey(&ec_pub_key, &oct_pub, ck_attr[0].ulValueLen);

			ec_sig = ECDSA_SIG_new();

			bn_r = BN_bin2bn((uint8_t *)sig, sig_bytes/2, bn_r);
			bn_s = BN_bin2bn((uint8_t *)sig + (sig_bytes/2), sig_bytes/2, bn_s);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
			ec_sig->r = bn_r;
			ec_sig->s = bn_s;
#else
			ECDSA_SIG_set0(ec_sig, bn_r, bn_s);
#endif
			mech.mechanism = getOptValue->mechanismID;
			switch (mech.mechanism) {
				case CKM_ECDSA_SHA1:
					SHA1_Init(&c1);
					j = 0;
					for (i = 0; i < getOptValue->num_of_times; i++) {
						memcpy(&data[data_len], &data_array[j], strlen(data_array[j]));
						printf("Digest Update count with string[%lu] = %lu.\n", j, i);
						SHA1_Update(&c1, data, strlen(data));
						j++;
						j = j % 10;
					}

					SHA1_Final(hash, &c1);

					ret = ECDSA_do_verify(hash, 20, ec_sig, ec_pub_key);
					if (ret == 1) {
						printf("CKM_ECDSA_SHA1 verification success\n");
						ret = APP_OK;
					} else
						printf("ret = %d, CKM_ECDSA_SHA1 verification failed\n", ret);
					break;
				default:
					rc = CKR_MECHANISM_INVALID;
			}
			break;
		}
		default:
			printf("Unsupported Key Type\n");
			goto cleanup;
	}

cleanup:
	/* done...close the session and verify the object is deleted */
	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK) {
		ret = APP_CKR_ERR;
		return rc;
	}
	if (data)
		free(data);

	return ret;
}

void print_help(void)
{
	printf("    Only one of the below option is allowed per execution:-\n\n");
	printf("\t -S - C_SignInit -> C_SignUpdate(n times) -> C_SignFinal\n");
	printf("\t -V - Verify -S option. (Make sure to use all the same options used earlier while running the command with -S option).\n");
	printf("\t -D - C_DigestInit -> C_DigestUpdate(n times) -> C_DigestFinal -> C_Sign\n");
	printf("\t -W - Verify -D option. (Make sure to use all the same options used earlier while running the command with -D option).\n");
	printf("\t Use below Sub options along with Main options:-\n");
	printf("\t\t -n - Number of times (Default n =100).\n");
	printf("\t\t -k - Key Type (Supported: rsa, ec)\n");
	printf("\t\t -b - Object Label.\n");
	printf("\t\t -p - Slot Id.\n");
	printf("\t\t -m - Mechanism Id \n");
	printf("\t\t Supported Mechanism: md5-rsa, sha1-rsa, sha256-rsa, sha384-rsa, sha512-rsa\n");
	printf("\t\t -d - Plain Data\n");
	printf("\t\t -s - Signature Data\n");
	printf("\t Usage:\n");
	printf("\t\tSignature Generation\n");
	printf("\t\t\tsign_digest_update_final -S -k <key-type> -b <key-label> -d <Data-to-be-signed> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tsign_digest_update_final -D -k <key-type> -b <key-label> -d <Data-to-be-signed> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tsign_digest_update_final -S -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -m md5-rsa -p 0\n");
	printf("\t\t\tsign_digest_update_final -D -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -m md5-rsa -p 0\n");
	printf("\t\tSignature Verification\n");
	printf("\t\t\tsign_digest_update_final -V -k <key-type> -b <key-label> -d <Data-previously-signed> -s <signature-file> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tsign_digest_update_final -W -k <key-type> -b <key-label> -d <Data-previously-signed> -s <signature-file> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tsign_digest_update_final -V -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -s sig.data -m md5-rsa -p 0\n");
	printf("\t\t\tsign_digest_update_final -W -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -s sig.data -m md5-rsa -p 0\n");

}

int proc_sub_option(int option, uint8_t *optarg, struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	FILE *file;

	switch (option) {
	case 'p':
		getOptValue->slot_id = atoi(optarg);
		break;
	case 'b':
		getOptValue->label = optarg;
		getOptValue->findCritCount++;
		break;
	case 'k':
		getOptValue->key_type = getKeyType(optarg);
		if (getOptValue->key_type == UL_INVALID)
			ret = APP_IN_ERR;
		getOptValue->findCritCount++;
		break;
	case 'm':
		getOptValue->mechanismID = getMechId(optarg);
		if (getOptValue->mechanismID == UL_INVALID)
			ret = APP_IN_ERR;
		break;
	case 'n':
		getOptValue->num_of_times = atoi(optarg);
		break;
	case 'd':
		getOptValue->data = optarg;
		break;
	case 's':
		getOptValue->signed_data = optarg;
		file = fopen(getOptValue->signed_data, "r");
		if (!file) {
			ret = APP_IP_ERR;
			printf("Error Opening the File.\n");
		}
		if (file)
			fclose(file);
		break;
	default:
		print_help();
		exit(EXIT_FAILURE);
	}
	return ret;
}

int proc_main_option(int operation,
		int option,
		uint8_t *optarg,
		struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	int rc = 0;
	CK_RV rv = 0;
	void    *d = NULL;

	if (operation == PERFORM) {

		d = dlopen(getOptValue->libFileName, RTLD_NOW);
		if (d == NULL) {
			printf("Failure to open PKCS Library[%s].\n", dlerror());
			ret = APP_LIB_ERR;
			return ret;
		}

		ret = do_GetFuncList(d);
		if (ret != APP_OK)  {
			printf("Failed to Get Function List[%d]\n", rc);
			dlclose(d);
			ret = APP_LIB_ERR;
			return ret;
		}

		funcs->C_Initialize(NULL_PTR);
		{
			CK_SESSION_HANDLE hsess = 0;

			rc = funcs->C_GetFunctionStatus(hsess);
			if (rc != CKR_FUNCTION_NOT_PARALLEL) {
				ret = APP_LIB_ERR;
				goto performcleanup;
			}

			rc = funcs->C_CancelFunction(hsess);
			if (rc != CKR_FUNCTION_NOT_PARALLEL) {
				ret = APP_LIB_ERR;
				goto performcleanup;
			}
		}
	}

	switch (option) {
	case 'S':
		if (operation == PERFORM) {
			printf("Test for Sign Init Update Final started.\n");
			if ((getOptValue->data == NULL)
				|| (getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
				printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -p -d -m]\n");
				ret = APP_IP_ERR;
				break;
		}
		ret = do_Sign_init_update_final(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'D':
		if (operation == PERFORM) {
			printf("Test for Digest Init Update Final and then Sign is started.\n");
			if ((getOptValue->data == NULL)
				|| (getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
				printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -p -d -m]\n");
				ret = APP_IP_ERR;
				break;
		}
		ret = do_Digest_init_update_final_Sign(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'V':
		if (operation == PERFORM) {
			printf("Verifying...\n");
			if ((getOptValue->data == NULL)
				|| (getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->data == NULL)
				|| (getOptValue->signed_data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
					printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -p -d -s -m]\n");
					ret = APP_IP_ERR;
				break;
			}
			ret = do_Verify(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'W':
		if (operation == PERFORM) {
			printf("Verifying...\n");
			if ((getOptValue->data == NULL)
				|| (getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->data == NULL)
				|| (getOptValue->signed_data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
					printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -p -d -s -m]\n");
					ret = APP_IP_ERR;
				break;
			}

			getOptValue->digest_sign = 1;
			ret = do_Verify(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	default:
		if (getOptValue->numOfMainOpt && operation == PARSE) {
			if (option != '?') {
				ret = proc_sub_option(option, optarg, getOptValue);
				if (ret != APP_OK)
					break;
			}
		} else {
			print_help();
			exit(EXIT_FAILURE);
		}
	}

performcleanup:
	if (operation == PERFORM) {
		rv = funcs->C_Finalize(NULL_PTR);
		if (rv != CKR_OK)
			printf("Command Failed[%s]\n", p11_get_error_string(rv));

		dlclose(d);
	}

	return ret;
}

int main(int argc, char **argv)
{
	struct getOptValue_t getOptValue = {
		.main_option = 0,
		.numOfMainOpt = 0,
		.libFileName = NULL,
		.num_of_times = 100,
		.slot_id = UL_UNINTZD,
		.key_type = UL_UNINTZD,
		.mechanismID = UL_UNINTZD,
		.data = NULL,
		.label = NULL,
		.digest_sign = 0,
		.findCritCount = 0
	};
	int ret = APP_OK;
	int option;
	extern char *optarg; extern int optind;
	uint8_t *default_libFile = "libpkcs11.so";

	while ((option = getopt(argc, argv, "SDVWb:d:k:m:n:p:s:")) != -1) {
		ret = proc_main_option(PARSE, option, optarg, &getOptValue);
		if (ret != APP_OK)
			break;
	}

	if (ret != APP_OK) {
		printf("Command Failed due to PKCS App: input error.\n");
		return ret;
	}

	if (getOptValue.numOfMainOpt != 1) {
		print_help();
		exit(EXIT_FAILURE);
	}

	if (getOptValue.libFileName == NULL) {	/* -f was mandatory */
		getOptValue.libFileName = default_libFile;
	}

	ret = proc_main_option(PERFORM, getOptValue.main_option, optarg, &getOptValue);
	if (ret != APP_OK && ret != APP_IP_ERR) {
		if (ret == APP_CKR_ERR)
			printf("Command Failed due to PKCS Lib Error\n");
		else
			printf("Command Failed due to PKCS APP error.\n");
	}

	return 0;
}
