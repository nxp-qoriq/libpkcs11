/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <dlfcn.h>

#include "cryptoki.h"
#include <tee_slot.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>

#include <sched.h>
#include <pthread.h>

CK_FUNCTION_LIST  *funcs;

#define err2str(X)     case X: return #X
#define MAX_THREADS	10

// p11_get_error_string - return textual interpretation of a CKR_ error code
// @rc is the CKR_.. error

char *p11_get_error_string( CK_RV rc )
{
   switch (rc) {
      err2str(CKR_OK);
      err2str(CKR_CANCEL);
      err2str(CKR_HOST_MEMORY);
      err2str(CKR_SLOT_ID_INVALID);
      err2str(CKR_GENERAL_ERROR);
      err2str(CKR_FUNCTION_FAILED);
      err2str(CKR_ARGUMENTS_BAD);
      err2str(CKR_NO_EVENT);
      err2str(CKR_NEED_TO_CREATE_THREADS);
      err2str(CKR_CANT_LOCK);
      err2str(CKR_ATTRIBUTE_READ_ONLY);
      err2str(CKR_ATTRIBUTE_SENSITIVE);
      err2str(CKR_ATTRIBUTE_TYPE_INVALID);
      err2str(CKR_ATTRIBUTE_VALUE_INVALID);
      err2str(CKR_DATA_INVALID);
      err2str(CKR_DATA_LEN_RANGE);
      err2str(CKR_DEVICE_ERROR);
      err2str(CKR_DEVICE_MEMORY);
      err2str(CKR_DEVICE_REMOVED);
      err2str(CKR_ENCRYPTED_DATA_INVALID);
      err2str(CKR_ENCRYPTED_DATA_LEN_RANGE);
      err2str(CKR_FUNCTION_CANCELED);
      err2str(CKR_FUNCTION_NOT_PARALLEL);
      err2str(CKR_FUNCTION_NOT_SUPPORTED);
      err2str(CKR_KEY_HANDLE_INVALID);
      err2str(CKR_KEY_SIZE_RANGE);
      err2str(CKR_KEY_TYPE_INCONSISTENT);
      err2str(CKR_KEY_NOT_NEEDED);
      err2str(CKR_KEY_CHANGED);
      err2str(CKR_KEY_NEEDED);
      err2str(CKR_KEY_INDIGESTIBLE);
      err2str(CKR_KEY_FUNCTION_NOT_PERMITTED);
      err2str(CKR_KEY_NOT_WRAPPABLE);
      err2str(CKR_KEY_UNEXTRACTABLE);
      err2str(CKR_MECHANISM_INVALID);
      err2str(CKR_MECHANISM_PARAM_INVALID);
      err2str(CKR_OBJECT_HANDLE_INVALID);
      err2str(CKR_OPERATION_ACTIVE);
      err2str(CKR_OPERATION_NOT_INITIALIZED);
      err2str(CKR_PIN_INCORRECT);
      err2str(CKR_PIN_INVALID);
      err2str(CKR_PIN_LEN_RANGE);
      err2str(CKR_PIN_EXPIRED);
      err2str(CKR_PIN_LOCKED);
      err2str(CKR_SESSION_CLOSED);
      err2str(CKR_SESSION_COUNT);
      err2str(CKR_SESSION_HANDLE_INVALID);
      err2str(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
      err2str(CKR_SESSION_READ_ONLY);
      err2str(CKR_SESSION_EXISTS);
      err2str(CKR_SESSION_READ_ONLY_EXISTS);
      err2str(CKR_SESSION_READ_WRITE_SO_EXISTS);
      err2str(CKR_SIGNATURE_INVALID);
      err2str(CKR_SIGNATURE_LEN_RANGE);
      err2str(CKR_TEMPLATE_INCOMPLETE);
      err2str(CKR_TEMPLATE_INCONSISTENT);
      err2str(CKR_TOKEN_NOT_PRESENT);
      err2str(CKR_TOKEN_NOT_RECOGNIZED);
      err2str(CKR_TOKEN_WRITE_PROTECTED);
      err2str(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
      err2str(CKR_UNWRAPPING_KEY_SIZE_RANGE);
      err2str(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
      err2str(CKR_USER_ALREADY_LOGGED_IN);
      err2str(CKR_USER_NOT_LOGGED_IN);
      err2str(CKR_USER_PIN_NOT_INITIALIZED);
      err2str(CKR_USER_TYPE_INVALID);
      err2str(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
      err2str(CKR_USER_TOO_MANY_TYPES);
      err2str(CKR_WRAPPED_KEY_INVALID);
      err2str(CKR_WRAPPED_KEY_LEN_RANGE);
      err2str(CKR_WRAPPING_KEY_HANDLE_INVALID);
      err2str(CKR_WRAPPING_KEY_SIZE_RANGE);
      err2str(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
      err2str(CKR_RANDOM_SEED_NOT_SUPPORTED);
      err2str(CKR_RANDOM_NO_RNG);
      err2str(CKR_BUFFER_TOO_SMALL);
      err2str(CKR_SAVED_STATE_INVALID);
      err2str(CKR_INFORMATION_SENSITIVE);
      err2str(CKR_STATE_UNSAVEABLE);
      err2str(CKR_CRYPTOKI_NOT_INITIALIZED);
      err2str(CKR_CRYPTOKI_ALREADY_INITIALIZED);
      err2str(CKR_MUTEX_BAD);
      err2str(CKR_MUTEX_NOT_LOCKED);
      default:					return "UNKNOWN";
   }
}

CK_RV do_Sign(CK_MECHANISM_TYPE mech_type)
{
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id;
	CK_RV             rc = CKR_OK;
	CK_SESSION_HANDLE h_session;

	CK_BYTE           false = FALSE;
	CK_ULONG i, j;

	CK_OBJECT_HANDLE  obj;
	CK_ULONG          find_count;
	CK_ULONG          num_existing_objects;

	CK_ATTRIBUTE ck_attr[2];
	CK_OBJECT_CLASS obj_type;
	CK_KEY_TYPE key_type;
	CK_ULONG count = 0;

	CK_MECHANISM mech = {0};
	CK_BYTE data[] = "Hello PKCS api";
	CK_BYTE data_out[512] = {0};
	CK_BYTE hash[64] = {0};
	CK_ULONG data_out_len = 0;
	CK_BYTE *sig = NULL;
	CK_ULONG sig_bytes = 0;
	RSA *pub_key;
	SHA_CTX c1;
	SHA256_CTX c2;
	SHA512_CTX c3;
	BIGNUM *bn_mod, *bn_exp;
	uint8_t ret = 0;

	obj_type = CKO_PRIVATE_KEY;
	key_type = CKK_RSA;

	ck_attr[0].type = CKA_CLASS;
	ck_attr[0].pValue = &obj_type;
	ck_attr[0].ulValueLen = sizeof(CK_OBJECT_CLASS);

	ck_attr[1].type = CKA_KEY_TYPE;
	ck_attr[1].pValue = &key_type;
	ck_attr[1].ulValueLen = sizeof(CK_KEY_TYPE);

	printf("Starting do_Sign\n");
	printf("\nActual data: %s\n", (char *)data);

	slot_id = TEE_SLOT_ID;

	/* create a USER R/O session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK) {
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
		return rc;
	} else {
		printf("R/O Session with handle = 0x%lx created\n", h_session);
	}

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, 2);
	if (rc != CKR_OK) {
		printf("C_FindObjectsInit failed\n");
		return rc;
	}

	rc = funcs->C_FindObjects(h_session, &obj, 1, &num_existing_objects);
	if (rc != CKR_OK) {
		printf("C_FindObjects failed\n");
		return rc;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		printf("C_FindObjectsFinal failed\n");
		return rc;
	}

	printf("num_existing_objects = %lu\n", num_existing_objects);
	if (num_existing_objects)
		printf("object = %lx\n", obj);
	else {
		printf("find_list empty\n");
		return rc;
	}

	memset(ck_attr, 0, sizeof(CK_ATTRIBUTE) * 2);

	mech.mechanism = mech_type;
	rc = funcs->C_SignInit(h_session, &mech, obj);
	if (rc != CKR_OK) {
		printf("C_SignInit() rc = %s\n", p11_get_error_string(rc));
		return rc;
	}

	rc = funcs->C_Sign(h_session, data, sizeof(data), sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		return rc;
	}

	printf("Signature size: %lu\n", sig_bytes);
	sig = (CK_BYTE *)malloc(sig_bytes);
	if (sig == NULL) {
		printf("signature malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	rc = funcs->C_Sign(h_session, data, sizeof(data), sig, &sig_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		goto end;
	}

#if 0
	printf("Signature:\n");
	for (j = 0; j < sig_bytes; j++) {
		printf("%02x", *(sig + j));
		if ((j+1) % 12 == 0)
			printf("\n");
	}
	printf("\n");
#endif
	ck_attr[0].type = CKA_MODULUS;
	ck_attr[0].pValue = NULL;
	ck_attr[0].ulValueLen = 0;

	ck_attr[1].type = CKA_PUBLIC_EXPONENT;
	ck_attr[1].pValue = NULL;
	ck_attr[1].ulValueLen = 0;

	rc = funcs->C_GetAttributeValue(h_session, obj, ck_attr, 2);
	if (rc != CKR_OK) {
		printf("C_GetAttributeValue() rc = %s\n", p11_get_error_string(rc));
#if 0
		for (i = 0; i < 2; i++)
			printf("ck_attr[%lu].ulValueLen = %ld\n",
				i, (CK_LONG)ck_attr[i].ulValueLen);
#endif
		goto end;
	} else {
#if 0
		for (i = 0; i < 2; i++) {
			printf("ck_attr[%lu].ulValueLen = %lu\n",
				i, ck_attr[i].ulValueLen);
		}
#endif
		ck_attr[0].pValue = (void *)malloc(ck_attr[0].ulValueLen);
		ck_attr[1].pValue = (void *)malloc(ck_attr[1].ulValueLen);
		rc = funcs->C_GetAttributeValue(h_session, obj, ck_attr, 2);
		if (rc != CKR_OK)
			goto end;
	}

	pub_key = RSA_new();
	RSA_blinding_off(pub_key);
	bn_mod = BN_new();
	bn_exp = BN_new();

	/* Convert from strings to BIGNUMs and stick them in the RSA struct */
	BN_bin2bn((unsigned char *)ck_attr[0].pValue, ck_attr[0].ulValueLen,
		  bn_mod);
	BN_bin2bn((unsigned char *)ck_attr[1].pValue, ck_attr[1].ulValueLen,
		  bn_exp);

	pub_key->n = bn_mod;
	pub_key->e = bn_exp;

	switch (mech_type) {
	case CKM_RSA_PKCS:
		data_out_len = RSA_public_decrypt(sig_bytes, sig, data_out,
				  pub_key, RSA_PKCS1_PADDING);
		printf("\nCKM_RSA_PKCS Recovered data: %s\n", (char *)data_out);
		break;
	case CKM_MD5_RSA_PKCS:
		MD5(data, sizeof(data), hash);
		ret = RSA_verify(NID_md5, hash, 16, sig, sig_bytes,
					  pub_key);
		if (ret == 1)
			printf("\nCKM_MD5_RSA_PKCS verification success\n");
		else
			printf("\nCKM_MD5_RSA_PKCS verification failure\n");
		break;
	case CKM_SHA1_RSA_PKCS:
		SHA1_Init(&c1);
		SHA1_Update(&c1, data, sizeof(data));
		SHA1_Final(hash, &c1);
		ret = RSA_verify(NID_sha1, hash, 20, sig, sig_bytes,
					  pub_key);
		if (ret == 1)
			printf("\nCKM_SHA1_RSA_PKCS verification success\n");
		else
			printf("\nCKM_SHA1_RSA_PKCS verification failure\n");
		break;
	case CKM_SHA256_RSA_PKCS:
		SHA256_Init(&c2);
		SHA256_Update(&c2, data, sizeof(data));
		SHA256_Final(hash, &c2);
		ret = RSA_verify(NID_sha256, hash, 32, sig, sig_bytes,
					  pub_key);
		if (ret == 1)
			printf("\nCKM_SHA256_RSA_PKCS verification success\n");
		else
			printf("\nCKM_SHA256_RSA_PKCS verification failure\n");
		break;
	case CKM_SHA384_RSA_PKCS:
		SHA384_Init(&c3);
		SHA384_Update(&c3, data, sizeof(data));
		SHA384_Final(hash, &c3);
		ret = RSA_verify(NID_sha384, hash, 48, sig, sig_bytes,
					  pub_key);
		if (ret == 1)
			printf("\nCKM_SHA384_RSA_PKCS verification success\n");
		else
			printf("\nCKM_SHA384_RSA_PKCS verification failure\n");
		break;
	case CKM_SHA512_RSA_PKCS:
		SHA512_Init(&c3);
		SHA512_Update(&c3, data, sizeof(data));
		SHA512_Final(hash, &c3);
		ret = RSA_verify(NID_sha512, hash, 64, sig, sig_bytes,
					  pub_key);
		if (ret == 1)
			printf("\nCKM_SHA512_RSA_PKCS verification success\n");
		else
			printf("\nCKM_SHA512_RSA_PKCS verification failure\n");
		break;
	default:
		rc = CKR_MECHANISM_INVALID;
	}

	/* done...close the session and verify the object is deleted */
	rc = funcs->C_CloseSession(h_session);

end:
	if (sig)
		free(sig);

	if (ck_attr[0].pValue)
		free(ck_attr[0].pValue);

	if (ck_attr[1].pValue)
		free(ck_attr[1].pValue);

	return rc;
}


CK_RV do_GetFunctionList(void *lib_handle)
{
	CK_RV            rc = CKR_GENERAL_ERROR;
	CK_RV  (*pfoo)();
	void    *d = NULL;

	d = lib_handle;
	pfoo = (CK_RV (*)())dlsym(d, "C_GetFunctionList");
	if (pfoo == NULL ) {
		printf("C_GetFunctionList not found\n");
		goto out;
	}

	rc = pfoo(&funcs);
	if (rc != CKR_OK) {
		printf("C_GetFunctionList rc=%lu", rc);
		goto out;
	}

out:
	return rc;
}

static void *thread_function(void *arg)
{
	CK_RV rv = 0;
	pthread_t thread;
	cpu_set_t cpuset;

	thread = pthread_self();
	CPU_SET(*(int *)arg, &cpuset);

	if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset))
		printf("Not able to set the affinity\n");

#if 0
//	printf("[%lu] Getting Information about Cryptoki Library\n", pthread_self());
	rv = do_GetInfo();
	if (rv != CKR_OK)
		printf("do_GetInfo failed\n");

//	printf("[%lu] do_GetSlotList\n", pthread_self());
	rv = do_GetSlotList();
	if (rv != CKR_OK)
		printf("do_GetSlotList failed\n");

	rv = do_GetSlotInfo();
	if (rv != CKR_OK)
		printf("do_GetSlotInfo failed\n");

	rv = do_GetTokenInfo();
	if (rv != CKR_OK)
		printf("do_GetTokenInfo failed\n");

	rv = do_GetMechanismList();
	if (rv != CKR_OK)
		printf("do_GetMechanismList failed\n");

	rv = do_GetMechanismInfo();
	if (rv != CKR_OK)
		printf("do_GetMechanismInfo failed\n");


	rv = sess_mgmt_functions();
	if (rv != CKR_OK)
		printf("sess_mgmt_functions failed rv=%s\n", p11_get_error_string(rv));

	rv = do_FindObjects();
	if (rv != CKR_OK)
		printf("do_FindObjects failed rv=%s\n", p11_get_error_string(rv));
#endif

	rv = do_Sign(CKM_RSA_PKCS);
	if (rv != CKR_OK)
		printf("do_Sign failed rv=%s\n", p11_get_error_string(rv));

	rv = funcs->C_Finalize(NULL_PTR);
	if (rv != CKR_OK)
		printf("C_Finalize failed rv=%s\n", p11_get_error_string(rv));

	printf("***************** C_FInalize done ***********************\n");
	pthread_exit((void *)rv);
}

int main(int argc, char **argv)
{
	int i = 0;
	CK_RV rv = CKR_OK;
	void *thread_ret_val;
	void    *d = NULL;
	char    *f = "libpkcs11.so";
	pthread_t *thread_ids;
	CK_C_INITIALIZE_ARGS cinit_args;
	int num_threads = 0;

	if (argc > 1)
		num_threads = atoi(argv[1]);
	else
		num_threads = MAX_THREADS;

	printf("Creating %d threads\n", num_threads);

	int cpu[num_threads];
	for (i =0; i < num_threads; i++)
		cpu[i] = i % 4;

	d = dlopen(f, RTLD_NOW);
	if (d == NULL) {
		printf("dlopen failed %s\n", dlerror());
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	rv = do_GetFunctionList(d);
	if (rv) {
		printf("do_getFunctionList() returned %lu\n", rv);
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	memset(&cinit_args, 0, sizeof(CK_C_INITIALIZE_ARGS));
	cinit_args.flags = CKF_OS_LOCKING_OK;
	funcs->C_Initialize((void *)&cinit_args);
	{
		CK_SESSION_HANDLE hsess = 0;

		rv = funcs->C_GetFunctionStatus(hsess);
		if (rv != CKR_FUNCTION_NOT_PARALLEL)
			goto end;

		rv = funcs->C_CancelFunction(hsess);
		if (rv != CKR_FUNCTION_NOT_PARALLEL)
			goto end;
	}

	/* Again setting the rv to default value, because it will get changed
	from above function calls*/
	rv = CKR_OK;

	thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
	if (thread_ids == NULL) {
		rv = CKR_GENERAL_ERROR;
		goto end;
	}

	for (i = 0; i < num_threads; i++) {
		if (pthread_create(&thread_ids[i], NULL, thread_function,
			(void *)&cpu[i])) {
			rv = CKR_GENERAL_ERROR;
			printf("Error creating threads\n");
			goto end;
		}
	}

	for (i=0; i <num_threads; i++) {
		if (pthread_join(thread_ids[i], &thread_ret_val)) {
			rv = CKR_GENERAL_ERROR;
			printf("Error in %d: %p\n", (int)thread_ids[i],
				&thread_ret_val);
		}
	}

end:
	if (d)
		dlclose(d);

	printf("PKCS Library finalized successfully\n");

	if (thread_ids)
		free(thread_ids);

	return rv;
}
