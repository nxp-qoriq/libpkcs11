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

CK_FUNCTION_LIST	*funcs;

struct getOptValue_t {
	uint32_t main_option;
	uint32_t numOfMainOpt;
	uint8_t *libFileName;
	uint8_t list;
	uint8_t info;
	uint32_t num_of_obj;
	uint8_t *label;
	CK_SLOT_ID slot_id;
	CK_KEY_TYPE key_type;
	CK_OBJECT_CLASS obj_type;
	CK_MECHANISM_TYPE mechanismID;
	uint8_t *data;
	uint8_t *signed_data;
	uint8_t *enc_data;
	uint32_t data_len;
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

int do_Sign_init_update_final1(struct getOptValue_t *getOptValue)
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
	CK_BYTE *data = (CK_BYTE *)getOptValue->data;
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

	j = 0;
	for (i = 0; i < 100; i++) {
		printf("Sign Update count with string[%lu] = %lu\n", j, i);
		rc = funcs->C_SignUpdate(h_session, data_array[j], strlen(data_array[j]));
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

void print_help(void)
{
	printf("    Only one of the below option is allowed per execution:-\n\n");
	printf("\t -S - Sign\n");
	printf("\t Use below Sub options along with Main options:-\n");
	printf("\t\t -i - Info.\n");
	printf("\t\t -l - List.\n");
	printf("\t\t -k - Key Type (Supported: rsa, ec)\n");
	printf("\t\t -o - Object Type (Supported: pub, prv)\n");
	printf("\t\t -b - Object Label.\n");
	printf("\t\t -p - Slot Id.\n");
	printf("\t\t -n - Number of Object to be Listed (Default n =10).\n");
	printf("\t\t -m - Mechanism Id \n");
	printf("\t\t Supported Mechanism: rsa, rsa-oaep, md5-rsa, sha1-rsa, sha256-rsa, sha384-rsa, sha512-rsa, ec, sha1-ec\n");
	printf("\t\t EC/RSA Sign/Verify: rsa, md5-rsa, sha1-rsa, sha256-rsa, sha384-rsa, sha512-rsa, ec, sha1-ec\n");
	printf("\t\t RSA Encrypt/Decrypt: rsa, rsa-oaep\n");
	printf("\t\t -d - Plain Data\n");
	printf("\t\t -s - Signature Data\n");
	printf("\t\t -e - Encrypted Data\n\n");
	printf("\t Usage:\n");
	printf("\t\tLibrary Information:\n");
	printf("\t\tSignature Generation\n");
	printf("\t\t\tsign_update_final -S -k <key-type> -b <key-label> -d <Data-to-be-signed> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tsign_update_final -S -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -m md5-rsa -p 0\n");
	printf("\t\t\tsign_update_fina -S -k ec -b Device_Key -d \"PKCS11 TEST DATA\" -m sha1-ec -p 0\n\n");

}

int proc_sub_option(int option, uint8_t *optarg, struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	FILE *file;

	switch (option) {
	case 'f':
		getOptValue->libFileName = optarg;
		break;
	case 'i':
		getOptValue->info = ENABLE;
		break;
	case 'l':
		getOptValue->list = ENABLE;
		break;
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
	case 'o':
		getOptValue->obj_type = getClassID(optarg);
		if (getOptValue->obj_type == UL_INVALID)
			ret = APP_IN_ERR;
		getOptValue->findCritCount++;
		break;
	case 'm':
		getOptValue->mechanismID = getMechId(optarg);
		if (getOptValue->mechanismID == UL_INVALID)
			ret = APP_IN_ERR;
		break;
	case 'n':
		getOptValue->num_of_obj = atoi(optarg);
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
	case 'e':
		getOptValue->enc_data = optarg;
		file = fopen(getOptValue->enc_data, "r");
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
			printf("Signing...\n");
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
		ret = do_Sign_init_update_final1(getOptValue);
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
		.list = DISABLE,
		.info = DISABLE,
		.num_of_obj = 0,
		.slot_id = UL_UNINTZD,
		.key_type = UL_UNINTZD,
		.obj_type = UL_UNINTZD,
		.mechanismID = UL_UNINTZD,
		.data = NULL,
		.label = NULL,
		.findCritCount = 0
	};
	int ret = APP_OK;
	int option;
	extern char *optarg; extern int optind;
	uint8_t *default_libFile = "libpkcs11.so";

	while ((option = getopt(argc, argv, "Sb:d:f:ik:lm:n:o:p:s:e:")) != -1) {
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
