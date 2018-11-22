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

int do_GetInfo(void)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_INFO info;
	uint32_t i = 0;

	rc = funcs->C_GetInfo(&info);
	if (rc != CKR_OK) {
		printf("C_GetInfo() rc=%s\n", p11_get_error_string(rc));
		return APP_CKR_ERR;
	}

	printf("Library Manufacturer = ");
	for (i = 0; i < sizeof(info.manufacturerID); i++)
		printf("%c", info.manufacturerID[i]);
	printf("\n");

	printf("Library Description = ");
	for (i = 0; i < sizeof(info.libraryDescription); i++)
		printf("%c", info.libraryDescription[i]);
	printf("\n");

	return rc;
}

int do_GetSlotList(void)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_BBOOL tokenPresent;
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_ULONG ulCount = 0;
	CK_ULONG i;

	tokenPresent = TRUE;

	/*
	 * If pSlotList is NULL_PTR, then all that C_GetSlotList does is
	 * return (in *pulCount) the number of slots, without actually
	 * returning a list of slots.
	 */
	rc = funcs->C_GetSlotList(tokenPresent, NULL, &ulCount);
	if (rc != CKR_OK) {
		printf("C_GetSlotList failed rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	if (!ulCount) {
		printf("Received slot count as zero.\n");
		goto cleanup;
	}

	pSlotList = (CK_SLOT_ID *)malloc(ulCount * sizeof(CK_SLOT_ID));
	if (!pSlotList) {
		printf("malloc failed to allocate memory for list\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	/* Get the slots */
	rc = funcs->C_GetSlotList(tokenPresent, pSlotList, &ulCount);
	if (rc != CKR_OK) {
		printf("C_GetSlotList rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Slot List :\n");
	for (i = 0; i < ulCount; i++)
		printf("\tSlot ID = %lu\n", pSlotList[i]);

cleanup:
	if (pSlotList)
		free(pSlotList);

	return ret;

}

int do_GetSlotInfo(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = getOptValue->slot_id;
	CK_SLOT_INFO info;
	uint32_t i = 0;

	rc = funcs->C_GetSlotInfo(slot_id, &info);
	if (rc != CKR_OK) {
		if (rc == CKR_SLOT_ID_INVALID) {
			printf("Invalid Slot Id : %lu.\n", slot_id);
			ret = APP_IN_ERR;
			goto cleanup;
		}
		ret = APP_CKR_ERR;
		printf("Command failed[%s].\n", p11_get_error_string(rc));
		goto cleanup;
	}
	printf("Slot info of in-use slot with ID = %lu :\n", slot_id);
	printf("\tSlot Description:");
	for (i = 0; i < sizeof(info.slotDescription); i++)
		printf("%c", info.slotDescription[i]);
	printf("\n");

	printf("\tSlot Manufacturer = ");
	for (i = 0; i < sizeof(info.manufacturerID); i++)
		printf("%c", info.manufacturerID[i]);
	printf("\n");

cleanup:
	return ret;
}

int do_GetTokenInfo(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = getOptValue->slot_id;
	CK_TOKEN_INFO info;
	uint32_t i = 0;

	rc = funcs->C_GetTokenInfo(slot_id, &info);
	if (rc != CKR_OK) {
		if (rc == CKR_SLOT_ID_INVALID) {
			printf("Invalid Slot Id : %lu.\n", slot_id);
			ret = APP_IN_ERR;
			goto cleanup;
		}
		printf("Command failed[%s].\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}
	printf("TokenInfo for Slot Id: %lu.\n", slot_id);
	printf("\tToken Label = ");
	for (i = 0; i < sizeof(info.label); i++)
		printf("%c", info.label[i]);
	printf("\n");

	printf("\tToken Manufacturer = ");
	for (i = 0; i < sizeof(info.manufacturerID); i++)
		printf("%c", info.manufacturerID[i]);
	printf("\n");

cleanup:
	return ret;
}

int do_GetMechanismList(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = getOptValue->slot_id;
	CK_ULONG count;
	CK_MECHANISM_TYPE *mech_list = NULL;
	uint8_t *mechanismStr;

	CK_ULONG i;
	/*
	 * If pMechanismList is NULL_PTR, then all that C_GetMechanismList
	 * does is return (in *pulCount) the number of mechanisms, without
	 * actually returning a list of mechanisms. The contents of
	 * *pulCount on entry to C_GetMechanismList has no meaning in this
	 * case, and the call returns the value CKR_OK.
	 */

	rc = funcs->C_GetMechanismList(slot_id, NULL, &count);

	if (rc != CKR_OK) {
		if (rc == CKR_SLOT_ID_INVALID) {
			printf("Invalid Slot Id : %lu.\n", slot_id);
			ret = APP_IN_ERR;
			goto cleanup;
		}
		ret = APP_CKR_ERR;
		printf("Command failed[%s].\n", p11_get_error_string(rc));
		goto cleanup;
	}

	mech_list = (CK_MECHANISM_TYPE *)malloc(count *
			sizeof(CK_MECHANISM_TYPE));
	if (!mech_list) {
		printf("malloc failed for mechanism list\n");
		rc = CKR_HOST_MEMORY;
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
	if (rc != CKR_OK) {
		printf("C_GetMechanismList rc=%s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Mechanism listing from the Slot Id = %lu:\n", slot_id);

	for (i = 0; i < count; i++) {
		mechanismStr = getMechanismString(mech_list[i]);
		printf("\t%s with mechanism ID[%lu].\n", mechanismStr, mech_list[i]);
	}

cleanup:
	if (mech_list)
		free(mech_list);

	return ret;
}

int do_GetMechanismInfo(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = getOptValue->slot_id;
	CK_MECHANISM_INFO info;
	CK_ULONG i, count, j;
	CK_MECHANISM_TYPE *mech_list = NULL;
	CK_MECHANISM_TYPE mechanismID = getOptValue->mechanismID;
	CK_ULONG mechanismCap[25];
	CK_ULONG capCount = 0;

	if (mechanismID != UL_UNINTZD) {
		rc = funcs->C_GetMechanismInfo(slot_id, mechanismID, &info);
		if (rc != CKR_OK) {
			if (rc == CKR_SLOT_ID_INVALID) {
				printf("Invalid Slot Id : %lu.\n", slot_id);
				ret = APP_IN_ERR;
				goto cleanup;
			}
			ret = APP_CKR_ERR;
			printf("Command failed[%s].\n", p11_get_error_string(rc));
			goto cleanup;
		}
		printf("Mechanism Info for %s with mechanism ID[%lu].\n",
				getMechanismString(mechanismID), mechanismID);
		printf("\tMinimum Key Size = %lu\n", info.ulMinKeySize);
		printf("\tMaximum Key Size = %lu\n", info.ulMaxKeySize);
		printf("\tMechanism Capabilties:");
		memset(mechanismCap, 0, sizeof(mechanismCap));
		capCount = getMechanismCap(info.flags, mechanismCap);

		for (i = 0; i < capCount; i++) {
			if (mechanismCap[i])
				printf(" %s, ", getMechCapString(mechanismCap[i]));
		}
		printf("\n");
		goto cleanup;
	}

	rc = funcs->C_GetMechanismList(slot_id, NULL, &count);
	if (rc != CKR_OK) {
		if (rc == CKR_SLOT_ID_INVALID) {
			printf("Invalid Slot Id : %lu.\n", slot_id);
			ret = APP_IN_ERR;
			goto cleanup;
		}
		ret = APP_CKR_ERR;
		printf("Command failed[%s].\n", p11_get_error_string(rc));
		goto cleanup;
	}

	mech_list = (CK_MECHANISM_TYPE *)malloc(count *
			sizeof(CK_MECHANISM_TYPE));
	if (!mech_list) {
		printf("malloc failed for mechanism list\n");
		rc = CKR_HOST_MEMORY;
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
	if (rc != CKR_OK) {
		printf("C_GetMechanismList Failed with error=%s.\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Mechanism Info ");
	for (i = 0; i < count; i++) {
		rc = funcs->C_GetMechanismInfo(slot_id, mech_list[i], &info);
		if (rc != CKR_OK) {
			ret = APP_CKR_ERR;
			break;
		}

		printf("Mechanism Info for %s with mechanism ID[%lu].\n",
				getMechanismString(mech_list[i]), mech_list[i]);
		printf("\tMinimum Key Size = %lu\n", info.ulMinKeySize);
		printf("\tMaximum Key Size = %lu\n", info.ulMaxKeySize);
		printf("\tMechanism Capabilties:");
		memset(mechanismCap, 0, sizeof(mechanismCap));
		capCount = getMechanismCap(info.flags, mechanismCap);

		for (j = 0; j < capCount; j++) {
			if (mechanismCap[j])
				printf(" %s, \n", getMechCapString(mechanismCap[j]));
		}
	}

cleanup:
	if (mech_list)
		free(mech_list);

	return ret;
}

int do_GetFunctionList(void *lib_handle)
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

int do_FindObjects(struct getOptValue_t *getOptValue)
{
	int ret = APP_OK;
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id = getOptValue->slot_id;
	CK_RV             rc = 0;
	CK_SESSION_HANDLE h_session = 0;

	CK_BYTE           false = FALSE;
	CK_ULONG i = 0, j, numAttrCount;

	CK_OBJECT_HANDLE  obj_list[getOptValue->num_of_obj];
	CK_ULONG          find_count;
	CK_ULONG          num_existing_objects;

	CK_ATTRIBUTE *ck_attr = NULL;
	CK_ATTRIBUTE foundObj_ck_attr[5];
	CK_OBJECT_CLASS obj_type;
	CK_KEY_TYPE key_type;
	CK_ULONG modulus_bits;
	CK_ULONG count = 0;
	uint8_t *label = NULL;

	if (getOptValue->findCritCount) {

		ck_attr = malloc(sizeof(CK_ATTRIBUTE) * getOptValue->findCritCount);
		if (!ck_attr) {
			printf("malloc failed for CK_ATTRIBUTE.\n");
			ret = APP_MALLOC_FAIL;
			goto cleanup;
		}


		if (getOptValue->label) {
			label = getOptValue->label;
			ck_attr[i].type = CKA_LABEL;
			ck_attr[i].pValue = label;
			ck_attr[i].ulValueLen = strlen(label);
			i++;
		}

		if (getOptValue->obj_type != UL_UNINTZD) {
			obj_type = getOptValue->obj_type;
			ck_attr[i].type = CKA_CLASS;
			ck_attr[i].pValue = &obj_type;
			ck_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
			i++;
		}

		if (getOptValue->key_type != UL_UNINTZD) {
			key_type = getOptValue->key_type;
			ck_attr[i].type = CKA_KEY_TYPE;
			ck_attr[i].pValue = &key_type;
			ck_attr[i].ulValueLen = sizeof(CK_KEY_TYPE);
			i++;
		}
	}
	/* create a USER R/W session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK) {
		if (rc == CKR_SLOT_ID_INVALID) {
			printf("Invalid Slot Id : %lu.\n", slot_id);
			ret = APP_IP_ERR;
			goto cleanup;
		} else {
			printf("Command failed[%s].\n", p11_get_error_string(rc));
			ret = APP_CKR_ERR;
			goto cleanup;
		}
	}

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, getOptValue->findCritCount);
	if (rc != CKR_OK) {
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_FindObjects(h_session, obj_list, getOptValue->num_of_obj, &num_existing_objects);
	if (rc != CKR_OK) {
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	if (!num_existing_objects) {
		printf("No object found matching search criteria.\n");
		goto cleanup;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	for (i = 0; i < num_existing_objects; i++) {
		printf("object[%lu] = %lx\n", i, obj_list[i]);

		foundObj_ck_attr[count].type = CKA_LABEL;
		foundObj_ck_attr[count].pValue = NULL;
		foundObj_ck_attr[count].ulValueLen = 0;
		count++;

		foundObj_ck_attr[count].type = CKA_CLASS;
		foundObj_ck_attr[count].pValue = NULL;
		foundObj_ck_attr[count].ulValueLen = 0;
		count++;

		foundObj_ck_attr[count].type = CKA_ID;
		foundObj_ck_attr[count].pValue = NULL;
		foundObj_ck_attr[count].ulValueLen = 0;
		count++;

		foundObj_ck_attr[count].type = CKA_KEY_TYPE;
		foundObj_ck_attr[count].pValue = NULL;
		foundObj_ck_attr[count].ulValueLen = 0;
		count++;

		rc = funcs->C_GetAttributeValue(h_session,
				obj_list[i], foundObj_ck_attr, count);
		if (rc != CKR_OK) {
			printf("C_GetAttributeValue() rc = %s\n",
					p11_get_error_string(rc));
			ret = APP_CKR_ERR;
			goto cleanup;
		}
		for (j = 0; j < count; j++) {
			if (foundObj_ck_attr[j].ulValueLen != -1) {
				foundObj_ck_attr[j].pValue =
					(void *)malloc(foundObj_ck_attr[j].ulValueLen);

				if (!foundObj_ck_attr[j].pValue) {
					printf("malloc failed CK_ATTR[%lu].pValue\n", j);
					rc = CKR_HOST_MEMORY;
					ret = APP_MALLOC_FAIL;
					goto cleanup;
				}
			}

		}
		rc = funcs->C_GetAttributeValue(h_session, obj_list[i], foundObj_ck_attr, count);
		if (rc != CKR_OK) {
			printf("C_GetAttributeValue() rc = %s\n",
					p11_get_error_string(rc));
			ret = APP_CKR_ERR;
			goto cleanup;
		}

		j = 0;
		printf("\tLabel: %s\n", (char *)foundObj_ck_attr[j].pValue);
		j++;
		printf("\tClass: %s\n", getClassString(*((CK_OBJECT_CLASS *)foundObj_ck_attr[j].pValue)));
		j++;
		printf("\tObject ID: 0x%lx\n", *((CK_ULONG *)foundObj_ck_attr[j].pValue));
		j++;
		printf("\tKey Type: %s\n", getKeyTypeString(*((CK_KEY_TYPE *)foundObj_ck_attr[j].pValue)));
		j++;
		count = 0;
	}
cleanup:
	/* done...close the session and verify the object is deleted */
	if (h_session)
		rc = funcs->C_CloseSession(h_session);

	if (ck_attr)
		free(ck_attr);

	for (j = 0; j < count; j++) {
		if (foundObj_ck_attr[j].pValue)
			free(foundObj_ck_attr[j].pValue);
	}

	return ret;
}

int do_Decrypt(struct getOptValue_t *getOptValue)
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
	CK_BYTE *plain_text = NULL;
	CK_ULONG plain_text_bytes = 0;

	FILE *decFile = NULL;
	CK_BYTE enc[256];
	CK_ULONG enc_bytes = 256;
	FILE *encFile = NULL;
	uint8_t *label = getOptValue->label;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	memset(enc, 0, 256);

	encFile = fopen(getOptValue->enc_data, "rb");
	if (encFile == NULL) {
		printf("Error! opening file");
		ret = APP_FILE_ERR;
		return ret;
	}

	enc_bytes = fread(enc, 1, enc_bytes, encFile);
	fclose(encFile);

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
	switch (mech.mechanism) {
		case CKM_RSA_PKCS:
			mech.pParameter = NULL;
			mech.ulParameterLen = 0;
			break;
		case CKM_RSA_PKCS_OAEP:
			memset(&oaep_params, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
			oaep_params.hashAlg = CKM_SHA_1;
			oaep_params.mgf = CKG_MGF1_SHA1;
			oaep_params.source = CKZ_DATA_SPECIFIED;
			oaep_params.pSourceData = NULL;
			oaep_params.ulSourceDataLen = 0;
			mech.pParameter = &oaep_params;
			mech.ulParameterLen = sizeof(oaep_params);
			break;
		default:
			printf("Only CKM_RSA_PKCS(rsa), CKM_RSA_PKCS_OAEP(rsa-oaep) supported\n");
			goto cleanup;
	}

	rc = funcs->C_DecryptInit(h_session, &mech, obj);
	if (rc != CKR_OK) {
		printf("C_DecryptInit() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	rc = funcs->C_Decrypt(h_session, enc, enc_bytes, plain_text, &plain_text_bytes);
	if (rc != CKR_OK) {
		printf("C_Sign() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	plain_text = (CK_BYTE *)malloc(plain_text_bytes);
	if (plain_text == NULL) {
		printf("plain_text malloc failed\n");
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	rc = funcs->C_Decrypt(h_session, enc, enc_bytes, plain_text, &plain_text_bytes);
	if (rc != CKR_OK) {
		printf("C_Decrypt() rc = %s\n", p11_get_error_string(rc));
		ret = APP_CKR_ERR;
		goto cleanup;
	}

	printf("Decrypted Data: %s \n", plain_text);

cleanup:
	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK)
		ret = APP_CKR_ERR;

	return ret;
}

int do_Encrypt(struct getOptValue_t *getOptValue)
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
	CK_BYTE *data = getOptValue->data;
	RSA *pub_key;
	BIGNUM *bn_mod = NULL, *bn_exp = NULL;
	CK_ULONG i, j;
	CK_OBJECT_CLASS obj_type;
	uint8_t *label = getOptValue->label;
	CK_KEY_TYPE key_type = 0;

	FILE *encFile = NULL;
	CK_ULONG enc_bytes = 256;
	CK_BYTE enc[256];
	uint32_t attrCount = 0;

	key_type = getOptValue->key_type;

	/* Encrypt always done using Public Key */
	obj_type = CKO_PUBLIC_KEY;

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
				case CKM_RSA_PKCS:
					data_out_len = RSA_public_encrypt(strlen(data), data, data_out,
							pub_key, RSA_PKCS1_PADDING);
					if (data_out_len == -1)
						printf("RSA_public_encrypt failed\n");
					break;
				case CKM_RSA_PKCS_OAEP:
					data_out_len = RSA_public_encrypt(strlen(data), data, data_out,
							pub_key, RSA_PKCS1_OAEP_PADDING);
					if (data_out_len == -1)
						printf("RSA_public_encrypt failed\n");
					break;
				default:
					rc = CKR_MECHANISM_INVALID;
			}
			break;
		default:
			printf("Unsupported Key Type\n");
			goto cleanup;
	}

	encFile = fopen("enc.data", "wb");
	if (encFile == NULL) {
		printf("Error! opening file");
		ret = APP_FILE_ERR;
		goto cleanup;
	}

	fwrite((void *)data_out, 1, data_out_len, encFile);
	printf("Encrypted data saved in enc.data\n");
	fclose(encFile);

cleanup:
	/* done...close the session and verify the object is deleted */
	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK) {
		ret = APP_CKR_ERR;
		return rc;
	}

	return ret;
}

int do_Sign(struct getOptValue_t *getOptValue)
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
	printf("Size of Unsigned data = %lu\n", strlen(data));
	rc = funcs->C_Sign(h_session, data, strlen(data), sig, &sig_bytes);
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

	rc = funcs->C_Sign(h_session, data, strlen(data), sig, &sig_bytes);
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
	CK_BYTE *data = getOptValue->data;
	RSA *pub_key;
	EC_KEY *ec_pub_key;
	BIGNUM *bn_mod = NULL, *bn_exp = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL;
	CK_ULONG i, j;
	CK_OBJECT_CLASS obj_type;
	uint8_t *label = getOptValue->label;
	CK_KEY_TYPE key_type = 0;

	CK_BYTE hash[64] = {0};
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
				case CKM_RSA_PKCS:
					data_out_len = RSA_public_decrypt(sig_bytes, sig, data_out,
							pub_key, RSA_PKCS1_PADDING);
					if (!(memcmp(data_out, data, strlen(data))))
						printf("CKM_RSA_PKCS verification success.\n");
					else
						printf("CKM_RSA_PKCS verification failure.\n");
					break;
				case CKM_MD5_RSA_PKCS:
					MD5(data, strlen(data), hash);
					res = RSA_verify(NID_md5, hash, 16, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_MD5_RSA_PKCS verification success\n");
					else
						printf("CKM_MD5_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA1_RSA_PKCS:
					SHA1_Init(&c1);
					SHA1_Update(&c1, data, strlen(data));
					SHA1_Final(hash, &c1);
					res = RSA_verify(NID_sha1, hash, 20, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA1_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA1_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA256_RSA_PKCS:
					SHA256_Init(&c2);
					SHA256_Update(&c2, data, strlen(data));
					SHA256_Final(hash, &c2);
					res = RSA_verify(NID_sha256, hash, 32, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA256_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA256_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA384_RSA_PKCS:
					SHA384_Init(&c3);
					SHA384_Update(&c3, data, strlen(data));
					SHA384_Final(hash, &c3);
					res = RSA_verify(NID_sha384, hash, 48, sig, sig_bytes,
							pub_key);
					if (res == 1)
						printf("CKM_SHA384_RSA_PKCS verification success\n");
					else
						printf("CKM_SHA384_RSA_PKCS verification failure\n");
					break;
				case CKM_SHA512_RSA_PKCS:
					SHA512_Init(&c3);
					SHA512_Update(&c3, data, strlen(data));
					SHA512_Final(hash, &c3);
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
					SHA1_Update(&c1, data, strlen(data));
					SHA1_Final(hash, &c1);

					ret = ECDSA_do_verify(hash, 20, ec_sig, ec_pub_key);
					if (ret == 1) {
						printf("CKM_ECDSA_SHA1 verification success\n");
						ret = APP_OK;
					} else
						printf("ret = %d, CKM_ECDSA_SHA1 verification failed\n", ret);
					break;

				case CKM_ECDSA:
					ret = ECDSA_do_verify(data, strlen(data), ec_sig, ec_pub_key);
					if (ret == 1) {
						printf("CKM_ECDSA verification success\n");
						ret = APP_OK;
					} else
						printf("ret = %d, CKM_ECDSA verification failed\n", ret);

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

	return ret;
}

void print_usage(void)
{
	printf("    Only one of the below option is allowed per execution:-\n\n");
	printf("\t -I - Library Information.\n");
	printf("\t -T - Token\n");
	printf("\t -P - Slot\n");
	printf("\t -M - Mechanism\n");
	printf("\t -F - Find\n");
	printf("\t -S - Sign\n");
	printf("\t -V - Verify\n");
	printf("\t -E - Encrypt\n");
	printf("\t -D - Decrypt\n\n");
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
	printf("\t\t\tpkcs11_app -I\n\n");
	printf("\t\tSlot/Token Commands:\n");
	printf("\t\t\tpkcs11_app -P -l\n");
	printf("\t\t\tpkcs11_app -P -i -p <slot-ID>; (pkcs11_app -P -i -p 0)\n");
	printf("\t\t\tpkcs11_app -T -i -p <slot-ID>; (pkcs11_app -T -i -p 0)\n\n");
	printf("\t\tMechanism:\n");
	printf("\t\t\tpkcs11_app -M -l -p <slot-ID>; (pkcs11_app -M -l -p 0)\n");
	printf("\t\t\tpkcs11_app -M -m <mech-ID> -i -p <slot-ID>; (pkcs11_app -M -m rsa -i -p 0)\n");
	printf("\t\t\tpkcs11_app -M -i -p <slot-ID>; (pkcs11_app -M -i -p 0)\n\n");
	printf("\t\tObject Search:\n");
	printf("\t\t\tpkcs11_app -F -p <slot-ID> [-n <num-of-obj> -k <key-type> -b <obj-label> -o <obj-type>]\n");
	printf("\t\t\tObjects can be listed based on combination of any above criteria.\n\n");
	printf("\t\tSignature Generation\n");
	printf("\t\t\tpkcs11_app -S -k <key-type> -b <key-label> -d <Data-to-be-signed> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tpkcs11_app -S -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -m md5-rsa -p 0\n");
	printf("\t\t\tpkcs11_app -S -k ec -b Device_Key -d \"PKCS11 TEST DATA\" -m sha1-ec -p 0\n\n");
	printf("\t\tSignature Verification\n");
	printf("\t\t\tpkcs11_app -V -k <key-type> -b <key-label> -d <Data-previously-signed> -s <signature-file> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tpkcs11_app -V -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -s sig.data -m md5-rsa -p 0\n");
	printf("\t\t\tpkcs11_app -V -k ec -b Device_Key -d \"PKCS11 TEST DATA\" -s sig.data -m sha1-ec -p 0\n\n");
	printf("\t\tPublic Key Encryption (RSA Only)\n");
	printf("\t\t\tpkcs11_app -E -k <key-type> -b <key-label> -d <Data-to-be-encrypted> -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tpkcs11_app -E -k rsa -b Device_Key -d \"PKCS11 TEST DATA\" -m rsa -p 0\n\n");
	printf("\t\tPrivate Key Decryption (RSA Only)\n");
	printf("\t\t\tpkcs11_app -D -k <key-type> -b <key-label> -e enc.data -m <mech-ID> -p <slot-ID>\n");
	printf("\t\t\tpkcs11_app -D -k rsa -b Device_Key -e enc.data -m rsa -p 0\n\n");

}

int process_sub_option(int option, uint8_t *optarg, struct getOptValue_t *getOptValue)
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
		print_usage();
		exit(EXIT_FAILURE);
	}
	return ret;
}

int process_main_option(int operation,
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

		ret = do_GetFunctionList(d);
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
	case 'F':
		if (operation == PERFORM) {
			if (getOptValue->slot_id == UL_UNINTZD) {
				printf("Abort: Missing slot ID  [-p].\n");
				ret = APP_IP_ERR;
				break;
			}
			if (!getOptValue->findCritCount)
				printf("None of the search option (-b -o -k) is provided. Listing all Object.\n");
			if (getOptValue->num_of_obj == 0) {
				printf("Missing Option [-n]. Listing Object max upto Count = 10.\n");
				getOptValue->num_of_obj = DEFAULT_FIND_OBJ_SIZE;
			}
			if (getOptValue->num_of_obj > MAX_FIND_OBJ_SIZE)
				printf("[-n] given is %d, Maximum of 100 Objects can be shown.\n",
				getOptValue->num_of_obj);

			ret = do_FindObjects(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'I':
		if (operation == PERFORM) {
			printf("Getting Information about Cryptoki Library\n");
			ret = do_GetInfo();
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'M':
		if (operation == PERFORM) {
			if (getOptValue->slot_id == UL_UNINTZD) {
				printf("Abort: Missing slot ID  [-p].\n");
				ret = APP_IP_ERR;
			}

			if ((getOptValue->info == DISABLE)
					&& (getOptValue->list == DISABLE)) {
				printf("None of the mandatory option (-i or -l) is provided.\n");
			}

			if (getOptValue->list == ENABLE)
				ret = do_GetMechanismList(getOptValue);

			if (getOptValue->info == ENABLE) {
				if (getOptValue->mechanismID == UL_UNINTZD)
					printf("Missing Option [-m].\nListing Capabilities of all the Mechanism.\n");
				ret = do_GetMechanismInfo(getOptValue);
			}
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'P':
		if (operation == PERFORM) {
			if ((getOptValue->info == DISABLE)
					&& (getOptValue->list == DISABLE)) {
				printf("None of the mandatory option (-i or -l) is provided.\n");
			}

			if (getOptValue->list == ENABLE)
				ret = do_GetSlotList();

			if (getOptValue->info == ENABLE) {
				if (getOptValue->slot_id == UL_UNINTZD) {
					printf("Abort: Missing slot ID  [-p].\n");
					ret = APP_IP_ERR;
					break;
				}
				ret = do_GetSlotInfo(getOptValue);
			}
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'T':
		if (operation == PERFORM) {
			if (getOptValue->slot_id == UL_UNINTZD) {
				printf("Abort: Missing slot ID  [-p].\n");
				ret = APP_IP_ERR;
				break;
			}
			ret = do_GetTokenInfo(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
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
		ret = do_Sign(getOptValue);
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
	case 'D':
		if (operation == PERFORM) {
			printf("Decrypting...\n");
			if ((getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->enc_data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
					printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -p -e -m]\n");
					ret = APP_IP_ERR;
				break;
			}
			ret = do_Decrypt(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	case 'E':
		if (operation == PERFORM) {
			printf("Encrypting...\n");
			if ((getOptValue->label == NULL)
				|| (getOptValue->slot_id == UL_UNINTZD)
				|| (getOptValue->key_type == UL_UNINTZD)
				|| (getOptValue->data == NULL)
				|| (getOptValue->mechanismID == UL_UNINTZD)) {
					printf("Abort: Missing or Invalid Value to one or more of the mandatory options [-b -k -d -p -m]\n");
					ret = APP_IP_ERR;
				break;
			}
			ret = do_Encrypt(getOptValue);
		} else {
			getOptValue->main_option = option;
			(getOptValue->numOfMainOpt)++;
		}
		break;
	default:
		if (getOptValue->numOfMainOpt && operation == PARSE) {
			if (option != '?') {
				ret = process_sub_option(option, optarg, getOptValue);
				if (ret != APP_OK)
					break;
			}
		} else {
			print_usage();
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

	while ((option = getopt(argc, argv, "FIMPSTVEDb:d:f:ik:lm:n:o:p:s:e:")) != -1) {
		ret = process_main_option(PARSE, option, optarg, &getOptValue);
		if (ret != APP_OK)
			break;
	}

	if (ret != APP_OK) {
		printf("Command Failed due to PKCS App: input error.\n");
		return ret;
	}

	if (getOptValue.numOfMainOpt != 1) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (getOptValue.libFileName == NULL) {	/* -f was mandatory */
		getOptValue.libFileName = default_libFile;
	}

	ret = process_main_option(PERFORM, getOptValue.main_option, optarg, &getOptValue);
	if (ret != APP_OK && ret != APP_IP_ERR) {
		if (ret == APP_CKR_ERR)
			printf("Command Failed due to PKCS Lib Error\n");
		else
			printf("Command Failed due to PKCS APP error.\n");
	}

	return 0;
}
