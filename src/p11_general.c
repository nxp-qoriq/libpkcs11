#include "cryptoki.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <tee_slot.h>
#include <objects.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

CK_BBOOL is_lib_initialized(void);

SK_FUNCTION_LIST  *sk_funcs;

/* Flag to find if cryptoki library is initialised or not */
CK_ULONG	initialized;

/*
 * Information about this cryptoki implementation
 */
static CK_INFO cryptoki_info;

/*
 * List of function entry points
 */
static CK_FUNCTION_LIST global_function_list;

/*
 *  GENERAL-PURPOSE FUNCTIONS
 */

CK_BBOOL is_lib_initialized(void)
{
	return initialized != 0;
}

static int get_function_list(void)
{
	SK_RET_CODE	rc;
	SK_RET_CODE	(*pfoo)(SK_FUNCTION_LIST_PTR_PTR);
	void    *d;
	const char    *e;
	const char    *f = "libsecurekey.so";

	e = getenv("SECUREKEY_LIB");
	if ( e == NULL)
		e = f;

	d = dlopen(e, RTLD_NOW);
	if ( d == NULL ) {
		printf("dlopen failed %s\n", dlerror());
		return FALSE;
	}

	pfoo = (SK_RET_CODE (*)(SK_FUNCTION_LIST_PTR_PTR))dlsym(d, "SK_GetFunctionList");
	if (pfoo == NULL ) {
		return FALSE;
	}

	rc = pfoo(&sk_funcs);

	if (rc != SKR_OK) {
		printf("SK_GetFunctionList rc=%u", rc);
		return FALSE;
	}

	return TRUE;

}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	int rc;
	if (is_lib_initialized())
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (pInitArgs != NULL)
		return CKR_ARGUMENTS_BAD;

	rc = get_function_list();
	if (!rc) {
		printf("get_function_list(), rc=%d\n", rc);
		return CKR_GENERAL_ERROR;
	}

	initialized = 1;

	return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	destroy_object_list(TEE_SLOT_ID);

	initialized = 0;
 
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (cryptoki_info.manufacturerID[0] == 0) {
		cryptoki_info.cryptokiVersion.major = 0x2;
		cryptoki_info.cryptokiVersion.minor = 0x28;

		memset(cryptoki_info.manufacturerID, ' ', sizeof(cryptoki_info.manufacturerID));
		strncpy((char *)cryptoki_info.manufacturerID, "NXP", strlen("NXP"));

		cryptoki_info.flags = 0;

		memset(cryptoki_info.libraryDescription, ' ', sizeof(cryptoki_info.libraryDescription));
		strncpy((char *)cryptoki_info.libraryDescription, "libpkcs11",
			strlen("libpkcs11"));

		cryptoki_info.libraryVersion.major = 1;
		cryptoki_info.libraryVersion.minor = 0;
	}

	memcpy(pInfo, &cryptoki_info, sizeof(CK_INFO));

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;

	global_function_list.version.major =		0x2;
	global_function_list.version.minor =		0x28;
	global_function_list.C_Initialize =		C_Initialize;
	global_function_list.C_Finalize  =		C_Finalize;
	global_function_list.C_GetInfo  =		C_GetInfo;
	global_function_list.C_GetFunctionList =	C_GetFunctionList;
	global_function_list.C_GetSlotList  =		C_GetSlotList;
	global_function_list.C_GetSlotInfo  =		C_GetSlotInfo;
	global_function_list.C_GetTokenInfo  =		C_GetTokenInfo;
	global_function_list.C_GetMechanismList  =	C_GetMechanismList;
	global_function_list.C_GetMechanismInfo  =	C_GetMechanismInfo;
	global_function_list.C_InitToken  =		C_InitToken;
	global_function_list.C_InitPIN  =		C_InitPIN;
	global_function_list.C_SetPIN  =		C_SetPIN;
	global_function_list.C_OpenSession  =		C_OpenSession;
	global_function_list.C_CloseSession  =		C_CloseSession;
	global_function_list.C_CloseAllSessions  =	C_CloseAllSessions;
	global_function_list.C_GetSessionInfo  =	C_GetSessionInfo;
	global_function_list.C_GetOperationState  =	C_GetOperationState;
	global_function_list.C_SetOperationState  =	C_SetOperationState;
	global_function_list.C_Login  =			C_Login;
	global_function_list.C_Logout  =		C_Logout;
	global_function_list.C_CreateObject  =		C_CreateObject;
	global_function_list.C_CopyObject  =		C_CopyObject;
	global_function_list.C_DestroyObject  =		C_DestroyObject;
	global_function_list.C_GetObjectSize  =		C_GetObjectSize;
	global_function_list.C_GetAttributeValue  =	C_GetAttributeValue;
	global_function_list.C_SetAttributeValue  =	C_SetAttributeValue;
	global_function_list.C_FindObjectsInit  =	C_FindObjectsInit;
	global_function_list.C_FindObjects  =		C_FindObjects;
	global_function_list.C_FindObjectsFinal  =	C_FindObjectsFinal;
#if 0
	global_function_list.C_EncryptInit  =		C_EncryptInit;
	global_function_list.C_Encrypt  =		C_Encrypt;
	global_function_list.C_EncryptUpdate  =		C_EncryptUpdate;
	global_function_list.C_EncryptFinal  =		C_EncryptFinal;
	global_function_list.C_DecryptInit  =		C_DecryptInit;
	global_function_list.C_Decrypt  =		C_Decrypt;
	global_function_list.C_DecryptUpdate  =		C_DecryptUpdate;
	global_function_list.C_DecryptFinal  =		C_DecryptFinal;
	global_function_list.C_DigestInit  =		C_DigestInit;
	global_function_list.C_Digest  =		C_Digest;
	global_function_list.C_DigestUpdate  =		C_DigestUpdate;
	global_function_list.C_DigestKey  =		C_DigestKey;
	global_function_list.C_DigestFinal  =		C_DigestFinal;
	global_function_list.C_SignInit  =		C_SignInit;
	global_function_list.C_Sign  =			C_Sign;
	global_function_list.C_SignUpdate  =		C_SignUpdate;
	global_function_list.C_SignFinal  =		C_SignFinal;
	global_function_list.C_SignRecoverInit  =	C_SignRecoverInit;
	global_function_list.C_SignRecover  =		C_SignRecover;
	global_function_list.C_VerifyInit  =		C_VerifyInit;
	global_function_list.C_Verify  =		C_Verify;
	global_function_list.C_VerifyUpdate  =		C_VerifyUpdate;
	global_function_list.C_VerifyFinal  =		C_VerifyFinal;
	global_function_list.C_VerifyRecoverInit  =	C_VerifyRecoverInit;
	global_function_list.C_VerifyRecover  =		C_VerifyRecover;
	global_function_list.C_DigestEncryptUpdate  =	C_DigestEncryptUpdate;
	global_function_list.C_DecryptDigestUpdate  =	C_DecryptDigestUpdate;
	global_function_list.C_SignEncryptUpdate  =	C_SignEncryptUpdate;
	global_function_list.C_DecryptVerifyUpdate  =	C_DecryptVerifyUpdate;
	global_function_list.C_GenerateKey  =		C_GenerateKey;
	global_function_list.C_GenerateKeyPair  =	C_GenerateKeyPair;
	global_function_list.C_WrapKey  =		C_WrapKey;
	global_function_list.C_UnwrapKey  =		C_UnwrapKey;
	global_function_list.C_DeriveKey  =		C_DeriveKey;
	global_function_list.C_SeedRandom  =		C_SeedRandom;
	global_function_list.C_GenerateRandom  =	C_GenerateRandom;
#endif
	global_function_list.C_GetFunctionStatus  =	C_GetFunctionStatus;
	global_function_list.C_CancelFunction  =	C_CancelFunction;
#if 0
	global_function_list.C_WaitForSlotEvent  =	C_WaitForSlotEvent;
#endif
	*ppFunctionList = &global_function_list;
 
	return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}
