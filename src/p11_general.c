#include "cryptoki.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

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
CK_FUNCTION_LIST global_function_list = {
	.version =				{0x2, 0x28},
	.C_Initialize =				C_Initialize,
	.C_Finalize  =				C_Finalize,
	.C_GetInfo  =				C_GetInfo,
	.C_GetFunctionList  =			C_GetFunctionList,
	.C_GetSlotList  =			C_GetSlotList,
	.C_GetSlotInfo  =			C_GetSlotInfo,
	.C_GetTokenInfo  =			C_GetTokenInfo,
	.C_GetMechanismList  =			C_GetMechanismList,
	.C_GetMechanismInfo  =			C_GetMechanismInfo,
	.C_InitToken  =				C_InitToken,
	.C_InitPIN  =				C_InitPIN,
	.C_SetPIN  =				C_SetPIN,
	.C_OpenSession  =			C_OpenSession,
	.C_CloseSession  =			C_CloseSession,
	.C_CloseAllSessions  =			C_CloseAllSessions,
	.C_GetSessionInfo  =			C_GetSessionInfo,
	.C_GetOperationState  =			C_GetOperationState,
	.C_SetOperationState  =			C_SetOperationState,
	.C_Login  =				C_Login,
	.C_Logout  =				C_Logout,
#if 0
	.C_CreateObject  =			C_CreateObject,
	.C_CopyObject  =			C_CopyObject,
	.C_DestroyObject  =			C_DestroyObject,
	.C_GetObjectSize  =			C_GetObjectSize,
	.C_GetAttributeValue  =			C_GetAttributeValue,
	.C_SetAttributeValue  =			C_SetAttributeValue,
	.C_FindObjectsInit  =			C_FindObjectsInit,
	.C_FindObjects  =			C_FindObjects,
	.C_FindObjectsFinal  =			C_FindObjectsFinal,
	.C_EncryptInit  =			C_EncryptInit,
	.C_Encrypt  =				C_Encrypt,
	.C_EncryptUpdate  =			C_EncryptUpdate,
	.C_EncryptFinal  =			C_EncryptFinal,
	.C_DecryptInit  =			C_DecryptInit,
	.C_Decrypt  =				C_Decrypt,
	.C_DecryptUpdate  =			C_DecryptUpdate,
	.C_DecryptFinal  =			C_DecryptFinal,
	.C_DigestInit  =			C_DigestInit,
	.C_Digest  =				C_Digest,
	.C_DigestUpdate  =			C_DigestUpdate,
	.C_DigestKey  =				C_DigestKey,
	.C_DigestFinal  =			C_DigestFinal,
	.C_SignInit  =				C_SignInit,
	.C_Sign  =				C_Sign,
	.C_SignUpdate  =			C_SignUpdate,
	.C_SignFinal  =				C_SignFinal,
	.C_SignRecoverInit  =			C_SignRecoverInit,
	.C_SignRecover  =			C_SignRecover,
	.C_VerifyInit  =			C_VerifyInit,
	.C_Verify  =				C_Verify,
	.C_VerifyUpdate  =			C_VerifyUpdate,
	.C_VerifyFinal  =			C_VerifyFinal,
	.C_VerifyRecoverInit  =			C_VerifyRecoverInit,
	.C_VerifyRecover  =			C_VerifyRecover,
	.C_DigestEncryptUpdate  =		C_DigestEncryptUpdate,
	.C_DecryptDigestUpdate  =		C_DecryptDigestUpdate,
	.C_SignEncryptUpdate  =			C_SignEncryptUpdate,
	.C_DecryptVerifyUpdate  =		C_DecryptVerifyUpdate,
	.C_GenerateKey  =			C_GenerateKey,
	.C_GenerateKeyPair  =			C_GenerateKeyPair,
	.C_WrapKey  =				C_WrapKey,
	.C_UnwrapKey  =				C_UnwrapKey,
	.C_DeriveKey  =				C_DeriveKey,
	.C_SeedRandom  =			C_SeedRandom,
	.C_GenerateRandom  =			C_GenerateRandom,
#endif
	.C_GetFunctionStatus  =			C_GetFunctionStatus,
	.C_CancelFunction  =			C_CancelFunction,
#if 0
	.C_WaitForSlotEvent  =			C_WaitForSlotEvent,
#endif
};

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
