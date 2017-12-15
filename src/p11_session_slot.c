 #include "cryptoki.h"
 
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <gen_func.h>
#include <tee_slot.h>
#include <sessions.h>
#include <objects.h>

/*
 *  SLOT AND TOKEN MANAGEMENT
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	int ret = CKR_OK;
	struct slot_info *slot_info;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	tokenPresent = tokenPresent;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (pSlotList == NULL)
		goto out;

	/* only support 1 slot which is TEE_SLOT */
	if (*pulCount >= SLOT_COUNT) {
		pSlotList[0] = TEE_SLOT_ID;
		slot_info = get_global_slot_info(TEE_SLOT_ID);
		slot_info->slot_id = TEE_SLOT_ID;
	} else
		ret =  CKR_BUFFER_TOO_SMALL;

out:
	*pulCount = 1;

	return ret;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	/* Currently only one slot is added i.e. TEE_SLOT
	  * In order to add another slot, need to add 2 files
	  * just like tee_slot.c and tee_slot.h in src folder
	  * and add a case for that slot here */
	switch (slotID) {
		case TEE_SLOT_ID:
			Get_TEE_SlotInfo(pInfo);
			break;
		default:
			return CKR_SLOT_ID_INVALID;
	}

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	switch (slotID) {
		case TEE_SLOT_ID:
			Get_TEE_TokenInfo(pInfo);
			break;
		default:
			return CKR_SLOT_ID_INVALID;
	}

	return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
	flags = flags;
	pSlot = pSlot;
	pRserved = pRserved;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV ret = 0;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	switch (slotID) {
		case TEE_SLOT_ID:
			ret = Get_TEE_MechanismList(pMechanismList, pulCount);
			break;
		default:
			return CKR_SLOT_ID_INVALID;
	}

	return ret;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
		CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV ret;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	switch (slotID) {
		case TEE_SLOT_ID:
			ret = Get_TEE_MechanismInfo(type, pInfo);
			break;
		default:
			return CKR_SLOT_ID_INVALID;
	}

	return ret;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	slotID = slotID;
	pPin = pPin;
	ulPinLen = ulPinLen;
	pLabel = pLabel;
	return CKR_FUNCTION_NOT_SUPPORTED; 
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	hSession = hSession;
	pPin = pPin;
	ulPinLen = ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_UTF8CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	hSession = hSession;
	pOldPin = pOldPin;
	ulOldLen = ulOldLen;
	pNewPin = pNewPin;
	ulNewLen = ulNewLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * SESSION MANAGEMENT
 */

CK_RV C_OpenSession(CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV ret;
	pApplication = pApplication;
	Notify = Notify;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (phSession == NULL)
		return CKR_ARGUMENTS_BAD;

	if ((flags & CKF_RW_SESSION))
		return CKR_ARGUMENTS_BAD;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	ret = create_session(slotID, flags, phSession);
	if (ret != CKR_OK)
		printf("create_session failed \n");

	return ret;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV ret;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	ret = delete_session(hSession);
	if (ret != CKR_OK)
		printf("delete session failed\n");

	return ret;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV ret;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	ret = destroy_session_list(slotID);
	if (ret != CKR_OK)
		printf("destroy_session_list failed\n");

	return ret;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV ret;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	ret = get_session_info(hSession, pInfo);
	if (ret != CKR_OK)
		printf("get_session_info failed\n");

	return ret;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	hSession = hSession;
	pOperationState = pOperationState;
	pulOperationStateLen = pulOperationStateLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	hSession = hSession;
	pOperationState = pOperationState;
	ulOperationStateLen = ulOperationStateLen;
	hEncryptionKey = hEncryptionKey;
	hAuthenticationKey = hAuthenticationKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)
{
	hSession = hSession;
	userType = userType;
	pPin = pPin;
	ulPinLen = ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}
