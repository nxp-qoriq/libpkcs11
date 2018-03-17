/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

 #include "cryptoki.h"
 
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <general.h>
#include <tee_slot.h>
#include <sessions.h>
#include <objects.h>

/*
 *  SLOT AND TOKEN MANAGEMENT
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rc = CKR_OK;
	struct slot_info *slot_info;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	tokenPresent = tokenPresent;

	if (pulCount == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (pSlotList == NULL)
		goto end;

	/* only support 1 slot which is TEE_SLOT */
	if (*pulCount >= SLOT_COUNT) {
		pSlotList[0] = TEE_SLOT_ID;
		slot_info = get_global_slot_info(TEE_SLOT_ID);
		slot_info->slot_id = TEE_SLOT_ID;
	} else
		rc =  CKR_BUFFER_TOO_SMALL;

end:
	*pulCount = 1;
	p11_global_unlock();
	return rc;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (pInfo == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	/* Currently only one slot is added i.e. TEE_SLOT
	  * In order to add another slot, need to add 2 files
	  * just like tee_slot.c and tee_slot.h in src folder
	  * and add a case for that slot here */
	switch (slotID) {
		case TEE_SLOT_ID:
			Get_TEE_SlotInfo(pInfo);
			break;
		default:
			rc = CKR_SLOT_ID_INVALID;
	}

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (pInfo == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	switch (slotID) {
		case TEE_SLOT_ID:
			Get_TEE_TokenInfo(pInfo);
			break;
		default:
			rc = CKR_SLOT_ID_INVALID;
	}

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			CK_VOID_PTR pRserved)
{
	flags = flags;
	pSlot = pSlot;
	pRserved = pRserved;

	/* Currently since we are not supporting any removable token
	  * it is better to return CKR_FUNCTION_NOT_SUPPORTED */
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (pulCount == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	switch (slotID) {
		case TEE_SLOT_ID:
			rc = Get_TEE_MechanismList(pMechanismList, pulCount);
			break;
		default:
			rc = CKR_SLOT_ID_INVALID;
	}

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
		CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (pInfo == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	switch (slotID) {
		case TEE_SLOT_ID:
			rc = Get_TEE_MechanismInfo(type, pInfo);
			break;
		default:
			rc = CKR_SLOT_ID_INVALID;
	}

end:
	p11_global_unlock();
	return rc;
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
	CK_RV rc = CKR_OK;
	pApplication = pApplication;
	Notify = Notify;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (phSession == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if ((flags & CKF_RW_SESSION)) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (!(flags & CKF_SERIAL_SESSION)) {
		rc = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
		goto end;
	}

	if (slotID != TEE_SLOT_ID) {
		rc = CKR_SLOT_ID_INVALID;
		goto end;
	}

	rc = create_session(slotID, flags, phSession);
	if (rc != CKR_OK)
		print_error("create_session failed \n");

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (!is_session_valid(hSession)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	rc = delete_session(hSession);
	if (rc != CKR_OK)
		print_error("delete session failed\n");

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	rc = destroy_session_list(slotID);
	if (rc != CKR_OK)
		print_error("destroy_session_list failed\n");

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (!is_session_valid(hSession)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (!pInfo) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	rc = get_session_info(hSession, pInfo);
	if (rc != CKR_OK)
		print_error("get_session_info failed\n");

end:
	p11_global_unlock();
	return rc;
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
