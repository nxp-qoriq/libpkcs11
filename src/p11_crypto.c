/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include "cryptoki.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <general.h>
#include <tee_slot.h>
#include <crypto.h>

/*
 * ENCRYPTION FUNCTIONS
 */

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	hSession = hSession;
	pData = pData;
	ulDataLen = ulDataLen;
	pEncryptedData = pEncryptedData;
	pulEncryptedDataLen = pulEncryptedDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;
	pEncryptedPart = pEncryptedPart;
	pulEncryptedPartLen = pulEncryptedPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	hSession = hSession;
	pLastEncryptedPart = pLastEncryptedPart;
	pulLastEncryptedPartLen = pulLastEncryptedPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * DECRYPTION FUNCTIONS
 */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	hSession = hSession;
	pEncryptedData = pEncryptedData;
	ulEncryptedDataLen = ulEncryptedDataLen;
	pData = pData;
	pulDataLen = pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	hSession = hSession;
	pEncryptedPart = pEncryptedPart;
	ulEncryptedPartLen = ulEncryptedPartLen;
	pPart = pPart;
	pulPartLen = pulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	hSession = hSession;
	pLastPart = pLastPart;
	pulLastPartLen = pulLastPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * MESSAGE DIGESTING FUNCTIONS
 */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	hSession = hSession;
	pMechanism = pMechanism;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	hSession = hSession;
	pData = pData;
	ulDataLen = ulDataLen;
	pDigest = pDigest;
	pulDigestLen = pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	hSession = hSession;
	pDigest = pDigest;
	pulDigestLen = pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/*
 * SIGNING AND MACING FUNCTIONS
 */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	session *sess = NULL;
	CK_RV rc;
	CK_BBOOL valid = FALSE;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pMechanism)
		return CKR_MECHANISM_INVALID;

	if (!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* Check for valid object handle */
	valid = is_object_handle_valid(hKey, sess->session_info.slotID);
	if (valid != TRUE)
		return CKR_OBJECT_HANDLE_INVALID;

	/* Call sign init */
	rc = sign_init(hSession, &sess->sign_ctx, pMechanism, FALSE, hKey);
	if (rc != CKR_OK)
		return rc;

	return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
	     CK_BYTE_PTR pData,
	     CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature,
	     CK_ULONG_PTR pulSignatureLen)
{
	session *sess = NULL;
	CK_RV rc;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pData || !pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* Call sign function */
	rc = sign(hSession, sess, pData, ulDataLen, pSignature,
		  pulSignatureLen);
	if (rc != CKR_OK)
		return rc;

	return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	hSession = hSession;
	pSignature = pSignature;
	pulSignatureLen = pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	hSession = hSession;
	pData = pData;
	ulDataLen = ulDataLen;
	pSignature = pSignature;
	pulSignatureLen = pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * FUNCTIONS FOR VERIFYING SIGNATURES AND MACS
 */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	hSession = hSession;
	pData = pData;
	ulDataLen = ulDataLen;
	pSignature = pSignature;
	ulSignatureLen = ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	hSession = hSession;
	pSignature = pSignature;
	ulSignatureLen = ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen,
		      CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	hSession = hSession;
	pSignature = pSignature;
	ulSignatureLen = ulSignatureLen;
	pData = pData;
	pulDataLen = pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * DUAL-FUNCTION CRYPTOGRAPHIC FUNCTIONS
 */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;
	pEncryptedPart = pEncryptedPart;
	pulEncryptedPartLen = pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	hSession = hSession;
	pEncryptedPart = pEncryptedPart;
	ulEncryptedPartLen = ulEncryptedPartLen;
	pPart = pPart;
	pulPartLen = pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen,
			  CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;
	pEncryptedPart = pEncryptedPart;
	pulEncryptedPartLen = pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	hSession = hSession;
	pEncryptedPart = pEncryptedPart;
	ulEncryptedPartLen = ulEncryptedPartLen;
	pPart = pPart;
	pulPartLen = pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * KEY MANAGEMENT FUNCTIONS
 */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	pTemplate = pTemplate;
	ulCount = ulCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	pPublicKeyTemplate = pPublicKeyTemplate;
	ulPublicKeyAttributeCount = ulPublicKeyAttributeCount;
	pPrivateKeyTemplate = pPrivateKeyTemplate;
	ulPrivateKeyAttributeCount = ulPrivateKeyAttributeCount;
	phPublicKey = phPublicKey;
	phPrivateKey = phPrivateKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hWrappingKey = hWrappingKey;
	hKey = hKey;
	pWrappedKey = pWrappedKey;
	pulWrappedKeyLen = pulWrappedKeyLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey,
		  CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hUnwrappingKey = hUnwrappingKey;
	pWrappedKey = pWrappedKey;
	ulWrappedKeyLen = ulWrappedKeyLen;
	pTemplate = pTemplate;
	ulAttributeCount = ulAttributeCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hBaseKey = hBaseKey;
	pTemplate = pTemplate;
	ulAttributeCount = ulAttributeCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * RANDOM NUMBER GENERATOR FUNCTIONS
 */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	hSession = hSession;
	pSeed = pSeed;
	ulSeedLen = ulSeedLen;
	return CKR_RANDOM_NO_RNG;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
		       CK_ULONG ulRandomLen)
{
	hSession = hSession;
	RandomData = RandomData;
	ulRandomLen = ulRandomLen;
	return CKR_RANDOM_NO_RNG;
}
