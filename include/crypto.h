/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef ___CRYPTO_H_INC___
#define ___CRYPTO_H_INC___

#include <sessions.h>

#define MAX_RSA_KEYLEN	512

/* RSA block formatting types */
#define RSA_PKCS_BT_1	1
#define RSA_PKCS_BT_2	2

CK_RV sign_init(CK_SESSION_HANDLE hSession, sign_verify_context * ctx,
		CK_MECHANISM * mech, CK_BBOOL recover_mode,
		CK_OBJECT_HANDLE key);

CK_RV sign(CK_SESSION_HANDLE hSession, session *sess, CK_BYTE_PTR pData,
	   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	   CK_ULONG_PTR pulSignatureLen);

#endif
