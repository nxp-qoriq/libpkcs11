#ifndef ___CRYPTO_H_INC___
#define ___CRYPTO_H_INC___

#include <sessions.h>

CK_RV sign_init(CK_SESSION_HANDLE hSession, sign_verify_context * ctx,
		CK_MECHANISM * mech, CK_BBOOL recover_mode,
		CK_OBJECT_HANDLE key);

#endif
