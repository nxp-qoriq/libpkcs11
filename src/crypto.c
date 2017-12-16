#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cryptoki.h>
#include <crypto.h>

/* Init for sign mechanism */
CK_RV sign_init(CK_SESSION_HANDLE hSession, sign_verify_context *ctx,
		CK_MECHANISM *mech, CK_BBOOL recover_mode,
		CK_OBJECT_HANDLE key)
{
	CK_ATTRIBUTE attr[4] = {0};
	CK_BYTE *ptr = NULL;
	CK_KEY_TYPE keytype;
	CK_OBJECT_CLASS class;
	CK_BBOOL sign = FALSE, found = FALSE;
	CK_MECHANISM_TYPE_PTR obj_mechanisms;
	CK_ULONG n;
	CK_RV rc;

	if (ctx->active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto out;
	}

	/* Get all object attributes needed */
	attr[0].type = CKA_SIGN;
	attr[1].type = CKA_ALLOWED_MECHANISMS;
	attr[2].type = CKA_KEY_TYPE;
	attr[3].type = CKA_CLASS;
	rc = C_GetAttributeValue(hSession, key, attr, 4);
	if (rc != CKR_OK)
		goto out;
	obj_mechanisms =
		(CK_MECHANISM_TYPE_PTR)malloc(sizeof(CK_MECHANISM_TYPE)
					      * attr[1].ulValueLen);
	if (!obj_mechanisms) {
		rc = CKR_HOST_MEMORY;
		goto out;
	}
	attr[0].pValue = &sign;
	attr[1].pValue = obj_mechanisms;
	attr[2].pValue = &keytype;
	attr[3].pValue = &class;
	rc = C_GetAttributeValue(hSession, key, attr, 4);
	if (rc != CKR_OK)
		goto out;

	/* Check if object can support sign mechanism */
	if (sign != TRUE) {
		rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto out;
	}

	/* Check if object can support sign mechanism type */
	for (n = 0; n < attr[1].ulValueLen; n++) {
		if (mech->mechanism ==
			*((CK_MECHANISM_TYPE_PTR)attr[1].pValue + n)) {
			found = TRUE;
			break;
		}
	}
	if (found != TRUE) {
		rc = CKR_MECHANISM_INVALID;
		goto out;
	}

	/* Check for key attributes if they match with mechanism provided */
	switch (mech->mechanism) {
	case CKM_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		if (mech->ulParameterLen != 0) {
			rc = CKR_MECHANISM_PARAM_INVALID;
			goto out;
		}
		/* Key type must be RSA */
		if (keytype != CKK_RSA) {
			rc = CKR_KEY_TYPE_INCONSISTENT;
			goto out;
		}
		/* Key class must be Private */
		if (class != CKO_PRIVATE_KEY) {
			rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
			goto out;
		}
		/* Currently we don't support multi-part RSA ops */
		ctx->context_len = 0;
		ctx->context     = NULL;
		break;

	default:
		rc = CKR_MECHANISM_INVALID;
		goto out;
	}

	if (mech->ulParameterLen > 0) {
		ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
		if (!ptr) {
			rc = CKR_HOST_MEMORY;
			goto out;
		}
		memcpy(ptr, mech->pParameter, mech->ulParameterLen);
	}

	/* Keeping the sign information in session ctx */
	ctx->key                 = key;
	ctx->mech.ulParameterLen = mech->ulParameterLen;
	ctx->mech.mechanism      = mech->mechanism;
	ctx->mech.pParameter     = ptr;
	ctx->multi               = FALSE;
	ctx->active              = TRUE;
	ctx->recover             = recover_mode;

out:
	if (obj_mechanisms)
		free(obj_mechanisms);

	return rc;
}
