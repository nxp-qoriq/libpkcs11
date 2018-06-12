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
#include "utils.h"

CK_FUNCTION_LIST  *funcs;

#define err2str(X)     case X: return #X

/*p11_get_error_string - return textual interpretation of a CKR_ error code
 * @rc is the CKR_.. error
 */

char *p11_get_error_string(CK_RV rc)
{
	switch (rc) {
		err2str(CKR_OK);
		err2str(CKR_CANCEL);
		err2str(CKR_HOST_MEMORY);
		err2str(CKR_SLOT_ID_INVALID);
		err2str(CKR_GENERAL_ERROR);
		err2str(CKR_FUNCTION_FAILED);
		err2str(CKR_ARGUMENTS_BAD);
		err2str(CKR_NO_EVENT);
		err2str(CKR_NEED_TO_CREATE_THREADS);
		err2str(CKR_CANT_LOCK);
		err2str(CKR_ATTRIBUTE_READ_ONLY);
		err2str(CKR_ATTRIBUTE_SENSITIVE);
		err2str(CKR_ATTRIBUTE_TYPE_INVALID);
		err2str(CKR_ATTRIBUTE_VALUE_INVALID);
		err2str(CKR_DATA_INVALID);
		err2str(CKR_DATA_LEN_RANGE);
		err2str(CKR_DEVICE_ERROR);
		err2str(CKR_DEVICE_MEMORY);
		err2str(CKR_DEVICE_REMOVED);
		err2str(CKR_ENCRYPTED_DATA_INVALID);
		err2str(CKR_ENCRYPTED_DATA_LEN_RANGE);
		err2str(CKR_FUNCTION_CANCELED);
		err2str(CKR_FUNCTION_NOT_PARALLEL);
		err2str(CKR_FUNCTION_NOT_SUPPORTED);
		err2str(CKR_KEY_HANDLE_INVALID);
		err2str(CKR_KEY_SIZE_RANGE);
		err2str(CKR_KEY_TYPE_INCONSISTENT);
		err2str(CKR_KEY_NOT_NEEDED);
		err2str(CKR_KEY_CHANGED);
		err2str(CKR_KEY_NEEDED);
		err2str(CKR_KEY_INDIGESTIBLE);
		err2str(CKR_KEY_FUNCTION_NOT_PERMITTED);
		err2str(CKR_KEY_NOT_WRAPPABLE);
		err2str(CKR_KEY_UNEXTRACTABLE);
		err2str(CKR_MECHANISM_INVALID);
		err2str(CKR_MECHANISM_PARAM_INVALID);
		err2str(CKR_OBJECT_HANDLE_INVALID);
		err2str(CKR_OPERATION_ACTIVE);
		err2str(CKR_OPERATION_NOT_INITIALIZED);
		err2str(CKR_PIN_INCORRECT);
		err2str(CKR_PIN_INVALID);
		err2str(CKR_PIN_LEN_RANGE);
		err2str(CKR_PIN_EXPIRED);
		err2str(CKR_PIN_LOCKED);
		err2str(CKR_SESSION_CLOSED);
		err2str(CKR_SESSION_COUNT);
		err2str(CKR_SESSION_HANDLE_INVALID);
		err2str(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
		err2str(CKR_SESSION_READ_ONLY);
		err2str(CKR_SESSION_EXISTS);
		err2str(CKR_SESSION_READ_ONLY_EXISTS);
		err2str(CKR_SESSION_READ_WRITE_SO_EXISTS);
		err2str(CKR_SIGNATURE_INVALID);
		err2str(CKR_SIGNATURE_LEN_RANGE);
		err2str(CKR_TEMPLATE_INCOMPLETE);
		err2str(CKR_TEMPLATE_INCONSISTENT);
		err2str(CKR_TOKEN_NOT_PRESENT);
		err2str(CKR_TOKEN_NOT_RECOGNIZED);
		err2str(CKR_TOKEN_WRITE_PROTECTED);
		err2str(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
		err2str(CKR_UNWRAPPING_KEY_SIZE_RANGE);
		err2str(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
		err2str(CKR_USER_ALREADY_LOGGED_IN);
		err2str(CKR_USER_NOT_LOGGED_IN);
		err2str(CKR_USER_PIN_NOT_INITIALIZED);
		err2str(CKR_USER_TYPE_INVALID);
		err2str(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
		err2str(CKR_USER_TOO_MANY_TYPES);
		err2str(CKR_WRAPPED_KEY_INVALID);
		err2str(CKR_WRAPPED_KEY_LEN_RANGE);
		err2str(CKR_WRAPPING_KEY_HANDLE_INVALID);
		err2str(CKR_WRAPPING_KEY_SIZE_RANGE);
		err2str(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
		err2str(CKR_RANDOM_SEED_NOT_SUPPORTED);
		err2str(CKR_RANDOM_NO_RNG);
		err2str(CKR_BUFFER_TOO_SMALL);
		err2str(CKR_SAVED_STATE_INVALID);
		err2str(CKR_INFORMATION_SENSITIVE);
		err2str(CKR_STATE_UNSAVEABLE);
		err2str(CKR_CRYPTOKI_NOT_INITIALIZED);
		err2str(CKR_CRYPTOKI_ALREADY_INITIALIZED);
		err2str(CKR_MUTEX_BAD);
		err2str(CKR_MUTEX_NOT_LOCKED);
	default:
		return "UNKNOWN";
	}
}

CK_MECHANISM_TYPE getMechId(char *mechIdStr)
{
	if (mechIdStr == NULL)
		return UL_INVALID;
	else if (strcmp(mechIdStr, "rsa") == 0)
		return CKM_RSA_PKCS;
	else if (strcmp(mechIdStr, "md5-rsa") == 0)
		return CKM_MD5_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha1-rsa") == 0)
		return CKM_SHA1_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha256-rsa") == 0)
		return CKM_SHA256_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha384-rsa") == 0)
		return CKM_SHA384_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha512-rsa") == 0)
		return CKM_SHA512_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha224-rsa") == 0)
		return CKM_SHA224_RSA_PKCS;
	else if (strcmp(mechIdStr, "sha1-ec") == 0)
		return CKM_ECDSA_SHA1;
	else if (strcmp(mechIdStr, "ec") == 0)
		return CKM_ECDSA;

	printf("Unsupported Mechnism: %s\n", mechIdStr);
	return UL_INVALID;
}

char *getMechanismString(CK_MECHANISM_TYPE mechanismID)
{
	switch (mechanismID) {
	case CKM_RSA_PKCS:
		return "CKM_RSA_PKCS";
	case CKM_MD5_RSA_PKCS:
		return "CKM_MD5_RSA_PKCS";
	case CKM_SHA1_RSA_PKCS:
		return "CKM_SHA1_RSA_PKCS";
	case CKM_SHA256_RSA_PKCS:
		return "CKM_SHA256_RSA_PKCS";
	case CKM_SHA384_RSA_PKCS:
		return "CKM_SHA384_RSA_PKCS";
	case CKM_SHA512_RSA_PKCS:
		return "CKM_SHA512_RSA_PKCS";
	case CKM_SHA224_RSA_PKCS:
		return "CKM_SHA224_RSA_PKCS";
	case CKM_ECDSA_SHA1:
		return "CKM_ECDSA_SHA1";
	case CKM_ECDSA:
		return "CKM_ECDSA";

	default:
		return NULL;
	}
}

char *getMechCapString(CK_FLAGS flag_value)
{
	switch (flag_value) {
	case CKF_ENCRYPT:
		return "CKF_ENCRYPT";
	case CKF_DECRYPT:
		return "CKF_DERYPT";
	case CKF_DIGEST:
		return "CKF_DIGEST";
	case CKF_SIGN:
		return "CKF_SIGN";
	case CKF_SIGN_RECOVER:
		return "CKF_SIGN_RECOVER";
	case CKF_VERIFY:
		return "CKF_VERIFY";
	case CKF_VERIFY_RECOVER:
		return "CKF_VERIFY_RECOVER";
	case CKF_GENERATE:
		return "CKF_GENERATE";
	case CKF_GENERATE_KEY_PAIR:
		return "CKF_GENERATE_KEY_PAIR";
	case CKF_WRAP:
		return "CKF_WRAP";
	case CKF_UNWRAP:
		return "CKF_UNWRAP";
	case CKF_DERIVE:
		return "CKF_DERIVE";
	default:
		return NULL;
	}
}

CK_ULONG getMechanismCap(CK_FLAGS flags, CK_ULONG *mechanismCap)
{
	CK_ULONG i;
	CK_FLAGS flagBitInfo[] = {
		CKF_ENCRYPT,
		CKF_DECRYPT,
		CKF_DIGEST,
		CKF_SIGN,
		CKF_SIGN_RECOVER,
		CKF_VERIFY,
		CKF_VERIFY_RECOVER,
		CKF_GENERATE,
		CKF_GENERATE_KEY_PAIR,
		CKF_WRAP,
		CKF_UNWRAP,
		CKF_DERIVE,
	};
	for (i = 0; i < sizeof(flagBitInfo)/sizeof(CK_FLAGS); i++) {
		if (flagBitInfo[i] & flags)
			mechanismCap[i] = flagBitInfo[i];
	}
	return i;
}

CK_KEY_TYPE getKeyType(char *keyTypeStr)
{
	if (keyTypeStr == NULL)
		return UL_INVALID;
	else if (strcmp(keyTypeStr, "rsa") == 0)
		return CKK_RSA;
	else if (strcmp(keyTypeStr, "ec") == 0)
		return CKK_EC;

	printf("Unsupported Key Type: %s\n", keyTypeStr);
	return UL_INVALID;
}

char *getKeyTypeString(CK_KEY_TYPE key_type)
{
	switch (key_type) {
	case CKK_RSA: return "CKK_RSA";
	case CKK_DSA: return "CKK_DSA";
	case CKK_DH: return "CKK_DH";
	/*case CKK_ECDSA: return "CKK_ECDSA"; Depricated */
	case CKK_EC: return "CKK_EC";
	case CKK_X9_42_DH: return "CKK_X9_42_DH";
	case CKK_KEA: return "CKK_KEA";
	case CKK_GENERIC_SECRET: return "CKK_GENERIC_SECRET";
	case CKK_RC2: return "CKK_RC2";
	case CKK_RC4: return "CKK_RC4";
	case CKK_DES: return "CKK_DES";
	case CKK_DES2: return "CKK_DES2";
	case CKK_DES3: return "CKK_DES3";
	case CKK_CAST: return "CKK_CAST";
	case CKK_CAST3: return "CKK_CAST3";
	/*case CKK_CAST5: return "CKK_CAST5"; // Depricated */
	case CKK_CAST128: return "CKK_CAST128";
	case CKK_RC5: return "CKK_RC5";
	case CKK_IDEA: return "CKK_IDEA";
	case CKK_SKIPJACK: return "CKK_SKIPJACK";
	case CKK_BATON: return "CKK_BATON";
	case CKK_JUNIPER: return "CKK_JUNIPER";
	case CKK_CDMF: return "CKK_CDMF";
	case CKK_AES: return "CKK_AES";
	case CKK_BLOWFISH: return "CKK_BLOWFISH";
	case CKK_TWOFISH: return "CKK_TWOFISH";
	case CKK_SECURID: return "CKK_SECURID";
	case CKK_HOTP: return "CKK_HOTP";
	case CKK_ACTI: return "CKK_ACTI";
	case CKK_CAMELLIA: return "CKK_CAMELLIA";
	case CKK_ARIA: return "CKK_ARIA";
	case CKK_MD5_HMAC: return "CKK_MD5_HMAC";
	case CKK_SHA_1_HMAC: return "CKK_SHA_1_HMAC";
	case CKK_RIPEMD128_HMAC: return "CKK_RIPEMD128_HMAC";
	case CKK_RIPEMD160_HMAC: return "CKK_RIPEMD160_HMAC";
	case CKK_SHA256_HMAC: return "CKK_SHA256_HMAC";
	case CKK_SHA384_HMAC: return "CKK_SHA384_HMAC";
	case CKK_SHA512_HMAC: return "CKK_SHA512_HMAC";
	case CKK_SHA224_HMAC: return "CKK_SHA224_HMAC";
	case CKK_SEED: return "CKK_SEED";
	case CKK_GOSTR3410: return "CKK_GOSTR3410";
	case CKK_GOSTR3411: return "CKK_GOSTR3411";
	case CKK_GOST28147: return "CKK_GOST28147";
	case CKK_VENDOR_DEFINED: return "CKK_VENDOR_DEFINED";
	default: return "NOT DEFINED";
	}
}

char *getClassString(CK_OBJECT_CLASS obj_type)
{
	switch (obj_type) {
	case CKO_DATA: return "CKO_DATA";
	case CKO_CERTIFICATE: return "CKO_CERTIFICATE";
	case CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY";
	case CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY";
	case CKO_SECRET_KEY: return "CKO_SECRET_KEY";
	case CKO_HW_FEATURE: return "CKO_HW_FEATURE";
	case CKO_DOMAIN_PARAMETERS: return "CKO_DOMAIN_PARAMETERS";
	case CKO_MECHANISM: return "CKO_MECHANISM";
	case CKO_OTP_KEY: return "CKO_OTP_KEY";
	case CKO_VENDOR_DEFINED: return "CKO_VENDOR_DEFINED";
	default: return "NOT DEFINED";
	}
}

CK_OBJECT_CLASS getClassID(char *objTypeStr)
{
	if (objTypeStr == NULL)
		return UL_INVALID;
	else if (strcmp(objTypeStr, "data") == 0)
		return CKO_DATA;
	else if (!strcmp(objTypeStr, "cert"))
		return CKO_CERTIFICATE;
	else if (!strcmp(objTypeStr, "pub"))
		return CKO_PUBLIC_KEY;
	else if (!strcmp(objTypeStr, "prv"))
		return CKO_PRIVATE_KEY;
	else if (!strcmp(objTypeStr, "sec"))
		return CKO_SECRET_KEY;
	else if (!strcmp(objTypeStr, "hw"))
		return CKO_HW_FEATURE;
	else if (!strcmp(objTypeStr, "dom"))
		return CKO_DOMAIN_PARAMETERS;
	else if (!strcmp(objTypeStr, "mech"))
		return CKO_MECHANISM;
	else if (!strcmp(objTypeStr, "otp"))
		return CKO_OTP_KEY;
	else if (!strcmp(objTypeStr, "vend"))
		return CKO_VENDOR_DEFINED;

	return UL_INVALID;
}

int validate_key_len(uint32_t key_len)
{
	switch (key_len) {
	case 512:
	case 1024:
	case 2048:
		return key_len;
	default:
		printf("Unsupported Key Length = %d\n", key_len);
		return UL_INVALID;
	}
}
