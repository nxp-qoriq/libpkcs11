/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <cryptoki.h>
#include <string.h>


CK_RV Get_TEE_SlotInfo(CK_SLOT_INFO_PTR pInfo);
CK_RV Get_TEE_TokenInfo(CK_TOKEN_INFO_PTR pInfo);
CK_RV Get_TEE_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount);
CK_RV Get_TEE_MechanismInfo(CK_MECHANISM_TYPE type,
			CK_MECHANISM_INFO_PTR pInfo);

#define MAX_MECHANISM_COUNT	16

struct mechanisms {
	CK_MECHANISM_TYPE algo ;
	CK_MECHANISM_INFO info;
};

struct mechanisms tee_mechanisms[MAX_MECHANISM_COUNT] = {
{
	.algo =     CKM_MD5,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_DIGEST
	}
},
{
	.algo =     CKM_SHA_1,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_DIGEST
	}
},
{
	.algo =     CKM_SHA256,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_DIGEST
	}
},
{
	.algo =     CKM_SHA384,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_DIGEST
	}
},
{
	.algo =     CKM_SHA512,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_DIGEST
	}
},
{
	.algo =     CKM_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN | CKF_DECRYPT
	}
},
{
	.algo =     CKM_MD5_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_SHA1_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_SHA256_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_SHA384_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_SHA512_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_ECDSA_SHA1,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 384,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_ECDSA,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 384,
		.flags = CKF_SIGN
	}
},
{
	.algo =     CKM_RSA_PKCS_KEY_PAIR_GEN,
	.info = {
		.ulMinKeySize = 1024,
		.ulMaxKeySize = 2048,
		.flags = CKF_GENERATE_KEY_PAIR
	}
},
{
	.algo =     CKM_EC_KEY_PAIR_GEN,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 384,
		.flags = CKF_GENERATE_KEY_PAIR
	}
},
{
	.algo =     CKM_RSA_PKCS_OAEP,
	.info = {
		.ulMinKeySize = 1024,
		.ulMaxKeySize = 2048,
		.flags = CKF_DECRYPT
	}
}
};

CK_RV Get_TEE_SlotInfo(CK_SLOT_INFO_PTR pInfo)
{
	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	strncpy((char *)pInfo->slotDescription, "TEE_BASED_SLOT",
		strlen("TEE_BASED_SLOT"));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	strncpy((char *)pInfo->manufacturerID, "NXP", strlen("NXP"));

	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;

	return CKR_OK;
}

CK_RV Get_TEE_TokenInfo(CK_TOKEN_INFO_PTR pInfo)
{
	memset(pInfo->label, ' ', sizeof(pInfo->label));
	strncpy((char *)pInfo->label, "TEE_BASED_TOKEN",
		strlen("TEE_BASED_TOKEN"));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	strncpy((char *)pInfo->manufacturerID, "NXP", strlen("NXP"));

	memset(pInfo->model, ' ', sizeof(pInfo->model));
	strncpy((char *)pInfo->model, "PKCS11-OP-TEE",
		strlen("PKCS11-OP-TEE"));

	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	strncpy((char *)pInfo->serialNumber, "1", strlen("1"));

	pInfo->flags = 0;
	pInfo->ulMaxSessionCount = 10;
	pInfo->ulSessionCount = 0;
	pInfo->ulMaxRwSessionCount = 5;
	pInfo->ulRwSessionCount = 0;
	pInfo->ulMaxPinLen = 8;
	pInfo->ulMinPinLen = 4;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;
	memset(pInfo->utcTime, '0', sizeof(pInfo->utcTime));

	return CKR_OK;
}

CK_RV Get_TEE_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	unsigned int i;
	CK_RV rc = CKR_OK;

	if (pMechanismList == NULL)
		goto end;

	if (*pulCount < MAX_MECHANISM_COUNT) {
		rc =  CKR_BUFFER_TOO_SMALL;
		goto end;
	}

	for (i = 0; i < MAX_MECHANISM_COUNT; i++) {
		pMechanismList[i] = tee_mechanisms[i].algo;
	}

end:
	*pulCount = MAX_MECHANISM_COUNT;
	return rc;
}

CK_RV Get_TEE_MechanismInfo(CK_MECHANISM_TYPE type,
			CK_MECHANISM_INFO_PTR pInfo)
{
	unsigned int i, found = 0;

	for (i = 0; i < MAX_MECHANISM_COUNT; i++) {
		if (type == tee_mechanisms[i].algo) {
			memcpy(pInfo, &tee_mechanisms[i].info, sizeof(CK_MECHANISM_INFO));
			found = 1;
			break;
		}
	}

	if (found)
		return CKR_OK;
	else
		return CKR_MECHANISM_INVALID;
}

