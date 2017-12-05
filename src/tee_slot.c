#include <stdio.h>
#include <cryptoki.h>
#include <string.h>


CK_RV Get_TEE_SlotInfo(CK_SLOT_INFO_PTR pInfo);
CK_RV Get_TEE_TokenInfo(CK_TOKEN_INFO_PTR pInfo);
CK_RV Get_TEE_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount);
CK_RV Get_TEE_MechanismInfo(CK_MECHANISM_TYPE type,
			CK_MECHANISM_INFO_PTR pInfo);

#define MAX_MECHANISM_COUNT	1

struct mechanisms {
	CK_MECHANISM_TYPE algo ;
	CK_MECHANISM_INFO info;
};

struct mechanisms tee_mechanisms[MAX_MECHANISM_COUNT] = {
{
	.algo =     CKM_RSA_PKCS,
	.info = {
		.ulMinKeySize = 512,
		.ulMaxKeySize = 2048,
		.flags = CKF_SIGN
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

	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	strncpy((char *)pInfo->serialNumber, "1", strlen("1"));

	pInfo->flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulMaxPinLen = 0;
	pInfo->ulMinPinLen = 0;
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

	if ((sizeof(pMechanismList) / sizeof(CK_MECHANISM_TYPE)) < MAX_MECHANISM_COUNT)
		return CKR_BUFFER_TOO_SMALL;

	if (pMechanismList == NULL)
		goto end;

	for (i = 0; i < MAX_MECHANISM_COUNT; i++) {
		pMechanismList[i] = tee_mechanisms[i].algo;
	}

end:
	*pulCount = MAX_MECHANISM_COUNT;
	return CKR_OK;
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

