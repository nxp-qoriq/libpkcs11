#ifndef ___TEE_SLOT_H_INC___
#define ___TEE_SLOT_H_INC___

#include <cryptoki.h>

/* the slot id that we will assign to the TEE */
#define TEE_SLOT_ID 0

CK_RV Get_TEE_SlotInfo(CK_SLOT_INFO_PTR pInfo);
CK_RV Get_TEE_TokenInfo(CK_TOKEN_INFO_PTR pInfo);
CK_RV Get_TEE_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount);
CK_RV Get_TEE_MechanismInfo(CK_MECHANISM_TYPE type,
			CK_MECHANISM_INFO_PTR pInfo);

#endif
