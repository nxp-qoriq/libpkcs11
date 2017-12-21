/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef ___GENERAL_H_INC___
#define ___GENERAL_H_INC___

#include <cryptoki.h>
#include <sessions.h>
#include <objects.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

#define	PRINT_ERROR

#ifdef PRINT_ERROR
#define print_error(msg, ...) { \
printf("[libpkcs11:%s, %d] Error: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_error(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) { \
printf("[libpkcs11:%s, %d] Info: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_info(msg, ...)
#endif


#define P11_MIN(a, b)  ((a) < (b) ? (a) : (b))

struct slot_info {
	CK_SLOT_ID 	slot_id;
	struct object_list	obj_list;
	struct session_list	sess_list;
	SK_FUNCTION_LIST  *sk_funcs;
	void	*shared_lib_handle;
};

CK_BBOOL is_lib_initialized(void);

void pkcs_lib_init(void);

void pkcs_lib_finish(void);

CK_RV initialize_slot(CK_SLOT_ID slotID);

CK_RV destroy_slot(CK_SLOT_ID slotID);

#endif
