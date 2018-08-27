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
#define print_error(msg, ...) do { \
printf("[libpkcs11:%s, %d] Error: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
} while (0)
#else
#define print_error(msg, ...)  do { \
} while (0)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) do { \
printf("[libpkcs11:%s, %d] Info: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
} while (0)
#else
#define print_info(msg, ...)  do { \
} while (0)
#endif



#define P11_MIN(a, b)  ((a) < (b) ? (a) : (b))

#define SHA256_LEN	32
#define PIN_LEN	SHA256_LEN

struct token_data {
	CK_TOKEN_INFO	token_info;
	CK_BYTE		user_pin_hash[PIN_LEN];
	CK_BYTE		so_pin_hash[PIN_LEN];
};

struct slot_info {
	CK_SLOT_ID	slot_id;
	struct token_data	token_data;
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

CK_RV p11_init_lock(CK_C_INITIALIZE_ARGS_PTR pInitArgs);

void p11_free_lock(void);

CK_RV p11_global_lock(void);

void p11_global_unlock(void);

CK_BBOOL user_pin_initialized(CK_SLOT_ID slotID);

CK_RV token_get_so_pin(CK_SLOT_ID slotID,
			CK_UTF8CHAR_PTR pPinHash);

CK_BBOOL token_already_initialized(CK_SLOT_ID slotID);

CK_RV token_init(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);

CK_RV token_init_pin(CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

CK_RV token_set_pin(CK_SESSION_INFO_PTR pSession,
		CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
		CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

CK_RV token_load_data(CK_SLOT_ID slotID,
			struct token_data *token_data);

CK_RV token_save_data(CK_SLOT_ID slotID,
			struct token_data *token_data);
#endif
