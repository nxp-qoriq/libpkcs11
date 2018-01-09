/*
 * Copyright 2017 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#define UL_INVALID 0xFFFFFFFE
#define UL_UNINTZD 0xFFFFFFFF
#define MAX_FIND_OBJ_SIZE 10

#define PERFORM 1
#define PARSE 2

#define ENABLE 1
#define DISABLE 0

#define APP_OK 0
#define APP_IN_ERR -2
#define APP_LIB_ERR -3
#define APP_CKR_ERR -4
#define APP_MALLOC_FAIL -5
#define APP_PEM_READ_ERROR -6
#define APP_IP_ERR -7
#define APP_OPSSL_KEY_GEN_ERR -8
#define APP_FILE_ERR -9

char *p11_get_error_string(CK_RV rc);
void dump_sess_info(CK_SESSION_INFO *info);
char *getMechanismString(CK_MECHANISM_TYPE mechanismID);
char *getMechCapString(CK_FLAGS flag_value);
CK_ULONG getMechanismCap(CK_FLAGS flags, CK_ULONG *mechanismCap);
char *getKeyTypeString(CK_KEY_TYPE key_type);
char *getClassString(CK_OBJECT_CLASS obj_type);
CK_OBJECT_CLASS getClassID(char *objTypeStr);

CK_KEY_TYPE getKeyType(char *keyTypeStr);
CK_MECHANISM_TYPE getMechId(char *mechIdStr);

int validate_key_len(uint32_t key_len);

#endif /*__UTILS_H__*/
