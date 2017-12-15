#ifndef ___GENERAL_H_INC___
#define ___GENERAL_H_INC___

#include <cryptoki.h>
#include <sessions.h>
#include <objects.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

struct slot_info {
	CK_SLOT_ID 	slot_id;
	struct object_list	obj_list;
	struct session_list	sess_list;
	SK_FUNCTION_LIST  *sk_funcs;
};

CK_BBOOL is_lib_initialized(void);

void pkcs_lib_init(void);

void pkcs_lib_finish(void);

int get_function_list(CK_SLOT_ID slotID);

#endif
