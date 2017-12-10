#ifndef ___SESSIONS_H_INC___
#define ___SESSIONS_H_INC___

#include <objects.h>

typedef struct _session {
	CK_SESSION_INFO		session_info;
	CK_OBJECT_HANDLE_PTR	find_list;
	CK_ULONG		find_count;
	CK_ATTRIBUTE_PTR	find_template;
	CK_BBOOL		op_active;
	//SIGN_VERIFY_CONTEXT  sign_ctx; will be added with Crypto related APIs
} session;

/* The number of supported slots */
#define SLOT_COUNT 1

struct slot_info {
	CK_SLOT_ID 	slot_id;
	struct object_list	obj_list;
};

session *get_session(CK_SESSION_HANDLE hSession);

CK_BBOOL is_session_valid(CK_SESSION_HANDLE hSession);

CK_RV create_session(CK_SLOT_ID slotID,  CK_FLAGS flags,
		CK_SESSION_HANDLE_PTR phSession);

CK_RV delete_session(CK_SESSION_HANDLE hSession);

CK_RV delete_all_session(CK_SLOT_ID slotID);

CK_RV get_session_info(CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO_PTR pInfo);

struct slot_info *get_global_slot_info(CK_SLOT_ID slotID);

#endif
