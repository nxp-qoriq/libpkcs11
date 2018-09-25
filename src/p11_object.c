/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include "cryptoki.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <general.h>
#include <tee_slot.h>
#include <sessions.h>
#include <objects.h>

/*
 * OBJECT MANAGEMENT FUNCTIONS
 */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	session *sess = NULL;
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (!pTemplate || !phObject) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (!pTemplate && (ulCount != 0)) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	rc = objects_create_object(hSession, pTemplate,
			ulCount, phObject);

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phNewObject)
{
	hSession = hSession;
	hObject = hObject;
	pTemplate = pTemplate;
	ulCount = ulCount;
	phNewObject = phNewObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rc = CKR_OK;
	session *sess = NULL;
	CK_BBOOL destroyable = CK_FALSE;
	CK_BBOOL private = CK_FALSE;

	print_info("hSession = 0x%lx , hObject = 0x%lx\n",
			hSession, hObject);

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	destroyable = object_is_destroyable(hObject);
	if (!destroyable) {
		rc = CKR_ACTION_PROHIBITED;
		goto end;
	}

	private = object_is_private(hObject);
	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (private) {
		if (sess->session_info.state != CKS_RW_USER_FUNCTIONS)
			return CKR_USER_NOT_LOGGED_IN;
	}

	rc = destroy_object(hObject, sess->session_info.slotID);
	if (rc != CKR_OK)
		print_error("delete session failed\n");

end:
	p11_global_unlock();
	return rc;

}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	hSession = hSession;
	hObject = hObject;
	pulSize = pulSize;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	CK_RV rc = CKR_OK;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	rc = get_attr_value(hSession, hObject, pTemplate, ulCount);

end:
	p11_global_unlock();

	return rc;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	hSession = hSession;
	hObject = hObject;
	pTemplate = pTemplate;
	ulCount = ulCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	session *sess = NULL;
	CK_RV rc = CKR_OK;
	CK_ULONG objCount;
	struct object_list *obj_list;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if (pTemplate == NULL && ulCount > 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if(!is_session_valid(hSession)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (sess->op_active == CK_TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		goto end;
	}

	/*
	* Mainitaining the object list per slot/token
	* Getting all the token objects in the first C_FindObjectsInit
	* and then returning the objects from this list only.
	* Not going again to Securekey libraryfor any objects.
	*/
	obj_list = get_object_list(sess->session_info.slotID);
	if (!obj_list) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (STAILQ_EMPTY(obj_list)) {
		rc = get_all_token_objects(obj_list,
			sess->session_info.slotID);
		if (rc != CKR_OK) {
			print_error("get_all_token_objects failed\n");
			goto end;
		}
	}

	/*
	* Keeping the find_list in session, which will be filled with object
	* handle matching the template passed.
	* Currently supporting maximum of 50 objects.
	*/
	if (sess->find_list == NULL) {
		sess->find_list = (CK_OBJECT_HANDLE *)malloc(MAX_FIND_LIST_OBJECTS * sizeof(CK_OBJECT_HANDLE));
		if (!sess->find_list){
			print_error("sess->find_list malloc failed\n");
			rc = CKR_HOST_MEMORY;
			goto end;
		} else
			memset(sess->find_list, 0x0, MAX_FIND_LIST_OBJECTS * sizeof(CK_OBJECT_HANDLE));
	}

	if ((sess->session_info.state == CKS_RW_USER_FUNCTIONS) ||
		(sess->session_info.state == CKS_RO_USER_FUNCTIONS)) {
		if  (ulCount == 0) {
			/*
			* Filling the sess->find_list with all objects in that
			* token object list.
			*/
			find_matching_objects(sess->find_list, obj_list,
				NULL, 0, &objCount, 1);
			sess->find_count = objCount;
		} else {
			/*
			* Filling the sess->find_list with only objects matching
			* template passed from token object list.
			*/
			find_matching_objects(sess->find_list, obj_list,
				pTemplate, ulCount, &objCount, 1);
			sess->find_count = objCount;
		}
	} else {
		if  (ulCount == 0) {
			/*
			* Filling the sess->find_list with all objects in that
			* token object list.
			*/
			find_matching_objects(sess->find_list, obj_list,
				NULL, 0, &objCount, 0);
			sess->find_count = objCount;
		} else {
			/*
			* Filling the sess->find_list with only objects matching
			* template passed from token object list.
			*/
			find_matching_objects(sess->find_list, obj_list,
				pTemplate, ulCount, &objCount, 0);
			sess->find_count = objCount;
		}
	}

	sess->find_idx = 0;
	sess->op_active = CK_TRUE;

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount,
		CK_ULONG_PTR pulObjectCount)
{
	CK_RV rc = CKR_OK;
	session *sess = NULL;
	CK_ULONG count = 0;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if(!is_session_valid(hSession)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (sess->op_active == CK_FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto end;
	}

	if (!phObject || !pulObjectCount) {
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	count = P11_MIN(ulMaxObjectCount,
		(sess->find_count - sess->find_idx));

	if (count)
		memcpy(phObject, sess->find_list + sess->find_idx,
			count * sizeof(CK_OBJECT_HANDLE));
	*pulObjectCount = count;

	sess->find_idx += count;

end:
	p11_global_unlock();
	return rc;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rc = CKR_OK;
	session *sess = NULL;

	p11_global_lock();

	if (!is_lib_initialized()) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto end;
	}

	if(!is_session_valid(hSession)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	if (sess->op_active == CK_FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto end;
	}

	sess->op_active = CK_FALSE;
	sess->find_count = 0;
	sess->find_idx = 0;
	if (sess->find_list) {
		memset(sess->find_list, 0, sizeof(CK_OBJECT_HANDLE) *
			MAX_FIND_LIST_OBJECTS);
		free(sess->find_list);
	}

end:
	p11_global_unlock();
	return rc;
}
