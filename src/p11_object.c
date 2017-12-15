#include "cryptoki.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <general.h>
#include <tee_slot.h>
#include <sessions.h>
#include <objects.h>

#define MAX_FIND_LIST_OBJECTS	50
/*
 * OBJECT MANAGEMENT FUNCTIONS
 */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	hSession = hSession;
	pTemplate = pTemplate;
	ulCount = ulCount;
	phObject = phObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	hSession = hSession;
	hObject = hObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
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
	session *sess = NULL;
 	struct object_node *obj_node;
	CK_BBOOL is_obj_handle_valid;
 
	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL)
		return CKR_ARGUMENTS_BAD;

	if (ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if(!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	is_obj_handle_valid = is_object_handle_valid(hObject,
		sess->session_info.slotID);
	if (!is_obj_handle_valid)
		return CKR_OBJECT_HANDLE_INVALID;

	obj_node = (struct object_node *)hObject;

	return get_attribute_value(obj_node, pTemplate, ulCount);
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
	CK_RV rc;
	CK_ULONG objCount;
	struct object_list *obj_list;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL && ulCount > 0)
		return CKR_ARGUMENTS_BAD;

	if(!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->op_active == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	/*
	* Mainitaining the object list per slot/token
	* Getting all the token objects in the first C_FindObjectsInit
	* and then returning the objects from this list only.
	* Not going again to Securekey libraryfor any objects.
	*/
	obj_list = get_object_list(sess->session_info.slotID);
	if (!obj_list)
		return CKR_ARGUMENTS_BAD;

	if (STAILQ_EMPTY(obj_list)) {
		rc = get_all_token_objects(obj_list);
		if (rc != CKR_OK) {
			printf("get_all_token_objects failed\n");
			return rc;
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
			printf("sess->find_list malloc failed\n");
			return CKR_HOST_MEMORY;
		} else
			memset(sess->find_list, 0x0, MAX_FIND_LIST_OBJECTS * sizeof(CK_OBJECT_HANDLE));
	}

	if  (ulCount == 0) {
		/*
		* Filling the sess->find_list with all objects in that
		* token object list.
		*/
		find_matching_objects(sess->find_list, obj_list,
			NULL, 0, &objCount);
		sess->find_count = objCount;
	} else {
		/*
		* Filling the sess->find_list with only objects matching
		* template passed from token object list.
		*/
		find_matching_objects(sess->find_list, obj_list,
			pTemplate, ulCount, &objCount);
		sess->find_count = objCount;
	}

	sess->op_active = CK_TRUE;

	return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount,
		CK_ULONG_PTR pulObjectCount)
{
	session *sess = NULL;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->op_active == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	if (ulMaxObjectCount < sess->find_count)
		return CKR_ARGUMENTS_BAD;

	memcpy(phObject, sess->find_list, (sess->find_count * sizeof(CK_OBJECT_HANDLE)));
	*pulObjectCount = sess->find_count;

	return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	session *sess = NULL;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!is_session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	sess = get_session(hSession);
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->op_active == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->op_active = CK_FALSE;
	sess->find_count = 0;
	memset(sess->find_list, 0, sizeof(CK_OBJECT_HANDLE) *
		MAX_FIND_LIST_OBJECTS);
	free(sess->find_list);

	return CKR_OK;
}
