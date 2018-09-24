/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef ___OBJECTS_H_INC___
#define ___OBJECTS_H_INC___

#include <sys/queue.h>
#include <securekey_api_types.h>

#define MAX_FIND_LIST_OBJECTS  100

#define OP_GENERATE	0
#define OP_CREATE	1

/* Attributes in each objects are maintained as template nodes */
struct template_node {
	CK_ATTRIBUTE_PTR		attributes;
	STAILQ_ENTRY(template_node)	entry;
};
STAILQ_HEAD(template_list, template_node);

/* Objects */
typedef struct object{
	/* Securkey object handle */
	SK_OBJECT_HANDLE	sk_obj_handle;
	/* PKCS object class */
	CK_OBJECT_CLASS		obj_class;
	/* PKCS object subclass e.g. obj_class = CKO_PUBLIC_KEY and
	  * obj_subclass = SKK_RSA*/
	CK_ULONG		obj_subclass;
	/* List containing the templates associated with this object */
	struct template_list	template_list;
	/* Token/Slot ID with which this object is associated */
	CK_SLOT_ID		slotID;
} OBJECT;

/* Objects are maintained as list of object_node */
struct object_node {
	OBJECT object;
	STAILQ_ENTRY(object_node) entry;
};
STAILQ_HEAD(object_list, object_node);

struct object_list *get_object_list(CK_SLOT_ID slotID);

CK_BBOOL is_object_handle_valid(CK_OBJECT_HANDLE hObject,
		CK_SLOT_ID slotID);

CK_RV get_all_token_objects(struct object_list *obj_list,
		CK_SLOT_ID slotID);

CK_RV destroy_object_list(CK_SLOT_ID slotID);

CK_RV initialize_object_list(CK_SLOT_ID slotID);

CK_RV
template_destroy_template_list(struct template_list *template);

CK_RV
template_check_required_attributes(
				struct template_list *template,
				CK_ULONG class,
				CK_ULONG subclass,
				CK_ULONG op_type);

CK_RV
template_validate_attributes(struct template_list *template,
				CK_ULONG class, CK_ULONG subclass,
				CK_ULONG op_type);

CK_BBOOL p11_template_compare(CK_ATTRIBUTE *t1,
				CK_ULONG ulCount,
				struct template_list *tmpl_list);

CK_RV find_matching_objects(CK_OBJECT_HANDLE_PTR object_handle,
	struct object_list *obj_list, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_ULONG *pobjCount);

CK_RV get_attr_value(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount);

CK_RV
attribute_validate_base_attributes(CK_ATTRIBUTE *attr,
				CK_ULONG op_type);

CK_RV objects_generate_key_pair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV template_check_consistency(
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount);

CK_BBOOL p11_template_attribute_find(
				struct template_list *template,
				CK_ATTRIBUTE_TYPE type,
				CK_ATTRIBUTE **attr);

CK_RV
template_create_template_list(CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount,
			struct template_list **tmpl_list);

CK_BBOOL object_is_destroyable(CK_OBJECT_HANDLE hObject);

CK_BBOOL object_is_private(CK_OBJECT_HANDLE hObject);

CK_BBOOL
template_is_modifiable_set(struct template_list *template);

CK_BBOOL template_is_private_set(struct template_list *template);

CK_BBOOL template_is_public_set(struct template_list *template);

CK_BBOOL
template_is_token_object(struct template_list *template);

CK_BBOOL
template_is_session_object(struct template_list *template);

CK_RV destroy_object(CK_OBJECT_HANDLE hObject,
			CK_SLOT_ID slotID);
CK_BBOOL p11_template_get_class(struct template_list *tmpl_list,
	CK_ULONG *class, CK_ULONG *subclass);

CK_RV objects_create_object(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount,
			CK_OBJECT_HANDLE_PTR phObject);
#endif
