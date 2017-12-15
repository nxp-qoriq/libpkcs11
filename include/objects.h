#ifndef ___OBJECTS_H_INC___
#define ___OBJECTS_H_INC___

#include <sys/queue.h>
#include <securekey_api_types.h>

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

CK_RV get_all_token_objects(struct object_list *obj_list);

CK_RV destroy_object_list(CK_SLOT_ID slotID);

CK_RV initialize_object_list(CK_SLOT_ID slotID);

CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount,
		struct template_list *tmpl_list);

CK_RV find_matching_objects(CK_OBJECT_HANDLE_PTR object_handle,
	struct object_list *obj_list, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_ULONG *pobjCount);

CK_RV get_attribute_value(struct object_node *obj,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount);
#endif
