#ifndef ___OBJECTS_H_INC___
#define ___OBJECTS_H_INC___

#include <sys/queue.h>

struct template_node {
	CK_ATTRIBUTE_PTR	attributes;
	STAILQ_ENTRY(template_node)	entry;
};
STAILQ_HEAD(template_list, template_node);

typedef struct object{
	CK_OBJECT_HANDLE	obj_handle;
	CK_OBJECT_CLASS		obj_class;
	CK_ULONG		obj_subclass;
	struct template_list	template_list;
} OBJECT;

struct object_node {
	OBJECT object;
	STAILQ_ENTRY(object_node) entry;
};
STAILQ_HEAD(object_list, object_node);

struct object_list *get_object_list(CK_SLOT_ID slotID);

struct object_node *get_object_node(CK_OBJECT_HANDLE hObject,
		CK_SLOT_ID slotID);

CK_RV get_all_token_objects(struct object_list *obj_list);

CK_RV destroy_object_list(CK_SLOT_ID slotID);

CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount,
		struct template_list *tmpl_list);

CK_RV find_matching_objects(CK_OBJECT_HANDLE_PTR object_handle,
	struct object_list *obj_list, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_ULONG *pobjCount);

CK_RV get_attribute_value(struct object_node *obj,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount);
#endif
