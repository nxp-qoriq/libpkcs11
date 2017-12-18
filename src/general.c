#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <tee_slot.h>
#include <general.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

/* Flag to find if cryptoki library is initialised or not */
CK_ULONG	initialized;

static struct slot_info g_slot_info[SLOT_COUNT];

struct slot_info *get_global_slot_info(CK_SLOT_ID slotID)
{
	/* Need to change this when more slots are added */
	if (slotID != TEE_SLOT_ID)
		return NULL;

	return &g_slot_info[slotID];
}

struct SK_FUNCTION_LIST *get_slot_function_list(CK_SLOT_ID slotID)
{
	struct slot_info *s_info;

	if (slotID != TEE_SLOT_ID)
		return NULL;

	s_info = get_global_slot_info(slotID);
	if (!s_info)
		return NULL;

	return g_slot_info[slotID].sk_funcs;
}
/*
 *  GENERAL-PURPOSE FUNCTIONS
 */
void pkcs_lib_init(void)
{
	initialized = 1;
}

void pkcs_lib_finish(void)
{
	initialized = 0;
}

CK_BBOOL is_lib_initialized(void)
{
	return initialized != 0;
}

static int get_function_list(CK_SLOT_ID slotID, char *library)
{
	SK_RET_CODE	rc;
	SK_RET_CODE	(*pfoo)(SK_FUNCTION_LIST_PTR_PTR);
	void    *d;
	const char    *f = library;
	struct slot_info *s_info;

	d = dlopen(f, RTLD_NOW);
	if (d == NULL) {
		print_error("dlopen failed %s\n", dlerror());
		return FALSE;
	}

	pfoo = (SK_RET_CODE (*)(SK_FUNCTION_LIST_PTR_PTR))dlsym(d, "SK_GetFunctionList");
	if (pfoo == NULL) {
		return FALSE;
	}

	s_info = get_global_slot_info(slotID);
	if (!s_info)
		return FALSE;

	rc = pfoo(&s_info->sk_funcs);
	if (rc != SKR_OK) {
		print_error("SK_GetFunctionList rc=%u", rc);
		return FALSE;
	}

	return TRUE;

}

CK_RV initialize_slot(CK_SLOT_ID slotID)
{
	char library[20];
	CK_RV rc;

	switch (slotID) {
		case TEE_SLOT_ID:
			memcpy(library, "libsecurekey.so", sizeof("libsecurekey.so"));
			break;
		default:
			print_error("Invalid Slot ID\n");
			return CKR_ARGUMENTS_BAD;
	}

	rc = get_function_list(slotID, library);
	if (!rc) {
		print_error("get_function_list(), rc=%lu\n", rc);
		return CKR_GENERAL_ERROR;
	}

	if (initialize_object_list(slotID) != CKR_OK)
		return CKR_GENERAL_ERROR;

	if (initialize_session_list(slotID) != CKR_OK)
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}
