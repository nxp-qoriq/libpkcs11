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

static void *open_shared_lib(char *library)
{
	void *handle;

	handle = dlopen(library, RTLD_NOW);
	if (handle == NULL) {
		print_error("dlopen failed %s\n", dlerror());
		return NULL;
	}

	return handle;
}

static void close_shared_lib(void *handle)
{
	if (handle)
		dlclose(handle);
}

static int get_function_list(CK_SLOT_ID slotID, void *library_handle)
{
	SK_RET_CODE	rc;
	SK_RET_CODE	(*pfoo)(SK_FUNCTION_LIST_PTR_PTR);
	void    *d = NULL;
	struct slot_info *s_info;
	int ret = FALSE;

	d = library_handle;
	pfoo = (SK_RET_CODE (*)(SK_FUNCTION_LIST_PTR_PTR))dlsym(d, "SK_GetFunctionList");
	if (pfoo == NULL) {
		print_error("SK_GetFunctionList not found\n");
		goto out;
	}

	s_info = get_global_slot_info(slotID);
	if (!s_info) {
		print_error("get_global_slot_info failed\n");
		goto out;
	}

	rc = pfoo(&s_info->sk_funcs);
	if (rc != SKR_OK) {
		print_error("SK_GetFunctionList rc=%u", rc);
		goto out;
	}

	ret = TRUE;

out:
	return ret;

}

CK_RV destroy_slot(CK_SLOT_ID slotID)
{
	void *shared_lib_handle;
	struct slot_info *s_info;

	if (slotID != TEE_SLOT_ID)
		return CKR_GENERAL_ERROR;

	s_info = get_global_slot_info(slotID);
	if (s_info == NULL) {
		print_error("get_global_slot_info failed\n");
		return CKR_GENERAL_ERROR;
	}

	shared_lib_handle = s_info->shared_lib_handle;
	close_shared_lib(shared_lib_handle);

	if (destroy_object_list(slotID) != CKR_OK)
		return CKR_GENERAL_ERROR;

	if (destroy_session_list(slotID) != CKR_OK)
		return CKR_GENERAL_ERROR;

	return CKR_OK;

}

CK_RV initialize_slot(CK_SLOT_ID slotID)
{
	struct slot_info *s_info;
	void *shared_lib_handle;
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

	s_info = get_global_slot_info(slotID);
	if (s_info == NULL) {
		print_error("get_global_slot_info failed\n");
		return CKR_GENERAL_ERROR;
	}

	shared_lib_handle = open_shared_lib(library);
	if (shared_lib_handle == NULL) {
		print_error("open_shared_lib failed\n");
		return CKR_GENERAL_ERROR;
	}

	s_info->shared_lib_handle = shared_lib_handle;

	rc = get_function_list(slotID, shared_lib_handle);
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
