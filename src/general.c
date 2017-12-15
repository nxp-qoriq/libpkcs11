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

int get_function_list(CK_SLOT_ID slotID)
{
	SK_RET_CODE	rc;
	SK_RET_CODE	(*pfoo)(SK_FUNCTION_LIST_PTR_PTR);
	void    *d;
	const char    *e;
	const char    *f = "libsecurekey.so";
	struct slot_info *s_info;

	e = getenv("SECUREKEY_LIB");
	if ( e == NULL)
		e = f;

	d = dlopen(e, RTLD_NOW);
	if ( d == NULL ) {
		printf("dlopen failed %s\n", dlerror());
		return FALSE;
	}

	pfoo = (SK_RET_CODE (*)(SK_FUNCTION_LIST_PTR_PTR))dlsym(d, "SK_GetFunctionList");
	if (pfoo == NULL ) {
		return FALSE;
	}

	s_info = get_global_slot_info(slotID);
	if (!s_info)
		return FALSE;

	rc = pfoo(&s_info->sk_funcs);
	if (rc != SKR_OK) {
		printf("SK_GetFunctionList rc=%u", rc);
		return FALSE;
	}

	return TRUE;

}

