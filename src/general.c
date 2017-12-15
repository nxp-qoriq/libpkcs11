#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <tee_slot.h>
#include <general.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

SK_FUNCTION_LIST  *sk_funcs;

/* Flag to find if cryptoki library is initialised or not */
CK_ULONG	initialized;

static struct slot_info g_slot_info[SLOT_COUNT];

struct slot_info *get_global_slot_info(CK_SLOT_ID slotID)
{
	return &g_slot_info[slotID];
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

int get_function_list(void)
{
	SK_RET_CODE	rc;
	SK_RET_CODE	(*pfoo)(SK_FUNCTION_LIST_PTR_PTR);
	void    *d;
	const char    *e;
	const char    *f = "libsecurekey.so";

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

	rc = pfoo(&sk_funcs);
	if (rc != SKR_OK) {
		printf("SK_GetFunctionList rc=%u", rc);
		return FALSE;
	}

	return TRUE;

}

