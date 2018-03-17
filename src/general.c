/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <tee_slot.h>
#include <general.h>
#include <pthread.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

/* Flag to find if cryptoki library is initialised or not */
CK_ULONG	initialized;

static struct slot_info g_slot_info[SLOT_COUNT];

/*
  * Mutex Functions.
  */
static CK_RV create_mutex(void **mutex)
{
	pthread_mutex_t *m;
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	m = malloc(sizeof(*m));
	if (m == NULL)
		return CKR_GENERAL_ERROR;

	memset(m, 0, sizeof(*m));

	pthread_mutex_init(m, &attr);
	*mutex = m;
	return CKR_OK;
}

static CK_RV lock_mutex(void *p)
{
	if (p == NULL)
		return CKR_OK;
	if (pthread_mutex_trylock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

static CK_RV unlock_mutex(void *p)
{
	if (pthread_mutex_unlock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

static CK_RV destroy_mutex(void *p)
{
	pthread_mutex_destroy((pthread_mutex_t *) p);
	free(p);
	p = NULL;
	return CKR_OK;
}


static CK_C_INITIALIZE_ARGS default_locks = {
	create_mutex, destroy_mutex, lock_mutex, unlock_mutex, 0, NULL };

static CK_C_INITIALIZE_ARGS_PTR	default_mutex_functions = &default_locks;
static CK_C_INITIALIZE_ARGS_PTR	global_locking;
static void *global_lock = NULL;

CK_RV p11_global_lock(void)
{
	if (!global_lock)
		return CKR_OK;

	if (global_locking)  {
		while (global_locking->LockMutex(global_lock) != CKR_OK)
			;
	}

	return CKR_OK;
}

static void
__p11_global_unlock(void *lock)
{
	if (!lock)
		return;

	if (global_locking) {
		while (global_locking->UnlockMutex(lock) != CKR_OK)
			;
	}
}

void p11_global_unlock(void)
{
	__p11_global_unlock(global_lock);
}

CK_RV p11_init_lock(CK_C_INITIALIZE_ARGS_PTR pInitArgs)
{
	CK_RV rv = CKR_OK;
	char functions_map = 0;
	CK_C_INITIALIZE_ARGS *pArgs;

	if (global_lock)
		return CKR_OK;

	global_locking = NULL;

	if (pInitArgs != NULL) {
		pArgs = (CK_C_INITIALIZE_ARGS *) pInitArgs;

		if (pArgs->pReserved != NULL) {
			print_error("InitArgs reserved field not NULL\n");
			return CKR_ARGUMENTS_BAD;
		}

		functions_map = (pArgs->CreateMutex ? 0x01 << 0 : 0);
		functions_map |= (pArgs->DestroyMutex ? 0x01 << 1 : 0);
		functions_map |= (pArgs->LockMutex ? 0x01 << 2 : 0);
		functions_map |= (pArgs->UnlockMutex ? 0x01 << 3 : 0);

		/* Verify that all or none of the functions are set */
		if (functions_map != 0) {
			if (functions_map != 0x0f) {
				print_error("Not all function pointers are provided\n");
				return CKR_ARGUMENTS_BAD;
			}
		}

		/* Case 1.  Flag not set and function pointers NOT supplied */
		if (!(pArgs->flags & CKF_OS_LOCKING_OK) && !(functions_map)) {
			/* Will be returning CKR_OK if initialization works correctly */;
			global_locking = NULL;
		} else if ((pArgs->flags & CKF_OS_LOCKING_OK) && !(functions_map)) {
			/* Will be returning CKR_OK if initialization works correctly */;
			global_locking = default_mutex_functions;
		} else if (!(pArgs->flags & CKF_OS_LOCKING_OK) && (functions_map)) {
			/* Will be returning CKR_OK if initialization works correctly */;
			global_locking = pArgs;
		} else if ((pArgs->flags & CKF_OS_LOCKING_OK) && (functions_map)) {
			/* Will be returning CKR_OK if initialization works correctly */;
			global_locking = default_mutex_functions;
		}
	}

	if (global_locking != NULL) {
		/* create mutex */
		rv = global_locking->CreateMutex(&global_lock);
	}

	return rv;
}

void p11_free_lock(void)
{
	void	*tempLock;

	if (!(tempLock = global_lock))
		return;

	global_lock = NULL;

	__p11_global_unlock(tempLock);

	if (global_locking)
		global_locking->DestroyMutex(tempLock);

	//global_locking = NULL;
}

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
			memcpy(library, "libsecure_obj.so", sizeof("libsecure_obj.so"));
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
