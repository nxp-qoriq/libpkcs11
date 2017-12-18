#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <dlfcn.h>

#include "cryptoki.h"
#include <tee_slot.h>

CK_FUNCTION_LIST  *funcs;

#define err2str(X)     case X: return #X

// p11_get_error_string - return textual interpretation of a CKR_ error code
// @rc is the CKR_.. error

char *p11_get_error_string( CK_RV rc )
{
   switch (rc) {
      err2str(CKR_OK);
      err2str(CKR_CANCEL);
      err2str(CKR_HOST_MEMORY);
      err2str(CKR_SLOT_ID_INVALID);
      err2str(CKR_GENERAL_ERROR);
      err2str(CKR_FUNCTION_FAILED);
      err2str(CKR_ARGUMENTS_BAD);
      err2str(CKR_NO_EVENT);
      err2str(CKR_NEED_TO_CREATE_THREADS);
      err2str(CKR_CANT_LOCK);
      err2str(CKR_ATTRIBUTE_READ_ONLY);
      err2str(CKR_ATTRIBUTE_SENSITIVE);
      err2str(CKR_ATTRIBUTE_TYPE_INVALID);
      err2str(CKR_ATTRIBUTE_VALUE_INVALID);
      err2str(CKR_DATA_INVALID);
      err2str(CKR_DATA_LEN_RANGE);
      err2str(CKR_DEVICE_ERROR);
      err2str(CKR_DEVICE_MEMORY);
      err2str(CKR_DEVICE_REMOVED);
      err2str(CKR_ENCRYPTED_DATA_INVALID);
      err2str(CKR_ENCRYPTED_DATA_LEN_RANGE);
      err2str(CKR_FUNCTION_CANCELED);
      err2str(CKR_FUNCTION_NOT_PARALLEL);
      err2str(CKR_FUNCTION_NOT_SUPPORTED);
      err2str(CKR_KEY_HANDLE_INVALID);
      err2str(CKR_KEY_SIZE_RANGE);
      err2str(CKR_KEY_TYPE_INCONSISTENT);
      err2str(CKR_KEY_NOT_NEEDED);
      err2str(CKR_KEY_CHANGED);
      err2str(CKR_KEY_NEEDED);
      err2str(CKR_KEY_INDIGESTIBLE);
      err2str(CKR_KEY_FUNCTION_NOT_PERMITTED);
      err2str(CKR_KEY_NOT_WRAPPABLE);
      err2str(CKR_KEY_UNEXTRACTABLE);
      err2str(CKR_MECHANISM_INVALID);
      err2str(CKR_MECHANISM_PARAM_INVALID);
      err2str(CKR_OBJECT_HANDLE_INVALID);
      err2str(CKR_OPERATION_ACTIVE);
      err2str(CKR_OPERATION_NOT_INITIALIZED);
      err2str(CKR_PIN_INCORRECT);
      err2str(CKR_PIN_INVALID);
      err2str(CKR_PIN_LEN_RANGE);
      err2str(CKR_PIN_EXPIRED);
      err2str(CKR_PIN_LOCKED);
      err2str(CKR_SESSION_CLOSED);
      err2str(CKR_SESSION_COUNT);
      err2str(CKR_SESSION_HANDLE_INVALID);
      err2str(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
      err2str(CKR_SESSION_READ_ONLY);
      err2str(CKR_SESSION_EXISTS);
      err2str(CKR_SESSION_READ_ONLY_EXISTS);
      err2str(CKR_SESSION_READ_WRITE_SO_EXISTS);
      err2str(CKR_SIGNATURE_INVALID);
      err2str(CKR_SIGNATURE_LEN_RANGE);
      err2str(CKR_TEMPLATE_INCOMPLETE);
      err2str(CKR_TEMPLATE_INCONSISTENT);
      err2str(CKR_TOKEN_NOT_PRESENT);
      err2str(CKR_TOKEN_NOT_RECOGNIZED);
      err2str(CKR_TOKEN_WRITE_PROTECTED);
      err2str(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
      err2str(CKR_UNWRAPPING_KEY_SIZE_RANGE);
      err2str(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
      err2str(CKR_USER_ALREADY_LOGGED_IN);
      err2str(CKR_USER_NOT_LOGGED_IN);
      err2str(CKR_USER_PIN_NOT_INITIALIZED);
      err2str(CKR_USER_TYPE_INVALID);
      err2str(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
      err2str(CKR_USER_TOO_MANY_TYPES);
      err2str(CKR_WRAPPED_KEY_INVALID);
      err2str(CKR_WRAPPED_KEY_LEN_RANGE);
      err2str(CKR_WRAPPING_KEY_HANDLE_INVALID);
      err2str(CKR_WRAPPING_KEY_SIZE_RANGE);
      err2str(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
      err2str(CKR_RANDOM_SEED_NOT_SUPPORTED);
      err2str(CKR_RANDOM_NO_RNG);
      err2str(CKR_BUFFER_TOO_SMALL);
      err2str(CKR_SAVED_STATE_INVALID);
      err2str(CKR_INFORMATION_SENSITIVE);
      err2str(CKR_STATE_UNSAVEABLE);
      err2str(CKR_CRYPTOKI_NOT_INITIALIZED);
      err2str(CKR_CRYPTOKI_ALREADY_INITIALIZED);
      err2str(CKR_MUTEX_BAD);
      err2str(CKR_MUTEX_NOT_LOCKED);
      default:					return "UNKNOWN";
   }
}

void dump_sess_info( CK_SESSION_INFO *info )
{
	printf("   CK_SESSION_INFO:\n");
	printf("      slotID:         %ld\n", info->slotID );
	printf("      state:          ");
	switch (info->state) {
		case CKS_RO_PUBLIC_SESSION:   printf("CKS_RO_PUBLIC_SESSION\n");
					      break;
		case CKS_RW_PUBLIC_SESSION:   printf("CKS_RW_PUBLIC_SESSION\n");
					      break;
		case CKS_RO_USER_FUNCTIONS:   printf("CKS_RO_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_USER_FUNCTIONS:   printf("CKS_RW_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_SO_FUNCTIONS:     printf("CKS_RW_SO_FUNCTIONS\n");
					      break;
	}
	printf("      flags:          %p\n",    (void *)info->flags );
	printf("      ulDeviceError:  %ld\n",    info->ulDeviceError );
}

CK_RV do_GetInfo(void)
{
	CK_RV rc = 0;
	CK_INFO info;
	uint32_t i = 0;

	rc = funcs->C_GetInfo(&info);
	if (rc != CKR_OK){
		printf("C_GetInfo() rc=%s\n", p11_get_error_string(rc));
		return rc;
	}

	printf("Library Manufacturer = ");
	for (i = 0; i < sizeof(info.manufacturerID); i++)
		printf("%c", info.manufacturerID[i]);
	printf("\n");

	printf("Library Description = ");
	for (i = 0; i < sizeof(info.libraryDescription); i++)
		printf("%c", info.libraryDescription[i]);
	printf("\n");

	return rc;
}

CK_RV do_GetSlotList(void)
{
	CK_RV rc = 0;
	CK_BBOOL tokenPresent;
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_ULONG ulCount = 0;

	tokenPresent = TRUE;

	printf("\nTesting C_GetSlotList()\n");
	/* pkcs#11v2.20, Section 11.5
	 * If pSlotList is NULL_PTR, then all that C_GetSlotList does is
	 * return (in *pulCount) the number of slots, without actually
	 * returning a list of slots.
	 */
	rc = funcs->C_GetSlotList(tokenPresent, NULL, &ulCount);
	if (rc != CKR_OK) {
		printf("C_GetSlotList failed rc=%s\n", p11_get_error_string(rc));
		goto cleanup;
	}

	if (ulCount)
		printf("C_GetSlotList received slot count.\n");
	else
		printf("C_GetSlotList did not receive slot count.\n");

	pSlotList = (CK_SLOT_ID *)malloc(ulCount * sizeof(CK_SLOT_ID));
	if (!pSlotList) {
		printf("malloc failed to allocate memory for list\n");
		rc = CKR_HOST_MEMORY;
		goto cleanup;
	}

	/* Get the slots */
	rc = funcs->C_GetSlotList(tokenPresent, pSlotList, &ulCount);
	if (rc != CKR_OK) {
		printf("C_GetSlotList rc=%s\n", p11_get_error_string(rc));
		goto cleanup;
	}

	printf("Slot list returned successfully\n");

cleanup:
	if (pSlotList)
		free(pSlotList);

	return rc;

}

CK_RV do_GetSlotInfo(void)
{
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = TEE_SLOT_ID;
	CK_SLOT_INFO info;
	uint32_t i = 0;

	printf("Testing C_GetSlotInfo\n");

	rc = funcs->C_GetSlotInfo(slot_id, &info);
	if (rc != CKR_OK) {
		printf("C_GetSlotInfo() failed rc = %s\n", p11_get_error_string(rc));
		goto cleanup;
	} else {
		printf("Slot info of in-use slot received successfully, printing some info\n");
		printf("Slot Description = ");
		for (i = 0; i < sizeof(info.slotDescription); i++)
			printf("%c", info.slotDescription[i]);
		printf("\n");

		printf("Slot Manufacturer = ");
		for (i = 0; i < sizeof(info.manufacturerID); i++)
			printf("%c", info.manufacturerID[i]);
		printf("\n");
	}

	printf("\nTesting with Invalid SLOT ID\n");
	rc = funcs->C_GetSlotInfo(999, &info);

	if (rc != CKR_SLOT_ID_INVALID) {
		printf("C_GetSlotInfo returned %s instead of"
			      " CKR_SLOT_ID_INVALID.\n", p11_get_error_string(rc));
		rc = CKR_FUNCTION_FAILED; // dont confuse loop in main
		goto cleanup;
	} else {
		printf("C_GetSlotInfo correctly returned "
			      "CKR_SLOT_ID_INVALID.\n");
		rc = 0;		// don't confuse loop in main
	}

cleanup:
	return rc;
}

CK_RV do_GetTokenInfo(void)
{
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = TEE_SLOT_ID;
	CK_TOKEN_INFO info;
	uint32_t i = 0;

	printf("\nTesting C_GetTokenInfo()\n");

	rc = funcs->C_GetTokenInfo(slot_id, &info);
	if (rc != CKR_OK) {
		printf("C_GetTokenInfo failed rc=%s\n", p11_get_error_string(rc));
		return rc;
	} else {
		printf("C_GetTokenInfo returned successfully, printing some info\n");
		printf("Token Label = ");
		for (i = 0; i < sizeof(info.label); i++)
			printf("%c", info.label[i]);
		printf("\n");

		printf("Token Manufacturer = ");
		for (i = 0; i < sizeof(info.manufacturerID); i++)
			printf("%c", info.manufacturerID[i]);
		printf("\n");
	}

	printf("\nTesting with Invalid SLOT ID\n");
	rc = funcs->C_GetTokenInfo(999, &info);
	if (rc != CKR_SLOT_ID_INVALID) {
		printf("C_GetTokenInfo() failed rc = %s\n", p11_get_error_string(rc));
		goto cleanup;
	}

	printf("C_GetTokenInfo returned error when given invalid slot.\n");
	rc = CKR_OK;

cleanup:
	return rc;
}

CK_RV do_GetMechanismList(void)
{
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = TEE_SLOT_ID;
	CK_ULONG count;
	CK_MECHANISM_TYPE *mech_list = NULL;

	printf("\nTesting C_GetMechanismList\n");

	/* pkcs11v2.20, page 111
	 * If pMechanismList is NULL_PTR, then all that C_GetMechanismList
	 * does is return (in *pulCount) the number of mechanisms, without
	 * actually returning a list of mechanisms. The contents of
	 * *pulCount on entry to C_GetMechanismList has no meaning in this
	 * case, and the call returns the value CKR_OK.
	 */

	rc = funcs->C_GetMechanismList(slot_id, NULL, &count);
	if (rc != CKR_OK)
		printf("C_GetMechanismList 1 rc=%s\n",p11_get_error_string(rc));
	else
		printf("C_GetMechanismList 1 returned %lu mechanisms\n", count);

	if (count == 7)
		printf("C_GetMechanismList returned correct mechanism count.\n");
	else
		printf("C_GetMechanismList did not not return correct"
			      "mechanism count.\n");

	mech_list = (CK_MECHANISM_TYPE *)malloc(count *
		sizeof(CK_MECHANISM_TYPE));
	if (!mech_list) {
		printf("malloc failed for mechanism list\n");
		rc = CKR_HOST_MEMORY;
		goto cleanup;
	}

	rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
	if (rc != CKR_OK) {
		printf("C_GetMechanismList 2 rc=%s\n", p11_get_error_string(rc));
		goto cleanup;
	} else
		printf("Mechanism listing from current slot\n");

	rc = funcs->C_GetMechanismList(999, NULL, &count);

	if (rc != CKR_SLOT_ID_INVALID) {
		printf("C_GetMechanismList() returned %s instead of"
			      " CKR_SLOT_ID_INVALID.\n", p11_get_error_string(rc));
		rc = CKR_FUNCTION_FAILED;
		goto cleanup;
	} else {
		printf("C_GetMechanismList correctly returned "
			      "CKR_SLOT_ID_INVALID.\n");
		rc = CKR_OK;
	}

cleanup:
	if (mech_list)
		free(mech_list);

	return rc;
}

CK_RV do_GetMechanismInfo(void)
{
	CK_RV rc = 0;
	CK_SLOT_ID slot_id = TEE_SLOT_ID;
	CK_MECHANISM_INFO info;
	CK_ULONG i, count;
	CK_MECHANISM_TYPE *mech_list = NULL;

	printf("\nTesting C_GetMechanismInfo\n");

	rc = funcs->C_GetMechanismList(slot_id, NULL, &count);
	if (rc != CKR_OK)
		printf("C_GetMechanismList 1 rc=%s\n",p11_get_error_string(rc));
	else
		printf("C_GetMechanismList 1 returned %lu mechanisms\n", count);

	mech_list = (CK_MECHANISM_TYPE *)malloc(count *
		sizeof(CK_MECHANISM_TYPE));
	if (!mech_list) {
		printf("malloc failed for mechanism list\n");
		rc = CKR_HOST_MEMORY;
		goto cleanup;
	}

	rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
	if (rc != CKR_OK) {
		printf("C_GetMechanismList #2 rc=%s\n", p11_get_error_string(rc));
		goto cleanup;
	}

	if (count == 7)
		printf("C_GetMechanismList returned correct mechanism count.\n");
	else
		printf("C_GetMechanismList did not not return correct"
			      "mechanism count.\n");

	for (i = 0; i < count; i++) {
		rc = funcs->C_GetMechanismInfo(slot_id, mech_list[i], &info);
		if (rc != CKR_OK)
			break;
	}

	if (rc != CKR_OK)
		printf("C_GetMechanismInfo rc=%s\n", p11_get_error_string(rc));
	else
		printf("C_GetMechanismInfo was successful.\n");

cleanup:
	if (mech_list)
		free(mech_list);

	return rc;

}

int do_GetFunctionList( void )
{
	CK_RV            rc;
	CK_RV  (*pfoo)();
	void    *d;
	char    *e;
	char    *f = "libpkcs11.so";

	e = getenv("PKCSLIB");
	if ( e == NULL)
		e = f;

	d = dlopen(e, RTLD_NOW);
	if ( d == NULL ) {
		printf("dlopen failed %s\n", dlerror());
		return FALSE;
	}

	pfoo = (CK_RV (*)())dlsym(d, "C_GetFunctionList");
	if (pfoo == NULL ) {
		return FALSE;
	}

	rc = pfoo(&funcs);

	if (rc != CKR_OK) {
		printf("C_GetFunctionList rc=%lu", rc);
		return FALSE;
	}

	return TRUE;

}

CK_RV do_OpenSession( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE handle;
	CK_RV             rc;

	printf("\ndo_OpenSession Starting \n");

	slot_id = TEE_SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	printf("Creating R/O Session \n");
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &handle );
	if (rc != CKR_OK)
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session with handle = 0x%lx created\n", handle);

	printf("Closing Session \n");
	rc = funcs->C_CloseSession(handle);
	if (rc != CKR_OK)
		printf("C_CloseSession handle failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("Session Closed\n");

	printf("do_OpenSession Finish\n");

	return rc;
}


//
//
CK_RV do_OpenSession2( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2;
	CK_RV             rc;

	printf("\ndo_OpenSession2 Start\n");

	slot_id = TEE_SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	printf("Creating R/O Session h1\n");
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK)
		printf("C_OpenSession h1 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session created h1 = 0x%lx created\n", h1);

	printf("Creating R/W Session h2\n");
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK)
		printf("C_OpenSession h2 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/W Session created h2 = 0x%lx created\n", h2);


	printf("Closing Session h1\n");
	rc = funcs->C_CloseSession( h1 );
	if (rc != CKR_OK)
		printf("C_CloseSession h1 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("C_CloseSession h1 rc=%s\n", p11_get_error_string(rc));

	printf("Closing Session h2\n");
	rc = funcs->C_CloseSession( h2 );
	if (rc != CKR_OK)
		printf("C_CloseSession h2 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("C_CloseSession h2 rc=%s\n", p11_get_error_string(rc));

	printf("do_OpenSession2 Finish\n");

	return rc;
}


//
//
CK_RV do_CloseAllSessions( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2, h3;
	CK_RV             rc;

	printf("\ndo_CloseAllSessions Starting\n");

	slot_id = TEE_SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	printf("Creating R/O Session h1\n");
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK)
		printf("C_OpenSession h1 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session h1 = 0x%lx created\n", h1);

	printf("Creating R/O Session h2\n");
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK)
		printf("C_OpenSession h2 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session h2 = 0x%lx created\n", h2);

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	printf("Creating R/W Session h3\n");
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK)
		printf("C_OpenSession h3 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/W Session h2 = 0x%lx created\n", h2);

	printf("Closing all sessions for TEE_SLOT\n");
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK)
		printf("C_CloseAllSessions failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("C_CloseAllSessions rc=%s\n", p11_get_error_string(rc));

	printf("do_CloseAllSessions finish ...\n");

	return rc;
}

CK_RV do_FindObjects(void)
{
	CK_FLAGS          flags;
	CK_SLOT_ID        slot_id;
	CK_RV             rc = 0;
	CK_SESSION_HANDLE h_session;

	CK_BYTE           false = FALSE;
	CK_ULONG i, j;

	CK_OBJECT_HANDLE  obj_list[10];
	CK_ULONG          find_count;
	CK_ULONG          num_existing_objects;

	CK_ATTRIBUTE ck_attr[2];
	CK_OBJECT_CLASS obj_type;
	CK_KEY_TYPE key_type;
	CK_ULONG modulus_bits;
	CK_ULONG count = 0;

	obj_type = CKO_PUBLIC_KEY;
	key_type = CKK_RSA;

	ck_attr[0].type = CKA_CLASS;
	ck_attr[0].pValue = &obj_type;
	ck_attr[0].ulValueLen = sizeof(CK_OBJECT_CLASS);

	ck_attr[1].type = CKA_KEY_TYPE;
	ck_attr[1].pValue = &key_type;
	ck_attr[1].ulValueLen = sizeof(CK_KEY_TYPE);

	printf("starting do_FindObjects\n");

	slot_id = TEE_SLOT_ID;

	/* create a USER R/W session */
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &h_session);
	if (rc != CKR_OK)
		printf("C_OpenSession handle failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session with handle = 0x%lx created\n", h_session);

	rc = funcs->C_FindObjectsInit(h_session, ck_attr, 2);
	if (rc != CKR_OK)
		return rc;

	for (i = 0; i < 10; i++) {
		rc = funcs->C_FindObjects(h_session, &obj_list[i], 1, &num_existing_objects);
		if (rc != CKR_OK)
			return rc;

		if (num_existing_objects) {
			printf("object[%lu] = %lx\n", i, obj_list[i]);
			count++;
		} else {
			printf("find_list empty \n");
			break;
		}
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK)
		return rc;

	for (i = 0; i < count; i++)
		printf("object[%lu] = %lx\n", i, obj_list[i]);

	printf("num_existing_object =%lu\n", count);

	memset(ck_attr, 0, sizeof(CK_ATTRIBUTE) * 2);
	ck_attr[0].type = CKA_MODULUS;
	ck_attr[0].pValue = NULL;
	ck_attr[0].ulValueLen = 0;

	ck_attr[1].type = CKA_MODULUS_BITS;
	ck_attr[1].pValue = NULL;
	ck_attr[1].ulValueLen = 0;

	rc = funcs->C_GetAttributeValue(h_session, obj_list[0], ck_attr, 2);
	if (rc != CKR_OK) {
		printf("C_GetAttributeValue() rc = %s\n", p11_get_error_string(rc));
		for (i = 0; i < 2; i++)
			printf("ck_attr[%lu].ulValueLen = %ld\n",
				i, (CK_LONG)ck_attr[i].ulValueLen);
	} else {
		for (i = 0; i < 2; i++) {
			printf("ck_attr[%lu].ulValueLen = %lu\n",
				i, ck_attr[i].ulValueLen);
		}
		ck_attr[0].pValue = (void *)malloc(ck_attr[0].ulValueLen);
		ck_attr[1].pValue = (void *)malloc(ck_attr[1].ulValueLen);
		rc = funcs->C_GetAttributeValue(h_session, obj_list[0], ck_attr, 2);
		for (j = 0; j < ck_attr[0].ulValueLen; j++) {
			printf("%02x", *((uint8_t *)ck_attr[0].pValue + j));
			if ((j+1) % 12 == 0)
				printf("\n");
		}
		printf("\n");
		for (j = 0; j < ck_attr[1].ulValueLen; j++) {
			printf("%02x", *((uint8_t *)ck_attr[1].pValue + j));
			if ((j+1) % 12 == 0)
				printf("\n");
		}
	}

	/* done...close the session and verify the object is deleted */
	rc = funcs->C_CloseSession(h_session);
	if (rc != CKR_OK)
		return rc;

	printf("\ndo_FindObjects success \n");
	return rc;
}

CK_RV do_GetSessionInfo( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2, h3;
	CK_SESSION_INFO   info;
	CK_RV             rc;

	printf("\ndo_GetSessionInfo Starting\n");

	slot_id = TEE_SLOT_ID;
	flags = CKF_SERIAL_SESSION;   // read-only session

	printf("Creating R/O Session h1\n");
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK)
		printf("C_OpenSession h1 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session h1 = 0x%lx created\n", h1);

	printf("Creating R/W Session h2\n");
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK)
		printf("C_OpenSession h2 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/W Session h2 = 0x%lx created\n", h1);

	printf("Creating R/O Session h3\n");
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK)
		printf("C_OpenSession h3 failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("R/O Session h3 = 0x%lx created\n", h3);

	printf("Getting info about session h1\n");
	rc = funcs->C_GetSessionInfo( h1, &info );
	if (rc != CKR_OK)
		printf("C_GetSessionInfo h1 failed rc=%s\n", p11_get_error_string(rc));
	else
		dump_sess_info( &info );
	memset(&info, 0, sizeof(struct CK_SESSION_INFO));

	printf("Getting info about session h2\n");
	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK)
		printf("C_GetSessionInfo h2 failed rc=%s\n", p11_get_error_string(rc));
	else
		dump_sess_info( &info );
	memset(&info, 0, sizeof(struct CK_SESSION_INFO));

	printf("Getting info about session h3\n");
	rc = funcs->C_GetSessionInfo( h3, &info );
	if (rc != CKR_OK)
		printf("C_GetSessionInfo h3 failed rc=%s\n", p11_get_error_string(rc));
	else
		dump_sess_info( &info );

	printf("Closing all sessions for TEE_SLOT\n");
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK)
		printf("C_CloseAllSessions failed rc=%s\n", p11_get_error_string(rc));
	else
		printf("C_CloseAllSessions rc=%s\n", p11_get_error_string(rc));


	printf("do_GetSessionInfo finish\n");

	return rc;
}

CK_RV sess_mgmt_functions(void)
{
	CK_RV         rc = CKR_OK;

	do_OpenSession();
	do_OpenSession2();
	do_CloseAllSessions();
	do_GetSessionInfo();

	return rc;
}


int main(int argc, char **argv)
{
	int rc;
	CK_C_INITIALIZE_ARGS cinit_args;
	CK_RV rv = 0;

	rc = do_GetFunctionList();
	if (!rc) {
		printf("do_getFunctionList(), rc=%d\n", rc);
		return rc;
	}

	funcs->C_Initialize(NULL_PTR);
	{
		CK_SESSION_HANDLE hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	printf("Getting Information about Cryptoki Library\n");
	rv = do_GetInfo();
	if (rv != CKR_OK)
		printf("do_GetInfo failed\n");

	rv = do_GetSlotList();
	if (rv != CKR_OK)
		printf("do_GetSlotList failed\n");

	rv = do_GetSlotInfo();
	if (rv != CKR_OK)
		printf("do_GetSlotInfo failed\n");

	rv = do_GetTokenInfo();
	if (rv != CKR_OK)
		printf("do_GetTokenInfo failed\n");

	rv = do_GetMechanismList();
	if (rv != CKR_OK)
		printf("do_GetMechanismList failed\n");

	rv = do_GetMechanismInfo();
	if (rv != CKR_OK)
		printf("do_GetMechanismInfo failed\n");

	rv = sess_mgmt_functions();
	if (rv != CKR_OK)
		printf("sess_mgmt_functions failed rv=%s\n", p11_get_error_string(rv));

	rv = do_FindObjects();
	if (rv != CKR_OK)
		printf("do_FindObjects failed rv=%s\n", p11_get_error_string(rv));

	rv = funcs->C_Finalize(NULL_PTR);
	if (rv != CKR_OK)
		printf("C_Finalize failed rv=%s\n", p11_get_error_string(rv));

	if (rv == CKR_OK)
		printf("PKCS Library initialised finalised successfully\n");

	return rv;
}
