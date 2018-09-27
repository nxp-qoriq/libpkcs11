/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <cryptoki.h>
#include <sessions.h>
#include <general.h>
#include <crypto.h>

CK_STATE global_loggedin_state = CKS_RO_PUBLIC_SESSION;
CK_ULONG rw_session_count;
CK_ULONG session_count;

struct session_list *get_session_list(CK_SLOT_ID slotID)
{
	struct slot_info *ginfo;

	if (slotID >= SLOT_COUNT)
		return NULL;

	ginfo = get_global_slot_info(slotID);

	return &ginfo->sess_list;
}

CK_RV initialize_session_list(CK_SLOT_ID slotID)
{
	struct session_list *sess_list;
	sess_list = get_session_list(slotID);
	if (!sess_list)
		return CKR_ARGUMENTS_BAD;

	STAILQ_INIT(sess_list);
	return CKR_OK;
}

CK_BBOOL is_session_valid(CK_SESSION_HANDLE hSession)
{
	CK_BBOOL ret = CK_FALSE;
	struct session_node *temp, *sess;
	struct session_list *sess_list;

	sess = (struct session_node *)hSession;
	sess_list= get_session_list(sess->sess.session_info.slotID);
	if (!sess_list)
		return ret;

	if (STAILQ_EMPTY(sess_list))
		return ret;

	STAILQ_FOREACH(temp, sess_list, entry) {
		if ((CK_SESSION_HANDLE)temp == hSession) {
			ret = CK_TRUE;
			break;
		}
	}

	return ret;
}

session *get_session(CK_SESSION_HANDLE hSession)
{
	struct session_node *s;

	if(!is_session_valid(hSession))
		return NULL;

	s = (struct session_node *)hSession;
	return &s->sess;
}

CK_BBOOL session_ro_exist(void)
{
	if (rw_session_count != session_count)
		return CK_TRUE;
	else
		return CK_FALSE;
}

CK_RV create_session(CK_SLOT_ID slotID,  CK_FLAGS flags,
		CK_SESSION_HANDLE_PTR phSession)
{
	struct session_node *s;
	struct session_list *sess_list;
	CK_RV rc = CKR_OK;
	CK_BBOOL so_session = CK_FALSE, user_session = CK_FALSE;

	struct slot_info *ginfo = NULL;
	CK_TOKEN_INFO_PTR token_info = NULL;

	ginfo = get_global_slot_info(slotID);
	token_info = &(ginfo->token_data.token_info);

	print_info("ulRwSessionCount = %lu, ulMaxRwSessionCount = %lu\n",
		rw_session_count, token_info->ulMaxRwSessionCount);
	if (flags & CKF_RW_SESSION) {
		if (rw_session_count >
			token_info->ulMaxRwSessionCount) {
			rc = CKR_SESSION_COUNT;
			goto end;
		}
	}

	print_info("ulSessionCount = %lu, ulMaxSessionCount = %lu\n",
		session_count, token_info->ulMaxSessionCount);
	if (session_count >
		token_info->ulMaxSessionCount) {
		rc = CKR_SESSION_COUNT;
		goto end;
	}

	so_session  = so_session_exist();
	user_session = user_session_exist();

	s = (struct session_node *)malloc(sizeof(struct session_node));
	if (s == NULL) {
		print_error("session_node malloc failed\n");
		rc = CKR_HOST_MEMORY;
		goto end;
	}

	sess_list = get_session_list(slotID);
	if (!sess_list) {
		print_error("get_session_list failed\n");
		free(s);
		rc = CKR_ARGUMENTS_BAD;
		goto end;
	}

	memset(s, 0, sizeof(struct session_node));

	s->sess.session_info.slotID = slotID;
	s->sess.session_info.flags = flags;
	s->sess.session_info.ulDeviceError= 0;

	if (user_session) {
		if (flags & CKF_RW_SESSION)
			s->sess.session_info.state = CKS_RW_USER_FUNCTIONS;
		else
			s->sess.session_info.state = CKS_RO_USER_FUNCTIONS;
	} else if (so_session) {
			if (session_ro_exist()) {
				rc = CKR_SESSION_READ_ONLY_EXISTS;
				goto end;
			}
			s->sess.session_info.state = CKS_RW_SO_FUNCTIONS;
	} else {
		if (flags & CKF_RW_SESSION)
			s->sess.session_info.state = CKS_RW_PUBLIC_SESSION;
		else
			s->sess.session_info.state = CKS_RO_PUBLIC_SESSION;
	}

	STAILQ_INSERT_HEAD(sess_list, s, entry);
	if (flags & CKF_RW_SESSION)
		rw_session_count++;
	session_count++;

	*phSession = (CK_SESSION_HANDLE)s;
end:
	return rc;
}

CK_RV delete_session(CK_SESSION_HANDLE hSession)
{
	struct session_node *s;
	struct session_list *sess_list;

	s = (struct session_node *)hSession;
	if (s) {
		if (s->sess.session_info.flags & CKF_RW_SESSION)
			rw_session_count--;
		session_count--;

		sess_list = get_session_list(s->sess.session_info.slotID);
		if (!sess_list)
			return CKR_ARGUMENTS_BAD;

		STAILQ_REMOVE(sess_list, s, session_node, entry);
		free(s);
	}

	if (STAILQ_EMPTY(sess_list))
		global_loggedin_state = CKS_RO_PUBLIC_SESSION;

	return CKR_OK;
}

CK_RV destroy_session_list(CK_SLOT_ID slotID)
{
	struct session_node *s;
	struct session_list *sess_list;

	sess_list = get_session_list(slotID);
	if (!sess_list)
		return CKR_ARGUMENTS_BAD;

	rw_session_count = 0;
	session_count = 0;

	while ((s = STAILQ_FIRST(sess_list)) != NULL) {
		STAILQ_REMOVE(sess_list, s, session_node, entry);
		free(s);
	}

	global_loggedin_state = CKS_RO_PUBLIC_SESSION;
#if 0
	if (STAILQ_EMPTY(sess_list))
		printf("Session list destroyed successfuly\n");
#endif
	return CKR_OK;
}

CK_RV get_session_info(CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO_PTR pInfo) 
{
	struct session_node *s;

	s = (struct session_node *)hSession;

	memcpy(pInfo, &s->sess.session_info, sizeof(CK_SESSION_INFO));

	return CKR_OK;
}

CK_BBOOL so_session_exist(void)
{
	if (global_loggedin_state == CKS_RW_SO_FUNCTIONS)
		return CK_TRUE;
	else
		return CK_FALSE;
}

CK_BBOOL user_session_exist(void)
{
	if ((global_loggedin_state == CKS_RW_USER_FUNCTIONS) ||
		(global_loggedin_state == CKS_RO_USER_FUNCTIONS))
		return CK_TRUE;
	else
		return CK_FALSE;
}

CK_BBOOL public_session_exist(void)
{
	if ((global_loggedin_state == CKS_RO_PUBLIC_SESSION) ||
		(global_loggedin_state == CKS_RW_PUBLIC_SESSION))
		return CK_TRUE;
	else
		return CK_FALSE;
}

CK_RV session_template_check_consistency(
			CK_SESSION_HANDLE hSession,
			struct template_list *template)
{
	CK_RV rc = CKR_OK;
	session *sess = NULL_PTR;
	CK_BBOOL sess_obj = CK_FALSE, priv_obj = CK_FALSE;

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sess_obj = template_is_session_object(template);
	priv_obj = template_is_private_set(template);

	print_info("sess_obj = %u, priv_obj = %u\n",
			sess_obj, priv_obj);

	if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
		if (priv_obj) {
			rc = CKR_USER_NOT_LOGGED_IN;
			goto end;
		}

		if (!sess_obj) {
			rc = CKR_SESSION_READ_ONLY;
			goto end;
		}
	}

	if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
		if (!sess_obj) {
			rc = CKR_SESSION_READ_ONLY;
			goto end;
		}
	}

	if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
		if (priv_obj) {
			rc = CKR_USER_NOT_LOGGED_IN;
			goto end;
		}
	}

	if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (priv_obj) {
			rc = CKR_USER_NOT_LOGGED_IN;
			goto end;
		}
	}

end:
	return rc;

}

static CK_RV sessions_login_all(CK_SLOT_ID slotID,
				CK_USER_TYPE userType)
{
	CK_RV rc = CKR_OK;
	struct session_node *temp = NULL;
	struct session_list *sess_list = NULL;
	session *sess = NULL;

	sess_list= get_session_list(slotID);
	if (!sess_list) {
		print_error("get_session_list failed\n");
		rc = CKR_SLOT_ID_INVALID;
		goto end;
	}

	STAILQ_FOREACH(temp, sess_list, entry) {
		sess = &temp->sess;
		if (sess->session_info.flags & CKF_RW_SESSION) {
			if (userType == CKU_USER)
				sess->session_info.state = CKS_RW_USER_FUNCTIONS;
			else
				sess->session_info.state = CKS_RW_SO_FUNCTIONS;
		} else {
			if (userType == CKU_USER)
				sess->session_info.state = CKS_RO_USER_FUNCTIONS;
		}
	}

	global_loggedin_state = sess->session_info.state;
end:
	return rc;
}

CK_RV session_login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL so_session = CK_FALSE, user_session = CK_FALSE;
	CK_BYTE pinHash[PIN_LEN];
	struct slot_info *s_info = NULL;
	struct token_data *token_data = NULL;
	CK_SESSION_INFO sess_info = { 0 };

	rc = get_session_info(hSession, &sess_info);
	if (rc != CKR_OK) {
		print_error("get_session_info failed\n");
		goto end;
	}

	so_session = so_session_exist();
	user_session = user_session_exist();

	if (userType == CKU_USER) {
		if (!user_pin_initialized(sess_info.slotID)) {
			rc = CKR_USER_PIN_NOT_INITIALIZED;
			goto end;
		}
		if (so_session) {
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
			goto end;
		}
		if (user_session) {
			rc = CKR_USER_ALREADY_LOGGED_IN;
			goto end;
		}
	} else if (userType == CKU_SO) {
		if (!(sess_info.flags & CKF_RW_SESSION)) {
			rc = CKR_SESSION_READ_ONLY_EXISTS;
			goto end;
		}
		if (user_session) {
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
			goto end;
		}
		if (so_session) {
			rc = CKR_USER_ALREADY_LOGGED_IN;
			goto end;
		}
	} else {
		rc = CKR_USER_TYPE_INVALID;
		goto end;
	}

	/* Get SHA256  of pin */
	rc = get_digest(pPin, ulPinLen, pinHash);
	if (rc) {
		print_error("get_digest failed\n");
		goto end;
	}

	s_info = get_global_slot_info(sess_info.slotID);
	if (s_info == NULL) {
		print_error("get_global_slot_info failed\n");
		rc = CKR_SLOT_ID_INVALID;
		goto end;
	}
	token_data = &s_info->token_data;

	if (userType == CKU_USER) {
		if (memcmp(token_data->user_pin_hash, pinHash,
			PIN_LEN)) {
			rc = CKR_PIN_INCORRECT;
			goto end;
		}
	} else {
		if (memcmp(token_data->so_pin_hash, pinHash,
			PIN_LEN)) {
			rc = CKR_PIN_INCORRECT;
			goto end;
		}
	}

	rc = sessions_login_all(sess_info.slotID, userType);
	if (rc)
		print_error("sessions_login_all failed\n");

end:
	return rc;
}

CK_RV session_logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rc = CKR_OK;
	CK_SESSION_INFO sess_info = { 0 };
	struct session_node *temp = NULL;
	struct session_list *sess_list = NULL;
	session *sess = NULL;

	rc = get_session_info(hSession, &sess_info);
	if (rc) {
		print_error("get_session_info failed\n");
		goto end;
	}

	sess_list= get_session_list(sess_info.slotID);
	if (!sess_list) {
		print_error("get_session_list failed\n");
		rc = CKR_SLOT_ID_INVALID;
		goto end;
	}

	STAILQ_FOREACH(temp, sess_list, entry) {
		sess = &temp->sess;
		if (sess->session_info.flags & CKF_RW_SESSION)
			sess->session_info.state = CKS_RW_PUBLIC_SESSION;
		else
			sess->session_info.state = CKS_RO_PUBLIC_SESSION;
	}

	global_loggedin_state = sess->session_info.state;
end:
	return rc;
}
