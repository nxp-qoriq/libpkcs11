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

CK_RV create_session(CK_SLOT_ID slotID,  CK_FLAGS flags,
		CK_SESSION_HANDLE_PTR phSession)
{
	struct session_node *s;
	struct session_list *sess_list;

	s = (struct session_node *)malloc(sizeof(struct session_node));
	if (s == NULL) {
		print_error("session_node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	sess_list = get_session_list(slotID);
	if (!sess_list) {
		print_error("get_session_list failed\n");
		free(s);
		return CKR_ARGUMENTS_BAD;
	}

	memset(s, 0, sizeof(struct session_node));

	s->sess.session_info.slotID = slotID;
	s->sess.session_info.flags = flags;
	s->sess.session_info.state = CKS_RO_PUBLIC_SESSION;
	s->sess.session_info.ulDeviceError= 0;

	STAILQ_INSERT_HEAD(sess_list, s, entry);

	*phSession = (CK_SESSION_HANDLE)s;

	return CKR_OK;
}

CK_RV delete_session(CK_SESSION_HANDLE hSession)
{
	struct session_node *s;
	struct session_list *sess_list;

	s = (struct session_node *)hSession;
	sess_list = get_session_list(s->sess.session_info.slotID);
	if (!sess_list)
		return CKR_ARGUMENTS_BAD;

	STAILQ_REMOVE(sess_list, s, session_node, entry);
	free(s);

	return CKR_OK;
}

CK_RV destroy_session_list(CK_SLOT_ID slotID)
{
	struct session_node *s;
	struct session_list *sess_list;

	sess_list = get_session_list(slotID);
	if (!sess_list)
		return CKR_ARGUMENTS_BAD;

	while ((s = STAILQ_FIRST(sess_list)) != NULL) {
		STAILQ_REMOVE(sess_list, s, session_node, entry);
		free(s);
	}

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
