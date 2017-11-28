#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <cryptoki.h>
#include <sessions.h>

struct session_node {
	session sess;
	STAILQ_ENTRY(session_node) entry;
};

STAILQ_HEAD(sess_list, session_node);
struct sess_list session_list;

CK_BBOOL is_session_valid(CK_SESSION_HANDLE hSession)
{
	CK_BBOOL ret = CK_FALSE;
	struct session_node *temp;

	STAILQ_FOREACH(temp, &session_list, entry) {
		if ((CK_SESSION_HANDLE)temp == hSession) {
			ret = CK_TRUE;
			break;
		}
	}

	return ret;
}

CK_RV create_session(CK_SLOT_ID slotID,  CK_FLAGS flags,
		CK_SESSION_HANDLE_PTR phSession)
{
	struct session_node *s = (struct session_node *)malloc(sizeof(struct session_node));
	if (s == NULL) {
		printf("session_node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(s, 0, sizeof(struct session_node));

	s->sess.session_info.slotID = slotID;
	s->sess.session_info.flags = flags;
	s->sess.session_info.state = CKS_RO_PUBLIC_SESSION;
	s->sess.session_info.ulDeviceError= 0;

	STAILQ_INSERT_HEAD(&session_list, s, entry);

	*phSession = (CK_SESSION_HANDLE)s;

	return CKR_OK;
}

CK_RV delete_session(CK_SESSION_HANDLE hSession)
{
	struct session_node *s;

	s = (struct session_node *)hSession;

	STAILQ_REMOVE(&session_list, s, session_node, entry);
	free(s);

	return CKR_OK;
}

CK_RV delete_all_session(CK_SLOT_ID slotID)
{
	struct session_node *temp, *s = NULL;

	STAILQ_FOREACH(temp, &session_list, entry) {
		if (temp->sess.session_info.slotID == slotID) {
			s =  temp;
			STAILQ_REMOVE(&session_list, s,
				session_node, entry);
			free(s);
		}
	}

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
