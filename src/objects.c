/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <cryptoki.h>
#include <objects.h>
#include <sessions.h>
#include <general.h>
#include <crypto.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

static CK_BBOOL p11_is_attribute_defined(CK_ATTRIBUTE_TYPE attr_type)
{
	if (attr_type >= CKA_VENDOR_DEFINED)
		return TRUE;

	switch (attr_type)
	{
		case  CKA_CLASS:
		case  CKA_TOKEN:
		case  CKA_PRIVATE:
		case  CKA_LABEL:
		case  CKA_APPLICATION:
		case  CKA_VALUE:
		case  CKA_CERTIFICATE_TYPE:
		case  CKA_ISSUER:
		case  CKA_SERIAL_NUMBER:
		case  CKA_KEY_TYPE:
		case  CKA_ID:
		case  CKA_SUBJECT:
		case  CKA_SENSITIVE:
		case  CKA_DECRYPT:
		case  CKA_ENCRYPT:
		case  CKA_WRAP:
		case  CKA_SIGN:
		case  CKA_UNWRAP:
		case  CKA_SIGN_RECOVER:
		case  CKA_VERIFY:
		case  CKA_DERIVE:
		case  CKA_VERIFY_RECOVER:
		case  CKA_START_DATE:
		case  CKA_END_DATE:
		case  CKA_PRIME:
		case  CKA_BASE:
		case  CKA_SUBPRIME:
		case  CKA_VALUE_BITS:
		case  CKA_EXTRACTABLE:
		case  CKA_LOCAL:
		case  CKA_VALUE_LEN:
		case  CKA_NEVER_EXTRACTABLE:
		case  CKA_MODIFIABLE:
		case  CKA_ECDSA_PARAMS:
		case  CKA_ALWAYS_SENSITIVE:
		case  CKA_EC_POINT:
		case  CKA_HW_FEATURE_TYPE:
		case  CKA_RESET_ON_INIT:
		case  CKA_KEY_GEN_MECHANISM:
		case  CKA_HAS_RESET:
		case  CKA_PRIME_BITS:
		case  CKA_OBJECT_ID:
		case  CKA_SUBPRIME_BITS:
		case  CKA_AC_ISSUER:
		case  CKA_ATTR_TYPES:
		case  CKA_OWNER:
		case  CKA_TRUSTED:
		case  CKA_MODULUS_BITS:
		case  CKA_MODULUS:
		case  CKA_PUBLIC_EXPONENT:
		case  CKA_PRIVATE_EXPONENT:
		case  CKA_PRIME_2:
		case  CKA_EXPONENT_1:
		case  CKA_PRIME_1:
		case  CKA_COEFFICIENT:
		case  CKA_EXPONENT_2:
			return TRUE;
		default:
			return FALSE;
	}
}

static CK_RV
p11_template_update_attr(struct template_list *tmpl_list,
				struct template_node *tmpl_node)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_ATTRIBUTE *new_attr;
	struct template_node *temp = NULL;

	if (!tmpl_list || !tmpl_node)
		return CKR_ARGUMENTS_BAD;

	new_attr = tmpl_node->attributes;

	/* if the attribute already exists in the list, remove it.
	 * this algorithm will limit an attribute to appearing at most
	 * once in the list */
	STAILQ_FOREACH(temp, tmpl_list, entry) {
		attr = (CK_ATTRIBUTE *)temp->attributes;
		if (new_attr->type == attr->type) {
			STAILQ_REMOVE(tmpl_list, temp, template_node, entry);
			STAILQ_NEXT(temp, entry) = NULL;
			free(attr);
			free(temp);
			break;
		}
	}

	STAILQ_INSERT_HEAD(tmpl_list, tmpl_node, entry);

	return CKR_OK;
}
static CK_RV
key_object_set_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	CK_RV rc = CKR_OK;
	CK_ATTRIBUTE_PTR derive_attr = NULL;
	CK_ATTRIBUTE_PTR start_date_attr  = NULL;
	CK_ATTRIBUTE_PTR end_date_attr  = NULL;
	CK_ATTRIBUTE_PTR local_attr = NULL;
	CK_ATTRIBUTE_PTR id_attr = NULL;

	struct template_node *derive = NULL;
	struct template_node *start_date = NULL;
	struct template_node *end_date = NULL;
	struct template_node *local = NULL;
	struct template_node *id = NULL;

	if (!p11_template_attribute_find(tmpl_list, CKA_DERIVE,
			&derive_attr)) {
		derive_attr = (CK_ATTRIBUTE_PTR)malloc(
				sizeof(CK_ATTRIBUTE) +
				sizeof(CK_BBOOL));
		derive = (struct template_node *)malloc(
				sizeof(struct template_node));

		if (!derive_attr || !derive) {
			rc = CKR_HOST_MEMORY;
			goto free_memory;
		}

		derive->attributes = derive_attr;

		derive_attr->type = CKA_DERIVE;
		derive_attr->ulValueLen = sizeof(CK_BBOOL);
		derive_attr->pValue = (CK_BYTE *)derive_attr +
					sizeof(CK_ATTRIBUTE);
		*(CK_BBOOL *)derive_attr->pValue = FALSE;
	} else {
		derive_attr = NULL;
	}

	if (!p11_template_attribute_find(tmpl_list, CKA_START_DATE,
			&start_date_attr)) {
		start_date_attr = (CK_ATTRIBUTE_PTR)malloc(
				sizeof(CK_ATTRIBUTE) +
				sizeof(CK_DATE));
		start_date = (struct template_node *)malloc(
				sizeof(struct template_node));

		if (!start_date_attr || !start_date) {
			rc = CKR_HOST_MEMORY;
			goto free_memory;
		}

		start_date->attributes = start_date_attr;

		start_date_attr->type = CKA_START_DATE;
		start_date_attr->ulValueLen = sizeof(CK_BBOOL);
		start_date_attr->pValue = (CK_BYTE *)start_date_attr +
					sizeof(CK_ATTRIBUTE);
		memset(start_date_attr->pValue, 0, sizeof(CK_DATE));
	} else {
		start_date_attr = NULL;
	}

	if (!p11_template_attribute_find(tmpl_list, CKA_END_DATE,
			&end_date_attr)) {
		end_date_attr = (CK_ATTRIBUTE_PTR)malloc(
				sizeof(CK_ATTRIBUTE) +
				sizeof(CK_DATE));
		end_date = (struct template_node *)malloc(
				sizeof(struct template_node));

		if (!end_date_attr || !end_date) {
			rc = CKR_HOST_MEMORY;
			goto free_memory;
		}

		end_date->attributes = end_date_attr;

		end_date_attr->type = CKA_END_DATE;
		end_date_attr->ulValueLen = sizeof(CK_BBOOL);
		end_date_attr->pValue = (CK_BYTE *)end_date_attr +
					sizeof(CK_ATTRIBUTE);
		memset(end_date_attr->pValue, 0, sizeof(CK_DATE));
	} else {
		end_date_attr = NULL;
	}

	if (!p11_template_attribute_find(tmpl_list, CKA_ID,
			&id_attr)) {
		id_attr = (CK_ATTRIBUTE_PTR)malloc(
				sizeof(CK_ATTRIBUTE));
		id = (struct template_node *)malloc(
				sizeof(struct template_node));

		if (!id_attr || !id) {
			rc = CKR_HOST_MEMORY;
			goto free_memory;
		}

		id->attributes = id_attr;

		id_attr->type = CKA_ID;
		id_attr->ulValueLen = 0;
		id_attr->pValue = NULL;
	} else {
		id_attr = NULL;
	}

	local_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) +
				sizeof(CK_BBOOL));
	local = (struct template_node *)malloc(sizeof(struct template_node));

	if (!local_attr || !local) {
		rc = CKR_HOST_MEMORY;
		goto free_memory;
	}

	local_attr->type = CKA_LOCAL;
	local_attr->ulValueLen = sizeof(CK_BBOOL);
	local_attr->pValue = (CK_BYTE *)local_attr +
				sizeof(CK_ATTRIBUTE);
	if (op_type == OP_GENERATE)
		*(CK_BBOOL *)local_attr->pValue = CK_TRUE;
	else
		*(CK_BBOOL *)local_attr->pValue = CK_FALSE;

	local->attributes = local_attr;

	if (derive && derive_attr)
		p11_template_update_attr(tmpl_list, derive);
	if (start_date && start_date_attr)
		p11_template_update_attr(tmpl_list, start_date);
	if (end_date && end_date_attr)
		p11_template_update_attr(tmpl_list, end_date);
	if (local && local_attr)
		p11_template_update_attr(tmpl_list, local);
	if (id && id_attr)
		p11_template_update_attr(tmpl_list, id);

	goto end;

free_memory:
	if (local_attr)
		free(local_attr);
	if (local)
		free(local);
	if (derive_attr)
		free(derive_attr);
	if (derive)
		free(derive);
	if (start_date_attr)
		free(start_date_attr);
	if (start_date)
		free(start_date);
	if (end_date_attr)
		free(end_date_attr);
	if (end_date)
		free(end_date);
	if (id_attr)
		free(id_attr);
	if (id)
		free(id);
end:
	return rc;
}

static CK_RV
pubk_add_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	/* To satisfy compiler */
	op_type = op_type;
	struct template_node *class;
	struct template_node *subject;
	struct template_node *encrypt;
	struct template_node *verify;
	struct template_node *verify_recover;
	struct template_node *wrap;
	struct template_node *trusted;
	struct template_node *wrap_template;
	struct template_node *public_key_info;

	CK_ATTRIBUTE    *pubk_class_attr = NULL;
	CK_ATTRIBUTE    *pubk_subject_attr = NULL;
	CK_ATTRIBUTE    *pubk_encrypt_attr = NULL;
	CK_ATTRIBUTE    *pubk_verify_attr = NULL;
	CK_ATTRIBUTE    *pubk_verify_recover_attr = NULL;
	CK_ATTRIBUTE    *pubk_wrap_attr = NULL;
	CK_ATTRIBUTE    *pubk_trusted_attr = NULL;
	CK_ATTRIBUTE    *pubk_wrap_template_attr = NULL;
	CK_ATTRIBUTE_PTR pubk_public_key_info_attr = NULL;

	CK_RV	rc;

	rc = key_object_set_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK){
		print_error("key_object_set_default_attr failed\n");
		return rc;
	}

	/* add the default CKO_PUBLIC_KEY attributes */
	pubk_class_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_OBJECT_CLASS));
	pubk_subject_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	pubk_encrypt_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	pubk_verify_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	pubk_verify_recover_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	pubk_wrap_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	pubk_trusted_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	pubk_wrap_template_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	pubk_public_key_info_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));

	class = (struct template_node *)malloc(sizeof(struct template_node));
	subject = (struct template_node *)malloc(sizeof(struct template_node));
	encrypt = (struct template_node *)malloc(sizeof(struct template_node));
	verify = (struct template_node *)malloc(sizeof(struct template_node));
	verify_recover = (struct template_node *)malloc(sizeof(struct template_node));
	wrap = (struct template_node *)malloc(sizeof(struct template_node));
	trusted = (struct template_node *)malloc(sizeof(struct template_node));
	wrap_template = (struct template_node *)malloc(sizeof(struct template_node));
	public_key_info = (struct template_node *)malloc(sizeof(struct template_node));

	if (!pubk_class_attr || !pubk_subject_attr || !pubk_encrypt_attr ||
		!pubk_verify_attr  || !pubk_verify_recover_attr ||
		!pubk_wrap_attr || !pubk_public_key_info_attr ||
		!subject || !class || !encrypt ||
		!verify || !verify_recover || !wrap || !trusted ||
		!wrap_template || !pubk_trusted_attr ||
		!pubk_wrap_template_attr || !public_key_info)
	{
		if (pubk_class_attr)
			free(pubk_class_attr);
		if (pubk_subject_attr)
			free(pubk_subject_attr);
		if (pubk_encrypt_attr)
			free(pubk_encrypt_attr);
		if (pubk_verify_attr)
			free(pubk_verify_attr);
		if (pubk_verify_recover_attr)
			free(pubk_verify_recover_attr);
		if (pubk_wrap_attr)
			free(pubk_wrap_attr);
		if (subject)
			free(subject);
		if (class)
			free(class);
		if (encrypt)
			free(encrypt);
		if (verify)
			free(verify);
		if (verify_recover)
			free(verify_recover);
		if (wrap)
			free(wrap);
		if (trusted)
			free(trusted);
		if (wrap_template)
			free(wrap_template);
		if (pubk_trusted_attr)
			free(pubk_trusted_attr);
		if (pubk_wrap_template_attr)
			free(pubk_wrap_template_attr);
		if (pubk_public_key_info_attr)
			free(pubk_public_key_info_attr);
		if (public_key_info)
			free(public_key_info);

		return CKR_HOST_MEMORY;
	}

	pubk_class_attr->type = CKA_CLASS;
	pubk_class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
	pubk_class_attr->pValue = (CK_BYTE *)pubk_class_attr + sizeof(CK_ATTRIBUTE);
	*(CK_OBJECT_CLASS *)pubk_class_attr->pValue = CKO_PUBLIC_KEY;

	pubk_subject_attr->type         = CKA_SUBJECT;
	pubk_subject_attr->ulValueLen   = 0;
	pubk_subject_attr->pValue       = NULL;

	pubk_encrypt_attr->type          = CKA_ENCRYPT;
	pubk_encrypt_attr->ulValueLen    = sizeof(CK_BBOOL);
	pubk_encrypt_attr->pValue        = (CK_BYTE *)pubk_encrypt_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)pubk_encrypt_attr->pValue = TRUE;

	pubk_verify_attr->type          = CKA_VERIFY;
	pubk_verify_attr->ulValueLen    = sizeof(CK_BBOOL);
	pubk_verify_attr->pValue        = (CK_BYTE *)pubk_verify_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)pubk_verify_attr->pValue = FALSE;

	pubk_verify_recover_attr->type          = CKA_VERIFY_RECOVER;
	pubk_verify_recover_attr->ulValueLen    = sizeof(CK_BBOOL);
	pubk_verify_recover_attr->pValue        = (CK_BYTE *)pubk_verify_recover_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)pubk_verify_recover_attr->pValue = FALSE;

	pubk_wrap_attr->type          = CKA_WRAP;
	pubk_wrap_attr->ulValueLen    = sizeof(CK_BBOOL);
	pubk_wrap_attr->pValue        = (CK_BYTE *)pubk_wrap_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)pubk_wrap_attr->pValue = FALSE;

	pubk_trusted_attr->type          = CKA_TRUSTED;
	pubk_trusted_attr->ulValueLen    = sizeof(CK_BBOOL);
	pubk_trusted_attr->pValue        = (CK_BYTE *)pubk_trusted_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)pubk_trusted_attr->pValue = FALSE;

	pubk_wrap_template_attr->type          = CKA_WRAP_TEMPLATE;
	pubk_wrap_template_attr->ulValueLen    = 0;
	pubk_wrap_template_attr->pValue        = NULL;

	pubk_public_key_info_attr->type          = CKA_PUBLIC_KEY_INFO;
	pubk_public_key_info_attr->ulValueLen    = 0;
	pubk_public_key_info_attr->pValue        = NULL;

	class->attributes = pubk_class_attr;
	subject->attributes = pubk_subject_attr;
	encrypt->attributes = pubk_encrypt_attr;
	verify->attributes = pubk_verify_attr;
	verify_recover->attributes = pubk_verify_recover_attr;
	wrap->attributes = pubk_wrap_attr;
	trusted->attributes = pubk_trusted_attr;
	wrap_template->attributes = pubk_wrap_template_attr;
	public_key_info->attributes = pubk_public_key_info_attr;

	p11_template_update_attr(tmpl_list, class);
	p11_template_update_attr(tmpl_list, subject);
	p11_template_update_attr(tmpl_list, encrypt);
	p11_template_update_attr(tmpl_list, verify);
	p11_template_update_attr(tmpl_list, verify_recover);
	p11_template_update_attr(tmpl_list, wrap);
	p11_template_update_attr(tmpl_list, trusted);
	p11_template_update_attr(tmpl_list, wrap_template);
	p11_template_update_attr(tmpl_list, public_key_info);

	return CKR_OK;
}


static CK_RV
rsa_pubk_add_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	CK_RV rc;
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = pubk_add_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK) {
		print_error("pubk_add_default_attr failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_MECHANISM_TYPE));
	allowed_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_KEY_TYPE));

	if (!key_type || !keygen_mech || !allowed_mech ||
		!keygen_mech_attr || !allowed_mech_attr ||
		!key_type_attr) {
		if (key_type)
			free(key_type);
		if (keygen_mech)
			free(keygen_mech);
		if (allowed_mech)
			free(allowed_mech);
		if (key_type_attr)
			free(key_type_attr);
		if (keygen_mech_attr)
			free(keygen_mech_attr);
		if (allowed_mech_attr)
			free(allowed_mech_attr);

		return CKR_HOST_MEMORY;
	}

	key_type_attr->type = CKA_KEY_TYPE;
	key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
	key_type_attr->pValue = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
	*(CK_KEY_TYPE *)key_type_attr->pValue = CKK_RSA;

	keygen_mech_attr->type = CKA_KEY_GEN_MECHANISM;
	if (op_type == OP_GENERATE) {
		keygen_mech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
		keygen_mech_attr->pValue = (CK_BYTE *)keygen_mech_attr + sizeof(CK_ATTRIBUTE);
		*(CK_MECHANISM_TYPE_PTR)keygen_mech_attr->pValue = CKM_RSA_PKCS_KEY_PAIR_GEN;
	} else {
		keygen_mech_attr->ulValueLen = 0;
		keygen_mech_attr->pValue = NULL;
	}

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = 0;
	allowed_mech_attr->pValue = NULL;

	key_type->attributes = key_type_attr;
	keygen_mech->attributes = keygen_mech_attr;
	allowed_mech->attributes = allowed_mech_attr;

	p11_template_update_attr(tmpl_list, key_type);
	p11_template_update_attr(tmpl_list, keygen_mech);
	p11_template_update_attr(tmpl_list, allowed_mech);

	return CKR_OK;
}

static CK_RV
ecc_pubk_add_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	CK_RV rc;
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = pubk_add_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK) {
		print_error("pubk_add_default_attr failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_MECHANISM_TYPE));
	allowed_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_KEY_TYPE));

	if (!key_type || !keygen_mech || !allowed_mech ||
		!keygen_mech_attr || !allowed_mech_attr ||
		!key_type_attr) {
		if (key_type)
			free(key_type);
		if (keygen_mech)
			free(keygen_mech);
		if (allowed_mech)
			free(allowed_mech);
		if (key_type_attr)
			free(key_type_attr);
		if (keygen_mech_attr)
			free(keygen_mech_attr);
		if (allowed_mech_attr)
			free(allowed_mech_attr);

		return CKR_HOST_MEMORY;
	}

	key_type_attr->type = CKA_KEY_TYPE;
	key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
	key_type_attr->pValue = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
	*(CK_KEY_TYPE *)key_type_attr->pValue = CKK_EC;

	keygen_mech_attr->type = CKA_KEY_GEN_MECHANISM;
	if (op_type == OP_GENERATE) {
		keygen_mech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
		keygen_mech_attr->pValue = (CK_BYTE *)keygen_mech_attr + sizeof(CK_ATTRIBUTE);
		*(CK_MECHANISM_TYPE_PTR)keygen_mech_attr->pValue = CKM_EC_KEY_PAIR_GEN;
	} else {
		keygen_mech_attr->ulValueLen = 0;
		keygen_mech_attr->pValue = NULL;
	}

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = 0;
	allowed_mech_attr->pValue = NULL;

	key_type->attributes = key_type_attr;
	keygen_mech->attributes = keygen_mech_attr;
	allowed_mech->attributes = allowed_mech_attr;

	p11_template_update_attr(tmpl_list, key_type);
	p11_template_update_attr(tmpl_list, keygen_mech);
	p11_template_update_attr(tmpl_list, allowed_mech);

	return CKR_OK;
}

static CK_RV
privk_add_default_attr(struct template_list *tmpl_list,
			CK_ULONG op_type)
{
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *class;
	struct template_node *subject;
	struct template_node *sensitive;
	struct template_node *decrypt;
	struct template_node *sign;
	struct template_node *sign_recover;
	struct template_node *unwrap;
	struct template_node *extractable;
	struct template_node *never_extr;
	struct template_node *always_sens;
	struct template_node *wrap_with_trusted;
	struct template_node *unwrap_templ;
	struct template_node *always_auth;
	struct template_node *public_key_info;

	CK_ATTRIBUTE *privk_class_attr = NULL;
	CK_ATTRIBUTE *privk_subject_attr = NULL;
	CK_ATTRIBUTE *privk_sensitive_attr = NULL;
	CK_ATTRIBUTE *privk_decrypt_attr = NULL;
	CK_ATTRIBUTE *privk_sign_attr = NULL;
	CK_ATTRIBUTE *privk_sign_recover_attr = NULL;
	CK_ATTRIBUTE *privk_unwrap_attr = NULL;
	CK_ATTRIBUTE *privk_extractable_attr = NULL;
	CK_ATTRIBUTE *privk_never_extr_attr = NULL;
	CK_ATTRIBUTE *privk_always_sens_attr = NULL;
	CK_ATTRIBUTE *privk_wrap_with_trusted_attr = NULL;
	CK_ATTRIBUTE *privk_unwrap_templ_attr = NULL;
	CK_ATTRIBUTE *privk_always_auth_attr = NULL;
	CK_ATTRIBUTE_PTR privk_public_key_info_attr = NULL;

	CK_RV	rc;

	rc = key_object_set_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK){
		print_error("key_object_set_default_attr failed\n");
		return rc;
	}

	class = (struct template_node *)malloc(sizeof(struct template_node));
	subject = (struct template_node *)malloc(sizeof(struct template_node));
	sensitive = (struct template_node *)malloc(sizeof(struct template_node));
	decrypt = (struct template_node *)malloc(sizeof(struct template_node));
	sign = (struct template_node *)malloc(sizeof(struct template_node));
	sign_recover = (struct template_node *)malloc(sizeof(struct template_node));
	unwrap = (struct template_node *)malloc(sizeof(struct template_node));
	extractable = (struct template_node *)malloc(sizeof(struct template_node));
	never_extr = (struct template_node *)malloc(sizeof(struct template_node));
	always_sens = (struct template_node *)malloc(sizeof(struct template_node));
	wrap_with_trusted = (struct template_node *)malloc(sizeof(struct template_node));
	unwrap_templ = (struct template_node *)malloc(sizeof(struct template_node));
	always_auth = (struct template_node *)malloc(sizeof(struct template_node));
	public_key_info = (struct template_node *)malloc(sizeof(struct template_node));

	privk_class_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS)) ;
	privk_subject_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	privk_sensitive_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_decrypt_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_sign_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_sign_recover_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_unwrap_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_extractable_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_never_extr_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_always_sens_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_wrap_with_trusted_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_unwrap_templ_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	privk_always_auth_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	privk_public_key_info_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));

	if (!privk_class_attr || !privk_subject_attr || !privk_sensitive_attr
		|| !privk_decrypt_attr || !privk_sign_attr  ||
		!privk_sign_recover_attr || !privk_unwrap_attr ||
		!privk_extractable_attr || !privk_never_extr_attr ||
		!privk_always_sens_attr || !class || !subject ||
		!decrypt || !sensitive || !sign || !sign_recover ||
		!unwrap || !extractable || !never_extr ||
		!always_sens || !wrap_with_trusted || !unwrap_templ ||
		!always_auth|| !privk_wrap_with_trusted_attr ||
		!privk_unwrap_templ_attr || !privk_always_auth_attr ||
		!privk_public_key_info_attr || !public_key_info)
	{
		if (privk_class_attr)
			free(privk_class_attr);
		if (privk_subject_attr)
			free(privk_subject_attr);
		if (privk_sensitive_attr)
			free(privk_sensitive_attr);
		if (privk_decrypt_attr)
			free(privk_decrypt_attr);
		if (privk_sign_attr)
			free(privk_sign_attr);
		if (privk_sign_recover_attr)
			free(privk_sign_recover_attr);
		if (privk_unwrap_attr)
			free(privk_unwrap_attr);
		if (privk_extractable_attr)
			free(privk_extractable_attr);
		if (privk_always_sens_attr)
			free(privk_always_sens_attr);
		if (privk_never_extr_attr)
			free(privk_never_extr_attr);
		if (class)
			free(class);
		if (subject)
			free(subject);
		if (sensitive)
			free(sensitive);
		if (decrypt)
			free(decrypt);
		if (sign)
			free(sign);
		if (sign_recover)
			free(sign_recover);
		if (unwrap)
			free(unwrap);
		if (extractable)
			free(extractable);
		if (always_sens)
			free(always_sens);
		if (never_extr)
			free(never_extr);
		if (wrap_with_trusted)
			free(wrap_with_trusted);
		if (unwrap_templ)
			free(unwrap_templ);
		if (always_auth)
			free(always_auth);
		if (privk_wrap_with_trusted_attr)
			free(privk_wrap_with_trusted_attr);
		if (privk_unwrap_templ_attr)
			free(privk_unwrap_templ_attr);
		if (privk_always_auth_attr)
			free(privk_always_auth_attr);
		if (public_key_info)
			free(public_key_info);
		if (privk_public_key_info_attr)
			free(privk_public_key_info_attr);

		return CKR_HOST_MEMORY;
	}

	privk_class_attr->type = CKA_CLASS;
	privk_class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
	privk_class_attr->pValue = (CK_BYTE *)privk_class_attr + sizeof(CK_ATTRIBUTE);
	*(CK_OBJECT_CLASS *)privk_class_attr->pValue = CKO_PRIVATE_KEY;

	privk_subject_attr->type       = CKA_SUBJECT;
	privk_subject_attr->ulValueLen = 0;
	privk_subject_attr->pValue     = NULL;

	privk_sensitive_attr->type       = CKA_SENSITIVE;
	privk_sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_sensitive_attr->pValue     = (CK_BYTE *)privk_sensitive_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_sensitive_attr->pValue = TRUE;

	privk_decrypt_attr->type       = CKA_DECRYPT;
	privk_decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_decrypt_attr->pValue     = (CK_BYTE *)privk_decrypt_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_decrypt_attr->pValue = FALSE;

	privk_sign_attr->type       = CKA_SIGN;
	privk_sign_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_sign_attr->pValue     = (CK_BYTE *)privk_sign_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_sign_attr->pValue = TRUE;

	privk_sign_recover_attr->type       = CKA_SIGN_RECOVER;
	privk_sign_recover_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_sign_recover_attr->pValue     = (CK_BYTE *)privk_sign_recover_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_sign_recover_attr->pValue = FALSE;

	privk_unwrap_attr->type       = CKA_UNWRAP;
	privk_unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_unwrap_attr->pValue     = (CK_BYTE *)privk_unwrap_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_unwrap_attr->pValue = FALSE;

	privk_extractable_attr->type       = CKA_EXTRACTABLE;
	privk_extractable_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_extractable_attr->pValue     = (CK_BYTE *)privk_extractable_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_extractable_attr->pValue = FALSE;

	privk_never_extr_attr->type       = CKA_NEVER_EXTRACTABLE;
	privk_never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_never_extr_attr->pValue     = (CK_BYTE *)privk_never_extr_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_never_extr_attr->pValue = TRUE;

	privk_always_sens_attr->type       = CKA_ALWAYS_SENSITIVE;
	privk_always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_always_sens_attr->pValue     = (CK_BYTE *)privk_always_sens_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_always_sens_attr->pValue = TRUE;

	privk_wrap_with_trusted_attr->type       = CKA_WRAP_WITH_TRUSTED;
	privk_wrap_with_trusted_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_wrap_with_trusted_attr->pValue     = (CK_BYTE *)privk_wrap_with_trusted_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_wrap_with_trusted_attr->pValue = FALSE;

	privk_unwrap_templ_attr->type       = CKA_UNWRAP_TEMPLATE;
	privk_unwrap_templ_attr->ulValueLen = 0;
	privk_unwrap_templ_attr->pValue     = NULL;

	privk_always_auth_attr->type       = CKA_ALWAYS_AUTHENTICATE;
	privk_always_auth_attr->ulValueLen = sizeof(CK_BBOOL);
	privk_always_auth_attr->pValue     = (CK_BYTE *)privk_always_auth_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)privk_always_auth_attr->pValue = FALSE;

	privk_public_key_info_attr->type          = CKA_PUBLIC_KEY_INFO;
	privk_public_key_info_attr->ulValueLen    = 0;
	privk_public_key_info_attr->pValue        = NULL;

	class->attributes = privk_class_attr;
	subject->attributes = privk_subject_attr;
	sensitive->attributes = privk_sensitive_attr;
	decrypt->attributes = privk_decrypt_attr;
	sign->attributes = privk_sign_attr;
	sign_recover->attributes = privk_sign_recover_attr;
	unwrap->attributes = privk_unwrap_attr;
	extractable->attributes = privk_extractable_attr;
	never_extr->attributes = privk_never_extr_attr;
	always_sens->attributes = privk_always_sens_attr;
	wrap_with_trusted->attributes = privk_wrap_with_trusted_attr;
	unwrap_templ->attributes = privk_unwrap_templ_attr;
	always_auth->attributes = privk_always_auth_attr;
	public_key_info->attributes = privk_public_key_info_attr;

	p11_template_update_attr(tmpl_list, class);
	p11_template_update_attr(tmpl_list, subject);
	p11_template_update_attr(tmpl_list, sensitive);
	p11_template_update_attr(tmpl_list, decrypt);
	p11_template_update_attr(tmpl_list, sign);
	p11_template_update_attr(tmpl_list, sign_recover);
	p11_template_update_attr(tmpl_list, unwrap);
	p11_template_update_attr(tmpl_list, extractable);
	p11_template_update_attr(tmpl_list, never_extr);
	p11_template_update_attr(tmpl_list, always_sens);
	p11_template_update_attr(tmpl_list, wrap_with_trusted);
	p11_template_update_attr(tmpl_list, unwrap_templ);
	p11_template_update_attr(tmpl_list, always_auth);
	p11_template_update_attr(tmpl_list, public_key_info);

	return CKR_OK;
}


static CK_RV
rsa_privk_add_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	CK_RV rc;
	uint32_t rsa_priv_key_mech_count = 7;
	CK_MECHANISM_TYPE_PTR mech;
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = privk_add_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK) {
		print_error("privk_add_default_attr failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_KEY_TYPE));
	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_MECHANISM_TYPE));
	allowed_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ (sizeof(CK_MECHANISM_TYPE) * rsa_priv_key_mech_count));

	if (!key_type || !keygen_mech || !allowed_mech ||
		!keygen_mech_attr || !allowed_mech_attr ||
		!key_type_attr) {
		if (key_type)
			free(key_type);
		if (keygen_mech)
			free(keygen_mech);
		if (allowed_mech)
			free(allowed_mech);
		if (keygen_mech_attr)
			free(keygen_mech_attr);
		if (allowed_mech_attr)
			free(allowed_mech_attr);
		if (key_type_attr)
			free(key_type_attr);

		return CKR_HOST_MEMORY;
	}

	key_type_attr->type = CKA_KEY_TYPE;
	key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
	key_type_attr->pValue = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
	*(CK_KEY_TYPE *)key_type_attr->pValue = CKK_RSA;

	keygen_mech_attr->type = CKA_KEY_GEN_MECHANISM;
	if (op_type == OP_GENERATE) {
		keygen_mech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
		keygen_mech_attr->pValue = (CK_BYTE *)keygen_mech_attr + sizeof(CK_ATTRIBUTE);
		*(CK_MECHANISM_TYPE_PTR)keygen_mech_attr->pValue = CKM_RSA_PKCS_KEY_PAIR_GEN;
	} else {
		keygen_mech_attr->ulValueLen = 0;
		keygen_mech_attr->pValue = NULL;
	}

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = rsa_priv_key_mech_count *
					sizeof(CK_MECHANISM_TYPE);
	allowed_mech_attr->pValue = (CK_BYTE *)allowed_mech_attr
		+ sizeof(CK_ATTRIBUTE);
	mech = (CK_MECHANISM_TYPE_PTR)allowed_mech_attr->pValue;

	mech[0] = CKM_RSA_PKCS;
	mech[1] = CKM_MD5_RSA_PKCS;
	mech[2] = CKM_SHA1_RSA_PKCS;
	mech[3] = CKM_SHA224_RSA_PKCS;
	mech[4] = CKM_SHA256_RSA_PKCS;
	mech[5] = CKM_SHA384_RSA_PKCS;
	mech[6] = CKM_SHA512_RSA_PKCS;

	key_type->attributes = key_type_attr;
	keygen_mech->attributes = keygen_mech_attr;
	allowed_mech->attributes = allowed_mech_attr;

	p11_template_update_attr(tmpl_list, key_type);
	p11_template_update_attr(tmpl_list, keygen_mech);
	p11_template_update_attr(tmpl_list, allowed_mech);

	return CKR_OK;
}

static CK_RV
ecc_privk_add_default_attr(struct template_list *tmpl_list,
				CK_ULONG op_type)
{
	CK_RV rc;
	uint32_t ecc_priv_key_mech_count = 2;
	CK_MECHANISM_TYPE_PTR mech;
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = privk_add_default_attr(tmpl_list, op_type);
	if (rc != CKR_OK) {
		print_error("privk_add_default_attr failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_KEY_TYPE));
	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_MECHANISM_TYPE));
	allowed_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ (sizeof(CK_MECHANISM_TYPE) * ecc_priv_key_mech_count));

	if (!key_type || !keygen_mech || !allowed_mech ||
		!keygen_mech_attr || !allowed_mech_attr ||
		!key_type_attr) {
		if (key_type)
			free(key_type);
		if (keygen_mech)
			free(keygen_mech);
		if (allowed_mech)
			free(allowed_mech);
		if (keygen_mech_attr)
			free(keygen_mech_attr);
		if (allowed_mech_attr)
			free(allowed_mech_attr);
		if (key_type_attr)
			free(key_type_attr);

		return CKR_HOST_MEMORY;
	}

	key_type_attr->type = CKA_KEY_TYPE;
	key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
	key_type_attr->pValue = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
	*(CK_KEY_TYPE *)key_type_attr->pValue = CKK_EC;

	keygen_mech_attr->type = CKA_KEY_GEN_MECHANISM;
	if (op_type == OP_GENERATE) {
		keygen_mech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
		keygen_mech_attr->pValue = (CK_BYTE *)keygen_mech_attr + sizeof(CK_ATTRIBUTE);
		*(CK_MECHANISM_TYPE_PTR)keygen_mech_attr->pValue = CKM_EC_KEY_PAIR_GEN;
	} else {
		keygen_mech_attr->ulValueLen = 0;
		keygen_mech_attr->pValue = NULL;
	}

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = ecc_priv_key_mech_count *
		sizeof(CK_MECHANISM_TYPE);
	allowed_mech_attr->pValue = (CK_BYTE *)allowed_mech_attr
		+ sizeof(CK_ATTRIBUTE);

	mech = (CK_MECHANISM_TYPE_PTR)allowed_mech_attr->pValue;
	mech[0] = CKM_ECDSA_SHA1;
	mech[1] = CKM_ECDSA;

	key_type->attributes = key_type_attr;
	keygen_mech->attributes = keygen_mech_attr;
	allowed_mech->attributes = allowed_mech_attr;

	p11_template_update_attr(tmpl_list, key_type);
	p11_template_update_attr(tmpl_list, keygen_mech);
	p11_template_update_attr(tmpl_list, allowed_mech);

	return CKR_OK;
}

static
CK_RV attribute_check_required_base_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	CK_ATTRIBUTE *attr;
	CK_BBOOL found;

	found = p11_template_attribute_find(template, CKA_CLASS, &attr);

	if (op_type == OP_CREATE && found == FALSE) {
		print_error("Class attribute not given\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	return CKR_OK;
}


CK_RV
attribute_validate_base_attributes(CK_ATTRIBUTE *attr,
		CK_ULONG op_type)
{
	CK_BBOOL value;
	if (!attr) {
		print_error("attr passed is NULL");
		return CKR_FUNCTION_FAILED;
	}

	switch (attr->type) {
		case CKA_TOKEN:
			value = *(CK_BBOOL *)attr->pValue;
			if (value == CK_FALSE) {
				print_error("Session Objects not supported.\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			} else
				return CKR_OK;
		case CKA_CLASS:
		case CKA_PRIVATE:
			return CKR_OK;
		case CKA_LABEL:
			return CKR_OK;
		case CKA_MODIFIABLE:
			/* For now in any operation if CKA_MODIFIABLE
			  * is set to CK_TRUE, we are returning error */
			if ((op_type & (OP_CREATE|OP_GENERATE))  != 0) {
				value = *(CK_BBOOL *)attr->pValue;
				if (value == CK_TRUE) {
					print_error("Objects Modification not suppoted.\n");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				return CKR_OK;
			} else {
				print_error("Objects modification is not supported.\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
		case CKA_COPYABLE:
			value = *(CK_BBOOL *)attr->pValue;
			if (value == CK_TRUE) {
				print_error("Objects Copy not suppoted.\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			return CKR_OK;
		case CKA_DESTROYABLE:
			return CKR_OK;
		default:
			print_error("Template Inconsistent\n");
			return CKR_TEMPLATE_INCONSISTENT;
	}

	print_error(" Attribute Read Only op_type = %lu, Attr type = %lu\n",
				op_type, attr->type);
	return CKR_ATTRIBUTE_READ_ONLY;
}

static CK_RV
attribute_key_object_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	CK_ATTRIBUTE * attr = NULL;
	CK_BBOOL    found;

	found = p11_template_attribute_find(template, CKA_KEY_TYPE,
			&attr);
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("Key type not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	return attribute_check_required_base_attributes(template, op_type);
}


	static CK_RV
attribute_key_object_validate(CK_ATTRIBUTE *attr,
		CK_ULONG op_type)
{
	CK_BBOOL value;
	switch (attr->type) {
		case CKA_KEY_TYPE:
			if (op_type == OP_CREATE ||
					op_type == OP_GENERATE)
				return CKR_OK;
			else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
			return CKR_OK;

		case CKA_DERIVE:
			value = *(CK_BBOOL *)attr->pValue;
			if (value != CK_FALSE) {
				print_error("Derive Key not supported\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			} else
				return CKR_OK;

		case CKA_LOCAL:
			print_error("Attribute Read Only\n");
			return CKR_ATTRIBUTE_READ_ONLY;
		default:
			return attribute_validate_base_attributes(attr,
					op_type);
	}

	print_error("Attribute Type Invalid\n");
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
attribute_pubk_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	//CKO_PRIVATE_KEY has no required attributes

	return attribute_key_object_check_required_attributes(template,
			op_type);
}

	static CK_RV
attribute_pubk_validate(CK_ATTRIBUTE *attr, CK_ULONG op_type)
{
	CK_BBOOL value;
	switch (attr->type) {
		case CKA_SUBJECT:
			return CKR_OK;

		case CKA_ENCRYPT:
		case CKA_VERIFY:
			return CKR_OK;
		case CKA_VERIFY_RECOVER:
		case CKA_WRAP:
			value = *(CK_BBOOL *)attr->pValue;
			if (value == CK_TRUE) {
				print_error("Wrap/Verify Recover not supported\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			} else
				return CKR_OK;
		default:
			return attribute_key_object_validate(attr,
					op_type);
	}

	print_error("Attribute Type Invalid\n");
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
attribute_privk_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	//CKO_PRIVATE_KEY has no required attributes

	return attribute_key_object_check_required_attributes(template,
			op_type);
}


	static CK_RV
attribute_privk_validate(CK_ATTRIBUTE *attr, CK_ULONG op_type)
{
	CK_BBOOL value;
	switch (attr->type) {
		case CKA_SUBJECT:
		case CKA_DECRYPT:
		case CKA_SIGN:
			return CKR_OK;

		case CKA_SIGN_RECOVER:
		case CKA_UNWRAP:
			value = *(CK_BBOOL *)attr->pValue;
			if (value != CK_FALSE) {
				print_error("SIGN_RECOVER/UNWRAP not supported\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			} else
				return CKR_OK;
		case CKA_SENSITIVE:
			if (op_type == OP_CREATE ||
					op_type == OP_GENERATE) {
				value = *(CK_BBOOL *)attr->pValue;
				if (value != TRUE) {
					print_error("Attribute Read Only\n");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				} else
					return CKR_OK;
			} else
				return CKR_ATTRIBUTE_READ_ONLY;
		case CKA_EXTRACTABLE:
			value = *(CK_BBOOL *)attr->pValue;
			if ((op_type != OP_CREATE && op_type != OP_GENERATE) && value !=
					FALSE) {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (value == CK_TRUE) {
				print_error("CKA_EXTRACTABLE only CK_FALSE allowed\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			return CKR_OK;

		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
			print_error("Attribute Read Only\n");
			return CKR_ATTRIBUTE_READ_ONLY;

		default:
			return attribute_key_object_validate(attr,
					op_type);
	}

	print_error("Attribute Invalid \n");
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
attribute_rsa_pubk_check_required_attributes(
		struct template_list *template, CK_ULONG op_type)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_BBOOL   found = CK_FALSE;

	found = p11_template_attribute_find(template,
				CKA_MODULUS, &attr);
	if (!found) {
		if (op_type == OP_CREATE) {
			print_error("Modulus not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find(template,
				CKA_MODULUS_BITS, &attr);
	if (!found) {
		if (op_type == OP_GENERATE) {
			print_error("Modulus bits not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find(template,
				CKA_PUBLIC_EXPONENT, &attr);
	if (!found) {
		if (op_type == OP_CREATE) {
			print_error("Public Exponent not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	return attribute_pubk_check_required_attributes(template,
						op_type);
}


static
CK_RV attribute_rsa_pubk_validate(CK_ATTRIBUTE_PTR attr,
		CK_ULONG op_type)
{
	switch (attr->type) {
		case CKA_MODULUS_BITS:
			if (op_type == OP_GENERATE) {
				if (attr->ulValueLen != sizeof(CK_ULONG))
					return CKR_ATTRIBUTE_VALUE_INVALID;
				else {
					CK_ULONG mod_bits = *(CK_ULONG *)attr->pValue;

					if (mod_bits < 1024 || mod_bits > 2048) {
						print_error("Unsupported RSA size = %lu\n", mod_bits);
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}

					if (mod_bits % 8 != 0) {
						print_error("Unsupported RSA size = %lu\n", mod_bits);
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}

					return CKR_OK;
				}
			} else {
				print_error("Attribute read only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_MODULUS:
			if (op_type == OP_CREATE) {
				//				p11_attribute_trim(attr);
				return CKR_OK;
			}
			else {
				print_error("Attribute read only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_PUBLIC_EXPONENT:
			if (op_type == OP_CREATE || op_type == OP_GENERATE) {
				//				p11_attribute_trim(attr);
				return CKR_OK;
			} else {
				print_error("Attribute read only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		default:
			return attribute_pubk_validate(attr, op_type);
	}

}

static CK_RV
attribute_rsa_privk_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_BBOOL   found;


	found = p11_template_attribute_find(template, CKA_MODULUS, &attr);
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("Modulus not given \n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}


	//
	// PKCS #11 is flexible with respect to which attributes must be present
	// in an RSA key.  Keys can be specified in Chinese-Remainder format or
	// they can be specified in modular-exponent format.  Right now, I only
	// support keys created in Chinese-Remainder format.  That is, we return
	// CKR_TEMPLATE_INCOMPLETE if a modular-exponent key is specified.  This
	// is allowed by PKCS #11.
	//
	// In the future, we should allow for creation of keys in modular-exponent
	// format too.  This raises some issues.  It's easy enough to recognize
	// when a key has been specified in modular-exponent format.  And it's
	// easy enough to recognize when all attributes have been specified
	// (which is what we require right now).  What's trickier to handle is
	// the "middle" cases in which more than the minimum yet less than the
	// full number of attributes have been specified.  Do we revert back to
	// modular-exponent representation?  Do we compute the missing attributes
	// ourselves?  Do we simply return CKR_TEMPLATE_INCOMPLETE?
	//

	found = p11_template_attribute_find(template, CKA_PUBLIC_EXPONENT,
			&attr );
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("Public Exponent not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find(template, CKA_PRIVATE_EXPONENT,
			&attr);
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("Private Exponent not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}
#if 0
	found = p11_template_attribute_find( tmpl, CKA_PRIME_1, &attr );
	if (!found) {
		if (mode == MODE_CREATE){
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find( tmpl, CKA_PRIME_2, &attr );
	if (!found) {
		if (mode == MODE_CREATE){
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find( tmpl, CKA_EXPONENT_1, &attr );
	if (!found) {
		if (mode == MODE_CREATE){
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find( tmpl, CKA_EXPONENT_2, &attr );
	if (!found) {
		if (mode == MODE_CREATE){
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find( tmpl, CKA_COEFFICIENT, &attr );
	if (!found) {
		if (mode == MODE_CREATE){
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}
#endif
	return attribute_privk_check_required_attributes(template, op_type);
}

static
CK_RV attribute_rsa_privk_validate(CK_ATTRIBUTE_PTR attr,
		CK_ULONG op_type)
{
	switch (attr->type) {
		case CKA_MODULUS:
		case CKA_PRIVATE_EXPONENT:
			if (op_type == OP_CREATE) {
				//				p11_attribute_trim(attr);
				return CKR_OK;
			} else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_PUBLIC_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
			if (op_type == OP_CREATE) {
				//				p11_attribute_trim( attr );
				return CKR_OK;
			}
			else{
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		default:
			return attribute_privk_validate(attr,
					op_type);
	}

}

static CK_RV
attribute_ec_pubk_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_BBOOL   found;


	found = p11_template_attribute_find(template, CKA_EC_PARAMS, &attr);
	if (!found) {
		if (op_type == OP_CREATE || op_type == OP_GENERATE) {
			print_error("EC Params not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find(template, CKA_EC_POINT, &attr);
	if (!found) {
		if (op_type == OP_CREATE) {
			print_error("EC Point is not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	return attribute_pubk_check_required_attributes(template, op_type);
}


static
CK_RV attribute_ec_pubk_validate(CK_ATTRIBUTE_PTR attr,
		CK_ULONG op_type)
{
	switch (attr->type) {
		case CKA_EC_PARAMS:
			if (op_type == OP_GENERATE || op_type == OP_CREATE)
				return CKR_OK;
			else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_EC_POINT:
			if (op_type == OP_CREATE)
				return CKR_OK;
			else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		default:
			return attribute_pubk_validate(attr, op_type);
	}
}

static CK_RV
attribute_ec_privk_check_required_attributes(
		struct template_list *template,
		CK_ULONG op_type)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_BBOOL   found;


	found = p11_template_attribute_find(template, CKA_EC_PARAMS, &attr);
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("EC Params not given\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	found = p11_template_attribute_find(template, CKA_VALUE, &attr);
	if (!found) {
		if (op_type == OP_CREATE){
			print_error("Priv Key Value not provided for EC\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	return attribute_privk_check_required_attributes(template, op_type);
}


static
CK_RV attribute_ec_privk_validate(CK_ATTRIBUTE_PTR attr,
		CK_ULONG op_type)
{
	switch (attr->type) {
		case CKA_EC_PARAMS:
			if (op_type == OP_CREATE)
				return CKR_OK;
			else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		case CKA_VALUE:
			if (op_type == OP_CREATE) {
				//				p11_attribute_trim(attr);
				return CKR_OK;
			} else {
				print_error("Attribute Read Only\n");
				return CKR_ATTRIBUTE_READ_ONLY;
			}
		default:
			return attribute_privk_validate(attr, op_type);
	}

}

static CK_RV template_merge(struct template_list *dest,
			struct template_list **src)
{
	CK_RV rc = CKR_OK;
	struct template_node *temp = NULL, *s = NULL;
	struct template_list *src_tmpl_list = NULL;

	if (!dest || !src) {
		print_error("Invalid Function arguements\n");
		return CKR_FUNCTION_FAILED;
	}

	src_tmpl_list = *src;

	temp = STAILQ_FIRST(src_tmpl_list);
	while (temp) {
		s = STAILQ_NEXT(temp, entry);
		STAILQ_REMOVE(src_tmpl_list, temp, template_node, entry);
		STAILQ_NEXT(temp, entry) = NULL;
		rc = p11_template_update_attr(dest, temp);
		if (rc != CKR_OK) {
			print_error("p11_template_update_attr failed\n");
			return rc;
		}
		temp = s;
	}

	template_destroy_template_list(src_tmpl_list);
	*src = NULL;

	return CKR_OK;
}

/* p11_template_add_default_common_attr()
 *
 * Set the default attributes common to all objects:
 *
 *	CKA_TOKEN:	TRUE
 *	CKA_PRIVATE:	FALSE -- Cryptoki leaves this up to the token to decide
 *	CKA_MODIFIABLE:	FALSE
 */
static CK_RV
p11_template_add_default_common_attr(
			struct template_list *tmpl_list,
			CK_ULONG op_type)
{
	/* To satisfy compiler */
	op_type = op_type;

	struct template_node *token_node;
	struct template_node *mod_node;
	struct template_node *copyable_node;
	struct template_node *destroyable_node;

	CK_ATTRIBUTE *com_token_attr;
	CK_ATTRIBUTE *com_mod_attr;
	CK_ATTRIBUTE *com_copyable_attr;
	CK_ATTRIBUTE *com_destroyable_attr;
	CK_ATTRIBUTE_PTR temp = NULL_PTR;

	token_node = (struct template_node *)malloc(sizeof(struct template_node));
	mod_node = (struct template_node *)malloc(sizeof(struct template_node));
	copyable_node = (struct template_node *)malloc(sizeof(struct template_node));
	destroyable_node = (struct template_node *)malloc(sizeof(struct template_node));

	/* add the default common attributes */
	com_token_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));
	com_mod_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));
	com_copyable_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));
	com_destroyable_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));

	if (!com_token_attr || !com_mod_attr ||
		!com_copyable_attr || !com_copyable_attr ||
		!token_node || !mod_node ||
		!copyable_node || !destroyable_node) {
		if (com_token_attr) free(com_token_attr);
		if (com_mod_attr) free(com_mod_attr);
		if (com_copyable_attr) free(com_copyable_attr);
		if (com_destroyable_attr) free(com_destroyable_attr);
		if (token_node) free(token_node);
		if (mod_node) free(mod_node);
		if (copyable_node) free(copyable_node);
		if (destroyable_node) free(destroyable_node);

		return CKR_HOST_MEMORY;
	}

	com_token_attr->type = CKA_TOKEN;
	com_token_attr->ulValueLen = sizeof(CK_BBOOL);
	com_token_attr->pValue = (CK_BYTE *)com_token_attr +
				sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)com_token_attr->pValue = TRUE;

	com_mod_attr->type = CKA_MODIFIABLE;
	com_mod_attr->ulValueLen = sizeof(CK_BBOOL);
	com_mod_attr->pValue = (CK_BYTE *)com_mod_attr +
				sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)com_mod_attr->pValue = FALSE;

	com_copyable_attr->type = CKA_COPYABLE;
	com_copyable_attr->ulValueLen = sizeof(CK_BBOOL);
	com_copyable_attr->pValue = (CK_BYTE *)com_copyable_attr +
				sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)com_copyable_attr->pValue = FALSE;

	com_destroyable_attr->type = CKA_DESTROYABLE;
	com_destroyable_attr->ulValueLen = sizeof(CK_BBOOL);
	com_destroyable_attr->pValue = (CK_BYTE *)com_destroyable_attr
		+ sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)com_destroyable_attr->pValue = TRUE;


	token_node->attributes = com_token_attr;
	mod_node->attributes = com_mod_attr;
	copyable_node->attributes = com_copyable_attr;
	destroyable_node->attributes = com_destroyable_attr;

	p11_template_update_attr(tmpl_list, token_node);
	p11_template_update_attr(tmpl_list, mod_node);
	p11_template_update_attr(tmpl_list, copyable_node);
	p11_template_update_attr(tmpl_list, destroyable_node);

	if (!p11_template_attribute_find(
			tmpl_list, CKA_PRIVATE,
			&temp)) {
		struct template_node *priv_node = NULL;
		CK_ATTRIBUTE_PTR com_priv_attr = NULL_PTR;

		com_priv_attr = (CK_ATTRIBUTE_PTR)malloc(
				sizeof(CK_ATTRIBUTE) +
				sizeof(CK_BBOOL));
		priv_node = (struct template_node *)malloc(
				sizeof(struct template_node));

		priv_node->attributes = com_priv_attr;

		com_priv_attr->type = CKA_PRIVATE;
		com_priv_attr->ulValueLen = sizeof(CK_BBOOL);
		com_priv_attr->pValue = (CK_BYTE *)com_priv_attr +
					sizeof(CK_ATTRIBUTE);
		*(CK_BBOOL *)com_priv_attr->pValue = FALSE;
	}

	return CKR_OK;
}

static CK_RV p11_template_add_default_attr(OBJECT *obj,
					CK_ULONG op_type)
{
	CK_RV rc;

	CK_ULONG class, subclass;

	class = obj->obj_class;
	subclass = obj->obj_subclass;

	/* first add the default common attributes */
	rc = p11_template_add_default_common_attr(&obj->template_list,
						op_type);
	if (rc != CKR_OK) {
		print_error("p11_template_add_default_common_attr failed.\n");
		return rc;
	}

	/* set the template class-specific default attributes */
	switch (class) {
		case CKO_PUBLIC_KEY:
			switch (subclass) {
				case CKK_RSA:
					return rsa_pubk_add_default_attr(&obj->template_list, op_type);
				case CKK_EC:
					return ecc_pubk_add_default_attr(&obj->template_list, op_type);
				default:
					print_error("Invalid Attribute\n");
					return CKR_ATTRIBUTE_VALUE_INVALID;
			}

		case CKO_PRIVATE_KEY:
			switch (subclass) {
				case CKK_RSA:
					return rsa_privk_add_default_attr(&obj->template_list, op_type);
				case CKK_EC:
					return ecc_privk_add_default_attr(&obj->template_list, op_type);
				default:
					print_error("Invalid Attribute\n");
					return CKR_ATTRIBUTE_VALUE_INVALID;
			}

		default:
			print_error("Invalid Attribute\n");
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
}

static CK_RV
p11_template_add_attr(struct template_list *template_list,
		CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
	struct template_node *tmpl_node;
	struct CK_ATTRIBUTE *attr;
	unsigned int i;

	for (i = 0; i < ulCount; i++) {

		if (!p11_is_attribute_defined(pTemplate[i].type)) {
			print_error("Template type invalid \n");
			continue;
		}

		attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
					      pTemplate[i].ulValueLen);
		if (!attr) {
			print_error("attr malloc failed\n");
			return CKR_HOST_MEMORY;
		}

		attr->type = pTemplate[i].type;
		attr->ulValueLen = pTemplate[i].ulValueLen;

		/* If there is anything in the ulValueLen, then a complete
		  * buffer for CK_ATTRIBUTE + ulValueLen is allocated
		  * and pValue will point to buffer_start +
		  * sizeof(CK_ATTRIBUTE).
		  */
		if (attr->ulValueLen != 0) {
			attr->pValue = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
			memcpy(attr->pValue, pTemplate[i].pValue,
				attr->ulValueLen);
		} else
			attr->pValue = NULL;

		tmpl_node = malloc(sizeof(struct template_node));
		if (!tmpl_node) {
			print_error("template node malloc failed\n");
			return CKR_HOST_MEMORY;
		}

		tmpl_node->attributes = attr;
		print_info("tmpl_node = %p, attr type = 0x%08lx, attr = %p, len = %lu\n",
			tmpl_node, attr->type, attr->pValue, attr->ulValueLen);
		p11_template_update_attr(template_list, tmpl_node);
	}

	return CKR_OK;
}

static CK_BBOOL p11_template_check_attr(struct template_list *tmpl_list,
		CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE **attr)
{
	CK_ATTRIBUTE *a = NULL;
	struct template_node *temp;

	if (!tmpl_list || !attr)
		return FALSE;

	STAILQ_FOREACH(temp, tmpl_list, entry) {
		a = (CK_ATTRIBUTE *)temp->attributes;
		if (type == a->type) {
			*attr = a;
			return TRUE;
		}
	}

	*attr = NULL;
	return FALSE;
}

CK_BBOOL p11_template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount,
		struct template_list *tmpl_list)
{
	CK_ATTRIBUTE *attr1 = NULL;
	CK_ATTRIBUTE *attr2 = NULL;
	CK_ULONG i;
	CK_RV rc;

	if (!t1 || !tmpl_list)
		return FALSE;

	attr1 = t1;

	for (i = 0; i < ulCount; i++) {
		rc = p11_template_check_attr(tmpl_list, attr1->type, &attr2);
		if (rc == FALSE)
			return FALSE;

		if (attr1->ulValueLen != attr2->ulValueLen)
			return FALSE;

		if (memcmp(attr1->pValue, attr2->pValue, attr1->ulValueLen) != 0)
			return FALSE;

		attr1++;
	}

	return TRUE;
}

static CK_BBOOL p11_template_get_class(struct template_list *tmpl_list,
	CK_ULONG *class, CK_ULONG *subclass)
{
	CK_BBOOL found = FALSE;
	struct template_node *tmpl_temp;

	if (!tmpl_list || !class || !subclass)
		return FALSE;

	/* have to iterate through all attributes. no early exits */
	STAILQ_FOREACH(tmpl_temp, tmpl_list, entry) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)tmpl_temp->attributes;

		if (attr->type == CKA_CLASS) {
			*class = *(CK_OBJECT_CLASS *)attr->pValue;
			found = TRUE;
		}

		/* underneath, these guys are both CK_ULONG so we
		 * could combine this
		 */
		if (attr->type == CKA_CERTIFICATE_TYPE)
			*subclass = *(CK_CERTIFICATE_TYPE *)attr->pValue;

		if (attr->type == CKA_KEY_TYPE)
			*subclass = *(CK_KEY_TYPE *)attr->pValue;
	}

	return found;
}

CK_BBOOL p11_template_attribute_find(struct template_list *template,
				CK_ATTRIBUTE_TYPE type,
				CK_ATTRIBUTE **attr)
{
	struct template_node *tmpl_node;

	if (!template || !attr)
		return CK_FALSE;

	/* have to iterate through all attributes. no early exits */
	STAILQ_FOREACH(tmpl_node, template, entry) {
		CK_ATTRIBUTE *temp = (CK_ATTRIBUTE *)tmpl_node->attributes;
		if (type == temp->type) {
			*attr = temp;
			return CK_TRUE;
		}
	}

	*attr = NULL;
	return CK_FALSE;
}

CK_BBOOL
template_is_modifiable_set(struct template_list *template)
{
	CK_ATTRIBUTE  *modifiable_attr = NULL;

	if (p11_template_attribute_find(template,
			CKA_MODIFIABLE, &modifiable_attr)) {
		if (*(CK_BBOOL *)(modifiable_attr->pValue) == CK_TRUE)
			return CK_TRUE;
		else
			return CK_FALSE;
	} else
		return CK_FALSE;
}

CK_BBOOL template_is_private_set(struct template_list *template)
{
	CK_ATTRIBUTE  *private_attr = NULL;

	if (p11_template_attribute_find(template,
			CKA_PRIVATE, &private_attr)) {
		if (*(CK_BBOOL *)(private_attr->pValue) == CK_TRUE)
			return CK_TRUE;
		else
			return CK_FALSE;
	} else
		return CK_FALSE;
}

CK_BBOOL template_is_public_set(struct template_list *template)
{
	CK_BBOOL rc;

	rc = template_is_private_set(template);

	if (rc)
		return FALSE;
	else
		return TRUE;
}

CK_BBOOL
template_is_token_object(struct template_list *template)
{
	CK_ATTRIBUTE  *token_attr = NULL;

	if (p11_template_attribute_find(template,
			CKA_TOKEN, &token_attr)) {
		if (*(CK_BBOOL *)(token_attr->pValue) == CK_TRUE)
			return CK_TRUE;
		else
			return CK_FALSE;
	} else
		return CK_FALSE;
}

CK_BBOOL
template_is_session_object(struct template_list *template)
{
	CK_BBOOL rc;

	rc = template_is_token_object(template);

	if (rc)
		return FALSE;
	else
		return TRUE;
}

CK_RV
template_destroy_template_list(struct template_list *template)
{
	CK_RV rc = CKR_OK;
	struct template_list *tmpl_list = NULL;
	struct template_node *t = NULL;

	if (!template)
		return CKR_ARGUMENTS_BAD;

	tmpl_list = template;
	while ((t = STAILQ_FIRST(tmpl_list)) != NULL ) {
		if (t->attributes)
			free(t->attributes);
			STAILQ_REMOVE(tmpl_list, t, template_node, entry);
			free(t);
	}

	return rc;
}

CK_RV
template_create_template_list(CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount,
			struct template_list **tmpl_list)
{
	CK_RV rc = CKR_OK;
	struct template_list *list = NULL;

	/* Not checking pTemplate validity status, because in some
	  * cases it can be NULL also. Like in case if private key template
	  * in C_GenerateKeyPair function.
	  */
	if (!tmpl_list) {
		print_error("Arguments bad\n");
		return CKR_ARGUMENTS_BAD;
	}

	list = malloc(sizeof(struct template_list));
	if (!list) {
		print_error("malloc failed\n");
		rc = CKR_HOST_MEMORY;
		goto end;
	}

	STAILQ_INIT(list);
	rc = p11_template_add_attr(list, pTemplate, ulCount);
	if (rc != CKR_OK) {
		print_error("p11_template_add_attr failed\n");
		goto end;
	}

	*tmpl_list = list;
end:
	return rc;
}

static CK_RV
template_validate_attribute(CK_ATTRIBUTE *attr,
				CK_ULONG class, CK_ULONG subclass,
				CK_ULONG op_type)
{
	if (class == CKO_PUBLIC_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return attribute_rsa_pubk_validate(attr,
						op_type);

		case CKK_ECDSA:
			return attribute_ec_pubk_validate(attr,
						op_type);

		default:
			print_error("Only RSA/EC Keys supported\n");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	} else if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return attribute_rsa_privk_validate(attr,
						op_type);
		case CKK_ECDSA:
			return attribute_ec_privk_validate(attr,
						op_type);

		default:
			print_error("Only RSA/EC Keys supported\n");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	print_error("Only Public/Private Keys are supported\n");
	return CKR_ATTRIBUTE_VALUE_INVALID;

}

CK_RV
template_check_required_attributes(
				struct template_list *template,
				CK_ULONG class,
				CK_ULONG subclass,
				CK_ULONG op_type)
{
	if (class == CKO_PUBLIC_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return attribute_rsa_pubk_check_required_attributes(template, op_type);

		case CKK_ECDSA:
			return attribute_ec_pubk_check_required_attributes(template, op_type);

		default:
			print_error("Only RSA/EC Keys supported\n");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	} else if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return attribute_rsa_privk_check_required_attributes(template, op_type);

		case CKK_ECDSA:
			return attribute_ec_privk_check_required_attributes(template, op_type);

		default:
			print_error("Only RSA/EC  keys Supported\n");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	print_error("Only Public/Private Keys supported\n");
	return CKR_ATTRIBUTE_VALUE_INVALID;
}


CK_RV
template_validate_attributes(struct template_list *template,
				CK_ULONG class,
				CK_ULONG subclass,
				CK_ULONG op_type)
{
	CK_RV rc = CKR_OK;
	struct template_node *tmpl_node = NULL;

	STAILQ_FOREACH(tmpl_node, template, entry) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)tmpl_node->attributes;
		rc = template_validate_attribute(attr, class, subclass,
					op_type);
		if (rc != CKR_OK) {
			print_error("template_validate_attribute failed\n");
			goto end;
		}
	}

end:
	return rc;
}

static CK_BBOOL
check_rsa_privk_exportability(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
		case CKA_PRIVATE_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
			return FALSE;
		default:
			return TRUE;
	}
}

static CK_BBOOL
check_ecc_privk_exportability(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_VALUE:
		return FALSE;
	default:
		return TRUE;
	}
}

static CK_BBOOL check_attr_exportability(struct template_list *tmpl_list,
		CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE *sensitive = NULL;
	CK_ATTRIBUTE *extractable = NULL;
	CK_ULONG class;
	CK_ULONG subclass;
	CK_BBOOL sensitive_val;
	CK_BBOOL extractable_val;

	if (!tmpl_list)
		return FALSE;

	p11_template_get_class(tmpl_list, &class, &subclass);

	/* Early exits:
	 * 1) CKA_SENSITIVE and CKA_EXTRACTABLE only apply to private key
	 * and secret key objects.  If object type is any other, then
	 * by default the attribute is exportable.
	 *
	 * 2) If CKA_SENSITIVE = FALSE  and CKA_EXTRACTABLE = TRUE then
	 * all attributes are exportable
	 */
	if (class != CKO_PRIVATE_KEY && class != CKO_SECRET_KEY)
		return TRUE;

	sensitive_val = p11_template_check_attr(tmpl_list, CKA_SENSITIVE,
				&sensitive);
	extractable_val = p11_template_check_attr(tmpl_list, CKA_EXTRACTABLE,
				&extractable);
	if (sensitive_val && extractable_val) {
		sensitive_val = *(CK_BBOOL *)sensitive->pValue;
		extractable_val = *(CK_BBOOL *)extractable->pValue;
		if (sensitive_val == FALSE && extractable_val == TRUE)
			return TRUE;
	} else {
		return FALSE;
	}

	/* So we know the object is having CKA_SENSITIVE = TRUE
	 * or CKA_EXTRACTABLE = FALSE (or both).
	 * now we need to check if particular attribute in question is
	 * a "sensitive" attribute or not.
	 */
	if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return check_rsa_privk_exportability(type);
		case CKK_EC:
			return check_ecc_privk_exportability(type);

		default:
			return TRUE;
		}
	}

	return TRUE;
}

static CK_RV map_pkcs_to_sk_attr(CK_ATTRIBUTE_PTR ck_attr,
		CK_ULONG ck_attr_count, SK_ATTRIBUTE **sk_attrs,
		uint32_t *attr_count)
{
	CK_ATTRIBUTE_TYPE ck_attr_type;
	CK_ATTRIBUTE_PTR ck_attrs = NULL;

	SK_ATTRIBUTE *sk_attr =NULL;

	unsigned char *sk_label = NULL, *sk_id = NULL;
	uint32_t *mod_bits = NULL;
	unsigned char *sk_mod = NULL, *sk_pub_exp = NULL;
	unsigned char *sk_ec_params = NULL, *sk_ec_point = NULL;
	uint32_t i = 0, attrCount = 0;

	sk_attr = malloc(sizeof(SK_ATTRIBUTE) * 7);
	if (!sk_attr)
		return CKR_HOST_MEMORY;

	memset(sk_attr, 0, sizeof(SK_ATTRIBUTE) * 7);

	for (i = 0; i < ck_attr_count; i++) {
		ck_attrs = &ck_attr[i];
		ck_attr_type = ck_attrs->type;

		switch(ck_attr_type) {
#if 0
			case CKA_CLASS:
				ck_obj_class = *(CK_OBJECT_CLASS *)ck_attr->pValue;
				switch (ck_obj_class) {
					case CKO_PRIVATE_KEY:
						sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
							sizeof(CK_OBJECT_CLASS));
						if (!sk_attr)
							return CKR_HOST_MEMORY;

						sk_object_type = (SK_OBJECT_TYPE *)((uint8_t  *)sk_attr + sizeof(SK_ATTRIBUTE));
						*(sk_object_type) = SK_KEY_PAIR;

						sk_attr->type = SK_ATTR_OBJECT_TYPE;
						sk_attr->value = sk_object_type;
						sk_attr->valueLen = sizeof(SK_OBJECT_TYPE);

						break;
					case CKO_PUBLIC_KEY:
						sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
							sizeof(CK_OBJECT_CLASS));
						if (!sk_attr)
							return CKR_HOST_MEMORY;

						sk_object_type = (SK_OBJECT_TYPE *)((uint8_t  *)sk_attr + sizeof(SK_ATTRIBUTE));
						*(sk_object_type) = SK_PUBLIC_KEY;

						sk_attr->type = SK_ATTR_OBJECT_TYPE;
						sk_attr->value = sk_object_type;
						sk_attr->valueLen = sizeof(SK_OBJECT_TYPE);

						break;
					default:
						print_error("Ojbect type not supported\n");
						return CKR_ATTRIBUTE_TYPE_INVALID;
				}
				break;
			case CKA_KEY_TYPE:
				ck_key_type = *(CK_KEY_TYPE *)ck_attr->pValue;

				switch (ck_key_type) {
					case CKK_RSA:
						sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
							sizeof(CK_KEY_TYPE));
						if (!sk_attr)
							return CKR_HOST_MEMORY;

						sk_key_type = (SK_KEY_TYPE *)((uint8_t  *)sk_attr + sizeof(SK_ATTRIBUTE));
						*(sk_key_type) = SKK_RSA;

						sk_attr->type = SK_ATTR_KEY_TYPE;
						sk_attr->value = sk_key_type;
						sk_attr->valueLen = sizeof(SK_KEY_TYPE);

						break;

					case CKK_EC:
						sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
							sizeof(CK_KEY_TYPE));
						if (!sk_attr)
							return CKR_HOST_MEMORY;

						sk_key_type = (SK_KEY_TYPE *)((uint8_t  *)sk_attr + sizeof(SK_ATTRIBUTE));
						*(sk_key_type) = SKK_EC;

						sk_attr->type = SK_ATTR_KEY_TYPE;
						sk_attr->value = sk_key_type;
						sk_attr->valueLen = sizeof(SK_KEY_TYPE);

						break;

					default:
						print_error("Key type not supported\n");
						return CKR_ATTRIBUTE_TYPE_INVALID;
				}
				break;
#endif
			case CKA_LABEL:
				sk_label = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_label)
					return CKR_HOST_MEMORY;
				memset(sk_label, 0, ck_attrs->ulValueLen);
				memcpy(sk_label, ck_attrs->pValue, ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_OBJECT_LABEL;
				sk_attr[attrCount].value = sk_label;
				sk_attr[attrCount].valueLen = ck_attrs->ulValueLen;
				attrCount++;

				break;
			case CKA_ID:
				sk_id = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_id)
					return CKR_HOST_MEMORY;

				memset(sk_id, 0, ck_attrs->ulValueLen);
				memcpy(sk_id, ck_attrs->pValue, ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_OBJECT_INDEX;
				sk_attr[attrCount].value = sk_id;
				sk_attr[attrCount].valueLen = ck_attrs->ulValueLen;
				attrCount++;

				break;
			case CKA_MODULUS_BITS:
				mod_bits = malloc(	sizeof(uint32_t));
				if (!mod_bits)
					return CKR_HOST_MEMORY;
				*mod_bits = *(uint32_t *)(ck_attrs->pValue);
				sk_attr[attrCount].type = SK_ATTR_MODULUS_BITS;
				sk_attr[attrCount].value = mod_bits;
				sk_attr[attrCount].valueLen = sizeof(uint32_t);
				attrCount++;

				break;
			case CKA_MODULUS:
				sk_mod = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_mod)
					return CKR_HOST_MEMORY;

				memset(sk_mod, 0, ck_attrs->ulValueLen);
				memcpy(sk_mod, ck_attrs->pValue, ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_MODULUS;
				sk_attr[attrCount].value = sk_mod;
				sk_attr[attrCount].valueLen = (uint32_t)ck_attrs->ulValueLen;
				attrCount++;

				break;
			case CKA_PUBLIC_EXPONENT:
				sk_pub_exp = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_pub_exp)
					return CKR_HOST_MEMORY;

				memset(sk_pub_exp, 0, ck_attrs->ulValueLen);
				memcpy(sk_pub_exp, ck_attrs->pValue,
					ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_PUBLIC_EXPONENT;
				sk_attr[attrCount].value = sk_pub_exp;
				sk_attr[attrCount].valueLen = (uint32_t)ck_attrs->ulValueLen;
				attrCount++;

				break;
			case CKA_EC_PARAMS:
				sk_ec_params = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_ec_params)
					return CKR_HOST_MEMORY;

				memset(sk_ec_params, 0, ck_attrs->ulValueLen);
				memcpy(sk_ec_params, ck_attrs->pValue,
					ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_PARAMS;
				sk_attr[attrCount].value = sk_ec_params;
				sk_attr[attrCount].valueLen = ck_attrs->ulValueLen;
				attrCount++;

				break;
			case CKA_EC_POINT:
				sk_ec_point = (unsigned char *)malloc(
					ck_attrs->ulValueLen);
				if (!sk_ec_point)
					return CKR_HOST_MEMORY;

				memset(sk_ec_point, 0, ck_attrs->ulValueLen);
				memcpy(sk_ec_point, ck_attrs->pValue,
					ck_attrs->ulValueLen);

				sk_attr[attrCount].type = SK_ATTR_POINT;
				sk_attr[attrCount].value = sk_ec_point;
				sk_attr[attrCount].valueLen = ck_attrs->ulValueLen;
				attrCount++;

				break;
			default:
				break;
		}
	}

	*attr_count = attrCount;
	*sk_attrs = sk_attr;
	return CKR_OK;
}

static CK_RV map_sk_to_pkcs_attr(SK_ATTRIBUTE *sk_attrs,
		CK_ATTRIBUTE_PTR *ck_attr)
{
	SK_OBJECT_TYPE sk_obj_type = SK_ANY_TYPE;
	SK_KEY_TYPE sk_key_type;
	SK_ATTRIBUTE_TYPE sk_attr_type;
	CK_ATTRIBUTE_PTR ck_attrs;
	CK_OBJECT_CLASS *ck_obj_class;
	CK_KEY_TYPE *ck_key_type;
	CK_BYTE *ck_label, *ck_id;
	CK_ULONG *mod_bits;
	CK_BYTE *temp;
	uint32_t i = 0;

	ck_attr = ck_attr;

	sk_attr_type = sk_attrs[i].type;
	switch(sk_attr_type) {
		case SK_ATTR_OBJECT_TYPE:
			sk_obj_type = *(SK_OBJECT_TYPE *)sk_attrs[i].value;
			switch (sk_obj_type) {
				case SK_KEY_PAIR:
					ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sizeof(CK_OBJECT_CLASS));
					if (!ck_attrs)
						return CKR_HOST_MEMORY;

					ck_obj_class = (CK_OBJECT_CLASS *)((CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_obj_class) = CKO_PRIVATE_KEY;

					ck_attrs->type = CKA_CLASS;
					ck_attrs->pValue = ck_obj_class;
					ck_attrs->ulValueLen = sizeof(CK_OBJECT_CLASS);

					break;
				case SK_PUBLIC_KEY:
					ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sizeof(CK_OBJECT_CLASS));
					if (!ck_attrs)
						return CKR_HOST_MEMORY;

					ck_obj_class =  (CK_OBJECT_CLASS *)((CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_obj_class) = CKO_PUBLIC_KEY;

					ck_attrs->type = CKA_CLASS;
					ck_attrs->pValue = ck_obj_class;
					ck_attrs->ulValueLen = sizeof(CK_OBJECT_CLASS);

					break;
				default:
					print_error("Ojbect type not supported\n");
					return CKR_ATTRIBUTE_TYPE_INVALID;
			}
			break;
		case SK_ATTR_KEY_TYPE:
			sk_key_type = *(SK_KEY_TYPE *)sk_attrs[i].value;

			switch (sk_key_type) {
				case SKK_RSA:
					ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sizeof(CK_KEY_TYPE));
					if (!ck_attrs)
						return CKR_HOST_MEMORY;

					ck_key_type = (CK_KEY_TYPE *)((CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_key_type) = CKK_RSA;

					ck_attrs->type = CKA_KEY_TYPE;
					ck_attrs->pValue = ck_key_type;
					ck_attrs->ulValueLen = sizeof(CK_KEY_TYPE);
					break;

				case SKK_EC:
					ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sizeof(CK_KEY_TYPE));
					if (!ck_attrs)
						return CKR_HOST_MEMORY;

					ck_key_type = (CK_KEY_TYPE *)((CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_key_type) = CKK_EC;

					ck_attrs->type = CKA_KEY_TYPE;
					ck_attrs->pValue = ck_key_type;
					ck_attrs->ulValueLen = sizeof(CK_KEY_TYPE);
					break;

				default:
					print_error("Key type not supported\n");
					return CKR_ATTRIBUTE_TYPE_INVALID;
			}
			break;
		case SK_ATTR_OBJECT_LABEL:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			ck_label = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(ck_label, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_LABEL;
			ck_attrs->pValue = ck_label;
			ck_attrs->ulValueLen = sk_attrs->valueLen;
			break;

		case SK_ATTR_OBJECT_INDEX:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			ck_id = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(ck_id, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_ID;
			ck_attrs->pValue = ck_id;
			ck_attrs->ulValueLen = sk_attrs->valueLen;
			break;

		case SK_ATTR_MODULUS_BITS:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sizeof(CK_ULONG));
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			mod_bits = (CK_ULONG *)((CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE));
			*mod_bits = *(uint32_t *)(sk_attrs->value);

			ck_attrs->type = CKA_MODULUS_BITS;
			ck_attrs->pValue = (void *)mod_bits;
			ck_attrs->ulValueLen = sizeof(CK_ULONG);
			break;

		case SK_ATTR_MODULUS:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			temp = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(temp, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_MODULUS;
			ck_attrs->pValue = temp;
			ck_attrs->ulValueLen = sk_attrs->valueLen;

			break;

		case SK_ATTR_PUBLIC_EXPONENT:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			temp = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(temp, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_PUBLIC_EXPONENT;
			ck_attrs->pValue = temp;
			ck_attrs->ulValueLen = sk_attrs->valueLen;
			break;

		case SK_ATTR_PARAMS:
		{
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
				sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			temp = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(temp, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_EC_PARAMS;
			ck_attrs->pValue = temp;
			ck_attrs->ulValueLen = sk_attrs->valueLen;
			break;
		}
		case SK_ATTR_POINT:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
				sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			temp = (CK_BYTE *)ck_attrs + sizeof(CK_ATTRIBUTE);
			memcpy(temp, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_EC_POINT;
			ck_attrs->pValue = temp;
			ck_attrs->ulValueLen = sk_attrs->valueLen;
			break;

		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	*ck_attr = ck_attrs;
	return CKR_OK;
}

CK_RV find_matching_objects(CK_OBJECT_HANDLE_PTR object_handle,
	struct object_list *obj_list, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount, CK_ULONG *pobjCount)
{
	struct object_node *temp;
	uint32_t i = 0;
	CK_BBOOL ret;

	if (ulCount != 0) {
		STAILQ_FOREACH(temp, obj_list, entry) {
			ret = p11_template_compare(pTemplate, ulCount,
				&temp->object.template_list);
			if (ret == TRUE) {
				object_handle[i] = (CK_OBJECT_HANDLE)temp;
				i++;
				if (i > MAX_FIND_LIST_OBJECTS)
					break;
			}
		}
	} else {
		STAILQ_FOREACH(temp, obj_list, entry) {
			object_handle[i] = (CK_OBJECT_HANDLE)temp;
			i++;
			if (i > MAX_FIND_LIST_OBJECTS)
				break;
		}
	}

	*pobjCount = i;
	return CKR_OK;
}

struct object_list *get_object_list(CK_SLOT_ID slotID)
{
	struct slot_info *ginfo;

	if (slotID >= SLOT_COUNT)
		return NULL;

	ginfo = get_global_slot_info(slotID);

	return &ginfo->obj_list;
}

CK_RV initialize_object_list(CK_SLOT_ID slotID)
{
	struct object_list *obj_list;
	obj_list = get_object_list(slotID);
	if (!obj_list)
		return CKR_ARGUMENTS_BAD;

	STAILQ_INIT(obj_list);
	return CKR_OK;
}

CK_RV destroy_object_list(CK_SLOT_ID slotID)
{
	struct object_list *obj_list;
	struct template_list *tmpl_list;
	struct object_node *o;
	struct template_node *t;

	obj_list = get_object_list(slotID);
	if (!obj_list)
		return CKR_ARGUMENTS_BAD;

	if (!STAILQ_EMPTY(obj_list)) {
		while ((o = STAILQ_FIRST(obj_list)) != NULL) {
			OBJECT *obj = &o->object;
			tmpl_list = &obj->template_list;
			while ((t = STAILQ_FIRST(tmpl_list)) != NULL ) {
				if (t->attributes)
					free(t->attributes);
				STAILQ_REMOVE(tmpl_list, t, template_node, entry);
				free(t);
			}
#if 0
			if (STAILQ_EMPTY(tmpl_list))
				printf("Template list destroyed successfuly\n");
#endif

			STAILQ_REMOVE(obj_list, o, object_node, entry);
			free(o);
		}
	}
#if 0
	if (STAILQ_EMPTY(obj_list))
		printf("Object list destroyed successfuly\n");
#endif

	return CKR_OK;
}

CK_BBOOL is_object_handle_valid(CK_OBJECT_HANDLE hObject,
		CK_SLOT_ID slotID)
{
	struct object_list *obj_list;
	struct object_node *temp;

	obj_list = get_object_list(slotID);
	if (!obj_list)
		return FALSE;

	STAILQ_FOREACH(temp, obj_list, entry) {
		if ((CK_OBJECT_HANDLE)temp == hObject)
			return TRUE;
	}

	return FALSE;
}

CK_RV get_attr_value(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	CK_ATTRIBUTE *attr;
	CK_RV ret = CKR_OK;
	CK_ULONG i = 0;
	CK_BBOOL flag;
	struct template_list *obj_tmpl;
	struct object_node *obj_node;
	CK_BBOOL is_obj_handle_valid;
	session *sess = NULL;

	if (pTemplate == NULL) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (ulCount == 0) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if(!is_session_valid(hSession)) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sess = get_session(hSession);
	if (!sess) {
		ret = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	is_obj_handle_valid = is_object_handle_valid(hObject,
		sess->session_info.slotID);
	if (!is_obj_handle_valid) {
		ret = CKR_OBJECT_HANDLE_INVALID;
		goto end;
	}

	obj_node = (struct object_node *)hObject;

	obj_tmpl = &obj_node->object.template_list;

	for (i = 0; i < ulCount; i++) {
		flag = check_attr_exportability(obj_tmpl, pTemplate[i].type);
		if (flag == FALSE) {
			ret = CKR_ATTRIBUTE_SENSITIVE;
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
			continue;
		}

		flag = p11_template_check_attr(obj_tmpl, pTemplate[i].type, &attr);
		if (flag == FALSE) {
			ret = CKR_ATTRIBUTE_TYPE_INVALID;
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
			continue;
		}

		if (pTemplate[i].pValue == NULL) {
			pTemplate[i].ulValueLen = attr->ulValueLen;
		}
		else if (pTemplate[i].ulValueLen >= attr->ulValueLen) {
			memcpy( pTemplate[i].pValue, attr->pValue, attr->ulValueLen );
			pTemplate[i].ulValueLen = attr->ulValueLen;
		}
		else {
			ret = CKR_BUFFER_TOO_SMALL;
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
		}
	}

end:
	return ret;
}

#define OBJ_SK_ATTR_COUNT	2
#define RSA_PUB_SK_ATTR_COUNT	5
#define RSA_PRIV_SK_ATTR_COUNT	4

SK_ATTRIBUTE_TYPE rsa_pub_attr_type[RSA_PUB_SK_ATTR_COUNT] = {
	SK_ATTR_OBJECT_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_MODULUS,
	SK_ATTR_PUBLIC_EXPONENT,
	SK_ATTR_MODULUS_BITS
};

SK_ATTRIBUTE_TYPE rsa_priv_attr_type[RSA_PRIV_SK_ATTR_COUNT] = {
	SK_ATTR_OBJECT_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_MODULUS,
	SK_ATTR_PUBLIC_EXPONENT
};

#define ECC_PUB_SK_ATTR_COUNT	4
#define ECC_PRIV_SK_ATTR_COUNT	3

SK_ATTRIBUTE_TYPE ecc_pub_attr_type[ECC_PUB_SK_ATTR_COUNT] = {
	SK_ATTR_OBJECT_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_PARAMS,
	SK_ATTR_POINT
};

SK_ATTRIBUTE_TYPE ecc_priv_attr_type[ECC_PRIV_SK_ATTR_COUNT] = {
	SK_ATTR_OBJECT_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_PARAMS
};

CK_BBOOL object_is_destroyable(CK_OBJECT_HANDLE hObject)
{
	struct object_node *obj_node = NULL;
	CK_ATTRIBUTE_PTR destroy_attr = NULL;

	obj_node = (struct object_node *)hObject;

	if (p11_template_attribute_find(&obj_node->object.template_list,
			CKA_DESTROYABLE, &destroy_attr)) {
		if (*(CK_BBOOL *)(destroy_attr->pValue) == CK_TRUE)
			return CK_TRUE;
		else
			return CK_FALSE;
	} else
		return CK_FALSE;
}

CK_BBOOL object_is_private(CK_OBJECT_HANDLE hObject)
{
	struct object_node *obj_node = NULL;
	obj_node = (struct object_node *)hObject;

	return template_is_private_set(&obj_node->object.template_list);
}


static CK_RV object_add_template(OBJECT *obj,
		SK_ATTRIBUTE_TYPE *sk_attr_type, uint32_t attrCount)
{
	SK_ATTRIBUTE temp_sk_attr[attrCount], *sk_attr;
	SK_FUNCTION_LIST_PTR sk_funcs = NULL;
	CK_ATTRIBUTE_PTR ck_attr;
	SK_RET_CODE ret;
	uint32_t i = 0;
	CK_RV rc;

	sk_funcs = get_slot_function_list(obj->slotID);
	if (!sk_funcs)
		return CKR_ARGUMENTS_BAD;

	memset(temp_sk_attr, 0, sizeof(SK_ATTRIBUTE) * attrCount);
	for (i = 0; i < attrCount; i++)
		temp_sk_attr[i].type = sk_attr_type[i];

	ret = sk_funcs->SK_GetObjectAttribute(obj->sk_obj_handle,
			temp_sk_attr, attrCount);
	if (ret != SKR_OK) {
		print_error("SK_GetObjectAttribute failed %x\n", ret);
		return CKR_GENERAL_ERROR;
	}

	for (i = 0; i < attrCount; i++) {
		if ((int16_t)temp_sk_attr[i].valueLen == -1)
			continue;

		sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
			temp_sk_attr[i].valueLen);
		if (!sk_attr)
			return CKR_HOST_MEMORY;

		sk_attr->type = temp_sk_attr[i].type;
		sk_attr->value = (uint8_t *)sk_attr + sizeof(SK_ATTRIBUTE);
		sk_attr->valueLen = temp_sk_attr[i].valueLen;

		ret = sk_funcs->SK_GetObjectAttribute(obj->sk_obj_handle,
			sk_attr, 1);
		if (ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed with error code = %x\n", ret);
			free(sk_attr);
			return CKR_GENERAL_ERROR;
		}

		rc = map_sk_to_pkcs_attr(sk_attr, &ck_attr);
		if (rc != CKR_OK) {
			print_error("map_sk_to_pkcs_attr failed\n");
			free(sk_attr);
			return CKR_GENERAL_ERROR;
		}

		rc = p11_template_add_attr(&obj->template_list,
					ck_attr, 1);
		if (rc != CKR_OK) {
			print_error("p11_template_add_attr failed\n");
			return rc;
		}

		free(sk_attr);
		free(ck_attr);
	}

	return CKR_OK;
}

static CK_RV object_add_to_list(CK_SLOT_ID slotID,
			struct object_node *object)
{
	struct object_list *obj_list = NULL;
	CK_RV rc = CKR_OK;

	obj_list = get_object_list(slotID);
	if (!obj_list) {
		print_error("Object list not found for given SLOT\n");
		rc = CKR_FUNCTION_FAILED;
		goto end;
	}

	STAILQ_INSERT_HEAD(obj_list, object, entry);

end:
	return rc;
}

static CK_RV create_rsa_pub_key_object(SK_OBJECT_HANDLE hObject,
		struct object_node **rsa_pub_key, CK_SLOT_ID slotID)
{
	struct object_node *pub_key;
	CK_RV rc;

	pub_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!pub_key) {
		print_error("pub_key object node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(pub_key, 0, sizeof(struct object_node));
	STAILQ_INIT(&pub_key->object.template_list);

	pub_key->object.sk_obj_handle = hObject;
	pub_key->object.slotID = slotID;

	pub_key->object.obj_class = CKO_PUBLIC_KEY;
	pub_key->object.obj_subclass = CKK_RSA;

	rc = object_add_template(&pub_key->object, rsa_pub_attr_type,
			RSA_PUB_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		print_error("object_add_template failed\n");
		free(pub_key);
		return rc;
	}

	*rsa_pub_key = pub_key;
	return CKR_OK;
}

static CK_RV create_rsa_priv_key_object(SK_OBJECT_HANDLE hObject,
		struct object_node **rsa_priv_key, CK_SLOT_ID slotID)
{
	struct object_node *priv_key;
	CK_RV rc;

	priv_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!priv_key) {
		print_error("priv_key object node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(priv_key, 0, sizeof(struct object_node));
	STAILQ_INIT(&priv_key->object.template_list);

	priv_key->object.sk_obj_handle = hObject;
	priv_key->object.slotID = slotID;
	priv_key->object.obj_class = CKO_PRIVATE_KEY;
	priv_key->object.obj_subclass = CKK_RSA;

	rc = object_add_template(&priv_key->object, rsa_priv_attr_type,
			RSA_PRIV_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		print_error("object_add_template failed\n");
		free(priv_key);
		return rc;
	}

	*rsa_priv_key = priv_key;
	return CKR_OK;
}

static CK_RV create_ecc_pub_key_object(SK_OBJECT_HANDLE hObject,
		struct object_node **ecc_pub_key, CK_SLOT_ID slotID)
{
	struct object_node *pub_key;
	CK_RV rc;

	pub_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!pub_key) {
		print_error("pub_key object node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(pub_key, 0, sizeof(struct object_node));
	STAILQ_INIT(&pub_key->object.template_list);

	pub_key->object.sk_obj_handle = hObject;
	pub_key->object.slotID = slotID;
	pub_key->object.obj_class = CKO_PUBLIC_KEY;
	pub_key->object.obj_subclass = CKK_EC;

	rc = object_add_template(&pub_key->object, ecc_pub_attr_type,
		ECC_PUB_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		print_error("object_add_template failed\n");
		free(pub_key);
		return rc;
	}

	*ecc_pub_key = pub_key;
	return CKR_OK;
}

static CK_RV create_ecc_priv_key_object(SK_OBJECT_HANDLE hObject,
				struct object_node **ecc_priv_key, CK_SLOT_ID slotID)
{
	struct object_node *priv_key;
	CK_RV rc;

	priv_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!priv_key) {
		print_error("priv_key object node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(priv_key, 0, sizeof(struct object_node));
	STAILQ_INIT(&priv_key->object.template_list);

	priv_key->object.sk_obj_handle = hObject;
	priv_key->object.slotID = slotID;
	priv_key->object.obj_class = CKO_PRIVATE_KEY;
	priv_key->object.obj_subclass = CKK_EC;

	rc = object_add_template(&priv_key->object, ecc_priv_attr_type,
		ECC_PRIV_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		print_error("object_add_template failed\n");
		free(priv_key);
		return rc;
	}

	*ecc_priv_key = priv_key;
	return CKR_OK;
}

static CK_RV create_key_object(SK_OBJECT_HANDLE hObject,
			CK_ULONG class,
			CK_ULONG subclass,
			struct template_list *template,
			struct object_node **object_node,
			CK_SLOT_ID slotID)
{
	CK_RV rc = CKR_OK;
	struct object_node *temp = NULL;

	switch (class) {
		case CKO_PUBLIC_KEY:
			switch (subclass) {
				case CKK_RSA:
					rc = create_rsa_pub_key_object(hObject, object_node, slotID);
					if (rc != CKR_OK) {
						print_error("create_rsa_pub_key_object failed\n");
						return rc;
					}
					break;
				case CKK_EC:
					rc = create_ecc_pub_key_object(hObject, object_node, slotID);
					if (rc != CKR_OK) {
						print_error("create_ecc_pub_key_object failed\n");
						return rc;
					}
					break;
				default:
					print_error("Only RSA/EC keys supported\n");
					return CKR_FUNCTION_FAILED;
			}
			break;
		case CKO_PRIVATE_KEY:
			switch (subclass) {
				case CKK_RSA:
					rc = create_rsa_priv_key_object(hObject, object_node, slotID);
					if (rc != CKR_OK) {
						print_error("create_rsa_priv_key_object failed\n");
						return rc;
					}
					break;
				case CKK_EC:
					rc = create_ecc_priv_key_object(hObject, object_node, slotID);
					if (rc != CKR_OK) {
						print_error("create_ecc_priv_key_object failed\n");
						return rc;
					}
					break;
				default:
					print_error("Only RSA/EC keys supported\n");
					return CKR_FUNCTION_FAILED;
			}
			break;
		default:
			print_error("Only Public/Private Keys supported\n");
			return CKR_FUNCTION_FAILED;
	}

	temp = *object_node;

	rc = template_merge(&temp->object.template_list, &template);
	if (rc != CKR_OK) {
		print_error("template_merge failed\n");
		return rc;
	}

	rc = p11_template_add_default_attr(&temp->object, OP_GENERATE);
	if (rc != CKR_OK) {
		print_error("p11_template_add_default_attr failed\n");
		return rc;
	}

	rc = object_add_to_list(slotID, *object_node);
	if (rc != CKR_OK) {
		print_error("p11_template_add_default_attr failed\n");
		return rc;
	}

	return CKR_OK;
}

CK_RV destroy_object(CK_OBJECT_HANDLE hObject,
			CK_SLOT_ID slotID)
{
	struct object_node *o = NULL;
	struct object_list *obj_list = NULL;
	struct template_list *tmpl_list = NULL;
	OBJECT *obj = NULL;
	struct template_node *t = NULL;
	SK_FUNCTION_LIST_PTR sk_funcs = NULL;
	SK_RET_CODE ret = SKR_OK;

	o = (struct object_node *)hObject;
	if (o) {
		obj_list = get_object_list(slotID);
		if (!obj_list)
			return CKR_ARGUMENTS_BAD;

		obj = &o->object;
		tmpl_list = &obj->template_list;

		while ((t = STAILQ_FIRST(tmpl_list)) != NULL ) {
			if (t->attributes)
				free(t->attributes);

			STAILQ_REMOVE(tmpl_list, t, template_node, entry);
			free(t);
		}

		sk_funcs = get_slot_function_list(slotID);
		if (!sk_funcs)
			return CKR_ARGUMENTS_BAD;

		ret = sk_funcs->SK_EraseObject(obj->sk_obj_handle);
		if (ret != SKR_OK) {
			if (ret != SKR_ERR_ITEM_NOT_FOUND) {
				print_error("SK_EraseObject failed\n");
				return CKR_FUNCTION_FAILED;
			}
		}

		STAILQ_REMOVE(obj_list, o, object_node, entry);
		free(o);
	}

	return CKR_OK;
}

CK_RV objects_generate_key_pair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rc = CKR_OK;
	session *sess = NULL;
	struct template_list *publ_tmpl = NULL, *priv_tmpl = NULL;
	CK_ULONG subclass;
	CK_ULONG op_type = OP_GENERATE;

	SK_RET_CODE sk_ret = SKR_OK;
	SK_MECHANISM_INFO mechanismType = {0};
	SK_ATTRIBUTE *sk_attrs = NULL;
	SK_OBJECT_HANDLE hObject = 1234;
	uint32_t attrCount = 0;
	struct object_node *public_key = NULL, *priv_key = NULL;
	SK_FUNCTION_LIST_PTR sk_funcs = NULL;

	sess = get_session(hSession);
	if (!sess) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto end;
	}

	sk_funcs = get_slot_function_list(sess->session_info.slotID);
	if (!sk_funcs) {
		print_error("get_slot_function_list failed\n");
		return CKR_ARGUMENTS_BAD;
	}

	rc = mechanism_template_check_consistency(pMechanism,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			&subclass);
	if (rc) {
		print_error("mechanism_template_check_consistency failed\n");
		goto end;
	}

	rc = template_create_template_list(pPublicKeyTemplate,
				ulPublicKeyAttributeCount,
				&publ_tmpl);
	if (rc) {
		print_error("template_create_template_list failed\n");
		goto end;
	}

	rc = template_create_template_list(pPrivateKeyTemplate,
				ulPrivateKeyAttributeCount,
				&priv_tmpl);
	if (rc) {
		print_error("template_create_template_list failed\n");
		goto end;
	}

	rc = session_template_check_consistency(hSession, publ_tmpl);
	if (rc) {
		print_error("session_template_check_consistency failed\n");
		goto end;
	}

	rc = session_template_check_consistency(hSession, priv_tmpl);
	if (rc) {
		print_error("session_template_check_consistency failed\n");
		goto end;
	}

	rc = template_validate_attributes(publ_tmpl, CKO_PUBLIC_KEY,
				subclass, op_type);
	if (rc) {
		print_error("template_validate_attributes public key failed\n");
		goto end;
	}

	rc = template_validate_attributes(priv_tmpl, CKO_PRIVATE_KEY,
				subclass, op_type);
	if (rc) {
		print_error("template_validate_attributes private key failed\n");
		goto end;
	}

	rc = template_check_required_attributes(publ_tmpl,
				CKO_PUBLIC_KEY, subclass, op_type);
	if (rc) {
		print_error("template_check_required_attributes public key failed\n");
		goto end;
	}

	rc = template_check_required_attributes(priv_tmpl,
				CKO_PRIVATE_KEY, subclass, op_type);
	if (rc) {
		print_error("template_check_required_attributes private key failed\n");
		goto end;
	}

	rc = map_pkcs_to_sk_attr(pPublicKeyTemplate,
				ulPublicKeyAttributeCount,
				&sk_attrs, &attrCount);
	if (rc != CKR_OK) {
		print_error("map_pkcs_to_sk_attr failed\n");
		goto end;
	}

	switch (subclass) {
		case CKK_RSA:
			mechanismType.mechanism =
				SKM_RSA_PKCS_KEY_PAIR_GEN;
			break;
		case CKK_EC:
			mechanismType.mechanism =
				SKM_RSA_PKCS_KEY_PAIR_GEN;
			break;
		default:
			print_error("Only RSA/EC Keys supported\n");
	}

	sk_ret = sk_funcs->SK_GenerateKeyPair(&mechanismType, sk_attrs,
				attrCount, &hObject);
	if (sk_ret != SKR_OK) {
		print_error("SK_GenerateKeyPair failed wit err code = 0x%x\n", sk_ret);
		rc = CKR_GENERAL_ERROR;
		goto end;
	}

	rc = create_key_object(hObject, CKO_PUBLIC_KEY, subclass, publ_tmpl,
			&public_key, sess->session_info.slotID);
	if (rc != CKR_OK) {
		print_error("SK_GenerateKeyPair failed wit err code = 0x%x\n", sk_ret);
		goto end;
	}

	rc = create_key_object(hObject, CKO_PRIVATE_KEY, subclass, priv_tmpl,
			&priv_key, sess->session_info.slotID);
	if (rc != CKR_OK) {
		print_error("SK_GenerateKeyPair failed wit err code = 0x%x\n", sk_ret);
		goto end;
	}

	*phPublicKey = (CK_OBJECT_HANDLE)public_key;
	*phPrivateKey = (CK_OBJECT_HANDLE)priv_key;

end:
	if (rc != CKR_OK) {
		if (publ_tmpl)
			template_destroy_template_list(publ_tmpl);
		if (priv_tmpl)
			template_destroy_template_list(priv_tmpl);
	}

	return rc;
}

CK_RV get_all_token_objects(struct object_list *obj_list,
		CK_SLOT_ID slotID)
{
	uint32_t obj_count, j = 0;
	SK_ATTRIBUTE temp_sk_attr[OBJ_SK_ATTR_COUNT];
	SK_FUNCTION_LIST_PTR sk_funcs = NULL;
	SK_RET_CODE ret;
	SK_OBJECT_HANDLE objs[MAX_FIND_LIST_OBJECTS];
	SK_KEY_TYPE key_type;
	SK_OBJECT_TYPE obj_type;

	CK_RV rc;
	CK_ULONG op_type = OP_CREATE;

	sk_funcs = get_slot_function_list(slotID);
	if (!sk_funcs)
		return CKR_ARGUMENTS_BAD;

	/* For now only 50 objects are read from token and maintained
	  * in PKCS library */
	ret = sk_funcs->SK_EnumerateObjects(NULL, 0, objs,
			MAX_FIND_LIST_OBJECTS, &obj_count);
	if (ret != SKR_OK) {
		print_error("SK_EnumerateObjects failed with ret code 0x%x\n", ret);
		return CKR_GENERAL_ERROR;
	}

	for (j = 0; j < obj_count; j++) {
		memset(temp_sk_attr, 0, sizeof(SK_ATTRIBUTE) *
			OBJ_SK_ATTR_COUNT);

		temp_sk_attr[0].type = SK_ATTR_OBJECT_TYPE;
		temp_sk_attr[0].value = &obj_type;
		temp_sk_attr[0].valueLen = sizeof(SK_OBJECT_TYPE);

		temp_sk_attr[1].type = SK_ATTR_KEY_TYPE;
		temp_sk_attr[1].value = &key_type;
		temp_sk_attr[1].valueLen = sizeof(SK_KEY_TYPE);

		ret = sk_funcs->SK_GetObjectAttribute(objs[j],
			temp_sk_attr, 1);
		if (ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed\n");
			return CKR_GENERAL_ERROR;
		}

		// if this is a key, get its key type
		if (obj_type == SK_KEY_PAIR || obj_type == SK_PUBLIC_KEY) {
			ret = sk_funcs->SK_GetObjectAttribute(objs[j],
				&temp_sk_attr[1], 1);
			if (ret != SKR_OK) {
				print_error("SK_GetObjectAttribute failed\n");
				return CKR_GENERAL_ERROR;
			}
		}

		switch (obj_type) {
			case SK_KEY_PAIR:
				switch (key_type) {
					case SKK_RSA:
					{
						struct object_node *rsa_pub_key, *rsa_priv_key;

						rc = create_rsa_pub_key_object(objs[j], &rsa_pub_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_rsa_pub_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&rsa_pub_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, rsa_pub_key, entry);

						rc = create_rsa_priv_key_object(objs[j], &rsa_priv_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_rsa_priv_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&rsa_priv_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}
						STAILQ_INSERT_HEAD(obj_list, rsa_priv_key, entry);
					}
					break;
					case SKK_EC:
					{
						struct object_node *ecc_pub_key, *ecc_priv_key;

						rc = create_ecc_pub_key_object(objs[j], &ecc_pub_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_ecc_pub_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&ecc_pub_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, ecc_pub_key, entry);

						rc = create_ecc_priv_key_object(objs[j], &ecc_priv_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_ecc_priv_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&ecc_priv_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, ecc_priv_key, entry);
					}
					break;
					default:
						continue;
				}
			break;
			case SK_PUBLIC_KEY:
				switch (key_type) {
					case SKK_RSA:
					{
						struct object_node *pub_key;

						rc = create_rsa_pub_key_object(objs[j], &pub_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_rsa_pub_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&pub_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, pub_key, entry);
					}
					break;
					case SKK_EC:
					{
						struct object_node *pub_key;

						rc = create_ecc_pub_key_object(objs[j], &pub_key, slotID);
						if (rc != CKR_OK) {
							print_error("create_ecc_pub_key_object failed\n");
							return rc;
						}

						rc = p11_template_add_default_attr(&pub_key->object, op_type);
						if (rc != CKR_OK) {
							print_error("p11_template_add_default_attr failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, pub_key, entry);
					}
					break;
					default:
						continue;
				}
			break;
			default:
				continue;
		}
	}

	return CKR_OK;
}
