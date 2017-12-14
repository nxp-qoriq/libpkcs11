#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <cryptoki.h>
#include <objects.h>
#include <sessions.h>

#include <securekey_api.h>
#include <securekey_api_types.h>

extern SK_FUNCTION_LIST  *sk_funcs;

static CK_BBOOL is_attribute_defined(CK_ATTRIBUTE_TYPE type)
{
	if (type >= CKA_VENDOR_DEFINED)
		return TRUE;

	switch (type)
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
		case  CKA_SUBJECT:
		case  CKA_ID:
		case  CKA_SENSITIVE:
		case  CKA_ENCRYPT:
		case  CKA_DECRYPT:
		case  CKA_WRAP:
		case  CKA_UNWRAP:
		case  CKA_SIGN:
		case  CKA_SIGN_RECOVER:
		case  CKA_VERIFY:
		case  CKA_VERIFY_RECOVER:
		case  CKA_DERIVE:
		case  CKA_START_DATE:
		case  CKA_END_DATE:
		case  CKA_MODULUS:
		case  CKA_MODULUS_BITS:
		case  CKA_PUBLIC_EXPONENT:
		case  CKA_PRIVATE_EXPONENT:
		case  CKA_PRIME_1:
		case  CKA_PRIME_2:
		case  CKA_EXPONENT_1:
		case  CKA_EXPONENT_2:
		case  CKA_COEFFICIENT:
		case  CKA_PRIME:
		case  CKA_SUBPRIME:
		case  CKA_BASE:
		case  CKA_VALUE_BITS:
		case  CKA_VALUE_LEN:
		case  CKA_EXTRACTABLE:
		case  CKA_LOCAL:
		case  CKA_NEVER_EXTRACTABLE:
		case  CKA_ALWAYS_SENSITIVE:
		case  CKA_MODIFIABLE:
		case  CKA_ECDSA_PARAMS:
		case  CKA_EC_POINT:
		case  CKA_HW_FEATURE_TYPE:
		case  CKA_HAS_RESET:
		case  CKA_RESET_ON_INIT:
		case  CKA_KEY_GEN_MECHANISM:
		case  CKA_PRIME_BITS:
		case  CKA_SUBPRIME_BITS:
		case  CKA_OBJECT_ID:
		case  CKA_AC_ISSUER:
		case  CKA_OWNER:
		case  CKA_ATTR_TYPES:
		case  CKA_TRUSTED:
			return TRUE;
		default:
			return FALSE;
	}
}

static CK_RV template_update_attribute(struct template_list *tmpl_list,
		struct template_node *tmpl_node)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_ATTRIBUTE *new_attr = tmpl_node->attributes;
	struct template_node *temp = NULL, *s = NULL;

	if (!tmpl_list || !tmpl_node)
		return CKR_ARGUMENTS_BAD;

	/* if the attribute already exists in the list, remove it.
	 * this algorithm will limit an attribute to appearing at most
	 * once in the list */
	STAILQ_FOREACH(temp, tmpl_list, entry) {
		attr = (CK_ATTRIBUTE *)temp->attributes;
		if (new_attr->type == attr->type) {
			s = temp;
			STAILQ_REMOVE(tmpl_list, s, template_node, entry);
			free(attr);
			free(s);
			break;
		}
	}

	STAILQ_INSERT_HEAD(tmpl_list, tmpl_node, entry);

	return CKR_OK;
}


static CK_RV
key_object_set_default_attributes(struct template_list *tmpl_list)
{
	struct template_node *sdate;
	struct template_node *edate;
	struct template_node *derive;
	struct template_node *local;
 
	CK_ATTRIBUTE *sdate_attr  = NULL;
	CK_ATTRIBUTE *edate_attr  = NULL;
	CK_ATTRIBUTE *derive_attr = NULL;
	CK_ATTRIBUTE *local_attr  = NULL;

	sdate_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE));
	edate_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE));
	derive_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	local_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

	sdate = (struct template_node *)malloc( sizeof(struct template_node));
	edate = (struct template_node *)malloc( sizeof(struct template_node));
	derive = (struct template_node *)malloc( sizeof(struct template_node));
	local = (struct template_node *)malloc( sizeof(struct template_node));

	if (!sdate_attr || !edate_attr || !derive_attr || !local_attr ||
		!sdate || !edate || !derive || !local) {
		if (sdate_attr)
			free(sdate_attr);
		if (edate_attr)
			free(edate_attr);
		if (derive_attr)
			free(derive_attr);
		if (local_attr)
			free(local_attr);
		if (sdate)
			free(sdate);
		if (edate)
			free(edate);
		if (derive)
			free(derive);
		if (local)
			free(local);
		return CKR_HOST_MEMORY;
	}

	sdate_attr->type        = CKA_START_DATE;
	sdate_attr->ulValueLen  = 0;
	sdate_attr->pValue      = NULL;

	edate_attr->type        = CKA_END_DATE;
	edate_attr->ulValueLen  = 0;
	edate_attr->pValue      = NULL;

	derive_attr->type       = CKA_DERIVE;
	derive_attr->ulValueLen = sizeof(CK_BBOOL);
	derive_attr->pValue     = (CK_BYTE *)derive_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)derive_attr->pValue = FALSE;

	local_attr->type        = CKA_LOCAL;
	local_attr->ulValueLen  = sizeof(CK_BBOOL);
	local_attr->pValue      = (CK_BYTE *)local_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)local_attr->pValue = FALSE;

	sdate->attributes = sdate_attr;
	edate->attributes = edate_attr;
	derive->attributes = derive_attr;
	local->attributes = local_attr;

	template_update_attribute(tmpl_list, sdate);
	template_update_attribute(tmpl_list, edate);
	template_update_attribute(tmpl_list, derive);
	template_update_attribute(tmpl_list, local);

	return CKR_OK;
}

static CK_RV
publ_key_add_default_attributes(struct template_list *tmpl_list)
{
	struct template_node *class;
	struct template_node *subject;
	struct template_node *encrypt;
	struct template_node *verify;
	struct template_node *verify_recover;
	struct template_node *wrap;
	struct template_node *trusted;
	struct template_node *wrap_template;

	CK_ATTRIBUTE    *class_attr = NULL;
	CK_ATTRIBUTE    *subject_attr = NULL;
	CK_ATTRIBUTE    *encrypt_attr = NULL;
	CK_ATTRIBUTE    *verify_attr = NULL;
	CK_ATTRIBUTE    *verify_recover_attr = NULL;
	CK_ATTRIBUTE    *wrap_attr = NULL;
	CK_ATTRIBUTE    *trusted_attr = NULL;
	CK_ATTRIBUTE    *wrap_template_attr = NULL;

	CK_RV            rc;

	rc = key_object_set_default_attributes(tmpl_list);
	if (rc != CKR_OK){
		printf("key_object_set_default_attributes failed\n");
		return rc;
	}

	/* add the default CKO_PUBLIC_KEY attributes */
	class_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_OBJECT_CLASS));
	subject_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	encrypt_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	verify_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	verify_recover_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	wrap_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
		sizeof(CK_BBOOL));
	trusted_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	wrap_template_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));

	class = (struct template_node *)malloc(sizeof(struct template_node));
	subject = (struct template_node *)malloc(sizeof(struct template_node));
	encrypt = (struct template_node *)malloc(sizeof(struct template_node));
	verify = (struct template_node *)malloc(sizeof(struct template_node));
	verify_recover = (struct template_node *)malloc(sizeof(struct template_node));
	wrap = (struct template_node *)malloc(sizeof(struct template_node));
	trusted = (struct template_node *)malloc(sizeof(struct template_node));
	wrap_template = (struct template_node *)malloc(sizeof(struct template_node));

	if (!class_attr || !subject_attr || !encrypt_attr ||
		!verify_attr  || !verify_recover_attr || !wrap_attr ||
		!subject || !class || !encrypt || !verify || !verify_recover ||
		!wrap || !trusted || !wrap_template || !trusted_attr ||
		!wrap_template_attr)
	{
		if (class_attr)
			free(class_attr);
		if (subject_attr)
			free(subject_attr);
		if (encrypt_attr)
			free(encrypt_attr);
		if (verify_attr)
			free(verify_attr);
		if (verify_recover_attr)
			free(verify_recover_attr);
		if (wrap_attr)
			free(wrap_attr);
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
		if (trusted_attr)
			free(trusted_attr);
		if (wrap_template_attr)
			free(wrap_template_attr);

		return CKR_HOST_MEMORY;
	}

	class_attr->type = CKA_CLASS;
	class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
	class_attr->pValue = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
	*(CK_OBJECT_CLASS *)class_attr->pValue = CKO_PUBLIC_KEY;

	subject_attr->type         = CKA_SUBJECT;
	subject_attr->ulValueLen   = 0;  // empty string
	subject_attr->pValue       = NULL;

	encrypt_attr->type          = CKA_ENCRYPT;
	encrypt_attr->ulValueLen    = sizeof(CK_BBOOL);
	encrypt_attr->pValue        = (CK_BYTE *)encrypt_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)encrypt_attr->pValue = TRUE;

	verify_attr->type          = CKA_VERIFY;
	verify_attr->ulValueLen    = sizeof(CK_BBOOL);
	verify_attr->pValue        = (CK_BYTE *)verify_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)verify_attr->pValue = FALSE;

	verify_recover_attr->type          = CKA_VERIFY_RECOVER;
	verify_recover_attr->ulValueLen    = sizeof(CK_BBOOL);
	verify_recover_attr->pValue        = (CK_BYTE *)verify_recover_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)verify_recover_attr->pValue = FALSE;

	wrap_attr->type          = CKA_WRAP;
	wrap_attr->ulValueLen    = sizeof(CK_BBOOL);
	wrap_attr->pValue        = (CK_BYTE *)wrap_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)wrap_attr->pValue = FALSE;

	trusted_attr->type          = CKA_TRUSTED;
	trusted_attr->ulValueLen    = sizeof(CK_BBOOL);
	trusted_attr->pValue        = (CK_BYTE *)verify_recover_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)trusted_attr->pValue = FALSE;

	wrap_template_attr->type          = CKA_WRAP_TEMPLATE;
	wrap_template_attr->ulValueLen    = 0;
	wrap_template_attr->pValue        = NULL;

	class->attributes = class_attr;
	subject->attributes = subject_attr;
	encrypt->attributes = encrypt_attr;
	verify->attributes = verify_attr;
	verify_recover->attributes = verify_recover_attr;
	wrap->attributes = wrap_attr;
	trusted->attributes = trusted_attr;
	wrap_template->attributes = wrap_template_attr;

	template_update_attribute(tmpl_list, class);
	template_update_attribute(tmpl_list, subject);
	template_update_attribute(tmpl_list, encrypt);
	template_update_attribute(tmpl_list, verify);
	template_update_attribute(tmpl_list, verify_recover);
	template_update_attribute(tmpl_list, wrap);
	template_update_attribute(tmpl_list, trusted);
	template_update_attribute(tmpl_list, wrap_template);

	return CKR_OK;
}


static CK_RV
rsa_publ_add_default_attributes(struct template_list *tmpl_list)
{
	CK_RV rc;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = publ_key_add_default_attributes(tmpl_list);
	if (rc != CKR_OK) {
		printf("publ_key_set_default_attributes failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
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
	keygen_mech_attr->ulValueLen = 0;
	keygen_mech_attr->pValue = NULL;

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = 0;
	allowed_mech_attr->pValue = NULL;

	key_type->attributes = key_type_attr;
	keygen_mech->attributes = keygen_mech_attr;
	allowed_mech->attributes = allowed_mech_attr;

	template_update_attribute(tmpl_list, key_type);
	template_update_attribute(tmpl_list, keygen_mech);
	template_update_attribute(tmpl_list, allowed_mech);

	return CKR_OK;
}


/* template_set_default_common_attributes()
 *
 * Set the default attributes common to all objects:
 *
 *	CKA_TOKEN:	TRUE
 *	CKA_PRIVATE:	FALSE -- Cryptoki leaves this up to the token to decide
 *	CKA_MODIFIABLE:	FALSE
 */
static CK_RV
template_add_default_common_attributes(struct template_list *tmpl_list)
{
	struct template_node *token_node;
	struct template_node *priv_node;
	struct template_node *mod_node;

	CK_ATTRIBUTE *token_attr;
	CK_ATTRIBUTE *priv_attr;
	CK_ATTRIBUTE *mod_attr;

	token_node = (struct template_node *)malloc(sizeof(struct template_node));
	priv_node = (struct template_node *)malloc(sizeof(struct template_node));
	mod_node = (struct template_node *)malloc(sizeof(struct template_node));

	/* add the default common attributes */
	token_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));
	priv_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));
	mod_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
			+ sizeof(CK_BBOOL));

	if (!token_attr || !priv_attr || !mod_attr ||!token_node ||
		!priv_node || !mod_node) {
		if (token_attr) free(token_attr);
		if (priv_attr) free(priv_attr);
		if (mod_attr) free(mod_attr);
		if (token_node) free(token_node);
		if (priv_node) free(priv_node);
		if (mod_node) free(mod_node);

		return CKR_HOST_MEMORY;
	}

	token_attr->type = CKA_TOKEN;
	token_attr->ulValueLen = sizeof(CK_BBOOL);
	token_attr->pValue = (CK_BYTE *)token_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)token_attr->pValue = TRUE;

	priv_attr->type = CKA_PRIVATE;
	priv_attr->ulValueLen = sizeof(CK_BBOOL);
	priv_attr->pValue = (CK_BYTE *)priv_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)priv_attr->pValue = FALSE;

	mod_attr->type = CKA_MODIFIABLE;
	mod_attr->ulValueLen = sizeof(CK_BBOOL);
	mod_attr->pValue = (CK_BYTE *)mod_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)mod_attr->pValue = FALSE;

	token_node->attributes = token_attr;
	priv_node->attributes = priv_attr;
	mod_node->attributes = mod_attr;

	template_update_attribute(tmpl_list, token_node);
	template_update_attribute(tmpl_list, priv_node);
	template_update_attribute(tmpl_list, mod_node);

	return CKR_OK;
}

static CK_RV
priv_key_add_default_attributes(struct template_list *tmpl_list)
{
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

	CK_ATTRIBUTE *class_attr = NULL;
	CK_ATTRIBUTE *subject_attr = NULL;
	CK_ATTRIBUTE *sensitive_attr = NULL;
	CK_ATTRIBUTE *decrypt_attr = NULL;
	CK_ATTRIBUTE *sign_attr = NULL;
	CK_ATTRIBUTE *sign_recover_attr = NULL;
	CK_ATTRIBUTE *unwrap_attr = NULL;
	CK_ATTRIBUTE *extractable_attr = NULL;
	CK_ATTRIBUTE *never_extr_attr = NULL;
	CK_ATTRIBUTE *always_sens_attr = NULL;
	CK_ATTRIBUTE *wrap_with_trusted_attr = NULL;
	CK_ATTRIBUTE *unwrap_templ_attr = NULL;
	CK_ATTRIBUTE *always_auth_attr = NULL;
	CK_RV	rc;


	rc = key_object_set_default_attributes(tmpl_list);
	if (rc != CKR_OK){
		printf("key_object_set_default_attributes failed\n");
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

	class_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS)) ;
	subject_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	sensitive_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	decrypt_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	sign_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	sign_recover_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	unwrap_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	extractable_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	never_extr_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	always_sens_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	wrap_with_trusted_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
	unwrap_templ_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
	always_auth_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

	if (!class_attr || !subject_attr || !sensitive_attr || !decrypt_attr ||
			!sign_attr  || !sign_recover_attr ||
			!unwrap_attr    || !extractable_attr ||
			!never_extr_attr || !always_sens_attr ||
			!class || !subject || !decrypt || !sensitive ||
			!sign || !sign_recover || !unwrap ||
			!extractable || !never_extr || !always_sens ||
			!wrap_with_trusted || !unwrap_templ ||
			!always_auth|| !wrap_with_trusted_attr ||
			!unwrap_templ_attr || !always_auth_attr)
	{
		if (class_attr)
			free(class_attr);
		if (subject_attr)
			free(subject_attr);
		if (sensitive_attr)
			free(sensitive_attr);
		if (decrypt_attr)
			free(decrypt_attr);
		if (sign_attr)
			free(sign_attr);
		if (sign_recover_attr)
			free(sign_recover_attr);
		if (unwrap_attr)
			free(unwrap_attr);
		if (extractable_attr)
			free(extractable_attr);
		if (always_sens_attr)
			free(always_sens_attr);
		if (never_extr_attr)
			free(never_extr_attr);
		if (class)
			free(class);
		if (subject)
			free(subject);
		if (sensitive_attr)
			free(sensitive);
		if (decrypt_attr)
			free(decrypt);
		if (sign_attr)
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
		if (wrap_with_trusted_attr)
			free(wrap_with_trusted_attr);
		if (unwrap_templ_attr)
			free(unwrap_templ_attr);
		if (always_auth_attr)
			free(always_auth_attr);

		return CKR_HOST_MEMORY;
	}

	class_attr->type = CKA_CLASS;
	class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
	class_attr->pValue = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
	*(CK_OBJECT_CLASS *)class_attr->pValue = CKO_PRIVATE_KEY;

	subject_attr->type       = CKA_SUBJECT;
	subject_attr->ulValueLen = 0;  // empty string
	subject_attr->pValue     = NULL;

	sensitive_attr->type       = CKA_SENSITIVE;
	sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
	sensitive_attr->pValue     = (CK_BYTE *)sensitive_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)sensitive_attr->pValue = TRUE;

	decrypt_attr->type       = CKA_DECRYPT;
	decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
	decrypt_attr->pValue     = (CK_BYTE *)decrypt_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)decrypt_attr->pValue = FALSE;

	sign_attr->type       = CKA_SIGN;
	sign_attr->ulValueLen = sizeof(CK_BBOOL);
	sign_attr->pValue     = (CK_BYTE *)sign_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)sign_attr->pValue = TRUE;

	sign_recover_attr->type       = CKA_SIGN_RECOVER;
	sign_recover_attr->ulValueLen = sizeof(CK_BBOOL);
	sign_recover_attr->pValue     = (CK_BYTE *)sign_recover_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)sign_recover_attr->pValue = FALSE;

	unwrap_attr->type       = CKA_UNWRAP;
	unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
	unwrap_attr->pValue     = (CK_BYTE *)unwrap_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)unwrap_attr->pValue = FALSE;

	extractable_attr->type       = CKA_EXTRACTABLE;
	extractable_attr->ulValueLen = sizeof(CK_BBOOL);
	extractable_attr->pValue     = (CK_BYTE *)extractable_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)extractable_attr->pValue = FALSE;

	never_extr_attr->type       = CKA_NEVER_EXTRACTABLE;
	never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
	never_extr_attr->pValue     = (CK_BYTE *)never_extr_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)never_extr_attr->pValue = TRUE;

	always_sens_attr->type       = CKA_ALWAYS_SENSITIVE;
	always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
	always_sens_attr->pValue     = (CK_BYTE *)always_sens_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)always_sens_attr->pValue = TRUE;

	wrap_with_trusted_attr->type       = CKA_WRAP_WITH_TRUSTED;
	wrap_with_trusted_attr->ulValueLen = sizeof(CK_BBOOL);
	wrap_with_trusted_attr->pValue     = (CK_BYTE *)extractable_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)extractable_attr->pValue = FALSE;

	unwrap_templ_attr->type       = CKA_UNWRAP_TEMPLATE;
	unwrap_templ_attr->ulValueLen = 0;
	unwrap_templ_attr->pValue     = NULL;

	always_auth_attr->type       = CKA_ALWAYS_AUTHENTICATE;
	always_auth_attr->ulValueLen = sizeof(CK_BBOOL);
	always_auth_attr->pValue     = (CK_BYTE *)always_sens_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)always_sens_attr->pValue = FALSE;

	class->attributes = class_attr;
	subject->attributes = subject_attr;
	sensitive->attributes = sensitive_attr;
	decrypt->attributes = decrypt_attr;
	sign->attributes = sign_attr;
	sign_recover->attributes = sign_recover_attr;
	unwrap->attributes = unwrap_attr;
	extractable->attributes = extractable_attr;
	never_extr->attributes = never_extr_attr;
	always_sens->attributes = always_sens_attr;
	wrap_with_trusted->attributes = wrap_with_trusted_attr;
	unwrap_templ->attributes = unwrap_templ_attr;
	always_auth->attributes = always_auth_attr;

	template_update_attribute(tmpl_list, class);
	template_update_attribute(tmpl_list, subject);
	template_update_attribute(tmpl_list, sensitive);
	template_update_attribute(tmpl_list, decrypt);
	template_update_attribute(tmpl_list, sign);
	template_update_attribute(tmpl_list, sign_recover);
	template_update_attribute(tmpl_list, unwrap);
	template_update_attribute(tmpl_list, extractable);
	template_update_attribute(tmpl_list, never_extr);
	template_update_attribute(tmpl_list, always_sens);
	template_update_attribute(tmpl_list, wrap_with_trusted);
	template_update_attribute(tmpl_list, unwrap_templ);
	template_update_attribute(tmpl_list, always_auth);

	return CKR_OK;
}


static CK_RV
rsa_priv_add_default_attributes(struct template_list *tmpl_list)
{
	CK_RV rc;
	uint32_t rsa_priv_key_mech_count = 7;
	CK_MECHANISM_TYPE_PTR mech;

	struct template_node *keygen_mech;
	struct template_node *allowed_mech;
	struct template_node *key_type;

	CK_ATTRIBUTE   *keygen_mech_attr = NULL;
	CK_ATTRIBUTE   *allowed_mech_attr = NULL;
	CK_ATTRIBUTE   *key_type_attr = NULL;

	rc = priv_key_add_default_attributes(tmpl_list);
	if (rc != CKR_OK) {
		printf("priv_key_set_default_attributes failed\n");
		return rc;
	}

	key_type = (struct template_node *)malloc(sizeof(struct template_node));
	keygen_mech = (struct template_node *)malloc(sizeof(struct template_node));
	allowed_mech = (struct template_node *)malloc(sizeof(struct template_node));

	key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
		+ sizeof(CK_KEY_TYPE));
	keygen_mech_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
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
	keygen_mech_attr->ulValueLen = 0;
	keygen_mech_attr->pValue = NULL;

	allowed_mech_attr->type = CKA_ALLOWED_MECHANISMS;
	allowed_mech_attr->ulValueLen = rsa_priv_key_mech_count;
	allowed_mech_attr->pValue = (CK_MECHANISM_TYPE_PTR)allowed_mech_attr
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

	template_update_attribute(tmpl_list, key_type);
	template_update_attribute(tmpl_list, keygen_mech);
	template_update_attribute(tmpl_list, allowed_mech);

	return CKR_OK;
}

static CK_RV template_add_default_attributes(OBJECT *obj)
{
	CK_RV rc;

	CK_ULONG class, subclass;

	class = obj->obj_class;
	subclass = obj->obj_subclass;

	/* first add the default common attributes */
	rc = template_add_default_common_attributes(&obj->template_list);
	if (rc != CKR_OK) {
		printf("template_set_default_common_attributes failed.\n");
		return rc;
	}

	/* set the template class-specific default attributes */
	switch (class) {
		case CKO_PUBLIC_KEY:
			switch (subclass) {
				case CKK_RSA:
					return rsa_publ_add_default_attributes(&obj->template_list);
				default:
					printf("%s, %d Invalid Attribute\n", __func__,__LINE__);
					return CKR_ATTRIBUTE_VALUE_INVALID;
			}

		case CKO_PRIVATE_KEY:
			switch (subclass) {
				case CKK_RSA:
					return rsa_priv_add_default_attributes(&obj->template_list);
				default:
					printf("%s, %d Invalid Attribute\n", __func__,__LINE__);
					return CKR_ATTRIBUTE_VALUE_INVALID;
			}

		default:
			printf("%s, %d Invalid Attribute\n", __func__,
					__LINE__);
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
}


/* template_add_attributes() */
static CK_RV template_add_attributes(OBJECT *obj,
		CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
	struct template_node *tmpl_node;
	struct CK_ATTRIBUTE *attr;
	unsigned int i;

	for (i = 0; i < ulCount; i++) {

		if (!is_attribute_defined(pTemplate[i].type)) {
			printf("Template type invalid \n");
			continue;
		}

		attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
					      pTemplate[i].ulValueLen);
		if (!attr) {
			printf("attr malloc failed\n");
			return CKR_HOST_MEMORY;
		}

		attr->type = pTemplate[i].type;
		attr->ulValueLen = pTemplate[i].ulValueLen;

		if (attr->ulValueLen != 0) {
			attr->pValue = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
			memcpy(attr->pValue, pTemplate[i].pValue,
				attr->ulValueLen);
		} else
			attr->pValue = NULL;

		tmpl_node = malloc(sizeof(struct template_node));
		if (!tmpl_node) {
			printf("template malloc failed\n");
			return CKR_HOST_MEMORY;
		}

		tmpl_node->attributes = attr;

		template_update_attribute(&obj->template_list, tmpl_node);
	}

	return CKR_OK;
}

static CK_BBOOL template_has_attribute(struct template_list *tmpl_list,
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

/* template_compare() */
CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount,
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
		rc = template_has_attribute(tmpl_list, attr1->type, &attr2);
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

static CK_BBOOL template_get_class(struct template_list *tmpl_list,
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

static CK_BBOOL
rsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
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

static CK_BBOOL attributes_check_exportability(struct template_list *tmpl_list,
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

	template_get_class(tmpl_list, &class, &subclass);

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

	sensitive_val = template_has_attribute(tmpl_list, CKA_SENSITIVE,
				&sensitive);
	extractable_val = template_has_attribute(tmpl_list, CKA_EXTRACTABLE,
				&extractable);
	if (sensitive_val && extractable_val) {
		sensitive_val = *(CK_BBOOL *)sensitive->pValue;
		extractable_val = *(CK_BBOOL *)extractable->pValue;
		if (sensitive_val == FALSE && extractable_val == TRUE)
			return TRUE;
	} else {
		/* technically, we should throw an error here... */
		return FALSE;
	}

	/* at this point, we know the object must have CKA_SENSITIVE = TRUE
	 * or CKA_EXTRACTABLE = FALSE (or both).
	 * need to determine whether the particular attribute in question is
	 * a "sensitive" attribute.
	 */
	if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_priv_check_exportability(type);

		default:
			return TRUE;
		}
	}

	return TRUE;
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

					ck_obj_class = (CK_OBJECT_CLASS *)(ck_attrs + sizeof(CK_ATTRIBUTE));
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

					ck_obj_class =  (CK_OBJECT_CLASS *)(ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_obj_class) = CKO_PUBLIC_KEY;

					ck_attrs->type = CKA_CLASS;
					ck_attrs->pValue = ck_obj_class;
					ck_attrs->ulValueLen = sizeof(CK_OBJECT_CLASS);

					break;
				default:
					printf("Ojbect type not supported\n");
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

					ck_key_type = (CK_KEY_TYPE *)(ck_attrs + sizeof(CK_ATTRIBUTE));
					*(ck_key_type) = CKK_RSA;

					ck_attrs->type = CKA_KEY_TYPE;
					ck_attrs->pValue = ck_key_type;
					ck_attrs->ulValueLen = sizeof(CK_KEY_TYPE);
					break;

				default:
					printf("Key type not supported\n");
					return CKR_ATTRIBUTE_TYPE_INVALID;
			}
			break;
		case SK_ATTR_LABEL:
			ck_attrs = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) +
						sk_attrs->valueLen);
			if (!ck_attrs)
				return CKR_HOST_MEMORY;

			ck_label = (CK_BYTE *)(ck_attrs + sizeof(CK_ATTRIBUTE));
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

			ck_id = (CK_BYTE *)(ck_attrs + sizeof(CK_ATTRIBUTE));
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

			mod_bits = (CK_ULONG *)(ck_attrs + sizeof(CK_ATTRIBUTE));
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

			temp = (CK_BYTE *)(ck_attrs + sizeof(CK_ATTRIBUTE));
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

			temp = (CK_BYTE *)(ck_attrs + sizeof(CK_ATTRIBUTE));
			memcpy(temp, sk_attrs->value, sk_attrs->valueLen);

			ck_attrs->type = CKA_PUBLIC_EXPONENT;
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
			ret = template_compare(pTemplate, ulCount,
				&temp->object.template_list);
			if (ret == TRUE) {
				object_handle[i] = (CK_OBJECT_HANDLE)temp;
				i++;
			}
		}
	} else {
		STAILQ_FOREACH(temp, obj_list, entry) {
			object_handle[i] = (CK_OBJECT_HANDLE)temp;
			i++;
		}
	}

	*pobjCount = i;
	return CKR_OK;
}

struct object_list *get_object_list(CK_SLOT_ID slotID)
{
	struct slot_info *ginfo;

	ginfo = get_global_slot_info(slotID);

	return &ginfo->obj_list;
}

CK_BBOOL is_object_handle_valid(CK_OBJECT_HANDLE hObject,
		CK_SLOT_ID slotID)
{
	struct object_list *obj_list;
	struct object_node *temp;

	obj_list = get_object_list(slotID);

	STAILQ_FOREACH(temp, obj_list, entry) {
		if ((CK_OBJECT_HANDLE)temp == hObject)
			return TRUE;
	}

	return FALSE;
}

CK_RV get_attribute_value(struct object_node *obj,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	CK_ATTRIBUTE *attr;
	CK_RV ret = CKR_OK;
	CK_ULONG i = 0;
	CK_BBOOL flag;
	struct template_list *obj_tmpl;

	obj_tmpl = &obj->object.template_list;

	for (i = 0; i < ulCount; i++) {
		flag = attributes_check_exportability(obj_tmpl, pTemplate[i].type);
		if (flag == FALSE) {
			ret = CKR_ATTRIBUTE_SENSITIVE;
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
			continue;
		}

		flag = template_has_attribute(obj_tmpl, pTemplate[i].type, &attr);
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

	return ret;
}

CK_RV destroy_object_list(CK_SLOT_ID slotID)
{
	struct object_list *obj_list = get_object_list(slotID);
	struct template_list *tmpl_list;
	struct object_node *obj_temp;
	struct template_node *tmpl_temp;

	if (!STAILQ_EMPTY(obj_list)) {
		STAILQ_FOREACH(obj_temp, obj_list, entry) {
			OBJECT *obj = &obj_temp->object;
			tmpl_list = &obj->template_list;
			STAILQ_FOREACH(tmpl_temp, tmpl_list, entry) {
				STAILQ_REMOVE(tmpl_list, tmpl_temp, template_node, entry);
			}
#if 0
			if (STAILQ_EMPTY(tmpl_list))
				printf("Template list destroyed successfuly\n");
#endif

			STAILQ_REMOVE(obj_list, obj_temp, object_node, entry);			
		}
	}
#if 0
	if (STAILQ_EMPTY(obj_list))
		printf("Object list destroyed successfuly\n");
#endif

	return CKR_OK;
}

#define OBJ_SK_ATTR_COUNT	2
#define RSA_PUB_SK_ATTR_COUNT	5
#define RSA_PRIV_SK_ATTR_COUNT	4

SK_ATTRIBUTE_TYPE rsa_pub_attr_type[RSA_PUB_SK_ATTR_COUNT] = {
	SK_ATTR_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_MODULUS,
	SK_ATTR_PUBLIC_EXPONENT,
	SK_ATTR_MODULUS_BITS
};

SK_ATTRIBUTE_TYPE rsa_priv_attr_type[RSA_PRIV_SK_ATTR_COUNT] = {
	SK_ATTR_LABEL,
	SK_ATTR_OBJECT_INDEX,
	SK_ATTR_MODULUS,
	SK_ATTR_PUBLIC_EXPONENT
};

static CK_RV object_add_template(OBJECT *obj,
		SK_ATTRIBUTE_TYPE *sk_attr_type, uint32_t attrCount)
{
	SK_ATTRIBUTE temp_sk_attr[attrCount], *sk_attr;
	CK_ATTRIBUTE_PTR ck_attr;
	SK_RET_CODE ret;
	uint32_t i = 0;
	CK_RV rc;

	memset(temp_sk_attr, 0, sizeof(SK_ATTRIBUTE) * attrCount);
	for (i = 0; i < attrCount; i++)
		temp_sk_attr[i].type = sk_attr_type[i];

	ret = sk_funcs->SK_GetObjectAttribute(obj->obj_handle,
			temp_sk_attr, attrCount);
	if (ret != SKR_OK) {
		printf("%s, %d SK_GetObjectAttribute failed %x\n",
			__func__, __LINE__, ret);
		return CKR_GENERAL_ERROR;
	}

	for (i = 0; i < attrCount; i++) {
		if ((int16_t)temp_sk_attr[i].valueLen == -1)
			continue;

		sk_attr = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) +
			temp_sk_attr[i].valueLen);

		sk_attr->type = temp_sk_attr[i].type;
		sk_attr->value = sk_attr + sizeof(SK_ATTRIBUTE);
		sk_attr->valueLen = temp_sk_attr[i].valueLen;

		ret = sk_funcs->SK_GetObjectAttribute(obj->obj_handle,
			sk_attr, 1);
		if (ret != SKR_OK) {
			printf("%s, %d SK_GetObjectAttribute failed with error code = %x\n",
				__func__, __LINE__, ret);
			free(sk_attr);
			return CKR_GENERAL_ERROR;
		}

		rc = map_sk_to_pkcs_attr(sk_attr, &ck_attr);
		if (rc != CKR_OK) {
			free(sk_attr);
			return CKR_GENERAL_ERROR;
		}

		rc = template_add_attributes(obj, ck_attr, 1);
		if (rc != CKR_OK) {
			printf("template_add_attributes failed\n");
			return rc;
		}

		free(sk_attr);
		free(ck_attr);
	}

	return CKR_OK;
}

static CK_RV create_rsa_pub_key_object(SK_OBJECT_HANDLE hObject,
			struct object_node **rsa_pub_key)
{
	struct object_node *pub_key;
	CK_RV rc;

	pub_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!pub_key) {
		printf("pub_key object node malloc failed\n");
		return CKR_HOST_MEMORY;
	}

	memset(pub_key, 0, sizeof(struct object_node));
	pub_key->object.obj_handle = hObject;

	rc = object_add_template(&pub_key->object, rsa_pub_attr_type,
				RSA_PUB_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		printf("object_add_template failed\n");
		free(pub_key);
		return rc;
	}

	*rsa_pub_key = pub_key;
	return CKR_OK;
}

static CK_RV create_rsa_priv_key_object(SK_OBJECT_HANDLE hObject,
			struct object_node **rsa_priv_key)
{
	struct object_node *priv_key;
	CK_RV rc;

	priv_key = (struct object_node *)malloc(sizeof(struct object_node));
	if (!priv_key) {
		printf("%s, %d, priv_key object node malloc failed\n",
			__func__, __LINE__);
		return CKR_HOST_MEMORY;
	}

	priv_key->object.obj_handle = hObject;
	memset(priv_key, 0, sizeof(struct object_node));

	rc = object_add_template(&priv_key->object, rsa_priv_attr_type,
				RSA_PRIV_SK_ATTR_COUNT);
	if (rc != CKR_OK) {
		printf("template_add_attributes failed\n");
		free(priv_key);
		return rc;
	}

	*rsa_priv_key = priv_key;
	return CKR_OK;
}

CK_RV get_all_token_objects(struct object_list *obj_list)
{
	uint32_t obj_count, max_obj_count = 50, j = 0;
	SK_ATTRIBUTE temp_sk_attr[OBJ_SK_ATTR_COUNT];
	SK_RET_CODE ret;
	SK_OBJECT_HANDLE objs[max_obj_count];
	SK_KEY_TYPE key_type;
	SK_OBJECT_TYPE obj_type;

	CK_RV rc;

	ret = sk_funcs->SK_EnumerateObjects(NULL, 0, objs,
			max_obj_count, &obj_count);
	if (ret != SKR_OK) {
		printf("SK_EnumerateObjects failed with ret code 0x%x\n", ret);
		return CKR_GENERAL_ERROR;
	}

	printf("%s,%d SK_EnumerateObjects returned %u objects\n",
		__func__, __LINE__, obj_count);

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
			temp_sk_attr, OBJ_SK_ATTR_COUNT);
		if (ret != SKR_OK) {
			printf("%s, %d SK_GetObjectAttribute failed\n",
				__func__, __LINE__);
			return CKR_GENERAL_ERROR;
		}

		switch (obj_type) {
			case SK_KEY_PAIR:
				switch (key_type) {
					case SKK_RSA:
					{
						struct object_node *rsa_pub_key, *rsa_priv_key;

						rc = create_rsa_pub_key_object(objs[j], &rsa_pub_key);
						if (rc != CKR_OK) {
							printf("create_rsa_pub_key_object object node malloc failed\n");
							return rc;
						}

						rsa_pub_key->object.obj_class = CKO_PUBLIC_KEY;
						rsa_pub_key->object.obj_subclass = CKK_RSA;

						rc = template_add_default_attributes(&rsa_pub_key->object);
						if (rc != CKR_OK) {
							printf("template_add_default_attributes failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, rsa_pub_key, entry);

						rc = create_rsa_priv_key_object(objs[j], &rsa_priv_key);
						if (rc != CKR_OK) {
							printf("create_rsa_priv_key_object object node malloc failed\n");
							return rc;
						}

						rsa_priv_key->object.obj_class = CKO_PRIVATE_KEY;
						rsa_priv_key->object.obj_subclass = CKK_RSA;

						rc = template_add_default_attributes(&rsa_priv_key->object);
						if (rc != CKR_OK) {
							printf("template_add_default_attributes failed\n");
							return rc;
						}
						STAILQ_INSERT_HEAD(obj_list, rsa_priv_key, entry);
					}
					break;
					default:
						return CKR_GENERAL_ERROR;
				}
			break;
			case SK_PUBLIC_KEY:
				switch (key_type) {
					case SKK_RSA:
					{
						struct object_node *pub_key;

						rc = create_rsa_pub_key_object(objs[j], &pub_key);
						if (rc != CKR_OK) {
							printf("create_rsa_pub_key_object object node malloc failed\n");
							return rc;
						}

						pub_key->object.obj_class = CKO_PUBLIC_KEY;
						pub_key->object.obj_subclass = CKK_RSA;

						rc = template_add_default_attributes(&pub_key->object);
						if (rc != CKR_OK) {
							printf("template_add_default_attributes failed\n");
							return rc;
						}

						STAILQ_INSERT_HEAD(obj_list, pub_key, entry);
					}
					break;
					default:
						return CKR_ARGUMENTS_BAD;
				}
			break;
			default:
				return CKR_ARGUMENTS_BAD;
		}
	}

	return CKR_OK;
}
