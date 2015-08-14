/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008*/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef ENABLE_OPENSSL
#include <openssl/pem.h>
#endif

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "common/compat_strlcpy.h"

#include "vsctpm-md.h"

#define MANU_ID	"VSC TPM"
#define VSCTPM_PKCS15_PIN_AUTH_ID 1
#define VSCTPM_PKCS15_PUK_AUTH_ID 2
#define VSCTPM_PKCS15_ADMIN_AUTH_ID 0x10

unsigned char vsctpm_admin_skey_value[24] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
int sc_pkcs15emu_vsctpm_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int
vsctpm_detect_card( struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);

	/* check if we have the correct card OS */
	if (p15card->card->type != SC_CARD_TYPE_VSCTPM_GENERIC)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_add_user_pin (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_auth_info auth_info;
        struct sc_pkcs15_object   obj;
	int rv, tries_left = -1;

#if ENABLE_MINIDRIVER
	PIN_INFO md_pin_info;
	size_t md_pin_info_size = sizeof(md_pin_info);

	LOG_FUNC_CALLED(ctx);

        tries_left = -1;

	rv = vsctpm_md_get_pin_info(card, ROLE_USER, &md_pin_info);
        LOG_TEST_RET(ctx, rv, "Failed to get User PIN info");
	sc_log(ctx, "User PIN type %X, purpose %X", md_pin_info.PinType, md_pin_info.PinPurpose);

	if (md_pin_info.PinType != AlphaNumericPinType)    {
		sc_log(ctx, "User PIN is expected to be AlphaNumeric");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

        /* add PIN */
        memset(&auth_info, 0, sizeof(auth_info));
        memset(&obj,  0, sizeof(obj));

        auth_info.auth_type	= SC_PKCS15_PIN_AUTH_TYPE_PIN;
        auth_info.auth_method   = SC_AC_CHV;
        auth_info.auth_id.len =		1;
        auth_info.auth_id.value[0] =	VSCTPM_PKCS15_PIN_AUTH_ID;
        auth_info.attrs.pin.min_length          = 8;
        auth_info.attrs.pin.max_length          = 15;
        auth_info.attrs.pin.stored_length	= 8;
        auth_info.attrs.pin.type                = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
        auth_info.attrs.pin.reference           = VSCTPM_USER_PIN_REF;
        auth_info.attrs.pin.flags               = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL;
        auth_info.tries_left			= tries_left;

        strncpy(obj.label, "User PIN", SC_PKCS15_MAX_LABEL_SIZE - 1);
        obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
	obj.auth_id.len = 1;
        obj.auth_id.value[0] = VSCTPM_PKCS15_PUK_AUTH_ID;

        sc_log(ctx, "Add PIN object '%s', id:%s, reference:%i, auth-id:%s", obj.label,
			sc_pkcs15_print_id(&auth_info.auth_id), auth_info.attrs.pin.reference, sc_pkcs15_print_id(&obj.auth_id));
        rv = sc_pkcs15emu_add_pin_obj(p15card, &obj, &auth_info);
        LOG_TEST_RET(ctx, rv, "VSC TPM init failed: cannot add User PIN object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_add_user_puk (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_auth_info auth_info;
        struct sc_pkcs15_object   obj;
	int rv, tries_left;

#if ENABLE_MINIDRIVER
	PIN_INFO md_pin_info;
	size_t md_pin_info_size = sizeof(md_pin_info);

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_md_get_pin_info(card, ROLE_ADMIN, &md_pin_info);
        LOG_TEST_RET(ctx, rv, "Failed to get User PIN info");
	sc_log(ctx, "Admin PIN type %X, purpose %X", md_pin_info.PinType, md_pin_info.PinPurpose);

	if (md_pin_info.PinType != ChallengeResponsePinType)   {
		sc_log(ctx, "Admin PIN is expected to be ChallengeResponsePinType");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

        tries_left = -1;
        memset(&auth_info, 0, sizeof(auth_info));
        memset(&obj,  0, sizeof(obj));

        auth_info.auth_type	= SC_PKCS15_PIN_AUTH_TYPE_AUTH_KEY;
        auth_info.auth_method   = SC_AC_AUT;
        auth_info.auth_id.len =		1;
        auth_info.auth_id.value[0] =	VSCTPM_PKCS15_PUK_AUTH_ID;
        auth_info.attrs.authkey.derived			= 0;
        auth_info.attrs.authkey.skey_id.len		= 1;
        auth_info.attrs.authkey.skey_id.value[0]	= VSCTPM_PKCS15_ADMIN_AUTH_ID;
        auth_info.attrs.authkey.flags = SC_PKCS15_PIN_FLAG_SO_PIN | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL;
        auth_info.attrs.authkey.reference		= VSCTPM_ADMIN_PIN_REF;

        strncpy(obj.label, "User PUK", SC_PKCS15_MAX_LABEL_SIZE - 1);
        obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

        sc_log(ctx, "Add SoPIN object '%s', auth_id:%s", obj.label, sc_pkcs15_print_id(&auth_info.auth_id));
        rv = sc_pkcs15emu_add_auth_key_obj(p15card, &obj, &auth_info);
        LOG_TEST_RET(ctx, rv, "VSC TPM init failed: cannot add User PUK object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_add_admin_skey(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_skey_info kinfo;
	struct sc_pkcs15_object kobj;
	size_t key_size = sizeof(vsctpm_admin_skey_value);
	int    rv;

	LOG_FUNC_CALLED(ctx);

	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));

	kinfo.id.len = 1;
	kinfo.id.value[0] = VSCTPM_PKCS15_ADMIN_AUTH_ID;
	kinfo.key_type = CKM_DES3_CBC;
	kinfo.value_len = key_size;
	kinfo.key_reference = 0x01;

	kinfo.data.value = malloc(key_size);
	if (!kinfo.data.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(kinfo.data.value, vsctpm_admin_skey_value, key_size);
	kinfo.data.len = key_size;

        strncpy(kobj.label, "Admin SKey", SC_PKCS15_MAX_LABEL_SIZE - 1);
	kobj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

	rv = sc_pkcs15emu_add_skey(p15card, &kobj, &kinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add admin PKCS#15 skey object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


#if ENABLE_MINIDRIVER
static int
sc_pkcs15emu_vsctpm_pubkey_from_cert_context(struct sc_context *ctx, CERT_CONTEXT *cert_ctx, struct sc_pkcs15_der *out)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;
	struct sc_pkcs15_der der;
	int rv;

	if (!cert_ctx || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	der.value = cert_ctx->pbCertEncoded;
	der.len = cert_ctx->cbCertEncoded;

	rv = sc_pkcs15_pubkey_from_cert(ctx, &der, &pubkey);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from certificate");

	rv = sc_pkcs15_encode_pubkey(ctx, pubkey, &(out->value), &(out->len));
	LOG_TEST_RET(ctx, rv, "Cannot encode public key");

	sc_pkcs15_free_pubkey(pubkey);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_id_from_cert_context(struct sc_context *ctx, const CERT_CONTEXT *cert_ctx, struct sc_pkcs15_id *id)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;
	struct sc_pkcs15_der der;
	int rv;

	if (!cert_ctx || !id)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	der.value = cert_ctx->pbCertEncoded;
	der.len = cert_ctx->cbCertEncoded;

	rv = sc_pkcs15_pubkey_from_cert(ctx, &der, &pubkey);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from certificate");

#ifdef ENABLE_OPENSSL
	SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, id->value);
	id->len = SHA_DIGEST_LENGTH;
#elif
#error "Get Object ID not implemented"
#endif
	sc_pkcs15_free_pubkey(pubkey);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_prvkey_info_from_cert_context(struct sc_context *ctx, const CERT_CONTEXT *cert_ctx,
		struct vsctpm_md_container *mdc, struct sc_pkcs15_prkey_info *kinfo)
{
	struct sc_pkcs15_cert cert;
	struct sc_pkcs15_der blob;
	char cmap_guid[256];
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!cert_ctx || !kinfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "Private key info blob (%p, %i)", cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded);
	blob.value = cert_ctx->pbCertEncoded;
	blob.len = cert_ctx->cbCertEncoded;

	rv = sc_pkcs15emu_vsctpm_id_from_cert_context(ctx, cert_ctx, &kinfo->id);
	LOG_TEST_RET(ctx, rv, "Cannot get ID from cert context");

	rv = sc_pkcs15_parse_x509_cert(ctx, &blob, &cert);
	LOG_TEST_RET(ctx, rv, "Cannot get certificate from cert. context");

	if (kinfo->subject.value)
		free(kinfo->subject.value);
	kinfo->subject.value = malloc(cert.subject_len);
	if (!kinfo->subject.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(kinfo->subject.value, cert.subject, cert.subject_len);
	kinfo->subject.len = cert.subject_len;

	kinfo->modulus_length = (cert.key->u.rsa.modulus.len & ~0x07) << 3;
	kinfo->native = 1;

	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;

	wcstombs(cmap_guid, mdc->rec.wszGuid, sizeof(cmap_guid));
	kinfo->cmap_record.guid = strdup(cmap_guid);
	kinfo->cmap_record.guid_len = strlen(cmap_guid);
	kinfo->cmap_record.flags = mdc->rec.bFlags;
	kinfo->cmap_record.keysize_sign = mdc->rec.wSigKeySizeBits;
	kinfo->cmap_record.keysize_keyexchange = mdc->rec.wKeyExchangeKeySizeBits;

	sc_pkcs15_free_certificate_data(&cert);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_prvkey_info_from_pubkeyinfo(struct sc_context *ctx, CERT_PUBLIC_KEY_INFO *pubkey_info,
		struct vsctpm_md_container *mdc, struct sc_pkcs15_prkey_info *kinfo)
{
	struct sc_pkcs15_pubkey *pubkey;
	char cmap_guid[256];
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!pubkey_info || !mdc || !kinfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	wcstombs(cmap_guid, mdc->rec.wszGuid, sizeof(cmap_guid));

        pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (!pubkey)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	pubkey->algorithm = SC_ALGORITHM_RSA;

	sc_log(ctx, "Private key info blob (%p, %i)", pubkey_info->PublicKey.pbData, pubkey_info->PublicKey.cbData);
	rv = sc_pkcs15_decode_pubkey(ctx, pubkey, pubkey_info->PublicKey.pbData, pubkey_info->PublicKey.cbData);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from blob");

	kinfo->cmap_record.guid = strdup(cmap_guid);
	kinfo->cmap_record.guid_len = strlen(cmap_guid);
	kinfo->cmap_record.flags = mdc->rec.bFlags;
	kinfo->cmap_record.keysize_sign = mdc->rec.wSigKeySizeBits;
	kinfo->cmap_record.keysize_keyexchange = mdc->rec.wKeyExchangeKeySizeBits;

#ifdef ENABLE_OPENSSL
	SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, kinfo->id.value);
	kinfo->id.len = SHA_DIGEST_LENGTH;
#elif
#error "Get Object ID not implemented"
#endif
	kinfo->modulus_length = ((pubkey->u.rsa.modulus.len + 3) & ~0x07) << 3;
	kinfo->native = 1;

	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;

	sc_pkcs15_free_pubkey(pubkey);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_pubkey_info_from_pubkeyinfo(struct sc_context *ctx, CERT_PUBLIC_KEY_INFO *pubkey_info,
		struct sc_pkcs15_pubkey_info *kinfo)
{
	struct sc_pkcs15_pubkey *pubkey;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!pubkey_info || !kinfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

        pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (!pubkey)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	pubkey->algorithm = SC_ALGORITHM_RSA;

	sc_log(ctx, "Public key info blob (%p, %i)", pubkey_info->PublicKey.pbData, pubkey_info->PublicKey.cbData);
	rv = sc_pkcs15_decode_pubkey(ctx, pubkey, pubkey_info->PublicKey.pbData, pubkey_info->PublicKey.cbData);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from blob");

#ifdef ENABLE_OPENSSL
	SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, kinfo->id.value);
	kinfo->id.len = SHA_DIGEST_LENGTH;
#elif
#error "Get Object ID not implemented"
#endif
	kinfo->modulus_length = (pubkey->u.rsa.modulus.len & ~0x07) << 3;
	kinfo->native = 1;

        kinfo->usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_VERIFY;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER | SC_PKCS15_PRKEY_USAGE_WRAP;

	sc_pkcs15_free_pubkey(pubkey);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_pubkey_info_from_cert_context(struct sc_context *ctx,
		CERT_CONTEXT *cert_ctx, struct sc_pkcs15_pubkey_info *kinfo)
{
	struct sc_pkcs15_cert cert;
	struct sc_pkcs15_der blob;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!cert_ctx || !kinfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "Public key info blob (%p, %i)", cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded);
	blob.value = cert_ctx->pbCertEncoded;
	blob.len = cert_ctx->cbCertEncoded;

	rv = sc_pkcs15emu_vsctpm_id_from_cert_context(ctx, cert_ctx, &kinfo->id);
	LOG_TEST_RET(ctx, rv, "Cannot get ID from cert context");

	rv = sc_pkcs15_parse_x509_cert(ctx, &blob, &cert);
	LOG_TEST_RET(ctx, rv, "Cannot get certificate from cert. context");

	if (kinfo->subject.value)
		free(kinfo->subject.value);
	kinfo->subject.value = malloc(cert.subject_len);
	if (!kinfo->subject.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(kinfo->subject.value, cert.subject, cert.subject_len);
	kinfo->subject.len = cert.subject_len;

	kinfo->modulus_length = (cert.key->u.rsa.modulus.len & ~0x07) << 3;
	kinfo->native = 1;

	kinfo->usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_VERIFY;
	kinfo->usage |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER | SC_PKCS15_PRKEY_USAGE_WRAP;

	sc_pkcs15_free_certificate_data(&cert);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_container_add_prvkey(struct sc_pkcs15_card *p15card, unsigned idx,
		 struct vsctpm_md_container *mdc, const CERT_CONTEXT *cert_ctx)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_prkey_info kinfo;
	struct sc_pkcs15_object kobj;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int    rv;

	LOG_FUNC_CALLED(ctx);
	if (!cert_ctx || !mdc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));

	sc_log(ctx, "Private key index '0x%X'", idx);
        if(!CertGetNameString(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, kobj.label, sizeof(kobj.label) - 1))   {
		sc_log(ctx, "Cannot get certificate label: error Ox%X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_CORRUPTED_DATA);
	}
	sc_log(ctx, "Private key label '%s'", kobj.label);

	kinfo.key_reference = idx;

	rv = sc_pkcs15emu_vsctpm_prvkey_info_from_cert_context(ctx, cert_ctx, mdc, &kinfo);
	LOG_TEST_RET(ctx, rv, "Cannot get key info from cert context");

	kobj.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE;
	kobj.auth_id.len = 1;
	kobj.auth_id.value[0] = VSCTPM_PKCS15_PIN_AUTH_ID;

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &kobj, &kinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add PKCS#15 private key object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_pubkeyinfo_add_prvkey(struct sc_pkcs15_card *p15card,
		unsigned idx, struct vsctpm_md_container *mdc, CERT_PUBLIC_KEY_INFO *pubkey_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_prkey_info kinfo;
	struct sc_pkcs15_object kobj;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	char cmap_guid[256];
	int    rv;

	LOG_FUNC_CALLED(ctx);
	if (!pubkey_info || !mdc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	wcstombs(cmap_guid, mdc->rec.wszGuid, sizeof(cmap_guid));
	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));

	sc_log(ctx, "Private key '%s' index:0x%X", cmap_guid, idx);
	strlcpy(kobj.label, cmap_guid, sizeof(kobj.label));

	kinfo.key_reference = idx;

	rv = sc_pkcs15emu_vsctpm_prvkey_info_from_pubkeyinfo(ctx, pubkey_info, mdc, &kinfo);
	LOG_TEST_RET(ctx, rv, "Cannot get key info from cert context");

	kobj.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE;
	kobj.auth_id.len = 1;
	kobj.auth_id.value[0] = VSCTPM_PKCS15_PIN_AUTH_ID;

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &kobj, &kinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add PKCS#15 private key object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_pubkeyinfo_add_pubkey(struct sc_pkcs15_card *p15card,
		unsigned idx, struct vsctpm_md_container *mdc, CERT_PUBLIC_KEY_INFO *pubkey_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_pubkey_info kinfo;
	struct sc_pkcs15_object kobj;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	char cmap_guid[256];
	int    rv;

	LOG_FUNC_CALLED(ctx);
	if (!pubkey_info || !mdc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	wcstombs(cmap_guid, mdc->rec.wszGuid, sizeof(cmap_guid));
	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));

	sc_log(ctx, "Public key '%s' index:0x%X", cmap_guid, idx);
	strlcpy(kobj.label, cmap_guid, sizeof(kobj.label));

	rv = sc_pkcs15emu_vsctpm_pubkey_info_from_pubkeyinfo(ctx, pubkey_info, &kinfo);
	LOG_TEST_RET(ctx, rv, "Cannot get key info from pubkey-info context");

	kinfo.key_reference = idx;

	kobj.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE;
	kobj.auth_id.len = 1;
	kobj.auth_id.value[0] = VSCTPM_PKCS15_PIN_AUTH_ID;

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &kobj, &kinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add PKCS#15 public key object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_container_add_pubkey(struct sc_pkcs15_card *p15card,
		unsigned idx, const CERT_CONTEXT *cert_ctx)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_pubkey_info kinfo;
	struct sc_pkcs15_object kobj;
	struct sc_pkcs15_der der;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int    rv;

	LOG_FUNC_CALLED(ctx);
	if (!cert_ctx)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));

	sc_log(ctx, "Public key index '0x%X'", idx);
        if(!CertGetNameString(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, kobj.label, sizeof(kobj.label) - 1))   {
		sc_log(ctx, "Cannot get certificate label: error Ox%X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_CORRUPTED_DATA);
	}
	sc_log(ctx, "Public key label '%s'", kobj.label);

	kinfo.key_reference = idx;

	rv = sc_pkcs15emu_vsctpm_pubkey_info_from_cert_context(ctx, cert_ctx, &kinfo);
	LOG_TEST_RET(ctx, rv, "Cannot get key info from cert context");

	kobj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

	rv = sc_pkcs15emu_vsctpm_pubkey_from_cert_context(ctx, cert_ctx, &der);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from certificate");

	rv = sc_der_copy(&kobj.content, &der);
	LOG_TEST_RET(ctx, rv, "Failed to copy DER data");

	rv = sc_der_copy(&kinfo.direct.raw, &der);
	LOG_TEST_RET(ctx, rv, "Failed to copy DER data");

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &kobj, &kinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add PKCS#15 private key object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_container_add_cert (struct sc_pkcs15_card *p15card, const CERT_CONTEXT *cert_ctx)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_pkcs15_cert_info cinfo;
	struct sc_pkcs15_object cobj;
	struct sc_pkcs15_der der;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int    rv;

	LOG_FUNC_CALLED(ctx);
	if (!cert_ctx)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(&cinfo, 0, sizeof(cinfo));
	memset(&cobj, 0, sizeof(cobj));

	if(!CertGetNameString(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, cobj.label, sizeof(cobj.label) - 1))   {
		sc_log(ctx, "Cannot get certificate label: error Ox%X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_CORRUPTED_DATA);
	}
	cobj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;

	rv = sc_pkcs15emu_vsctpm_id_from_cert_context(ctx, cert_ctx, &cinfo.id);
	LOG_TEST_RET(ctx, rv, "Cannot get ID from cert context");

	der.value = cert_ctx->pbCertEncoded;
	der.len = cert_ctx->cbCertEncoded;

	rv = sc_der_copy(&cobj.content, &der);
	LOG_TEST_RET(ctx, rv, "Failed to copy DER data");

	rv = sc_der_copy(&cinfo.value, &der);
	LOG_TEST_RET(ctx, rv, "Failed to copy DER data");

	rv = sc_pkcs15emu_add_x509_cert(p15card, &cobj, &cinfo);
	LOG_TEST_RET(ctx, rv, "Failed to add PKCS#15 certificate object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_enum_containers (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	unsigned char *buf = NULL;
	size_t buf_len = 0;
	struct vsctpm_md_container mdc;
	int    rv, idx, nn_cont;
	char cmap_guid[256];

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_md_cmap_size(card);
	LOG_TEST_RET(ctx, rv, "CMAP cannot get size");
	nn_cont = rv;
	sc_log(ctx, "CMAP length %i", nn_cont);

	for (idx=0; idx < nn_cont; idx++)   {
		rv = vsctpm_md_cmap_init_container(card, idx, &mdc);
		if (rv == SC_ERROR_OBJECT_NOT_FOUND)
			continue;
		LOG_TEST_RET(ctx, rv, "Get MD container error");

		wcstombs(cmap_guid, mdc.rec.wszGuid, sizeof(cmap_guid));
		sc_log(ctx, "%i: cmap-record(%s) flags %X, sizes %i/%i", idx, cmap_guid, mdc.rec.bFlags, mdc.rec.wSigKeySizeBits, mdc.rec.wKeyExchangeKeySizeBits);

		if (mdc.signCertContext)   {
			unsigned ref = (idx + 1);

			rv = sc_pkcs15emu_vsctpm_container_add_cert(p15card, mdc.signCertContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign certificate error");

			rv = sc_pkcs15emu_vsctpm_container_add_prvkey(p15card, ref, &mdc, mdc.signCertContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign certificate error");
		}
		else if (mdc.signRequestContext)   {
			unsigned ref = (idx + 1);

			rv = sc_pkcs15emu_vsctpm_container_add_prvkey(p15card, ref, &mdc, mdc.signRequestContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign request error");

			rv = sc_pkcs15emu_vsctpm_container_add_pubkey(p15card, ref, mdc.signRequestContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign request error");
		}
		else if (mdc.signPublicKeyInfo)   {
			unsigned ref = (idx + 1);

			rv = sc_pkcs15emu_vsctpm_pubkeyinfo_add_prvkey(p15card, ref, &mdc, mdc.signPublicKeyInfo);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign request error");

			rv = sc_pkcs15emu_vsctpm_pubkeyinfo_add_pubkey(p15card, ref, &mdc, mdc.signPublicKeyInfo);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 sign request error");
		}

		if (mdc.exCertContext)   {
			unsigned ref = (idx + 1) | 0x80;

			rv = sc_pkcs15emu_vsctpm_container_add_cert(p15card, mdc.exCertContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 key exchange certificate error");

			rv = sc_pkcs15emu_vsctpm_container_add_prvkey(p15card, ref, &mdc, mdc.exCertContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 key exchange certificate error");
		}
		else if (mdc.exRequestContext)   {
			unsigned ref = (idx + 1) | 0x80;

			rv = sc_pkcs15emu_vsctpm_container_add_prvkey(p15card, ref, &mdc, mdc.exRequestContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 key exchange request error");

			rv = sc_pkcs15emu_vsctpm_container_add_pubkey(p15card, ref, mdc.exRequestContext);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 key exchange request error");
		}
		else if (mdc.exPublicKeyInfo)   {
			unsigned ref = (idx + 1) | 0x80;

			rv = sc_pkcs15emu_vsctpm_pubkeyinfo_add_prvkey(p15card, ref, &mdc, mdc.exPublicKeyInfo);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 exchange pubkey info error");

			rv = sc_pkcs15emu_vsctpm_pubkeyinfo_add_pubkey(p15card, ref, &mdc, mdc.exPublicKeyInfo);
			LOG_TEST_RET(ctx, rv, "Cannot parse PKCS#15 exchange pubkey info error");
		}

		vsctpm_md_free_container(ctx, &mdc);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_enum_files (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	unsigned char *buf = NULL;
	size_t buf_len = 0;
	int    rv;

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_md_enum_files(card, szBASE_CSP_DIR, &buf, &buf_len);
        LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	vsctpm_md_free(card, buf);
	buf = NULL, buf_len = 0;

	rv = vsctpm_md_enum_files(card, "", &buf, &buf_len);
        LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	vsctpm_md_free(card, buf);
	buf = NULL, buf_len = 0;

/*
	if (p15card->md_data)   {
		if (p15card->md_data->cmaps)
			free(p15card->md_data->cmaps);
		free(p15card->md_data);
	}

	mdd = p15card->md_data = calloc(1, sizeof(p15card->md_data));
	if (!mdd)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	for (ptr = buf; (ptr-buf) < buf_len; )   {
		struct sc_md_cmap_record *cmap = NULL;
		mdd->cmaps = realloc(mdd->cmaps, (mdd->cmaps_num + 1) * (sizeof(sc_md_cmap_record)));
		if (!mdd->cmaps)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		cmap = mdd->cmaps + mdd->cmaps_num;


		mdd->cmaps_num  += 1;
	}
*/

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif /* ENABLE_MINIDRIVER */


static int
sc_pkcs15emu_vsctpm_init (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_serial_number serial;
	char   buf[256];
	int    rv;

	LOG_FUNC_CALLED(ctx);

	/* get serial number */
	rv = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	LOG_TEST_RET(ctx, rv, "Cannot get serial nomber");

        rv = vsctpm_md_get_card_info (card);
	LOG_TEST_RET(ctx, rv, "Cannot get card info");

	rv = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (rv != SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	if (p15card->tokeninfo->serial_number)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = malloc(strlen(buf) + 1);
	if (!p15card->tokeninfo->serial_number)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->serial_number, buf);

	if (p15card->tokeninfo->manufacturer_id)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = malloc(strlen(MANU_ID) + 1);
	if (!p15card->tokeninfo->manufacturer_id)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->manufacturer_id, MANU_ID);

	if (!p15card->tokeninfo->label)
		p15card->tokeninfo->label = strdup(card->reader->friendly_name);

	rv = vsctpm_add_user_pin (p15card);
	LOG_TEST_RET(ctx, rv, "Failed to add User PIN object");

	rv = vsctpm_add_user_puk (p15card);
	LOG_TEST_RET(ctx, rv, "Failed to add User PUK object");

	rv = vsctpm_add_admin_skey (p15card);
	LOG_TEST_RET(ctx, rv, "Failed to add Admin Key object");

#if ENABLE_MINIDRIVER
	rv = sc_pkcs15emu_vsctpm_enum_files (p15card);
	LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	rv = sc_pkcs15emu_vsctpm_enum_containers (p15card);
	LOG_TEST_RET(ctx, rv, "Cannot parse CMAP file");
#endif
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15emu_vsctpm_init_ex(struct sc_pkcs15_card *p15card, struct sc_pkcs15emu_opt *opts)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_vsctpm_init(p15card);

	rv = vsctpm_detect_card(p15card);
	if (rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	return sc_pkcs15emu_vsctpm_init(p15card);
}
