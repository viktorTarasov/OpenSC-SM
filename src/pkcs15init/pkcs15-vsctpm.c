/*
 * VSCTPM specific operations for PKCS #15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/log.h"
#include "../libopensc/pkcs15.h"
#include "../libopensc/cards.h"
#include "../libopensc/vsctpm-md.h"

#include "pkcs15-init.h"
#include "profile.h"

int
vsctpm_pkcs15_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
//	struct sc_card *card = p15card->card;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
}


/*
 * Erase the card
 *
 */
static int
vsctpm_pkcs15_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
//	struct sc_file  *file = NULL;
//	struct sc_path  path;
//	struct sc_pkcs15_df *df;
//	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
}


/*
 * Allocate a file
 */

static int
vsctpm_md_key_type_from_usage(struct sc_context *ctx, unsigned usage)
{
#ifdef ENABLE_MINIDRIVER
	LOG_FUNC_CALLED(ctx);

	if (usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
		LOG_FUNC_RETURN(ctx, AT_SIGNATURE);
	if (usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP | SC_PKCS15_PRKEY_USAGE_DERIVE))
		LOG_FUNC_RETURN(ctx, AT_KEYEXCHANGE);

	LOG_FUNC_RETURN(ctx, AT_KEYEXCHANGE);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


/*
 * Select a key reference
 */
static int
vsctpm_pkcs15_select_key_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_file *file = NULL;
	int rv = 0, idx, type;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Select key reference, initial value 0x%X", key_info->key_reference);

	rv = vsctpm_md_cmap_get_free_index(card);
	LOG_TEST_RET(ctx, rv, "Failed to get CMAP free index");
	idx = rv + 1;

	type = vsctpm_md_key_type_from_usage(ctx, key_info->usage);
	if (type == AT_KEYEXCHANGE)
		idx |= 0x80;

	key_info->key_reference = idx;

	sc_log(ctx, "Select key reference, key type %i, index 0x%X", type, key_info->key_reference);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_pkcs15_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct vsctpm_md_container mdc;
	struct sc_pkcs15_prkey *priv_key = NULL;
	char pin[50];
	unsigned type;
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "create private key(keybits:%i,usage:%X,access:%X,ref:%X)",
		key_info->modulus_length, key_info->usage, key_info->access_flags, key_info->key_reference);

	rv = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_CHV, VSCTPM_USER_PIN_REF);
	LOG_TEST_RET(ctx, rv, "Failed to verify secret 'VSCTPM_USER_PIN_REF'");

	memset(&mdc, 0, sizeof(struct vsctpm_md_container));
	mdc.idx = (key_info->key_reference & 0x7F) - 1;

	type = vsctpm_md_key_type_from_usage(ctx, key_info->usage);
	if (type == AT_KEYEXCHANGE)
		mdc.rec.wKeyExchangeKeySizeBits = key_info->modulus_length;
	else if (type == AT_SIGNATURE)
		mdc.rec.wSigKeySizeBits = key_info->modulus_length;
	else
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = vsctpm_md_cmap_create_container(card, pin, &key_info->cmap_record.guid, &key_info->cmap_record.guid_len);
	LOG_TEST_RET(ctx, rv, "Failed to create container");
	sc_log(ctx, "New container '%s'", key_info->cmap_record.guid);

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}

/*
 * RSA key generation
 */
static int
vsctpm_pkcs15_generate_key(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	char pin[50];
	unsigned type;
	unsigned char *blob;
	size_t blob_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "generate key(bits:%i,AuthID:%s", key_info->modulus_length, sc_pkcs15_print_id(&object->auth_id));
	sc_log(ctx, "Container '%s'", key_info->cmap_record.guid);

        type = vsctpm_md_key_type_from_usage(ctx, key_info->usage);

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = vsctpm_md_key_generate(card, key_info->cmap_record.guid, type, key_info->modulus_length, pin, &blob, &blob_len);
	LOG_TEST_RET(ctx, rv, "Failed to generate private key");

	rv = sc_pkcs15_decode_pubkey(ctx, pubkey, blob, blob_len);
	LOG_TEST_RET(ctx, rv, "Cannot get public key from blob");

	free(blob);

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


/*
 * Store a private key
 */
static int
vsctpm_pkcs15_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey *prvkey)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct sc_pkcs15_prkey_rsa *rsa = &prvkey->u.rsa;
	char pin[50];
	unsigned type;
	unsigned char *blob = NULL;
	size_t blob_len = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Store key(keybits:%i,AuthID:%s)", key_info->modulus_length, sc_pkcs15_print_id(&object->auth_id));
	sc_log(ctx, "Container '%s'", key_info->cmap_record.guid);

        type = vsctpm_md_key_type_from_usage(ctx, key_info->usage);

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = sc_pkcs15_encode_prvkey_rsa(ctx, &prvkey->u.rsa, &blob, &blob_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode private key");
	sc_log(ctx, "Private key blob (%p, %i)", blob, blob_len);

	rv = vsctpm_md_key_import(card, key_info->cmap_record.guid, type, key_info->modulus_length, pin, blob, blob_len);
	LOG_TEST_RET(ctx, rv, "Failed to import private key");

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_pkcs15_delete_container (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *key_object)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) key_object->data;
	struct sc_pkcs15_object *cert_obj = NULL;
	char pin[50], cmap_guid[50];
	int rv, idx;

	LOG_FUNC_CALLED(ctx);

	idx = (key_info->key_reference & 0x7F) - 1;
	sc_log(ctx, "Delete Private Key '%s', reference 0x%X, container index %i", key_object->label, key_info->key_reference, idx);

	memset(cmap_guid, 0, sizeof(cmap_guid));
	memcpy(cmap_guid, key_info->cmap_record.guid, key_info->cmap_record.guid_len);

	rv = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_CHV, VSCTPM_USER_PIN_REF);
	LOG_TEST_RET(ctx, rv, "Failed to verify secret 'VSCTPM_USER_PIN_REF'");

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = sc_pkcs15_find_cert_by_id(p15card, &key_info->id, &cert_obj);
	if (cert_obj)   {
		rv = sc_pkcs15init_delete_object(p15card, profile, cert_obj);
		LOG_TEST_RET(ctx, rv, "Cannot delete linked certificate");
	}

	rv = vsctpm_md_cmap_delete_container(card, pin, cmap_guid);
	LOG_TEST_RET(ctx, rv, "Cannot delete container");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_pkcs15_delete_cert (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *obj)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_MINIDRIVER
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) obj->data;
	struct sc_pkcs15_cert *p15cert = NULL;
	char pin[50];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Delete Cert '%s'", obj->label);

	rv = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_CHV, VSCTPM_USER_PIN_REF);
	LOG_TEST_RET(ctx, rv, "Failed to verify secret 'VSCTPM_USER_PIN_REF'");

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = sc_pkcs15_read_certificate(p15card, cert_info, &p15cert);
	LOG_TEST_RET(ctx, rv, "Read certificate failed");

	rv = vsctpm_md_cmap_delete_certificate(card, pin, p15cert);
	LOG_TEST_RET(ctx, rv, "Cannot delete container");

	sc_pkcs15_free_certificate(p15cert);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
#endif
}


static int
vsctpm_pkcs15_delete_object (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	switch(object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PUBKEY:
		sc_log(ctx, "Delete Public Key '%s'", object->label);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	case SC_PKCS15_TYPE_PRKEY:
		rv = vsctpm_pkcs15_delete_container(profile, p15card, object);
		LOG_TEST_RET(ctx, rv, "Cannot delete container");
		break;
	case SC_PKCS15_TYPE_CERT:
		sc_log(ctx, "Delete Certificate '%s'", object->label);
		rv = vsctpm_pkcs15_delete_cert(profile, p15card, object);
		LOG_TEST_RET(ctx, rv, "Cannot delete certificate");
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_store_prvkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)object->data;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Private Key id '%s'", sc_pkcs15_print_id(&prkey_info->id));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_store_pubkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *pubkey_info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Public Key id '%s'", sc_pkcs15_print_id(&pubkey_info->id));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_store_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object, struct sc_pkcs15_der *data,
		struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	struct sc_pkcs15_object *prkey_object = NULL;
	char pin[50], cmap_guid[50];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "vsctpm_store_cert() ID '%s', data(%p,%i)", sc_pkcs15_print_id(&cert_info->id), data->value, data->len);

	rv = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_CHV, VSCTPM_USER_PIN_REF);
	LOG_TEST_RET(ctx, rv, "Failed to verify secret 'VSCTPM_USER_PIN_REF'");

	rv = vsctpm_get_pin_from_cache(p15card, pin, sizeof(pin));
	LOG_TEST_RET(ctx, rv, "Cannot get PIN from cache");

	rv = sc_pkcs15_find_prkey_by_id(p15card, &cert_info->id, &prkey_object);
	if (prkey_object)   {
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)prkey_object->data;

		sc_log(ctx, "Found corresponding private key object");
		memset(cmap_guid, 0, sizeof(cmap_guid));
		memcpy(cmap_guid, prkey_info->cmap_record.guid, prkey_info->cmap_record.guid_len);

		rv = vsctpm_md_store_my_cert(card, pin, cmap_guid, cert_info->authority, object->label, data->value, data->len);
	}
	else   {
		rv = vsctpm_md_store_my_cert(card, pin, NULL, cert_info->authority, object->label, data->value, data->len);
	}

	LOG_TEST_RET(ctx, rv, "Failed to store certificate");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_IMPLEMENTED;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		rv = vsctpm_store_prvkey(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		rv = vsctpm_store_pubkey(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_CERT:
		rv = vsctpm_store_cert(p15card, profile, object, data, path);
		break;
	default:
		rv = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_emu_update_any_df(struct sc_profile *profilr, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *obj)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static struct sc_pkcs15init_operations
sc_pkcs15init_vsctpm_operations = {
	vsctpm_pkcs15_erase_card,
	NULL,					/* init_card  */
	NULL,					/* create_dir */
	NULL,					/* create_domain */
	NULL,					/* select_pin_reference */
	NULL,					/* create_pin */
	vsctpm_pkcs15_select_key_reference,
	vsctpm_pkcs15_create_key,
	vsctpm_pkcs15_store_key,
	vsctpm_pkcs15_generate_key,
	NULL,					/* encode private key */
	NULL,					/* encode public key */
	NULL,					/* finalize_card */
	vsctpm_pkcs15_delete_object,
	NULL,					/* pkcs15init emulation update_dir */
	vsctpm_emu_update_any_df,		/* pkcs15init emulation update_any_df */
	NULL,					/* pkcs15init emulation update_tokeninfo */
	NULL,					/* pkcs15init emulation write_info */
	vsctpm_emu_store_data,
	NULL,					/* sanity_check */
};


struct sc_pkcs15init_operations *
sc_pkcs15init_get_vsctpm_ops(void)
{
	return &sc_pkcs15init_vsctpm_operations;
}

#endif /* ENABLE_OPENSSL */
