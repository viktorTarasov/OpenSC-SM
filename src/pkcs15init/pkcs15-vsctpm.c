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
	struct sc_card *card = p15card->card;

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
	struct sc_file  *file = NULL;
	struct sc_path  path;
	struct sc_pkcs15_df *df;
	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
}


/*
 * Allocate a file
 */
static int
vsctpm_pkcs15_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file	*file = NULL;
	const char *_template = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "type %X; num %i\n", type, num);
	switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			_template = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			_template = "public-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			_template = "certificate";
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Profile template not supported");
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Select a key reference
 */
static int
vsctpm_pkcs15_select_key_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file  *file = NULL;
	int rv = 0, idx = key_info->key_reference & ~IASECC_OBJECT_REF_LOCAL;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "'seed' key reference %i; path %s", key_info->key_reference & ~IASECC_OBJECT_REF_LOCAL,
			sc_print_path(&key_info->path));

	rv = sc_select_file(card, &key_info->path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select DF to select key reference in");

	/* 1 <= ObjReference <= 31 */
	if (idx < IASECC_OBJECT_REF_MIN)
		idx = IASECC_OBJECT_REF_MIN;

	/* Look for the suitable slot */
	if (idx <= IASECC_OBJECT_REF_MAX)   {
		struct vsctpm_ctl_get_free_reference ctl_data;

		ctl_data.key_size = key_info->modulus_length;
		ctl_data.usage = key_info->usage;
		ctl_data.access = key_info->access_flags;
		ctl_data.index = idx;

		rv = sc_card_ctl(card, SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE, &ctl_data);
		if (!rv)
			sc_log(ctx, "found allocated slot %i", idx);
		else if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND && idx <= IASECC_OBJECT_REF_MAX)
			sc_log(ctx, "found empty slot %i", idx);
		else
			LOG_TEST_RET(ctx, rv, "Cannot select key reference");

		idx = ctl_data.index;
	}

	/* All card objects but PINs are locals */
	key_info->key_reference = idx | IASECC_OBJECT_REF_LOCAL;
	sc_log(ctx, "selected key reference %i", key_info->key_reference);

	if (file)
		sc_file_free(file);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_sdo_get_data(struct sc_card *card, struct vsctpm_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_GET_DATA, sdo);
	LOG_TEST_RET(ctx, rv, "VscTpm: GET DATA error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_pkcs15_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
					struct sc_pkcs15_object *object)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct vsctpm_sdo *sdo_prvkey = NULL, *sdo_pubkey = NULL;
	size_t keybits = key_info->modulus_length;
	unsigned char zeros[0x200];
	int	 rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "create private key(keybits:%i,usage:%X,access:%X,ref:%X)",
			keybits, key_info->usage, key_info->access_flags, key_info->key_reference);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * RSA key generation
 */
static int
vsctpm_pkcs15_generate_key(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct vsctpm_sdo *sdo_prvkey = NULL;
	struct vsctpm_sdo *sdo_pubkey = NULL;
	struct sc_file	*file = NULL;
	unsigned char *tmp = NULL;
	size_t tmp_len;
	unsigned long caps;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "generate key(bits:%i,AuthID:%s", keybits, sc_pkcs15_print_id(&object->auth_id));

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Store a private key
 */
static int
vsctpm_pkcs15_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey *prvkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct sc_pkcs15_prkey_rsa *rsa = &prvkey->u.rsa;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Store IAS/ECC key(keybits:%i,AuthID:%s)", keybits, sc_pkcs15_print_id(&object->auth_id));

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_pkcs15_delete_object (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	int rv, key_ref;

	LOG_FUNC_CALLED(ctx);

	switch(object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PUBKEY:
		sc_log(ctx, "Delete Public Key '%s'", object->label);

		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	case SC_PKCS15_TYPE_PRKEY:
		sc_log(ctx, "Delete Private Key '%s'", object->label);

		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	case SC_PKCS15_TYPE_CERT:
		sc_log(ctx, "Delete Certificate '%s'", object->label);

		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
vsctpm_store_prvkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)object->data;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Private Key id '%s'", sc_pkcs15_print_id(&prkey_info->id));

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
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

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_store_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object, struct sc_pkcs15_der *data,
		struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "vsctpm_store_cert() authID '%s'", sc_pkcs15_print_id(&object->auth_id));

	/* NOT_IMPLEMENTED error code indicates to the upper call to execute the default 'store data' procedure */
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
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
	NULL,					/* pkcs15init emulation update_any_df */
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
