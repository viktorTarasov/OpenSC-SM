/*
 * Athena Laser specific operation for PKCS #15 initialization
 *
 * Copyright (C) 2013	Athena
 *			Viktor Tarasov <viktor.tarasov@gmail.com>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "config.h"
#include "libopensc/asn1.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/laser.h"
#include "profile.h"
#include "pkcs15-init.h"
#include "pkcs11/pkcs11.h"

#define LASER_ATTRS_PRKEY_RSA (SC_PKCS15_TYPE_VENDOR_DEFINED | SC_PKCS15_TYPE_PRKEY_RSA)
#define LASER_ATTRS_PUBKEY_RSA (SC_PKCS15_TYPE_VENDOR_DEFINED | SC_PKCS15_TYPE_PUBKEY_RSA)
#define LASER_ATTRS_CERT_X509 (SC_PKCS15_TYPE_VENDOR_DEFINED | SC_PKCS15_TYPE_CERT_X509)
#define LASER_ATTRS_DATA_OBJECT (SC_PKCS15_TYPE_VENDOR_DEFINED | SC_PKCS15_TYPE_DATA_OBJECT)

static int
laser_validate_key_reference(int key_reference)
{
	if (key_reference < LASER_FS_KEY_REF_MIN)
		return SC_ERROR_INVALID_DATA;

	if (key_reference > LASER_FS_KEY_REF_MAX)
		return SC_ERROR_INVALID_DATA;

	return SC_SUCCESS;
}


static int
laser_validate_attr_reference(int key_reference)
{
	if (key_reference < LASER_FS_ATTR_REF_MIN)
		return SC_ERROR_INVALID_DATA;

	if (key_reference > LASER_FS_ATTR_REF_MAX)
		return SC_ERROR_INVALID_DATA;

	return SC_SUCCESS;
}


static int
laser_write_tokeninfo (struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		char *label, unsigned flags)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


int
laser_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Erase the card
 */
static int
laser_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_create_dir(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Allocate a file
 */
static int
laser_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file	*file;
	const char *_template = NULL, *desc = NULL;
	unsigned file_descriptor = 0x01;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_new_file() type %X; num %i",type, num);
	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			_template = "template-private-key";
			file_descriptor = LASER_FILE_DESCRIPTOR_KO;
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			_template = "template-public-key";
			file_descriptor = LASER_FILE_DESCRIPTOR_KO;
			break;
		case SC_PKCS15_TYPE_PUBKEY_DSA:
			desc = "DSA public key";
			_template = "template-public-key";
			file_descriptor = LASER_FILE_DESCRIPTOR_KO;
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			_template = "template-public-data";
			file_descriptor = LASER_FILE_DESCRIPTOR_EF;
			break;
		case LASER_ATTRS_PRKEY_RSA:
			desc = "private key Laser attributes";
			_template = "laser-private-key-attributes";
			file_descriptor = LASER_FILE_DESCRIPTOR_EF;
			break;
		case LASER_ATTRS_PUBKEY_RSA:
			desc = "public key Laser attributes";
			_template = "laser-public-key-attributes";
			file_descriptor = LASER_FILE_DESCRIPTOR_EF;
			break;
		case LASER_ATTRS_CERT_X509:
			desc = "certificate Laser attributes";
			_template = "laser-certificate-attributes";
			file_descriptor = LASER_FILE_DESCRIPTOR_EF;
			break;
		case LASER_ATTRS_DATA_OBJECT:
			desc = "DATA object Laser attributes";
			_template = "laser-public-data-attributes";
			file_descriptor = LASER_FILE_DESCRIPTOR_EF;
			break;
		}
		if (_template)
			break;
		/* If this is a specific type such as SC_PKCS15_TYPE_CERT_FOOBAR,
		 * fall back to the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			sc_log(ctx, "Unsupported file type 0x%X", type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_log(ctx, "laser_new_file() template %s; num %i",_template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_log(ctx, "Profile doesn't define %s template '%s'", desc, _template);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	file->id |= (num & 0xFF);
	file->path.value[file->path.len-1] |= (num & 0xFF);

	if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		file->ef_structure = file_descriptor;

	sc_log(ctx, "new laser file: size %i; EF-type %i/%i; path %s",
			file->size, file->type, file->ef_structure, sc_print_path(&file->path));
	*out = file;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Select private key reference
 */
static int
laser_select_key_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	rv = laser_get_free_index(p15card, SC_PKCS15_TYPE_PRKEY);
	LOG_TEST_RET(ctx, rv, "Cannot get free key reference number");

	key_info->key_reference = rv | LASER_FS_BASEFID_PRVKEY;

	sc_log(ctx, "return selected key reference 0x%X", key_info->key_reference);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Create private key file
 */
static int
laser_create_key_file(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char null_content[2] = {LASER_KO_DATA_TAG_RSA, 0};
	int rv = 0;

	LOG_FUNC_CALLED(ctx);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Create key failed: RSA only supported");

	sc_log(ctx, "create private key(type:%X) ID:%s key-ref:0x%X", object->type, sc_pkcs15_print_id(&key_info->id), key_info->key_reference);
	/* Here, the path of private key file should be defined.
	 * Neverthelles, we need to instanciate private key to get the ACLs. */
	rv = laser_new_file(profile, p15card->card, object->type, key_info->key_reference, &file);
	LOG_TEST_RET(ctx, rv, "Cannot create private key: failed to allocate new key object");

	file->size = key_info->modulus_length / 8;

	file->prop_attr = calloc(1, 5);
	if (!file->prop_attr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->prop_attr_len = 5;

	*(file->prop_attr + 0) = LASER_KO_CLASS_RSA_CRT;

	if (key_info->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP))
		*(file->prop_attr + 1) |= LASER_KO_USAGE_DECRYPT;
	if (key_info->usage & (SC_PKCS15_PRKEY_USAGE_NONREPUDIATION | SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER))
		*(file->prop_attr + 1) |= LASER_KO_USAGE_SIGN;

	*(file->prop_attr + 2) = LASER_KO_ALGORITHM_RSA;
	*(file->prop_attr + 3) = LASER_KO_PADDING_NO;
	*(file->prop_attr + 4) = 0xA3;	/* Max retry counter 10, 3 tries to unlock. TODO what's this ????? */

	sc_log(ctx, "Create private key file: path %s, propr. info %s",
			sc_print_path(&file->path), sc_dump_hex(file->prop_attr, file->prop_attr_len));

	rv = sc_select_file(p15card->card, &file->path, NULL);
	if (rv == 0)   {
		rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE_SELF);
		LOG_TEST_RET(ctx, rv, "Cannot authenticate SC_AC_OP_DELETE_SELF");

		rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
		LOG_TEST_RET(ctx, rv, "Failed to delete private key file");
	}
	else if (rv != SC_ERROR_FILE_NOT_FOUND)    {
		LOG_TEST_RET(ctx, rv, "Select key file error");
	}

	file->encoded_content = malloc(2);
	memcpy(file->encoded_content, null_content, sizeof(null_content));
	file->encoded_content_len = sizeof(null_content);

	rv = sc_pkcs15init_create_file(profile, p15card, file);
	LOG_TEST_RET(ctx, rv, "Failed to create private key file");

	key_info->key_reference = file->path.value[file->path.len - 1];
	key_info->path = file->path;
	sc_log(ctx, "created private key file %s, ref:%X", sc_print_path(&key_info->path), key_info->key_reference);

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_cardctl_laser_genkey args;
	struct sc_file *key_file = NULL;
	unsigned char default_exponent[3] = {0x01, 0x00, 0x01};
	int rv = 0;
	unsigned char piv_algo = 0;

	LOG_FUNC_CALLED(ctx);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "For a while only RSA can be generated");

	rv = sc_select_file(card, &key_info->path, &key_file);
	LOG_TEST_RET(ctx, rv, "Failed to generate key: cannot select private key file");

	rv = sc_pkcs15init_authenticate(profile, p15card, key_file, SC_AC_OP_GENERATE);
	LOG_TEST_RET(ctx, rv, "Cannot generate key: 'GENERATE' authentication failed");

	if (key_info->modulus_length == 1024)
		piv_algo = LASER_PIV_ALGO_RSA_1024;
	else if (key_info->modulus_length == 2048)
                piv_algo = LASER_PIV_ALGO_RSA_2048;

	memset(&args, 0, sizeof(args));

	args.algorithm = piv_algo;

	args.modulus = malloc(key_info->modulus_length / 8);
	args.exponent = malloc(sizeof(default_exponent));
	if (!args.exponent || !args.modulus)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "laser_generate_key() cannot allocate exponent or/and modulus buffers");
	args.modulus_len = key_info->modulus_length / 8;
	args.exponent_len = sizeof(default_exponent);
	memcpy(args.exponent, default_exponent,  sizeof(default_exponent));

	rv = sc_card_ctl(card, SC_CARDCTL_ATHENA_GENERATE_KEY, &args);
	LOG_TEST_RET(ctx, rv, "laser_generate_key() SC_CARDCTL_ATHENA_GENERATE_KEY failed");

	sc_log(ctx, "modulus %s", sc_dump_hex(args.modulus, args.modulus_len));
	sc_log(ctx, "exponent %s", sc_dump_hex(args.exponent, args.exponent_len));

	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_SENSITIVE;
	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE;
	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_LOCAL;

	/* allocated buffers with the public key components do not released
	 * but re-assigned to the pkcs15-public-key data */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = args.modulus_len;
	pubkey->u.rsa.modulus.data  = args.modulus;

	pubkey->u.rsa.exponent.len  = args.exponent_len;
	pubkey->u.rsa.exponent.data = args.exponent;

	sc_file_free(key_file);

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Store a private key
 */
static int
laser_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *prkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	struct sc_cardctl_laser_updatekey args;
	int rv;

	LOG_FUNC_CALLED(ctx);

        sc_log(ctx, "store key ID %s, path %s", sc_pkcs15_print_id(&key_info->id), sc_print_path(&key_info->path));
        sc_log(ctx, "store key %i %i %i %i %i %i", prkey->u.rsa.d.len, prkey->u.rsa.p.len,
			prkey->u.rsa.q.len, prkey->u.rsa.iqmp.len,
			prkey->u.rsa.dmp1.len, prkey->u.rsa.dmq1.len);

	rv = sc_select_file(p15card->card, &key_info->path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot store key: select key file failed");

	rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, rv, "No authorisation to store private key");

	rv = laser_encode_update_key(ctx, prkey, &args);
	LOG_TEST_RET(ctx, rv, "Cannot encode key update data");

	sc_log(ctx, "Update data %s", sc_dump_hex(args.data, args.len));

	rv = sc_card_ctl(p15card->card, SC_CARDCTL_ATHENA_UPDATE_KEY, &args);
	LOG_TEST_RET(ctx, rv, "laser_generate_key() SC_CARDCTL_ATHENA_GENERATE_KEY failed");

	free(args.data);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_update_dir (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_app_info *info)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_update_df_create_private_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0, attrs_num = 0, attrs_ref;
	int rv;

	LOG_FUNC_CALLED(ctx);

	attrs_ref = (info->key_reference & LASER_FS_REF_MASK) - 1;
	rv = laser_validate_attr_reference(attrs_ref);
	LOG_TEST_RET(ctx, rv, "Invalid attribute file reference");

	sc_log(ctx, "Private key attributes file reference 0x%X", attrs_ref);
	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_PRKEY_RSA, attrs_ref, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate private key attributes file");

	rv =  laser_attrs_prvkey_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode private key attributes");
	sc_log(ctx, "Attributes(%i) '%s'",attrs_num, sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to create/update private key attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_create_public_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0, attrs_num = 0, attrs_ref;
	int rv;

	LOG_FUNC_CALLED(ctx);

	attrs_ref = (info->key_reference & LASER_FS_REF_MASK) - 1;
	rv = laser_validate_attr_reference(attrs_ref);
	LOG_TEST_RET(ctx, rv, "Invalid attribute file reference");

	sc_log(ctx, "Public key attributes file reference 0x%X", attrs_ref);
	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_PUBKEY_RSA, attrs_ref, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate public key attributes file");

	rv = laser_attrs_pubkey_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode public key attributes");
	sc_log(ctx, "Attributes(%i) '%s'",attrs_num, sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to create/update public key attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_need_update(struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, int *need_update)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	struct sc_path *path = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0;
	int rv;
	unsigned char sha1[SHA_DIGEST_LENGTH];

	LOG_FUNC_CALLED(ctx);

	if (!need_update)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	*need_update = 1;

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_CERT:
		path = &((struct sc_pkcs15_cert_info *)object->data)->path;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		path = &((struct sc_pkcs15_data_info *)object->data)->path;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	sc_log(ctx, "check laser attribute file's 'update' status; path %s", sc_print_path(path));

	rv = sc_select_file(p15card->card, path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select laser attributes file");

	rv = sc_read_binary(p15card->card, 0x0C, sha1, SHA_DIGEST_LENGTH, 0);
	LOG_TEST_RET(ctx, rv, "Cannot read current checksum");
	if (rv != SHA_DIGEST_LENGTH)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Invalid size of current checksum");

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_CERT:
		rv = laser_attrs_cert_encode(p15card, object, file->id, &attrs, &attrs_len);
		LOG_TEST_RET(ctx, rv, "Failed to encode laser certificate attributes");
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = laser_attrs_data_object_encode(p15card, object, file->id, &attrs, &attrs_len);
		LOG_TEST_RET(ctx, rv, "Failed to encode laser DATA attributes");
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	*need_update = memcmp(sha1, attrs + 0x0C, SHA_DIGEST_LENGTH) ? 1 : 0;

	if (file)
		sc_file_free(file);
	sc_log(ctx, "returns 'need-update' status %s", *need_update ? "yes" : "no");
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_create_certificate(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0;
	int rv, need_update;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "create certificate attribute file %s", sc_print_path(&info->path));

	rv = laser_need_update(p15card, object, &need_update);
	LOG_TEST_RET(ctx, rv, "Failed to get 'need-update' status of certificate data");

	if (!need_update)   {
		sc_log(ctx, "No need to update Laser CDF");
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	rv = sc_select_file(p15card->card, &info->path, &file);
	LOG_TEST_RET(ctx, rv, "Failed to update DF: cannot select laser certificate file");

	rv = laser_attrs_cert_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode laser certificate attributes");
	sc_log(ctx, "update laser certificate attributes '%s'", sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	/* TODO: implement Laser's 'resize' file */
	rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	LOG_TEST_RET(ctx, rv, "Failed to update DF: cannot delete laser certificate");

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to update laser certificate attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_create_data_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0;
	int rv, need_update;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "create update DF for DATA file %s", sc_print_path(&info->path));

	rv = laser_need_update(p15card, object, &need_update);
	LOG_TEST_RET(ctx, rv, "Failed to get 'need-update' status of DATA object");

	if (!need_update)   {
		sc_log(ctx, "No need to update Laser DataDF");
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	rv = sc_select_file(p15card->card, &info->path, &file);
	LOG_TEST_RET(ctx, rv, "Failed to update DF: cannot select laser DATA file");

	rv = laser_attrs_data_object_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode laser DATA attributes");
	sc_log(ctx, "update laser DATA attributes '%s'", sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	/* TODO: implement Laser's 'resize' file */
	rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	LOG_TEST_RET(ctx, rv, "Failed to update DF: cannot delete laser DATA");

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to update laser DATA attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_update_df_create(struct sc_profile *profile, struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

	switch (object->type)   {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		rv = laser_update_df_create_private_key(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		rv = laser_update_df_create_public_key(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		rv = laser_update_df_create_certificate(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = laser_update_df_create_data_object(profile, p15card, object);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_delete_private_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	size_t attrs_ref;
	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	attrs_ref = (info->key_reference & LASER_FS_REF_MASK) - 1;
	rv = laser_validate_attr_reference(attrs_ref);
	LOG_TEST_RET(ctx, rv, "Invalid attribute file reference");

	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_PRKEY_RSA, attrs_ref, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate private key attributes file");

	rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	LOG_TEST_RET(ctx, rv, "Failed to delete private key attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_delete_public_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_file *file = NULL;
	size_t attrs_ref;
	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	attrs_ref = (info->key_reference & LASER_FS_REF_MASK) - 1;
	rv = laser_validate_attr_reference(attrs_ref);
	LOG_TEST_RET(ctx, rv, "Invalid attribute file reference");

	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_PUBKEY_RSA, attrs_ref, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate public key attributes file");

	rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	LOG_TEST_RET(ctx, rv, "Failed to delete private key attributes file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_df_delete_certificate(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)object->data;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15init_delete_by_path(profile, p15card, &info->path);
	if (rv != SC_ERROR_FILE_NOT_FOUND)
		LOG_TEST_RET(ctx, rv, "Failed to delete certificate attributes file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_update_df_delete_data_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *)object->data;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15init_delete_by_path(profile, p15card, &info->path);
	if (rv != SC_ERROR_FILE_NOT_FOUND)
		LOG_TEST_RET(ctx, rv, "Failed to delete data object attributes file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_emu_update_df_delete(struct sc_profile *profile, struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	switch (object->type)   {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		rv = laser_update_df_delete_private_key(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		rv = laser_update_df_delete_public_key(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		rv = laser_update_df_delete_certificate(profile, p15card, object);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = laser_update_df_delete_data_object(profile, p15card, object);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_update_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	switch(op)   {
	case SC_AC_OP_ERASE:
		sc_log(ctx, "Update DF; erase object('%s',type:%X)", object->label, object->type);
		rv = laser_emu_update_df_delete(profile, p15card, object);
		break;
	case SC_AC_OP_CREATE:
		sc_log(ctx, "Update DF; create object('%s',type:%X)", object->label, object->type);
		rv = laser_emu_update_df_create(profile, p15card, object);
		break;
	}
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_update_tokeninfo(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_tokeninfo *tinfo)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_write_info(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *pin_obj)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_store_pubkey(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	struct sc_pkcs15_pubkey pubkey;
	struct sc_file *file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Public Key id '%s'", sc_pkcs15_print_id(&info->id));
	if (data)
		sc_log(ctx, "data(%i) %p", data->len, data->value);
	if (object->content.value)
		sc_log(ctx, "content(%i) %p", object->content.len, object->content.value);

	pubkey.algorithm = SC_ALGORITHM_RSA;
	rv = sc_pkcs15_decode_pubkey(ctx, &pubkey, object->content.value, object->content.len);
	LOG_TEST_RET(ctx, rv, "Decode public key error");

	sc_log(ctx, "Modulus '%s'",sc_dump_hex(pubkey.u.rsa.modulus.data, pubkey.u.rsa.modulus.len));
	sc_log(ctx, "Exponent '%s'",sc_dump_hex(pubkey.u.rsa.exponent.data, pubkey.u.rsa.exponent.len));

	rv = sc_pkcs15_find_prkey_by_id(p15card, &info->id, &prkey_object);
	LOG_TEST_RET(ctx, rv, "Find related PrKey error");

	prkey_info = (struct sc_pkcs15_prkey_info *)prkey_object->data;

        info->key_reference = (prkey_info->key_reference & LASER_FS_REF_MASK) | LASER_FS_BASEFID_PUBKEY;
	info->modulus_length = prkey_info->modulus_length;
	info->native = prkey_info->native;
	sc_log(ctx, "Public Key ref %X, length %i", info->key_reference, info->modulus_length);

	rv = laser_new_file(profile, p15card->card, SC_PKCS15_TYPE_PUBKEY_RSA, info->key_reference, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate new laser public-key file");

	file->size = info->modulus_length / 8;
	if (info->path.len)
		file->path = info->path;

	file->prop_attr = calloc(1, 5);
	if (!file->prop_attr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->prop_attr_len = 5;

	*(file->prop_attr + 0) = LASER_KO_CLASS_RSA_CRT;

	if (info->usage & (SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP))
		*(file->prop_attr + 1) |= LASER_KO_USAGE_ENCRYPT;
	if (info->usage & SC_PKCS15_PRKEY_USAGE_VERIFY)
		*(file->prop_attr + 1) |= LASER_KO_USAGE_VERIFY;

	*(file->prop_attr + 2) = LASER_KO_ALGORITHM_RSA;
	*(file->prop_attr + 3) = LASER_KO_PADDING_NO;
	*(file->prop_attr + 4) = 0xA3;	/* Max retry counter 10, 3 tries to unlock. TODO what's this ????? */

	sc_log(ctx, "Create public key file: path %s, propr.info %s",
			sc_print_path(&file->path), sc_dump_hex(file->prop_attr, file->prop_attr_len));

	rv = sc_select_file(p15card->card, &file->path, NULL);
	if (rv == 0)   {
		rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE_SELF);
		LOG_TEST_RET(ctx, rv, "Cannot authenticate SC_AC_OP_DELETE_SELF");

		rv = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
		LOG_TEST_RET(ctx, rv, "Failed to delete public key file");
	}
	else if (rv != SC_ERROR_FILE_NOT_FOUND)    {
		LOG_TEST_RET(ctx, rv, "Select public key file error");
	}

	rv = laser_encode_pubkey(ctx, &pubkey, &file->encoded_content, &file->encoded_content_len);
	LOG_TEST_RET(ctx, rv, "public key encoding error");

	sc_log(ctx, "Encoded: '%s'",sc_dump_hex(file->encoded_content, file->encoded_content_len));

	rv = sc_pkcs15init_create_file(profile, p15card, file);
	LOG_TEST_RET(ctx, rv, "Failed to create public key file");

	info->key_reference = file->path.value[file->path.len - 1];
	info->path = file->path;
	sc_log(ctx, "created public key file %s, ref:%X", sc_print_path(&info->path), info->key_reference);

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_store_certificate(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0;
	int rv, idx;

	LOG_FUNC_CALLED(ctx);

	idx = laser_get_free_index(p15card, SC_PKCS15_TYPE_CERT_X509);
	LOG_TEST_RET(ctx, idx, "Cannot get free certificate index");

	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_CERT_X509, idx, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate laser certificate attributes file");

	sc_log(ctx, "create certificate attribute file %s", sc_print_path(&file->path));

	rv = laser_attrs_cert_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode laser certificate attributes");
	sc_log(ctx, "laser certificate attributes '%s'", sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to create/update laser certificate attributes file");

	info->path = file->path;

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_store_data_object(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *)object->data;
	struct sc_file *file = NULL;
	unsigned char *attrs = NULL;
	size_t attrs_len = 0;
	int rv, idx;

	LOG_FUNC_CALLED(ctx);

	idx = laser_get_free_index(p15card, SC_PKCS15_TYPE_DATA_OBJECT);
	LOG_TEST_RET(ctx, idx, "Cannot get free DATA object index");

	rv = laser_new_file(profile, p15card->card, LASER_ATTRS_DATA_OBJECT, idx, &file);
	LOG_TEST_RET(ctx, rv, "Cannot instantiate laser DATA object attributes file");

	sc_log(ctx, "create DATA object attribute file %s", sc_print_path(&file->path));

	rv = laser_attrs_data_object_encode(p15card, object, file->id, &attrs, &attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to encode laser DATA object attributes");
	sc_log(ctx, "laser DATA object attributes '%s'", sc_dump_hex(attrs, attrs_len));

	file->size = attrs_len;

	rv = sc_pkcs15init_update_file(profile, p15card, file, attrs, attrs_len);
	LOG_TEST_RET(ctx, rv, "Failed to create/update laser DATA object attributes file");

	info->path = file->path;

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		rv = SC_ERROR_NOT_IMPLEMENTED;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		rv = laser_emu_store_pubkey(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_CERT:
		rv = laser_emu_store_certificate(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = laser_emu_store_data_object(p15card, profile, object, data, path);
		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static struct sc_pkcs15init_operations
sc_pkcs15init_laser_operations = {
	laser_erase_card,
	NULL,				/* init_card  */
	laser_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	NULL,				/* select_pin_reference */
	NULL,				/* create_pin*/
	laser_select_key_reference,	/* select_key_reference */
	laser_create_key_file,		/* create_key */
	laser_store_key,		/* store_key */
	laser_generate_key,		/* generate_key */
	NULL,
	NULL,				/* encode private/public key */
	NULL,				/* finalize_card */
	NULL,				/* delete_object */
#ifdef ENABLE_OPENSSL
	laser_emu_update_dir,
	laser_emu_update_df,
	laser_emu_update_tokeninfo,
	laser_emu_write_info,
	laser_emu_store_data,
	NULL				/* sanity_check */
#else
	NULL, NULL, NULL, NULL, NULL,
	NULL
#endif
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_laser_ops(void)
{
	return &sc_pkcs15init_laser_operations;
}
