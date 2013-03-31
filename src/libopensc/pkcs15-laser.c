/*
 * pkcs15-laser.c: pkcs15 emulation for Athena LASER card
 *
 * Copyright (C) 2012 Athena
 *		viktor.tarasov@gmail.com
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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "pkcs11/pkcs11.h"
#include "common/compat_strlcpy.h"
#include "laser.h"

#define PATH_APPLICATION	"3F003000"
#define PATH_TOKENINFO		"3F003000C000"
#define PATH_PUBLICDIR		"3F0030003001"
#define PATH_PRIVATEDIR		"3F0030003002"
#define PATH_USERPIN		"3F000020"
#define PATH_SOPIN		"3F000010"

#define AUTH_ID_PIN	0x20
#define AUTH_ID_SOPIN	0x10

#define LASER_BASEKX_MASK		0x7F00
#define LASER_TYPE_KX_CERT		0x11
#define LASER_TYPE_KX_PRVKEY		0x12
#define LASER_TYPE_KX_PUBKEY		0x13
#define LASER_TYPE_KX_SKEY		0x14
#define LASER_TYPE_KX_DATA		0x15
#define LASER_TYPE_CERT			0x20
#define LASER_TYPE_PRVKEY		0x30
#define LASER_TYPE_PUBKEY		0x40
#define LASER_TYPE_SKEY			0x50
#define LASER_TYPE_DATA			0x60

struct laser_ko_props {
	unsigned char class;
	unsigned char usage;
	unsigned char algorithm;
	unsigned char padding;
	struct   {
		unsigned char retry_byte;
		unsigned char unlock_byte;
	} auth_attrs;
	struct   {
		unsigned char min_length;
		unsigned char max_length;
		unsigned char upper_case;
		unsigned char lower_case;
		unsigned char digits;
		unsigned char alphas;
		unsigned char specials;
		unsigned char occurrence;
		unsigned char sequence;
	} pin_policy;
};

struct laser_cka {
	unsigned cka;
	unsigned char internal_cka;

	unsigned char *val;
	size_t len;
};

int sc_pkcs15emu_laser_init_ex(struct sc_pkcs15_card *, struct sc_pkcs15emu_opt *);


static int
_laser_type(int id)
{
	if ((id & 0xFF00) == 0x0)   {
		if ((id & LASER_FS_REF_MASK) == LASER_FS_BASEFID_PUBKEY)
			return LASER_TYPE_PUBKEY;
		else
			return LASER_TYPE_PRVKEY;
	}

	switch (id & LASER_BASEKX_MASK)   {
	case 0x0100 :
		return LASER_TYPE_KX_PUBKEY;
	case 0x0200 :
		return LASER_TYPE_KX_PRVKEY;
	case 0x0300 :
		return LASER_TYPE_KX_SKEY;
	case 0x0400 :
	case 0x0500 :
		return LASER_TYPE_KX_CERT;
	case 0x0600 :
		return LASER_TYPE_KX_DATA;
	}

	return -1;
}


static int
_alloc_ck_string(unsigned char *data, size_t max_len, char **out)
{
	char *str = calloc(1, max_len + 1);

	if (!out)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!str)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(str, data, max_len);
	while(*(str + strlen(str) - 1) == ' ')
		*(str + strlen(str) - 1)  = '\0';

	if (*out != NULL)
		free(*out);

	*out = strdup(str);

	free(str);
	return SC_SUCCESS;
}


static int
_create_application(struct sc_pkcs15_card * p15card,
		char *label, char *aid_str, char *path_str)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_app_info *app = NULL;
	struct sc_file *app_file = NULL;
	struct sc_path app_path;
	int rv;

	LOG_FUNC_CALLED(ctx);

	app = calloc(1, sizeof(struct sc_app_info));
	if (!app)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	app->label = strdup(label);
	if (!app->label)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	sc_format_path(path_str, &app->path);

	app->aid.len = sizeof(app->aid.value);
	sc_hex_to_bin(aid_str, app->aid.value, &app->aid.len);

	card->app[card->app_count] = app;
	card->app_count++;

	if (p15card->file_app)
		free(p15card->file_app);
	sc_format_path(PATH_APPLICATION, &app_path);
	rv = sc_select_file(card, &app_path, &app_file);
	LOG_TEST_RET(ctx, rv, "Cannot application path");

	p15card->file_app = app_file;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
_create_pin(struct sc_pkcs15_card * p15card, char *label,
		char *pin_path, unsigned char auth_id, unsigned flags)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object pin_obj;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_path path;
	struct sc_file *file = NULL;
	struct laser_ko_props *props = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&auth_info, 0, sizeof(auth_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	sc_format_path(pin_path, &path);
	rv = sc_select_file(p15card->card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select USER PIN");

	if (!file->prop_attr_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "No PIN attributs in FCP");
	sc_log(ctx, "FCP User PIN attributes '%s'", sc_dump_hex(file->prop_attr, file->prop_attr_len));

	props = (struct laser_ko_props *)file->prop_attr;

	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.auth_method   = SC_AC_CHV;
	auth_info.auth_id.value[0] = auth_id;
	auth_info.auth_id.len = 1;
	auth_info.attrs.pin.reference = path.value[path.len - 1];

	auth_info.attrs.pin.flags = flags;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_INITIALIZED;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA;
	auth_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_CASE_SENSITIVE;

	/* Not imposed by card */
	auth_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;

	auth_info.attrs.pin.min_length = props->pin_policy.min_length;
	auth_info.attrs.pin.max_length = props->pin_policy.max_length;
	auth_info.attrs.pin.stored_length = props->pin_policy.max_length;
	auth_info.attrs.pin.pad_char = 0xff;
	auth_info.tries_left = (props->auth_attrs.retry_byte >> 4) & 0x0F;

	strlcpy(pin_obj.label, label, sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
	rv = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &auth_info);
	LOG_TEST_RET(ctx, rv, "Failed to create PIN PKCS#15 object");
	sc_file_free(file);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
_create_certificate(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_cert_info info;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	unsigned char sha1[SHA_DIGEST_LENGTH], sha1_attr[SHA_DIGEST_LENGTH];
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));

	sc_format_path(PATH_PUBLICDIR, &info.path);
	sc_append_path_id(&info.path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &info.path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 11)	/* header 7 bytes, tail 4 bytes */
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "certificate attributes file is too short");

	rv = laser_attrs_cert_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_RET(ctx, rv, "Decode certificate attributes error.");

	rv = sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add certificate object");

	memcpy(sha1_attr, data+12, SHA_DIGEST_LENGTH);
	memset(data + 12,0,SHA_DIGEST_LENGTH);
	SHA1(data, len, sha1);

	if (memcmp(sha1, sha1_attr, SHA_DIGEST_LENGTH))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid checksum of certificate attributes");

	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_create_pubkey(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_pubkey_info info;
	struct sc_pkcs15_pubkey_rsa key_rsa;
	struct sc_file *key_file = NULL;
	unsigned ko_fid = ((file_id & LASER_FS_REF_MASK) | LASER_FS_BASEFID_PUBKEY) + 1;
	struct sc_path path;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PUBLICDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 11)	/* header 7 bytes, tail 4 bytes */
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid length of public key attributes data");

	/* set info path to public key KO */
	path.value[path.len - 2] = (ko_fid >> 8) & 0xFF;
	path.value[path.len - 1] = ko_fid & 0xFF;
	info.path = path;
	info.key_reference = ko_fid & 0xFF;

	rv = sc_select_file(p15card->card, &info.path, &key_file);
	LOG_TEST_RET(ctx, rv, "Cannot select key file");

	info.modulus_length = key_file->size * 8;
	sc_file_free(key_file);

	info.native = 1;

	/* ignore header and tail */
	rv = laser_attrs_pubkey_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_RET(ctx, rv, "Decode public key attributes error.");

	if (!info.id.len)   {
		free(data);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "Missing public key ID");
	}

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add public key object");

	sc_log(ctx, "Key path %s", sc_print_path(&info.path));
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_create_prvkey(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj, *pobj = NULL;
	struct sc_pkcs15_prkey_info info, *pinfo = NULL;
	struct sc_pkcs15_prkey_rsa key_rsa;
	struct sc_file *key_file = NULL;
	unsigned ko_fid = ((file_id & LASER_FS_REF_MASK) | LASER_FS_BASEFID_PRVKEY) + 1;
	struct sc_path path;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "create PKCS#15 private key object. FID:%X, KID:%X", file_id, ko_fid);
	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PRIVATEDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 11)	 /* header 7 bytes, tail 4 bytes */
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "private key attributes file is too short");

	/* set info path to private key KO */
	path.value[path.len - 2] = ko_fid / 0x100;
	path.value[path.len - 1] = ko_fid % 0x100;
	info.path = path;
	info.key_reference = ko_fid % 0x100;

	rv = sc_select_file(p15card->card, &info.path, &key_file);
	LOG_TEST_RET(ctx, rv, "Cannot select key file");

	info.modulus_length = key_file->size * 8;
	sc_file_free(key_file);

	info.native = 1;

	 /* ignore header 7 bytes and tail 4 bytes */
	rv = laser_attrs_prvkey_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_RET(ctx, rv, "Decode private key attributes error.");

	if (!info.id.len)   {
		free(data);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "Missing private key ID");
	}

	obj.auth_id.len = 1;
	obj.auth_id.value[0] = AUTH_ID_PIN;

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add private key object");

	rv = sc_pkcs15_find_prkey_by_id(p15card, &info.id, &pobj);
	LOG_TEST_RET(ctx, rv, "Cannot get new key object");

	pinfo = (struct sc_pkcs15_prkey_info *)pobj->data;

	/* If ID is in Athena style, use it as object's GUID */
	if (pinfo->id.len > SHA_DIGEST_LENGTH)   {
		char *id = (char *)(&(pinfo->id.value[0]));

		if (pinfo->cmap_record.guid)
			free(pinfo->cmap_record.guid);

		/* "c55e834a-ecc8-46b8-a726-ddae4b2c4811" */
		if (*(id+8) == '-' && *(id+13) == '-' && *(id+18) == '-' && *(id+23) == '-')   {
			pinfo->cmap_record.guid = (char *)calloc(sizeof(char), pinfo->id.len + 1);
			if (!pinfo->cmap_record.guid)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			memcpy(pinfo->cmap_record.guid, pinfo->id.value, pinfo->id.len);
		}
	}

	if (!pinfo->cmap_record.guid)   {
		char guid[40];

		rv = sc_pkcs15_get_guid(p15card, pobj, 1, guid, sizeof(guid));
		LOG_TEST_RET(ctx, rv, "Cannot get private key GUID");

		pinfo->cmap_record.guid = strdup(guid);
		if (!pinfo->cmap_record.guid)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	}

	sc_log(ctx, "Key path %s; GUID %s", sc_print_path(&pinfo->path), pinfo->cmap_record.guid);
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_create_data_object(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_data_info info;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len;
	unsigned char sha1[SHA_DIGEST_LENGTH], sha1_attr[SHA_DIGEST_LENGTH];
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));

	sc_format_path(PATH_PUBLICDIR, &info.path);
	sc_append_path_id(&info.path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &info.path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 11)	/* header 7 bytes, tail 4 bytes */
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "data object file is too short");

	rv = laser_attrs_data_object_decode(ctx, &obj, &info, data + 7, len - 11);
	LOG_TEST_RET(ctx, rv, "Decode data object error.");

	rv = sc_pkcs15emu_add_data_object(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add data object");

	memcpy(sha1_attr, data+12, SHA_DIGEST_LENGTH);
	memset(data + 12,0,SHA_DIGEST_LENGTH);
	SHA1(data, len, sha1);

	if (memcmp(sha1, sha1_attr, SHA_DIGEST_LENGTH))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid checksum of DATA attributes");

	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_parse_fs_data(struct sc_pkcs15_card * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t ii, count;
	char *df_paths[3] = {PATH_PUBLICDIR, PATH_PRIVATEDIR, NULL};
	int rv, df;
	struct sc_pkcs15_object *pubkeys[12], *dobjs[12];
	size_t pubkeys_num, dobjs_num;

	LOG_FUNC_CALLED(ctx);

	for (df=0; df_paths[df]; df++)   {
		struct sc_path path;

		sc_format_path(df_paths[df], &path);
		rv = sc_select_file(card, &path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select object's DF");

		rv = sc_list_files(card, buf, sizeof(buf));
		LOG_TEST_RET(ctx, rv, "'List file' error in object's DF");

		count = rv/2;
		/* TODO:
		 * Laser's EF may have the 'DF name' attribute.
		 * Normally here this attribute has to be used to identify
		 * the kxc and kxs files.
		 * But, for a while, for the sake of simplicity,
		 * the FID/mask (0x0400/0xFFF0) is used instead.
		 */
		for (ii=0; ii<count; ii++)   {
			unsigned fid, type;

			fid = *(buf + ii*2) * 0x100 + *(buf + ii*2 + 1);
			type = _laser_type(fid);
			sc_log(ctx, "parse FID:%04X, type:0x%04X", fid, type);
			switch (type)   {
			case LASER_TYPE_KX_PRVKEY:
				sc_log(ctx, "parse private key attributes FID:%04X", fid);
				rv = _create_prvkey(p15card, fid);
				if (rv != SC_ERROR_NOT_IMPLEMENTED)	/* ignore keys without ID */
					LOG_TEST_RET(ctx, rv, "Cannot create private key PKCS#15 object");
				break;
			case LASER_TYPE_KX_CERT:
				sc_log(ctx, "parse certificate attributes FID:%04X", fid);
				rv = _create_certificate(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create certificate PKCS#15 object");
				break;
			case LASER_TYPE_KX_PUBKEY:
				sc_log(ctx, "parse public key attributes FID:%04X", fid);
				rv = _create_pubkey(p15card, fid);
				if (rv != SC_ERROR_NOT_IMPLEMENTED)	/* ignore keys without ID */
					LOG_TEST_RET(ctx, rv, "Cannot create public key PKCS#15 object");
				break;
			case LASER_TYPE_KX_DATA:
				sc_log(ctx, "parse data object attributes FID:%04X", fid);
				rv = _create_data_object(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create data PKCS#15 object");
				break;
			default:
				break;
			}
		}
	}

	pubkeys_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY, pubkeys, 12);
	sc_log(ctx, "Number of public keys %i", pubkeys_num);
	for (ii = 0; ii < pubkeys_num; ii++)   {
		struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)pubkeys[ii]->data;
		struct sc_pkcs15_object *prkey_obj = NULL;

		if (!sc_pkcs15_find_prkey_by_id(p15card, &info->id, &prkey_obj))
			if (strlen(prkey_obj->label) && !strlen(pubkeys[ii]->label))
				memcpy(pubkeys[ii]->label, prkey_obj->label, sizeof(pubkeys[ii]->label));
	}

	dobjs_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, dobjs, 12);
	for (ii = 0; ii < dobjs_num; ii++)   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;
		struct sc_pkcs15_data *data = NULL;
		struct laser_cmap_record *rec = NULL;
		struct sc_pkcs15_object *prkeys[12];
		size_t prkeys_num;
		size_t offs = 0;

		if (strcmp(dobjs[ii]->label, "cmapfile") || strcmp(dinfo->app_label, CMAP_DO_APPLICATION_NAME))
			continue;

		prkeys_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, prkeys, 12);
		LOG_TEST_RET(ctx, prkeys_num, "Failed to get private key objects");
		if (prkeys_num ==  0)
			break;

		rv = sc_pkcs15_read_data_object(p15card, dinfo, &data);
		LOG_TEST_RET(ctx, rv, "Cannot create data PKCS#15 object");

		sc_log(ctx, "Use '%s' DATA object to update private key MD data", dobjs[ii]->label);
		for (offs = 0; offs < data->data_len;)   {
			char *guid_str = NULL;

			rv = laser_md_cmap_record_decode(ctx, data, &offs, &rec);
			LOG_TEST_RET(ctx, rv, "Failed to decode CMAP entry");
			if (!rec)
				break;
			if (rec->keysize_sign || rec->keysize_keyexchange)   {
				rv = laser_md_cmap_record_guid(ctx, rec, &guid_str);
				LOG_TEST_RET(ctx, rv, "Cannot get GUID string");

				sc_log(ctx, "CMAP record GUID %s", guid_str);
				for (ii=0; ii<prkeys_num; ii++)   {
					struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)prkeys[ii]->data;

					sc_log(ctx, "Key GUID %s", info->cmap_record.guid);
					if (strcmp(info->cmap_record.guid, guid_str))
						continue;

					info->cmap_record.flags = rec->flags;
					info->cmap_record.keysize_sign = rec->keysize_sign;
					info->cmap_record.keysize_keyexchange = rec->keysize_keyexchange;
					sc_log(ctx, "Updated MD container data: flags:0x%X, sign-size %i, keyexchange-size %i",
							info->cmap_record.flags, info->cmap_record.keysize_sign,
							info->cmap_record.keysize_keyexchange);
				}
			}

			free(guid_str);
			free(rec);
		}

		sc_pkcs15_free_data_object(data);
		break;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_laser_init(struct sc_pkcs15_card * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path path;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	int rv;
	CK_TOKEN_INFO *ck_ti = NULL;

	LOG_FUNC_CALLED(ctx);

	sc_format_path(PATH_TOKENINFO, &path);
	rv = sc_pkcs15_read_file(p15card, &path, &buf, &buflen);
	LOG_TEST_RET(ctx, rv, "Cannot select&read TOKEN-INFO file");

	if (buflen < sizeof(CK_TOKEN_INFO))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid TOKEN-INFO data");

	ck_ti = (CK_TOKEN_INFO *) buf;

	rv = _alloc_ck_string(ck_ti->label, sizeof(ck_ti->label), &p15card->tokeninfo->label);
	LOG_TEST_RET(ctx, rv, "Cannot allocate token label");

	rv = _alloc_ck_string(ck_ti->manufacturerID, sizeof(ck_ti->manufacturerID), &p15card->tokeninfo->manufacturer_id);
	LOG_TEST_RET(ctx, rv, "Cannot allocate manufacturerID");

	rv = _alloc_ck_string(ck_ti->serialNumber, sizeof(ck_ti->serialNumber), &p15card->tokeninfo->serial_number);
	LOG_TEST_RET(ctx, rv, "Cannot allocate serialNumber");

	p15card->tokeninfo->version = 0;
	p15card->tokeninfo->flags = ck_ti->flags;

#if 0
	rv = _create_application(p15card, "Athena LASER", "A0000001644C415345520001", "3F00");
	LOG_TEST_RET(ctx, rv, "Cannot create application");
#endif

	rv = _create_pin(p15card, "User PIN", PATH_USERPIN, AUTH_ID_PIN, 0);
	LOG_TEST_RET(ctx, rv, "Cannot create 'User PIN' object");

	rv = _create_pin(p15card, "SO PIN", PATH_SOPIN, AUTH_ID_SOPIN, SC_PKCS15_PIN_FLAG_SO_PIN);
	LOG_TEST_RET(ctx, rv, "Cannot create 'SO PIN' object");

	rv = _parse_fs_data(p15card);
	LOG_TEST_RET(ctx, rv, "Error while creating 'certificate' objects");

	free(buf);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_detect_card(sc_pkcs15_card_t * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;

	sc_log(ctx, "laser_detect_card (%s)", card->name);
	if (card->type != SC_CARD_TYPE_ATHENA_LASER)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}


int
sc_pkcs15emu_laser_init_ex(struct sc_pkcs15_card *p15card, struct sc_pkcs15emu_opt *opts)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_laser_init(p15card);

	rv = laser_detect_card(p15card);
	LOG_TEST_RET(ctx, rv, "It's not Athena LASER card");

	rv = sc_pkcs15emu_laser_init(p15card);
	LOG_FUNC_RETURN(ctx, rv);
}
