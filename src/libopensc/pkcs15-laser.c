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

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "pkcs11/pkcs11.h"
#include "common/compat_strlcpy.h"

#define PATH_TOKENINFO	"3F003000C000"
#define PATH_PUBLICDIR	"3F0030003001"
#define PATH_PRIVATEDIR	"3F0030003002"
#define PATH_USERPIN	"3F000020"
#define PATH_SOPIN	"3F000010"

#define AUTH_ID_PIN	0x20
#define AUTH_ID_SOPIN	0x10

#define LASER_BASEFID_MASK		0xFFF0
#define LASER_BASEFID_KXS		0x0200
#define LASER_BASEFID_KXC		0x0400
#define LASER_BASEFID_KXC_PUBKEY	0x0140
#define LASER_BASEFID_PUBKEY		0x0080
#define LASER_BASEFID_PRVKEY		0x0040

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
_alloc_ck_string(unsigned char *data, size_t max_len, char ** out)
{
	char *str = calloc(1, max_len + 1);

	if (!str)
		return SC_ERROR_MEMORY_FAILURE;
	if (!out)
		return SC_ERROR_INVALID_ARGUMENTS;

	memcpy(str, data, max_len);
	while(*(str + strlen(str) - 1) == ' ')
		*(str + strlen(str) - 1)  = '\0';

	if (*out != NULL)
		free(*out);
	*out = strdup(str);

	return SC_SUCCESS;
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


static size_t
_get_attr(unsigned char *data, size_t length, size_t *in_offs, struct laser_cka *attr)
{
	size_t offs;

	if (!attr || !data || !in_offs)
		return 0;

	/*
	 * At the end of kxc/s files there are misterious 4 bytes (like 'OD OO OD OO').
	 * TODO: Get know what for they are.
	 */
	for (offs = *in_offs; (*(data + offs) == 0xFF) && (offs < length - 4); offs++)
		;
	if (offs >= length - 4)
		return 0;

	attr->cka = *(data + offs + 0) * 0x100 + *(data + offs + 1);
	attr->internal_cka = *(data + offs + 2);
	attr->len = *(data + offs + 3) * 0x100 + *(data + offs + 4);
	attr->val = data + offs + 5;

	*in_offs = offs + 5 + attr->len;
	return 0;
}


static int
_cka_get_unsigned(struct laser_cka *attr, unsigned *out)
{
	int ii;

	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (attr->len != 4)
		return SC_ERROR_INVALID_DATA;

	for (ii=0, *out = 0; ii < 4; ii++)
		*out = *out * 0x100 + *(attr->val + 3 - ii);

	return SC_SUCCESS;
}


static int
_cka_set_label(struct laser_cka *attr, struct sc_pkcs15_object *obj)
{
	size_t len;

	if (!attr || !obj)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(obj->label, 0, sizeof(obj->label));
	len = (attr->len < sizeof(obj->label) - 1) ? attr->len : sizeof(obj->label) - 1;
	if (len)
		memcpy(obj->label, attr->val, len);

	return SC_SUCCESS;
}


static int
_cka_get_blob(struct laser_cka *attr, struct sc_pkcs15_der *out)
{
	struct sc_pkcs15_der der;

	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	der.value = malloc(attr->len);
	if (!der.value)
		return SC_ERROR_MEMORY_FAILURE;
	memcpy(der.value, attr->val, attr->len);
	der.len = attr->len;

	*out = der;
	return SC_SUCCESS;
}


static int
_cka_set_id(struct laser_cka *attr, struct sc_pkcs15_id *out)
{
	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (attr->len > SC_PKCS15_MAX_ID_SIZE)
		return SC_ERROR_INVALID_DATA;

	memcpy(out->value, attr->val, attr->len);
	out->len = attr->len;

	return SC_SUCCESS;
}


static int
_create_certificate(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_cert_info info;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len, offs, next;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));

	sc_format_path(PATH_PUBLICDIR, &info.path);
	sc_append_path_id(&info.path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &info.path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	if (len < 7)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "certificate attributes file is too short");

	for (next = offs = 7; offs < len - 4; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%X) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka)   {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");
			if (uval != CKO_CERTIFICATE)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				obj.flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, &obj);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_VALUE:
			rv = _cka_get_blob(&attr, &info.value);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object value");
			break;
		case CKA_CERTIFICATE_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");
			if (uval != CKC_X_509)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Other then CKC_X_509 cert type is not supported");
			break;
		case CKA_ISSUER:
			break;
		case CKA_SUBJECT:
			break;
		case CKA_SERIAL_NUMBER:
			break;
		case CKA_TRUSTED:
			info.authority = (*attr.val != 0);
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info.id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				obj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		}
	}

	rv = sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add certificate object");

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
	unsigned ko_fid = ((file_id & ~LASER_BASEFID_MASK) | LASER_BASEFID_PUBKEY) + 1;
	struct sc_path path;
	struct sc_pkcs15_der der;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len, offs, next;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PUBLICDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	/* set info path to public key KO */
	path.value[path.len - 2] = (ko_fid >> 8) & 0xFF;
	path.value[path.len - 1] = ko_fid & 0xFF;
	info.path = path;

	if (len < 7)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "public key attributes file is too short");

	for (next = offs = 7; offs < len - 4; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%X) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka)   {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");

			if (uval != CKO_PUBLIC_KEY)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Need to be CKO_PUBLIC_KEY CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				obj.flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, &obj);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				obj.type = SC_PKCS15_TYPE_PUBKEY_RSA;
			else if (uval == CKK_EC)
				obj.type = SC_PKCS15_TYPE_PUBKEY_EC;
			else if (uval == CKK_GOSTR3410)
				obj.type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
			else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported public key type");
			break;
		case CKA_SUBJECT:
			break;
		case CKA_TRUSTED:
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info.id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				obj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		case CKA_ENCRYPT:
			if (*attr.val)
				info.usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
			break;
		case CKA_WRAP:
			if (*attr.val)
				info.usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
			break;
		case CKA_VERIFY:
			if (*attr.val)
				info.usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
			break;
		case CKA_VERIFY_RECOVER:
			if (*attr.val)
				info.usage |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
			break;
		case CKA_DERIVE:
			if (*attr.val)
				info.usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			break;
		case CKA_MODULUS:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public key modulus");

			key_rsa.modulus.data = der.value;
			key_rsa.modulus.len = der.len;
			break;
		case CKA_MODULUS_BITS:
			rv = _cka_get_unsigned(&attr, &info.modulus_length);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_MODULUS_BITS");
			break;
		case CKA_PUBLIC_EXPONENT:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public exponent");

			key_rsa.exponent.data = der.value;
			key_rsa.exponent.len = der.len;
			break;
		case CKA_LOCAL:
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		}
	}
	free(data);

	if (key_rsa.exponent.len && key_rsa.modulus.len)   {
		rv = sc_pkcs15_encode_pubkey_rsa(ctx, &key_rsa, &obj.content.value, &obj.content.len);
		LOG_TEST_RET(ctx, rv, "Encode RSA public key content error");
	}

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add public key object");

	sc_log(ctx, "Key path %s", sc_print_path(&info.path));
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_create_prvkey(struct sc_pkcs15_card * p15card, unsigned file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object obj;
	struct sc_pkcs15_prkey_info info;
	struct sc_pkcs15_prkey_rsa key_rsa;
	unsigned ko_fid = ((file_id & ~LASER_BASEFID_MASK) | LASER_BASEFID_PRVKEY) + 1;
	struct sc_path path;
	struct sc_pkcs15_der der;
	unsigned char fid[2] = {((file_id >> 8) & 0xFF), (file_id & 0xFF)};
	unsigned char *data = NULL;
	size_t len, offs, next;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(&info, 0, sizeof(info));
	memset(&obj, 0, sizeof(obj));
	memset(&key_rsa, 0, sizeof(key_rsa));

	sc_format_path(PATH_PRIVATEDIR, &path);
	sc_append_path_id(&path, fid, sizeof(fid));

	rv = sc_pkcs15_read_file(p15card, &path, &data, &len);
	LOG_TEST_RET(ctx, rv, "Error while getting file content.");

	/* set info path to private key KO */
	path.value[path.len - 2] = ko_fid / 0x100;
	path.value[path.len - 1] = ko_fid % 0x100;
	info.path = path;

	if (len < 7)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "private key attributes file is too short");

	for (next = offs = 7; offs < len - 4; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%X) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka)   {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");

			if (uval != CKO_PRIVATE_KEY)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Need to be CKO_PRIVATE_KEY CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				obj.flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, &obj);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_TRUSTED:
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				obj.type = SC_PKCS15_TYPE_PRKEY_RSA;
			else if (uval == CKK_EC)
				obj.type = SC_PKCS15_TYPE_PRKEY_EC;
			else if (uval == CKK_GOSTR3410)
				obj.type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
			else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported private key type");
			break;
		case CKA_SUBJECT:
			rv = _cka_get_blob(&attr, &info.subject);
			LOG_TEST_RET(ctx, rv, "Cannot set private key subject");
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info.id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_SENSITIVE:
			sc_log(ctx, "CKA_SENSITIVE: %s", (*attr.val) ? "yes" : "no");
			info.access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_SENSITIVE : 0;
			break;
		case CKA_DECRYPT:
			info.usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DECRYPT : 0;
			break;
		case CKA_UNWRAP:
			info.usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_UNWRAP : 0;
			break;
		case CKA_SIGN:
			info.usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGN : 0;
			break;
		case CKA_SIGN_RECOVER:
			info.usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGNRECOVER : 0;
			break;
		case CKA_DERIVE:
			info.usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DERIVE : 0;
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			break;
		case CKA_PUBLIC_EXPONENT:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public exponent");
			/*
			key_rsa.exponent.data = der.value;
			key_rsa.exponent.len = der.len;
			*/
			break;
		case CKA_EXTRACTABLE:
			sc_log(ctx, "CKA_EXTRACTABLE: %s", (*attr.val) ? "yes" : "no");
			info.access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE : 0;
			break;
		case CKA_LOCAL:
			sc_log(ctx, "CKA_LOCAL: %s", (*attr.val) ? "yes" : "no");
			info.access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_LOCAL : 0;
			break;
		case CKA_NEVER_EXTRACTABLE:
			sc_log(ctx, "CKA_NEVER_EXTRACTABLE: %s", (*attr.val) ? "yes" : "no");
			info.access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE : 0;
			break;
		case CKA_ALWAYS_SENSITIVE:
			sc_log(ctx, "CKA_ALWAYS_SENSITIVE: %s", (*attr.val) ? "yes" : "no");
			info.access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE : 0;
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		case CKA_MODIFIABLE:
			obj.flags |= (*attr.val) ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0;
			break;
		}
	}
	free(data);

	obj.auth_id.len = 1;
	obj.auth_id.value[0] = AUTH_ID_PIN; 

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
	LOG_TEST_RET(ctx, rv, "Failed to emu-add private key object");

	sc_log(ctx, "Key path %s", sc_print_path(&info.path));
	LOG_FUNC_RETURN(ctx, rv);
}


static int
_parse_fs_data(struct sc_pkcs15_card * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t ii, count, pubkey_num;
	char *df_paths[3] = {PATH_PUBLICDIR, PATH_PRIVATEDIR, NULL};
	int rv, df;
	struct sc_pkcs15_object *pubkeys[12];

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
			unsigned fid = *(buf + ii*2) * 0x100 + *(buf + ii*2 + 1);
			switch (fid & LASER_BASEFID_MASK)   {
			case LASER_BASEFID_KXS:
				sc_log(ctx, "parse private key attributes FID:%04X", fid);
				rv = _create_prvkey(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create private key PKCS#15 object");
				break;
			case LASER_BASEFID_KXC:
				sc_log(ctx, "parse certificate attributes FID:%04X", fid);
				rv = _create_certificate(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create certificate PKCS#15 object");
				break;
			case LASER_BASEFID_KXC_PUBKEY:
				sc_log(ctx, "parse public key attributes FID:%04X", fid);
				rv = _create_pubkey(p15card, fid);
				LOG_TEST_RET(ctx, rv, "Cannot create public key PKCS#15 object");
				break;
			default:
				break;
			}
		}
	}

	pubkey_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY, pubkeys, 12);
	for (ii = 0; ii < pubkey_num; ii++)   {
		struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)pubkeys[ii]->data;
		struct sc_pkcs15_object *prkey_obj = NULL;

		if (!sc_pkcs15_find_prkey_by_id(p15card, &info->id, &prkey_obj))
			if (strlen(prkey_obj->label) && !strlen(pubkeys[ii]->label))
				memcpy(pubkeys[ii]->label, prkey_obj->label, sizeof(pubkeys[ii]->label));
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

	rv = _create_pin(p15card, "User PIN", PATH_USERPIN, AUTH_ID_PIN, 0);
	LOG_TEST_RET(ctx, rv, "Cannot create 'User PIN' object");

	rv = _create_pin(p15card, "SO PIN", PATH_SOPIN, AUTH_ID_SOPIN, SC_PKCS15_PIN_FLAG_SO_PIN);
	LOG_TEST_RET(ctx, rv, "Cannot create 'SO PIN' object");

	rv = _parse_fs_data(p15card);
	LOG_TEST_RET(ctx, rv, "Error while creating 'certificate' objects");

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
