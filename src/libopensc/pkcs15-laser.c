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
#define PATH_USERPIN	"3F000020"
#define PATH_SOPIN	"3F000010"

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


static int
sc_pkcs15emu_laser_init(struct sc_pkcs15_card * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file *file = NULL;
	struct sc_path path;
	unsigned char *buf = NULL;
	size_t buflen = 0;
	int rv, ii;
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

	rv = _create_pin(p15card, "User PIN", PATH_USERPIN, 0xC1, 0);
	LOG_TEST_RET(ctx, rv, "Cannot create 'User PIN' object");

	rv = _create_pin(p15card, "SO PIN", PATH_SOPIN, 0x01, SC_PKCS15_PIN_FLAG_SO_PIN);
	LOG_TEST_RET(ctx, rv, "Cannot create 'SO PIN' object");

	rv = _create_certs(p15card, );
	LOG_TEST_RET(ctx, rv, "Cannot create 'SO PIN' object");



#if 0
	sc_format_path("0002", &path);
	r = sc_select_file(card, &path, &file);
	if (r) 
	{
		goto out;
	}
	else
	{
		/* certificate file */
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object pubkey_obj;
		struct sc_pkcs15_pubkey *pkey = NULL;
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));
		cert_info.id.len = 1;
		cert_info.id.value[0] = 0x45;
		cert_info.authority = 0;
		cert_info.path = path;
		r = sc_pkcs15_read_certificate(p15card, &cert_info,
					       (sc_pkcs15_cert_t
						**) (&cert_obj.data));
		if (!r) {
			sc_pkcs15_cert_t *cert =
			    (sc_pkcs15_cert_t *) (cert_obj.data);
			strlcpy(cert_obj.label, "User certificat",
				sizeof(cert_obj.label));
			cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;
			r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj,
						       &cert_info);
			if (r)
				goto out;
			pkey = cert->key;
			
			if (pkey->algorithm == SC_ALGORITHM_RSA) {
				modulus_length = (int)(pkey->u.rsa.modulus.len * 8);
			}

		}
		else
		{
			/* or public key */
			memset(&pubkey_info, 0, sizeof(pubkey_info));
			memset(&pubkey_obj, 0, sizeof(pubkey_obj));
			pubkey_info.id.len = 1;
			pubkey_info.id.value[0] = 0x45;
			pubkey_info.modulus_length = modulus_length;
			pubkey_info.key_reference = 1;
			pubkey_info.native = 1;
			pubkey_info.usage =
			    SC_PKCS15_PRKEY_USAGE_VERIFY |
			    SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER |
			    SC_PKCS15_PRKEY_USAGE_ENCRYPT |
			    SC_PKCS15_PRKEY_USAGE_WRAP;
			pubkey_info.path = path;
			strlcpy(pubkey_obj.label, "Public Key",
				sizeof(pubkey_obj.label));
			pubkey_obj.auth_id.len = 1;
			pubkey_obj.auth_id.value[0] = 1;
			pubkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
			pubkey_obj.type = SC_PKCS15_TYPE_PUBKEY_RSA;
			if (pkey == NULL) {
				pubkey_obj.data = &pubkey_info;
				r = sc_pkcs15_read_pubkey(p15card, &pubkey_obj, &pkey);
				if (r)
					goto out;
				/* not sure if necessary */
				pubkey_obj.flags = 0;
			}
			if (pkey->algorithm == SC_ALGORITHM_RSA) {
				modulus_length = (int)(pkey->u.rsa.modulus.len * 8);
			}
			pubkey_info.modulus_length = modulus_length;
			pubkey_obj.data = pkey;
			r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj,
							&pubkey_info);
			if (r < 0)
				goto out;
		}
	}
	if (file)
		sc_file_free(file);
	file = NULL;
	sc_format_path("0001", &path);
	r = sc_select_file(card, &path, &file);
	if (r) 
	{
		goto out;
	}
	else
	{
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;
		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));
		prkey_info.id.len = 1;
		prkey_info.id.value[0] = 0x45;
		prkey_info.usage =
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT
			| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		prkey_info.native = 1;
		prkey_info.key_reference = 1;
		prkey_info.modulus_length = modulus_length;
		prkey_info.path = path;
		strlcpy(prkey_obj.label, "Private Key",
			sizeof(prkey_obj.label));
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = 1;
		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj,
					&prkey_info);
		if (r < 0)
			goto out;
	}
	r = 0;
out:
	if (file)
		sc_file_free(file);
#endif
	return rv;
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
	struct sc_card *card = p15card->card;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_laser_init(p15card);

	rv = laser_detect_card(p15card);
	LOG_TEST_RET(ctx, rv, "It's not Athena LASER card");

	rv = sc_pkcs15emu_laser_init(p15card);
	LOG_FUNC_RETURN(ctx, rv);
}
