/*
 * pkcs15-tccardos.c: PKCS#15 profile for TC CardOS M4 cards
 *
 * Copyright (C) 2005  Nils Larsch <nils@larsch.net>
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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "log.h"
#include "pkcs15.h"

#define MANU_ID			"SIEMENS AG"
#define TC_CARDOS_APP_DF	"3F001002"
#define TC_CARDOS_LABEL		"TC CardOS M4"

#define TC_CARDOS_SIGN		0x0020
#define TC_CARDOS_AUTH		0x0040
#define TC_CARDOS_DEC		0x0080
#define TC_CARDOS_NOPIN		0x1000
#define TC_CARDOS_LOCALPIN	0x2000
#define TC_CARDOS_GLOBALPIN	0x3000
#define TC_CARDOS_PIN_MASK	0x3000

int sc_pkcs15emu_tccardos_init_ex(sc_pkcs15_card_t *p15card,
				  sc_pkcs15emu_opt_t *opts);

static int read_file(struct sc_card *card, const char *file, u8 *buf,
	size_t *len)
{
	int r;
	struct sc_path path;
	struct sc_file *fid = NULL;

	sc_format_path(file, &path);
	r = sc_select_file(card, &path, &fid);
	if (r != SC_SUCCESS || !fid)
		return r;
	if (fid->size < *len)
		*len = fid->size;
	r = sc_read_binary(card, 0, buf, *len, 0);
	free(fid);
	if ((size_t)r < *len)
		return SC_ERROR_INTERNAL;

	return SC_SUCCESS;
}

static const char *get_keyholder(int fileId)
{
	u8 tmp = fileId & 0x0f;

	if (tmp < 0x08)
		return "CH";
	else if (tmp < 0x0d)
		return "CA";
	else if (tmp == 0x0e)
		return "RCA";
	else
		return "error";
}

static const char *get_service(int fileId)
{
	u8 tmp = (fileId >> 8) & 0x0f;

	if (tmp == 0)
		return "DS";
	else if (tmp == 2 || tmp == 3)
		return "KE";
	else if (tmp == 5)
		return "AUT";
	else
		return "error";
}

static int create_cert_obj(sc_pkcs15_card_t *p15card, int fileId)
{
	sc_pkcs15_object_t    p15obj;
	sc_pkcs15_cert_info_t cinfo;

	memset(&p15obj, 0, sizeof(p15obj));
	memset(&cinfo,  0, sizeof(cinfo));
	/* the certificate attributes */
	cinfo.id.value[0] = (fileId >> 8) & 0xff;
	cinfo.id.value[1] = fileId & 0xff;
	cinfo.id.len = 2;
	cinfo.authority = fileId & 0x08 ? 1 : 0;
	cinfo.path.value[0] = (fileId >> 8) & 0xff;
	cinfo.path.value[1] = fileId & 0xff;
	cinfo.path.len   = 2;
	cinfo.path.type  = SC_PATH_TYPE_FILE_ID;
	cinfo.path.index =  0;
	cinfo.path.count = -1;

	/* compose the certificate name from the fileID */
	sprintf(p15obj.label, "C.%s.%s", get_keyholder(fileId), get_service(fileId));
	p15obj.flags        = 0; /* XXX */
	p15obj.user_consent = 0;

	return sc_pkcs15emu_add_x509_cert(p15card, &p15obj, &cinfo);
}

static int create_pkey_obj(sc_pkcs15_card_t *p15card, int cert, int key_descr,
	unsigned int keyId, unsigned int pinId)
{
	sc_pkcs15_object_t     p15obj;
	sc_pkcs15_prkey_info_t pinfo;

	/* init data objects */
	memset(&p15obj, 0, sizeof(p15obj));
	memset(&pinfo,  0, sizeof(pinfo));
	/* the private key attributes */
	pinfo.id.value[0] = (cert >> 8) & 0xff;
	pinfo.id.value[1] = cert & 0xff;
	pinfo.id.len = 2;
	pinfo.native   = 1;
	pinfo.key_reference  = (u8)keyId;
	pinfo.modulus_length = 1024; /* XXX */
	pinfo.access_flags = SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
	pinfo.usage    = 0;
	if (key_descr & TC_CARDOS_SIGN)
		pinfo.usage = SC_PKCS15_PRKEY_USAGE_SIGN |
		              SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	if (key_descr & TC_CARDOS_AUTH)
		pinfo.usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
	if (key_descr & TC_CARDOS_DEC)
		pinfo.usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT |
			      SC_PKCS15_PRKEY_USAGE_DECRYPT |
			      SC_PKCS15_PRKEY_USAGE_WRAP    |
			      SC_PKCS15_PRKEY_USAGE_UNWRAP;
	sc_format_path(TC_CARDOS_APP_DF, &pinfo.path);
	pinfo.path.index = 0;
	pinfo.path.count = 0;
	/* the common object attributes */
	sprintf(p15obj.label, "SK.CH.%s", get_service(cert));
	if (pinId && (key_descr & TC_CARDOS_PIN_MASK)) {
		p15obj.auth_id.value[0] = (u8)pinId;
		p15obj.auth_id.len      = 1;
	}
	p15obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	p15obj.user_consent = 0;
	p15obj.type = SC_PKCS15_TYPE_PRKEY_RSA;

	return sc_pkcs15emu_add_rsa_prkey(p15card, &p15obj, &pinfo);
}

static int create_pin_obj(sc_pkcs15_card_t *p15card, int cert,
	int key_descr, unsigned int pinId)
{
	sc_pkcs15_object_t   p15obj;
	sc_pkcs15_auth_info_t ainfo;

	/* init data objects */
	memset(&p15obj, 0, sizeof(p15obj));
	memset(&ainfo,  0, sizeof(ainfo));
	/* the authentication object attributes */
	ainfo.auth_id.value[0] = (u8)pinId;
	ainfo.auth_id.len   = 1;
	ainfo.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	ainfo.attrs.pin.reference = (u8)pinId;
	ainfo.attrs.pin.flags = SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA;
	if ((key_descr & TC_CARDOS_PIN_MASK) == TC_CARDOS_LOCALPIN)
		ainfo.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_LOCAL;
	ainfo.attrs.pin.type  = SC_PKCS15_PIN_TYPE_BCD; /* XXX */
	ainfo.attrs.pin.min_length = 6;    /* XXX */
	ainfo.attrs.pin.stored_length = 8; /* XXX */
	ainfo.attrs.pin.max_length = 8;
	ainfo.attrs.pin.pad_char   = 0;
	ainfo.tries_left = 3;    /* XXX */
	sc_format_path(TC_CARDOS_APP_DF, &ainfo.path);
	ainfo.path.index = 0;
	ainfo.path.count = 0;
	/* the common object attributes */
	sprintf(p15obj.label, "PIN.CH.%s", get_service(cert));
	p15obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	p15obj.user_consent = 0;
	p15obj.type = SC_PKCS15_TYPE_AUTH_PIN;

	return sc_pkcs15emu_add_pin_obj(p15card, &p15obj, &ainfo);
}

#define MAX_INFO1_SIZE		256
#define MAX_INFO2_SIZE		256

static int parse_EF_CardInfo(sc_pkcs15_card_t *p15card)
{
	int    r;
	u8     info1[MAX_INFO1_SIZE];
	size_t info1_len = MAX_INFO1_SIZE;
	u8     info2[MAX_INFO2_SIZE];
	size_t info2_len = MAX_INFO2_SIZE;
	u8     *p1, *p2;
	size_t key_num, i;
	struct sc_context *ctx = p15card->card->ctx;

	/* read EF_CardInfo1 */
	r = read_file(p15card->card, "3F001003b200", info1, &info1_len);
	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;
	/* read EF_CardInfo2 */
	r = read_file(p15card->card, "3F001003b201", info2, &info2_len);
	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;
	/* get the number of private keys */
	key_num = info1[info1_len-1] | (info1[info1_len-2] << 8) |
		  (info1[info1_len-3] << 16) | (info1[info1_len-4] << 24);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		"found %d private keys\n", (int)key_num);
	/* set p1 to the address of the first key descriptor */
	p1 = info1 + (info1_len - 4 - key_num * 2);
	p2 = info2;
	for (i=0; i<key_num; i++) {
		u8   pinId, keyId, cert_count;
		int  ch_cert, ca_cert, r1_cert, r2_cert = 0;
		int  key_descr;
		/* evaluate CertInfo2 */
		cert_count = *p2++;
		p2 += 2; /* ignore cert DF (it's always 1002) */
		keyId = *p2++;
		p2++;	/* ignore transport pin XXX */
		pinId = *p2++;
		p2 += 2; /* RFU */
		ch_cert = (p2[0] << 8) | p2[1];
		p2 += 2;
		ca_cert = (p2[0] << 8) | p2[1];
		p2 += 2;
		r1_cert = (p2[0] << 8) | p2[1];
		p2 += 2;
		if (cert_count == 4) {
			r2_cert = (p2[0] << 8) | p2[1];
			p2 += 2;
		}
		/* evaluate CertInfo1 */
		key_descr = (p1[0] << 8) | p1[1];
		p1 += 2;
		/* create and add certificates */
		if (ch_cert) {
			r = create_cert_obj(p15card, ch_cert);
			if (r < 0)
				return r;
		}
		if (ca_cert) {
			r = create_cert_obj(p15card, ca_cert);
			if (r < 0)
				return r;
		}
		if (r1_cert) {
			r = create_cert_obj(p15card, r1_cert);
			if (r < 0)
				return r;
		}
		if (r2_cert) {
			r = create_cert_obj(p15card, r2_cert);
			if (r < 0)
				return r;
		}
		/* create and add pin object */
		if ((key_descr & TC_CARDOS_PIN_MASK) != TC_CARDOS_NOPIN) {
			r = create_pin_obj(p15card, ch_cert, key_descr, pinId);
			if (r < 0)
				return r;
		} else
			pinId = 0;
		/* create and add private key */
		r = create_pkey_obj(p15card, ch_cert, key_descr, keyId, pinId);
		if (r < 0)
			return r;
	}
	return SC_SUCCESS;
}


static int sc_pkcs15_tccardos_init_func(sc_pkcs15_card_t *p15card)
{
	int    r;
	struct sc_path path;
	struct sc_file *file = NULL;
	u8     gdo[MAX_INFO1_SIZE];
	char   hex_buf[256];
	size_t gdo_len = MAX_INFO1_SIZE;
	struct sc_card *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "CardOS M4"))
		return SC_ERROR_WRONG_CARD;
	/* create pkcs15 objects */
	r = parse_EF_CardInfo(p15card);
	if (r != SC_SUCCESS)
		return r;
	/* set card label */
	if (p15card->tokeninfo->label != NULL)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = strdup(TC_CARDOS_LABEL);
	if (p15card->tokeninfo->label == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	/* set the manufacturer ID */
	if (p15card->tokeninfo->manufacturer_id != NULL)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);
	if (p15card->tokeninfo->manufacturer_id == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	/* set the serial number */
	r = read_file(p15card->card, "3F002F02", gdo, &gdo_len);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	sc_bin_to_hex(gdo + 7, 8, hex_buf, sizeof(hex_buf), 0);
	p15card->tokeninfo->serial_number = strdup(hex_buf);
	if (p15card->tokeninfo->serial_number == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	/* select the application DF */
	sc_format_path(TC_CARDOS_APP_DF, &path);
	r = sc_select_file(card, &path, &file);
	if (r != SC_SUCCESS || file == NULL)
		return SC_ERROR_INTERNAL;
	/* set the application DF */
	if (p15card->file_app)
		free(p15card->file_app);
	p15card->file_app = file;

	return SC_SUCCESS;
}

int sc_pkcs15emu_tccardos_init_ex(sc_pkcs15_card_t *p15card,
				  sc_pkcs15emu_opt_t *opts)
{
	return sc_pkcs15_tccardos_init_func(p15card);
}
