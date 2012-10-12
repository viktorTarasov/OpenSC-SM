/*
 * card-laser.c: Support for Athena LASER smart cards
 *
 * Copyright (C) 2012  Viktor Tarasov <viktor.tarasov@gmail.com>
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

#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "opensc.h"
#include "iso7816.h"
#include "pkcs15.h"

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations laser_ops;

static struct sc_card_driver laser_drv = {
	"Athena-Laser",
	"laser",
	&laser_ops,
	NULL, 0, NULL
};

static struct sc_atr_table laser_known_atrs[] = {
	{ "3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:0B:03:52:00:05:38", NULL,
		"Athena Laser", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_aid laser_aid = {
	{0xA0, 0x00, 0x00, 0x01, 0x64, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x00, 0x01},
	12
};

struct laser_card_capabilities  {
	unsigned char supported_keys[5];
	unsigned char crypto[3];
	struct {
		unsigned char data[2];
		unsigned char serial[4];
		unsigned char batch[2];
	} serial;
	struct {
		unsigned char total_size[4];
		unsigned char free_space[4];
		unsigned char size[4];
	} eeprom;
};

struct laser_private_data {
	struct sc_security_env security_env;
	size_t key_size;

	struct laser_card_capabilities caps;
};

static int laser_get_serialnr(struct sc_card *card, struct sc_serial_number *serial);

static int
laser_get_capability(struct sc_card *card, unsigned tag,
		unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[0x100];
	unsigned char p1 = (unsigned char)((tag>>8)&0xFF);
	unsigned char p2 = (unsigned char)(tag&0xFF);
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCB, p1, p2);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "get SE data  error");

	if (!out && !out_len)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (apdu.resplen > *out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, apdu.resp, apdu.resplen);
	*out_len = apdu.resplen;

	LOG_FUNC_RETURN(ctx, rv);
}

static int
laser_get_caps(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv_data = (struct laser_private_data *)card->drv_data;
	unsigned char buf[8];
	size_t buf_len;
	int rv;

	buf_len = sizeof(buf);
	rv = laser_get_capability(card, 0x0180, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'CRYPTO' card capability");
	if (buf_len != sizeof(prv_data->caps.crypto))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'CRYPTO' capability data");
	memcpy(prv_data->caps.crypto, buf, buf_len);

	buf_len = sizeof(buf);
	rv = laser_get_capability(card, 0x0188, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'KEY LENGTHS' card capability");
	if (buf_len != sizeof(prv_data->caps.supported_keys))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'KEY LENGTHS' capability data");
	memcpy(prv_data->caps.supported_keys, buf, buf_len);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_match_card(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i;

	sc_log(ctx, "laser_match_card(%s) called", sc_dump_hex(card->atr.value, card->atr.len));
	i = _sc_match_atr(card, laser_known_atrs, &card->type);
	if (i < 0)   {
		sc_log(ctx, "card not matched");
		return 0;
	}

	sc_log(ctx, "'%s' card matched", laser_known_atrs[i].name);
	return 1;
}


static int
laser_init(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *private_data = NULL;
	struct sc_path path;
	int rv = SC_ERROR_NO_CARD_SUPPORT;

	LOG_FUNC_CALLED(ctx);
	private_data = (struct laser_private_data *) calloc(1, sizeof(struct laser_private_data));
	if (private_data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	card->cla  = 0x00;
	card->drv_data = private_data;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, laser_aid.value, laser_aid.len, 0, 0);
	rv = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select Laser AID");

	rv = laser_get_serialnr(card, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot get card serial");

	rv = laser_get_caps(card);
	LOG_TEST_RET(ctx, rv, "Cannot get card capabilities");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buf, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_read_binary(card:%p) offs %i; count %i", card, offs, count);
	if (offs > 0x7fff) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", offs);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, (offs >> 8) & 0x7F, offs & 0xFF);
	apdu.le = count < 0x100 ? count : 0x100;
	apdu.resplen = count;
	apdu.resp = buf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "laser_read_binary() failed");
	sc_log(ctx, "laser_read_binary() apdu.resplen %i", apdu.resplen);

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


static int
laser_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_erase_binary(card:%p) count %i", card, count);
	if (!count)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "'ERASE BINARY' failed: invalid size to erase");

	tmp = malloc(count);
	if (!tmp)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate temporary buffer");
	memset(tmp, 0xFF, count);

	rv = sc_update_binary(card, offs, tmp, count, flags);
	free(tmp);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_select_file(struct sc_card *card, const struct sc_path *in_path,
		 struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int cache_valid = card->cache.valid, df_from_cache = 0;
	int rv, pathlen, selecting_laser = 0;

	LOG_FUNC_CALLED(ctx);
	if (!path)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "laser_select_file(card:%p) path(type:%i):%s out:%p", card, in_path->type, sc_print_path(in_path), file_out);
	sc_print_cache(card);

        memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;
	if (file_out)
		*file_out = NULL;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	apdu.cla = 0x80;

	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		if (laser_aid.len == pathlen && !memcmp(laser_aid.value, path, pathlen))   {
			/* 'LASER' application has to be selected by the standand ISO7816 command */
			apdu.cla = 0x00;
			selecting_laser = 1;
		}
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen < 2 )   {
			apdu.p1 = 0;
			break;
		}
		else if (memcmp(path, "\x3F\x00", 2))   {
			/* In a difference to ISO7816-4 specification (tab. 39)
			 * leading 3F00 has to be inlcuded into 'path-from-MF'. */
			memcpy(path + 2, path, pathlen);
			memcpy(path, "\x3F\x00", 2);
			pathlen += 2;
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.p2 = 0x0C;		/* not ISO 7816-4 */
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;
	}
	else {
		apdu.p2 = 0x00;		/* not ISO7816-4 */
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		LOG_FUNC_RETURN(ctx, rv);
	}
	LOG_TEST_RET(ctx, rv, "Select file error");

	if (apdu.resplen < 2)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	switch (apdu.resp[0]) {
	case ISO7816_TAG_FCI:
	case ISO7816_TAG_FCP:
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
		}

		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)
			card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
		*file_out = file;
		break;
	case 0x00: /* proprietary coding */
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Proprietary encoding in 'SELECT' APDU response not supported");
	default:
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Unknown 'SELECT' APDU response tag");
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_process_fci(struct sc_card *card, struct sc_file *file, const u8 *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	LOG_FUNC_CALLED(ctx);
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(ctx, "  file identifier: 0x%02X%02X", tag[0], tag[1]);
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
	if (tag != NULL && taglen > 0 && taglen < 3) {
		file->size = tag[0];
		if (taglen == 2)
			file->size = (file->size << 8) + tag[1];
		sc_log(ctx, "  bytes in file: %d", file->size);
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];

			sc_log(ctx, "  bytes in file: %d", bytes);
			file->size = bytes;
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x87, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			sc_log(ctx, "  shareable: %s", (byte & 0x40) ? "yes" : "no");
			file->ef_structure = byte & 0x07;
			switch ((byte >> 3) & 7) {
			case 0:
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				break;
			case 1:
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				break;
			case 7:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			default:
				type = "unknown";
				break;
			}
			sc_log(ctx, "  type: %s", type);
			sc_log(ctx, "  EF structure: %d", byte & 0x07);
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char tbuf[128];

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, file->name, file->namelen, tbuf, sizeof(tbuf));
		sc_log(ctx, "  File name: %s", tbuf);
		if (!file->type)
			file->type = SC_FILE_TYPE_DF;
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_prop_attr(file, tag, taglen);
	else
		file->prop_attr_len = 0;

	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_prop_attr(file, tag, taglen);

	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_sec_attr(file, tag, taglen);

	tag = sc_asn1_find_tag(ctx, p, len, 0x8A, &taglen);
	if (tag != NULL && taglen==1) {
		if (tag[0] == 0x01)
			file->status = SC_FILE_STATUS_CREATION;
		else if (tag[0] == 0x07 || tag[0] == 0x05)
			file->status = SC_FILE_STATUS_ACTIVATED;
		else if (tag[0] == 0x06 || tag[0] == 0x04)
			file->status = SC_FILE_STATUS_INVALIDATED;
	}

	file->magic = SC_FILE_MAGIC;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_fcp_encode(struct sc_card *card, struct sc_file *file, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buf[0x80];
	size_t offs = 0;
	unsigned char  ops_df[6] = {
		SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE
	};
	unsigned char  ops_ef[4] = {
		SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF
	};
	unsigned char *ops = NULL;
	size_t ii, ops_len, file_size;

	LOG_FUNC_CALLED(ctx);
	if (file->type == SC_FILE_TYPE_DF)   {
		ops = &ops_df[0];
		ops_len = sizeof(ops_df);
		file_size = 0;
	}
	else if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		ops = &ops_ef[0];
		ops_len = sizeof(ops_ef);
		file_size = file->size;
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Create of the non DF and non EF file types is not supported.");
	}

	memset(buf, 0, sizeof(buf));
	offs = 0;

	buf[offs++] = 0x83;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF;

	buf[offs++] = 0x80;
	buf[offs++] = 2;
	buf[offs++] = (file_size >> 8) & 0xFF;
	buf[offs++] = file_size & 0xFF;

	if (file->type == SC_FILE_TYPE_DF && file->namelen)   {
		buf[offs++] = 0x84;
		buf[offs++] = file->namelen;
		memcpy(buf + offs, file->name, file->namelen);
		offs += file->namelen;
	}

	buf[offs++] = 0x8A;
	buf[offs++] = 1;
	buf[offs++] = 0x04;

	buf[offs++] = 0x86;
	buf[offs++] = ops_len * 2;;
	for (ii = 0; ii < ops_len; ii++) {
		const struct sc_acl_entry *entry = sc_file_get_acl_entry(file, ops[ii]);

		if (entry)
			sc_log(ctx, "ops 0x%X: method %X, reference %X", ops[ii], entry->method, entry->key_ref);
		else
			sc_log(ctx, "ops 0x%X: no ACL entry", ops[ii]);

		if (!entry || entry->method == SC_AC_NEVER)   {
			buf[offs++] = 0x00;
			buf[offs++] = 0xFF;
		}
		else if (entry->method == SC_AC_NONE)   {
			buf[offs++] = 0x00;
			buf[offs++] = 0x00;
		}
		else if (entry->method == SC_AC_SCB)   {
			buf[offs++] = (entry->key_ref >> 8) & 0xFF;
			buf[offs++] = entry->key_ref & 0xFF;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported AC method");
		}
	}

	if (out)   {
		if (out_len < offs)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to encode FCP");
		memcpy(out, buf, offs);
	}

	LOG_FUNC_RETURN(ctx, offs);
}


static int
laser_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	const struct sc_acl_entry *entry = NULL;
	unsigned char sbuf[0x100];
	size_t sbuf_len;
	int rv;
	unsigned char file_type;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);

	if (file->type != SC_FILE_TYPE_WORKING_EF && file->type != SC_FILE_TYPE_DF)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Only DF or EF file can be created");

	sbuf_len = laser_fcp_encode(card, file, sbuf + 2, sizeof(sbuf)-2);
	LOG_TEST_RET(ctx, sbuf_len, "FCP encode error");

	sbuf[0] = ISO7816_TAG_FCP;
	sbuf[1] = sbuf_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.p1 = file->type == SC_FILE_TYPE_DF ? 0x38 : 0x01;
	apdu.data = sbuf;
	apdu.datalen = sbuf_len + 2;
	apdu.lc = sbuf_len + 2;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "laser_create_file() create file error");

	rv = laser_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select newly created file");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *private_data = (struct laser_private_data *)card->drv_data;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char p1s[] = {0x01, 0x38, 0x08};
	int rv, ii;
	size_t offs;

	LOG_FUNC_CALLED(ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x30, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 0x00;

	for (ii = 0, offs = 0; ii < sizeof(p1s); ii++)   {
		unsigned char tmp[SC_MAX_APDU_BUFFER_SIZE];
		size_t oo;
		int jj;

		apdu.p1 = p1s[ii];
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "list files error");

		if (apdu.resplen < 4)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		if (rbuf[3]*2 + offs > buflen)
			LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

		for (oo=4, jj=0; jj < rbuf[3]; jj++)   {
			if (rbuf[oo] != 0xD2)
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
			memcpy(buf + offs, rbuf + oo + 2, 2);
			oo += 2 + rbuf[oo+1];
			offs += 2;
		}
	}

	LOG_FUNC_RETURN(ctx, offs);
}


static int
laser_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	if (sw1 == 0x62 && sw2 == 0x82)
		return SC_SUCCESS;

	return iso_ops->check_sw(card, sw1, sw2);
}


static int
laser_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_set_security_env(card:%p) operation 0x%X; senv.algorithm 0x%X, senv.algorithm_ref 0x%X",
			card, env->operation, env->algorithm, env->algorithm_ref);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (pin_cmd->pin1.data && !pin_cmd->pin1.len)   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, pin_cmd->pin_reference);
	}
	else if (pin_cmd->pin1.data && pin_cmd->pin1.len)   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_cmd->pin_reference);
		apdu.data = pin_cmd->pin1.data;
		apdu.datalen = pin_cmd->pin1.len;
		apdu.lc = pin_cmd->pin1.len;
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

        rv = sc_transmit_apdu(card, &apdu);
        LOG_TEST_RET(ctx, rv, "APDU transmit failed");

        if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
        rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

        LOG_FUNC_RETURN(ctx, rv);

}


static int
laser_pin_is_verified(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd_data,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	int rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

	LOG_FUNC_CALLED(ctx);
	if (!pin_cmd_data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (pin_cmd_data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non CHV PIN type is not supported for verification");

	pin_cmd = *pin_cmd_data;
	pin_cmd.pin1.data = (unsigned char *)"";
	pin_cmd.pin1.len = 0;
	rv = laser_chv_verify(card, &pin_cmd, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_select_global_pin(struct sc_card *card, unsigned reference)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Select global PIN file %X", reference);

	sc_format_path("3F0000FF", &path);
	path.value[path.len - 1] = reference;

	rv = laser_select_file(card, &path, NULL);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_pin_verify(struct sc_card *card, unsigned type, unsigned reference,
		const unsigned char *data, size_t data_len, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	unsigned chv_ref = reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify PIN(type:%X,ref:%i,data(len:%i,%p)", type, reference, data_len, data);
	if (type == SC_AC_AUT)   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	else if (type == SC_AC_SCB)   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	else if (type == SC_AC_CHV)   {
		if (!(reference & 0x80))   {
			rv =  laser_select_global_pin(card, reference);
			LOG_TEST_RET(ctx, rv, "Select PIN file error");
			chv_ref = 0;
		}
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = chv_ref;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;
	pin_cmd.pin1.data = data;
	pin_cmd.pin1.len = data_len;

	rv = laser_pin_is_verified(card, &pin_cmd, tries_left);
	if (data && !data_len)
		LOG_FUNC_RETURN(ctx, rv);

	if (rv != SC_ERROR_PIN_CODE_INCORRECT && rv != SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		LOG_FUNC_RETURN(ctx, rv);

	rv = laser_chv_verify(card, &pin_cmd, tries_left);
	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(ref:%i,lengths:%i/%i)", data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure can be used only with the PINs of type CHV");

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%i, PIN-2 %p:%i",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);
	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = laser_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	default:
		sc_log(ctx, "PIN command 0x%X do not yet supported.", data->cmd);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non-supported PIN command");
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv_data = (struct laser_private_data *)card->drv_data;
	struct sc_serial_number sn;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->serialnr.len)   {
		if (serial)
			*serial = card->serialnr;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sn.len = sizeof(sn.value);
	rv = laser_get_capability(card, 0x0114, sn.value, &sn.len);
	LOG_TEST_RET(ctx, rv, "cannot get 'serial number' card capability");

	if (sizeof(prv_data->caps.serial) != sn.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'SERIAL NUMBER' data");
	memcpy(&prv_data->caps.serial, sn.value, sn.len);

	card->serialnr = sn;
	if (serial)
		*serial = sn;
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;
	struct laser_sdo *sdo = (struct laser_sdo *) ptr;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return laser_get_serialnr(card, (struct sc_serial_number *)ptr);
#if 0
	case SC_CARDCTL_IASECC_SDO_CREATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_CREATE: sdo_class %X", sdo->sdo_class);
		return laser_sdo_create(card, (struct laser_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_DELETE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_DELETE: sdo_class %X", sdo->sdo_class);
		return laser_sdo_delete(card, (struct laser_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_PUT_DATA: sdo_class %X", sdo->sdo_class);
		return laser_sdo_put_data(card, (struct laser_sdo_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA");
		return laser_sdo_key_rsa_put_data(card, (struct laser_sdo_rsa_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_GET_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return laser_sdo_get_data(card, (struct laser_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_GENERATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return laser_sdo_generate(card, (struct laser_sdo *) ptr);
	case SC_CARDCTL_GET_SE_INFO:
		sc_log(ctx, "CMD SC_CARDCTL_GET_SE_INFO: sdo_class %X", sdo->sdo_class);
		return laser_se_get_info(card, (struct laser_se_info *) ptr);
	case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
		sc_log(ctx, "CMD SC_CARDCTL_GET_CHV_REFERENCE_IN_SE");
		return laser_get_chv_reference_from_se(card, (int *)ptr);
	case SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE");
		return laser_get_free_reference(card, (struct laser_ctl_get_free_reference *)ptr);
#endif
	}
	return SC_ERROR_NOT_SUPPORTED;
}


static int
laser_decipher(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(card->ctx, "crgram_len %i;  outlen %i", in_len, out_len);
	if (!out || !out_len || in_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_compute_signature_dst(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_compute_signature_dst() input length %i", in_len);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");
	else if (!(prv->key_size & 0x1E0) || (prv->key_size & ~0x1E0))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key size for SC_SEC_OPERATION_SIGN");
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_compute_signature_at(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	if (env->operation != SC_SEC_OPERATION_AUTHENTICATE)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_AUTHENTICATE");

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "inlen %i, outlen %i", in_len, out_len);
	if (!card || !in || !out)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid compute signature arguments");

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return laser_compute_signature_dst(card, in, in_len, out,  out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return laser_compute_signature_at(card, in, in_len, out,  out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (!iso_ops)
		iso_ops = iso_drv->ops;

	laser_ops = *iso_ops;

	laser_ops.match_card = laser_match_card;
	laser_ops.init = laser_init;
	laser_ops.finish = laser_finish;
	laser_ops.read_binary = laser_read_binary;
	/*	write_binary: ISO7816 implementation works	*/
	/*	update_binary: ISO7816 implementation works	*/
	laser_ops.erase_binary = laser_erase_binary;
	/*	resize_binary	*/
	/*	read_record: Untested	*/
	/*	write_record: Untested	*/
	/*	append_record: Untested	*/
	/*	update_record: Untested	*/
	laser_ops.select_file = laser_select_file;
	/*	get_response: Untested	*/
	/*	get_challenge: ISO7816 implementation works	*/
	laser_ops.logout = laser_logout;
	/*	restore_security_env	*/
	laser_ops.set_security_env = laser_set_security_env;
	laser_ops.decipher = laser_decipher;
	laser_ops.compute_signature = laser_compute_signature;
	laser_ops.create_file = laser_create_file;
	laser_ops.delete_file = laser_delete_file;
	laser_ops.list_files = laser_list_files;
	laser_ops.check_sw = laser_check_sw;
	laser_ops.card_ctl = laser_card_ctl;
	laser_ops.process_fci = laser_process_fci;
	/*	construct_fci: Not needed	*/
	laser_ops.pin_cmd = laser_pin_cmd;
	/*	get_data: Not implemented	*/
	/*	put_data: Not implemented	*/
	/*	delete_record: Not implemented	*/

	/* laser_ops.read_public_key = laser_read_public_key	*/

	return &laser_drv;
}

struct sc_card_driver *
sc_get_laser_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
