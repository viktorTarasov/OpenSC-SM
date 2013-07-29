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
#include <time.h>

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
#include "laser.h"

#include <libsm/sm-common.h>

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#else
#include <process.h>
#define getpid() _getpid()
#endif

#define LASER_CARD_DEFAULT_FLAGS ( SC_ALGORITHM_ONBOARD_KEY_GEN	\
		| SC_ALGORITHM_RSA_RAW		\
		| SC_ALGORITHM_RSA_PAD_ISO9796	\
		| SC_ALGORITHM_RSA_PAD_PKCS1	\
		| SC_ALGORITHM_RSA_HASH_NONE	\
		| SC_ALGORITHM_RSA_HASH_SHA1	\
		| SC_ALGORITHM_RSA_HASH_SHA256)

//#define TESTING

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
        // 3b,dc,00,ff,80,91,fe,1f,c3,80,73,c8,21,10,66,00,00,00,00,00,00,00
	{ "3B:DC:00:FF:80:91:FE:1F:C3:80:73:C8:21:10:66:00:00:00:00:00:00:00",
        // ff,ff,00,ff,f0,ff,ff,ff,ff,ff,ff,ff,ff,f0,ff,00,00,00,00,00,00,00
	  "FF:FF:00:FF:F0:FF:FF:FF:FF:FF:FF:FF:FF:F0:FF:00:00:00:00:00:00:00",
		"Athena LASER IDProtect(X)", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,d5,00,ff,80,91,fe,1f,c3,80,73,c8,21,10,00
	{ "3B:D5:00:FF:80:91:FE:1F:C3:80:73:C8:21:10:00",
	// ff,ff,00,ff,f0,ff,ff,ff,ff,ff,ff,ff,ff,f0,00
	  "FF:FF:00:FF:F0:FF:FF:FF:FF:FF:FF:FF:FF:F0:00",
		"Athena LASER IDProtect", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,6c,00,ff,80,73,c8,21,13,66,01,06,11,59,00,01
	{ "3B:6C:00:FF:80:73:C8:21:13:66:01:06:11:59:00:01",
	// ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
	  "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
		"Athena LASER JaCarta EMV T0", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,fc,13,00,ff,81,31,fe,45,80,73,c8,21,13,66,01,06,11,59,00,01,3a
	{ "3B:FC:13:00:FF:81:31:FE:45:80:73:C8:21:13:66:01:06:11:59:00:01:3A",
	// ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
	  "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
		"Athena LASER JaCarta EMV T1", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,fc,00,00,ff,10,00,80,73,c8,21,10,66,00,00,00,00,00,00
	{ "3B:FC:00:00:FF:10:00:80:73:C8:21:10:66:00:00:00:00:00:00",
	// ff,ff,00,ff,ff,ff,ff,ff,ff,ff,ff,f0,ff,00,00,00,00,00,00
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:F0:FF:00:00:00:00:00:00",
		"Athena LASER PayProtect", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,9a,00,81,31,fe,45,54,69,63,54,6f,6b,20,31,2e,30,00
	{ "3B:9A:00:81:31:FE:45:54:69:63:54:6F:6B:20:31:2E:30:00",
	// ff,ff,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00",
		"Athena LASER TicTok V1.0", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,da,00,ff,80,b1,fe,00,1f,c3,54,69,63,54,6f,6b,20,31,2e,00,00
	{ "3B:DA:00:FF:80:B1:FE:00:1F:C3:54:69:63:54:6F:6B:20:31:2E:00:00",
	// ff,ff,00,ff,f0,ff,ff,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00
	  "FF:FF:00:FF:F0:FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00:00",
		"Athena LASER TicTok V1.x", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	// 3b,da,00,ff,80,b1,fe,00,1f,c3,54,69,63,54,6f,6b,20,32,2e,00,00
	{ "3B:DA:00:FF:80:B1:FE:00:1F:C3:54:69:63:54:6F:6B:20:32:2E:00:00",
	// ff,ff,00,ff,f0,ff,ff,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00
	  "FF:FF:00:FF:F0:FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00:00",
		"Athena LASER TicTok V2.x", SC_CARD_TYPE_ATHENA_LASER, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_aid laser_aid = {
	{0xA0, 0x00, 0x00, 0x01, 0x64, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x00, 0x01},
	12
};

unsigned char laser_ops_df[6] = {
	SC_AC_OP_CREATE, SC_AC_OP_CREATE_DF, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE
};
unsigned char laser_ops_ef[4] = {
	SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF
};
unsigned char laser_ops_do[3] = {
	SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN
};
unsigned char laser_ops_ko[7] = {
	SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO
};
unsigned char laser_ops_pin[7] = {
	SC_AC_OP_READ, SC_AC_OP_PIN_CHANGE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO
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
	struct sc_file *last_ko;

	int secure_verify;
	int sm_min_level;

	struct laser_card_capabilities caps;
};

static int laser_get_serialnr(struct sc_card *, struct sc_serial_number *);
static int laser_get_default_key(struct sc_card *, struct sc_cardctl_default_key *);
static int laser_parse_sec_attrs(struct sc_card *, struct sc_file *);
static int laser_process_fci(struct sc_card *, struct sc_file *, const unsigned char *, size_t);

#ifdef ENABLE_SM
static int laser_sm_open(struct sc_card *card);
static int laser_sm_wrap_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
static int laser_sm_free_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
static int laser_sm_close(struct sc_card *card);

static int laser_cbc_cksum(struct sc_context *ctx, unsigned char *key, size_t key_size,
		unsigned char *in, size_t in_len, DES_cblock *icv);
#endif

static int
laser_get_tag_data(struct sc_context *ctx, unsigned char *data, size_t data_len, struct sc_tlv_data *out)
{
	size_t taglen;
	const unsigned char *ptr = NULL;

	if (!ctx || !data || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = sc_asn1_find_tag(ctx, data, data_len, out->tag, &taglen);
	if (!ptr)
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;

	out->value = malloc(taglen);
	if (!out->value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(out->value, ptr, taglen);
	out->len = taglen;

	return SC_SUCCESS;
}

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
laser_tlv_parse(unsigned char *buf, size_t buf_len, struct sc_tlv_data *tlv)
{
	size_t offs;

	if (!buf || !tlv)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (buf_len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;

	offs = 0;
	tlv->tag = *(buf + offs++);
	if (!(*(buf + offs) & 0x80))   {
		tlv->len = *(buf + offs++);
		tlv->value = buf + offs;
	}
	else   {
		size_t ii, nn = *(buf + offs++) & 0x7F;

		if (buf_len < 2 + nn)
			return SC_ERROR_INVALID_ARGUMENTS;

		for (ii = 0, tlv->len = 0; ii < nn; ii++)
			tlv->len = tlv->len * 0x100 + *(buf + offs++);
		tlv->value = buf + offs;
	}

	return SC_SUCCESS;
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
	scconf_block *atrblock = NULL;
	struct laser_private_data *private_data = NULL;
	struct sc_path path;
	unsigned int flags;
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

	flags = LASER_CARD_DEFAULT_FLAGS;
	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (atrblock)   {
		int min_level = scconf_get_int(atrblock, "sm_min_level", 0);

		if (min_level != 0 && min_level != 1 && min_level != 3)
		        LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "Invalid SM min level configuration value");
		private_data->sm_min_level = min_level;

		private_data->secure_verify = scconf_get_bool(atrblock, "secure_verify", 0);
	}
	sc_log(ctx, "SM-min-level %i, secure-verify %i", private_data->sm_min_level, private_data->secure_verify);

#ifdef ENABLE_SM
	card->sm_ctx.ops.open = laser_sm_open;
	card->sm_ctx.ops.get_sm_apdu = laser_sm_wrap_apdu;
	card->sm_ctx.ops.free_sm_apdu = laser_sm_free_apdu;
	card->sm_ctx.ops.close = laser_sm_close;

	if (private_data->sm_min_level)   {
		rv = laser_sm_open(card);
		LOG_TEST_RET(ctx, rv, "Cannot open SM");
	}
	sc_log(ctx, "SM ops: open %p, wrap %p, free %p ", card->sm_ctx.ops.open, card->sm_ctx.ops.get_sm_apdu, card->sm_ctx.ops.free_sm_apdu);
#endif
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
	/* int cache_valid = card->cache.valid, df_from_cache = 0; */
	unsigned pathlen;
	int rv, selecting_laser = 0;

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

	/* Return FCI data */
	apdu.p2 = 0x0C;		/* not ISO 7816-4 */
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Select file error");

	if (apdu.resplen < 2)   {
		if (file_out)
			LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		else
			LOG_FUNC_RETURN(ctx, rv);
	}

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

		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)   {
			struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;

			rv = laser_process_fci(card, file, apdu.resp+2, apdu.resp[1]);
			LOG_TEST_RET(ctx, rv, "Process FCI error");

			rv = laser_parse_sec_attrs(card, file);
			LOG_TEST_RET(ctx, rv, "Security attributes parse error");

			if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
				if (prv->last_ko)
					sc_file_free(prv->last_ko);
				sc_file_dup(&prv->last_ko, file);
			}
		}

		if (file_out)
			*file_out = file;
		else
			sc_file_free(file);
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
	const unsigned char *tag = NULL, *p = buf;

	LOG_FUNC_CALLED(ctx);
	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_FID, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(ctx, "  file identifier: 0x%02X%02X", tag[0], tag[1]);
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE, &taglen);
	if (tag != NULL && taglen > 0 && taglen < 3) {
		file->size = tag[0];
		if (taglen == 2)
			file->size = (file->size << 8) + tag[1];
		sc_log(ctx, "  bytes in file: %d", file->size);
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE_FULL, &taglen);
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

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_DF_NAME, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char tbuf[128];

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, file->name, file->namelen, tbuf, sizeof(tbuf));
		sc_log(ctx, "  File name: %s", tbuf);
		if (!file->type)
			file->type = SC_FILE_TYPE_DF;
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_PROP_INFO, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_prop_attr(file, tag, taglen);
	else
		file->prop_attr_len = 0;

	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen)   {
		sc_file_set_prop_attr(file, tag, taglen);
	}
	else   {
		tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
		if (tag != NULL && taglen)
			sc_file_set_prop_attr(file, tag, taglen);
	}

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
laser_parse_sec_attrs(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	unsigned type = file->type;
	unsigned char *attrs = file->sec_attr;
	size_t len = file->sec_attr_len;
	unsigned char *ops = NULL;
	size_t ii, ops_len;

	LOG_FUNC_CALLED(ctx);
	if(type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(laser_ops_ko) * 2)   {
		if (file->prop_attr_len > 2)   {
			if (*(file->prop_attr + 2) == LASER_KO_ALGORITHM_PIN)   {
				sc_log(ctx, "KO-PIN");
				ops = &laser_ops_pin[0];
				ops_len = sizeof(laser_ops_pin)/sizeof(laser_ops_pin[0]);
			}
			else {
				sc_log(ctx, "KO algo:%X", *(file->prop_attr + 2));
				ops = &laser_ops_ko[0];
				ops_len = sizeof(laser_ops_ko)/sizeof(laser_ops_ko[0]);
			}
		}
		else   {
			sc_log(ctx, "KO");
			ops = &laser_ops_ko[0];
			ops_len = sizeof(laser_ops_ko)/sizeof(laser_ops_ko[0]);
		}
	}
	else if (type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(laser_ops_do) * 2)   {
		sc_log(ctx, "DO");
		ops = &laser_ops_do[0];
		ops_len = sizeof(laser_ops_do)/sizeof(laser_ops_do[0]);
	}
	else if (type == SC_FILE_TYPE_WORKING_EF)   {
		sc_log(ctx, "EF");
		ops = &laser_ops_ef[0];
		ops_len = sizeof(laser_ops_ef)/sizeof(laser_ops_ef[0]);
	}
	else if (type == SC_FILE_TYPE_DF)   {
		sc_log(ctx, "DF");
		ops = &laser_ops_df[0];
		ops_len = sizeof(laser_ops_df)/sizeof(laser_ops_df[0]);
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported file type");
	}
	sc_log(ctx, "sec.attrs(%i) %s, ops_len %i", len, sc_dump_hex(attrs, len), ops_len);

	for (ii=0; ii<ops_len; ii++)   {
		unsigned val = *(attrs + ii*2) * 0x100 + *(attrs + ii*2 + 1);

		sc_log(ctx, "access rule 0x%04X, op 0x%X(%i)", val, *(ops + ii), *(ops + ii));
		if (*(attrs + ii*2))   {
			sc_log(ctx, "op:%X SC_AC_SCB, val:%X", *(ops + ii), val);
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_SCB, val);
		}
		else if (*(attrs + ii*2 + 1) == 0xFF)   {
			sc_log(ctx, "op:%X SC_AC_NEVER, val:%X", *(ops + ii));
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		}
		else if (*(attrs + ii*2 + 1))   {
			unsigned char ref = *(attrs + ii*2 + 1);
			unsigned method = (ref == LASER_TRANSPORT_PIN1_REFERENCE) ? SC_AC_AUT : SC_AC_CHV;
			/* TODO: normally, here we should check the type of referenced KO */

			if (ref == 0x30)   {
				sc_log(ctx, "TODO: not supported LOGIC KO; here ref-30 changed for ref-20 : TODO");
				ref = 0x20;
			}

			sc_file_add_acl_entry(file, *(ops + ii), method, ref);
		}
		else   {
			sc_log(ctx, "op:%X SC_AC_NONE, val:%X", *(ops + ii));
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_NONE, SC_AC_KEY_REF_NONE);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_fcp_encode(struct sc_card *card, struct sc_file *file, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buf[0x400];
	size_t offs = 0;
	unsigned char *ops = NULL;
	size_t ii, ops_len, file_size;

	LOG_FUNC_CALLED(ctx);

	if (file->type == SC_FILE_TYPE_DF)   {
		ops = &laser_ops_df[0];
		ops_len = sizeof(laser_ops_df);
		file_size = 0;
	}
	else if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		ops = &laser_ops_ef[0];
		ops_len = sizeof(laser_ops_ef);
		file_size = file->size;
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF
			&& file->ef_structure == LASER_FILE_DESCRIPTOR_KO)   {
		ops = &laser_ops_ko[0];
		ops_len = sizeof(laser_ops_ko);
		file_size = file->size;
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported type of the file to be created.");
	}

	memset(buf, 0, sizeof(buf));
	offs = 0;

	buf[offs++] = ISO7816_TAG_FCP_LCS;
	buf[offs++] = 1;
	buf[offs++] = 0x04;

	buf[offs++] = ISO7816_TAG_FCP_FID;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF;

	buf[offs++] = ISO7816_TAG_FCP_SIZE;
	buf[offs++] = 2;
	buf[offs++] = (file_size >> 8) & 0xFF;
	buf[offs++] = file_size & 0xFF;

	if (file->namelen)   {
		buf[offs++] = ISO7816_TAG_FCP_DF_NAME;
		buf[offs++] = file->namelen;
		memcpy(buf + offs, file->name, file->namelen);
		offs += file->namelen;
	}

	if (file->prop_attr && file->prop_attr_len)   {
		buf[offs++] = ISO7816_TAG_FCP_PROP_INFO;
		buf[offs++] = file->prop_attr_len;
		memcpy(buf + offs, file->prop_attr, file->prop_attr_len);
		offs += file->prop_attr_len;
	}

	buf[offs++] = ISO7816_TAG_FCP_ACLS;
	buf[offs++] = ops_len * 2;;
	for (ii = 0; ii < ops_len; ii++) {
		const struct sc_acl_entry *entry = sc_file_get_acl_entry(file, ops[ii]);

		if (entry)
			sc_log(ctx, "ops %i: method %X, reference %X", ops[ii], entry->method, entry->key_ref);
		else
			sc_log(ctx, "ops %i: no ACL entry", ops[ii]);

		if (!entry || entry->method == SC_AC_NEVER)   {
			buf[offs++] = 0x00;
			buf[offs++] = 0xFF;
		}
		else if (entry->method == SC_AC_NONE)   {
			buf[offs++] = 0x00;
			buf[offs++] = 0x00;
		}
		else if (entry->method == SC_AC_CHV)   {
			buf[offs++] = 0x00;
			buf[offs++] = entry->key_ref & 0xFF;
		}
		else if (entry->method == SC_AC_SCB)   {
			buf[offs++] = (entry->key_ref >> 8) & 0xFF;
			buf[offs++] = entry->key_ref & 0xFF;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported AC method");
		}
	}

	if (file->encoded_content && file->encoded_content_len)   {
		memcpy(buf + offs, file->encoded_content, file->encoded_content_len);
		offs += file->encoded_content_len;
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
	unsigned char sbuf[0x400], fcp[0x400], p1;
	size_t fcp_len, offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);
	sc_log(ctx, "create file (type:%i, ID:0x%X, path:%s)", file->type, file->id, sc_print_path(&file->path));

	/* Select parent */
	if (file->path.len > 2)   {
		struct sc_path parent_path = file->path;

		parent_path.len -= 2;
		rv = laser_select_file(card, &parent_path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select newly created file");
	}

	fcp_len = laser_fcp_encode(card, file, fcp, sizeof(fcp));
	LOG_TEST_RET(ctx, fcp_len, "FCP encode error");

	if (file->type == SC_FILE_TYPE_WORKING_EF)
		p1 = 0x01;
	else if (file->type == SC_FILE_TYPE_DF)
		p1 = 0x38;
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		p1 = file->ef_structure;
	else
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported type of the file to create");

	offs = 0;
	sbuf[offs++] = ISO7816_TAG_FCP;
	sbuf[offs++] = fcp_len > 0xFF ? 0x82 : 0x81;
	if (fcp_len > 0xFF)
		sbuf[offs++] = (fcp_len >> 8) & 0xFF;
	sbuf[offs++] = fcp_len & 0xFF;
	memcpy(sbuf + offs, fcp,  fcp_len);
	offs += fcp_len;

	sc_log(ctx, "FCP data '%s'", sc_dump_hex(sbuf, offs));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.p1 = p1;
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "laser_create_file() create file error");

	if (!file->path.len)   {
		sc_append_file_id(&file->path, file->id);
		file->path.type = SC_PATH_TYPE_FILE_ID;
	}

	rv = laser_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select newly created file");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	/* TODO: reset secure status of User and SO PINs */
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;

	LOG_FUNC_CALLED(ctx);

	if (prv)   {
		if (prv->last_ko)
			sc_file_free(prv->last_ko);
		free(prv);
	}
	card->drv_data = NULL;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	int rv, p1 = 0;

	LOG_FUNC_CALLED(ctx);

	rv = laser_select_file(card, path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	if (file->type == SC_FILE_TYPE_DF)
		p1 = 1;
	sc_file_free(file);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, p1, 0x00);

	sc_log(ctx, "delete %s file '%s'", (p1 ? "DF" : "EF"), sc_print_path(path));
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Failed to delete file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char p1s[] = {0x01, 0x38, 0x08};
	unsigned ii;
	size_t offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x30, 0, 0);
	apdu.cla = 0x80;

	for (ii = 0, offs = 0; ii < sizeof(p1s); ii++)   {
		size_t oo;
		int jj;

		apdu.p1 = p1s[ii];
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;
		apdu.le = apdu.resplen > 256 ? 0x100 : apdu.resplen;

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
		const struct sc_security_env *senv, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	if (!senv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "laser_set_security_env() op:%X,flags:%X,algo:(%X,ref:%X,flags:%X)",
			senv->operation, senv->flags, senv->algorithm, senv->algorithm_ref, senv->algorithm_flags);
	*env = *senv;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_chv_secure_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char plain_text[16], sha1[SHA_DIGEST_LENGTH];
	unsigned char *encrypted = NULL;
	size_t encrypted_len;
	int rv, ii;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (!pin_cmd->pin1.data || !pin_cmd->pin1.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "null value not allowed for secure PIN verify");

	srand((unsigned)getpid() ^ (unsigned)time(NULL));
	for (ii=0; ii<8; ii++)
		plain_text[ii] = (unsigned char )(rand() & 0xFF);

	rv = iso_ops->get_challenge(card, plain_text + 8, 8);
	LOG_TEST_RET(ctx, rv, "Get card challenge failed");

	SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, sha1);

	sc_log(ctx, "key '%s'", sc_dump_hex(sha1, 16));
	sc_log(ctx, "plain text '%s'", sc_dump_hex(plain_text, 16));
	rv = sm_encrypt_des_cbc3(ctx, sha1, plain_text, 16, &encrypted, &encrypted_len, 1);
	LOG_TEST_RET(ctx, rv, "_encrypt_des_cbc3() failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, pin_cmd->pin_reference);
	apdu.cla = 0x80;
	apdu.data = encrypted;
	apdu.datalen = encrypted_len;
	apdu.lc = encrypted_len;

        rv = sc_transmit_apdu(card, &apdu);
        LOG_TEST_RET(ctx, rv, "APDU transmit failed");

        if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
        rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (encrypted)
		free(encrypted);
        LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *private_data = (struct laser_private_data *) card->drv_data;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (pin_cmd->pin1.data && !pin_cmd->pin1.len)   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_cmd->pin_reference);
	}
	else if (pin_cmd->pin1.data && pin_cmd->pin1.len)   {
		if (private_data->secure_verify)   {
			rv = laser_chv_secure_verify(card, pin_cmd, tries_left);
			LOG_FUNC_RETURN(ctx, rv);
		}
		else   {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_cmd->pin_reference);
			apdu.data = pin_cmd->pin1.data;
			apdu.datalen = pin_cmd->pin1.len;
			apdu.lc = pin_cmd->pin1.len;
		}
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
laser_pin_from_ko_le(struct sc_context *ctx, unsigned reference, unsigned *out)
{
	if (!out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (reference == 0x30)   {
		*out = 0x20;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_select_global_pin(struct sc_card *card, unsigned reference, struct sc_file **out_file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Select global PIN file %X", reference);

	sc_format_path("3F0000FF", &path);
	path.value[path.len - 1] = reference;

	rv = laser_select_file(card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Failed to select PIN file");

	if (file->prop_attr && (file->prop_attr_len >= 3) && (*(file->prop_attr + 2) == LASER_KO_ALGORITHM_LOGIC))   {
		unsigned ref;

		rv = laser_pin_from_ko_le(ctx, reference, &ref);
		LOG_TEST_RET(ctx, rv, "Unknown LogicalExpression KO");
		path.value[path.len - 1] = ref;

		sc_file_free(file);
		rv = laser_select_file(card, &path, &file);
		LOG_TEST_RET(ctx, rv, "Failed to select PIN file");
	}

	if (out_file)
		*out_file = file;
	else
		sc_file_free(file);

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

	if (type == SC_AC_AUT && reference == LASER_TRANSPORT_PIN1_REFERENCE)
		type = SC_AC_CHV;

	if (type == SC_AC_AUT)   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	else if (type == SC_AC_SCB)   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	else if (type == SC_AC_CHV)   {
		if (!(reference & 0x80))   {
			rv =  laser_select_global_pin(card, reference, NULL);
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

#if 0
	rv = laser_pin_is_verified(card, &pin_cmd, tries_left);
	if (data && !data_len)
		LOG_FUNC_RETURN(ctx, rv);

	if (rv != SC_ERROR_PIN_CODE_INCORRECT && rv != SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		LOG_FUNC_RETURN(ctx, rv);
#else
	if (data && !data_len)   {
		rv = laser_pin_is_verified(card, &pin_cmd, tries_left);
		 LOG_FUNC_RETURN(ctx, rv);
	}
#endif

	rv = laser_chv_verify(card, &pin_cmd, tries_left);
	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	LOG_FUNC_RETURN(ctx, rv);
}


#ifdef ENABLE_SM
static int
laser_sm_chv_change(struct sc_card *card, struct sc_pin_cmd_data *data, unsigned chv_ref,
		int *tries_left, unsigned op_acl)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *private_data =  (struct laser_private_data *) card->drv_data;
	struct sc_apdu apdu;
	unsigned char pin_data[SC_MAX_APDU_BUFFER_SIZE];
	size_t offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM change CHV(ref %i, length %i, op-acl %X)", chv_ref, data->pin2.len, op_acl);

	if (!data->pin2.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure needs new PIN defined");

	if ((unsigned)(data->pin2.len) > sizeof(pin_data))
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'SM change CHV' data");

	if (!private_data->sm_min_level)   {
		rv = laser_sm_open(card);
		LOG_TEST_RET(ctx, rv, "Cannot open SM");
	}

	card->sm_ctx.info.security_condition = op_acl;

	offs = 0;
	pin_data[offs++] = 0x62;
	pin_data[offs++] = data->pin2.len + 2;
	pin_data[offs++] = 0x81;
	pin_data[offs++] = data->pin2.len;
	memcpy(pin_data + offs, data->pin2.data, data->pin2.len);
	offs += data->pin2.len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, chv_ref);
	apdu.cla = 0x80;
	apdu.data = pin_data;
	apdu.datalen = offs;
	apdu.lc = offs;

        rv = sc_transmit_apdu(card, &apdu);
	if (!rv)
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if(!private_data->sm_min_level)
		laser_sm_close(card);

	card->sm_ctx.info.security_condition = 0;

	LOG_TEST_RET(ctx, rv, "SM change CHV failed");
	LOG_FUNC_RETURN(ctx, rv);
}
#else
#endif


static int
laser_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	struct sc_file *pin_file = NULL;
	unsigned char pin_data[SC_MAX_APDU_BUFFER_SIZE];
	unsigned chv_ref = data->pin_reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(type:%i,ref:%i,lengths:%i/%i)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (data->pin1.len)   {
		rv = laser_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_TEST_RET(ctx, rv, "Cannot verify old PIN");
	}

	if (!data->pin2.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing new PIN value");

	if ((unsigned)(data->pin2.len) > sizeof(pin_data))
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'Change PIN' data");

	if (data->pin_reference & 0x80)   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "TODO: local PINs");
	}
	else   {
		const struct sc_acl_entry *entry;

		rv =  laser_select_global_pin(card, data->pin_reference, &pin_file);
		LOG_TEST_RET(ctx, rv, "Select PIN file error");

		chv_ref = 0;
		entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_CHANGE);
		if (entry)   {
			if (entry->key_ref & 0xC000)   {
#ifdef ENABLE_SM
				rv = laser_sm_chv_change(card, data, chv_ref, tries_left, entry->key_ref);
				LOG_FUNC_RETURN(ctx, rv);
#else
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif /* ifdef ENABLE_SM */
			}
		}
	}

	memcpy(pin_data, data->pin1.data, data->pin1.len);
	memcpy(pin_data + data->pin1.len, data->pin2.data, data->pin2.len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, chv_ref);
	apdu.data = pin_data;
	apdu.datalen = data->pin1.len + data->pin2.len;
	apdu.lc = apdu.datalen;

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PIN change failed");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	struct sc_file *pin_file = NULL;
	unsigned chv_ref = data->pin_reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(type:%i,ref:%i,lengths:%i/%i)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (!(data->pin_reference & 0x80))   {
		const struct sc_acl_entry *entry;

		rv =  laser_select_global_pin(card, data->pin_reference, &pin_file);
		LOG_TEST_RET(ctx, rv, "Select PIN file error");

		if (data->pin1.len)   {
			entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_RESET);
			if (entry)   {
				sc_log(ctx, "Acl(PIN_RESET): %04X", entry->key_ref);
				if ((entry->key_ref & 0x00FF) == 0xFF)   {
					LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "Reset PIN not allowed");
				}
				else if (entry->key_ref & 0xC000)   {
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Reset PIN protectd by SM: not supported (TODO)");
				}
				else if (entry->key_ref & 0x00FF)   {
					rv = laser_pin_verify(card, SC_AC_CHV, entry->key_ref & 0x00FF, data->pin1.data, data->pin1.len, tries_left);
					LOG_TEST_RET(ctx, rv, "Verify PUK failed");

					rv =  laser_select_global_pin(card, data->pin_reference, &pin_file);
					LOG_TEST_RET(ctx, rv, "Select PIN file error");
				}
			}
		}

		chv_ref = 0;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 0, 0);
	apdu.cla = 0x80;

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PIN change failed");

	if (data->pin2.len)   {
		int save_len = data->pin1.len;

		data->pin1.len = 0;
		rv = laser_pin_change(card, data, tries_left);
		data->pin1.len = save_len;
		LOG_TEST_RET(ctx, rv, "Cannot set new PIN value");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "laser_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%i, PIN-2 %p:%i",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);
	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = laser_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_CHANGE:
		rv = laser_pin_change(card, data, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_UNBLOCK:
		rv = laser_pin_reset(card, data, tries_left);
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
	sc_log(ctx, "card laser serial '%s'", sc_dump_hex(sn.value, sn.len));
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_get_default_key(struct sc_card *card, struct sc_cardctl_default_key *data)
{
	struct sc_context *ctx = card->ctx;
	scconf_block *atrblock = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (!atrblock)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);

	if (data->method == SC_AC_AUT && data->key_ref == 1)   {
		const char *default_key = scconf_get_str(atrblock,
				"default_transport_pin1", LASER_TRANSPORT_PIN1_VALUE);

		rv = sc_hex_to_bin(default_key, data->key_data, &data->len);
		LOG_TEST_RET(ctx, rv,  "Cannot get trasnport PIN01 default value: HEX to BIN conversion error");

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);
}


static int
laser_generate_key(struct sc_card *card, struct sc_cardctl_laser_genkey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE], rbuf[2*SC_MAX_APDU_BUFFER_SIZE], *ptr = NULL;
	size_t offs, taglen;
	int rv;

	LOG_FUNC_CALLED(ctx);

	offs = 0;
	sbuf[offs++] = 0xAC;
	sbuf[offs++] = args->exponent_len + 6;
	sbuf[offs++] = 0x80;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = args->algorithm;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = args->exponent_len;
	memcpy(sbuf + offs, args->exponent, args->exponent_len);
	offs += args->exponent_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x47, 0x00, 0x00);
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	/* get modulus */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x81, &taglen);
	if (!ptr || (taglen != args->modulus_len))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid modulus data length");
	memcpy(args->modulus, ptr, taglen);

	/* get exponent */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x82, &taglen);
	if (!ptr || (taglen != args->exponent_len) || memcmp(ptr, args->exponent, taglen))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid exponent data");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_update_key(struct sc_card *card, struct sc_cardctl_laser_updatekey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, 0x00);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.cla = 0x80;
	apdu.datalen = args->len;
	apdu.data = args->data;
	apdu.lc = args->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return laser_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return laser_get_default_key(card, (struct sc_cardctl_default_key *)ptr);
	case SC_CARDCTL_ATHENA_GENERATE_KEY:
		sc_log(ctx, "CMD SC_CARDCTL_ATHENA_GENERATE_KEY");
		return laser_generate_key(card, (struct sc_cardctl_laser_genkey *) ptr);
	case SC_CARDCTL_ATHENA_UPDATE_KEY:
		sc_log(ctx, "SC_CARDCTL_ATHENA_UPDATE_KEY");
		return laser_update_key(card, (struct sc_cardctl_laser_updatekey *) ptr);
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
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE], rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_tlv_data tlv;
	int rv;
	size_t offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "in-length:%i, key-size:%i, out-length:%i", in_len, (prv->last_ko ? prv->last_ko->size : 0), out_len);
	if (env->operation != SC_SEC_OPERATION_DECIPHER)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "has to be SC_SEC_OPERATION_DECIPHER");
	else if (in_len > (sizeof(sbuf) - 4))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "invalid data length");

	offs = 0;
	sbuf[offs++] = 0x82;
	if (in_len >= 0x100)   {
		sbuf[offs++] = 0x82;
		sbuf[offs++] = in_len/0x100;
		sbuf[offs++] = in_len%0x100;
	}
	else   {
		sbuf[offs++] = 0x81;
		sbuf[offs++] = in_len;
	}
	memcpy(sbuf + offs, in, in_len);
	offs += in_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80,
			(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x0A : 0x0C);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = 256;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	rv = laser_tlv_parse(apdu.resp, apdu.resplen, &tlv);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	if (tlv.tag != 0x80)   {
		sc_log(ctx, "invalid decrypted data tag. response(%i) %s ...", apdu.resplen, sc_dump_hex(apdu.resp, 12));
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	if (tlv.len > out_len)   {
		sc_log(ctx, "PSO Decipher failed: response data too long: %i\n", tlv.len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}

	memcpy(out, tlv.value, tlv.len);
	LOG_FUNC_RETURN(ctx, tlv.len);
}


static int
laser_compute_signature_dst(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE], rbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char algo;
	int rv;
	size_t offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "in-length:%i, key-size:%i", in_len, (prv->last_ko != NULL ? prv->last_ko->size : 0));
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");
	else if (env->algorithm_flags & SC_ALGORITHM_RSA_RAW)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "RAW sign mechanism not supported");
	else if (prv->last_ko && in_len > (prv->last_ko->size - 11))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "too much of the input data");

	if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
		algo = 0x0A;	/* ALG_RSA_SHA_PKCS1 */
	else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)
		algo = 0x28;	/* ALG_RSA_SHA_256_PKCS1 */
	else
		algo = 0x8A;	/* ALG_RSA_PKCS1 */

	offs = 0;
	sbuf[offs++] = 0x80;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = in_len;
	memcpy(sbuf + offs, in, in_len);
	offs += in_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, algo);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = out_len > 256 ? 256 : out_len;
	apdu.resp = rbuf;
	apdu.resplen = out_len;

        rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	if (apdu.resplen > out_len)   {
		sc_log(ctx, "Compute signature failed: invalide response length %i\n", apdu.resplen);
		LOG_FUNC_RETURN(ctx, SC_ERROR_CARD_CMD_FAILED);
	}

	memcpy(out, apdu.resp, apdu.resplen);
	LOG_FUNC_RETURN(ctx, apdu.resplen);
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
	sc_log(ctx, "op:%x, inlen %i, outlen %i", env->operation, in_len, out_len);
	if (!card || !in || !out)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid compute signature arguments");

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return laser_compute_signature_dst(card, in, in_len, out,  out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return laser_compute_signature_at(card, in, in_len, out,  out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

/* SM functions */
#ifdef ENABLE_SM
static int
laser_sm_open(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sm_dh_session *dh_session = &card->sm_ctx.info.session.dh;
	struct sc_apdu apdu;
	BIGNUM *bn_ifd_y, *bn_N, *bn_g, *bn_icc_p;
	DH *dh;
	unsigned char uu, rbuf[SC_MAX_APDU_BUFFER_SIZE * 2];
	int rv, rd, dh_check;

	LOG_FUNC_CALLED(ctx);
	memset(&card->sm_ctx.info, 0, sizeof(card->sm_ctx.info));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x48, 0x00, 0x80);
	apdu.cla = 0x80;
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "'GET PUBLIC KEY' failed");

	dh_session->g.tag = LASER_SM_RSA_TAG_G;
	rv = laser_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->g);
	LOG_TEST_RET(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'g'");
	bn_g = BN_bin2bn(dh_session->g.value, dh_session->g.len, NULL);

	dh_session->N.tag = LASER_SM_RSA_TAG_N;
	rv = laser_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->N);
	LOG_TEST_RET(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'N'");
	bn_N = BN_bin2bn(dh_session->N.value, dh_session->N.len, NULL);

	dh_session->icc_p.tag = LASER_SM_RSA_TAG_ICC_P;
	rv = laser_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->icc_p);
	LOG_TEST_RET(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'ICC-P'");
	bn_icc_p = BN_bin2bn(dh_session->icc_p.value, dh_session->icc_p.len, NULL);

	dh_session->ifd_y.value = malloc(SHA_DIGEST_LENGTH);
	if (!dh_session->ifd_y.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	srand((unsigned)getpid() ^ (unsigned)time(NULL));
	rd = rand();
	SHA1((unsigned char *)(&rd), sizeof(rd), dh_session->ifd_y.value);
	dh_session->ifd_y.len = SHA_DIGEST_LENGTH;
	bn_ifd_y = BN_bin2bn(dh_session->ifd_y.value, dh_session->ifd_y.len, NULL);

	dh = DH_new();
	if (!dh)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate DH key");

	dh->p = bn_N;
	dh->g = bn_g;
	dh->priv_key = bn_ifd_y;

	if (!DH_check(dh, &dh_check))
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "OpenSSL 'DH-check' failed");
	if (!DH_generate_key(dh))
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "OpenSSL 'DH-generate-key' failed");

	dh_session->ifd_p.value=(unsigned char *)OPENSSL_malloc(BN_num_bytes(dh->pub_key));
	if (!dh_session->ifd_p.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	dh_session->ifd_p.len = BN_bn2bin(dh->pub_key, dh_session->ifd_p.value);

	dh_session->shared_secret.value=(unsigned char *)OPENSSL_malloc(DH_size(dh));
	if (!dh_session->shared_secret.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	dh_session->shared_secret.len = DH_compute_key(dh_session->shared_secret.value, bn_icc_p, dh);
	sc_log(ctx, "shared-secret(%i) %s", dh_session->shared_secret.len,
			sc_dump_hex(dh_session->shared_secret.value, dh_session->shared_secret.len));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x86, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.lc = dh_session->ifd_p.len;
	apdu.datalen = dh_session->ifd_p.len;
	apdu.data = dh_session->ifd_p.value;
	apdu.le = sizeof(dh_session->card_challenge);
	apdu.resplen = sizeof(dh_session->card_challenge);
	apdu.resp = dh_session->card_challenge;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "'OPEN SM' failed");

	memcpy(dh_session->session_enc, dh_session->shared_secret.value, sizeof(dh_session->session_enc));
	memcpy(dh_session->session_mac, dh_session->shared_secret.value + 24, sizeof(dh_session->session_mac));
	for (uu = 0; uu < sizeof(dh_session->session_enc); uu++)   {
		dh_session->session_enc[uu] ^= dh_session->card_challenge[uu];
		dh_session->session_mac[uu] ^= dh_session->card_challenge[16 + uu];
	}

	sc_log(ctx, "session key enc: %s", sc_dump_hex(dh_session->session_enc, 16));
	sc_log(ctx, "session key auth: %s", sc_dump_hex(dh_session->session_mac, 16));

	memset(dh_session->ssc, 0, sizeof(dh_session->ssc));
	card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;

	if (dh)
		DH_free(dh);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_sm_ignore(struct sc_apdu *apdu)
{
	if (apdu->cla == 0x00 && apdu->ins == 0xC0 && apdu->p1 == 0x00 && apdu->p2 == 0x00)
		return 1;
	return 0;
}


static int
laser_sm_wrap_apdu(struct sc_card *card, struct sc_apdu *in_apdu, struct sc_apdu **out_apdu)
{
	struct sc_context *ctx = card->ctx;
	struct laser_private_data *prv = (struct laser_private_data *) card->drv_data;
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	struct sc_apdu *apdu = NULL;
	int rv;
	int sm_level = prv->sm_min_level;

	LOG_FUNC_CALLED(ctx);
	if (!in_apdu || !out_apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	apdu = sc_sm_allocate_apdu(in_apdu);
	if (!apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	sc_log(ctx, "ACL 0x%X", card->sm_ctx.info.security_condition);
	if (card->sm_ctx.info.security_condition & LASER_SM_ACCESS_INPUT)
		sm_level = 3;

	if (sm_level == 3 && laser_sm_ignore(apdu))
		sm_level = 1;

	sc_log(ctx, "Using SM level %i", sm_level);
	if (sm_level == 3)   {
		unsigned char data[SC_MAX_APDU_BUFFER_SIZE * 2], *val = NULL;
		unsigned char edfb[SC_MAX_APDU_BUFFER_SIZE * 2];
		unsigned char chsum_data[SC_MAX_APDU_BUFFER_SIZE * 2];
		size_t offs, val_len, chsum_data_len;
		size_t edfb_len = 0;
		unsigned char icv[8];

		memset(icv, 0, sizeof(icv));
		memset(data, 0, sizeof(data));
		memset(edfb, 0, sizeof(edfb));
		memset(chsum_data, 0, sizeof(chsum_data));

		if (apdu->data && apdu->datalen)  {
			sc_log(ctx, "Data to Encrypt %s", sc_dump_hex(apdu->data, apdu->datalen));
			rv = sm_encrypt_des_cbc3(ctx, sess->session_enc, apdu->data, apdu->datalen, &val, &val_len, SC_SM_PADDING_MANDATORY);
		        LOG_TEST_RET(ctx, rv, "sm_encrypt_des_cbc3() failed");

			offs = 0;
			edfb[offs++] = 0x87;
			if ((val_len + 1) > 0x7F)
				edfb[offs++] = 0x81;
			edfb[offs++] = val_len + 1;
			edfb[offs++] = 0x01;
			memcpy(edfb + offs, val, val_len);
			offs += val_len;
			edfb_len = offs;

			sc_log(ctx, "edfb %s", sc_dump_hex(edfb, edfb_len));
			free(val);
		}

		offs = 0;
		sm_incr_ssc(sess->ssc, sizeof(sess->ssc));
		memcpy(chsum_data, sess->ssc, sizeof(sess->ssc));
		offs +=  sizeof(sess->ssc);

		chsum_data[offs++] = apdu->cla | 0x0C;
		chsum_data[offs++] = apdu->ins;
		chsum_data[offs++] = apdu->p1;
		chsum_data[offs++] = apdu->p2;
		chsum_data[offs++] = 0x80;
		chsum_data[offs++] = 0x00;
		chsum_data[offs++] = 0x00;
		chsum_data[offs++] = 0x00;

		if (edfb_len)  {
			memcpy(chsum_data + offs, edfb, edfb_len);
			offs += edfb_len;
		}

		if (in_apdu->le)   {
			chsum_data[offs++] = 0x97;
			chsum_data[offs++] = 0x01;
			chsum_data[offs++] = (in_apdu->le >= 0x100) ? 0 : in_apdu->le;
		}

		if (edfb_len || in_apdu->le)   {
			chsum_data[offs++] = 0x80;
			offs += 7;
			offs -=  (offs % 8);
		}

		chsum_data_len = offs;
		sc_log(ctx, "chsum_data(%i) %s", chsum_data_len, sc_dump_hex(chsum_data, chsum_data_len));

		rv = laser_cbc_cksum(ctx, sess->session_mac, sizeof(sess->session_mac), chsum_data, chsum_data_len, &icv);
		LOG_TEST_RET(ctx, rv, "Cannot get checksum CBC 3DES");

		offs = 0;
		memcpy(apdu->data, edfb, edfb_len);
		offs += edfb_len;

		if (in_apdu->le)   {
			*(apdu->data + offs++) = 0x97;
			*(apdu->data + offs++) = 0x01;
			*(apdu->data + offs++) = in_apdu->le & 0xFF;
		}

		*(apdu->data + offs++) = 0x8E;
		*(apdu->data + offs++) = 0x08;
		memcpy(apdu->data + offs, icv, 8);
		offs += 8;
		apdu->lc = offs;
		apdu->datalen = offs;

		apdu->cla |= 0x0C;
		apdu->cse = SC_APDU_CASE_4_SHORT;
	}

	*out_apdu = apdu;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_cbc_cksum(struct sc_context *ctx, unsigned char *key, size_t key_size,
		unsigned char *in, size_t in_len, DES_cblock *icv)
{
	DES_key_schedule ks, ks2;
	size_t len = in_len;
	DES_cblock out, last;
	int ii;

	if (!key || !in || !icv)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (in_len % 8)
		return SC_ERROR_INVALID_DATA;

	DES_set_key((const_DES_cblock*) &key[0], &ks);
	DES_set_key((const_DES_cblock*) &key[8], &ks2);

	sc_log(ctx, "data for checksum (%i) %s", in_len, sc_dump_hex(in, in_len));
	for (len = in_len; len > 8; len -= 8, in += 8)
		DES_ncbc_encrypt(in, out, 8, &ks, icv, DES_ENCRYPT);

	for(ii=0; ii < 8; ii++)
		last[ii] = *(in + ii) ^ (*icv)[ii];

	DES_ecb2_encrypt(&last, &out, &ks, &ks2, DES_ENCRYPT);
	memcpy(icv, &out, sizeof(*icv));

	sc_log(ctx, "cksum %s", sc_dump_hex((unsigned char *)icv, 8));
	return SC_SUCCESS;
}


static int
laser_sm_check_mac(struct sc_card *card, unsigned char *data, size_t data_len,
		unsigned char *mac, size_t mac_len)
{
	struct sc_context *ctx = card->ctx;
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	unsigned char icv[8], *dt =  NULL, *ptr;
	size_t dt_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(icv, 0, sizeof(icv));
	sm_incr_ssc(sess->ssc, sizeof(sess->ssc));

	/* Reserve place for SSC, data and padding. */
	dt_len = data_len + sizeof(sess->ssc) +  8;
	dt_len -= (dt_len % 8);
	ptr = dt = calloc(1, dt_len);
	if (!dt)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(ptr, sess->ssc, sizeof(sess->ssc));
	ptr += sizeof(sess->ssc);

	memcpy(ptr, data, data_len);
	ptr += data_len;

	/* Mandatory padding */
	*(ptr++) = 0x80;

	rv = laser_cbc_cksum(ctx, sess->session_mac, sizeof(sess->session_mac), dt, dt_len, &icv);
	LOG_TEST_RET(ctx, rv, "Cannot get checksum CBC 3DES");

	if (memcmp(mac, icv, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_INVALID_CHECKSUM);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_sm_free_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu)
{
	struct sc_context *ctx = card->ctx;
	struct sm_dh_session *dh_session = &card->sm_ctx.info.session.dh;
	struct sm_card_response sm_resp;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!apdu || !sm_apdu ||  !(*sm_apdu))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "unwrap resp %s", sc_dump_hex((*sm_apdu)->resp, (*sm_apdu)->resplen));
	memset(&sm_resp, 0, sizeof(sm_resp));
	rv = sc_sm_parse_answer(card, (*sm_apdu)->resp, (*sm_apdu)->resplen, &sm_resp);
	if (rv == SC_SUCCESS)   {
		unsigned char *out = NULL;
		size_t out_len = 0;

		(*sm_apdu)->sw1 = sm_resp.sw1;
		(*sm_apdu)->sw2 = sm_resp.sw2;

		if (sm_resp.mac_len)   {
			rv = laser_sm_check_mac(card, (*sm_apdu)->resp, (*sm_apdu)->resplen - 10, sm_resp.mac, sm_resp.mac_len);
			LOG_TEST_RET(ctx, rv, "Invalid checksum");
			(*sm_apdu)->mac_len = sm_resp.mac_len;
			memcpy((*sm_apdu)->mac, sm_resp.mac, sizeof(apdu->mac));
		}

		if (sm_resp.data_len)   {
			sc_log(ctx, "encrypted data (%i) %s", sm_resp.data_len, sc_dump_hex(sm_resp.data, sm_resp.data_len));
			if (sm_resp.data[0] != 0x01)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid padding indicator");
			rv = sm_decrypt_des_cbc3(ctx, dh_session->session_enc, sm_resp.data + 1, sm_resp.data_len - 1, &out, &out_len);
			LOG_TEST_RET(ctx, rv, "DES CBC3 decrypt error");
			sc_log(ctx, "decrypted data (%i) %s", out_len, sc_dump_hex(out, out_len));

			while (*(out + out_len - 1) != 0x80 && out_len > 0)
			       out_len--;
			if (!out_len)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "No padding in decrypted data");
			out_len--;

			memcpy((*sm_apdu)->resp, out, out_len);
			(*sm_apdu)->resplen = out_len;

			free(out);
		}
		(*sm_apdu)->resplen = out_len;
	}
	else {
		rv = sc_check_sw(card, (*sm_apdu)->sw1, (*sm_apdu)->sw2);
	}

	if (apdu->resplen < (*sm_apdu)->resplen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	apdu->resplen = (*sm_apdu)->resplen;
	memcpy(apdu->resp, (*sm_apdu)->resp, apdu->resplen);

	apdu->sw1 = (*sm_apdu)->sw1;
	apdu->sw2 = (*sm_apdu)->sw2;

	apdu->mac_len = (*sm_apdu)->mac_len;
	memcpy(apdu->mac, (*sm_apdu)->mac, sizeof(apdu->mac));

	sc_sm_free_apdu(*sm_apdu);
	*sm_apdu = NULL;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_sm_close(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);

	card->sm_ctx.sm_mode = SM_MODE_NONE;
        sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x86, 0xFF, 0xFF);
	apdu.cla = 0x80;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "'CLOSE SM' failed");

	memset(&card->sm_ctx.info, 0, sizeof(card->sm_ctx.info));
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif /* ifdef ENABLE_SM */

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
