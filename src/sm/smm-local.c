/*
 * smm-local.c: Secure Messaging 'local' module
 *
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
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "libopensc/iasecc.h"

#include "sm-module.h"

const unsigned char CardManagerAID[7] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00};

const unsigned char host_serial[8] = "\x11\x22\x33\x44\x55\x66\x77\x88";

void * sc_module_init(char *name);
char *sc_driver_version(void);

static char *version = "0.0.1";

void * 
sc_module_init(char *name)
{
	printf("Initialize SM module %s\n", name);
	return NULL;
}


char *
sc_driver_version(void)
{
	return version;
}


static int
sm_gp_config_get_keyset(struct sc_context *ctx, struct sm_info *sm_info)
{
	scconf_block *sm_conf_block = NULL, **blocks;
	const char *kmc = NULL;
	unsigned char hex[48];		
	size_t hex_len = sizeof(hex);
	int rv, ii;

	sc_log(ctx, "SM get KMC from config section '%s'", sm_info->module_name);
        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->module_name);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}
	                       
		if (sm_conf_block)
			break;
	}

	kmc = scconf_get_str(sm_conf_block, "kmc", NULL);
	if (!kmc)
		return SC_ERROR_SM_KEYSET_NOT_FOUND;

	rv = sc_hex_to_bin(kmc, hex, &hex_len);
	if (rv)   {		
		sc_log(ctx, "SM get KMC: hex to bin failed for '%s'; error %i", kmc, rv);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
		
	sc_log(ctx, "SM type:%X, KMC(%i) %s", sm_info->sm_type, hex_len, sc_dump_hex(hex, hex_len));
	if (hex_len != 16 && hex_len != 48 )
		return SC_ERROR_INVALID_DATA;

	memcpy(sm_info->schannel.keyset.gp.kmc, hex, hex_len);
	sm_info->schannel.keyset.gp.kmc_len = hex_len;

	return SC_SUCCESS;
}


static int
sm_cwa_config_get_keyset(struct sc_context *ctx, struct sm_info *sm_info)
{
	struct sm_cwa_session *session_data = &sm_info->schannel.session.cwa;
	scconf_block *sm_conf_block = NULL, **blocks;
	struct sc_crt *crt_at = &sm_info->sm_params.cwa.crt_at;
	const char *value = NULL;
	char name[128];
	unsigned char hex[48];
	size_t hex_len = sizeof(hex);
	int rv, ii, ref = crt_at->refs[0] & IASECC_OBJECT_REF_MAX;

        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->module_name);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}
	                       
		if (sm_conf_block)
			break;
	}

	sc_log(ctx, "CRT(algo:%X,ref:%X)", crt_at->algo, crt_at->refs[0]);
	/* Keyset ENC */
	if (sm_info->current_aid.len && (crt_at->refs[0] & IASECC_OBJECT_REF_LOCAL))
		snprintf(name, sizeof(name), "keyset_%s_%02i_enc", 
				sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len), ref);
	else
		snprintf(name, sizeof(name), "keyset_%02i_enc", ref);
	value = scconf_get_str(sm_conf_block, name, NULL);
	if (!value)   {
		sc_log(ctx, "No %s value in OpenSC config", name);
		return SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_log(ctx, "keyset::enc(%i) %s", strlen(value), value);
	if (strlen(value) == 16)   {
		memcpy(sm_info->schannel.keyset.cwa.enc, value, 16);
	}
	else   {
		hex_len = sizeof(hex);
		rv = sc_hex_to_bin(value, hex, &hex_len);
		if (rv)   {		
			sc_log(ctx, "SM get %s: hex to bin failed for '%s'; error %i", name, value, rv);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_log(ctx, "ENC(%i) %s", hex_len, sc_dump_hex(hex, hex_len));
		if (hex_len != 16)
			return SC_ERROR_INVALID_DATA;
	
		memcpy(sm_info->schannel.keyset.cwa.enc, hex, hex_len);
	}
	sc_log(ctx, "%s %s", name, sc_dump_hex(sm_info->schannel.keyset.cwa.enc, 16));

	/* Keyset MAC */
	if (sm_info->current_aid.len && (crt_at->refs[0] & IASECC_OBJECT_REF_LOCAL))
		snprintf(name, sizeof(name), "keyset_%s_%02i_mac", 
				sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len), ref);
	else
		snprintf(name, sizeof(name), "keyset_%02i_mac", ref);
	value = scconf_get_str(sm_conf_block, name, NULL);
	if (!value)   {
		sc_log(ctx, "No %s value in OpenSC config", name);
		return SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_log(ctx, "keyset::mac(%i) %s", strlen(value), value);
	if (strlen(value) == 16)   {
		memcpy(sm_info->schannel.keyset.cwa.mac, value, 16);
	}
	else   {
		hex_len = sizeof(hex);
		rv = sc_hex_to_bin(value, hex, &hex_len);
		if (rv)   {		
			sc_log(ctx, "SM get '%s': hex to bin failed for '%s'; error %i", name, value, rv);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_log(ctx, "MAC(%i) %s", hex_len, sc_dump_hex(hex, hex_len));
		if (hex_len != 16)
			return SC_ERROR_INVALID_DATA;
	
		memcpy(sm_info->schannel.keyset.cwa.mac, hex, hex_len);
	}
	sc_log(ctx, "%s %s", name, sc_dump_hex(sm_info->schannel.keyset.cwa.mac, 16));

	sm_info->schannel.keyset.cwa.sdo_reference = crt_at->refs[0];


	/* IFD parameters */
	memset(session_data, 0, sizeof(struct sm_cwa_session));
	value = scconf_get_str(sm_conf_block, "ifd_serial", NULL);
	if (!value)
		return SC_ERROR_SM_IFD_DATA_MISSING;
	hex_len = sizeof(hex);
	rv = sc_hex_to_bin(value, hex, &hex_len);
	if (rv)   {		
		sc_log(ctx, "SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	if (hex_len != sizeof(session_data->ifd.sn))   {
		sc_log(ctx, "SM get 'ifd_serial': invalid IFD serial length: %i", hex_len);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	
	memcpy(session_data->ifd.sn, hex, hex_len);

        rv = RAND_bytes(session_data->ifd.rnd, 8);
        if (!rv)   {
		sc_log(ctx, "Generate random error: %i", rv);
		return SC_ERROR_SM_RAND_FAILED;
	}

        rv = RAND_bytes(session_data->ifd.k, 32);
        if (!rv)   {
		sc_log(ctx, "Generate random error: %i", rv);
		return SC_ERROR_SM_RAND_FAILED;
	}
	sc_log(ctx, "IFD.Serial: %s", sc_dump_hex(session_data->ifd.sn, sizeof(session_data->ifd.sn)));
	sc_log(ctx, "IFD.Rnd: %s", sc_dump_hex(session_data->ifd.rnd, sizeof(session_data->ifd.rnd)));
	sc_log(ctx, "IFD.K: %s", sc_dump_hex(session_data->ifd.k, sizeof(session_data->ifd.k)));

	return SC_SUCCESS;
}


int 
initialize(struct sc_context *ctx, struct sm_info *sm_info, 
		struct sc_remote_data *out)
{
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "Current AID: %s", sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len));
	switch (sm_info->sm_type)   {
	case SM_TYPE_GP_SCP01:
		rv = sm_gp_config_get_keyset(ctx, sm_info);
		LOG_TEST_RET(ctx, rv, "SM gp configuration error");
		rv = sm_gp_initialize(ctx, sm_info, out);
		LOG_TEST_RET(ctx, rv, "SM gp initializing error");
		break;
	case SM_TYPE_CWA14890:
		rv = sm_iasecc_config_get_keyset(ctx, sm_info);
		LOG_TEST_RET(ctx, rv, "SM iasecc configuration error");
		rv = sm_iasecc_initialize(ctx, sm_info, out);
		LOG_TEST_RET(ctx, rv, "SM iasecc initializing error");
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported SM type");
	};

	LOG_FUNC_RETURN(ctx, rv);
}


int
get_apdus(struct sc_context *ctx, struct sm_info *sm_info, unsigned char *init_data, size_t init_len, 
		struct sc_remote_data *out)
{
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get APDUs: out:%p", out);
	sc_log(ctx, "SM get APDUs: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));

	if (sm_info->card_type == SC_CARD_TYPE_OBERTHUR_AUTHENTIC_3_2)   {
		rv = sm_authentic_get_apdus(ctx, sm_info, init_data, init_len, out, 1);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: failed for AuthentIC");
	}
	else if (sm_info->card_type/10*10 == SC_CARD_TYPE_IASECC_BASE)   {
		rv = sm_iasecc_get_apdus(ctx, sm_info, init_data, init_len, out, 1);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: failed for IAS/ECC");
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "SM get APDUs: unsupported card type");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
finalize(struct sc_context *ctx, struct sm_info *sm_info, char *str_data, unsigned char *out, size_t out_len)
{
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM finalize: buffer length %i for decoded card response of %i bytes length", out_len, strlen(str_data));
	if (!str_data || strlen(str_data) == 0)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (sm_info->sm_type == SM_TYPE_GP_SCP01)
		rv = sm_gp_decode_card_answer(ctx, str_data, out, out_len);
	else if (sm_info->card_type/10*10 == SC_CARD_TYPE_IASECC_BASE)
		rv = sm_iasecc_decode_card_data(ctx, sm_info, str_data, out, out_len);
	else
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "SM finalize: cannot decode card response(s)");

	LOG_FUNC_RETURN(ctx, rv);
}


int 
module_init(struct sc_context *ctx, char *data)
{

	sc_log(ctx, "Module init data '%s'", data);
	return SC_SUCCESS;

}


int 
module_cleanup(struct sc_context *ctx)
{
	sc_log(ctx, "Module cleanup: TODO");
	return SC_SUCCESS;
}


int
callback_sm_test(struct sc_context *ctx, struct sm_info *info, char *out, size_t *out_len)
{
	sc_log(ctx, "Test");
	return SC_SUCCESS;
}


