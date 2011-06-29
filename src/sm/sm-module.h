/*
 * sm-module.h: Support for the external Secure Messaging module for
 *               IAS/ECC and 'AuthentIC v3' cards
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

#ifndef _SM_MODULE_H
#define _SM_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/des.h>
#include <openssl/sha.h>

#include "libopensc/sm.h"

DES_LONG DES_cbc_cksum_3des(const unsigned char *in, DES_cblock *output, long length, 
		DES_key_schedule *schedule, DES_key_schedule *schedule2, const_DES_cblock *ivec);
DES_LONG DES_cbc_cksum_3des_emv96(const unsigned char *in, DES_cblock *output,
		long length, DES_key_schedule *schedule, DES_key_schedule *schedule2,
		const_DES_cblock *ivec);
int sm_encrypt_des_ecb3(unsigned char *key, unsigned char *data, int data_len,
		unsigned char **out, int *out_len);
int sm_encrypt_des_cbc3(struct sc_context *ctx, unsigned char *key, 
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int 
		not_force_pad);
int sm_decrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		unsigned char *data, size_t data_len, unsigned char **out, size_t *out_len);

/* Global Platform definitions */
int sm_gp_get_mac(unsigned char *key, DES_cblock *icv, unsigned char *in, int in_len, 
		DES_cblock *out);
int sm_gp_get_cryptogram(unsigned char *session_key, unsigned char *left, unsigned char *right,
		unsigned char *out, int out_len);
int sm_gp_external_authentication(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len,
		struct sc_remote_data *out,
		int (*diversify_keyset)(struct sc_context *ctx, struct sm_info *sm_info,
			unsigned char *idata, size_t idata_len));
int sm_gp_initialize(struct sc_context *ctx, struct sm_info *sm_info,
		struct sc_remote_data *out);
int sm_gp_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_apdu *apdu);
int sm_gp_decode_card_answer(struct sc_context *ctx, char *str_data,
		unsigned char *out, size_t out_len);
void sm_gp_close_session(struct sc_context *ctx, struct sm_secure_channel *sc);


/* CWA-14890 helper functions */
int sm_cwa_initialize(struct sc_context *ctx, struct sm_info *sm_info, char *out, size_t *out_len);
int sm_cwa_get_apdus(struct sc_context *ctx, struct sm_info *sm_info, 
		unsigned char *init_data, size_t init_len, struct sc_remote_data *out, int release_sm);
int sm_cwa_decode_card_data(struct sc_context *ctx, struct sm_info *sm_info, char *str_data,
		unsigned char *out, size_t out_len);

/* SM AuthentIC v3 definitions */
int sm_authentic_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *out, int release_sm);
#ifdef __cplusplus
}
#endif

#endif

