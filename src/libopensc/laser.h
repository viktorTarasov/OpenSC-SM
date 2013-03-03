/*
 * laser.h Support for Athena LASER cards
 *
 * Copyright (C) 2012 Athena
 *              Viktor Tarasov <viktor.tarasov@gmail.com>
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

#ifndef _OPENSC_LASER_H
#define _OPENSC_LASER_H

#include "libopensc/errors.h"
#include "libopensc/types.h"

#define LASER_TITLE "LASER"

#define LASER_KO_CLASS_SKEY	0x01
#define LASER_KO_CLASS_ECC	0x03
#define LASER_KO_CLASS_RSA	0x04
#define LASER_KO_CLASS_RSA_CRT	0x05

#define LASER_KO_USAGE_AUTH_EXT		0x01
#define LASER_KO_USAGE_AUTH_INT		0x02
#define LASER_KO_USAGE_SIGN		0x04
#define LASER_KO_USAGE_VERIFY		0x04
#define LASER_KO_USAGE_ENCRYPT		0x08
#define LASER_KO_USAGE_DECRYPT		0x08
#define LASER_KO_USAGE_KEY_AGREEMENT	0x80

#define LASER_KO_ALGORITHM_PIN		0x00
#define LASER_KO_ALGORITHM_BIOMETRIC	0x01
#define LASER_KO_ALGORITHM_LOGIC	0x0F
#define LASER_KO_ALGORITHM_TDES		0x10
#define LASER_KO_ALGORITHM_AES		0x11
#define LASER_KO_ALGORITHM_RSA		0x20
#define LASER_KO_ALGORITHM_ECC		0x30

#define LASER_KO_PADDING_NO		0x00
#define LASER_KO_PADDING_YES		0x01

#define LASER_FILE_DESCRIPTOR_EF	0x01
#define LASER_FILE_DESCRIPTOR_DF	0x38
#define LASER_FILE_DESCRIPTOR_DO	0x39
#define LASER_FILE_DESCRIPTOR_KO	0x08

#define LASER_KO_DATA_TAG_RSA	0x71

#define LASER_PIV_ALGO_RSA_1024		0x06
#define LASER_PIV_ALGO_RSA_2048		0x07
#define LASER_PIV_ALGO_ECC_FP224	0x0E
#define LASER_PIV_ALGO_ECC_FP256	0x11

#define LASER_SM_RSA_TAG_G      0x80
#define LASER_SM_RSA_TAG_N      0x81
#define LASER_SM_RSA_TAG_ICC_P  0x82

#define LASER_SM_ACCESS_INPUT   0x4000
#define LASER_SM_ACCESS_OUTPUT  0x8000

#define LASER_FS_REF_MASK	0x3F
#define LASER_FS_BASEFID_PUBKEY         0x0080
/* TODO: Private key can have different 'BASEFID's */
#define LASER_FS_BASEFID_PRVKEY         0x0040

#define LASER_ATTRIBUTE_VALID	0
#define LASER_ATTRIBUTE_INVALID	1

#define LASER_FS_KEY_REF_MIN	0x01
#define LASER_FS_KEY_REF_MAX	0x1E

#define LASER_FS_ATTR_REF_MIN	0x00
#define LASER_FS_ATTR_REF_MAX	0x1D

#define CKA_ATHENA	0x80000010

struct sc_cardctl_laser_genkey {
	unsigned char algorithm;

	unsigned char *exponent;
	size_t exponent_len;

	unsigned char *modulus;
	size_t modulus_len;
};

struct sc_cardctl_laser_updatekey {
	unsigned char *data;
	size_t len;
};

int laser_encode_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key,
		unsigned char **buf, size_t *len);

int laser_attrs_cert_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_cert_info *info, unsigned char *data, size_t data_len);
int laser_attrs_prvkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey_info *info, unsigned char *data, size_t data_len);
int laser_attrs_pubkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey_info *info, unsigned char *data, size_t data_len);

int laser_data_prvkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int laser_data_pubkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);

int laser_encode_update_key(struct sc_context *ctx, struct sc_pkcs15_prkey *prkey,
		struct sc_cardctl_laser_updatekey *update_data);

#endif
