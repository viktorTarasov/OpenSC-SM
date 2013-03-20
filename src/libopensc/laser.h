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

#define CKA_ATHENA	0x80000010l
#define CKA_CERT_HASH	0x80000013l

#define CKFP_CANNOT_REVEAL		0x01l
#define CKFP_ONLY_SO_CAN_SET		0x02l
#define CKFP_READ_ONLY			0x04l
#define CKFP_MODIFIABLE			0x10l
#define CKFP_MODIFIABLE_TO_TRUE		0x30l
#define CKFP_MODIFIABLE_TO_FALSE	0x50l

/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN	39
 * #define CONTAINER_MAP_VALID_CONTAINER	1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER	2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *	WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *	BYTE bFlags;
 *	BYTE bReserved;
 *	WORD wSigKeySizeBits;
 *	WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
#define CMAP_FID	0x867F
#define CMAP_GUID_INFO_SIZE	80
#define CMAP_FLAG_CONTAINER_VALID	0x01
#define CMAP_FLAG_CONTAINER_DEFAULT	0x02

struct laser_cmap_record {
	/* original MD fields */
	unsigned char guid[CMAP_GUID_INFO_SIZE]; /* 40 x sizeof unicode chars */
	unsigned char flags;
	unsigned char reserved;
	unsigned short key_size_sign;
	unsigned short key_size_keyexchange;

	/* PKCS#11 helper fields */
	/* actual ASCII CKA_ID length (in unicode chars) */
	unsigned short guid_len;

	/* DF - DS/PKI + MSB in lower byte == 1 (0x80) if we use our
	 * Conversion to Unicode with MSB on in any byte */
	unsigned short rfu;
};

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

int laser_get_free_index(struct sc_pkcs15_card *p15card, unsigned int type);

int laser_encode_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key,
		unsigned char **buf, size_t *len);

int laser_attrs_cert_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_cert_info *info, unsigned char *data, size_t data_len);
int laser_attrs_prvkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey_info *info, unsigned char *data, size_t data_len);
int laser_attrs_pubkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey_info *info, unsigned char *data, size_t data_len);
int laser_attrs_data_object_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_data_info *info, unsigned char *data, size_t data_len);

int laser_attrs_prvkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int laser_attrs_pubkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int laser_attrs_cert_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int laser_attrs_data_object_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);

int laser_encode_update_key(struct sc_context *ctx, struct sc_pkcs15_prkey *prkey,
		struct sc_cardctl_laser_updatekey *update_data);

#endif
