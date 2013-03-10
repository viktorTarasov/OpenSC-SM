/*
 * laser.c: toolbox with procedures specific to Athena LASER on-card file system
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
#include "asn1.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "pkcs11/pkcs11.h"
#include "common/compat_strlcpy.h"
#include "laser.h"


#define C_ASN1_CREATE_RSA_KEY_SIZE 2
static struct sc_asn1_entry c_asn1_create_rsa_key[C_ASN1_CREATE_RSA_KEY_SIZE] = {
	/* tag 0x71 */
	{ "createRsaKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x11, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSA_PUB_COEFFICIENTS_SIZE 3
static struct sc_asn1_entry c_asn1_create_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE] = {
	/* tag 0x90 */
	{ "exponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x10, SC_ASN1_ALLOC, NULL, NULL },
	/* tag 0x91 */
	{ "modulus",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x11, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


#define C_ASN1_UPDATE_RSA_KEY_SIZE 2
static struct sc_asn1_entry c_asn1_update_rsa_key[C_ASN1_UPDATE_RSA_KEY_SIZE] = {
	/* tag 0x62 */
	{ "updateRsaKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x02, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSA_PRV_COEFFICIENTS_SIZE 6
static struct sc_asn1_entry c_asn1_create_rsa_prv_coefficients[C_ASN1_RSA_PRV_COEFFICIENTS_SIZE] = {
	/* tag 0x90 */
	{ "exponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x10, SC_ASN1_ALLOC, NULL, NULL },
	/* tag 0x91 */
	{ "modulus",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x11, SC_ASN1_ALLOC, NULL, NULL },
	/* tag 0x92 */
	{ "privateExponent",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x12, SC_ASN1_ALLOC, NULL, NULL },
	/* tag 0x93 */
	{ "privatePrimes",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x13, SC_ASN1_ALLOC, NULL, NULL },
	/* tag 0x94 */
	{ "privatePartialPrimes",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x14, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


struct laser_cka {
	unsigned long cka;
	unsigned char internal_cka;

	unsigned char *val;
	size_t len;
};


static int
laser_encode_pubkey_rsa(struct sc_context *ctx, struct sc_pkcs15_pubkey_rsa *key,
	unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_rsa_key[C_ASN1_CREATE_RSA_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_create_rsa_key, asn1_rsa_key);
	sc_format_asn1_entry(asn1_rsa_key + 0, asn1_rsa_pub_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_create_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, key->exponent.data, &key->exponent.len, 1);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, key->modulus.data, &key->modulus.len, 1);

	r = sc_asn1_encode(ctx, asn1_rsa_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding of RSA public key failed");

	return 0;
}

int
laser_encode_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key,
	       unsigned char **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return laser_encode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	return SC_ERROR_NOT_SUPPORTED;
}


static int
laser_encode_prvkey_rsa(struct sc_context *ctx, struct sc_pkcs15_prkey_rsa *key,
	unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_rsa_key[C_ASN1_UPDATE_RSA_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_coefficients[C_ASN1_RSA_PRV_COEFFICIENTS_SIZE];
	unsigned char *primes = NULL, *partial_primes = NULL;
	size_t primes_len = 0, partial_primes_len = 0;
	int r;

	primes = malloc(key->p.len + key->q.len);
	if (!primes)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(primes, key->p.data, key->p.len);
	memcpy(primes + key->p.len, key->q.data, key->q.len);
	primes_len =  key->p.len + key->q.len;

	partial_primes = malloc(key->dmp1.len + key->dmq1.len + key->iqmp.len);
	if (!partial_primes)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(partial_primes, key->dmp1.data, key->dmp1.len);
	memcpy(partial_primes + key->dmp1.len, key->dmq1.data, key->dmq1.len);
	memcpy(partial_primes + key->dmp1.len + key->dmq1.len, key->iqmp.data, key->iqmp.len);
	partial_primes_len = key->dmp1.len + key->dmq1.len + key->iqmp.len;

	sc_copy_asn1_entry(c_asn1_update_rsa_key, asn1_rsa_key);
	sc_format_asn1_entry(asn1_rsa_key + 0, asn1_rsa_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_create_rsa_prv_coefficients, asn1_rsa_coefficients);
	sc_format_asn1_entry(asn1_rsa_coefficients + 0, key->exponent.data, &key->exponent.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 1, key->modulus.data, &key->modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 2, key->d.data, &key->d.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 3, primes, &primes_len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 4, partial_primes, &partial_primes_len, 1);

	//sc_log(ctx, "Encoding modulus '%s'",sc_dump_hex(key->modulus.data, key->modulus.len));

	r = sc_asn1_encode(ctx, asn1_rsa_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding of RSA private key failed");

	free(primes);
	free(partial_primes);
	return SC_SUCCESS;
}


int
laser_encode_prvkey(struct sc_context *ctx, struct sc_pkcs15_prkey *key,
	       unsigned char **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return laser_encode_prvkey_rsa(ctx, &key->u.rsa, buf, len);
	return SC_ERROR_NOT_SUPPORTED;
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

	if (*(data + offs + 0) == 0x80)
		attr->cka = CKA_VENDOR_DEFINED + *(data + offs + 1);
	else
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
		return SC_ERROR_OUT_OF_MEMORY;
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
laser_add_attribute(unsigned char **buf, size_t *buf_sz, unsigned char flags,
		CK_ULONG cka, size_t cka_len, void *data)
{
	unsigned char *ptr = NULL;
	size_t offs = 0;

	if (!buf || !buf_sz)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = realloc(*buf, *buf_sz + cka_len + 5);
	if (!ptr)
		return SC_ERROR_OUT_OF_MEMORY;

	offs = *buf_sz;
	*(ptr + offs++) = (cka >> 8) & 0xFF;		/* cka type: 2 LSBs */
	*(ptr + offs++) = cka & 0xFF;
	*(ptr + offs++) = flags;
	*(ptr + offs++) = (cka_len >> 8) & 0xFF;	/* cka length: 2 bytes*/
	*(ptr + offs++) = cka_len & 0xFF;

	memset(ptr +  offs, 0, cka_len);
	if (data)
		memcpy(ptr + offs, (unsigned char *)data, cka_len);
	offs += cka_len;

	*buf = ptr;
	*buf_sz = offs;

	return SC_SUCCESS;
}


int
laser_attrs_cert_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_cert_info *info,
		unsigned char *data, size_t data_len)
{
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA;

	LOG_FUNC_CALLED(ctx);

	for (next = offs = 0; offs < data_len; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
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
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_VALUE:
			rv = _cka_get_blob(&attr, &info->value);
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
			info->authority = (*attr.val != 0);
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		}
	}

	if (info->value.len)   {
		/* TODO: get certificate authority:
		 * make the procedure 'sc_oberthur_get_certificate_authority' public and use it here.
		 */
		if (!info->id.len)   {
			struct sc_pkcs15_pubkey *pubkey = NULL;

			rv = sc_pkcs15_pubkey_from_cert(ctx, &info->value, &pubkey);
			LOG_TEST_RET(ctx, rv, "Cannot get public key from certificate data");

			SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, info->id.value);
			info->id.len = SHA_DIGEST_LENGTH;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_attrs_pubkey_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey_info *info,
		unsigned char *data, size_t data_len)
{
	//struct sc_pkcs15_pubkey_rsa key_rsa;
	struct sc_pkcs15_pubkey pub_key;
	struct sc_pkcs15_der der;
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA, have_public_key = 0;

	LOG_FUNC_CALLED(ctx);

	//memset(&key_rsa, 0, sizeof(key_rsa));
	memset(&pub_key, 0, sizeof(pub_key));

	for (next = offs = 0; offs < data_len; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
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
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				object->type = SC_PKCS15_TYPE_PUBKEY_RSA;
			else if (uval == CKK_EC)
				object->type = SC_PKCS15_TYPE_PUBKEY_EC;
			else if (uval == CKK_GOSTR3410)
				object->type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
			else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported public key type");
			break;
		case CKA_SUBJECT:
			break;
		case CKA_TRUSTED:
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		case CKA_ENCRYPT:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
			break;
		case CKA_WRAP:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
			break;
		case CKA_VERIFY:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
			break;
		case CKA_VERIFY_RECOVER:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
			break;
		case CKA_DERIVE:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			break;
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public key modulus");

			pub_key.algorithm = SC_ALGORITHM_RSA;
			if (attr.cka == CKA_MODULUS)  {
				pub_key.u.rsa.modulus.data = der.value;
				pub_key.u.rsa.modulus.len = der.len;
			}
			else   {
				pub_key.u.rsa.exponent.data = der.value;
				pub_key.u.rsa.exponent.len = der.len;
			}
			have_public_key = 1;
			break;
		case CKA_MODULUS_BITS:
			rv = _cka_get_unsigned(&attr, &info->modulus_length);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_MODULUS_BITS");
			break;
		case CKA_LOCAL:
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		default:
			sc_log(ctx, "Unknown CKA attribute: %X", attr.cka);
			break;
		}
	}

	if (have_public_key)   {
		rv = sc_pkcs15_encode_pubkey(ctx, &pub_key, &object->content.value, &object->content.len);
		LOG_TEST_RET(ctx, rv, "Cannot encode public key");
		sc_pkcs15_erase_pubkey(&pub_key);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_attrs_prvkey_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey_info *info,
		unsigned char *data, size_t data_len)
{
	struct sc_pkcs15_prkey_rsa key_rsa;
	struct sc_pkcs15_der der;
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA;

	LOG_FUNC_CALLED(ctx);

	memset(&key_rsa, 0, sizeof(key_rsa));

	for (next = offs = 0; offs < data_len; offs = next)   {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
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
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_TRUSTED:
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				object->type = SC_PKCS15_TYPE_PRKEY_RSA;
			else if (uval == CKK_EC)
				object->type = SC_PKCS15_TYPE_PRKEY_EC;
			else if (uval == CKK_GOSTR3410)
				object->type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
			else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported private key type");
			break;
		case CKA_SUBJECT:
			rv = _cka_get_blob(&attr, &info->subject);
			LOG_TEST_RET(ctx, rv, "Cannot set private key subject");
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_SENSITIVE:
			sc_log(ctx, "CKA_SENSITIVE: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_SENSITIVE : 0;
			break;
		case CKA_DECRYPT:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DECRYPT : 0;
			break;
		case CKA_UNWRAP:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_UNWRAP : 0;
			break;
		case CKA_SIGN:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGN : 0;
			break;
		case CKA_SIGN_RECOVER:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGNRECOVER : 0;
			break;
		case CKA_DERIVE:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DERIVE : 0;
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
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE : 0;
			break;
		case CKA_LOCAL:
			sc_log(ctx, "CKA_LOCAL: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_LOCAL : 0;
			break;
		case CKA_NEVER_EXTRACTABLE:
			sc_log(ctx, "CKA_NEVER_EXTRACTABLE: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE : 0;
			break;
		case CKA_ALWAYS_SENSITIVE:
			sc_log(ctx, "CKA_ALWAYS_SENSITIVE: %s", (*attr.val) ? "yes" : "no");

			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE : 0;
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		case CKA_MODIFIABLE:
			object->flags |= (*attr.val) ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0;
			sc_log(ctx, "CKA_MODIFIABLE: %X", *attr.val);
			break;
		default:
			sc_log(ctx, "Unknown CKA attribute: %X", attr.cka);
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_attach_cache_counter(unsigned char **buf, size_t *buf_sz)
{
	unsigned char *ptr = NULL;
	unsigned rand_val;

	if (!buf || !buf_sz)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = realloc(*buf, *buf_sz + 4);
	if (!ptr)
		return SC_ERROR_OUT_OF_MEMORY;

        srand((unsigned)time(NULL));
	rand_val = rand();
	*(ptr + *buf_sz + 0) = *(ptr + *buf_sz + 2) = rand_val & 0xFF;
	*(ptr + *buf_sz + 1) = *(ptr + *buf_sz + 3) = (rand_val >> 8) & 0xFF;

	*buf = ptr;
	*buf_sz += 4;

	return SC_SUCCESS;
}


int
laser_attrs_prvkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)object->data;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_PRIVATE_KEY;
	CK_BBOOL _true = TRUE, _false = FALSE, *flag;
	CK_KEY_TYPE type_rsa = CKK_RSA;
	CK_ULONG ffff = 0xFFFF;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

	data = malloc(7);
	if (!data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(CK_OBJECT_CLASS), &clazz);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_CLASS private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_TOKEN private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_PRIVATE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LABEL private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), &type_rsa);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_KEY_TYPE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SUBJECT, info->subject.len, info->subject.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SUBJECT private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ID private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_SENSITIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SENSITIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SENSITIVE private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_DECRYPT, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_DECRYPT private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_UNWRAP, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_UNWRAP private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_SIGN ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SIGN, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SIGN private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_SIGNRECOVER ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SIGN_RECOVER, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SIGN_RECOVER private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DERIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_DERIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_DERIVE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_START_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_START_DATE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_END_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_START_END private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_EXTRACTABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_EXTRACTABLE private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LOCAL, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LOCAL private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_NEVER_EXTRACTABLE private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ALWAYS_SENSITIVE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_GEN_MECHANISM, sizeof(CK_ULONG), &ffff);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_KEY_GEN_MECHANISM private key attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_MODIFIABLE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, 0x8010l, sizeof(CK_BBOOL), &_false);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA private key attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_counter(&data, &data_len);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA private key attribute");
	attrs_num++;

	sc_log(ctx, "Attributes(%i) '%s'",attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len)    {
		*out = data;
		*out_len = data_len;
	}
	else   {
		free(data);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_attrs_pubkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_pubkey pubkey;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_PUBLIC_KEY;
	CK_BBOOL _true = TRUE, _false = FALSE, *flag;
	CK_KEY_TYPE type_rsa = CKK_RSA;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

	pubkey.algorithm = SC_ALGORITHM_RSA;
	rv = sc_pkcs15_decode_pubkey(ctx, &pubkey, object->content.value, object->content.len);
	LOG_TEST_RET(ctx, rv, "Invalid public key data (object's content)");

	data = malloc(7);
	if (!data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(CK_OBJECT_CLASS), &clazz);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_CLASS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_TOKEN public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_PRIVATE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LABEL public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TRUSTED, sizeof(CK_BBOOL), &_false);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_TRUSTED public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), &type_rsa);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_KEY_TYPE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SUBJECT, info->subject.len, info->subject.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SUBJECT public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ID public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_ENCRYPT ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ENCRYPT, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ENCRYPT public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_WRAP ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_WRAP, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_WRAP public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_VERIFY ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VERIFY, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_VERIFY public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VERIFY_RECOVER, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_VERIFY_RECOVER public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DERIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_DERIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_DERIVE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_START_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_START_DATE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_END_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_START_END public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODULUS, pubkey.u.rsa.modulus.len, pubkey.u.rsa.modulus.data);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_MODULUS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODULUS_BITS, sizeof(CK_ULONG), &info->modulus_length);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_MODULUS_BITS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PUBLIC_EXPONENT, pubkey.u.rsa.exponent.len, pubkey.u.rsa.exponent.data);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_PUBLIC_EXPONENT public key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LOCAL, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LOCAL public key attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_MODIFIABLE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, 0x8010l, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA public key attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_counter(&data, &data_len);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA public key attribute");
	attrs_num++;

	sc_log(ctx, "Attributes(%i) '%s'",attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len)    {
		*out = data;
		*out_len = data_len;
	}
	else   {
		free(data);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_encode_update_key(struct sc_context *ctx, struct sc_pkcs15_prkey *prkey,
		struct sc_cardctl_laser_updatekey *update)
{
	int rv;

	if (!ctx || !prkey || !update)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);

	rv = laser_encode_prvkey(ctx, prkey, &update->data, &update->len);

	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_attrs_cert_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)object->data;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_BBOOL _true = TRUE, _false = FALSE, *flag;
	struct sc_pkcs15_cert *cert = NULL;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	size_t sha1_offs;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

        cert = malloc(sizeof(struct sc_pkcs15_cert));
	if (!cert)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memset(cert, 0, sizeof(struct sc_pkcs15_cert));

	rv = sc_pkcs15_read_certificate(p15card, info, &cert);
	LOG_TEST_RET(ctx, rv, "Cannot read/parse X509 certificate");

	data = malloc(7);
	if (!data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	memset(sha1, 0, sizeof(sha1));
	rv = laser_add_attribute(&data, &data_len, 0x00, 0x8013l, SHA_DIGEST_LENGTH, sha1);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA certificate attribute");
	attrs_num++;
	sha1_offs = data_len - SHA_DIGEST_LENGTH;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LABEL certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(CK_OBJECT_CLASS), &clazz);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_CLASS certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_TOKEN certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_false);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_PRIVATE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_LABEL certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VALUE, object->content.len, object->content.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_VALUE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CERTIFICATE_TYPE, sizeof(CK_CERTIFICATE_TYPE), &cert_type);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_CERTIFICATE_TYPE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ISSUER, cert->issuer_len, cert->issuer);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ISSUER certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SERIAL_NUMBER, cert->serial_len, cert->serial);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SERIAL_NUMBER certificate attribute");
	attrs_num++;

	flag = info->authority ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TRUSTED, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_TRUSTED certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SUBJECT, cert->subject_len, cert->subject);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_SUBJECT certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ID certificate attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_MODIFIABLE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, 0x8010l, sizeof(CK_BBOOL), &_true);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA certificate attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	SHA1(data, data_len, sha1);
	memcpy(data + sha1_offs, sha1, SHA_DIGEST_LENGTH);

	rv = laser_attach_cache_counter(&data, &data_len);
	LOG_TEST_RET(ctx, rv, "Failed to add CKA_ATHENA certificate attribute");
	attrs_num++;

	sc_log(ctx, "Attributes(%i) '%s'",attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len)    {
		*out = data;
		*out_len = data_len;
	}
	else   {
		free(data);
	}

	if (cert)
		sc_pkcs15_free_certificate(cert);
	LOG_FUNC_RETURN(ctx, rv);
}


int
laser_get_free_index(struct sc_pkcs15_card *p15card, unsigned int type)
{
	struct sc_context *ctx = p15card->card->ctx;
	int idx, ii, jj;

	LOG_FUNC_CALLED(ctx);

	if (type == SC_PKCS15_TYPE_CERT_X509)   {
		struct sc_pkcs15_object *cert_objs[32];
		int cert_num;

		cert_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, cert_objs, 32);
		LOG_TEST_RET(ctx, cert_num, "Failed to get certificate objects");

		for (ii=0; ii<0x100; ii++)   {
			for (jj=0; jj<cert_num; jj++)   {
				struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)cert_objs[jj]->data;

				sc_log(ctx, "found certificate %s", sc_print_path(&info->path));
				if (ii == info->path.value[info->path.len - 1])
					break;
			}
			if (jj == cert_num)
				break;
		}
		idx = ii;
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(ctx, idx);
}

