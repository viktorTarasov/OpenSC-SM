/*
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
/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008*/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"

#include "vsctpm-md.h"

#define MANU_ID	"VSC TPM"
#define VSCTPM_USER_PIN_REF 0x80

int sc_pkcs15emu_vsctpm_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int
vsctpm_detect_card( struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);

	/* check if we have the correct card OS */
	if (p15card->card->type != SC_CARD_TYPE_VSCTPM_GENERIC)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_add_user_pin (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_auth_info auth_info;
        struct sc_pkcs15_object   obj;
	int rv, tries_left;

	LOG_FUNC_CALLED(ctx);

        tries_left = -1;
/*
        rv = sc_verify(card, SC_AC_CHV, VSCTPM_USER_PIN_REF, (unsigned char *)"", 0, &tries_left);
        if (rv && rv != SC_ERROR_PIN_CODE_INCORRECT)
		LOG_TEST_RET(ctx, rv, "Invalid state 'User PIN' object");
*/
        /* add PIN */
        memset(&auth_info, 0, sizeof(auth_info));
        memset(&obj,  0, sizeof(obj));

        auth_info.auth_type	= SC_PKCS15_PIN_AUTH_TYPE_PIN;
        auth_info.auth_method   = SC_AC_CHV;
        auth_info.auth_id.len = 1;
        auth_info.auth_id.value[0] = 1;
        auth_info.attrs.pin.min_length          = 8;
        auth_info.attrs.pin.max_length          = 15;
        auth_info.attrs.pin.stored_length       = 8;
        auth_info.attrs.pin.type                = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
        auth_info.attrs.pin.reference           = VSCTPM_USER_PIN_REF;
        auth_info.attrs.pin.flags               = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL;
        auth_info.tries_left            = tries_left;

        strncpy(obj.label, "User PIN", SC_PKCS15_MAX_LABEL_SIZE-1);
        obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

        sc_log(ctx, "Add PIN object '%s', auth_id:%s,reference:%i", obj.label, sc_pkcs15_print_id(&auth_info.auth_id), auth_info.attrs.pin.reference);
        rv = sc_pkcs15emu_add_pin_obj(p15card, &obj, &auth_info);
        LOG_TEST_RET(ctx, rv, "VSC TPM init failed: cannot add User PIN object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
  6C0065002D00320038006200390034003700390061002D0038006600350030002D0034003600380063002D0062003700620034002D006600300036003300660065003400630033003700330035000000
  03
  00
  0000
  0008
*/
#if ENABLE_MINIDRIVER

static int
sc_pkcs15emu_vsctpm_enum_containers (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	unsigned char *buf = NULL;
	size_t buf_len = 0;
	struct vsctpm_md_container mdc;
	int    rv, idx, nn_cont;

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_md_cmap_size(card);
	LOG_TEST_RET(ctx, rv, "CMAP cannot get size");
	nn_cont = rv;
	sc_log(ctx, "CMAP length %i", nn_cont);

	for (idx=0; idx < nn_cont; idx++)   {
		rv = vsctpm_md_cmap_get_container(card, idx, &mdc);
		if (rv == SC_ERROR_OBJECT_NOT_FOUND)
			continue;
		LOG_TEST_RET(ctx, rv, "Get MD container error");
		sc_log(ctx, "cmap-record %i: flags %X, sizes %i/%i, blobs %i/%i", idx, mdc.rec.bFlags,
				mdc.rec.wSigKeySizeBits, mdc.rec.wKeyExchangeKeySizeBits, mdc.info.cbSigPublicKey, mdc.info.cbKeyExPublicKey);

		if (mdc.info.cbKeyExPublicKey && mdc.info.pbKeyExPublicKey)   {
			char k_name[6];

			sc_log(ctx, "PubKeyEx %s", sc_dump_hex(mdc.info.pbKeyExPublicKey, mdc.info.cbKeyExPublicKey));

			snprintf((char *)k_name, sizeof(k_name), "kxc%02i", idx);
			rv = vsctpm_md_read_file(card, szBASE_CSP_DIR, k_name, &mdc.cert_x.value, &mdc.cert_x.len);
			LOG_TEST_RET(ctx, rv, "Cannot read exchange certificate");

			sc_log(ctx, "PubKeyEx %s", sc_dump_hex(mdc.cert_x.value, mdc.cert_x.len));
		}

		if (mdc.info.cbSigPublicKey && mdc.info.pbSigPublicKey)   {
			char k_name[6];

			sc_log(ctx, "PubSig %s", sc_dump_hex(mdc.info.pbSigPublicKey, mdc.info.cbSigPublicKey));

			snprintf((char *)k_name, sizeof(k_name), "ksc%02i", idx);
			rv = vsctpm_md_read_file(card, szBASE_CSP_DIR, k_name, &mdc.cert_s.value, &mdc.cert_s.len);
			LOG_TEST_RET(ctx, rv, "Cannot read sign certificate");

			sc_log(ctx, "PubKeySign %s", sc_dump_hex(mdc.cert_s.value, mdc.cert_s.len));
		}


		/* 06 02 0000 00A40000 52534131 00080000 01000100 9D248A42CBF71DD0BCAD2893F3F212E71CC162FC51CEE431 ... */
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_enum_files (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	unsigned char *buf = NULL;
	size_t buf_len = 0;
	int    rv;

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_md_enum_files(card, szBASE_CSP_DIR, &buf, &buf_len);
        LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	vsctpm_md_free(card, buf);
	buf = NULL, buf_len = 0;

	rv = vsctpm_md_enum_files(card, "", &buf, &buf_len);
        LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	vsctpm_md_free(card, buf);
	buf = NULL, buf_len = 0;

/*
	if (p15card->md_data)   {
		if (p15card->md_data->cmaps)
			free(p15card->md_data->cmaps);
		free(p15card->md_data);
	}

	mdd = p15card->md_data = calloc(1, sizeof(p15card->md_data));
	if (!mdd)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	for (ptr = buf; (ptr-buf) < buf_len; )   {
		struct sc_md_cmap_record *cmap = NULL;
		mdd->cmaps = realloc(mdd->cmaps, (mdd->cmaps_num + 1) * (sizeof(sc_md_cmap_record)));
		if (!mdd->cmaps)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		cmap = mdd->cmaps + mdd->cmaps_num;


		mdd->cmaps_num  += 1;
	}
*/

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif /* ENABLE_MINIDRIVER */


static int
sc_pkcs15emu_vsctpm_init (struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_serial_number serial;
	char   buf[256];
	int    rv;

	LOG_FUNC_CALLED(ctx);

	/* get serial number */
	rv = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	LOG_TEST_RET(ctx, rv, "Cannot get serial nomber");

	rv = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (rv != SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	if (p15card->tokeninfo->serial_number)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = malloc(strlen(buf) + 1);
	if (!p15card->tokeninfo->serial_number)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->serial_number, buf);

	if (p15card->tokeninfo->manufacturer_id)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = malloc(strlen(MANU_ID) + 1);
	if (!p15card->tokeninfo->manufacturer_id)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	strcpy(p15card->tokeninfo->manufacturer_id, MANU_ID);

	if (!p15card->tokeninfo->label)
		p15card->tokeninfo->label = strdup(card->reader->friendly_name);

	rv = vsctpm_add_user_pin (p15card);
	LOG_TEST_RET(ctx, rv, "Failed to add User PIN object");

#if ENABLE_MINIDRIVER
	rv = sc_pkcs15emu_vsctpm_enum_files (p15card);
	LOG_TEST_RET(ctx, rv, "Cannot enum MD files");

	rv = sc_pkcs15emu_vsctpm_enum_containers (p15card);
	LOG_TEST_RET(ctx, rv, "Cannot parse CMAP file");
#endif

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15emu_vsctpm_init_ex(struct sc_pkcs15_card *p15card, struct sc_pkcs15emu_opt *opts)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_vsctpm_init(p15card);

	rv = vsctpm_detect_card(p15card);
	if (rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	return sc_pkcs15emu_vsctpm_init(p15card);
}
