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
	unsigned char sopin_reference = 0x04;

	LOG_FUNC_CALLED(ctx);

        tries_left = -1;
        rv = sc_verify(card, SC_AC_CHV, VSCTPM_USER_PIN_REF, (unsigned char *)"", 0, &tries_left);
        if (rv && rv != SC_ERROR_PIN_CODE_INCORRECT)
		LOG_TEST_RET(ctx, rv, "Invalid state 'User PIN' object");

        /* add PIN */
        memset(&auth_info, 0, sizeof(auth_info));
        memset(&obj,  0, sizeof(obj));

        auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
        auth_info.auth_method   = SC_AC_CHV;
        auth_info.auth_id.len = 1;
        auth_info.auth_id.value[0] = 1;
        auth_info.attrs.pin.min_length          = 8;
        auth_info.attrs.pin.max_length          = 8;
        auth_info.attrs.pin.stored_length       = 8;
        auth_info.attrs.pin.type                = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
        auth_info.attrs.pin.reference           = VSCTPM_USER_PIN_REF;
        auth_info.attrs.pin.pad_char            = 0xFF;
        auth_info.attrs.pin.flags               = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
                                | SC_PKCS15_PIN_FLAG_INITIALIZED
                                | SC_PKCS15_PIN_FLAG_NEEDS_PADDING
                                | SC_PKCS15_PIN_FLAG_SO_PIN;
        auth_info.tries_left            = tries_left;

        strncpy(obj.label, "User PIN", SC_PKCS15_MAX_LABEL_SIZE-1);
        obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

        sc_log(ctx, "Add PIN object '%s', auth_id:%s,reference:%i", obj.label, sc_pkcs15_print_id(&auth_info.auth_id), auth_info.attrs.pin.reference);
        rv = sc_pkcs15emu_add_pin_obj(p15card, &obj, &auth_info);
        LOG_TEST_RET(ctx, rv, "VSC TPM init failed: cannot add User PIN object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}



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
