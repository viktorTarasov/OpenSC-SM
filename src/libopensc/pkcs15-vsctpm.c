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

#define MANU_ID	"vsctpm"

int sc_pkcs15emu_vsctpm_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int
vsctpm_detect_card( struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);

	/* check if we have the correct card OS */
	if (strcmp(p15card->card->name, "vsctpm"))
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_vsctpm_init( struct sc_pkcs15_card *p15card)
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

	/* the manufacturer ID, in this case Giesecke & Devrient GmbH */
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
