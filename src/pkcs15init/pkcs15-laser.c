/*
 * Athena Laser specific operation for PKCS #15 initialization
 *
 * Copyright (C) 2013	Athena
 *			Viktor Tarasov <viktor.tarasov@gmail.com>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "config.h"
#include "libopensc/asn1.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/laser.h"
#include "profile.h"
#include "pkcs15-init.h"

static int
laser_write_tokeninfo (struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		char *label, unsigned flags)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


int
laser_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Erase the card
 */
static int
laser_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_create_dir(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Allocate a file
 */
static int
laser_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Create private key file
 */
static int
laser_create_key_file(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Store a private key
 */
static int
laser_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *prkey)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_update_dir (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_app_info *info)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
laser_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
laser_emu_update_tokeninfo(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_tokeninfo *tinfo)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_write_info(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *pin_obj)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_store_pubkey(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
laser_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;


	LOG_FUNC_CALLED(ctx);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static struct sc_pkcs15init_operations
sc_pkcs15init_laser_operations = {
	laser_erase_card,
	NULL,				/* init_card  */
	laser_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	NULL,				/* select_pin_reference */
	NULL,				/* create_pin*/
	NULL,				/* select_key_reference */
	laser_create_key_file,		/* create_key */
	laser_store_key,		/* store_key */
	laser_generate_key,		/* generate_key */
	NULL,
	NULL,				/* encode private/public key */
	NULL,				/* finalize_card */
	NULL,				/* delete_object */
#ifdef ENABLE_OPENSSL
	laser_emu_update_dir,
	laser_emu_update_any_df,
	laser_emu_update_tokeninfo,
	laser_emu_write_info,
	laser_emu_store_data,
	NULL				/* sanity_check */
#else
	NULL, NULL, NULL, NULL, NULL,
	NULL
#endif
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_laser_ops(void)
{
	return &sc_pkcs15init_laser_operations;
}
