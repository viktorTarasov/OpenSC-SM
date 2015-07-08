/*
 * card-vsctpm.c: Support for ACS VSCTPM cards.
 *
 * Copyright (C) 2007  Ian A. Young<ian@iay.org.uk>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "cardctl.h"

#include "vsctpm-md.h"

static struct sc_atr_table vsctpm_atrs[] = {
	{"3b:8d:01:80:fb:a0:00:00:03:97:42:54:46:59:03:01:c8", NULL, NULL, SC_CARD_TYPE_VSCTPM_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_aid Virtual_Identity_AID = {
	{0xa0,0x00,0x00,0x03,0x97,0x42,0x54,0x46,0x59}, 9
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations vsctpm_ops;
static struct sc_card_driver vsctpm_drv = {
	"TPM Virtual Smart Card",
	"vsctpm",
	&vsctpm_ops,
	NULL, 0, NULL
};

#define VSCTPM_MD_ENTRY_DNAME_SIZE 9
#define VSCTPM_MD_ENTRY_FNAME_SIZE 11
struct vsctpm_md_file {
	char dname[VSCTPM_MD_ENTRY_DNAME_SIZE + 1];
	char fname[VSCTPM_MD_ENTRY_FNAME_SIZE + 1];
	unsigned file_id, tag;
};

struct vsctpm_private_data {
	struct vsctpm_md_file *md_files;
	size_t md_files_num;

#if ENABLE_MINIDRIVER
	struct vsctpm_md_data md;
#endif
};

static int vsctpm_select_aid(struct sc_card *, struct sc_aid *, unsigned char *, size_t *);
static int vsctpm_get_data(struct sc_card *, unsigned, unsigned, unsigned char **, size_t *);
static int vsctpm_get_md_entries(struct sc_card *);
static int vsctpm_get_serialnr(struct sc_card *, struct sc_serial_number *);
static int vsctpm_pin_verify(struct sc_card *, struct sc_pin_cmd_data *, int *);

static int
vsctpm_match_card(struct sc_card *card)
{
	int ii;

	ii = _sc_match_atr(card, vsctpm_atrs, &card->type);
	if (ii < 0)
		return 0;

	return 1;
}


static int
vsctpm_init(struct sc_card * card)
{
	struct vsctpm_private_data *prv_data = NULL;
	struct sc_context *ctx = card->ctx;
	unsigned char resp[0x100];
	size_t resp_len = sizeof(resp);
	int rv;

	LOG_FUNC_CALLED(ctx);

	card->cla = 0x00;
	card->caps = SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	card->drv_data = calloc(1, sizeof(struct vsctpm_private_data));
	if (!card->drv_data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	rv = vsctpm_select_aid(card, &Virtual_Identity_AID, resp, &resp_len);
	LOG_TEST_RET(ctx, rv, "Cannot select Virtual Identity AID");
	sc_log(ctx, "selected AID: %s", sc_dump_hex(resp, resp_len));

	rv = vsctpm_get_md_entries(card);
	LOG_TEST_RET(ctx, rv, "Cannot parse MD entries");

	rv = vsctpm_get_serialnr(card, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot set serial number");

#if ENABLE_MINIDRIVER
	prv_data = (struct vsctpm_private_data *) card->drv_data;
        rv = vsctpm_md_init_card_data (card, &prv_data->md);
	LOG_TEST_RET(ctx, rv, "Failed to init MD card data");

        sc_log (ctx, "pcsc_connect() MD atr '%s'", sc_dump_hex(prv_data->md.card_data.pbAtr, prv_data->md.card_data.cbAtr));
#endif

	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_get_data(struct sc_card *card, unsigned file_id, unsigned tag, unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[4] = {0x5C, 0x02, 0xFF, 0xFF};
	unsigned char rbuf[0x100];
	unsigned char p1, p2;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!out || !out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	p1 = (file_id >> 8) & 0xFF;
	p2 = file_id & 0xFF;
	sbuf[2] = (tag >> 8) & 0xFF;
	sbuf[3] = tag & 0xFF;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, p1, p2);
	apdu.data = sbuf;
	apdu.datalen = sizeof(sbuf);
	apdu.lc = apdu.datalen;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "vsctpm_get_data() failed");
	sc_log(ctx, "vsctpm_get_data() apdu.resplen %i", apdu.resplen);

	*out = malloc(apdu.resplen);
	if (*out == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memmove(*out, apdu.resp, apdu.resplen);
	*out_len = apdu.resplen;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_parse_md_entry(unsigned char *data, struct vsctpm_md_file *mdf, unsigned char **tail)
{
	int ii;

	if (!data || !mdf)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(mdf, 0, sizeof(*mdf));

	memmove(mdf->dname, data, VSCTPM_MD_ENTRY_DNAME_SIZE);
	data += VSCTPM_MD_ENTRY_DNAME_SIZE;

	memmove(mdf->fname, data, VSCTPM_MD_ENTRY_FNAME_SIZE);
	data += VSCTPM_MD_ENTRY_FNAME_SIZE;

	for (ii=0; ii<4; ii++)
		mdf->tag = (mdf->tag << 8) + *(data + 3 - ii);
	data += 4;

	for (ii=0; ii<4; ii++)
		mdf->file_id = (mdf->file_id << 8) + *(data + 3 - ii);
	data += 4;

	if (tail)
		*tail = data;

	return SC_SUCCESS;
}


struct vsctpm_md_file *
vsctpm_get_md_file (struct sc_card *card, char *dname, char *fname)
{
	struct vsctpm_private_data *prv_data = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct vsctpm_md_file *ret = NULL;
	size_t ii;

	if (!card || !fname)
		return NULL;

	for (ii = 0; ii < prv_data->md_files_num; ii++)   {
		struct vsctpm_md_file *mdf = prv_data->md_files + ii;

		sc_log(ctx, "%i: fname %s, file %X, tag %X", ii, mdf->fname, mdf->file_id, mdf->tag);

		if (dname)
			if (strncmp(dname, mdf->dname, VSCTPM_MD_ENTRY_DNAME_SIZE))
				continue;

		if (strncmp(fname, mdf->fname, VSCTPM_MD_ENTRY_FNAME_SIZE))
			continue;

		ret = mdf;
		break;
	}

	return ret;
}


static int
vsctpm_get_md_entries(struct sc_card *card)
{
	struct vsctpm_private_data *prv_data = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	unsigned char *blob = NULL, *ptr;
	size_t blob_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = vsctpm_get_data(card, 0xA000, 0xDF1F, &blob, &blob_len);
	LOG_TEST_RET(ctx, rv, "vsctpm_get_md_entries() cannot get MD entries blob");
	sc_log(ctx, "MD entries blob %s", sc_dump_hex(blob, blob_len));

	if (*blob != 0xDF || *(blob + 1) != 0x1F)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	/* TODO: size can be encoded in more then one byte */
	ptr = blob + 5;

	if (prv_data->md_files)
		free(prv_data->md_files);
	prv_data->md_files = NULL;
	prv_data->md_files_num = 0;

	while ((unsigned)(ptr - blob) < blob_len)   {
		struct vsctpm_md_file mdf;
		unsigned char *tail = NULL;

		rv = vsctpm_parse_md_entry(ptr, &mdf, &tail);
		LOG_TEST_RET(ctx, rv, "vsctpm_get_md_entries() MD entry parse error");

		prv_data->md_files = (struct vsctpm_md_file *)realloc(prv_data->md_files, (sizeof (mdf)) * (prv_data->md_files_num + 1));
		if (!prv_data->md_files)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		sc_log(ctx, "%i: parsed MD entry %s:%s, file-id %X, tag %X", prv_data->md_files_num, mdf.dname, mdf.fname, mdf.file_id, mdf.tag);

		*(prv_data->md_files + prv_data->md_files_num) = mdf;
		prv_data->md_files_num++;

		ptr = tail;
	}

	free(blob);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_select_file_by_path(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	size_t in_len = in_path->len;
	const u8 *in_pos = &in_path->value[0];
	struct sc_path path;

	LOG_FUNC_CALLED(ctx);
	memset(&path, 0, sizeof(sc_path_t));
	path.len = 2;		/* one component at a time */
	path.type = SC_PATH_TYPE_FILE_ID;

	/*
	 * Check parameters.
	 */
	if (in_len % 2 != 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/*
	 * File ID by file ID...
	 */
	while (in_len) {
		int result;

		memcpy(path.value, in_pos, 2);
		result = iso_ops->select_file(card, &path, file_out);
		if (result != SC_SUCCESS)
			return result;
		in_len -= 2;
		in_pos += 2;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_select_file(struct sc_card *card, struct sc_path *in_path, struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "vsctpm_select_file() path %s", sc_print_path(in_path));
	switch (in_path->type) {
	case SC_PATH_TYPE_PATH:
		sc_log(ctx, "vsctpm_select_file() path length %i", in_path->len);
		if (in_path->len >= 2 && in_path->value[0] == 0x3F && in_path->value[1] == 0)   {
//			sc_log(ctx, "select VSC AID instead of MF");
//			rv = vsctpm_select_aid(card, &Virtual_Identity_AID, NULL, NULL);
//			LOG_TEST_RET(ctx, rv, "Cannot select Virtual Identity AID");

			if (in_path->len == 2)   {
				if (file_out)   {
					*file_out = sc_file_new();
					if (*file_out == NULL)
						LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
					(*file_out)->path = *in_path;
				}

				LOG_FUNC_RETURN(ctx, SC_SUCCESS);
			}

			in_path->len -= 2;
			if (in_path->len == 2)
				in_path->type = SC_PATH_TYPE_FILE_ID;
			else
				in_path->type = SC_PATH_TYPE_FROM_CURRENT;

			memmove(&in_path->value[0], &in_path->value[2], in_path->len);
		}

		rv = vsctpm_select_file_by_path(card, in_path, file_out);
		break;
	default:
		rv = iso_ops->select_file(card, in_path, file_out);
		break;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_select_aid(struct sc_card *card, struct sc_aid *aid, unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char apdu_resp[250];
	int rv;

	LOG_FUNC_CALLED(ctx);
	/* Select application (deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aid->len;
	apdu.data = aid->value;
	apdu.datalen = aid->len;
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;
	apdu.le = sizeof(apdu_resp);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Cannot select AID");

	if (out == NULL || out_len == NULL)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (*out_len < apdu.resplen)
	   LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	*out_len = apdu.resplen;

	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_md_file *mdf = NULL;
	unsigned char *blob = NULL;
	size_t blob_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	/*
	 * Return a cached serial number, if we have one.
	 */
	if (card->serialnr.len) {
		if (serial)
			memcpy(serial, &card->serialnr, sizeof(*serial));
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	mdf = vsctpm_get_md_file (card, NULL, "cardid");
	if (!mdf)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	sc_log(ctx, "MD file %s %X %X", mdf->fname, mdf->file_id, mdf->tag);
	rv = vsctpm_get_data(card, mdf->file_id, mdf->tag, &blob, &blob_len);
	LOG_TEST_RET(ctx, rv, "cannot get CardID data");
	sc_log(ctx, "Serial blob (%i) %s", blob_len, sc_dump_hex(blob, blob_len));

	if (blob_len < 3)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	/*
	 * Cache serial number.
	 */
	memcpy(card->serialnr.value, blob + 3, MIN((*(blob + 2)), SC_MAX_SERIALNR));
	card->serialnr.len = MIN((*(blob + 2)), SC_MAX_SERIALNR);


	/*
	 * Copy and return serial number.
	 */
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	free(blob);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;

	sc_log(ctx, "VSC ctl cmd SC_CARDCTL_GET_SERIALNR: cmd:%li, ptr:%p", cmd, ptr);
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return vsctpm_get_serialnr(card, (struct sc_serial_number *) ptr);
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
}


static int
vsctpm_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;
	size_t count;
	u8 *bufp = buf;		/* pointer into buf */
	int fno = 0;		/* current file index */

	LOG_FUNC_CALLED(ctx);
	/*
	 * Check parameters.
	 */
	if (!buf || (buflen & 1))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/*
	 * Use CARD GET INFO to fetch the number of files under the
	 * curently selected DF.
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x01, 0x00);
	apdu.cla |= 0x80;
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	if (apdu.sw1 != 0x90)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	count = apdu.sw2;

	while (count--) {
		u8 info[8];

		/*
		 * Truncate the scan if no more room left in output buffer.
		 */
		if (buflen == 0)
			break;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x02,
			       fno++);
		apdu.cla |= 0x80;
		apdu.resp = info;
		apdu.resplen = sizeof(info);
		apdu.le = sizeof(info);

		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed");

		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

		*bufp++ = info[2];
		*bufp++ = info[3];
		buflen -= 2;
	}

	rv = (int)(bufp - buf);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_pin_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, int *tries_left)
{
        struct sc_context *ctx = card->ctx;
        struct sc_apdu apdu;
        int rv;

        LOG_FUNC_CALLED(ctx);
        sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i)", pin_cmd->pin_reference, pin_cmd->pin1.len);

        if (pin_cmd->pin1.data && !pin_cmd->pin1.len)   {
                sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, pin_cmd->pin_reference);
        }
        else if (pin_cmd->pin1.data && pin_cmd->pin1.len)   {
                sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_cmd->pin_reference);
                apdu.data = pin_cmd->pin1.data;
                apdu.datalen = pin_cmd->pin1.len;
                apdu.lc = pin_cmd->pin1.len;
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
vsctpm_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
        struct sc_context *ctx = card->ctx;
        struct sc_apdu apdu;
        unsigned reference = data->pin_reference;
        unsigned char pin_data[0x100];
        int rv;

        LOG_FUNC_CALLED(ctx);
        sc_log(ctx, "Change PIN(ref:%i,type:0x%X,lengths:%i/%i)", reference, data->pin_type, data->pin1.len, data->pin2.len);

        if (!data->pin1.data && data->pin1.len)
                LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN1 arguments");

        if (!data->pin2.data && data->pin2.len)
                LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN2 arguments");

        rv = vsctpm_pin_verify(card, data, tries_left);
        sc_log(ctx, "pin_cmd(SC_PIN_CMD_CHANGE) pin_verify returned %i", rv);
        LOG_TEST_RET(ctx, rv, "PIN verification error");

        if ((unsigned)(data->pin1.len + data->pin2.len) > sizeof(pin_data))
                LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'Change PIN' data");

        if (data->pin1.data)
                memcpy(pin_data, data->pin1.data, data->pin1.len);
        if (data->pin2.data)
                memcpy(pin_data + data->pin1.len, data->pin2.data, data->pin2.len);

        sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, reference);
        apdu.data = pin_data;
        apdu.datalen = data->pin1.len + data->pin2.len;
        apdu.lc = apdu.datalen;

        rv = sc_transmit_apdu(card, &apdu);
        LOG_TEST_RET(ctx, rv, "APDU transmit failed");
        rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
        LOG_TEST_RET(ctx, rv, "PIN cmd failed");

        LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
        struct sc_context *ctx = card->ctx;
        int rv = SC_ERROR_NOT_SUPPORTED;

        LOG_FUNC_CALLED(ctx);
        sc_log(ctx, "cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%i, PIN-2 %p:%i",
                        data->cmd, data->pin_type, data->pin_reference,
                        data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);

        switch (data->cmd)   {
        case SC_PIN_CMD_VERIFY:
                rv = vsctpm_pin_verify(card, data, tries_left);
                break;
        case SC_PIN_CMD_CHANGE:
                rv = vsctpm_pin_change(card, data, tries_left);
                break;
        case SC_PIN_CMD_UNBLOCK:
        case SC_PIN_CMD_GET_INFO:
        default:
                sc_log(ctx, "Other pin commands not supported yet: 0x%X", data->cmd);
                rv = SC_ERROR_NOT_SUPPORTED;
        }

        LOG_FUNC_RETURN(ctx, rv);
}


#if ENABLE_MINIDRIVER
static int
vsctpm_md_acquire_context(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_md_delete_context(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_finish(struct sc_card *card)
{
	struct vsctpm_private_data *prv_data = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

        vsctpm_md_reset_card_data (card, &prv_data->md);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#endif /* ENABLE_MINIDRIVER */

static struct
sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;
	vsctpm_ops = *iso_ops;

	vsctpm_ops.match_card = vsctpm_match_card;
	vsctpm_ops.init = vsctpm_init;
	vsctpm_ops.select_file = vsctpm_select_file;
	vsctpm_ops.card_ctl = vsctpm_card_ctl;
	vsctpm_ops.list_files = vsctpm_list_files;
	vsctpm_ops.pin_cmd = vsctpm_pin_cmd;
#if ENABLE_MINIDRIVER
	vsctpm_ops.finish = vsctpm_finish;
	vsctpm_ops.md_acquire_context = vsctpm_md_acquire_context;
	vsctpm_ops.md_delete_context = vsctpm_md_delete_context;
#endif /* ENABLE_MINIDRIVER */
	return &vsctpm_drv;
}


struct sc_card_driver *
sc_get_vsctpm_driver(void)
{
	return sc_get_driver();
}
