/*
 * emv-tool.c: Tool for accessing EMV smart cards
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2019  Victor Tarasov <viktor.tarasov@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/gp.h"
#include "libopensc/asn1.h"
#include "util.h"

struct POD {
	unsigned char sfi;
    unsigned char idx_beg; 
    unsigned char idx_end; 
};

static const char *app_name = "emv-tool";

static int	opt_wait = 0;
static char **	opt_apdus;
static char	*opt_reader;
static char *opt_aid = NULL;
static int	opt_apdu_count = 0;
static int	verbose = 0;
static int	use_le_select_aid = 0;
static int	use_le_processing_options = 0;
static int	use_T0 = 0;

enum {
	OPT_SELECT_AID = 0x100,
    OPT_USE_LE_SELECT_AID,
    OPT_USE_LE_PROCESSING_OPTIONS,
    OPT_USE_T0,
	OPT_RESET,
};

static const struct option options[] = {
	{ "atr",		0, NULL,		'a' },
	{ "aid",        1, NULL,    OPT_SELECT_AID },
	{ "pan",		0, NULL,	'p'},
	{ "list-readers",	0, NULL,		'l' },
	{ "send-apdu",		1, NULL,		's' },
	{ "reader",		1, NULL,		'r' },
	{ "reset",		2, NULL,	OPT_RESET   },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ "use-le-select-aid",		0, NULL, OPT_USE_LE_SELECT_AID },
	{ "use-le-processing-options",		0, NULL, OPT_USE_LE_PROCESSING_OPTIONS },
	{ "use-T0",		0, NULL, OPT_USE_T0 },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Prints the ATR bytes of the card",
	"Select application (Visa, MasterCard, ...)", 
    "Print the card's PAN",
	"Lists readers",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
	"Uses reader number <arg> [0]",
	"Does card reset of type <cold|warm> [cold]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

static int list_readers(void)
{
	unsigned int i, rcount = sc_ctx_get_reader_count(ctx);

	if (rcount == 0) {
		printf("No smart card readers found.\n");
		return 0;
	}
	printf("# Detected readers (%s)\n", ctx->reader_driver->short_name);
	printf("Nr.  Card  Features  Name\n");
	for (i = 0; i < rcount; i++) {
		sc_reader_t *reader = sc_ctx_get_reader(ctx, i);
		int state = sc_detect_card_presence(reader);
		printf("%-5d%-6s%-10s%s\n", i, state & SC_READER_CARD_PRESENT ? "Yes":"No",
		      reader->capabilities & SC_READER_CAP_PIN_PAD ? "PIN pad":"",
		      reader->name);
		if (state & SC_READER_CARD_PRESENT && verbose) {
			struct sc_card *card;
			int r;
			char tmp[SC_MAX_ATR_SIZE*3];
			sc_bin_to_hex(reader->atr.value, reader->atr.len, tmp, sizeof(tmp) - 1, ':');

			if (state & SC_READER_CARD_EXCLUSIVE)
				printf("     %s [EXCLUSIVE]\n", tmp);
			else {
				if ((r = sc_connect_card(reader, &card)) != SC_SUCCESS) {
					fprintf(stderr, "     failed: %s\n", sc_strerror(r));
				} else {
					printf("     %s %s %s\n", tmp, card->name ? card->name : "", state & SC_READER_CARD_INUSE ? "[IN USE]" : "");
					sc_disconnect_card(card);
				}
			}
		}
	}
	return 0;
}

int
select_aid(struct sc_card *card, const struct sc_aid *aid, unsigned char *resp, size_t resp_len)
{
    struct sc_apdu apdu;
    int rv;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
    apdu.lc = aid->len;
    apdu.data = aid->value;
    apdu.datalen = aid->len;
    apdu.resp = resp;
    apdu.resplen = resp_len;
    apdu.le = resp_len;
    
    if (use_le_select_aid)
        apdu.flags |= SC_APDU_INCLUDE_LE;

    rv = sc_transmit_apdu(card, &apdu);

    if (rv < 0)
        return rv;

    rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (rv < 0)
        return rv;

    return apdu.resplen;
}


int
select_named_directory (struct sc_card *card, const char *dir, unsigned char *resp, size_t resp_len)
{
    struct sc_aid aid;
    
    if (strlen(dir) > sizeof(aid.value))
        return -1;
    memset(&aid, 0, sizeof(aid));
    memcpy(aid.value, dir, strlen(dir));
    aid.len = strlen(dir);

    return select_aid(card, &aid, resp, resp_len);
}


int
getPODL(struct sc_card *card, struct POD *podl, size_t podl_len)
{
    struct sc_apdu apdu;
    const unsigned char *tag_value = NULL;
    size_t ii, tag_len = 0;
    int rv;
	unsigned char rbuf[0x400];
    unsigned char GetProcessingOptions[] = {0x83, 0x00};

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA8, 0x00, 0x00);
    apdu.cla = 0x80;
    apdu.lc = sizeof(GetProcessingOptions);
    apdu.data = GetProcessingOptions;
    apdu.datalen = sizeof(GetProcessingOptions);
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    apdu.le = 0x100;

    if (use_le_processing_options)
        apdu.flags |= SC_APDU_INCLUDE_LE;

    rv = sc_transmit_apdu(card, &apdu);
    if (rv < 0)
        return rv;
    rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (rv < 0)
        return rv;

    tag_value = sc_asn1_find_tag(card->ctx, apdu.resp, apdu.resplen, 0x80, &tag_len);
    if (tag_value)   {
        tag_value += 2;
        tag_len -= 2;
    }
    else   {
        tag_value = sc_asn1_find_tag(card->ctx, apdu.resp, apdu.resplen, 0x77, &tag_len);
        if (tag_value)
            tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x94, &tag_len);
        if (!tag_value)   {
            fprintf(stderr, "Cannot find AFL data in 'Format 2' GetPODL response.\n");
            return -1;
        }
    }

    for (ii=0; ii<tag_len/4 && ii < podl_len; ii++)   {
        (podl + ii)->sfi = *(tag_value + 4*ii + 0) >> 3;
        (podl + ii)->idx_beg = *(tag_value + 4*ii + 1);
        (podl + ii)->idx_end = *(tag_value + 4*ii + 2);
    }

    return ii;
}


static int
send_apdu(void)
{
	sc_apdu_t apdu;
	unsigned char buf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	unsigned char rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t len0, r;
	int c;

    if (opt_aid)   {
        struct sc_aid aid;

        aid.len = sizeof(aid.value);
        if (sc_hex_to_bin(opt_aid, aid.value, &aid.len))   {
            fprintf(stderr, "Invalid AID value: '%s'\n", opt_aid);
            return 2;
        }
	
		if (select_aid(card, &aid, rbuf, sizeof(rbuf)) < 0)   {
            fprintf(stderr, "Cannot select application '%s'\n", opt_aid);
            return 2;
        }
	}

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);

		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
			return 2;
		}

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		printf("Sending: ");
		for (r = 0; r < len0; r++)
			printf("%02X ", buf[r]);
		printf("\n");
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_transmit_apdu(card, &apdu);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
			return 1;
		}
		printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
		      apdu.resplen ? ":" : "");
		if (apdu.resplen)
			util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}
	return 0;
}



static void print_pan(sc_card_t *in_card)
{
    struct POD podl[8];
    unsigned char resp[254];
    char pan[0x80];
	int rec, podl_len, pp, idx, r = 0;
    const unsigned char *tag_value = NULL;
    size_t tag_len = 0;
    struct sc_aid aid;

    memset(pan, 0, sizeof(pan));
    memset(&aid, 0, sizeof(aid));
	sc_lock(card);

    if (opt_aid)   {
        aid.len = sizeof(aid.value);
        if (sc_hex_to_bin(opt_aid, aid.value, &aid.len))   {
            fprintf(stderr, "Invalid AID value: '%s'\n", opt_aid);
            return;
        }
    }
	
    if (aid.len == 0)   {
        r = select_named_directory(card, "1PAY.SYS.DDF01", resp, sizeof(resp));
        if (r > 0)   {
            unsigned char sfi = 0;

            tag_value = sc_asn1_find_tag(card->ctx, resp, r, 0x6F, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0xA5, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x88, &tag_len);
            if (tag_value)
                sfi = *tag_value;

            if (sfi)   {
                for (rec=1; ; rec++)   {
                    unsigned char rec_data[254];
                    int rec_len = 0;

                    rec_len = sc_read_record(card, rec, rec_data, sizeof(rec_data), SC_RECORD_BY_REC_NR | sfi);
                    if (rec_len < 0)
                        break;

                    tag_value = sc_asn1_find_tag(card->ctx, rec_data, rec_len, 0x70, &tag_len);
                    if (tag_value)
                        tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x61, &tag_len);
                    if (tag_value)
                        tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x4F, &tag_len);
                    if (tag_value)   {
                        if (tag_len > sizeof(aid.value))   {
                            fprintf(stderr, "Invalid AID length in DIR record\n");
                            return;
                        }
                        aid.len = tag_len;
                        memcpy(aid.value, tag_value, tag_len);
                    }
                }
            }
        }
    }

    if (aid.len == 0)   {
        r = select_named_directory(card, "2PAY.SYS.DDF01", resp, sizeof(resp));
        if (r > 0 )   {
            tag_value = sc_asn1_find_tag(card->ctx, resp, r, 0x6F, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0xA5, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0xBF0C, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x61, &tag_len);
            if (tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag_value, tag_len, 0x4F, &tag_len);
            if (tag_value)   {
                if (tag_len > sizeof(aid.value))   {
                    fprintf(stderr, "Invalid AID length in DIR record\n");
                    return;
                }
                aid.len = tag_len;
                memcpy(aid.value, tag_value, tag_len);
            }
        }
    }

    if (aid.len == 0)   {
        fprintf(stdout, "Cannot find PAY application to select.\n");
        return;
    }

	r = select_aid(card, &aid, resp, sizeof(resp));
    if (r < 0)   {
        fprintf(stderr, "Cannot select application '%s'\n", opt_aid);
        return;
	}

    r = getPODL(card, podl, sizeof(podl)/sizeof(podl[0]));
    if (r < 0)   {
        podl[0].sfi = 0x01, podl[0].idx_beg = 0x01, podl[0].idx_end = 0x06;
        podl[1].sfi = 0x02, podl[1].idx_beg = 0x01, podl[1].idx_end = 0x06;
        podl[2].sfi = 0x03, podl[2].idx_beg = 0x01, podl[2].idx_end = 0x06;
        podl[3].sfi = 0x04, podl[3].idx_beg = 0x01, podl[3].idx_end = 0x06;
        podl[4].sfi = 0x05, podl[4].idx_beg = 0x01, podl[4].idx_end = 0x06;
        podl[5].sfi = 0x06, podl[5].idx_beg = 0x01, podl[5].idx_end = 0x06;
        r = 6;
    }
    podl_len = r;

    for (pp = 0; pp < podl_len; pp++)   {
        for (idx = podl[pp].idx_beg; idx <= podl[pp].idx_end; idx++)   {
            const unsigned char *tag70_value = NULL, *tag_value = NULL;
            size_t tag70_len = 0, tag_len = 0;

            r = sc_read_record(card, idx, resp, sizeof(resp), SC_RECORD_BY_REC_NR | podl[pp].sfi);
            if (r < 0)   {
                fprintf(stderr, "Failed to read SFI:%i REC:%i\n", podl[pp].sfi, idx);
                continue;
            }

            tag70_value = sc_asn1_find_tag(card->ctx, resp, r, 0x70, &tag70_len);
            if (!tag70_value)   {
                fprintf(stderr, "Invalid data in SFI:%i REC:%i\n", podl[pp].sfi, idx);
                continue;
            }

            tag_value = sc_asn1_find_tag(card->ctx, tag70_value, tag70_len, 0x5A, &tag_len);
            if (!tag_value)
                tag_value = sc_asn1_find_tag(card->ctx, tag70_value, tag70_len, 0x57, &tag_len);

            if (tag_value)   {
                size_t ii;
                char *ptr = NULL;

                memset(pan, 0, sizeof(pan));
                for(ii=0, ptr = pan; ii < tag_len; ii++)   {
                    if ((tag_value[ii] >> 4) == 0x0D)
                        break;
                    *ptr++ = (tag_value[ii] >> 4) + '0';

                    if ((tag_value[ii] & 0x0F) == 0x0D)
                        break;
                    *ptr++ = (tag_value[ii] & 0x0F) + '0';
                }
                printf("PAN: %s\n", pan);
                return;
            }
        }
        if (idx < podl[pp].idx_end)
            break;
    }

    sc_unlock(card);
    return;
}

static int card_reset(const char *reset_type)
{
	int cold_reset;
	int r;

	if (reset_type && strcmp(reset_type, "cold") &&
	    strcmp(reset_type, "warm")) {
		fprintf(stderr, "Invalid reset type: %s\n", reset_type);
		return 2;
	}

	cold_reset = !reset_type || strcmp(reset_type, "cold") == 0;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_reset(card, cold_reset);
	sc_unlock(card);
	if (r) {
		fprintf(stderr, "sc_reset(%s) failed: %d\n",
			cold_reset ? "cold" : "warm", r);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_list_readers = 0;
	int do_send_apdu = 0;
	int do_print_atr = 0;
	int do_print_pan = 0;
	int do_reset = 0;
	int action_count = 0;
	const char *opt_reset_type = NULL;
	char **p;
	sc_context_param_t ctx_param;

	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "lr:vs:awp", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'l':
			do_list_readers = 1;
			action_count++;
			break;
		case 's':
			p = (char **) realloc(opt_apdus,
					(opt_apdu_count + 1) * sizeof(char *));
			if (!p) {
				fprintf(stderr, "Not enough memory\n");
				err = 1;
				goto end;
			}
			opt_apdus = p;
			opt_apdus[opt_apdu_count] = optarg;
			do_send_apdu++;
			if (opt_apdu_count == 0)
				action_count++;
			opt_apdu_count++;
			break;
		case 'a':
			do_print_atr = 1;
			action_count++;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_SELECT_AID:
			opt_aid = optarg;
			break;
		case 'p':
			do_print_pan = 1;
			action_count++;
			break;
        case OPT_USE_LE_SELECT_AID:
            use_le_select_aid = 1;
            break;
        case OPT_USE_LE_PROCESSING_OPTIONS:
            use_le_processing_options = 1;
            break;
        case OPT_USE_T0:
            use_T0 = 1;
            break;
		case OPT_RESET:
			do_reset = 1;
			opt_reset_type = optarg;
			action_count++;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	ctx->flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;

	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	if (do_list_readers) {
		if ((err = list_readers()))
			goto end;
		action_count--;
	}
	if (action_count <= 0)
		goto end;

    err = sc_set_card_driver(ctx, "default");
    if (err < 0) {
        fprintf(stderr, "Cannot set default driver\n");
        goto end;
    }

	err = util_connect_card_ex(ctx, &card, opt_reader, opt_wait, 0, verbose);
	if (err)
		goto end;

	if (do_print_atr) {
		if (verbose) {
			printf("Card ATR:\n");
			util_hex_dump_asc(stdout, card->atr.value, card->atr.len, -1);
		} else {
			char tmp[SC_MAX_ATR_SIZE*3];
			sc_bin_to_hex(card->atr.value, card->atr.len, tmp, sizeof(tmp) - 1, ':');
			fprintf(stdout,"%s\n",tmp);
		}
		action_count--;
	}
	if (do_print_pan) {
		if (verbose)
			printf("Card PAN:");
		print_pan(card);
		action_count--;
	}
	if (do_send_apdu) {
		if ((err = send_apdu()))
			goto end;
		action_count--;
	}

	if (do_reset) {
		if ((err = card_reset(opt_reset_type)))
			goto end;
		action_count--;
	}
end:
	if (card) {
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
