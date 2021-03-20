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
#include "libopensc/internal.h"
#include "util.h"

struct POD {
	unsigned char sfi;
    unsigned char idx_beg; 
    unsigned char idx_end; 
};

static const char *app_name = "emv-tool";

static int	opt_wait = 0;
static char **opt_apdus;
static char	*opt_reader;
static char *opt_aid = NULL;
static int	opt_apdu_count = 0;
static char * opt_pin = NULL;
static char * opt_new_token_label = NULL;
static int	verbose = 0;

#define SC_CARD_TYPE_SAFENET_IDPRIME_MD 68000

static const struct sc_atr_table known_atrs[] = {
    { "3B:7F:96:00:00:80:31:80:65:B0:85:59:56:FB:12:0F:FE:82:90:00",
      "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
        "SafeNet IDPrime MD", SC_CARD_TYPE_SAFENET_IDPRIME_MD,  0, NULL },
    { NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_aid SafeNet_IDPrimeMD_AID = {
    {0xA0,0x00,0x00,0x00,0x18,0x80,0x00,0x00,0x00,0x06,0x62}, 11
};


enum {
	OPT_SELECT_AID = 0x100,
    OPT_UPDATE_TOKEN_LABEL,
    OPT_PIN,
	OPT_RESET,
};

static const struct option options[] = {
	{ "atr",		0, NULL,		'a' },
	{ "aid",        1, NULL,    OPT_SELECT_AID },
	{ "list-readers",	0, NULL,		'l' },
	{ "reader",		1, NULL,		'r' },
	{ "send-apdu",		1, NULL,		's' },
    { "update-token-label", required_argument, NULL, OPT_UPDATE_TOKEN_LABEL },
	{ "pin",  required_argument, NULL, OPT_PIN },
    { "reset",		2, NULL,	OPT_RESET   },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Prints the ATR bytes of the card",
	"Select application (Visa, MasterCard, ...)", 
	"Lists readers",
	"Uses reader number <arg> [0]",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
    "Update token label",
    "PIN to update token label",
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
    
    rv = sc_transmit_apdu(card, &apdu);
    if (rv < 0)
        return rv;

    rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (rv < 0)
        return rv;

    return apdu.resplen;
}


static int
send_apdu(char **apdus, int  apdu_count)
{
	sc_apdu_t apdu;
	unsigned char buf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	unsigned char rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t len0, r;
	int c;

	for (c = 0; c < apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(apdus[c], buf, &len0);

		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
			return 2;
		}

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

        if (verbose)   {
		    printf("Sending: ");
		    for (r = 0; r < len0; r++)
			    printf("%02X ", buf[r]);
		    printf("\n");
        }

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_transmit_apdu(card, &apdu);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
			return 1;
		}

        if (verbose)   {
		    printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		    if (apdu.resplen)
			    util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
        }
	}
	return 0;
}


static int
verify_pin(char *value)
{
//  APDU: 00 21 00 11 10 31 32 33 34 35 36 00 00 00 00 00 00 00 00 00 00
    unsigned char pin[0x10];
    struct sc_pin_cmd_data pin_cmd;
    int tries_left = -1;

    if (!value)   {
        fprintf(stderr, "PIN is mandatory arguments.\n");
        return -1;
    }

    if (strlen(value) > sizeof(pin))   {
        fprintf(stderr, "Invalid PIN length\n");
        return -1;
    }

    memset(pin, 0x00, sizeof(pin));
    memcpy(pin, value, strlen(value));

    memset(&pin_cmd, 0, sizeof(pin_cmd));
    pin_cmd.cmd = SC_PIN_CMD_VERIFY;
    pin_cmd.pin_type = SC_AC_CHV;
    pin_cmd.pin_reference = 0x11;
    pin_cmd.pin1.data = pin;
    pin_cmd.pin1.len = sizeof(pin);

    if (sc_pin_cmd(card, &pin_cmd, &tries_left))
        return -1;

    return 0;
}


static void
reset_pin(void)
{
    char *reset_pin_apdus[] = {"00:21:FF:11", "00:21:FF:83"};
    int reset_pin_apdus_count = sizeof(reset_pin_apdus)/sizeof(reset_pin_apdus[0]);

    if (send_apdu(reset_pin_apdus, reset_pin_apdus_count) < 0)
        fprintf(stderr, "Cannot reset PIN\n");
}


static int
update_token_label(char *pin, char *new_token_label)
{
    struct sc_path path;
    struct sc_file *file = NULL;
    unsigned char content[0x100];
    char *content_char = NULL;
    char buff_char[0x300];
    int rv;
    
    if (!pin || !new_token_label)   {
        fprintf(stderr, "SOPIN and NewTokenLabel are mandatory arguments.\n");
        return -1;
    }

    if (strlen(new_token_label) > 0x20)   {
        fprintf(stderr, "New label length cannot be more then 32 characters.\n");
        return -1;
    }

    if (verify_pin(pin))   {
        fprintf(stderr, "Cannot verify SoPIN\n");
        return -1;
    }

    sc_format_path("0202", &path);
    if (sc_select_file(card, &path, &file))   {
        fprintf(stderr, "Cannot select 0202.\n");
        return -1;
    }

    rv = sc_read_binary(card, 0, content, file->size, 0);
    if (rv < 0)   {
        fprintf(stderr, "Cannot read 0202.\n");
        return -1;
    }

    if (verbose)   {
        sc_bin_to_hex(content, rv, buff_char, sizeof(buff_char), 0);
        printf("Current stamp: '%s'\n", buff_char);
    }

    srand(time(NULL) ^ getpid());
    *((int *)content) ^= rand();
    *((int *)(content + rv - sizeof(int))) ^= rand();
   
    if (verbose)   {
        sc_bin_to_hex(content, rv, buff_char, sizeof(buff_char), 0);
        printf("New stamp: '%s'\n", buff_char);
    }

    rv = sc_update_binary(card, 0, content, file->size, 0);
    if (rv < 0)   {
        fprintf(stderr, "Cannot update TokenInfo binary file\n");
        return -1;
    }
    rv = 0;

    sc_format_path("0205", &path);
    if (sc_select_file(card, &path, &file))   {
        fprintf(stderr, "Cannot select DF 0205\n");
        return -1;
    }

    rv = sc_read_binary(card, 0, content, file->size, 0);
    if (rv < 0)   {
        fprintf(stderr, "Cannot read 0202.\n");
        return -1;
    }
    content[rv] = '\0';
    content_char = (char *)(content + 2);
    
    while (*(content_char + strlen(content_char) - 1) == ' ')   
        *(content_char+ strlen(content_char) - 1) = '\0';

    printf("Current token label: '%s'\n", content_char);
    if (file->size != 0x22)   {
        fprintf(stderr, "Unexpected TokenLabel size: %ld\n", file->size);
        return -1;
    }

    memset(content + 2, ' ', 0x20);
    memcpy(content + 2, new_token_label, strlen(new_token_label));

    printf("New token label: '%s'\n", new_token_label);
    rv = sc_update_binary(card, 0, content, file->size, 0);
    if (rv < 0)   {
        fprintf(stderr, "Cannot update TokenLabel file\n");
        return -1;
    }

    reset_pin();

    return 0;
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
	unsigned char aid_fcp[SC_READER_SHORT_APDU_MAX_RECV_SIZE];
    int do_update_token_label = 0;
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
        case OPT_PIN:
            opt_pin = optarg;
            break;
        case OPT_UPDATE_TOKEN_LABEL:
            do_update_token_label = 1;
            action_count++;
            opt_new_token_label = optarg;
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

    if (opt_aid)   {
        struct sc_aid aid;

        aid.len = sizeof(aid.value);
        if (sc_hex_to_bin(opt_aid, aid.value, &aid.len))   {
            fprintf(stderr, "Invalid AID value: '%s'\n", opt_aid);
            return 2;
        }
	
		if (select_aid(card, &aid, aid_fcp, sizeof(aid_fcp)) < 0)   {
            fprintf(stderr, "Cannot select application '%s'\n", opt_aid);
            return 2;
        }
	}
    else   {
        err = _sc_match_atr(card, known_atrs, NULL);
        if (err < 0)   {
            sc_log(ctx, "card not matched");
            return 2;
        }
        
        if (verbose)
            printf("Matched card '%s'\n", known_atrs[err].name);
        if (known_atrs[err].type == SC_CARD_TYPE_SAFENET_IDPRIME_MD)   {
            char *post_select_aid[] = {"00:A6:00:00:15"};
            int post_select_aid_count = sizeof(post_select_aid)/sizeof(post_select_aid[0]);
            
		    if (select_aid(card, &SafeNet_IDPrimeMD_AID, aid_fcp, sizeof(aid_fcp)) < 0)   {
                fprintf(stderr, "Cannot select application '%s'\n", opt_aid);
                return 2;
            }

		    err = send_apdu(post_select_aid, post_select_aid_count);
            if (err < 0)   {
                sc_log(ctx, "Card specific command failed");
                return 2;
            }
        }
    }

    if (do_send_apdu) {
		if ((err = send_apdu(opt_apdus, opt_apdu_count)))
			goto end;
		action_count--;
	}
    
    if (do_update_token_label)  {
		if ((err = update_token_label(opt_pin, opt_new_token_label)))
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
