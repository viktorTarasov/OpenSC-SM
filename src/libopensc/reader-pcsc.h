/*
 * reader-pcsc.c: Reader driver for PC/SC interface
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2009,2010 Martin Paljak <martin@martinpaljak.net>
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

#ifndef _READER_PCSC_H
#define _READER_PCSC_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_PCSC	/* empty file without pcsc */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/libscdl.h"
#include "internal.h"
#include "internal-winscard.h"

#if ENABLE_MINIDRIVER
#include <windows.h>
#include "cardmod.h"
#endif

/* Logging */
#define PCSC_TRACE(reader, desc, rv) do { sc_log(reader->ctx, "%s:" desc ": 0x%08lx\n", reader->name, rv); } while (0)
#define PCSC_LOG(ctx, desc, rv) do { sc_log(ctx, desc ": 0x%08lx\n", rv); } while (0)

/* Utility for handling big endian IOCTL codes. */
#define dw2i_be(a, x) ((((((a[x] << 8) + a[x+1]) << 8) + a[x+2]) << 8) + a[x+3])

#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)

struct pcsc_global_private_data {
	SCARDCONTEXT pcsc_ctx;
	SCARDCONTEXT pcsc_wait_ctx;
	int enable_pinpad;
	int enable_pace;
	int connect_exclusive;
	DWORD disconnect_action;
	DWORD transaction_end_action;
	DWORD reconnect_action;
	const char *provider_library;
	void *dlhandle;
	SCardEstablishContext_t SCardEstablishContext;
	SCardReleaseContext_t SCardReleaseContext;
	SCardConnect_t SCardConnect;
	SCardReconnect_t SCardReconnect;
	SCardDisconnect_t SCardDisconnect;
	SCardBeginTransaction_t SCardBeginTransaction;
	SCardEndTransaction_t SCardEndTransaction;
	SCardStatus_t SCardStatus;
	SCardGetStatusChange_t SCardGetStatusChange;
	SCardCancel_t SCardCancel;
	SCardControlOLD_t SCardControlOLD;
	SCardControl_t SCardControl;
	SCardTransmit_t SCardTransmit;
	SCardListReaders_t SCardListReaders;
	SCardGetAttrib_t SCardGetAttrib;
};

#ifdef ENABLE_MINIDRIVER
struct pcsc_md_data   {
	CARD_DATA       card_data;
	HMODULE         md_hmodule;
};
#endif

struct pcsc_private_data {
	struct pcsc_global_private_data *gpriv;
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE reader_state;
	DWORD verify_ioctl;
	DWORD verify_ioctl_start;
	DWORD verify_ioctl_finish;

	DWORD modify_ioctl;
	DWORD modify_ioctl_start;
	DWORD modify_ioctl_finish;

	DWORD pace_ioctl;

	DWORD pin_properties_ioctl;

	DWORD get_tlv_properties;

	int locked;

#ifdef ENABLE_MINIDRIVER
	struct pcsc_md_data md_data;
#endif
};

/* Local definitions */
#define SC_CCID_PIN_TIMEOUT	30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

#ifdef ENABLE_MINIDRIVER

#define SCARD_CLASS_SYSTEM     0x7fff
#define SCARD_ATTR_VALUE(Class, Tag) ((((ULONG)(Class)) << 16) | ((ULONG)(Tag)))
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0003)
#define SCARD_ATTR_DEVICE_SYSTEM_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0004)

#endif

#endif   /* ENABLE_PCSC */

#endif /* _READER_PCSC_H */
