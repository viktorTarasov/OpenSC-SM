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
#if defined(_WIN32)
	SCardListCards_t SCardListCards;
	SCardFreeMemory_t SCardFreeMemory;
	SCardGetCardTypeProviderName_t SCardGetCardTypeProviderName;
#endif
};

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
};

/* Local definitions */
#define SC_CCID_PIN_TIMEOUT	30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

#define SCARD_CLASS_SYSTEM     0x7fff
#define SCARD_ATTR_VALUE(Class, Tag) ((((ULONG)(Class)) << 16) | ((ULONG)(Tag)))
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0003)
#define SCARD_ATTR_DEVICE_SYSTEM_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0004)

#endif   /* ENABLE_PCSC */

#endif /* _READER_PCSC_H */
