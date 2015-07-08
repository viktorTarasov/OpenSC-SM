/*
 * pcsc-md.c: Minidriver helpers for pcsc
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

#ifdef ENABLE_PCSC	/* empty file without pcsc */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"
#include "cardctl.h"

#ifdef ENABLE_MINIDRIVER

#include "vsctpm-md.h"
#include "reader-pcsc.h"

/**
 * CSP management functions and cache context, needed by minidrivers'
 * CardAcquireContext functions
 */
LPVOID WINAPI
CSP_Alloc(SIZE_T uBytes)
{
	return((LPVOID)LocalAlloc(LPTR, uBytes));
}


LPVOID WINAPI
CSP_ReAlloc(LPVOID Address, SIZE_T uBytes)
{
	return((LPVOID)LocalReAlloc(Address, uBytes, LMEM_ZEROINIT));
}


void WINAPI
CSP_Free(LPVOID Address)
{
	LocalFree(Address);
}


int
vsctpm_md_init_card_data(struct sc_card *card, struct vsctpm_md_data *md)
{
	struct sc_context *ctx = card->ctx;
	struct pcsc_private_data *priv = GET_PRIV_DATA(card->reader);
	HRESULT hRes = S_OK;

	LOG_FUNC_CALLED(ctx);

	memset(md, 0, sizeof(struct vsctpm_md_data));
	md->card_data.hScard = priv->pcsc_card;
	md->card_data.hSCardCtx = priv->gpriv->pcsc_ctx;

	md->card_data.cbAtr = (DWORD)card->reader->atr.len;
	md->card_data.pbAtr = card->reader->atr.value;

	md->card_data.pfnCspAlloc   = (PFN_CSP_ALLOC)&CSP_Alloc;
	md->card_data.pfnCspReAlloc = (PFN_CSP_REALLOC)&CSP_ReAlloc;
	md->card_data.pfnCspFree    = (PFN_CSP_FREE)&CSP_Free;

	md->card_data.pwszCardName  = L"OpenTrust Virtual Smart Card";

	md->hmd = LoadLibrary(VSC_MODULE_NAME);
	if (md->hmd == NULL) {
		hRes = GetLastError();
		sc_log(ctx, "Failed to load VSC module: error %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	md->acquire_context = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(md->hmd, "CardAcquireContext");
	if (!md->acquire_context)   {
		sc_log(ctx, "GetProcAddress(CardAcquireContext) error");
		goto err;
	}

	sc_log(ctx, "Init MD card data: md->hmd %p; acquire context func %p", md->hmd, md->acquire_context);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

err:
	hRes = GetLastError();
	sc_log(ctx, "Last error %lX", hRes);
	vsctpm_md_reset_card_data(card, md);

	LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
}


void
vsctpm_md_reset_card_data(struct sc_card *card, struct vsctpm_md_data *md)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (md->hmd)
		FreeLibrary(md->hmd);

	memset(md, 0, sizeof(struct vsctpm_md_data));
}


int
vsctpm_md_get_serial(struct sc_card *card, struct vsctpm_md_data *md, struct sc_serial_number *out)
{
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	struct sc_serial_number serial;
	DWORD sz;

	if (!md->card_data.pfnCardGetProperty)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	hRes = md->card_data.pfnCardGetProperty(&md->card_data, CP_CARD_SERIAL_NO,
			serial.value, sizeof(serial.value), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_SERIAL_NO) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	serial.len = sz;

	sc_log(ctx, "MD serial '%s'", sc_dump_hex(serial.value, serial.len));
	if (out)
		*out = serial;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_get_guid(struct sc_card *card, struct vsctpm_md_data *md, unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	unsigned char guid[0x80];
	DWORD sz;

	if (!md->card_data.pfnCardGetProperty)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	hRes = md->card_data.pfnCardGetProperty(&md->card_data, CP_CARD_GUID,
			guid, sizeof(guid), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_GUID) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "MD serial '%s'", sc_dump_hex(guid, sz));

	if (!out)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (!out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*out_len < sz)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memmove(out, guid, sz);
	*out_len = sz;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#endif /* ENABLE_MINIDRIVER */

#endif   /* ENABLE_PCSC */

