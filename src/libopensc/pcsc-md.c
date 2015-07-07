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

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "reader-pcsc.h"

#ifdef ENABLE_MINIDRIVER

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
pcsc_md_init_card_data(struct sc_reader *reader)
{
	struct sc_context *ctx = reader->ctx;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	HRESULT hRes = S_OK;

	LOG_FUNC_CALLED(ctx);

	memset(&priv->md, 0, sizeof(priv->md));
	priv->md.card_data.hScard = priv->pcsc_card;
	priv->md.card_data.hSCardCtx = priv->gpriv->pcsc_ctx;

	priv->md.card_data.cbAtr = reader->atr.value;
	priv->md.card_data.pbAtr = reader->atr.len;

	priv->md.card_data.pfnCspAlloc   = (PFN_CSP_ALLOC)&CSP_Alloc;
	priv->md.card_data.pfnCspReAlloc = (PFN_CSP_REALLOC)&CSP_ReAlloc;
	priv->md.card_data.pfnCspFree    = (PFN_CSP_FREE)&CSP_Free;

	priv->md.card_data.pwszCardName  = reader->friendly_name;

	priv->md.hmd = LoadLibrary(VSC_MODULE_NAME);
	if (priv->md.hmd == NULL) {
		hRes = GetLastError();
		sc_log(ctx, "Failed to load VSC module: error %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	priv->md.acquire_context = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(priv->md.hmd, "CardAcquireContext");
	if (!priv->md.acquire_context)   {
		sc_log(ctx, "GetProcAddress(CardAcquireContext) error");
		goto err;
	}

	sc_log(reader->ctx, "Init MD card data: priv->md.hmd %p; acquire context func %p", priv->md.hmd, priv->md.acquire_context);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

err:
	hRes = GetLastError();
	sc_log(ctx, "Last error %lX", hRes);
	pcsc_md_reset_card_data(reader);
	LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
}


void
pcsc_md_reset_card_data(struct sc_reader *reader)
{
	struct sc_context *ctx = reader->ctx;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.hmd)
		FreeLibrary(priv->md.hmd);

	memset(&priv->md, 0, sizeof(priv->md));
}


#endif /* ENABLE_MINIDRIVER */

#endif   /* ENABLE_PCSC */

