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
	vsctpm_md_reset_card_data(card);

	LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
}


void
vsctpm_md_reset_card_data(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.hmd)
		FreeLibrary(priv->md.hmd);

	memset(&priv->md, 0, sizeof(priv->md));
}


int
vsctpm_md_free(struct sc_card *card, void *ptr)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (!priv->md.card_data.pfnCspFree)   {
		sc_log(ctx, "Invalid CARD_DATA: CSP-FREE not defined");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	priv->md.card_data.pfnCspFree(ptr);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_get_guid(struct sc_card *card, unsigned char *out, size_t *out_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	unsigned char guid[0x80];
	DWORD sz = 0;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardGetProperty)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_GUID, guid, sizeof(guid), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_GUID) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	if (!out)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (!out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*out_len < sz)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memmove(out, guid, sz);
	*out_len = sz;

	sc_log(ctx, "out MD GUID '%s'", sc_dump_hex(out, *out_len));
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_read_file(struct sc_card *card, char *dir_name, char *file_name,
		unsigned char **out, size_t *out_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD sz = -1;
	unsigned char *ptr = NULL;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "called CardReadFile(%s,%s)", dir_name, file_name);

	if (!out || !out_len || !file_name)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (!priv->md.card_data.pfnCardReadFile)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	hRes = priv->md.card_data.pfnCardReadFile(&priv->md.card_data, dir_name, file_name, 0, &ptr, &sz);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardReadFile(%s,%s) failed: hRes %lX", dir_name, file_name, hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "MD file (%s,%s) (%i,'%s')", dir_name, file_name, sz, sc_dump_hex(ptr, sz));

	*out = ptr;
	*out_len = sz;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_enum_files(struct sc_card *card, char *dir_name, char **out, size_t *out_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD sz = -1;
	unsigned char *buf = NULL, *ptr;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "called CardEnumFiles(%s)", dir_name);

	if (!dir_name)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (!priv->md.card_data.pfnCardEnumFiles)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "call pfhCardEnumFiles(%s)", dir_name);
	hRes = priv->md.card_data.pfnCardEnumFiles(&priv->md.card_data, dir_name, &buf, &sz, 0);
	sc_log(ctx, "call pfhCardEnumFiles(%s) hRes %lX", dir_name, hRes);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardEnumFiles(%s) failed: hRes %lX", dir_name, hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "MD files in %li bytes: '%s': '%s'", sz, dir_name, sc_dump_hex(buf, sz));

	for(ptr=buf; strlen(ptr) && (ptr-buf) < sz; )   {
		sc_log(ctx, "file in %s: %s", dir_name, ptr);
		ptr += strlen(ptr) + 1;
	}

	if (out && out_len)   {
		*out = buf;
		*out_len = sz;
	}
	else   {
		int rv = vsctpm_md_free(card, buf);
		LOG_FUNC_RETURN(ctx, rv);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#endif /* ENABLE_MINIDRIVER */

#endif   /* ENABLE_PCSC */

