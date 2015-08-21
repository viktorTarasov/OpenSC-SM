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

#include "reader-pcsc.h"
#include "pkcs15.h"
#include "vsctpm-md.h"

static int vsctpm_md_get_sc_error(HRESULT);

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


BOOL WINAPI
Callback_CertEnumSystemStoreLocation(LPCWSTR pvszStoreLocations, DWORD dwFlags, void *pvReserved, void *pvArg)
{
	ENUM_ARG *enumArg = (ENUM_ARG *)pvArg;
	struct sc_card *card = enumArg->card;
	struct sc_context *ctx = card->ctx;
	char name[255];

	if (wcstombs(name, pvszStoreLocations, sizeof(name)))
		sc_log(ctx, "%s: %s", enumArg->title, name);

	return TRUE;
}


/*
static BOOL
GetSystemName( const void *pvSystemStore, DWORD dwFlags, PENUM_ARG pEnumArg, LPCWSTR *ppwszSystemName)
{
//-------------------------------------------------------------------
// Declare local variables.

        *ppwszSystemName = NULL;

        if (pEnumArg->hKeyBase && 0 == (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG))   {
                printf("Failed => RELOCATE_FLAG not set in callback. \n");
                return FALSE;
        }
        else  {
                if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG)   {
                        PCERT_SYSTEM_STORE_RELOCATE_PARA pRelocatePara;
                        if (!pEnumArg->hKeyBase) {
                                MyHandleError("Failed => RELOCATE_FLAG is set in callback");
                        }
                        pRelocatePara = (PCERT_SYSTEM_STORE_RELOCATE_PARA) pvSystemStore;
                        if (pRelocatePara->hKeyBase != pEnumArg->hKeyBase)   {
                                MyHandleError("Wrong hKeyBase passed to callback");
                        }

                        *ppwszSystemName = pRelocatePara->pwszSystemStore;
                }
                else   {
                        *ppwszSystemName = (LPCWSTR) pvSystemStore;
                }
        }

        return TRUE;
}
*/

BOOL WINAPI
Callback_CertEnumSystemStore(const void *pvSystemStore, DWORD dwFlags,
		PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg)
{
	ENUM_ARG *enumArg = (ENUM_ARG *)pvArg;
	struct sc_card *card = enumArg->card;
	struct sc_context *ctx = card->ctx;
	LPCWSTR pwszSystemStore = (LPCWSTR) pvSystemStore;
	char name[255];

	if (wcstombs(name, pwszSystemStore, sizeof(name)))
		sc_log(ctx, "%s: %s", enumArg->title, name);

	return TRUE;
}


static int
vsctpm_md_test_list_cards(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_reader *reader =  card->reader;
	LPTSTR pmszCards = NULL, pCard;
	DWORD cch = SCARD_AUTOALLOCATE;
	LONG rv;
	int ii;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_global_private_data *gpriv = priv->gpriv;

	sc_log(ctx, "MD PKCS15 test 'list cards' started");
	if (!priv->gpriv->SCardListCards)  {
		sc_log(ctx, "No 'SCardListCards' handle");
		return SC_SUCCESS;
	}

	// Retrieve the list of cards.
	rv = gpriv->SCardListCards(gpriv->pcsc_ctx, reader->atr.value, NULL, 0, (LPTSTR)&pmszCards, &cch);
	if ( rv != SCARD_S_SUCCESS )   {
		sc_log(ctx, "Failed SCardListCards: error %lX", rv);
		return SC_SUCCESS;
	}

	for (ii=0, pCard = pmszCards; '\0' != *pCard; ii++)   {
		LPTSTR szProvider = NULL;
		DWORD chProvider = SCARD_AUTOALLOCATE;
		HCRYPTPROV hCryptProv;

		sc_log(ctx, "cards: %i -- %s", ii, pCard);
		// Get the library name
		chProvider = SCARD_AUTOALLOCATE;
		rv = gpriv->SCardGetCardTypeProviderName(gpriv->pcsc_ctx, pCard, SCARD_PROVIDER_KSP, (LPTSTR)&szProvider, &chProvider);
		if (rv != SCARD_S_SUCCESS)    {
			sc_log(ctx, "Failed SSCardGetCardTypeProviderName: error %lX", rv);
			break;
		}
		sc_log(ctx, "KSP provider: %i -- %s", ii, szProvider);

		chProvider = SCARD_AUTOALLOCATE;
		rv = gpriv->SCardGetCardTypeProviderName(gpriv->pcsc_ctx, pCard, SCARD_PROVIDER_CSP, (LPTSTR)&szProvider, &chProvider);
		if (rv != SCARD_S_SUCCESS)    {
			sc_log(ctx, "Failed SSCardGetCardTypeProviderName: error %lX", rv);
			break;
		}
		sc_log(ctx, "CSP provider: %i -- %s", ii, szProvider);

		if(CryptAcquireContext(&hCryptProv, NULL, szProvider, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
			unsigned char data[2000];
			size_t sz;
			sc_log(ctx, "Acquired Crypto provider %lX", hCryptProv);

			sz = sizeof(data);
			if (CryptGetProvParam(hCryptProv,PP_ENUMCONTAINERS, data, &sz, CRYPT_FIRST))   {
				sc_log(ctx, "First container '%s'", (char *)data);

				sz = sizeof(data);
				while(CryptGetProvParam(hCryptProv,PP_ENUMCONTAINERS, data, &sz, CRYPT_NEXT))   {
					sc_log(ctx, "Next container '%s'", (char *)data);
					sz = sizeof(data);
				}
			}

			sz = sizeof(data);
			if (CryptGetProvParam(hCryptProv, PP_SMARTCARD_READER, data, &sz, CRYPT_FIRST))
				sc_log(ctx, "Smartcard reader '%s'(%i)", (char *)data, sz);

			sz = sizeof(data);
			if (CryptGetProvParam(hCryptProv, PP_SMARTCARD_GUID, data, &sz, CRYPT_FIRST))
				sc_log(ctx, "Smartcard GUID '%s'(%i)", sc_dump_hex(data,sz), sz);

			if (!CryptReleaseContext(hCryptProv, 0))
				sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
			else
				sc_log(ctx, "CryptReleaseContext() released");
		}
		else   {
			sc_log(ctx, "CryptAcquireContext() failed: error %X", GetLastError());
		}

		pCard = pCard + strlen(pCard) + 1;
	}

	if (gpriv->SCardFreeMemory)
		rv = gpriv->SCardFreeMemory(gpriv->pcsc_ctx, pmszCards);
	else
		sc_log(ctx, "No 'SCardFreeMemory' handle");

	sc_log(ctx, "MD test 'list cards' finished");
	return SC_SUCCESS;
}


static int
vsctpm_md_test_list_providers(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_reader *reader =  card->reader;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_global_private_data *gpriv = priv->gpriv;
	ENUM_ARG enumArg;

	sc_log(ctx, "MD test 'list providers' started");

	enumArg.card = card;
	enumArg.title = "Store Location";

	if(CertEnumSystemStoreLocation(0, &enumArg, Callback_CertEnumSystemStoreLocation))
		sc_log(ctx, "CertEnumSystemStoreLocation() failed  , error %X", GetLastError());
	else
		sc_log(ctx, "CertEnumSystemStoreLocation() success");

	enumArg.title = "Store Current User";
	if(CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &enumArg, Callback_CertEnumSystemStore))
		sc_log(ctx, "CertEnumSystemStore() failed  , error %X", GetLastError());
	else
		sc_log(ctx, "CertEnumSystemStore() success");

	enumArg.title = "Store Local Machine";
	if(CertEnumSystemStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &enumArg, Callback_CertEnumSystemStore))
		sc_log(ctx, "CertEnumSystemStore() failed  , error %X", GetLastError());
	else
		sc_log(ctx, "CertEnumSystemStore() success");

	sc_log(ctx, "MD test 'list providers' finished");
	return SC_SUCCESS;
}


int
vsctpm_md_test(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_reader *reader =  card->reader;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_global_private_data *gpriv = priv->gpriv;
	HCERTSTORE hCertStore;
	int rv;

	sc_log(ctx, "MD test started, pcsc_ctx %p", gpriv->pcsc_ctx);

	rv = vsctpm_md_test_list_cards(card);
	LOG_TEST_RET(ctx, rv, "'List cards' test failed");

	rv = vsctpm_md_test_list_providers(card);
	LOG_TEST_RET(ctx, rv, "'List providers' test failed");

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL,
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (!hCertStore)   {
		sc_log(ctx, "CertOpenSystemStore() failed, error %X", GetLastError());
	}
	else   {
		PCCERT_CONTEXT pCertContext = NULL;
		unsigned char buf[12000];
		size_t len;

		sc_log(ctx, "CertOpenSystemStore() hCertStore %X", hCertStore);
		while(pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))   {
			char pszNameString[256];

			if(!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))   {
				sc_log(ctx, "CertificateName failed, error Ox%X", GetLastError());
				continue;
			}
			sc_log(ctx, "Certificate for '%s', pCertContext %p", pszNameString, pCertContext);
			sc_log(ctx, "type 0x%X, data(%i) %p", pCertContext->dwCertEncodingType, pCertContext->cbCertEncoded, pCertContext->pbCertEncoded);
			// sc_log(ctx, "cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
			sc_log(ctx, "cert serial '%s'", sc_dump_hex(pCertContext->pCertInfo->SerialNumber.pbData, pCertContext->pCertInfo->SerialNumber.cbData));

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_IDENTIFIER_PROP_ID, buf, &len))
				sc_log(ctx, "KeyID (%i) %s", len, sc_dump_hex(buf, len));

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &len))   {
				CRYPT_KEY_PROV_INFO *keyInfo;
				char name[255];

				// sc_log(ctx, "KeyInfo (%i) %s", len, sc_dump_hex(buf, len));
				keyInfo = (CRYPT_KEY_PROV_INFO *)buf;

				sc_log(ctx, "KeyInfo (%i), key spec 0x%X, provType 0x%X, flags 0x%X, number of params %i", len,
						keyInfo->dwKeySpec, keyInfo->dwProvType, keyInfo->dwFlags, keyInfo->cProvParam);
				if (wcstombs(name, keyInfo->pwszContainerName, sizeof(name)))
					sc_log(ctx, "pwszContainerName: %s", name);
				if (wcstombs(name, keyInfo->pwszProvName, sizeof(name)))
					sc_log(ctx, "pwszProvName: %s", name);
			}
			else   {
				sc_log(ctx, "CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) failed, error Ox%X", GetLastError());
			}
		}

		if (!CertCloseStore(hCertStore, 0))
			sc_log(ctx, "CertCloseStore() failed, error %X", GetLastError());
		else
			sc_log(ctx, "CertCloseStore() cert store closed");
	}

	{
		int rv;
		sc_log(ctx, "CardAuthenticateEx() failed: RESET-CARD");
		rv = card->reader->ops->reconnect(card->reader, SCARD_LEAVE_CARD);
		LOG_TEST_RET(ctx, rv, "Cannot reconnect card");

		sc_md_delete_context(card);
		rv = sc_md_acquire_context(card);
		LOG_TEST_RET(ctx, rv, "Failed to get CMAP size");
	}


	sc_log(ctx, "MD test finished");
	return SC_SUCCESS;
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

	md->hmd = LoadLibrary(VSCTPM_MODULE_NAME);
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

	if (priv->md.cmap_data.value)
		free(priv->md.cmap_data.value);

	if (priv->md.hmd)
		FreeLibrary(priv->md.hmd);

	memset(&priv->md, 0, sizeof(priv->md));
}


void
vsctpm_md_free(struct sc_card *card, void *ptr)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (!ptr)
		return;

	if (!priv->md.card_data.pfnCspFree)
		sc_log(ctx, "Invalid CARD_DATA: CSP-FREE not defined");
	else
		priv->md.card_data.pfnCspFree(ptr);
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
vsctpm_md_get_card_info(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct vsctpm_md_card_capabilities *caps = &priv->md.info;
	HRESULT hRes = S_OK;
	DWORD sz = 0;
	int ii;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardGetProperty)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sz = sizeof(caps->free_space);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_FREE_SPACE,
			(PBYTE)(&caps->free_space), sizeof(caps->free_space), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_FREE_SPACE) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Free space available:%i,containers:%i,max_containers:%i",
			caps->free_space.dwBytesAvailable,  caps->free_space.dwKeyContainersAvailable,  caps->free_space.dwMaxKeyContainers);

	sz = sizeof(caps->caps);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_CAPABILITIES,
			(PBYTE)(&caps->caps), sizeof(caps->caps), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_CAPABILITIES) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Caps version:%i,keyGen:%i,certCopression:%i", caps->caps.dwVersion, caps->caps.fKeyGen, caps->caps.fCertificateCompression);

	sz = sizeof(caps->sign_key_sizes);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_KEYSIZES,
			(PBYTE)(&caps->sign_key_sizes), sizeof(caps->sign_key_sizes), &sz, AT_SIGNATURE);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_KEYSIZES AT_SIGNATURE) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Sign key sizes version:%i,minBitLen:%i,defaultBitLen:%i,maxBitLen:%i,incrBitLen:%i", caps->sign_key_sizes.dwVersion,
			caps->sign_key_sizes.dwMinimumBitlen, caps->sign_key_sizes.dwDefaultBitlen,
			caps->sign_key_sizes.dwMaximumBitlen, caps->sign_key_sizes.dwIncrementalBitlen);

	sz = sizeof(caps->keyexchange_key_sizes);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_KEYSIZES,
			(PBYTE)(&caps->keyexchange_key_sizes), sizeof(caps->keyexchange_key_sizes), &sz, AT_KEYEXCHANGE);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_KEYSIZES AT_KEYEXCHANGE) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "KeyExchange sizes version:%i,minBitLen:%i,defaultBitLen:%i,maxBitLen:%i,incrBitLen:%i", caps->keyexchange_key_sizes.dwVersion,
			caps->keyexchange_key_sizes.dwMinimumBitlen, caps->keyexchange_key_sizes.dwDefaultBitlen,
			caps->keyexchange_key_sizes.dwMaximumBitlen, caps->keyexchange_key_sizes.dwIncrementalBitlen);

	sz = sizeof(caps->key_import);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_KEY_IMPORT_SUPPORT,
			(PBYTE)(&caps->key_import), sizeof(caps->key_import), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_KEYIMPORT_SUPPORT) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Key import support 0x%X", caps->key_import);

	sz = sizeof(caps->list_pins);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_LIST_PINS,
			(PBYTE)(&caps->list_pins), sizeof(caps->list_pins), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_LIST_PINS) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "List PINs 0x%X", caps->list_pins);

	for (ii=0; ii<6 && hRes!=SCARD_E_NO_KEY_CONTAINER; ii++)   {
		DWORD pin_id;

		sz = sizeof(pin_id);
		hRes = priv->md.card_data.pfnCardGetContainerProperty(&priv->md.card_data, ii, CCP_PIN_IDENTIFIER, (PBYTE)(&pin_id), sz, &sz, 0);
		if (hRes != SCARD_S_SUCCESS)
			sc_log(ctx, "CardGetContainerProperty(CCP_PIN_IDENTIFIER) failed: hRes %lX", hRes);
		else
			sc_log(ctx, "%i: PIN ID 0x%X", ii, pin_id);
	}

	// vsctpm_md_test(card);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_pin_authentication_state(struct sc_card *card, DWORD *out)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct vsctpm_md_card_capabilities *caps = &priv->md.info;
	HRESULT hRes = S_OK;
	DWORD sz = 0, auth_state;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardGetProperty)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sz = sizeof(auth_state);
	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_AUTHENTICATED_STATE,
			(PBYTE)(&auth_state), sizeof(auth_state), &sz, 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty(CP_CARD_AUTHENTICATED_STATE) failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}
	sc_log(ctx, "Authentication state 0x%X", auth_state);

	if (out)
		*out = auth_state;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_pin_authenticate(struct sc_card *card, unsigned char *pin, size_t pin_size, int *tries_left)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD attempts = 0;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardAuthenticateEx)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "vsctpm_md_pin_authenticate(%i:'%s')", pin_size, pin ? sc_dump_hex(pin, pin_size) : "null");
	hRes = priv->md.card_data.pfnCardAuthenticateEx(&priv->md.card_data, ROLE_USER, 0, pin, strlen(pin), NULL, NULL, &attempts);
	if (hRes == SCARD_W_RESET_CARD)   {
		int rv;
		sc_log(ctx, "CardAuthenticateEx() failed: RESET-CARD");
		rv = card->reader->ops->reconnect(card->reader, SCARD_LEAVE_CARD);
		LOG_TEST_RET(ctx, rv, "Cannot reconnect card");

		sc_md_delete_context(card);
		rv = sc_md_acquire_context(card);
		LOG_TEST_RET(ctx, rv, "Failed to get CMAP size");

		hRes = priv->md.card_data.pfnCardAuthenticateEx(&priv->md.card_data, ROLE_USER, 0, pin, strlen(pin), NULL, NULL, &attempts);
	}

	if (hRes == SCARD_W_WRONG_CHV)   {
		if (tries_left)
			*tries_left = attempts;
		sc_log(ctx, "attempts left %i", attempts);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}
	else if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardAuthenticateEx() failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_write_file(struct sc_card *card, char *dir_name, char *file_name,
		unsigned char *out, size_t out_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "called CardWriteFile(%s,%s)", dir_name, file_name);

	if (!out || !out_len || !file_name)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (!priv->md.card_data.pfnCardWriteFile)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "MD write file(%s,%s), data(%i,'%s')", dir_name, file_name, out_len, sc_dump_hex(out, out_len));
	hRes = priv->md.card_data.pfnCardWriteFile(&priv->md.card_data, dir_name, file_name, 0, out, out_len);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardWriteFile(%s,%s) failed: hRes %lX", dir_name, file_name, hRes);
		LOG_FUNC_RETURN(ctx, (vsctpm_md_get_sc_error(hRes)));
	}

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
		LOG_FUNC_RETURN(ctx, (vsctpm_md_get_sc_error(hRes)));
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
		vsctpm_md_free(card, buf);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
static int
vsctpm_md_pkcs15_container_init(struct sc_card *card, struct vsctpm_publickeublob *pubkey_hd, struct vsctpm_pkcs15_container *p15cont)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD sz = -1;
	unsigned char *modulus;

	LOG_FUNC_CALLED(ctx);
	if (!pubkey_hd || !p15cont)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (pubkey_hd->publickeystruc.bType != PUBLICKEYBLOB)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if (pubkey_hd->publickeystruc.aiKeyAlg != CALG_RSA_KEYX && pubkey_hd->publickeystruc.aiKeyAlg != CALG_RSA_SIGN)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if (pubkey_hd->rsapubkey.magic != 0x31415352)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	memset(p15cont, 0, sizeof(p15cont));

	vsctpm_md_test(card);

 * TODO ..........................;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
*/

static int
vsctpm_md_cmap_get_cert_context(struct sc_card *card, struct vsctpm_md_container *vsctpm_cont)
{
	struct sc_context *ctx = card->ctx;
	HCERTSTORE hCertStore;

	LOG_FUNC_CALLED(ctx);

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL,
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (!hCertStore)   {
		sc_log(ctx, "CertOpenSystemStore() failed, error %X", GetLastError());
	}
	else   {
		PCCERT_CONTEXT pCertContext = NULL;
		unsigned char buf[12000];
		size_t len;

		sc_log(ctx, "CertOpenSystemStore() hCertStore %X", hCertStore);
		while(pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))   {
			char pszNameString[256];

			if(!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))   {
				sc_log(ctx, "CertificateName failed, error Ox%X", GetLastError());
				continue;
			}
			sc_log(ctx, "Found certificate '%s'", pszNameString);

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &len))   {
				CRYPT_KEY_PROV_INFO *keyInfo = (CRYPT_KEY_PROV_INFO *)buf;
				if (!wcscmp(keyInfo->pwszContainerName, vsctpm_cont->rec.wszGuid))   {
					if (vsctpm_cont->rec.wSigKeySizeBits && (keyInfo->dwKeySpec == AT_SIGNATURE))   {
						sc_log(ctx, "Sign certificate matched");
						// sc_log(ctx, "Sign cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
						if (vsctpm_cont->signRequestContext)   {
							 CertFreeCertificateContext(vsctpm_cont->signRequestContext);
							 vsctpm_cont->signRequestContext = NULL;
						}
						vsctpm_cont->signCertContext = CertDuplicateCertificateContext(pCertContext);
					}
					else if (vsctpm_cont->rec.wKeyExchangeKeySizeBits && (keyInfo->dwKeySpec == AT_KEYEXCHANGE))   {
						sc_log(ctx, "KeyExchange certificate matched");
						// sc_log(ctx, "KeyExchange cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
						if (vsctpm_cont->exRequestContext)   {
							 CertFreeCertificateContext(vsctpm_cont->exRequestContext);
							 vsctpm_cont->exRequestContext = NULL;
						}
						vsctpm_cont->exCertContext = CertDuplicateCertificateContext(pCertContext);
					}
				}
			}
			else   {
				sc_log(ctx, "CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) failed, error Ox%X", GetLastError());
				continue;
			}
		}

		if (!CertCloseStore(hCertStore, 0))
			sc_log(ctx, "CertCloseStore() failed, error %X", GetLastError());
		else
			sc_log(ctx, "CertCloseStore() cert store closed");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_md_cmap_get_request_context(struct sc_card *card, struct vsctpm_md_container *vsctpm_cont)
{
	struct sc_context *ctx = card->ctx;
	HCERTSTORE hCertStore;

	LOG_FUNC_CALLED(ctx);

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL,
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"REQUEST");
	if (!hCertStore)   {
		sc_log(ctx, "CertOpenSystemStore() failed, error %X", GetLastError());
	}
	else   {
		PCCERT_CONTEXT pCertContext = NULL;
		unsigned char buf[12000];
		size_t len;

		sc_log(ctx, "CertOpenSystemStore() hCertStore %X", hCertStore);
		while(pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))   {
			char pszNameString[256];

			if(!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))   {
				sc_log(ctx, "CertificateName failed, error Ox%X", GetLastError());
				continue;
			}
			sc_log(ctx, "Found certificate '%s'", pszNameString);

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &len))   {
				CRYPT_KEY_PROV_INFO *keyInfo = (CRYPT_KEY_PROV_INFO *)buf;
				if (!wcscmp(keyInfo->pwszContainerName, vsctpm_cont->rec.wszGuid))   {
					if (vsctpm_cont->rec.wSigKeySizeBits && (keyInfo->dwKeySpec == AT_SIGNATURE))   {
						sc_log(ctx, "Sign request matched");
						if (!vsctpm_cont->signCertContext)   {
							sc_log(ctx, "Sign request dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
							vsctpm_cont->signRequestContext = CertDuplicateCertificateContext(pCertContext);
						}
					}
					else if (vsctpm_cont->rec.wKeyExchangeKeySizeBits && (keyInfo->dwKeySpec == AT_KEYEXCHANGE))   {
						sc_log(ctx, "KeyExchange request matched");
						if (!vsctpm_cont->exCertContext)   {
							sc_log(ctx, "KeyExchange request dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
							vsctpm_cont->exRequestContext = CertDuplicateCertificateContext(pCertContext);
						}
					}
				}
			}
			else   {
				sc_log(ctx, "CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) failed, error Ox%X", GetLastError());
				continue;
			}
		}

		if (!CertCloseStore(hCertStore, 0))
			sc_log(ctx, "CertCloseStore() failed, error %X", GetLastError());
		else
			sc_log(ctx, "CertCloseStore() cert store closed");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
vsctpm_md_cmap_get_key_context(struct sc_card *card, struct vsctpm_md_container *vsctpm_cont)
{
	struct sc_context *ctx = card->ctx;
        struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
        HCRYPTPROV hCryptProv;
        HRESULT hRes = S_OK;
	DWORD dwEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
        unsigned char cmap_guid[256];
        size_t sz;

        LOG_FUNC_CALLED(ctx);
        if (!vsctpm_cont)
                LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	wcstombs(cmap_guid, vsctpm_cont->rec.wszGuid, sizeof(cmap_guid));
	sc_log(ctx, "Get key context for contaner '%s'", cmap_guid);

        if ((vsctpm_cont->rec.bFlags & CONTAINER_MAP_VALID_CONTAINER) == 0)   {
		sc_log(ctx, "Ignore non-valid container '%s'", cmap_guid);
                LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

        if (!vsctpm_cont->rec.wSigKeySizeBits && !vsctpm_cont->rec.wKeyExchangeKeySizeBits)    {
		sc_log(ctx, "Ignore container '%s' without keys", cmap_guid);
                LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

        if(!CryptAcquireContext(&hCryptProv, cmap_guid, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
                sc_log(ctx, "CryptAcquireContext(CRYPT_MACHINE_KEYSET) failed: error %X", GetLastError());
                LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
        }

	if (vsctpm_cont->rec.wSigKeySizeBits)   {
		CERT_PUBLIC_KEY_INFO *pub_info;

		if (CryptExportPublicKeyInfo(hCryptProv, AT_SIGNATURE, dwEncodingType, NULL, &sz))   {
			pub_info = vsctpm_cont->signPublicKeyInfo = malloc(sz);
			if (vsctpm_cont->signPublicKeyInfo == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

			if (CryptExportPublicKeyInfo(hCryptProv, AT_SIGNATURE, dwEncodingType, vsctpm_cont->signPublicKeyInfo, &sz))   {
				pub_info = (CERT_PUBLIC_KEY_INFO *)vsctpm_cont->signPublicKeyInfo;
				sc_log(ctx, "CryptExportPublicKeyInfo pubkey(%i) %s", pub_info->PublicKey.cbData, sc_dump_hex(pub_info->PublicKey.pbData, pub_info->PublicKey.cbData));
				sc_log(ctx, "CryptExportPublicKeyInfo algorithm '%s'", pub_info->Algorithm.pszObjId);
				sc_log(ctx, "CryptExportPublicKeyInfo objId '%s'", sc_dump_hex(pub_info->Algorithm.Parameters.pbData, pub_info->Algorithm.Parameters.cbData));
			}
			else   {
				sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", GetLastError());
			}
		}
		else   {
			sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", GetLastError());
		}
	}

	if (vsctpm_cont->rec.wKeyExchangeKeySizeBits)   {
		CERT_PUBLIC_KEY_INFO *pub_info;

		if (CryptExportPublicKeyInfo(hCryptProv, AT_KEYEXCHANGE, dwEncodingType, NULL, &sz))   {
			pub_info = vsctpm_cont->exPublicKeyInfo = malloc(sz);
			if (vsctpm_cont->exPublicKeyInfo == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

			if (CryptExportPublicKeyInfo(hCryptProv, AT_KEYEXCHANGE, dwEncodingType, vsctpm_cont->exPublicKeyInfo, &sz))   {
				pub_info = (CERT_PUBLIC_KEY_INFO *)vsctpm_cont->exPublicKeyInfo;
				sc_log(ctx, "CryptExportPublicKeyInfo pubkey(%i) %s", pub_info->PublicKey.cbData, sc_dump_hex(pub_info->PublicKey.pbData, pub_info->PublicKey.cbData));
				sc_log(ctx, "CryptExportPublicKeyInfo algorithm '%s'", pub_info->Algorithm.pszObjId);
				sc_log(ctx, "CryptExportPublicKeyInfo objId '%s'", sc_dump_hex(pub_info->Algorithm.Parameters.pbData, pub_info->Algorithm.Parameters.cbData));
			}
			else   {
				sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", GetLastError());
			}
		}
		else   {
			sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", GetLastError());
		}
	}

        sc_log(ctx, "CryptReleaseContext");
        if (!CryptReleaseContext(hCryptProv, 0))   {
                sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
                LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
        }

        LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_cmap_init_container(struct sc_card *card, int idx, struct vsctpm_md_container *vsctpm_cont)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	char cmap_guid[256];
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!vsctpm_cont)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (!priv->md.card_data.pfnCardGetContainerInfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv = vsctpm_md_cmap_size(card);
	LOG_TEST_RET(ctx, rv, "Failed to get CMAP size");

	if ((idx + 1) > rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

	memset(vsctpm_cont, 0, sizeof(struct vsctpm_md_container));
	vsctpm_cont->idx = idx;
	vsctpm_cont->rec = *((PCONTAINER_MAP_RECORD)priv->md.cmap_data.value + idx);

	rv = vsctpm_md_cmap_get_cert_context(card, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failed to get certificate for container");

	rv = vsctpm_md_cmap_get_request_context(card, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failed to get request for container");

	rv = vsctpm_md_cmap_get_key_context(card, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failed to get key contexts");

	wcstombs(cmap_guid, vsctpm_cont->rec.wszGuid, sizeof(cmap_guid));
	sc_log(ctx, "Container('%s') contexts SignCert:%i ExKeyCert:%i SignReq:%i ExKeyReq:%i", cmap_guid,
			vsctpm_cont->signCertContext != NULL, vsctpm_cont->exCertContext != NULL,
			vsctpm_cont->signRequestContext != NULL, vsctpm_cont->exRequestContext != NULL);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_cmap_get_free_index(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
        unsigned char *buf = NULL;
        size_t buf_len = 0;
        struct vsctpm_md_container mdc;
        int    rv, idx, nn_cont;

        LOG_FUNC_CALLED(ctx);

        rv = vsctpm_md_cmap_size(card);
        LOG_TEST_RET(ctx, rv, "CMAP cannot get size");
        nn_cont = rv;
        sc_log(ctx, "CMAP length %i", nn_cont);

        for (idx=0; idx < nn_cont; idx++)   {
		int br = 0;
                rv = vsctpm_md_cmap_init_container(card, idx, &mdc);
                if (rv == SC_ERROR_OBJECT_NOT_FOUND)
                        break;
                LOG_TEST_RET(ctx, rv, "Get MD container error");

                sc_log(ctx, "cmap-record %i: flags %X, sizes %i/%i", idx, mdc.rec.bFlags, mdc.rec.wSigKeySizeBits, mdc.rec.wKeyExchangeKeySizeBits);

                br = ((mdc.rec.bFlags & CONTAINER_MAP_VALID_CONTAINER) == 0);
		if (!br)
			br = ((mdc.rec.wSigKeySizeBits == 0) && (mdc.rec.wKeyExchangeKeySizeBits == 0));

		vsctpm_md_free_container(ctx, &mdc);
		if (br)
			break;
	}

        sc_log(ctx, "returns free index %i", idx);
	LOG_FUNC_RETURN(ctx, idx);
}


int
vsctpm_md_new_guid(struct sc_context *ctx, char *guid, size_t guid_len)
{
	unsigned char buf[16];
	int ii, rv;

	srand((unsigned)time(NULL));
	for (ii=0; ii<sizeof(buf); ii++)
		*(buf + ii) = (unsigned char)(rand() & 0xFF);

	rv = sc_pkcs15_serialize_guid(buf, sizeof(buf), 1, guid, guid_len);
	LOG_TEST_RET(ctx, rv, "Cannot serialize GUID");
	sc_log(ctx, "Generated guid '%s'", guid);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_cmap_get_empty_container(struct sc_card *card,  unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
        int    idx, nn_cont;
	char cmap_guid[256];

        LOG_FUNC_CALLED(ctx);

	if (out && out_len)   {
		*out = NULL;
		*out_len = 0;
	}

        nn_cont = vsctpm_md_cmap_size(card);
        LOG_TEST_RET(ctx, nn_cont, "CMAP cannot get size");

        for (idx=0; idx < nn_cont; idx++)   {
		CONTAINER_MAP_RECORD *rec = (CONTAINER_MAP_RECORD *)(priv->md.cmap_data.value + sizeof(CONTAINER_MAP_RECORD)*idx);

                sc_log(ctx, "try cmap-record %i: flags %X, sizes %i/%i", idx, rec->bFlags, rec->wSigKeySizeBits, rec->wKeyExchangeKeySizeBits);
		if ((rec->bFlags & CONTAINER_MAP_VALID_CONTAINER) && ((rec->wSigKeySizeBits != 0) || (rec->wKeyExchangeKeySizeBits != 0)))
			continue;

		wcstombs(cmap_guid, rec->wszGuid, sizeof(cmap_guid));
		if (strlen(cmap_guid) == 0)
			continue;

		if (out && out_len)   {
			*out = strdup(cmap_guid);
			if (*out == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			*out_len = strlen(cmap_guid) + 1;
			sc_log(ctx, "returns guid(%i) '%s', idx:%i", *out_len, *out, idx);
		}
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_RECORD_NOT_FOUND);
}


/*
int
__vsctpm_md_cmap_get_container(struct sc_card *card, int idx, struct vsctpm_md_container *vsctpm_cont)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD sz = -1;
	CONTAINER_INFO cinfo;
	CONTAINER_MAP_RECORD *cmap_record = NULL;
	char cmap_guid[256];
	struct vsctpm_publickeublob *pubkey_hdr = NULL;
	struct vsctpm_pkcs15_container p15cont;
	int rv, nn_cont;

	LOG_FUNC_CALLED(ctx);

	if (!priv->md.card_data.pfnCardGetContainerInfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (priv->md.cmap_data.value == NULL)   {
		rv = vsctpm_md_read_file(card, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, &priv->md.cmap_data.value, &priv->md.cmap_data.len);
		LOG_TEST_RET(ctx, rv, "Cannot read CMAP file");
	}

	nn_cont = priv->md.cmap_data.len / sizeof(CONTAINER_MAP_RECORD);
	if ((idx + 1) > nn_cont)   {
		vsctpm_md_free(card, priv->md.cmap_data.value);
		priv->md.cmap_data.value = NULL;
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}

	cmap_record = (CONTAINER_MAP_RECORD *)(priv->md.cmap_data.value);
	sc_log(ctx, "SignKey size %i, ExKey size %i", (cmap_record + idx)->wSigKeySizeBits, (cmap_record + idx)->wKeyExchangeKeySizeBits);
	if (wcstombs(cmap_guid, (cmap_record + idx)->wszGuid, sizeof(cmap_guid)))
		sc_log(ctx, "Container: %s", cmap_guid);

	memset(&cinfo, 0, sizeof(cinfo));
	cinfo.dwVersion = CONTAINER_INFO_CURRENT_VERSION;

	hRes = priv->md.card_data.pfnCardGetContainerInfo(&priv->md.card_data, idx, 0, &cinfo);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "pfhCardGetContainerInfo(%i) failed: hRes %lX", idx, hRes);
		rv = (hRes == SCARD_E_NO_KEY_CONTAINER) ? SC_ERROR_OBJECT_NOT_FOUND : SC_ERROR_INTERNAL;
		LOG_FUNC_RETURN(ctx, rv);
	}
	sc_log(ctx, "md-cont %i: sign %i, key-ex %i", idx, cinfo.cbSigPublicKey, cinfo.cbKeyExPublicKey);

	if (!vsctpm_cont)   {
		vsctpm_md_free(card, priv->md.cmap_data.value);
		priv->md.cmap_data.value = NULL;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	if (cinfo.pbKeyExPublicKey && cinfo.pbSigPublicKey)   {
		sc_log(ctx, "Two keys (Sign and KeyEx) in one container not yet supported");
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	if (cinfo.pbKeyExPublicKey && cinfo.cbKeyExPublicKey)
		pubkey_hdr = (struct vsctpm_publickeublob *)cinfo.pbKeyExPublicKey;
	else if (cinfo.pbSigPublicKey && cinfo.cbSigPublicKey)
		pubkey_hdr = (struct vsctpm_publickeublob *)cinfo.pbSigPublicKey;
	else
		LOG_FUNC_RETURN(ctx, SC_ERROR_CORRUPTED_DATA);

	rv = vsctpm_md_pkcs15_container_init(card, pubkey_hdr, &p15cont);
	LOG_TEST_RET(ctx, rv, "Failed to parse pubkeyblob");

	rv = vsctpm_md_pkcs15_container_get_cert(card, &p15cont, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failes to get certificate for container");

	memset(vsctpm_cont, 0, sizeof(struct vsctpm_md_container));
	vsctpm_cont->idx = idx;
	vsctpm_cont->rec = *((PCONTAINER_MAP_RECORD)priv->md.cmap_data.value + idx);
	vsctpm_cont->info = cinfo;
	vsctpm_cont->p15cont = p15cont;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
*/


#if 0
int
vsctpm_md_cmap_size(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.cmap_data.value == NULL)   {
		rv = vsctpm_md_read_file(card, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, &priv->md.cmap_data.value, &priv->md.cmap_data.len);
		LOG_TEST_RET(ctx, rv, "Cannot read CMAP file");
	}

	return (priv->md.cmap_data.len / sizeof(CONTAINER_MAP_RECORD));
}


int
vsctpm_md_cmap_reload(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.cmap_data.value)   {
		vsctpm_md_free(card, priv->md.cmap_data.value);
		priv->md.cmap_data.value = NULL;
		priv->md.cmap_data.len = 0;
	}

	rv = vsctpm_md_read_file(card, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, &priv->md.cmap_data.value, &priv->md.cmap_data.len);
	LOG_TEST_RET(ctx, rv, "Cannot read CMAP file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif

int
vsctpm_md_cmap_size(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	int rv, ii, nn_cont = 0;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.cmap_data.value == NULL)   {
		HCRYPTPROV hCryptProv;
		HRESULT hRes = S_OK;
		char path[200], default_cont[200];
		unsigned char data[2000];
		size_t sz;

		sprintf(path, "\\\\.\\%s\\", card->reader->name);
		sc_log(ctx, "CryptAcquireContext('%s',DEFAULT_CONTAINER_OPTIONAL|SILENT)", path);
		if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DEFAULT_CONTAINER_OPTIONAL | CRYPT_SILENT))   {
			sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		}

		sz = sizeof(data);
		if (CryptGetProvParam(hCryptProv, PP_CONTAINER, data, &sz, 0))   {
			strcpy(default_cont, (char *)data);
			sc_log(ctx, "Default container '%s'", default_cont);
		}

		sz = sizeof(data);
		if (CryptGetProvParam(hCryptProv,PP_ENUMCONTAINERS, data, &sz, CRYPT_FIRST))   {
			CONTAINER_MAP_RECORD rec;

			do   {
				sc_log(ctx, "Container(%i) '%s'", nn_cont, (char *)data);
				memset(&rec, 0, sizeof(CONTAINER_MAP_RECORD));
				mbstowcs(rec.wszGuid, data, MAX_CONTAINER_NAME_LEN + 1);

				if (!strcmp(data, default_cont))
					rec.bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;

				sc_log(ctx, "Container(%i) priv->md.cmap_data.value %p", nn_cont, priv->md.cmap_data.value);
				priv->md.cmap_data.value = (char *) realloc(priv->md.cmap_data.value, (nn_cont + 1) * sizeof(CONTAINER_MAP_RECORD));
				if (priv->md.cmap_data.value == NULL)
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				sc_log(ctx, "Container(%i) priv->md.cmap_data.value %p", nn_cont, priv->md.cmap_data.value);
				rec.bFlags |= CONTAINER_MAP_VALID_CONTAINER;

				memcpy(priv->md.cmap_data.value + nn_cont*sizeof(CONTAINER_MAP_RECORD), &rec, sizeof(CONTAINER_MAP_RECORD));
				nn_cont++;

				sz = sizeof(data);
				hRes = CryptGetProvParam(hCryptProv,PP_ENUMCONTAINERS, data, &sz, CRYPT_NEXT);
				sc_log(ctx, "HRES '%X'", hRes);
			} while(hRes);
			priv->md.cmap_data.len = nn_cont * sizeof(CONTAINER_MAP_RECORD);
		}

		hRes = CryptReleaseContext(hCryptProv, 0);
		sc_log(ctx, "CryptReleaseContext() %s", hRes ? "released" : "failed");

		for (ii=0; ii<nn_cont; ii++)   {
			CONTAINER_MAP_RECORD *rec = NULL;
			HCRYPTKEY  hKey;
			char cont_guid[255];

			rec = (CONTAINER_MAP_RECORD *)(priv->md.cmap_data.value + ii * sizeof(CONTAINER_MAP_RECORD));
			wcstombs(cont_guid, rec->wszGuid, sizeof(cont_guid));

			sprintf(path, "\\\\.\\%s\\%s", card->reader->name, cont_guid);
			sc_log(ctx, "CryptAcquireContext('%s',CRYPT_MACHINE_KEYSET)", path);
			if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
				sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
				LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
			}

			if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hKey))   {
				sz = sizeof(data);
				if (CryptGetKeyParam(hKey, KP_KEYLEN, data, &sz, 0))
					rec->wKeyExchangeKeySizeBits = *((DWORD *)data);
			}

			if (CryptGetUserKey(hCryptProv, AT_SIGNATURE, &hKey))   {
				sz = sizeof(data);
				if (CryptGetKeyParam(hKey, KP_KEYLEN, data, &sz, 0))
					rec->wSigKeySizeBits = *((DWORD *)data);
			}

			hRes = CryptReleaseContext(hCryptProv, 0);
			sc_log(ctx, "KeyExchange %i, Sign %i", rec->wKeyExchangeKeySizeBits, rec->wSigKeySizeBits);
		}
	}

	nn_cont = priv->md.cmap_data.len / sizeof(CONTAINER_MAP_RECORD);
	LOG_FUNC_RETURN(ctx, nn_cont);
}


int
vsctpm_md_cmap_reload(struct sc_card *card)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (priv->md.cmap_data.value)   {
		free(priv->md.cmap_data.value);
		priv->md.cmap_data.value = NULL;
		priv->md.cmap_data.len = 0;
	}

	rv = vsctpm_md_cmap_size(card);
	LOG_TEST_RET(ctx, rv, "Cannot read CMAP file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_get_challenge(struct sc_card *card, unsigned char *rnd, size_t len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	PBYTE pbBinChallenge = NULL;
	DWORD cBinChallenge = 0;
	unsigned char *ptr = NULL;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardGetChallenge)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	hRes = priv->md.card_data.pfnCardGetChallenge(&priv->md.card_data, &pbBinChallenge, &cBinChallenge);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetChallenge(%p,%i) failed: hRes %lX", rnd, len, hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}
	sc_log(ctx, "Generated challenge(%i) %s", cBinChallenge, sc_dump_hex(pbBinChallenge, cBinChallenge));
	if (!rnd)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (len < cBinChallenge)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	len = cBinChallenge;
	memcpy(rnd, pbBinChallenge, len);
	LocalFree(pbBinChallenge);

	LOG_FUNC_RETURN(ctx, len);
}


int
vsctpm_md_cbc_encrypt(struct sc_card *card,
		unsigned char *key, size_t key_len,
		unsigned char *data, size_t data_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct vsctpm_deskey_blob deskey_blob;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	DWORD dwMode = CRYPT_MODE_CBC;
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);
	if (!key || key_len < sizeof(deskey_blob.key))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	// Prepare encrypt
	memset(&deskey_blob, 0, sizeof(deskey_blob));
	deskey_blob.hdr.bType = PLAINTEXTKEYBLOB;
	deskey_blob.hdr.bVersion = CUR_BLOB_VERSION;
	deskey_blob.hdr.aiKeyAlg = CALG_3DES;
	deskey_blob.keySize = sizeof(deskey_blob.key);
	memcpy(deskey_blob.key, key, deskey_blob.keySize);
	sc_log(ctx, "DES key blob '%s'", sc_dump_hex((unsigned char *)(&deskey_blob), sizeof(deskey_blob)));

	if(!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))   {
		sc_log(ctx, "Error while calling CryptAcquireContext(%s): 0x%08x", MS_ENHANCED_PROV, GetLastError());
		goto end;
	}

	if(!CryptImportKey(hProv, (BYTE*)&deskey_blob, sizeof(deskey_blob), 0, 0, &hKey))   {
		sc_log(ctx, "Error while calling CryptImportKey: 0x%08x", GetLastError());
		goto end;
	}

	if(!CryptSetKeyParam(hKey, KP_MODE, (LPBYTE)&dwMode, 0))   {
		sc_log(ctx, "Error while calling CryptSetKeyParam: 0x%08x", GetLastError());
		goto end;
	}

	sc_log(ctx, "Data to encrypt (%i)'%s'", data_len, sc_dump_hex(data, data_len));
	if(!CryptEncrypt(hKey, 0, FALSE, 0, data, &data_len, data_len))  {
		sc_log(ctx, "Error while calling CryptEncrypt: 0x%08x", GetLastError());
		goto end;
	}

	sc_log(ctx, "Encrypted data '%s'", sc_dump_hex(data, data_len));
	rv = data_len;
end:
	if (hKey)
		CryptDestroyKey(hKey);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
vsctpm_md_get_sc_error(HRESULT res)
{
	switch (res)   {
	case SCARD_S_SUCCESS:
		return SC_SUCCESS;
	case SCARD_W_RESET_CARD:
		return SC_ERROR_CARD_RESET;
	case SCARD_W_WRONG_CHV:
		return SC_ERROR_PIN_CODE_INCORRECT;
	case SCARD_E_INVALID_PARAMETER:
		return SC_ERROR_INCORRECT_PARAMETERS;
	case SCARD_E_UNSUPPORTED_FEATURE:
		return SC_ERROR_NOT_SUPPORTED;
	case SCARD_W_CHV_BLOCKED:
		return SC_ERROR_AUTH_METHOD_BLOCKED;
	case SCARD_W_SECURITY_VIOLATION:
		return SC_ERROR_NOT_ALLOWED;
	case SCARD_E_NO_MEMORY:
		return SC_ERROR_NOT_ENOUGH_MEMORY;
	}

	return SC_ERROR_INTERNAL;
}


int
vsctpm_md_admin_login(struct sc_card *card, unsigned char *auth, size_t auth_len, int *tries_left)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD attemptsRemaining = -1;

	LOG_FUNC_CALLED(ctx);
	if (!auth || !auth_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "Auth Data(%i)'%s'", auth_len, sc_dump_hex(auth, auth_len));

	hRes = priv->md.card_data.pfnCardAuthenticateEx(&priv->md.card_data, ROLE_ADMIN, CARD_PIN_SILENT_CONTEXT,
			auth, auth_len, NULL, NULL, &attemptsRemaining);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardAuthenticateEx() failed: hRes %lX", hRes);

		if (tries_left && attemptsRemaining != -1)
			*tries_left = attemptsRemaining;

		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}
	sc_log(ctx, "User PIN unblocked");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_user_pin_unblock(struct sc_card *card,
		unsigned char *auth, size_t auth_len,
		const unsigned char *pin, size_t pin_len)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	// DWORD tries_left = VSCTPM_USER_PIN_RETRY_COUNT;
	DWORD tries_left = 0;
	HRESULT hRes = S_OK;

	LOG_FUNC_CALLED(ctx);
	if (!auth || !auth_len || !pin || !pin_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "Auth Data(%i)'%s'", auth_len, sc_dump_hex(auth, auth_len));
	sc_log(ctx, "NewPIN(%i)'%s'", pin_len, sc_dump_hex(pin, pin_len));
	hRes = priv->md.card_data.pfnCardUnblockPin(&priv->md.card_data, wszCARD_USER_USER,
			auth, auth_len,
			pin, pin_len,
			tries_left, CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardUnblockPin(%p,%i %p,%i) failed: hRes %lX", auth, auth_len, pin, pin_len, hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}
	sc_log(ctx, "User PIN unblocked");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_get_pin_info(struct sc_card *card, DWORD role, PIN_INFO *pin_info)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD len = sizeof(PIN_INFO);

	LOG_FUNC_CALLED(ctx);
	if (!pin_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "Get PIN info, role 0x%X", role);

	hRes = priv->md.card_data.pfnCardGetProperty(&priv->md.card_data, CP_CARD_PIN_INFO, (unsigned char *)pin_info, len, &len, role);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardGetProperty() failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_logout(struct sc_card *card, DWORD role)
{
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	HRESULT hRes = S_OK;
	DWORD len = sizeof(PIN_INFO);

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardDeauthenticateEx)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	sc_log(ctx, "MD logout for PIN role 0x%X", role);

	hRes = priv->md.card_data.pfnCardDeauthenticateEx(&priv->md.card_data, CREATE_PIN_SET(role), 0);
	if (hRes != SCARD_S_SUCCESS)   {
		sc_log(ctx, "CardDeauthenticateEx() failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_free_container (struct sc_context *ctx, struct vsctpm_md_container *mdc)
{
        LOG_FUNC_CALLED(ctx);
        if(!mdc)
                LOG_FUNC_RETURN(ctx, SC_SUCCESS);

        sc_log(ctx, "signCertContext %p", mdc->signCertContext);
        if (mdc->signCertContext)
                CertFreeCertificateContext(mdc->signCertContext);
        mdc->signCertContext = NULL;

        sc_log(ctx, "exCertContext %p", mdc->exCertContext);
        if (mdc->exCertContext)
                CertFreeCertificateContext(mdc->exCertContext);
        mdc->exCertContext = NULL;

        sc_log(ctx, "signRequestContext %p", mdc->signRequestContext);
        if (mdc->signRequestContext)
                CertFreeCertificateContext(mdc->signRequestContext);
        mdc->signRequestContext = NULL;

        sc_log(ctx, "exRequestContext %p", mdc->exRequestContext);
        if (mdc->exRequestContext)
                CertFreeCertificateContext(mdc->exRequestContext);
        mdc->signRequestContext = NULL;

	sc_log(ctx, "signPublicKeyInfo %p", mdc->signPublicKeyInfo);
	if (mdc->signPublicKeyInfo)
		free(mdc->signPublicKeyInfo);
	mdc->signPublicKeyInfo = NULL;

	sc_log(ctx, "exPublicKeyInfo %p", mdc->exPublicKeyInfo);
	if (mdc->exPublicKeyInfo)
		free(mdc->exPublicKeyInfo);
	mdc->exPublicKeyInfo = NULL;

        memset(mdc, 0, sizeof(struct vsctpm_md_container));
        LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_cmap_create_container(struct sc_card *card, char *pin, unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	DWORD dwAuthState = 0;
	HRESULT hRes = S_OK;
	HCRYPTPROV hCryptProv;
	unsigned char *key_blob = NULL;
	unsigned char data[2000];
        char cont_guid[50], path[200];
	size_t sz;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!out || !out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	*out = NULL;
	*out_len = 0;

	rv = vsctpm_md_cmap_get_empty_container(card, out, out_len);
	if (rv == SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	else if (rv != SC_ERROR_RECORD_NOT_FOUND)
		LOG_TEST_RET(ctx, rv, "Failed to get empty container");

	sprintf(path, "\\\\.\\%s\\", card->reader->name);
	sc_log(ctx, "CryptAcquireContext('%s',DEFAULT_CONTAINER_OPTIONAL|SILENT)", path);
	if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DEFAULT_CONTAINER_OPTIONAL | CRYPT_SILENT))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptSetProvParam(PP_SIGNATURE_PIN)");
	if(!CryptSetProvParam(hCryptProv, PP_SIGNATURE_PIN, pin, 0))   {
		sc_log(ctx, "CryptSetProvParam(PP_SIGNATURE_PIN) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
	if(!CryptSetProvParam(hCryptProv, PP_KEYEXCHANGE_PIN, pin, 0))   {
		sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptReleaseContext('%s')", card->reader->name);
	if (!CryptReleaseContext(hCryptProv, 0))   {
		sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	rv = vsctpm_md_new_guid(ctx, cont_guid, sizeof(cont_guid));
	LOG_TEST_RET(ctx, rv, "Failed to get new guid");

	sprintf(path, "\\\\.\\%s\\%s", card->reader->name, cont_guid);
	sc_log(ctx, "CryptAcquireContext('%s',CRYPT_NEWKEYSET)", path);
	if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_NEWKEYSET))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptGetProvParam(PP_CONTAINER)");
	sz = sizeof(data);
	if (CryptGetProvParam(hCryptProv, PP_CONTAINER, data, &sz, 0))   {
		sc_log(ctx, "New container '%s'(%i)", (char *)data, sz);

		*out = strdup(data);
		if (*out == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		*out_len = strlen(data);
	}

	sc_log(ctx, "CryptReleaseContext");
	if (!CryptReleaseContext(hCryptProv, 0))   {
		sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
vsctpm_md_key_generate(struct sc_card *card, char *container, unsigned type, size_t key_length, char *pin,
		unsigned char **pubkey, size_t *pubkey_len)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	DWORD dwFlags;
	HCRYPTKEY hKey;
	HRESULT hRes = S_OK;
	HCRYPTPROV hCryptProv;
	size_t sz;
	int rv;
	DWORD dwEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

	LOG_FUNC_CALLED(ctx);
	if (!container)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "CMAP container '%s', type %X, key-size 0x%X", container, type, key_length);

	if(!CryptAcquireContext(&hCryptProv, container, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_MACHINE_KEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Context CRYPT_MACHINE_KEYSET acquired on '%s'", container);

	sc_log(ctx, "Set PIN '%s' type %i in crypto provider", pin, type);
	if(!CryptSetProvParam(hCryptProv, type == AT_KEYEXCHANGE ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN, pin, 0))   {
		sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN/PP_SIGNATURE_PIN) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	dwFlags = key_length << 16;
	if (!CryptGenKey(hCryptProv, type, dwFlags, &hKey))   {
		sc_log(ctx, "CryptGenKey() failed: error %X", GetLastError());
		rv = SC_ERROR_INTERNAL;
		goto out;
	}
	sc_log(ctx, "Key handle %X", hKey);

	if (CryptExportPublicKeyInfo(hCryptProv, type, dwEncodingType, NULL, &sz))   {
		CERT_PUBLIC_KEY_INFO *pub_info = (CERT_PUBLIC_KEY_INFO *)malloc(sz);
		if (pub_info == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		if (CryptExportPublicKeyInfo(hCryptProv, type, dwEncodingType, pub_info, &sz))   {
			if (pubkey && pubkey_len)   {
				*pubkey = malloc(pub_info->PublicKey.cbData);
				if (*pubkey == NULL)
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				memcpy(*pubkey, pub_info->PublicKey.pbData, pub_info->PublicKey.cbData);
				*pubkey_len = pub_info->PublicKey.cbData;
			}
		}
		else   {
			sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", GetLastError());
		}
		free(pub_info);
	}
	else   {
		sc_log(ctx, "CryptExportPublicKeyInfo(get-size) failed: error %X", GetLastError());
	}

	rv = SC_SUCCESS;
out:
	sc_log(ctx, "CryptReleaseContext");
	if (!CryptReleaseContext(hCryptProv, 0))   {
		sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
vsctpm_md_key_import(struct sc_card *card, char *container, unsigned type, size_t key_length, char *pin,
		unsigned char *blob, size_t blob_len)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	HCRYPTKEY hKey;
	HRESULT hRes = S_OK;
	HCRYPTPROV hCryptProv;
	DWORD dwEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	DWORD cbKeyBlob = 0;
	LPBYTE pbKeyBlob = NULL;
	CERT_PUBLIC_KEY_INFO *pub_info = NULL;
	size_t sz;
	HCERTSTORE hCertStore = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!container)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "CMAP container '%s', type %X, key-size 0x%X, blob(%p,%i)", container, type, key_length, blob, blob_len);

	if (!CryptDecodeObjectEx(dwEncodingType, PKCS_RSA_PRIVATE_KEY, blob, blob_len, 0, NULL, NULL, &cbKeyBlob))   {
		sc_log(ctx, "CryptDecodeObjectEx('get size') failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	pbKeyBlob = (LPBYTE) LocalAlloc(0, cbKeyBlob);
        if (!CryptDecodeObjectEx(dwEncodingType, PKCS_RSA_PRIVATE_KEY, blob, blob_len, 0, NULL, pbKeyBlob, &cbKeyBlob))   {
		sc_log(ctx, "CryptDecodeObjectEx('key blob') failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "KeyBlob(%i): %s", cbKeyBlob, sc_dump_hex(pbKeyBlob, cbKeyBlob));

	if(!CryptAcquireContext(&hCryptProv, container, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_MACHINE_KEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_log(ctx, "Context CRYPT_MACHINE_KEYSET acquired on '%s'", container);

	sc_log(ctx, "Set PIN '%s' type %i in crypto provider", pin, type);
	if(!CryptSetProvParam(hCryptProv, type == AT_KEYEXCHANGE ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN, pin, 0))   {
		HRESULT hRes = GetLastError();
		sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN/PP_SIGNATURE_PIN) failed: error %X", hRes);
		rv = vsctpm_md_get_sc_error(hRes);
		goto out;
	}

	if (!CryptImportKey(hCryptProv, pbKeyBlob, cbKeyBlob, 0, 0, &hKey))   {
		HRESULT hRes = GetLastError();
		sc_log(ctx, "CryptImportKey() failed: error %X", hRes);
		rv = vsctpm_md_get_sc_error(hRes);
		goto out;
	}
	sc_log(ctx, "Key(%p,%i) imported", pbKeyBlob, cbKeyBlob);

	if (!CryptExportPublicKeyInfo(hCryptProv, type, dwEncodingType, NULL, &sz))   {
		HRESULT hRes = GetLastError();
		sc_log(ctx, "CryptExportPublicKeyInfo(get-size) failed: error %X", hRes);
		rv = vsctpm_md_get_sc_error(hRes);
		goto out;
	}
	sc_log(ctx, "PublicKeyInfo size %i", sz);

	pub_info = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(0, sz);
	if (!pub_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	if (!CryptExportPublicKeyInfo(hCryptProv, type, dwEncodingType, pub_info, &sz))   {
		HRESULT hRes = GetLastError();
		sc_log(ctx, "CryptExportPublicKeyInfo() failed: error %X", hRes);
		rv = vsctpm_md_get_sc_error(hRes);
		goto out;
	}

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL,
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (!hCertStore)   {
		hRes = GetLastError();
		sc_log(ctx, "CertOpenStore() failed, error %X", hRes);
		rv = vsctpm_md_get_sc_error(hRes);
		goto out;
	}
	sc_log(ctx, "CertOpenStore('MY') hCertStore %X", hCertStore);

	pCertContext = CertFindCertificateInStore(hCertStore, dwEncodingType, 0, CERT_FIND_PUBLIC_KEY, pub_info, NULL);
	if (pCertContext)   {
		sc_log(ctx, "Found connected certificate type 0x%X, blob(%i) '%s'", pCertContext->dwCertEncodingType, pCertContext->cbCertEncoded,
				sc_dump_hex(pCertContext->pbCertEncoded,  pCertContext->cbCertEncoded));

		if (!CryptSetKeyParam(hKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0))   {
			hRes = GetLastError();
			sc_log(ctx, "CryptSetKeyParam(KP_CERTIFICATE) failed: error %X", hRes);
			rv = vsctpm_md_get_sc_error(hRes);
		}
		else   {
			rv = SC_SUCCESS;
		}
	}
	else   {
		sc_log(ctx, "No connected certificate");
	}

	rv = SC_SUCCESS;
out:
	if (hCertStore)
		CertCloseStore(hCertStore, 0);

	if (pub_info)
		LocalFree(pub_info);

	if (pbKeyBlob)
		LocalFree(pbKeyBlob);

	if (hKey)
		CryptDestroyKey(hKey);

	sc_log(ctx, "CryptReleaseContext");
	if (!CryptReleaseContext(hCryptProv, 0))   {
		sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
vsctpm_md_store_my_cert(struct sc_card *card, char *pin, char *container,
		unsigned char *blob, size_t blob_len)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	int rv = SC_ERROR_INTERNAL;
	HRESULT hRes;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Store 'MY' certificate; container '%s'", (container ? container : "none"));

	if (container && strlen(container))   {
		HCRYPTPROV hCryptProv;
		HCRYPTKEY hKey = 0;
		BOOL bRes;

		if(!CryptAcquireContext(&hCryptProv, container, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))   {
			hRes = GetLastError();
			sc_log(ctx, "CryptAcquireContext(CRYPT_MACHINE_KEYSET) failed: error %X", hRes);
			LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
		}
		sc_log(ctx, "Acquired crypto context '%s'", container);

		if (pin && strlen(pin))   {
			sc_log(ctx, "Set both PIN(%i) context params", strlen(pin));

			if(!CryptSetProvParam(hCryptProv, PP_KEYEXCHANGE_PIN, pin, 0))
				sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN) failed");
			if(!CryptSetProvParam(hCryptProv, PP_SIGNATURE_PIN, pin, 0))
				sc_log(ctx, "CryptSetProvParam(PP_SIGNATURE_PIN) failed");
		}

		if (!CryptGetUserKey(hCryptProv, AT_SIGNATURE, &hKey))   {
			hRes = GetLastError();
			if (hRes == NTE_NO_KEY)
				if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hKey))
					hRes = GetLastError();
		}

		if (hKey)   {
			if (!CryptSetKeyParam(hKey, KP_CERTIFICATE, blob, 0))   {
				hRes = GetLastError();
				sc_log(ctx, "CryptSetKeyParam(KP_CERTIFICATE) failed: error %X", hRes);
				rv = vsctpm_md_get_sc_error(hRes);
			}
			else   {
				rv = SC_SUCCESS;
			}
		}
		else   {
			sc_log(ctx, "CryptGetUserKey() failed: error %X", hRes);
			rv = vsctpm_md_get_sc_error(hRes);
		}

		if (!CryptReleaseContext(hCryptProv, 0))
			sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
	}
	else   {
		HCERTSTORE hCertStore;
		PCCERT_CONTEXT pCertContext = NULL;
		unsigned char buf[12000];
		size_t len;

		hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL,
				CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
		if (!hCertStore)   {
			hRes = GetLastError();
			sc_log(ctx, "CertOpenStore() failed, error %X", hRes);
			LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
		}

		sc_log(ctx, "CertOpenStore() hCertStore %X", hCertStore);

		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, blob, blob_len);
		if (!pCertContext) {
			hRes = GetLastError();
			sc_log(ctx, "CertCreateCertificateContext() failed: error %X", hRes);
			rv = vsctpm_md_get_sc_error(hRes);
		}
		else   {
			if (!CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL))   {
				HRESULT hRes = GetLastError();
				sc_log(ctx, "CertAddCertificateContextToStore() failed: error %X", hRes);
				rv = vsctpm_md_get_sc_error(hRes);
			}
			else   {
				sc_log(ctx, "Certificate added to store ");
				rv = SC_SUCCESS;
			}
			CertFreeCertificateContext(pCertContext);
		}

		if (!CertCloseStore(hCertStore, 0))
			sc_log(ctx, "CertCloseStore() failed, error %X", GetLastError());
	}

	LOG_FUNC_RETURN(ctx, rv);
}

#if 0
int
vsctpm_md_cmap_delete_container(struct sc_card *card, int idx)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	HRESULT hRes = S_OK;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!priv->md.card_data.pfnCardDeleteContainer)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "Delete container(idx:%i)", idx);
	hRes = priv->md.card_data.pfnCardDeleteContainer(&priv->md.card_data, idx, 0);
	if (hRes != S_OK)   {
		sc_log(ctx, "CardDeleteContainer() failed: hRes %lX", hRes);
		LOG_FUNC_RETURN(ctx, vsctpm_md_get_sc_error(hRes));
	}

	rv = vsctpm_md_cmap_reload(card);
	LOG_TEST_RET(ctx, rv, "Failed to reload CMAP");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif

#if 0
int
vsctpm_md_cmap_delete_container(struct sc_card *card, char *pin, char *container)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	HCRYPTPROV hCryptProv;
	HRESULT hRes = S_OK;
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "CryptAcquireContext(delete '%s')", container);
	if(!CryptAcquireContext(&hCryptProv, container, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DELETEKEYSET))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_DELETEKEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	rv = vsctpm_md_cmap_reload(card);
	LOG_TEST_RET(ctx, rv, "Failed to reload CMAP");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif

int
vsctpm_md_cmap_delete_container(struct sc_card *card, char *pin, char *container)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	HCRYPTPROV hCryptProv;
        char path[200];
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!container)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sprintf(path, "\\\\.\\%s\\%s", card->reader->name, container);
	sc_log(ctx, "CryptAcquireContext('%s',DEFAULT_CONTAINER_OPTIONAL|SILENT)", path);
	if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DEFAULT_CONTAINER_OPTIONAL | CRYPT_SILENT))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptSetProvParam(PP_SIGNATURE_PIN)");
	if(!CryptSetProvParam(hCryptProv, PP_SIGNATURE_PIN, pin, 0))   {
		sc_log(ctx, "CryptSetProvParam(PP_SIGNATURE_PIN) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
	if(!CryptSetProvParam(hCryptProv, PP_KEYEXCHANGE_PIN, pin, 0))   {
		sc_log(ctx, "CryptSetProvParam(PP_KEYEXCHANGE_PIN) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptReleaseContext('%s')", card->reader->name);
	if (!CryptReleaseContext(hCryptProv, 0))   {
		sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "CryptAcquireContext('%s',CRYPT_DELETEKEYSET)", path);
	if(!CryptAcquireContext(&hCryptProv, path, MS_SCARD_PROV_A, PROV_RSA_FULL, CRYPT_DELETEKEYSET))   {
		sc_log(ctx, "CryptAcquireContext(CRYPT_NEWKEYSET) failed: error %X", GetLastError());
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#endif /* ENABLE_MINIDRIVER */
#endif   /* ENABLE_PCSC */
