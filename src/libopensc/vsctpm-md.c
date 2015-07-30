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
	rv = gpriv->SCardListCards(gpriv->pcsc_ctx, reader->atr.value, NULL, NULL, (LPTSTR)&pmszCards, &cch);
	if ( rv != SCARD_S_SUCCESS )   {
		sc_log(ctx, "Failed SCardListCards: error %lX", rv);
		return SC_SUCCESS;
	}

	for (ii=0, pCard = pmszCards; '\0' != *pCard; ii++)   {
		LPTSTR szProvider = NULL;
		DWORD chProvider = SCARD_AUTOALLOCATE;

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

/*
		if(CryptAcquireContext(&hCryptProv, NULL, szProvider, PROV_RSA_FULL, 0))   {
			sc_log(ctx, "Acquired Crypto provider %lX", hCryptProv);

			if (!CryptReleaseContext(hCryptProv,0))   {
				sc_log(ctx, "CryptReleaseContext() failed: error %X", GetLastError());
			}
		}
		else   {
			sc_log(ctx, "CryptAcquireContext() failed: error %X", GetLastError());
		}
*/
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


static int
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

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
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
			sc_log(ctx, "cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
			sc_log(ctx, "cert serial '%s'", sc_dump_hex(pCertContext->pCertInfo->SerialNumber.pbData, pCertContext->pCertInfo->SerialNumber.cbData));

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_IDENTIFIER_PROP_ID, buf, &len))
				sc_log(ctx, "KeyID (%i) %s", len, sc_dump_hex(buf, len));

			len = sizeof(buf);
			if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &len))   {
				CRYPT_KEY_PROV_INFO *keyInfo;
				char name[255];

				sc_log(ctx, "KeyInfo (%i) %s", len, sc_dump_hex(buf, len));
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
		vsctpm_md_free(card, priv->md.cmap_data.value);

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

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
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
						sc_log(ctx, "Sign cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
						if (vsctpm_cont->signRequestContext)   {
							 CertFreeCertificateContext(vsctpm_cont->signRequestContext);
							 vsctpm_cont->signRequestContext = NULL;
						}
						vsctpm_cont->signCertContext = CertDuplicateCertificateContext(pCertContext);
					}
					else if (vsctpm_cont->rec.wKeyExchangeKeySizeBits && (keyInfo->dwKeySpec == AT_KEYEXCHANGE))   {
						sc_log(ctx, "KeyExchange certificate matched");
						sc_log(ctx, "KeyExchange cert dump '%s'", sc_dump_hex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
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

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
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


int
vsctpm_md_cmap_init_container(struct sc_card *card, int idx, struct vsctpm_md_container *vsctpm_cont)
{
	struct sc_context *ctx = card->ctx;
	struct vsctpm_private_data *priv = (struct vsctpm_private_data *) card->drv_data;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!priv->md.card_data.pfnCardGetContainerInfo)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv = vsctpm_md_cmap_size(card);
	LOG_TEST_RET(ctx, rv, "Failed to get CMAP size");

	if ((idx + 1) > rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

	if (!vsctpm_cont)   {
		vsctpm_md_free(card, priv->md.cmap_data.value);
		priv->md.cmap_data.value = NULL;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	memset(vsctpm_cont, 0, sizeof(struct vsctpm_md_container));
	vsctpm_cont->idx = idx;
	vsctpm_cont->rec = *((PCONTAINER_MAP_RECORD)priv->md.cmap_data.value + idx);

	rv = vsctpm_md_cmap_get_cert_context(card, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failed to get certificate for container");

	rv = vsctpm_md_cmap_get_request_context(card, vsctpm_cont);
	LOG_TEST_RET(ctx, rv, "Failed to get request for container");

	sc_log(ctx, "Container contextx %p %p %p %p",
			vsctpm_cont->signCertContext, vsctpm_cont->exCertContext,
			vsctpm_cont->signRequestContext, vsctpm_cont->exRequestContext);

	vsctpm_md_test(card);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
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


#endif /* ENABLE_MINIDRIVER */
#endif   /* ENABLE_PCSC */

