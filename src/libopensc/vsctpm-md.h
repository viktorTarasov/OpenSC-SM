#ifndef _VSCTPM_MD_H
#define _VSCTPM_MD_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/x509v3.h>

#if ENABLE_MINIDRIVER
#include <windows.h>
#include "cardmod.h"

struct vsctpm_publickeublob {
	PUBLICKEYSTRUC	publickeystruc;
	RSAPUBKEY	rsapubkey;
};

struct vsctpm_md_card_capabilities {
	CARD_FREE_SPACE_INFO free_space;
	CARD_CAPABILITIES caps;
	CARD_KEY_SIZES sign_key_sizes, keyexchange_key_sizes;
	DWORD key_import, list_pins;
};

struct vsctpm_md_data   {
	CARD_DATA       card_data;
	HMODULE         hmd;
	PFN_CARD_ACQUIRE_CONTEXT acquire_context;

	struct vsctpm_md_card_capabilities info;

	struct sc_lv_data cmap_data;
};

struct vsctpm_pkcs15_container {
	struct sc_pkcs15_pubkey *pubkey;
	struct sc_pkcs15_cert *cert;
};

struct vsctpm_md_container {
	int idx;
	CONTAINER_MAP_RECORD rec;

	const CERT_CONTEXT *signCertContext, *exCertContext;
	const CERT_CONTEXT *signRequestContext, *exRequestContext;
	CERT_PUBLIC_KEY_INFO *signPublicKeyInfo, *exPublicKeyInfo;
};

#define VSCTPM_MODULE_NAME "msclmd.dll"

int vsctpm_md_test(struct sc_card *);
int vsctpm_md_init_card_data(struct sc_card *, struct vsctpm_md_data *);
void vsctpm_md_reset_card_data(struct sc_card *);
void vsctpm_md_free(struct sc_card *, void *);
int vsctpm_md_get_guid(struct sc_card *, unsigned char *, size_t *);
int vsctpm_md_read_file(struct sc_card *, char *, char *, unsigned char **, size_t *);
int vsctpm_md_enum_files(struct sc_card *, char *, char **, size_t *);
int vsctpm_md_get_container(struct sc_card *, int, struct vsctpm_md_container *);
int vsctpm_md_cmap_size(struct sc_card *);
int vsctpm_md_cmap_reload(struct sc_card *);
int vsctpm_md_cmap_init_container(struct sc_card *, int, struct vsctpm_md_container *);
int vsctpm_md_get_challenge(struct sc_card *, unsigned char *, size_t);
int vsctpm_md_user_pin_unblock(struct sc_card *, unsigned char *, size_t, const unsigned char *, size_t);
int vsctpm_md_admin_login(struct sc_card *, unsigned char *, size_t, int *);
int vsctpm_md_cbc_encrypt(struct sc_card *, const unsigned char *, size_t, unsigned char *, size_t);
int vsctpm_md_get_property(struct sc_card *, LPCWSTR, void *, unsigned char *);
int vsctpm_md_get_pin_info(struct sc_card *, DWORD, PIN_INFO *);
int vsctpm_md_logout(struct sc_card *, DWORD);
int vsctpm_md_cmap_get_free_index(struct sc_card *);
int vsctpm_md_free_container (struct sc_context *, struct vsctpm_md_container *);
int vsctpm_md_get_card_info(struct sc_card *);
int vsctpm_md_pin_authentication_state(struct sc_card *, DWORD *);
int vsctpm_md_pin_authenticate(struct sc_card *, unsigned char *, size_t, int *);
int vsctpm_md_cmap_delete_container(struct sc_card *, char *, char *);
int vsctpm_md_cmap_delete_certificate(struct sc_card *, char *, struct sc_pkcs15_cert *);
int vsctpm_md_cmap_create_container(struct sc_card *, char *, unsigned char **, size_t *);
int vsctpm_md_key_generate(struct sc_card *, char *, unsigned, size_t, char *, unsigned char **, size_t *);
int vsctpm_md_key_import(struct sc_card *, char *, unsigned, size_t, char *, unsigned char *, size_t);
int vsctpm_md_store_my_cert(struct sc_card *, char *, char *, unsigned char *, size_t);
int vsctpm_get_pin_from_cache(struct sc_pkcs15_card *, char *, size_t);
int vsctpm_md_pin_change(struct sc_card *, const unsigned char *, size_t, const unsigned char *, size_t, int *);
int vsctpm_md_authkey_change(struct sc_card *, const unsigned char *, size_t, const unsigned char *, size_t, int *);
int vsctpm_md_compute_signature(struct sc_card *, int, const unsigned char *, size_t, unsigned char *, size_t);
int vsctpm_md_decipher(struct sc_card *, int, const unsigned char *, size_t, unsigned char *, size_t);
int vsctpm_md_get_serial(struct sc_card *, struct sc_serial_number *);

typedef struct _ENUM_ARG {
	BOOL fAll;
	BOOL fVerbose;
	DWORD dwFlags;
	const void  *pvStoreLocationPara;
	HKEY hKeyBase;

	struct sc_card *card;
	char *title;
} ENUM_ARG, *PENUM_ARG;

struct vsctpm_deskey_blob {
	BLOBHEADER hdr;
	DWORD keySize;
	BYTE key[24];
};

#endif  /* ENABLE_MINIDRIVER */

#define VSCTPM_MD_ENTRY_DNAME_SIZE 9
#define VSCTPM_MD_ENTRY_FNAME_SIZE 11
#define VSCTPM_MD_ENTRY_SIZE 28

struct vsctpm_md_file {
        char dname[VSCTPM_MD_ENTRY_DNAME_SIZE + 1];
        char fname[VSCTPM_MD_ENTRY_FNAME_SIZE + 1];
        unsigned file_id, tag;
};

struct vsctpm_private_data {
        struct vsctpm_md_file *md_files;
        size_t md_files_num;

	unsigned char admin_key[24];
	size_t admin_key_len;

	int user_logged, admin_logged;
#if ENABLE_MINIDRIVER
        struct vsctpm_md_data md;
#endif
	struct sc_security_env sec_env;
	unsigned char sec_data[6];
	unsigned char crt_tag;
};

#ifndef CKM_DES3_CBC
#define CKM_DES3_CBC (0x133UL)
#endif

#define VSCTPM_ALGORITHM_RSA_PKCS1_2048 0x57
#define VSCTPM_ALGORITHM_RSA_PKCS1_1024 0x56
#define VSCTPM_ALGORITHM_RSA_PKCS2_2048 0x47
#define VSCTPM_ALGORITHM_RSA_PKCS2_1024 0x46

#define VSCTPM_CRT_TAG_AT       0xA4
#define VSCTPM_CRT_TAG_CT       0xB8
#define VSCTPM_CRT_TAG_CCT      0xB4
#define VSCTPM_CRT_TAG_DST      0xB6
#define VSCTPM_CRT_TAG_HT       0xAA
#define VSCTPM_CRT_TAG_KAT      0xA6

#define VSCTPM_USER_PIN_RETRY_COUNT 3
#define VSCTPM_ADMIN_PIN_RETRY_COUNT 5

#define VSCTPM_USER_PIN_REF 0x80
#define VSCTPM_ADMIN_PIN_REF 0x82

#define VSCTPM_NOT_USE_APDU

#define HASH_SIZE_CALG_SSL3_SHAMD5 36

#ifdef __cplusplus
}
#endif

#endif /* _VSCTPM_MD_H */
