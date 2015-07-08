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

#if ENABLE_MINIDRIVER
#include <windows.h>
#include "cardmod.h"

struct vsctpm_md_data   {
	CARD_DATA       card_data;
	HMODULE         hmd;
	PFN_CARD_ACQUIRE_CONTEXT acquire_context;
};

#define VSC_MODULE_NAME "msclmd.dll"

int vsctpm_md_init_card_data(struct sc_card *, struct vsctpm_md_data *);
void vsctpm_md_reset_card_data(struct sc_card *);
int vsctpm_md_get_guid(struct sc_card *, unsigned char *, size_t *);
int vsctpm_md_read_file(struct sc_card *, char *, char *, unsigned char **, size_t *);

#endif  /* ENABLE_MINIDRIVER */

#define VSCTPM_MD_ENTRY_DNAME_SIZE 9
#define VSCTPM_MD_ENTRY_FNAME_SIZE 11
struct vsctpm_md_file {
        char dname[VSCTPM_MD_ENTRY_DNAME_SIZE + 1];
        char fname[VSCTPM_MD_ENTRY_FNAME_SIZE + 1];
        unsigned file_id, tag;
};

struct vsctpm_private_data {
        struct vsctpm_md_file *md_files;
        size_t md_files_num;

#if ENABLE_MINIDRIVER
        struct vsctpm_md_data md;
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* _VSCTPM_MD_H */
