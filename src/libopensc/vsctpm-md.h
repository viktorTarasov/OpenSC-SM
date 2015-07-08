#ifndef _VSCTPM_MD_H
#define _VSCTPM_MD_H

#if HAVE_CONFIG_H
#include "config.h"
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
void vsctpm_md_reset_card_data(struct sc_card *, struct vsctpm_md_data *);
int vsctpm_md_get_serial(struct sc_card *, struct vsctpm_md_data *, struct sc_serial_number *);

#endif  /* ENABLE_MINIDRIVER */
#endif /* _VSCTPM_MD_H */
