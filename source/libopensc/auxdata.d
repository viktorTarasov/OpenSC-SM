/*
 * aux-data.h: Non PKCS#15, non ISO7816 data
 *             Used to pass auxiliary data from non PKCS#15, non ISO7816 appliations (like minidriver)
 *             to card specific part through the standard PKCS#15 and ISO7816 frameworks
 *
 * Copyright (C) 2016  Viktor Tarasov <viktor.tarasov@gmail.com>
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

module libopensc.auxdata;

extern(C) :

import libopensc.opensc : sc_context;


enum SC_AUX_DATA_TYPE_NO_DATA        = 0x00;
enum SC_AUX_DATA_TYPE_MD_CMAP_RECORD = 0x01;

/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN       39
 * #define CONTAINER_MAP_VALID_CONTAINER        1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER      2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *      WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *      BYTE bFlags;
 *      BYTE bReserved;
 *      WORD wSigKeySizeBits;
 *      WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
enum SC_MD_MAX_CONTAINER_NAME_LEN          = 39;
enum SC_MD_CONTAINER_MAP_VALID_CONTAINER   = 0x01;
enum SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER = 0x02;

struct sc_md_cmap_record {
	ubyte[SC_MD_MAX_CONTAINER_NAME_LEN + 1] guid;
	size_t guid_len;
	uint flags;
	uint keysize_sign;
	uint keysize_keyexchange;
}

struct sc_auxiliary_data {
	uint type;
	union anonymous {
		sc_md_cmap_record cmap_record;
	}
	anonymous data;
}

int sc_aux_data_set_md_flags(sc_context*, sc_auxiliary_data*, ubyte);
int sc_aux_data_allocate(sc_context*, sc_auxiliary_data**, sc_auxiliary_data*);
int sc_aux_data_set_md_guid(sc_context*, sc_auxiliary_data*, char*);
void sc_aux_data_free(sc_auxiliary_data**);
int sc_aux_data_get_md_guid(sc_context*, sc_auxiliary_data*, uint, ubyte*, size_t*);
int sc_aux_data_get_md_flags(sc_context*, sc_auxiliary_data*, ubyte*);

