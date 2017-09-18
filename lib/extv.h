/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_EXTV_H
#define GNUTLS_EXTV_H

#include <gnutls/gnutls.h>

/* ext-val handling functions */

#define _gnutls_extv_init(v) \
	memset(v, 0, sizeof(tls_ext_vals_st))

void _gnutls_extv_deinit(tls_ext_vals_st *v);

/* check whether any non-advertized extension is present.
 * Requires a vals updated by extv_gen */
#define EXTV_CHECK_UNADVERTIZED 1

/* Server-behavior for hello. Save extensions received, and
 * check for duplicates */
#define EXTV_SAVE_RECEIVED (1<<1)

/* When sending, do not send any extensions that have not
 * been advertized by the other party */
#define EXTV_SEND_SAVED_ONLY (1<<2)

int _gnutls_extv_parse(gnutls_session_t session,
		       gnutls_ext_flags_t msg,
		       gnutls_ext_parse_type_t parse_type,
		       const uint8_t * data, int data_size,
		       tls_ext_vals_st *out,
		       unsigned extv_flags);

int _gnutls_extv_gen(gnutls_session_t session,
		     tls_ext_vals_st *vals,
		     gnutls_buffer_st * extdata,
		     gnutls_ext_flags_t msg,
		     gnutls_ext_parse_type_t,
		     unsigned extv_flags);

void
_gnutls_extv_data_unset(struct ext_data_st *data, const struct extension_entry_st *ext);
void
_gnutls_extv_data_unset_resumed(struct ext_data_st *data, const struct extension_entry_st *ext);

int _gnutls_extv_check_saved(tls_ext_vals_st *v, uint16_t id);
unsigned _gnutls_extv_add_saved(tls_ext_vals_st *v, const struct extension_entry_st *e, unsigned check_dup);

#endif
