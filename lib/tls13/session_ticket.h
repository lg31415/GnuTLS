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
#ifndef SESSION_TICKET_H
#define SESSION_TICKET_H

struct tls13_nst_st {
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	gnutls_datum_t ticket_nonce;
	gnutls_datum_t ticket;
};

int _gnutls13_send_session_ticket(gnutls_session_t session, unsigned again);
int _gnutls13_recv_session_ticket(gnutls_session_t session,
		gnutls_buffer_st *buf, struct tls13_nst_st *ticket);

int _gnutls13_unpack_session_ticket(gnutls_session_t session,
		gnutls_datum_t *data,
		gnutls_datum_t *rms, gnutls_mac_algorithm_t *kdf_id);

int _gnutls13_session_ticket_set(gnutls_session_t session,
		struct tls13_nst_st *ticket,
		const uint8_t *rms, size_t rms_size,
		const mac_entry_st *prf);
int _gnutls13_session_ticket_get(gnutls_session_t session,
		struct tls13_nst_st *ticket);
int _gnutls13_session_ticket_peek(gnutls_session_t session,
		struct tls13_nst_st *ticket);

void _gnutls13_session_ticket_destroy(struct tls13_nst_st *ticket);
#endif
