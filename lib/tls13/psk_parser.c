/*
 * Copyright (C) 2017 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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
#include "tls13/psk_parser.h"

void _gnutls13_psk_parser_init(struct psk_parser_st *p,
			       const unsigned char *data, size_t len,
			       uint16_t identities_len)
{
	memset(p, 0, sizeof(struct psk_parser_st));
	p->identities_len = identities_len;
	p->data = (unsigned char *) data;
	p->len = len;
}

void _gnutls13_psk_parser_deinit(struct psk_parser_st *p,
				 const unsigned char **data, size_t *len)
{
	if (data)
		*data = p->data;
	if (len)
		*len = p->len;
	memset(p, 0, sizeof(struct psk_parser_st));
}

int _gnutls13_psk_parser_next(struct psk_parser_st *p, struct psk_st *psk)
{
	if (p->identities_read >= p->identities_len)
		return -1;

	/* Read a PskIdentity structure */
	psk->identity.size = _gnutls_read_uint16(p->data);
	if (psk->identity.size == 0)
		return -1;

	DECR_LEN(p->len, 2);
	p->data += 2;
	p->identities_read += 2;

	psk->identity.data = p->data;

	DECR_LEN(p->len, psk->identity.size);
	p->data += psk->identity.size;
	p->identities_read += psk->identity.size;

	psk->ob_ticket_age = _gnutls_read_uint32(p->data);
	DECR_LEN(p->len, 4);
	p->data += 4;
	p->identities_read += 4;

	psk->selected_index = p->next_index++;
	return psk->selected_index;
}

