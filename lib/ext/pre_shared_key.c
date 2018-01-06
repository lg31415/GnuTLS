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

#include "gnutls_int.h"
#include "auth/psk.h"
#include "secrets.h"
#include "mem.h"
#include "str.h"
#include "tls13/finished.h"
#include "tls13/psk_parser.h"
#include "tls13/session_ticket.h"
#include "auth/psk_passwd.h"
#include <ext/session_ticket.h>
#include <ext/pre_shared_key.h>

typedef struct {
	struct tls13_nst_st *session_ticket;
	uint8_t *rms;
	size_t rms_size;
} psk_ext_st;

static int _gnutls13_session_ticket_get(gnutls_session_t session, struct tls13_nst_st *ticket);

static int
compute_psk_from_ticket(const mac_entry_st *prf,
		const uint8_t *rms,
		struct tls13_nst_st *ticket, gnutls_datum_t *key)
{
	int ret;
	unsigned hash_size = prf->output_size;
	char label[] = "resumption";

	key->data = gnutls_malloc(hash_size);
	key->size = hash_size;
	if (key->data == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	ret = _tls13_expand_secret2(prf,
			label, strlen(label),
			ticket->ticket_nonce.data, ticket->ticket_nonce.size,
			rms,
			hash_size,
			key->data);
	if (ret < 0) {
		_gnutls_free_datum(key);
		return gnutls_assert_val(ret);
	}

	return ret;
}

static int
compute_binder_key(const mac_entry_st *prf,
		const uint8_t *key, size_t keylen,
		void *out)
{
	int ret;
	char label[] = "ext_binder";
	size_t label_len = strlen(label);
	uint8_t tmp_key[MAX_HASH_SIZE];

	/* Compute HKDF-Extract(0, psk) */
	ret = _tls13_init_secret2(prf, key, keylen, tmp_key);
	if (ret < 0)
		return ret;

	/* Compute Derive-Secret(secret, label, transcript_hash) */
	ret = _tls13_derive_secret2(prf,
			label, label_len,
			NULL, 0,
			tmp_key,
			out);
	if (ret < 0)
		return ret;

	return 0;
}

static int
compute_psk_binder(unsigned entity,
		const mac_entry_st *prf, unsigned binders_length, unsigned hash_size,
		int exts_length, int ext_offset, unsigned displacement,
		const gnutls_datum_t *psk, const gnutls_datum_t *client_hello,
		void *out)
{
	int ret;
	unsigned extensions_len_pos;
	gnutls_buffer_st handshake_buf;
	uint8_t binder_key[MAX_HASH_SIZE];

	_gnutls_buffer_init(&handshake_buf);

	if (entity == GNUTLS_CLIENT) {
		if (displacement >= client_hello->size) {
			ret = GNUTLS_E_INTERNAL_ERROR;
			goto error;
		}

		gnutls_buffer_append_data(&handshake_buf,
				(const void *) (client_hello->data + displacement),
				client_hello->size - displacement);

		ext_offset -= displacement;
		if (ext_offset <= 0) {
			ret = GNUTLS_E_INTERNAL_ERROR;
			goto error;
		}

		/* This is a ClientHello message */
		handshake_buf.data[0] = 1;

		/*
		 * At this point we have not yet added the binders to the ClientHello,
		 * but we have to overwrite the size field, pretending as if binders
		 * of the correct length were present.
		 */
		_gnutls_write_uint24(handshake_buf.length + binders_length - 2, &handshake_buf.data[1]);
		_gnutls_write_uint16(handshake_buf.length + binders_length - ext_offset,
				&handshake_buf.data[ext_offset]);

		extensions_len_pos = handshake_buf.length - exts_length - 2;
		_gnutls_write_uint16(exts_length + binders_length + 2,
				&handshake_buf.data[extensions_len_pos]);
	} else {
		gnutls_buffer_append_data(&handshake_buf,
				(const void *) client_hello->data,
				client_hello->size - binders_length - 3);
	}

	ret = compute_binder_key(prf,
			psk->data, psk->size,
			binder_key);
	if (ret < 0)
		goto error;

	ret = _gnutls13_compute_finished(prf,
			binder_key, hash_size,
			&handshake_buf,
			out);
	if (ret < 0)
		goto error;

	_gnutls_buffer_clear(&handshake_buf);
	return 0;

error:
	_gnutls_buffer_clear(&handshake_buf);
	return gnutls_assert_val(ret);
}

static int get_credentials(gnutls_session_t session,
		const gnutls_psk_client_credentials_t cred,
		gnutls_datum_t *username, gnutls_datum_t *key)
{
	int ret, retval = 0;
	char *username_str = NULL;

	if (cred->get_function) {
		ret = cred->get_function(session, &username_str, key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		username->data = (uint8_t *) username_str;
		username->size = strlen(username_str);

		retval = username->size;
	} else if (cred->username.data != NULL && cred->key.data != NULL) {
		username->size = cred->username.size;
		if (username->size > 0) {
			username->data = gnutls_malloc(username->size);
			if (!username->data)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			memcpy(username->data, cred->username.data, username->size);
		}

		key->size = cred->key.size;
		if (key->size > 0) {
			key->data = gnutls_malloc(key->size);
			if (!key->data) {
				_gnutls_free_datum(username);
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			}
			memcpy(key->data, cred->key.data, key->size);
		}

		retval = username->size;
	}

	return retval;
}

static int
client_send_params(gnutls_session_t session,
		gnutls_buffer_t extdata,
		const gnutls_psk_client_credentials_t cred)
{
	int ret, extdata_len = 0, ext_offset = 0;
	uint8_t binder_value[MAX_HASH_SIZE];
	size_t length, pos = extdata->length;
	gnutls_datum_t username, key, client_hello;
	const mac_entry_st *prf = _gnutls_mac_to_entry(cred->tls13_binder_algo),
			*ticket_prf = NULL;
	unsigned hash_size = _gnutls_mac_get_algo_len(prf);
	struct tls13_nst_st ticket;
	uint32_t ob_ticket_age = 0;

	if (prf == NULL || hash_size == 0 || hash_size > 255)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	memset(&username, 0, sizeof(gnutls_datum_t));

	ret = get_credentials(session, cred, &username, &key);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* No out-of-band PSKs - let's see if we have a session ticket to send */
	if (ret == 0) {
		ret = _gnutls13_session_ticket_get(session, &ticket);
		if (ret > 0) {
			/* We found a session ticket */
			username.data = ticket.ticket.data;
			username.size = ticket.ticket.size;
			/* Get the PRF for this ticket */
			ticket_prf = _gnutls_mac_to_entry(ticket.kdf_id);
			if (unlikely(ticket_prf == NULL || ticket_prf->output_size == 0)) {
				ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
				goto cleanup;
			}
			/* FIXME 'rms' must not be NULL */
			ret = compute_psk_from_ticket(ticket_prf,
					NULL,
					&ticket, &key);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			/* Calculate obfuscated ticket age, in milliseconds, mod 2^32 */
			ob_ticket_age = (ticket.ticket_lifetime * 1000 + ticket.ticket_age_add) % 4294967296;
		}
	}

	/* No credentials - this extension is not applicable */
	if (ret == 0) {
		ret = 0;
		goto cleanup;
	}

	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	extdata_len += 2;

	if (username.size == 0 || username.size > 65536) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_PASSWORD);
		goto cleanup;
	}

	if ((ret = _gnutls_buffer_append_data_prefix(extdata, 16,
			username.data, username.size)) < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}
	/* Obfuscated ticket age */
	if ((ret = _gnutls_buffer_append_prefix(extdata, 32, ob_ticket_age)) < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}
	/* Total length appended is the length of the data, plus six octets */
	length = (username.size + 6);

	_gnutls_write_uint16(length, &extdata->data[pos]);
	extdata_len += length;

	ext_offset = _gnutls_ext_get_extensions_offset(session);

	/* Add the size of the binder (we only have one) */
	length = (hash_size + 1);

	/* Compute the binders */
	client_hello.data = extdata->data;
	client_hello.size = extdata->length;

	ret = compute_psk_binder(GNUTLS_CLIENT, prf,
			length, hash_size, extdata_len, ext_offset, sizeof(mbuffer_st),
			&key, &client_hello,
			binder_value);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	/* Now append the binders */
	ret = _gnutls_buffer_append_prefix(extdata, 16, length);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	extdata_len += 2;

	_gnutls_buffer_append_prefix(extdata, 8, hash_size);
	_gnutls_buffer_append_data(extdata, binder_value, hash_size);

	extdata_len += (hash_size + 1);

	/* Reference the selected pre-shared key */
	session->key.proto.tls13.psk = key.data;
	session->key.proto.tls13.psk_size = key.size;
	ret = extdata_len;

cleanup:
	_gnutls_free_datum(&username);
	return ret;
}

static int
server_send_params(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret;

	if (!(session->internals.hsk_flags & HSK_PSK_SELECTED))
		return 0;

	ret = _gnutls_buffer_append_prefix(extdata, 16,
			session->key.proto.tls13.psk_selected);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 2;
}

static int
server_find_binder(const unsigned char **data_p, long *len_p,
		int psk_index, gnutls_datum_t *binder_recvd)
{
	uint8_t binder_len;
	int cur_index = 0, binder_found = 0;
	const unsigned char *data = *data_p;
	long len = *len_p;

	while (len > 0) {
		binder_len = *data;
		if (binder_len == 0)
			return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

		DECR_LEN(len, 1);
		data++;

		if (cur_index == psk_index) {
			binder_recvd->data = gnutls_malloc(binder_len);
			if (!binder_recvd->data)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

			binder_recvd->size = binder_len;
			memcpy(binder_recvd->data, data, binder_len);

			DECR_LEN(len, binder_len);
			data += binder_len;

			binder_found = 1;
			break;
		}

		DECR_LEN(len, binder_len);
		data += binder_len;

		binder_len = 0;
		cur_index++;
	}

	*len_p = len;
	*data_p = data;

	return (binder_found ? binder_len : gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS));
}

static int server_recv_params(gnutls_session_t session,
		const unsigned char *data, long len,
		const gnutls_psk_server_credentials_t pskcred)
{
	int ret;
	const mac_entry_st *prf;
	gnutls_datum_t full_client_hello;
	psk_ext_st *priv = NULL;
	uint16_t ttl_identities_len;
	uint8_t binder_value[MAX_HASH_SIZE];
	int psk_index = -1;
	gnutls_datum_t binder_recvd;
	gnutls_datum_t username, key;
	unsigned hash_size;
	struct psk_parser_st psk_parser;
	struct psk_st psk;
	struct ticket_st *ticket = NULL;

	memset(&binder_recvd, 0, sizeof(gnutls_datum_t));
	memset(&username, 0, sizeof(gnutls_datum_t));
	memset(&key, 0, sizeof(gnutls_datum_t));

	/* No credentials - this extension is not applicable */
	if (!pskcred->hint)
		return 0;

	username.data = (unsigned char *) pskcred->hint;
	username.size = strlen(pskcred->hint);

	ret = _gnutls_psk_pwd_find_entry(session, pskcred->hint, &key);
	if (ret < 0)
		return ret;

	if (pskcred->hint) {
		username.data = (unsigned char *) pskcred->hint;
		username.size = strlen(pskcred->hint);

		ret = _gnutls_psk_pwd_find_entry(session, pskcred->hint, &key);
		if (ret < 0)
			return ret;
	}

	ttl_identities_len = _gnutls_read_uint16(data);
	/* The client advertised no PSKs */
	if (ttl_identities_len == 0)
		return 0;

	DECR_LEN(len, 2);
	data += 2;

	_gnutls13_psk_parser_init(&psk_parser, data, len, ttl_identities_len);

	while (_gnutls13_psk_parser_next(&psk_parser, &psk) >= 0) {
		/*
		 * First check if this is an out-of-band PSK.
		 * If it's not, try to decrypt it, as it might be a session ticket.
		 */
		if (username.size == psk.identity.size &&
		    safe_memcmp(username.data, psk.identity.data, psk.identity.size) == 0) {
			psk_index = psk.selected_index;
			break;
		}

		if (psk.identity.size < sizeof(struct ticket_st))
			break;

		ticket = (struct ticket_st *) psk.identity.data;
		if (_gnutls_decrypt_session_ticket(session, ticket) == 0) {
			psk_index = psk.selected_index;

			key.data = ticket->encrypted_state;
			key.size = ticket->encrypted_state_len;
			gnutls_free(ticket->encrypted_state);
			ticket->encrypted_state = NULL;

			session->internals.resumption_requested = 1;

			break;
		}
	}

	_gnutls13_psk_parser_deinit(&psk_parser, &data, (size_t *) &len);

	/* No suitable PSK found */
	if (psk_index < 0)
		return 0;

	DECR_LEN(len, 2);
	data += 2;

	ret = server_find_binder(&data, &len,
			psk_index, &binder_recvd);
	if (ret < 0)
		return gnutls_assert_val(ret);
	if (binder_recvd.size == 0)
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

	priv = gnutls_malloc(sizeof(psk_ext_st));
	if (!priv) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	/* Get full ClientHello */
	if (!_gnutls_ext_get_full_client_hello(session, &full_client_hello)) {
		ret = 0;
		goto cleanup;
	}

	/* Compute the binder value for this PSK */
	prf = _gnutls_mac_to_entry(pskcred->tls13_binder_algo);
	hash_size = prf->output_size;
	compute_psk_binder(GNUTLS_SERVER, prf, hash_size, hash_size, 0, 0, 0,
			&key, &full_client_hello,
			binder_value);
	if (_gnutls_mac_get_algo_len(prf) != binder_recvd.size ||
			safe_memcmp(binder_value, binder_recvd.data, binder_recvd.size)) {
		_gnutls_free_datum(&binder_recvd);
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);
	}

	session->internals.hsk_flags |= HSK_PSK_SELECTED;
	/* Reference the selected pre-shared key */
	session->key.proto.tls13.psk = key.data;
	session->key.proto.tls13.psk_size = key.size;
	session->key.proto.tls13.psk_selected = 0;
	_gnutls_free_datum(&binder_recvd);

cleanup:
	_gnutls_free_datum(&binder_recvd);
	return ret;
}

static int client_recv_params(gnutls_session_t session,
		const unsigned char *data, size_t len)
{
	uint16_t selected_identity = _gnutls_read_uint16(data);
	if (selected_identity == 0)
		session->internals.hsk_flags |= HSK_PSK_SELECTED;
	return 0;
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - GNUTLS_E_INT_RET_0 : Size of extension data is zero.
 *  - <0 : There's been an error.
 *
 * In the client, generates the PskIdentity and PskBinderEntry messages.
 *
 *      PskIdentity identities<7..2^16-1>;
 *      PskBinderEntry binders<33..2^16-1>;
 *
 *      struct {
 *          opaque identity<1..2^16-1>;
 *          uint32 obfuscated_ticket_age;
 *      } PskIdentity;
 *
 *      opaque PskBinderEntry<32..255>;
 *
 * The server sends the selected identity, which is a zero-based index
 * of the PSKs offered by the client:
 *
 *      struct {
 *          uint16 selected_identity;
 *      } PreSharedKeyExtension;
 */
static int _gnutls_psk_send_params(gnutls_session_t session,
		gnutls_buffer_t extdata)
{
	gnutls_psk_client_credentials_t cred = NULL;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT) {
			cred = (gnutls_psk_client_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);
		}

		/*
		 * If there are no PSK credentials, this extension is not applicable,
		 * so we return zero.
		 */
		return (cred ?
				client_send_params(session, extdata, cred) :
				0);
	} else {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED)
			return server_send_params(session, extdata);
		else
			return 0;
	}
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - <0 : There's been an error.
 */
static int _gnutls_psk_recv_params(gnutls_session_t session,
		const unsigned char *data, size_t len)
{
	gnutls_psk_server_credentials_t pskcred;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT)
			return client_recv_params(session, data, len);
		else
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);
	} else {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED) {
			pskcred = (gnutls_psk_server_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);

			/*
			 * If there are no PSK credentials, this extension is not applicable,
			 * so we return zero.
			 */
			return (pskcred ?
					server_recv_params(session, data, len, pskcred) :
					0);
		} else {
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);
		}
	}
}

static void destroy_ticket(struct tls13_nst_st *ticket)
{
	if (ticket) {
		_gnutls_free_datum(&ticket->ticket);
		_gnutls_free_datum(&ticket->ticket_nonce);
		memset(ticket, 0, sizeof(struct tls13_nst_st));
		gnutls_free(ticket);
	}
}

static int copy_ticket(struct tls13_nst_st *src, struct tls13_nst_st *dst)
{
	dst->ticket_lifetime = src->ticket_lifetime;
	dst->ticket_age_add = src->ticket_age_add;

	if (src->ticket_nonce.size > 0) {
		dst->ticket_nonce.data = gnutls_malloc(src->ticket_nonce.size);
		if (dst->ticket_nonce.data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		dst->ticket_nonce.size = src->ticket_nonce.size;
		memcpy(dst->ticket_nonce.data, src->ticket_nonce.data, src->ticket_nonce.size);
	}

	if (src->ticket.size > 0) {
		dst->ticket.data = gnutls_malloc(src->ticket.size);
		if (dst->ticket.data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		dst->ticket.size = src->ticket.size;
		memcpy(dst->ticket.data, src->ticket.data, src->ticket.size);
	}

	return 0;
}

static void _gnutls_psk_deinit(gnutls_ext_priv_data_t epriv)
{
	psk_ext_st *priv;

	if (epriv) {
		priv = epriv;

		destroy_ticket(priv->session_ticket);

		if (priv->rms) {
			gnutls_free(priv->rms);
			priv->rms = NULL;
			priv->rms_size = 0;
		}

		gnutls_free(priv);
	}
}

/*
 * Stores a session ticket locally.
 * All the fields of the ticket are copied, so they can safely be freed when this function returns.
 * The resumption master secret ('rms') is also copied.
 */
int _gnutls13_session_ticket_set(gnutls_session_t session, struct tls13_nst_st *ticket,
		const uint8_t *rms, size_t rms_size)
{
	psk_ext_st *priv = NULL;
	struct tls13_nst_st *src, *dst;

	if (unlikely(ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	if (unlikely(rms == NULL || rms_size == 0))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	priv = gnutls_calloc(1, sizeof(psk_ext_st));
	if (!priv)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	priv->session_ticket = gnutls_calloc(1, sizeof(struct tls13_nst_st));
	if (!priv->session_ticket) {
		goto cleanup;
	}

	/* Copy the ticket */
	src = ticket;
	dst = priv->session_ticket;

	if (copy_ticket(src, dst) < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Copy the resumption master secret ('rms') for this session */
	priv->rms = gnutls_calloc(1, rms_size);
	if (!priv->rms) {
		gnutls_assert();
		goto cleanup;
	}
	priv->rms_size = rms_size;
	memcpy(priv->rms, rms, rms_size);

	_gnutls_hello_ext_set_priv(session,
			GNUTLS_EXTENSION_SESSION_TICKET,
			(gnutls_ext_priv_data_t) priv);
	return 0;

cleanup:
	_gnutls_psk_deinit(priv);
	return GNUTLS_E_MEMORY_ERROR;
}

/*
 * Copy the locally stored session ticket to 'ticket'.
 * The fields of 'ticket' are copied not referenced, so they can be safely freed
 * after this function returns.
 */
static int _gnutls13_session_ticket_get(gnutls_session_t session, struct tls13_nst_st *ticket)
{
	int ret;
	psk_ext_st *priv;
	gnutls_ext_priv_data_t epriv;
	struct tls13_nst_st *src, *dst;

	if (unlikely(ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (_gnutls_hello_ext_get_priv(session,
			GNUTLS_EXTENSION_SESSION_TICKET,
			&epriv) < 0)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	priv = epriv;
	src = priv->session_ticket;
	dst = ticket;

	if ((ret = copy_ticket(src, dst)) < 0) {
		destroy_ticket(ticket);
		return gnutls_assert_val(ret);
	}

	return 0;
}

static int
_gnutls_psk_pack(gnutls_ext_priv_data_t epriv, gnutls_buffer_t buf)
{
	int ret; /* BUFFER_APPEND_NUM expects a variable called 'ret' to exist */
	psk_ext_st *priv = epriv;

	if (!priv)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	BUFFER_APPEND_NUM(buf, priv->session_ticket->ticket_lifetime);
	BUFFER_APPEND_NUM(buf, priv->session_ticket->ticket_age_add);
	BUFFER_APPEND_PFX4(buf,
			priv->session_ticket->ticket_nonce.data,
			priv->session_ticket->ticket_nonce.size);
	BUFFER_APPEND_PFX4(buf,
			priv->session_ticket->ticket.data,
			priv->session_ticket->ticket.size);
	BUFFER_APPEND_PFX4(buf,
			priv->rms,
			priv->rms_size);

	return 0;
}

static int
_gnutls_psk_unpack(gnutls_buffer_t buf, gnutls_ext_priv_data_t *_epriv)
{
	int ret;
	psk_ext_st *priv = NULL;
	gnutls_ext_priv_data_t epriv;

	priv = gnutls_calloc(1, sizeof(psk_ext_st));
	if (!priv)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	priv->session_ticket = gnutls_calloc(1, sizeof(struct tls13_nst_st));
	if (!priv->session_ticket) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	BUFFER_POP_NUM(buf, priv->session_ticket->ticket_lifetime);
	BUFFER_POP_NUM(buf, priv->session_ticket->ticket_age_add);
	BUFFER_POP_DATUM(buf, &priv->session_ticket->ticket_nonce);
	BUFFER_POP_DATUM(buf, &priv->session_ticket->ticket);

	BUFFER_POP_NUM(buf, priv->rms_size);
	priv->rms = gnutls_calloc(1, priv->rms_size);
	if (!priv->rms) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	BUFFER_POP(buf, priv->rms, priv->rms_size);

	epriv = priv;
	*_epriv = epriv;

	return 0;

error:
	/* BUFFER_POP_DATUM and BUFFER_POP_NUM expect a label called 'error' to exist */
	_gnutls_psk_deinit(priv);
	return ret;
}

const hello_ext_entry_st ext_pre_shared_key = {
	.name = "Pre Shared Key",
	.tls_id = 41,
	.gid = GNUTLS_EXTENSION_PRE_SHARED_KEY,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = _gnutls_psk_send_params,
	.recv_func = _gnutls_psk_recv_params,
	.pack_func = _gnutls_psk_pack,
	.unpack_func = _gnutls_psk_unpack,
	.deinit_func = _gnutls_psk_deinit
};
