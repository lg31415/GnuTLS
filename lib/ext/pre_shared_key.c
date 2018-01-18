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
#include "tls13/finished.h"
#include "auth/psk_passwd.h"
#include <ext/pre_shared_key.h>

typedef struct {
	uint16_t selected_identity;
} psk_ext_st;

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
	const mac_entry_st *prf = _gnutls_mac_to_entry(cred->tls13_binder_algo);
	unsigned hash_size = _gnutls_mac_get_algo_len(prf);

	if (prf == NULL || hash_size == 0 || hash_size > 255)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	memset(&username, 0, sizeof(gnutls_datum_t));

	ret = get_credentials(session, cred, &username, &key);
	if (ret < 0)
		return gnutls_assert_val(ret);
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
	/* Now append the ticket age, which is always zero for out-of-band PSKs */
	if ((ret = _gnutls_buffer_append_prefix(extdata, 32, 0)) < 0) {
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
server_read_identities(const unsigned char **data_p, long *len_p,
		uint16_t ttl_identities_len, gnutls_datum_t *username)
{
	int psk_index = 0, psk_found = 0;
	const unsigned char *identity;
	uint16_t identity_len, ob_ticket_age;
	uint16_t identities_read = 0;
	const unsigned char *data = *data_p;
	long len = *len_p;

	while (identities_read < ttl_identities_len) {
		/* Read a PskIdentity structure */
		identity_len = _gnutls_read_uint16(data);
		if (identity_len == 0)
			return -1;

		DECR_LEN(len, 2);
		data += 2;
		identities_read += 2;

		identity = data;

		DECR_LEN(len, identity_len);
		data += identity_len;
		identities_read += identity_len;

		ob_ticket_age = _gnutls_read_uint32(data);
		DECR_LEN(len, 4);
		data += 4;
		identities_read += 4;

		/*
		 * FIXME
		 * The obfuscated ticket age field should be zero for out-of-band PSKs.
		 * We'll extend this later when we support PSKs derived from NST.
		 */
		if (ob_ticket_age == 0 &&
				username->size == identity_len &&
				safe_memcmp(username->data, identity, identity_len) == 0) {
			psk_found = 1;
			break;
		}

		psk_index++;
	}

	*len_p = len;
	*data_p = data;
	return (psk_found ? psk_index : -1);
}

static int
server_read_binders(const unsigned char **data_p, long *len_p,
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
	int psk_index = 0;
	gnutls_datum_t binder_recvd;
	gnutls_datum_t username, key;
	unsigned hash_size;

	memset(&binder_recvd, 0, sizeof(gnutls_datum_t));

	/* No credentials - this extension is not applicable */
	if (!pskcred->hint)
		return 0;

	username.data = (unsigned char *) pskcred->hint;
	username.size = strlen(pskcred->hint);

	ret = _gnutls_psk_pwd_find_entry(session, pskcred->hint, &key);
	if (ret < 0)
		return ret;

	ttl_identities_len = _gnutls_read_uint16(data);
	/* The client advertised no PSKs */
	if (ttl_identities_len == 0)
		return 0;

	DECR_LEN(len, 2);
	data += 2;

	psk_index = server_read_identities(&data, &len,
			ttl_identities_len, &username);
	if (psk_index < 0)
		return 0;

	DECR_LEN(len, 2);
	data += 2;

	ret = server_read_binders(&data, &len,
			psk_index, &binder_recvd);
	if (ret < 0)
		return gnutls_assert_val(ret);
	if (binder_recvd.size == 0)
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

	priv = gnutls_malloc(sizeof(psk_ext_st));
	if (!priv) {
		_gnutls_free_datum(&binder_recvd);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	/* Get full ClientHello */
	if (!_gnutls_ext_get_full_client_hello(session, &full_client_hello)) {
		_gnutls_free_datum(&binder_recvd);
		return 0;
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

	return 0;
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

static void _gnutls_psk_deinit(gnutls_ext_priv_data_t epriv)
{
	if (epriv)
		gnutls_free(epriv);
}

const hello_ext_entry_st ext_pre_shared_key = {
	.name = "Pre Shared Key",
	.tls_id = 41,
	.gid = GNUTLS_EXTENSION_PRE_SHARED_KEY,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = _gnutls_psk_send_params,
	.recv_func = _gnutls_psk_recv_params,
	.deinit_func = _gnutls_psk_deinit
};
