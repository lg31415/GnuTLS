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

/* TLS 1.3 secret key derivation handling.
 */

#include <config.h>
#include "gnutls_int.h"
#ifdef HAVE_NETTLE_RSA_PSS
# include <nettle/hkdf.h>
#else
# include "nettle/int/hkdf.h"
#endif
#include <nettle/hmac.h>
#include "secrets.h"

/* HKDF-Extract(0,0) or HKDF-Extract(0, PSK) */
int _tls13_init_secret(gnutls_session_t session, const uint8_t *psk, size_t psk_size)
{
	session->key.temp_secret_size = gnutls_hmac_get_len(session->security_parameters.prf_mac);

	return gnutls_hmac_fast(session->security_parameters.prf_mac,
				"", 0,
				psk, psk_size,
				session->key.temp_secret);
}

int _tls13_update_secret(gnutls_session_t session, const uint8_t *key, size_t key_size)
{
	return gnutls_hmac_fast(session->security_parameters.prf_mac,
				session->key.temp_secret, session->key.temp_secret_size,
				key, key_size,
				session->key.temp_secret);
}

int _tls13_expand_secret(gnutls_session_t session,
			 const char *label, unsigned label_size,
			 const uint8_t *msg, size_t msg_size,
			 const uint8_t secret[MAX_CIPHER_KEY_SIZE],
			 unsigned out_size,
			 void *out)
{
	uint8_t tmp[256] = "tls13 ";
	unsigned digest_size;
	gnutls_buffer_st str;
	int ret;

	if (unlikely(label_size >= sizeof(tmp)-6))
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	digest_size = gnutls_hmac_get_len(session->security_parameters.prf_mac);

	_gnutls_buffer_init(&str);

	ret = _gnutls_buffer_append_prefix(&str, 16, out_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	memcpy(&tmp[6], label, label_size);
	ret = _gnutls_buffer_append_data_prefix(&str, 8, tmp, label_size+6);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_hash_fast((gnutls_digest_algorithm_t)session->security_parameters.prf_mac,
				msg, msg_size, tmp);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data_prefix(&str, 8, tmp, digest_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	switch(session->security_parameters.prf_mac) {
	case GNUTLS_MAC_SHA256:{
		struct hmac_sha256_ctx ctx;

		hmac_sha256_set_key(&ctx, SHA256_DIGEST_SIZE, secret);
		hkdf_expand(&ctx, (nettle_hash_update_func*)hmac_sha256_update,
			(nettle_hash_digest_func*)hmac_sha256_digest, SHA256_DIGEST_SIZE,
			str.length, str.data, out_size, out);
		break;
	}
	case GNUTLS_MAC_SHA384:{
		struct hmac_sha384_ctx ctx;

		hmac_sha384_set_key(&ctx, SHA384_DIGEST_SIZE, secret);
		hkdf_expand(&ctx, (nettle_hash_update_func*)hmac_sha384_update,
			(nettle_hash_digest_func*)hmac_sha384_digest, SHA384_DIGEST_SIZE,
			str.length, str.data, out_size, out);
		break;
	}
	default:
		gnutls_assert();
		ret = GNUTLS_E_INTERNAL_ERROR;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	_gnutls_buffer_clear(&str);
	return ret;
}

int _tls13_derive_secret(gnutls_session_t session,
			 const char *label, unsigned label_size,
			 const uint8_t *msg, size_t msg_size,
			 void *out)
{
	return _tls13_expand_secret(session, label, label_size, msg, msg_size,
				    session->key.temp_secret,
				    gnutls_hmac_get_len(session->security_parameters.prf_mac),
				    out);
}
