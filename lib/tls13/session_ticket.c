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

#include "gnutls_int.h"
#include "errors.h"
#include "extv.h"
#include "handshake.h"
#include "mbuffers.h"
#include "ext/pre_shared_key.h"
#include "ext/session_ticket.h"
#include "tls13/session_ticket.h"
#include "auth/cert.h"

#define IV_SIZE 16
#define BLOCK_SIZE 16
#define CIPHER GNUTLS_CIPHER_AES_256_CBC

#define MAC_ALGO GNUTLS_MAC_SHA1

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size);

static int pack_ticket(struct tls13_nst_st *ticket,
		const uint8_t *rms, unsigned rms_size,
		gnutls_datum_t *state)
{
	unsigned char *p;

	state->size = sizeof(uint16_t) +
			sizeof(uint32_t) +
			rms_size;
	state->data = gnutls_malloc(state->size);
	if (!state->data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	p = state->data;

	_gnutls_write_uint16(ticket->kdf_id, p);
	p += sizeof(uint16_t);
	_gnutls_write_uint32(rms_size, p);
	p += sizeof(uint32_t);
	memcpy(p, rms, rms_size);

	return 0;
}

static int unpack_ticket(gnutls_datum_t *state,
		gnutls_mac_algorithm_t *kdf_id,
		gnutls_datum_t *rms)
{
	unsigned rms_len;
	unsigned char *p;

	if (unlikely(state == NULL || kdf_id == NULL || rms == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	p = state->data;

	*kdf_id = (gnutls_mac_algorithm_t) _gnutls_read_uint16(p);
	p += sizeof(uint16_t);

	rms_len = (unsigned) _gnutls_read_uint32(p);
	p += sizeof(uint32_t);

	rms->size = rms_len;
	rms->data = gnutls_malloc(rms->size);
	if (!rms->data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	memcpy(rms->data, p, rms->size);

	return 0;
}

static int digest_ticket(const gnutls_datum_t *key, struct ticket_st *ticket,
		uint8_t *digest)
{
	int ret;
	mac_hd_st digest_hd;
	uint16_t length16;

	ret = _gnutls_mac_init(&digest_hd, mac_to_entry(MAC_ALGO),
			key->data, key->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	length16 = _gnutls_conv_uint16(ticket->encrypted_state_len);

	_gnutls_mac(&digest_hd, ticket->key_name, KEY_NAME_SIZE);
	_gnutls_mac(&digest_hd, ticket->IV, IV_SIZE);
	_gnutls_mac(&digest_hd, &length16, 2);
	_gnutls_mac(&digest_hd, ticket->encrypted_state, ticket->encrypted_state_len);

	_gnutls_mac_deinit(&digest_hd, digest);

	return 0;
}

static int encrypt_ticket(gnutls_session_t session,
		gnutls_datum_t *state, struct ticket_st *enc_ticket)
{
	int ret;
	cipher_hd_st cipher_hd;
	gnutls_datum_t key, IV;
	gnutls_datum_t encrypted_state = {NULL, 0};
	gnutls_datum_t mac_secret;
	uint8_t iv[IV_SIZE];
	uint32_t t;

	memset(&cipher_hd, 0, sizeof(cipher_hd_st));

	key.data = (void *) &session->key.session_ticket_key[KEY_POS];
	key.size = CIPHER_KEY_SIZE;
	IV.data = iv;
	IV.size = IV_SIZE;

	/* Generate an IV */
	t = gnutls_time(0);
	memcpy(iv, &t, 4);
	ret = gnutls_rnd(GNUTLS_RND_NONCE, iv + 4, IV_SIZE + 4);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Encrypt */
	ret = _gnutls_cipher_init(&cipher_hd, cipher_to_entry(CIPHER),
			&key, &IV, 1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	encrypted_state.size = ((state->size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
	encrypted_state.data = gnutls_calloc(1, encrypted_state.size);
	if (!encrypted_state.data) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}
	memcpy(encrypted_state.data, state->data, state->size);

	ret = _gnutls_cipher_encrypt(&cipher_hd,
			encrypted_state.data, encrypted_state.size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Compute the MAC */
	memcpy(enc_ticket->key_name, &session->key.session_ticket_key[NAME_POS], KEY_NAME_SIZE);
	memcpy(enc_ticket->IV, IV.data, IV.size);
	enc_ticket->encrypted_state = encrypted_state.data;
	enc_ticket->encrypted_state_len = encrypted_state.size;

	mac_secret.data = &session->key.session_ticket_key[MAC_SECRET_POS];
	mac_secret.size = MAC_SECRET_SIZE;

	ret = digest_ticket(&mac_secret, enc_ticket, enc_ticket->mac);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	encrypted_state.data = NULL;
	ret = 0;

cleanup:
	_gnutls_cipher_deinit(&cipher_hd);
	_gnutls_free_datum(&encrypted_state);
	return ret;
}

static int decrypt_ticket(gnutls_session_t session,
		struct ticket_st *enc_ticket, gnutls_datum_t *state)
{
	int ret;
	cipher_hd_st cipher_hd;
	gnutls_datum_t key, IV, mac_secret;
	uint8_t cmac[MAC_SIZE];

	/* Check the integrity of ticket */
	mac_secret.data = (void *) &session->key.session_ticket_key[MAC_SECRET_POS];
	mac_secret.size = MAC_SECRET_SIZE;
	ret = digest_ticket(&mac_secret, enc_ticket, cmac);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (memcmp(enc_ticket->mac, cmac, MAC_SIZE))
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
	if (enc_ticket->encrypted_state_len % BLOCK_SIZE != 0)
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);

	key.data = (void *) &session->key.session_ticket_key[KEY_POS];
	key.size = CIPHER_KEY_SIZE;
	IV.data = enc_ticket->IV;
	IV.size = IV_SIZE;

	ret = _gnutls_cipher_init(&cipher_hd, cipher_to_entry(CIPHER),
			&key, &IV, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_cipher_decrypt(&cipher_hd,
			enc_ticket->encrypted_state, enc_ticket->encrypted_state_len);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	state->data = enc_ticket->encrypted_state;
	state->size = enc_ticket->encrypted_state_len;

	ret = 0;
cleanup:
	_gnutls_cipher_deinit(&cipher_hd);
	return ret;
}

static int generate_session_ticket(gnutls_session_t session, struct tls13_nst_st *ticket)
{
	int ret;
	unsigned char *p;
	gnutls_datum_t state = { NULL, 0 };
	struct ticket_st encrypted_ticket;
	/* This is the resumption master secret */
	const uint8_t *rms = session->key.proto.tls13.ap_rms;
	unsigned rms_len = MAX_HASH_SIZE;

	memset(&encrypted_ticket, 0, sizeof(struct ticket_st));

	/* Generate a random 128-bit ticket nonce */
	ticket->ticket_nonce.size = 16;
	ticket->ticket_nonce.data = gnutls_malloc(ticket->ticket_nonce.size);
	if (ticket->ticket_nonce.data == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	if ((ret = gnutls_rnd(GNUTLS_RND_NONCE,
			ticket->ticket_nonce.data, ticket->ticket_nonce.size)) < 0)
		return gnutls_assert_val(ret);
	if ((ret = gnutls_rnd(GNUTLS_RND_RANDOM, &ticket->ticket_age_add, sizeof(uint32_t))) < 0)
		return gnutls_assert_val(ret);

	/* Set ticket lifetime to 1 day (86400 seconds) */
	ticket->ticket_lifetime = 86400;
	ticket->kdf_id = session->security_parameters.cs->prf;

	/* Encrypt the ticket and place the result in ticket->ticket */
	ret = pack_ticket(ticket, rms, rms_len, &state);
	if (ret < 0)
		return gnutls_assert_val(ret);
	ret = encrypt_ticket(session, &state, &encrypted_ticket);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ticket->ticket.size = KEY_NAME_SIZE +
			IV_SIZE +
			MAC_SIZE +
			sizeof(uint16_t) +
			encrypted_ticket.encrypted_state_len;
	ticket->ticket.data = gnutls_calloc(1, ticket->ticket.size);
	if (!ticket->ticket.data) {
		_gnutls_free_datum(&ticket->ticket_nonce);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	p = ticket->ticket.data;

	memcpy(p, encrypted_ticket.key_name, KEY_NAME_SIZE);
	p += KEY_NAME_SIZE;
	memcpy(p, encrypted_ticket.IV, IV_SIZE);
	p += IV_SIZE;
	_gnutls_write_uint16(encrypted_ticket.encrypted_state_len, p);
	p += 2;
	memcpy(p, encrypted_ticket.encrypted_state,
			encrypted_ticket.encrypted_state_len);
	p += encrypted_ticket.encrypted_state_len;
	gnutls_free(encrypted_ticket.encrypted_state);
	memcpy(p, encrypted_ticket.mac, MAC_SIZE);
	p += MAC_SIZE;

	return 0;
}

int _gnutls13_send_session_ticket(gnutls_session_t session, unsigned again)
{
	int ret;
	gnutls_buffer_st buf;
	mbuffer_st *bufel = NULL;
	struct tls13_nst_st ticket;
	uint16_t ticket_len;
	uint8_t *data = NULL, *p;
	int data_size = 0;

	/* Client does not send a NewSessionTicket */
	if (unlikely(session->security_parameters.entity == GNUTLS_CLIENT))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	/* Session resumption has not been enabled */
	if (!session->internals.session_ticket_enable)
		return 0;

	memset(&buf, 0, sizeof(gnutls_buffer_st));
	memset(&ticket, 0, sizeof(struct tls13_nst_st));

	if (again == 0) {
		/* FIXME ticket must be generated */
	//	ret = _gnutls13_session_ticket_get(session, &ticket);
		ret = generate_session_ticket(session, &ticket);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ticket_len = sizeof(uint32_t) +		/* ticket_lifetime */
				sizeof(uint32_t) +	/* ticket_age_add */
				ticket.ticket_nonce.size + 1 +
				ticket.ticket.size + 2 +
				2;			/* extensions length */
		bufel = _gnutls_handshake_alloc(session, ticket_len);
		if (bufel == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}

		data = _mbuffer_get_udata_ptr(bufel);
		p = data;

		/* append ticket_lifetime */
		_gnutls_write_uint32(ticket.ticket_lifetime, p);
		p += 4;
		/* append ticket_age_add */
		_gnutls_write_uint32(ticket.ticket_age_add, p);
		p += 4;
		/* append ticket_nonce */
		*p = (uint8_t) ticket.ticket_nonce.size;
		p++;
		memcpy(p, ticket.ticket_nonce.data, ticket.ticket_nonce.size);
		p += ticket.ticket_nonce.size;
		/* append ticket */
		_gnutls_write_uint16(ticket.ticket.size, p);
		p += 2;
		memcpy(p, ticket.ticket.data, ticket.ticket.size);
		p += ticket.ticket.size;

		/* No extensions */
		_gnutls_write_uint16(0, p);
		p += 2;

		data_size = p - data;
	}

	return _gnutls_send_handshake(session, data_size ? bufel : NULL,
			GNUTLS_HANDSHAKE_NEW_SESSION_TICKET);

	/* FIXME should free bufel and the rest of the buffers */

cleanup:
	if (ticket.ticket.data)
		gnutls_free(ticket.ticket.data);
	if (ticket.ticket_nonce.data)
		gnutls_free(ticket.ticket_nonce.data);
	_gnutls_buffer_clear(&buf);
	return ret;
}

int _gnutls13_recv_session_ticket(gnutls_session_t session, gnutls_buffer_st *buf,
		struct tls13_nst_st *ticket)
{
	int ret;

	if (unlikely(buf == NULL || ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	_gnutls_handshake_log("HSK[%p]: parsing session ticket message\n", session);

	/* ticket_lifetime */
	ret = _gnutls_buffer_pop_prefix32(buf, (size_t *) &ticket->ticket_lifetime, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* ticket_age_add */
	ret = _gnutls_buffer_pop_prefix32(buf, (size_t *) &ticket->ticket_age_add, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix8(buf, &ticket->ticket_nonce);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix16(buf, &ticket->ticket);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_extv_parse(NULL, parse_nst_extension, buf->data, buf->length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
cleanup:

	return ret;
}

int _gnutls13_recv_session_ticket2(gnutls_session_t session, gnutls_datum_t *dat,
		struct tls13_nst_st *ticket)
{
	int ret;
	gnutls_buffer_st buf;

	if (unlikely(dat == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	_gnutls_buffer_init(&buf);
	_gnutls_buffer_append_data(&buf, dat->data, dat->size);
	ret = _gnutls13_recv_session_ticket(session, &buf, ticket);
	_gnutls_buffer_clear(&buf);

	if (ret < 0)
		gnutls_assert();
	return ret;
}

int _gnutls13_parse_session_ticket(struct tls13_nst_st *ticket)
{
	int ret;

	/* TODO implement this */

	return 0;
}

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	/* ignore all extensions */
	return 0;
}
