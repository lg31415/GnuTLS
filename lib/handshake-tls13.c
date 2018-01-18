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

/* Functions that relate to the TLS handshake procedure.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "dh.h"
#include "debug.h"
#include "algorithms.h"
#include "cipher.h"
#include "buffers.h"
#include "mbuffers.h"
#include "kx.h"
#include "handshake.h"
#include "num.h"
#include "hash_int.h"
#include "db.h"
#include "hello_ext.h"
#include "supplemental.h"
#include "auth.h"
#include "sslv2_compat.h"
#include <auth/cert.h>
#include "constate.h"
#include <record.h>
#include <state.h>
#include <random.h>
#include <dtls.h>
#include "secrets.h"
#include "tls13/hello_retry.h"
#include "tls13/encrypted_extensions.h"
#include "tls13/certificate_request.h"
#include "tls13/certificate_verify.h"
#include "tls13/certificate.h"
#include "tls13/finished.h"
#include "tls13/key_update.h"
#include "tls13/session_ticket.h"

static int generate_hs_traffic_keys(gnutls_session_t session);
static int generate_ap_traffic_keys(gnutls_session_t session);

#define SAVE_TRANSCRIPT \
	if (session->internals.flags & GNUTLS_POST_HANDSHAKE_AUTH) { \
		/* If post-handshake auth is in use we need a copy of the original \
		 * handshake transcript */ \
		memcpy( &session->internals.post_handshake_hash_buffer, \
			&session->internals.handshake_hash_buffer, \
			sizeof(session->internals.handshake_hash_buffer)); \
		_gnutls_buffer_init(&session->internals.handshake_hash_buffer); \
	}

/*
 * _gnutls13_handshake_client
 * This function performs the client side of the handshake of the TLS/SSL protocol.
 */
int _gnutls13_handshake_client(gnutls_session_t session)
{
	int ret = 0;

	switch (STATE) {
	case STATE100:
		ret =
		    generate_hs_traffic_keys(session);
		STATE = STATE100;
		IMED_RET("generate session keys", ret, 0);
		/* fall through */
	case STATE101:
		ret = _gnutls13_recv_encrypted_extensions(session);
		STATE = STATE101;
		IMED_RET("recv encrypted extensions", ret, 0);
		/* fall through */
	case STATE102:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_recv_certificate_request(session);
		STATE = STATE102;
		IMED_RET("recv certificate request", ret, 0);
		/* fall through */
	case STATE103:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_recv_certificate(session);
		STATE = STATE103;
		IMED_RET("recv certificate", ret, 0);
		/* fall through */
	case STATE104:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_recv_certificate_verify(session);
		STATE = STATE104;
		IMED_RET("recv server certificate verify", ret, 0);
		/* fall through */
	case STATE105:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls_run_verify_callback(session, GNUTLS_CLIENT);
		STATE = STATE105;
		if (ret < 0)
			return gnutls_assert_val(ret);
		FALLTHROUGH;
	case STATE106:
		ret = _gnutls13_recv_finished(session);
		STATE = STATE106;
		IMED_RET("recv finished", ret, 0);
		/* fall through */
	case STATE107:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_send_certificate(session, AGAIN(STATE107));
		STATE = STATE107;
		IMED_RET("send certificate", ret, 0);
		/* fall through */
	case STATE108:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_send_certificate_verify(session, AGAIN(STATE108));
		STATE = STATE108;
		IMED_RET("send certificate verify", ret, 0);
		/* fall through */
	case STATE109:
		ret = _gnutls13_send_finished(session, AGAIN(STATE109));
		STATE = STATE109;
		IMED_RET("send finished", ret, 0);
		/* fall through */
	case STATE110:
		ret =
		    generate_ap_traffic_keys(session);
		STATE = STATE110;
		IMED_RET("generate app keys", ret, 0);

		STATE = STATE0;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	/* explicitly reset any false start flags */
	session->internals.recv_state = RECV_STATE_0;
	session->internals.initial_negotiation_completed = 1;

	SAVE_TRANSCRIPT;

	return 0;
}

static int generate_ap_traffic_keys(gnutls_session_t session)
{
	int ret;
	uint8_t zero[MAX_HASH_SIZE];

	ret = _tls13_derive_secret(session, DERIVED_LABEL, sizeof(DERIVED_LABEL)-1,
				   NULL, 0, session->key.proto.tls13.temp_secret,
				   session->key.proto.tls13.temp_secret);
	if (ret < 0)
		return gnutls_assert_val(ret);

	memset(zero, 0, session->security_parameters.prf->output_size);
	ret = _tls13_update_secret(session, zero, session->security_parameters.prf->output_size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _tls13_derive_secret(session, EXPORTER_MASTER_LABEL, sizeof(EXPORTER_MASTER_LABEL)-1,
				   session->internals.handshake_hash_buffer.data,
				   session->internals.handshake_hash_buffer_server_finished_len,
				   session->key.proto.tls13.temp_secret,
				   session->key.proto.tls13.ap_expkey);
	if (ret < 0)
		return gnutls_assert_val(ret);

	_gnutls_nss_keylog_write(session, "EXPORTER_SECRET",
				 session->key.proto.tls13.ap_expkey,
				 session->security_parameters.prf->output_size);

	_gnutls_epoch_bump(session);
	ret = _gnutls_epoch_dup(session);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _tls13_connection_state_init(session, STAGE_APP);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

static int generate_hs_traffic_keys(gnutls_session_t session)
{
	int ret;

	if (unlikely(session->key.key.size == 0 || session->key.proto.tls13.temp_secret_size == 0))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	ret = _tls13_update_secret(session, session->key.key.data, session->key.key.size);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _tls13_connection_state_init(session, STAGE_HS);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/*
 * _gnutls13_handshake_server
 * This function does the server stuff of the handshake protocol.
 */
int _gnutls13_handshake_server(gnutls_session_t session)
{
	int ret = 0;

	switch (STATE) {
	case STATE90:
		ret = _gnutls13_handshake_hash_buffers_synth(session, session->security_parameters.prf, 0);
		STATE = STATE90;
		IMED_RET("reset handshake buffers", ret, 0);
		/* fall through */
	case STATE91:
		ret = _gnutls13_send_hello_retry_request(session, AGAIN(STATE91));
		STATE = STATE91;
		IMED_RET("send hello retry request", ret, 0);
		/* fall through */
	case STATE92:
		ret =
		    _gnutls_recv_handshake(session,
					   GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   0, NULL);
		STATE = STATE92;

		if (ret == GNUTLS_E_INT_RET_0) {
			/* this is triggered by post_client_hello, and instructs the
			 * handshake to proceed but be put on hold */
			ret = GNUTLS_E_INTERRUPTED;
			STATE = STATE100; /* hello already parsed -> move on */
		} else {
			STATE = STATE92;
		}

		IMED_RET("recv client hello", ret, 0);
		/* fall through */
	case STATE93:
		ret = _gnutls_send_server_hello(session, AGAIN(STATE93));
		STATE = STATE93;
		IMED_RET("send hello", ret, 0);
		/* fall through */
	case STATE100:
		ret =
		    generate_hs_traffic_keys(session);
		STATE = STATE100;
		IMED_RET("generate session keys", ret, 0);
		/* fall through */
	case STATE101:
		ret = _gnutls13_send_encrypted_extensions(session, AGAIN(STATE101));
		STATE = STATE101;
		IMED_RET("send encrypted extensions", ret, 0);
		/* fall through */
	case STATE102:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_send_certificate_request(session, AGAIN(STATE102));
		STATE = STATE102;
		IMED_RET("send certificate request", ret, 0);
		/* fall through */
	case STATE103:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_send_certificate(session, AGAIN(STATE103));
		STATE = STATE103;
		IMED_RET("send certificate", ret, 0);
		/* fall through */
	case STATE104:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_send_certificate_verify(session, AGAIN(STATE104));
		STATE = STATE104;
		IMED_RET("send certificate verify", ret, 0);
		/* fall through */
	case STATE105:
		ret = _gnutls13_send_finished(session, AGAIN(STATE105));
		STATE = STATE105;
		IMED_RET("send finished", ret, 0);
		/* fall through */
	case STATE106:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_recv_certificate(session);
		STATE = STATE106;
		IMED_RET("recv certificate", ret, 0);
		/* fall through */
	case STATE107:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls13_recv_certificate_verify(session);
		STATE = STATE107;
		IMED_RET("recv certificate verify", ret, 0);
		/* fall through */
	case STATE108:
		if (!(session->internals.hsk_flags & HSK_PSK_SELECTED)) /* unless a PSK is being used */
			ret = _gnutls_run_verify_callback(session, GNUTLS_CLIENT);
		STATE = STATE108;
		if (ret < 0)
			return gnutls_assert_val(ret);
		/* fall through */
	case STATE109:
		ret = _gnutls13_recv_finished(session);
		STATE = STATE109;
		IMED_RET("recv finished", ret, 0);
		/* fall through */
	case STATE110:
		ret =
		    generate_ap_traffic_keys(session);
		STATE = STATE110;
		IMED_RET("generate app keys", ret, 0);

		STATE = STATE0;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	/* explicitly reset any false start flags */
	session->internals.recv_state = RECV_STATE_0;
	session->internals.initial_negotiation_completed = 1;

	SAVE_TRANSCRIPT;

	return 0;
}

/* Processes handshake messages received asynchronously after initial handshake.
 *
 * It is called once per message, with a read-only buffer in @buf,
 * and should return success, or a fatal error code.
 */
int
_gnutls13_recv_async_handshake(gnutls_session_t session, gnutls_buffer_st *buf)
{
	uint8_t type;
	int ret;
	size_t handshake_header_size = HANDSHAKE_HEADER_SIZE(session);
	size_t length;

	if (buf->length < handshake_header_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* The following messages are expected asynchronously after
	 * the handshake process is complete */
	if (unlikely(session->internals.handshake_in_progress))
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

	ret = _gnutls_buffer_pop_prefix8(buf, &type, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_buffer_pop_prefix24(buf, &length, 1);
	if (ret < 0)
		return gnutls_assert_val(ret);

	switch(type) {
		case GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST:
			if (!(session->security_parameters.entity == GNUTLS_CLIENT) ||
			    !(session->internals.flags & GNUTLS_POST_HANDSHAKE_AUTH)) {
				return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);
			}

			_gnutls_buffer_reset(&session->internals.reauth_buffer);

			/* include the handshake headers in reauth buffer */
			ret = _gnutls_buffer_append_data(&session->internals.reauth_buffer,
							 buf->data-4, buf->length+4);
			if (ret < 0)
				return gnutls_assert_val(ret);

			/* Application is expected to handle re-authentication
			 * explicitly.  */
			return GNUTLS_E_REAUTH_REQUEST;

		case GNUTLS_HANDSHAKE_KEY_UPDATE:
			ret = _gnutls13_recv_key_update(session, buf);
			if (ret < 0)
				return gnutls_assert_val(ret);
			break;
		case GNUTLS_HANDSHAKE_NEW_SESSION_TICKET:
			if (session->security_parameters.entity != GNUTLS_CLIENT)
				return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

			ret = _gnutls13_recv_session_ticket(session, buf);
			if (ret < 0)
				return gnutls_assert_val(ret);
			break;
		default:
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET;
	}

	return 0;
}

