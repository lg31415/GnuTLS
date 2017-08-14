/*
 * Copyright (C) 2015-2017 Red Hat, Inc.
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
#include "extensions.h"
#include "supplemental.h"
#include "auth.h"
#include "sslv2_compat.h"
#include <auth/cert.h>
#include "constate.h"
#include <record.h>
#include <state.h>
#include <ext/srp.h>
#include <ext/session_ticket.h>
#include <ext/status_request.h>
#include <ext/safe_renegotiation.h>
#include <auth/anon.h>		/* for gnutls_anon_server_credentials_t */
#include <auth/psk.h>		/* for gnutls_psk_server_credentials_t */
#include <random.h>
#include <dtls.h>
#include "secrets.h"

/*
 * _gnutls_tls13_handshake_client
 * This function performs the client side of the handshake of the TLS/SSL protocol.
 */
int _gnutls_tls13_handshake_client(gnutls_session_t session)
{
	int ret = 0;

	switch (STATE) {
	case STATE100:
		/* RECV CERTIFICATE */
		if (session->internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_certificate(session);
		STATE = STATE100;
		IMED_RET("recv server certificate", ret, 1);
		/* fall through */
	case STATE101:
#ifdef ENABLE_OCSP
		/* RECV CERTIFICATE STATUS */
		if (session->internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_server_certificate_status
			    (session);
		STATE = STATE101;
		IMED_RET("recv server certificate", ret, 1);
#endif
		/* fall through */
	case STATE102:
		ret = _gnutls_run_verify_callback(session, GNUTLS_CLIENT);
		STATE = STATE102;
		if (ret < 0)
			return gnutls_assert_val(ret);

		FALLTHROUGH;
	case STATE103:
		/* receive the server certificate request - if any 
		 */
		ret = _gnutls_recv_server_crt_request(session);
		STATE = STATE103;
		IMED_RET("recv server certificate request message", ret,
			 1);
		/* fall through */
	case STATE104:
		/* receive the server hello done */
		ret =
		    _gnutls_recv_handshake(session,
					   GNUTLS_HANDSHAKE_SERVER_HELLO_DONE,
					   0, NULL);
		STATE = STATE104;
		IMED_RET("recv server hello done", ret, 1);
		/* fall through */
	case STATE105:
		/* send our certificate - if any and if requested
		 */
		ret =
		    _gnutls_send_client_certificate(session,
						    AGAIN
						    (STATE105));
		STATE = STATE105;
		IMED_RET("send client certificate", ret, 0);
		/* fall through */
	case STATE106:
		/* send client certificate verify */
		ret =
		    _gnutls_send_client_certificate_verify(session,
							   AGAIN
							   (STATE106));
		STATE = STATE106;
		IMED_RET("send client certificate verify", ret, 1);
		/* fall through */
#if 0
	case STATE107:
		ret = send_handshake_final(session, TRUE);
		STATE = STATE107;
		IMED_RET("send handshake final 2", ret, 1);
		/* fall through */
	case STATE108:
		STATE = STATE108;

		ret = recv_handshake_final(session, TRUE);
		IMED_RET("recv handshake final", ret, 1);
#endif
		STATE = STATE0;
		/* fall through */
	default:
		break;
	}

	/* explicitly reset any false start flags */
	session->internals.recv_state = RECV_STATE_0;

	return 0;
}

static int generate_hs_traffic_keys(gnutls_session_t session)
{
	int ret;

	if (unlikely(session->key.key.size == 0))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	ret = _tls13_update_secret(session, session->key.key.data, session->key.key.size);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _tls13_connection_state_init(session);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _tls13_derive_secret(session, DERIVED_LABEL, sizeof(DERIVED_LABEL)-1,
				   NULL, 0, session->key.temp_secret);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/*
 * _gnutls_tls13_handshake_server
 * This function does the server stuff of the handshake protocol.
 */
int _gnutls_tls13_handshake_server(gnutls_session_t session)
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
		ret =
		    _gnutls_send_server_certificate(session,
						    AGAIN(STATE101));
		STATE = STATE101;
		IMED_RET("send server certificate", ret, 0);
		/* fall through */
	case STATE102:
		ret =
		    _gnutls_send_server_crt_request(session,
						    AGAIN(STATE102));
		STATE = STATE102;
		IMED_RET("send server cert request", ret, 0);
		/* fall through */
	case STATE103:
		ret = _gnutls_recv_client_certificate(session);
		STATE = STATE103;
		IMED_RET("recv client certificate", ret, 1);
		/* fall through */
	case STATE104:
		ret = _gnutls_run_verify_callback(session, GNUTLS_SERVER);
		STATE = STATE104;
		if (ret < 0)
			return gnutls_assert_val(ret);
		/* fall through */
	case STATE105:
		/* receive the client certificate verify message */
		ret =
		    _gnutls_recv_client_certificate_verify_message
		    (session);
		STATE = STATE105;
		IMED_RET("recv client certificate verify", ret, 1);
		/* fall through */

		STATE = STATE0;
		/* fall through */
	default:
		break;
	}

	return 0;
}

