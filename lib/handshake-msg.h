#ifndef HANDSHAKE_MSG_H
#define HANDSHAKE_MSG_H

struct handshake_msg_st;

int _gnutls_handshake_msg_init(struct handshake_msg_st **out,
		gnutls_handshake_description_t type,
		gnutls_session_t session);
void _gnutls_handshake_msg_deinit(struct handshake_msg_st **hs);

int _gnutls_handshake_hash_add_sent(gnutls_session_t session,
		gnutls_handshake_description_t type,
		uint8_t * dataptr, uint32_t datalen);
int _gnutls_handshake_hash_add_recvd(gnutls_session_t session,
		gnutls_handshake_description_t recv_type,
		uint8_t *header, uint16_t header_size,
		uint8_t *dataptr, uint32_t datalen);

int _gnutls_handshake_msg_commit_from_buffer(gnutls_session_t session,
		struct handshake_msg_st *hs,
		gnutls_buffer_st *buf,
		size_t head_skip_bytes,
		size_t header_length);
int _gnutls_handshake_msg_commit_from_mbuffer(gnutls_session_t session,
		struct handshake_msg_st *hs,
		mbuffer_st *bufel,
		size_t head_skip_bytes,
		size_t header_length);

#endif
