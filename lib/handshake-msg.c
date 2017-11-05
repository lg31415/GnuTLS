#include "gnutls_int.h"
#include "handshake.h"
#include "handshake-msg.h"
#include "mbuffers.h"

#define CHECK_SIZE(ll) \
  if ((session->internals.max_handshake_data_buffer_size > 0) && \
      (((ll) + session->internals.handshake_hash_buffer.length) > \
       session->internals.max_handshake_data_buffer_size)) { \
    _gnutls_debug_log("Handshake buffer length is %u (max: %u)\n", (unsigned)((ll) + session->internals.handshake_hash_buffer.length), (unsigned)session->internals.max_handshake_data_buffer_size); \
    return gnutls_assert_val(GNUTLS_E_HANDSHAKE_TOO_LARGE); \
    }

struct handshake_msg_st
{
	gnutls_handshake_description_t type;
	size_t committed_bytes;
};

int _gnutls_handshake_msg_init(struct handshake_msg_st **out,
		gnutls_handshake_description_t type,
		gnutls_session_t session)
{
	struct handshake_msg_st *hs = _gnutls_calloc(1, sizeof(struct handshake_msg_st));

	hs->type = type;

	*out = hs;
	return GNUTLS_E_SUCCESS;
}

void _gnutls_handshake_msg_deinit(struct handshake_msg_st **hs)
{
	gnutls_free(*hs);
	*hs = NULL;
}

/* This function add the handshake headers and the
 * handshake data to the handshake hash buffers. Needed
 * for the finished messages calculations.
 */
int
_gnutls_handshake_hash_add_recvd(gnutls_session_t session,
				 gnutls_handshake_description_t recv_type,
				 uint8_t * header, uint16_t header_size,
				 uint8_t * dataptr, uint32_t datalen)
{
	int ret;
	const version_entry_st *vers = get_version(session);

	if (unlikely(vers == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if ((vers->id != GNUTLS_DTLS0_9 &&
	     recv_type == GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST) ||
	    recv_type == GNUTLS_HANDSHAKE_HELLO_REQUEST)
		return 0;

	CHECK_SIZE(header_size + datalen);

	session->internals.handshake_hash_buffer_prev_len =
	    session->internals.handshake_hash_buffer.length;

	if (vers->id != GNUTLS_DTLS0_9) {
		ret =
		    _gnutls_buffer_append_data(&session->internals.
					       handshake_hash_buffer,
					       header, header_size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}
	if (datalen > 0) {
		ret =
		    _gnutls_buffer_append_data(&session->internals.
					       handshake_hash_buffer,
					       dataptr, datalen);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* save the size until client KX. That is because the TLS
	 * session hash is calculated up to this message.
	 */
	if (recv_type == GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE)
		session->internals.handshake_hash_buffer_client_kx_len =
			session->internals.handshake_hash_buffer.length;
	if (recv_type == GNUTLS_HANDSHAKE_FINISHED && session->security_parameters.entity == GNUTLS_CLIENT)
		session->internals.handshake_hash_buffer_server_finished_len =
			session->internals.handshake_hash_buffer.length;

	return 0;
}

/* This function will store the handshake message we sent.
 */
int
_gnutls_handshake_hash_add_sent(gnutls_session_t session,
		gnutls_handshake_description_t type,
		uint8_t * dataptr, uint32_t datalen)
{
	int ret;
	const version_entry_st *vers = get_version(session);

	if (unlikely(vers == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	/* We don't check for GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST because it
	 * is not sent via that channel.
	 */
	if (type != GNUTLS_HANDSHAKE_HELLO_REQUEST) {
		CHECK_SIZE(datalen);

		if (vers->id == GNUTLS_DTLS0_9) {
			/* Old DTLS doesn't include the header in the MAC */
			if (datalen < 12) {
				gnutls_assert();
				return GNUTLS_E_INTERNAL_ERROR;
			}
			dataptr += 12;
			datalen -= 12;

			if (datalen == 0)
				return 0;
		}

		ret =
		    _gnutls_buffer_append_data(&session->internals.
					       handshake_hash_buffer,
					       dataptr, datalen);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (type == GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE)
			session->internals.handshake_hash_buffer_client_kx_len =
				session->internals.handshake_hash_buffer.length;
		if (type == GNUTLS_HANDSHAKE_FINISHED && session->security_parameters.entity == GNUTLS_SERVER)
			session->internals.handshake_hash_buffer_server_finished_len =
				session->internals.handshake_hash_buffer.length;

		return 0;
	}

	return 0;
}

static int
handshake_commit(gnutls_session_t session,
		struct handshake_msg_st *hs,
		uint8_t *data, uint32_t datasize,
		size_t head_skip_bytes, size_t header_length)
{
	int ret;
	size_t to_commit, offset, prev_committed_bytes;

	/* This message is not taken into account for the hash */
	if (hs->type == GNUTLS_HANDSHAKE_HELLO_REQUEST)
		return GNUTLS_E_SUCCESS;

	prev_committed_bytes = hs->committed_bytes;

	if (datasize > hs->committed_bytes) {
		to_commit = datasize - hs->committed_bytes - head_skip_bytes;
		offset = hs->committed_bytes + head_skip_bytes;

		ret = _gnutls_handshake_hash_add_sent(session, hs->type,
				data + offset,
				to_commit);
		if (ret < 0)
			return gnutls_assert_val(ret);

		hs->committed_bytes += to_commit;
	}

	if (hs->committed_bytes > prev_committed_bytes) {
		/* Update type field */
		session->internals.handshake_hash_buffer.data[0] = (uint8_t) hs->type;
		/* Update size field */
		_gnutls_write_uint24(hs->committed_bytes - header_length,
				&session->internals.handshake_hash_buffer.data[1]);
	}

	return GNUTLS_E_SUCCESS;
}

int _gnutls_handshake_msg_commit_from_buffer(gnutls_session_t session,
		struct handshake_msg_st *hs,
		gnutls_buffer_st *buf,
		size_t head_skip_bytes,
		size_t header_length)
{
	uint8_t *data;
	uint32_t datasize;

	if (!hs || !buf)
		return GNUTLS_E_INTERNAL_ERROR;

	data = buf->data;
	datasize = buf->length;

	return handshake_commit(session, hs,
			data, datasize,
			head_skip_bytes, header_length);
}

int _gnutls_handshake_msg_commit_from_mbuffer(gnutls_session_t session,
		struct handshake_msg_st *hs,
		mbuffer_st *bufel,
		size_t head_skip_bytes, size_t header_length)
{
	uint8_t *data;
	uint32_t datasize;

	if (!hs || !bufel)
		return GNUTLS_E_INTERNAL_ERROR;

	data = _mbuffer_get_uhead_ptr(bufel);
	datasize = _mbuffer_get_udata_size(bufel) + _mbuffer_get_uhead_size(bufel);

	return handshake_commit(session, hs,
			data, datasize,
			head_skip_bytes, header_length);
}
