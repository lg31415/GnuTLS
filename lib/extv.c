/*
 * Copyright (C) 2001-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson
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

/* Functions that relate to TLS extension parsing.
 */

#include "gnutls_int.h"
#include "extv.h"
#include "extensions.h"

void
_gnutls_extv_data_unset_resumed(struct ext_data_st *data, const struct extension_entry_st *ext)
{
	if (data->resumed_set == 0)
		return;

	if (ext && ext->deinit_func && data->resumed_priv) {
		ext->deinit_func(data->resumed_priv);
	}
	data->resumed_set = 0;
}

void
_gnutls_extv_data_unset(struct ext_data_st *data, const struct extension_entry_st *ext)
{
	if (data->set == 0)
		return;

	if (ext && ext->deinit_func && data->priv != NULL)
		ext->deinit_func(data->priv);
	data->set = 0;
}

void _gnutls_extv_deinit(tls_ext_vals_st *v)
{
	unsigned int i;
	const struct extension_entry_st *ext;

	v->used_exts_size = 0;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (!v->ext_data[i].set && !v->ext_data[i].resumed_set)
			continue;

		ext = _gnutls_ext_ptr(v, v->ext_data[i].id, GNUTLS_EXT_ANY);

		_gnutls_extv_data_unset(&v->ext_data[i], ext);
		_gnutls_extv_data_unset_resumed(&v->ext_data[i], ext);
	}

	gnutls_free(v->rexts);
	v->rexts = NULL;
}

/* Checks if the extension @id provided has been requested
 * by us (in client side). In that case it returns zero, 
 * otherwise a negative error value.
 */
int
_gnutls_extv_check_saved(tls_ext_vals_st *v, uint16_t id)
{
	unsigned i;

	for (i = 0; i < v->used_exts_size; i++) {
		if (id == v->used_exts[i]->id)
			return 0;
	}

	return GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION;
}

/* Adds the extension we want to send in the extensions list.
 * This list is used in client side to check whether the (later) received
 * extensions are the ones we requested.
 *
 * In server side, this list is used to ensure we don't send
 * extensions that we didn't receive a corresponding value.
 *
 * Returns zero if failed, non-zero on success.
 */
unsigned _gnutls_extv_add_saved(tls_ext_vals_st *v, const struct extension_entry_st *e, unsigned check_dup)
{
	unsigned i;

	if (check_dup) {
		for (i=0;i<v->used_exts_size;i++) {
			if (v->used_exts[i]->id == e->id)
				return 0;
		}
	}

	if (v->used_exts_size < MAX_EXT_TYPES) {
		v->used_exts[v->used_exts_size] = e;
		v->used_exts_size++;
		return 1;
	} else {
		_gnutls_handshake_log
		    ("extensions: Increase MAX_EXT_TYPES\n");
		return 0;
	}
}

int
_gnutls_extv_parse(gnutls_session_t session,
		   gnutls_ext_flags_t msg,
		   gnutls_ext_parse_type_t parse_type,
		   const uint8_t * data, int data_size,
		   tls_ext_vals_st *out,
		   unsigned extv_flags)
{
	int next, ret;
	int pos = 0;
	uint16_t id;
	const uint8_t *sdata;
	const extension_entry_st *ext;
	uint16_t size;

	if (data_size == 0)
		return 0;

	DECR_LENGTH_RET(data_size, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
	next = _gnutls_read_uint16(data);
	pos += 2;

	DECR_LENGTH_RET(data_size, next, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	if (next == 0 && data_size == 0) /* field is present, but has zero length? Ignore it. */
		return 0;
	else if (data_size > 0) /* forbid unaccounted data */
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	do {
		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		id = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		if (extv_flags & EXTV_CHECK_UNADVERTIZED) {
			if ((ret =
			     _gnutls_extv_check_saved(out, id)) < 0) {
				_gnutls_debug_log("EXT[%p]: Received unexpected extension '%s/%d'\n", session,
						gnutls_ext_get_name(id), (int)id);
				gnutls_assert();
				return ret;
			}
		}

		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		size = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		DECR_LENGTH_RET(next, size, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		sdata = &data[pos];
		pos += size;

		ext = _gnutls_ext_ptr(out, id, parse_type);
		if (ext == NULL || ext->recv_func == NULL) {
			_gnutls_handshake_log
			    ("EXT[%p]: Ignoring extension '%s/%d'\n", session,
			     gnutls_ext_get_name(id), id);

			continue;
		}


		if ((ext->validity & msg) == 0) {

			_gnutls_debug_log("EXT[%p]: Received unexpected extension (%s/%d) for '%s'\n", session,
					  gnutls_ext_get_name(id), (int)id,
					  ext_msg_validity_to_str(msg));
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
		}

		if (extv_flags & EXTV_SAVE_RECEIVED) {
			ret = _gnutls_extv_add_saved(out, ext, 1);
			if (ret == 0)
				return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
		}

		_gnutls_handshake_log
		    ("EXT[%p]: Parsing extension '%s/%d' (%d bytes)\n",
		     session, gnutls_ext_get_name(id), id,
		     size);

		_gnutls_ext_set_msg(session, msg);

		if ((ret = ext->recv_func(session, sdata, size)) < 0) {
			gnutls_assert();
			return ret;
		}
	}
	while (next > 2);

	/* forbid leftovers */
	if (next > 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	return 0;
}

static
int send_extension(gnutls_session_t session,
		   tls_ext_vals_st *v,
		   const extension_entry_st *p,
		   gnutls_buffer_st *extdata,
		   gnutls_ext_flags_t msg,
		   gnutls_ext_parse_type_t parse_type,
		   unsigned extv_flags)
{
	int size_pos, appended, ret;
	size_t size_prev;

	if (p->send_func == NULL)
		return 0;

	if (parse_type != GNUTLS_EXT_ANY
	    && p->parse_type != parse_type)
		return 0;

	if ((msg & p->validity) == 0) {
		_gnutls_handshake_log("EXT[%p]: Not sending extension (%s/%d) for '%s'\n", session,
				  gnutls_ext_get_name(p->id), (int)p->id,
				  ext_msg_validity_to_str(msg));
		return 0;
	}

	/* ensure we are sending only what we received in server. */
	if (extv_flags & EXTV_SEND_SAVED_ONLY) {
		ret = _gnutls_extv_check_saved(v, p->id);
		if (ret < 0) /* not advertized */
			return 0;
	}

	ret = _gnutls_buffer_append_prefix(extdata, 16, p->id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size_pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	_gnutls_ext_set_msg(session, msg);

	size_prev = extdata->length;
	ret = p->send_func(session, extdata);
	if (ret < 0 && ret != GNUTLS_E_INT_RET_0) {
		return gnutls_assert_val(ret);
	}

	/* returning GNUTLS_E_INT_RET_0 means to send an empty
	 * extension of this type.
	 */
	appended = extdata->length - size_prev;

	if (appended > 0 || ret == GNUTLS_E_INT_RET_0) {
		if (ret == GNUTLS_E_INT_RET_0)
			appended = 0;

		/* write the real size */
		_gnutls_write_uint16(appended,
				     &extdata->data[size_pos]);

		/* add this extension to the extension list
		 */
		if (session->security_parameters.entity == GNUTLS_CLIENT)
			_gnutls_extv_add_saved(v, p, 0);

		_gnutls_handshake_log
			    ("EXT[%p]: Sending extension %s/%d (%d bytes)\n",
			     session, p->name, p->id, appended);
	} else if (appended == 0)
		extdata->length -= 4;	/* reset type and size */

	return 0;
}

int
_gnutls_extv_gen(gnutls_session_t session,
	         tls_ext_vals_st *v,
	         gnutls_buffer_st * extdata,
	         gnutls_ext_flags_t msg,
	         gnutls_ext_parse_type_t parse_type,
	         unsigned extv_flags)
{
	int size;
	int pos, ret;
	size_t i, init_size = extdata->length;
	uint16_t send_ids[MAX_EXT_TYPES];
	unsigned nsend_ids = 0, j;

	pos = extdata->length;	/* we will store length later on */

	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	for (i=0; i < v->rexts_size; i++) {
		ret = send_extension(session, v, &v->rexts[i], extdata, msg, parse_type, extv_flags);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (nsend_ids < MAX_EXT_TYPES)
			send_ids[nsend_ids++] = v->rexts[i].id;
	}

	/* send_extension() ensures we don't send duplicates, in case
	 * of overriden extensions */
	for (i = 0; _gnutls_extfunc[i] != NULL; i++) {
		for (j = 0; j < nsend_ids; j++) {
			if (send_ids[j] == _gnutls_extfunc[i]->id)
				continue;
		}

		ret = send_extension(session, v, _gnutls_extfunc[i], extdata, msg, parse_type, extv_flags);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* remove any initial data, and the size of the header */
	size = extdata->length - init_size - 2;

	if (size > UINT16_MAX) /* sent too many extensions */
		return gnutls_assert_val(GNUTLS_E_HANDSHAKE_TOO_LARGE);

	if (size > 0)
		_gnutls_write_uint16(size, &extdata->data[pos]);
	else if (size == 0)
		extdata->length -= 2;	/* the length bytes */

	return size;
}
