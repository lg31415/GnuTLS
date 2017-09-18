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

/* Functions that relate to the TLS hello extension parsing.
 * Hello extensions are packets appended in the TLS hello packet, and
 * allow for extra functionality.
 */

#include "gnutls_int.h"
#include "extensions.h"
#include "errors.h"
#include "ext/max_record.h"
#include <ext/server_name.h>
#include <ext/srp.h>
#include <ext/heartbeat.h>
#include <ext/session_ticket.h>
#include <ext/safe_renegotiation.h>
#include <ext/signature.h>
#include <ext/safe_renegotiation.h>
#include <ext/ecc.h>
#include <ext/status_request.h>
#include <ext/ext_master_secret.h>
#include <ext/supported_versions.h>
#include <ext/post_handshake.h>
#include <ext/srtp.h>
#include <ext/alpn.h>
#include <ext/dumbfw.h>
#include <ext/key_share.h>
#include <ext/etm.h>
#include <num.h>
#include "extv.h"

static int ext_register(extension_entry_st * mod);

extension_entry_st const *_gnutls_extfunc[MAX_EXT_TYPES+1] = {
	&ext_mod_max_record_size,
	&ext_mod_ext_master_secret,
	&ext_mod_supported_versions,
	&ext_mod_post_handshake,
	&ext_mod_etm,
#ifdef ENABLE_OCSP
	&ext_mod_status_request,
#endif
	&ext_mod_server_name,
	&ext_mod_sr,
#ifdef ENABLE_SRP
	&ext_mod_srp,
#endif
#ifdef ENABLE_HEARTBEAT
	&ext_mod_heartbeat,
#endif
#ifdef ENABLE_SESSION_TICKETS
	&ext_mod_session_ticket,
#endif
	&ext_mod_supported_ecc,
	&ext_mod_supported_ecc_pf,
	&ext_mod_sig,
	&ext_mod_key_share,
#ifdef ENABLE_DTLS_SRTP
	&ext_mod_srtp,
#endif
#ifdef ENABLE_ALPN
	&ext_mod_alpn,
#endif
	/* This must be the last extension registered.
	 */
	&ext_mod_dumbfw,
	NULL
};

const extension_entry_st *
_gnutls_ext_ptr(tls_ext_vals_st *v, uint16_t id, gnutls_ext_parse_type_t parse_type)
{
	unsigned i;
	const extension_entry_st *e;

	for (i=0;i<v->rexts_size;i++) {
		if (v->rexts[i].id == id) {
			e = &v->rexts[i];
			goto done;
		}
	}

	for (i = 0; _gnutls_extfunc[i] != NULL; i++) {
		if (_gnutls_extfunc[i]->id == id) {
			e = _gnutls_extfunc[i];
			goto done;
		}
	}

	return NULL;
done:
	if (parse_type == GNUTLS_EXT_ANY || e->parse_type == parse_type) {
		return e;
	} else {
		return NULL;
	}
}


/**
 * gnutls_ext_get_name:
 * @ext: is a TLS extension numeric ID
 *
 * Convert a TLS extension numeric ID to a printable string.
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified cipher, or %NULL.
 **/
const char *gnutls_ext_get_name(unsigned int ext)
{
	size_t i;

	for (i = 0; _gnutls_extfunc[i] != NULL; i++)
		if (_gnutls_extfunc[i]->id == ext)
			return _gnutls_extfunc[i]->name;

	return NULL;
}


void _gnutls_extension_list_add_sr(gnutls_session_t session)
{
	_gnutls_extv_add_saved(&session->internals.hello_ext, &ext_mod_sr, 1);
}

/* Global deinit and init of global extensions */
int _gnutls_ext_init(void)
{
	return GNUTLS_E_SUCCESS;
}

void _gnutls_ext_deinit(void)
{
	unsigned i;
	for (i = 0; _gnutls_extfunc[i] != NULL; i++) {
		if (_gnutls_extfunc[i]->free_struct != 0) {
			gnutls_free((void*)_gnutls_extfunc[i]->name);
			gnutls_free((void*)_gnutls_extfunc[i]);
			_gnutls_extfunc[i] = NULL;
		}
	}
}

static
int ext_register(extension_entry_st * mod)
{
	unsigned i = 0;

	while(_gnutls_extfunc[i] != NULL) {
		i++;
	}

	if (i >= MAX_EXT_TYPES-1) {
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	_gnutls_extfunc[i] = mod;
	_gnutls_extfunc[i+1] = NULL;
	return GNUTLS_E_SUCCESS;
}

/* Packing of extension data (for use in resumption) */
static int pack_extension(gnutls_session_t session, const extension_entry_st *extp,
			  gnutls_buffer_st *packed)
{
	int ret;
	int size_offset;
	int cur_size;
	gnutls_ext_priv_data_t data;
	int rval = 0;

	ret =
	    _gnutls_ext_get_session_data(session, extp->id,
					 &data);
	if (ret >= 0 && extp->pack_func != NULL) {
		BUFFER_APPEND_NUM(packed, extp->id);

		size_offset = packed->length;
		BUFFER_APPEND_NUM(packed, 0);

		cur_size = packed->length;

		ret = extp->pack_func(data, packed);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		rval = 1;
		/* write the actual size */
		_gnutls_write_uint32(packed->length - cur_size,
				     packed->data + size_offset);
	}

	return rval;
}

int _gnutls_ext_pack(gnutls_session_t session, gnutls_buffer_st *packed)
{
	unsigned int i;
	int ret;
	int total_exts_pos;
	int exts = 0;
	tls_ext_vals_st *v = &session->internals.hello_ext;

	total_exts_pos = packed->length;
	BUFFER_APPEND_NUM(packed, 0);

	for (i = 0; i < v->used_exts_size; i++) {
		ret = pack_extension(session, v->used_exts[i], packed);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (ret > 0)
			exts++;
	}

	_gnutls_write_uint32(exts, packed->data + total_exts_pos);

	return 0;
}

static void
_gnutls_ext_set_resumed_session_data(gnutls_session_t session,
				     uint16_t id,
				     gnutls_ext_priv_data_t data)
{
	int i;
	const struct extension_entry_st *ext;
	tls_ext_vals_st *vals = &session->internals.hello_ext;

	ext = _gnutls_ext_ptr(vals, id, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (vals->ext_data[i].id == id
		    || (!vals->ext_data[i].resumed_set && !vals->ext_data[i].set)) {

			if (vals->ext_data[i].resumed_set != 0)
				_gnutls_extv_data_unset_resumed(&vals->ext_data[i], ext);

			vals->ext_data[i].id = id;
			vals->ext_data[i].resumed_priv = data;
			vals->ext_data[i].resumed_set = 1;
			return;
		}
	}
}

int _gnutls_ext_unpack(gnutls_session_t session, gnutls_buffer_st * packed)
{
	int i, ret;
	gnutls_ext_priv_data_t data;
	int max_exts = 0;
	uint16_t id;
	int size_for_id, cur_pos;
	const struct extension_entry_st *ext;

	BUFFER_POP_NUM(packed, max_exts);
	for (i = 0; i < max_exts; i++) {
		BUFFER_POP_NUM(packed, id);
		BUFFER_POP_NUM(packed, size_for_id);

		cur_pos = packed->length;

		ext = _gnutls_ext_ptr(&session->internals.hello_ext, id, GNUTLS_EXT_ANY);
		if (ext == NULL || ext->unpack_func == NULL) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		ret = ext->unpack_func(packed, &data);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* verify that unpack read the correct bytes */
		cur_pos = cur_pos - packed->length;
		if (cur_pos /* read length */  != size_for_id) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		_gnutls_ext_set_resumed_session_data(session, id, data);
	}

	return 0;

      error:
	return ret;
}

void
_gnutls_ext_unset_session_data(gnutls_session_t session,
			       uint16_t id)
{
	int i;
	const struct extension_entry_st *ext;

	ext = _gnutls_ext_ptr(&session->internals.hello_ext, id, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (session->internals.hello_ext.ext_data[i].id == id) {
			_gnutls_extv_data_unset(&session->internals.hello_ext.ext_data[i], ext);
			return;
		}
	}
}



/* Deinitializes all data that are associated with TLS extensions.
 */
void _gnutls_ext_free_session_data(gnutls_session_t session)
{
	_gnutls_extv_deinit(&session->internals.hello_ext);
}

/* This function allows an extension to store data in the current session
 * and retrieve them later on. We use functions instead of a pointer to a
 * private pointer, to allow API additions by individual extensions.
 */
void
_gnutls_ext_set_session_data(gnutls_session_t session, uint16_t id,
			     gnutls_ext_priv_data_t data)
{
	unsigned int i;
	const struct extension_entry_st *ext;
	tls_ext_vals_st *v = &session->internals.hello_ext;

	ext = _gnutls_ext_ptr(v, id, GNUTLS_EXT_ANY);

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (v->ext_data[i].id == id ||
		    (!v->ext_data[i].set && !v->ext_data[i].resumed_set)) {

			if (v->ext_data[i].set != 0) {
				_gnutls_extv_data_unset(&v->ext_data[i], ext);
			}
			v->ext_data[i].id = id;
			v->ext_data[i].priv = data;
			v->ext_data[i].set = 1;
			return;
		}
	}
}

int
_gnutls_ext_get_session_data(gnutls_session_t session,
			     uint16_t id, gnutls_ext_priv_data_t * data)
{
	int i;
	tls_ext_vals_st *v = &session->internals.hello_ext;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (v->ext_data[i].set != 0 &&
		    v->ext_data[i].id == id)
		{
			*data =
			    v->ext_data[i].priv;
			return 0;
		}
	}
	return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
}

int
_gnutls_ext_get_resumed_session_data(gnutls_session_t session,
				     uint16_t id,
				     gnutls_ext_priv_data_t * data)
{
	int i;
	tls_ext_vals_st *v = &session->internals.hello_ext;

	for (i = 0; i < MAX_EXT_TYPES; i++) {
		if (v->ext_data[i].resumed_set != 0
		    && v->ext_data[i].id == id) {
			*data =
			    v->ext_data[i].resumed_priv;
			return 0;
		}
	}
	return GNUTLS_E_INVALID_REQUEST;
}

/**
 * gnutls_ext_register:
 * @name: the name of the extension to register
 * @id: the numeric id of the extension
 * @parse_type: the parse type of the extension (see gnutls_ext_parse_type_t)
 * @recv_func: a function to receive the data
 * @send_func: a function to send the data
 * @deinit_func: a function deinitialize any private data
 * @pack_func: a function which serializes the extension's private data (used on session packing for resumption)
 * @unpack_func: a function which will deserialize the extension's private data
 *
 * This function will register a new extension type. The extension will remain
 * registered until gnutls_global_deinit() is called. If the extension type
 * is already registered then %GNUTLS_E_ALREADY_REGISTERED will be returned.
 *
 * Each registered extension can store temporary data into the gnutls_session_t
 * structure using gnutls_ext_set_data(), and they can be retrieved using
 * gnutls_ext_get_data().
 *
 * Any extensions registered with this function are valid for the client
 * and TLS1.2 server hello (or encrypted extensions for TLS1.3).
 *
 * This function is not thread safe.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.4.0
 **/
int 
gnutls_ext_register(const char *name, int id, gnutls_ext_parse_type_t parse_type,
		    gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, 
		    gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func,
		    gnutls_ext_unpack_func unpack_func)
{
	extension_entry_st *tmp_mod;
	int ret;
	unsigned i;

	for (i = 0; _gnutls_extfunc[i] != NULL; i++) {
		if (_gnutls_extfunc[i]->id == id)
			return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
	}

	tmp_mod = gnutls_calloc(1, sizeof(*tmp_mod));
	if (tmp_mod == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	tmp_mod->name = gnutls_strdup(name);
	tmp_mod->free_struct = 1;
	tmp_mod->id = id;
	tmp_mod->parse_type = parse_type;
	tmp_mod->recv_func = recv_func;
	tmp_mod->send_func = send_func;
	tmp_mod->deinit_func = deinit_func;
	tmp_mod->pack_func = pack_func;
	tmp_mod->unpack_func = unpack_func;
	tmp_mod->validity = GNUTLS_EXT_FLAG_CLIENT_HELLO|GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO|GNUTLS_EXT_FLAG_EE;

	ret = ext_register(tmp_mod);
	if (ret < 0) {
		gnutls_free((void*)tmp_mod->name);
		gnutls_free(tmp_mod);
	}
	return ret;
}

#define VALIDITY_MASK (GNUTLS_EXT_FLAG_CLIENT_HELLO|GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO| \
			GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO| \
			GNUTLS_EXT_FLAG_EE|GNUTLS_EXT_FLAG_CT|GNUTLS_EXT_FLAG_CR| \
			GNUTLS_EXT_FLAG_NST|GNUTLS_EXT_FLAG_HRR)

/**
 * gnutls_session_ext_register:
 * @session: the session for which this extension will be set
 * @name: the name of the extension to register
 * @id: the numeric id of the extension
 * @parse_type: the parse type of the extension (see gnutls_ext_parse_type_t)
 * @recv_func: a function to receive the data
 * @send_func: a function to send the data
 * @deinit_func: a function deinitialize any private data
 * @pack_func: a function which serializes the extension's private data (used on session packing for resumption)
 * @unpack_func: a function which will deserialize the extension's private data
 * @flags: must be zero or flags from %gnutls_ext_flags_t
 *
 * This function will register a new extension type. The extension will be
 * only usable within the registered session. If the extension type
 * is already registered then %GNUTLS_E_ALREADY_REGISTERED will be returned,
 * unless the flag %GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL is specified. The latter
 * flag when specified can be used to override certain extensions introduced
 * after 3.6.0. It is expected to be used by applications which handle
 * custom extensions that are not currently supported in GnuTLS, but direct
 * support for them may be added in the future.
 *
 * Each registered extension can store temporary data into the gnutls_session_t
 * structure using gnutls_ext_set_data(), and they can be retrieved using
 * gnutls_ext_get_data().
 *
 * The validity of the extension registered can be given by the appropriate flags
 * of %gnutls_ext_flags_t. If no validity is given, then the registered extension
 * will be valid for client and TLS1.2 server hello (or encrypted extensions for TLS1.3).
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.5.5
 **/
int 
gnutls_session_ext_register(gnutls_session_t session,
			    const char *name, int id, gnutls_ext_parse_type_t parse_type,
			    gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, 
			    gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func,
			    gnutls_ext_unpack_func unpack_func, unsigned flags)
{
	extension_entry_st tmp_mod;
	extension_entry_st *exts;
	unsigned i;
	tls_ext_vals_st *v = &session->internals.hello_ext;

	/* reject handling any extensions which modify the TLS handshake
	 * in any way, or are mapped to an exported API. */
	for (i = 0; _gnutls_extfunc[i] != NULL; i++) {
		if (_gnutls_extfunc[i]->id == id) {
			if (!(flags & GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL)) {
				return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
			} else if (_gnutls_extfunc[i]->cannot_be_overriden) {
				return gnutls_assert_val(GNUTLS_E_ALREADY_REGISTERED);
			}
			break;
		}
	}

	memset(&tmp_mod, 0, sizeof(extension_entry_st));
	tmp_mod.free_struct = 1;
	tmp_mod.id = id;
	tmp_mod.parse_type = parse_type;
	tmp_mod.recv_func = recv_func;
	tmp_mod.send_func = send_func;
	tmp_mod.deinit_func = deinit_func;
	tmp_mod.pack_func = pack_func;
	tmp_mod.unpack_func = unpack_func;
	tmp_mod.validity = flags;

	if ((tmp_mod.validity & VALIDITY_MASK) == 0) {
		tmp_mod.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO|GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO|GNUTLS_EXT_FLAG_EE;
	}

	exts = gnutls_realloc(v->rexts, (v->rexts_size+1)*sizeof(*exts));
	if (exts == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	v->rexts = exts;

	memcpy(&v->rexts[v->rexts_size], &tmp_mod, sizeof(extension_entry_st));
	v->rexts_size++;

	return 0;
}

/**
 * gnutls_ext_set_data:
 * @session: a #gnutls_session_t opaque pointer
 * @id: the numeric id of the extension
 * @data: the private data to set
 *
 * This function allows an extension handler to store data in the current session
 * and retrieve them later on. The set data will be deallocated using
 * the gnutls_ext_deinit_data_func.
 *
 * Since: 3.4.0
 **/
void
gnutls_ext_set_data(gnutls_session_t session, unsigned id,
		    gnutls_ext_priv_data_t data)
{
	_gnutls_ext_set_session_data(session, id, data);
}

/**
 * gnutls_ext_get_data:
 * @session: a #gnutls_session_t opaque pointer
 * @id: the numeric id of the extension
 * @data: a pointer to the private data to retrieve
 *
 * This function retrieves any data previously stored with gnutls_ext_set_data().
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.4.0
 **/
int
gnutls_ext_get_data(gnutls_session_t session,
		    unsigned id, gnutls_ext_priv_data_t *data)
{
	return _gnutls_ext_get_session_data(session, id, data);
}
