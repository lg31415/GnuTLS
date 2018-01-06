#ifndef EXT_PRE_SHARED_KEY_H
#define EXT_PRE_SHARED_KEY_H

#include <hello_ext.h>
#include "tls13/session_ticket.h"

extern const hello_ext_entry_st ext_pre_shared_key;

int _gnutls13_session_ticket_set(gnutls_session_t session,
		struct tls13_nst_st *ticket,
		const uint8_t *rms, size_t rms_size);

#endif
