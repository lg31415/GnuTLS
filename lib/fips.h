/*
 * Copyright (C) 2013 Red Hat
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

#ifndef FIPS_H
# define FIPS_H

#include "gnutls_int.h"
#include <gnutls/gnutls.h>

#define FIPS140_RND_KEY_SIZE 32

typedef enum {
  LIB_STATE_POWERON,
  LIB_STATE_INIT,
  LIB_STATE_SELFTEST,
  LIB_STATE_OPERATIONAL,
  LIB_STATE_ERROR,
  LIB_STATE_SHUTDOWN
} gnutls_lib_state_t;

/* do not access directly */
extern unsigned int _gnutls_lib_mode;
extern gnutls_crypto_rnd_st _gnutls_fips_rnd_ops;

inline static 
void _gnutls_switch_lib_state(gnutls_lib_state_t state)
{
	/* Once into zombie state no errors can change us */
	_gnutls_lib_mode = state;
}

inline static gnutls_lib_state_t _gnutls_get_lib_state(void)
{
	return _gnutls_lib_mode;
}

int _gnutls_fips_perform_self_checks1(void);
int _gnutls_fips_perform_self_checks2(void);
void _gnutls_fips_mode_reset_zombie(void);

#ifdef ENABLE_FIPS140
unsigned _gnutls_fips_mode_enabled(void);
#else
# define _gnutls_fips_mode_enabled() 0
#endif

# define HAVE_LIB_ERROR() unlikely(_gnutls_get_lib_state() != LIB_STATE_OPERATIONAL && _gnutls_get_lib_state() != LIB_STATE_SELFTEST)

# define FAIL_IF_LIB_ERROR \
	if (HAVE_LIB_ERROR()) return GNUTLS_E_LIB_IN_ERROR_STATE

void _gnutls_switch_lib_state(gnutls_lib_state_t state);

void _gnutls_lib_simulate_error(void);
void _gnutls_lib_force_operational(void);

#ifdef ENABLE_FIPS140
inline
static unsigned is_mac_algo_forbidden(gnutls_mac_algorithm_t algo)
{
	if (_gnutls_fips_mode_enabled() != 0 &&
	    _gnutls_get_lib_state() != LIB_STATE_SELFTEST) {

		switch(algo) {
			case GNUTLS_MAC_SHA1:
			case GNUTLS_MAC_SHA256:
			case GNUTLS_MAC_SHA384:
			case GNUTLS_MAC_SHA512:
			case GNUTLS_MAC_SHA224:
			case GNUTLS_MAC_SHA3_224:
			case GNUTLS_MAC_SHA3_256:
			case GNUTLS_MAC_SHA3_384:
			case GNUTLS_MAC_SHA3_512:
				return 0;
			default:
				return 1;
		}
	}

	return 0;
}
#else
# define is_mac_algo_forbidden(x) 0
#endif

#endif /* FIPS_H */
