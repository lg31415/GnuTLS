#!/bin/sh

# Copyright (C) 2017 Red Hat, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

srcdir="${srcdir:-.}"
P11TOOL="${P11TOOL:-../src/p11tool${EXEEXT}}"
P11MOCKLIB1="${P11MOCKLIB1:-./.libs/libpkcs11mock1.so}"

TMPFILE=p11tool.$$.tmp

if ! test -x "${P11TOOL}"; then
	exit 77
fi

if ! test -x "/usr/lib64/pkcs11-spy.so" && ! test -x "/usr/lib/pkcs11-spy.so";then
	exit 77
fi 

. "${srcdir}/scripts/common.sh"

echo "Checking P11 tool basic operations"

rm -f ${TMPFILE}

echo "Check operations called during object listing"
"${P11TOOL}" --provider ${P11MOCKLIB1} --list-all --spy ${TMPFILE}
cat ${TMPFILE}

grep C_GetSlotList ${TMPFILE} >/dev/null
if test $? != 0;then
	echo "C_GetSlotList was not called"
	exit 1
fi

grep C_OpenSession ${TMPFILE} >/dev/null
if test $? != 0;then
	echo "C_OpenSession was not called"
	exit 1
fi

grep C_FindObjects ${TMPFILE} >/dev/null
if test $? != 0;then
	echo "C_FindObjects was not called"
	exit 1
fi

rm -f ${TMPFILE}

echo "Check operations called during object listing with Login"
"${P11TOOL}" --provider ${P11MOCKLIB1} --list-all --spy ${TMPFILE} --login --set-pin 1234
cat ${TMPFILE}

grep C_Login ${TMPFILE} >/dev/null
if test $? != 0;then
	echo "C_Login was not called"
	exit 1
fi

grep 'userType = CKU_USER' ${TMPFILE} >/dev/null
if test $? != 0;then
	echo "Login with userType = CKU_USER was not called"
	exit 1
fi

rm -f ${TMPFILE}

exit 0
