/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#ifndef __HMAC_H__
#define __HMAC_H__

#include "apr.h"

#include <openssl/evp.h>

#define HMAC_ALGORITHM EVP_sha256()
#define HMAC_DIGESTSIZE (EVP_MD_size(HMAC_ALGORITHM))

void hmac(const void *, apr_size_t, const void *, apr_size_t, void *);

#endif
