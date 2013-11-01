/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#ifndef __HMAC_H__
#define __HMAC_H__

#include <apr_strings.h>
#include <apr_sha1.h>
#include <apr_base64.h>

#define HMAC_DIGESTSIZE APR_SHA1_DIGESTSIZE
#define HMAC_BLOCKSIZE 64

void hmac(const void *, apr_size_t, const void *, apr_size_t, void *);

#endif
