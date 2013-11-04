/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#include "hmac.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

void hmac(const void *key, apr_size_t keylen, const void *data,
          apr_size_t datalen, void *result)
{
  HMAC(HMAC_ALGORITHM, key, keylen, data, datalen, result, NULL);

  return;
}
