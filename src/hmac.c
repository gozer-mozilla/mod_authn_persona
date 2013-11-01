#include "hmac.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

void hmac(const void *key, apr_size_t keylen, const void *data,
          apr_size_t datalen, void *result)
{
  HMAC(HMAC_ALGORITHM, key, keylen, data, datalen, result, NULL);

  return;
}
