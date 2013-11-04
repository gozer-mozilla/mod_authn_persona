/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __VERIFY_H__
#define __VERIFY_H__

#include "defines.h"
#include "cookie.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"       /* for ap_hook_(check_user_id | auth_checker) */
#include "apr_base64.h"

#include <json.h>

typedef struct _VerifyResult
{
  const char *verifiedEmail;    // email that was verified
  const char *identityIssuer;   // domain that issued the identity
  const char *audience;         // domain that requested the identity
  apr_time_t expires;           // Expiry of the assertion
  const char *errorResponse;
}            *VerifyResult;

VerifyResult verify_assertion_local(request_rec *, const char *);

/**
 * process an assertion:
 *   verify an assertion, either locally or using mozilla's verification
 *   service.  Upon success, extract an email address, upon failure,
 *   generate a json formatted error message that can be returned to
 *   front end javascript.
 *
 * RETURN VALUE:
 *   VerifyResult structure.
 *    - Upon success has non-NULL verifiedEmail and identityIssuer fields.
 *    - Upon failure, has non-NULL errorResponse.
 */
VerifyResult processAssertion(request_rec *r, const char *verifier_url,
                              const char *assertion);

#endif
