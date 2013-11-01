/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 *  Cookie management routines
 */

#ifndef __COOKIE_H__
#define __COOKIE_H__

#include <httpd.h>
#include "defines.h"
#include "hmac.h"

typedef struct _Cookie
{
  const char *verifiedEmail;    // email that was verified
  const char *identityIssuer;   // domain that issued the identity
  const char *domain;           // cookie domain
  const char *path;             // cookie path
  unsigned int expires;         // lifetime in seconds of the cookie
  int secure;                   // flag for cookie secure flag
}      *Cookie;

/* Look through the 'Cookie' headers for the indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
char *extractCookie(request_rec *r, const buffer_t *secret,
                    const char *szCookie_name);

/* Check the cookie and make sure it is valid */
Cookie validateCookie(request_rec *r, const buffer_t *secret,
                      const char *szCookieValue);

/** Create a session cookie with a given identity */
void sendSignedCookie(request_rec *r, const buffer_t *secret,
                      const char *cookie_name, const Cookie cookie);
/** Clears the session cookie */
void clearCookie(request_rec *r, const buffer_t *secret,
                 const char *cookie_name, const Cookie cookie);

#endif
