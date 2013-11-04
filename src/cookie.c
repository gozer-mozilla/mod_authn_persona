/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC

#include <apr_want.h>
#include <apr_strings.h>
#include <apr_base64.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>

#include "cookie.h"
#include "defines.h"

#include <json.h>

/* Cookies can't include the characters ';','=', so Base64 Encoding
 * isn't safe, base64url, however, is (RFC4648)
 */
static char *cookie_base64urlescape(apr_pool_t * p, const char *src)
{
  char *encoded = apr_pstrdup(p, src);

  char *c;

  for (c = encoded; *c; c++) {
    switch (*c) {
    case '=':
      *c = 0;
      break;
    case '+':
      *c = '-';
      break;
    case '/':
      *c = '_';
      break;
    }
  }

  return encoded;
}

static char *cookie_base64_urlunescape(apr_pool_t * p, const char *src)
{
  char *decoded = apr_pstrdup(p, src);

  char *c;

  for (c = decoded; *c; c++) {
    switch (*c) {
    case '-':
      *c = '+';
      break;
    case '_':
      *c = '/';
      break;
    }
  }

  return decoded;
}

/** Generates a HMAC with the given inputs, returning a Base64-encoded
 * signature value. */
static char *generateHMAC(request_rec *r, const buffer_t *secret,
                          const char *data)
{
  unsigned char digest[HMAC_DIGESTSIZE];
  char *digest64;

  hmac(secret->data, secret->len, data, strlen(data), &digest);
  digest64 = apr_palloc(r->pool, apr_base64_encode_len(HMAC_DIGESTSIZE));
  apr_base64_encode(digest64, (char *) digest, HMAC_DIGESTSIZE);

  return digest64;
}

/* Look through the 'Cookie' headers for the indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
char *extractCookie(request_rec *r, const buffer_t *secret,
                    const char *szCookie_name)
{
  char *szRaw_cookie_start = NULL, *szRaw_cookie_end;
  char *szCookie;
  /* get cookie string */
  char *szRaw_cookie = (char *) apr_table_get(r->headers_in, "Cookie");
  if (!szRaw_cookie)
    return 0;

  /* loop to search cookie name in cookie header */
  do {
    /* search cookie name in cookie string */
    if (!(szRaw_cookie = strstr(szRaw_cookie, szCookie_name)))
      return 0;
    szRaw_cookie_start = szRaw_cookie;
    /* search '=' */
    if (!(szRaw_cookie = strchr(szRaw_cookie, '=')))
      return 0;
  } while (strncmp
           (szCookie_name, szRaw_cookie_start,
            szRaw_cookie - szRaw_cookie_start) != 0);

  /* skip '=' */
  szRaw_cookie++;

  /* search end of cookie name value: ';' or end of cookie strings */
  if (!((szRaw_cookie_end = strchr(szRaw_cookie, ';'))
        || (szRaw_cookie_end = strchr(szRaw_cookie, '\0'))))
    return 0;

  /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
  if (!
      (szCookie =
       apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end - szRaw_cookie)))
         return 0;
  /* unescape the value string */
  if (ap_unescape_url(szCookie) != 0)
    return 0;

  return szCookie;
}

/* Check the cookie and make sure it is valid */
Cookie validateCookie(request_rec *r, const buffer_t *secret,
                      const char *szCookieValue)
{
  char *digest64 = apr_pstrdup(r->pool, szCookieValue);
  char *cookie_payload;

  /* split at | */
  char *delim = strchr(digest64, '|');

  if (!delim) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                  ERRTAG "invalid Persona cookie (tamper?)");
    return NULL;
  }

  /* Truncate at the delimiter, now digest64 is the checksum */
  *delim = '\0';

  /* And cookie_payload is the JSON payload */
  cookie_payload = delim + 1;

  char *computed_digest64 = generateHMAC(r, secret, cookie_payload);
  computed_digest64 = cookie_base64urlescape(r->pool, computed_digest64);

  if (strncmp(digest64, computed_digest64, strlen(computed_digest64))) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                  ERRTAG "invalid Persona cookie, HMAC mismatch (tamper?)");
    return NULL;
  }

  enum json_tokener_error jerr;
  const char *cookie_string =
    cookie_base64_urlunescape(r->pool, cookie_payload);
  cookie_string = ap_pbase64decode(r->pool, cookie_string);

  json_object *jcookie = json_tokener_parse_verbose(cookie_string, &jerr);

  /* This is very unlikely, we are parsing what we know for sure we have generated */
  if (jerr != json_tokener_success) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                  ERRTAG "Error parsing JSON in verified cookie : %s",
                  json_tokener_error_desc(jerr));
  }

  Cookie c = apr_pcalloc(r->pool, sizeof(struct _Cookie));

  json_object *expires = json_object_object_get(jcookie, "expires");
  // Verify the cookie is still valid
  if (expires && json_object_is_type(expires, json_type_int)) {
    apr_time_t expiry;
    apr_time_ansi_put(&expiry, json_object_get_int64(expires));
    c->expires = expiry;
    if (expiry > 0) {
      apr_time_t now = apr_time_now();
      if (now >= expiry) {
        char when[APR_RFC822_DATE_LEN];
        apr_rfc822_date(when, expiry);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                      ERRTAG "Persona cookie expired on %s", when);
        json_object_put(jcookie);
        return NULL;
      }
    }
  }

  json_object *email = json_object_object_get(jcookie, "email");
  if (email && json_object_is_type(email, json_type_string)) {
    c->verifiedEmail = apr_pstrdup(r->pool, json_object_get_string(email));
  }

  json_object *issuer = json_object_object_get(jcookie, "issuer");
  if (issuer && json_object_is_type(issuer, json_type_string)) {
    c->identityIssuer = apr_pstrdup(r->pool, json_object_get_string(issuer));
  }

  json_object_put(jcookie);

  return c;
}

void clearCookie(request_rec *r, const buffer_t *secret,
                 const char *cookie_name, const Cookie cookie)
{
  char *cookie_buf;
  char *domain = "";

  if (cookie->domain) {
    domain = apr_pstrcat(r->pool, "Domain=", cookie->domain, ";", NULL);
  }

  cookie_buf = apr_psprintf(r->pool,
                            "%s=; Path=%s; %sMax-Age=0",
                            cookie_name, cookie->path, domain);
  apr_table_set(r->err_headers_out, "Set-Cookie", cookie_buf);
  apr_table_set(r->headers_out, "Set-Cookie", cookie_buf);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                ERRTAG "Sending cookie payload: %s", cookie_buf);

  return;
}

/** Create a session cookie with a given identity */
void sendSignedCookie(request_rec *r, const buffer_t *secret,
                      const char *cookie_name, const Cookie cookie)
{
  apr_time_t duration;
  char *path = "/";
  char *max_age = "";
  char *domain = "";
  char *secure = "";
  json_object *jcookie = json_object_new_object();

  json_object_object_add(jcookie, "v",
                         json_object_new_int(PERSONA_COOKIE_VERSION));

  if (cookie->path) {
    path = apr_pstrcat(r->pool, "Path=", cookie->path, ";", NULL);
  }

  if (cookie->expires > 0) {
    apr_time_ansi_put(&duration, cookie->expires);
    duration += apr_time_now();

    max_age =
      apr_pstrcat(r->pool, "Max-Age=", apr_itoa(r->pool, cookie->expires),
                  ";", NULL);
    json_object_object_add(jcookie, "expires",
                           json_object_new_int64(apr_time_sec(duration)));
  }

  if (cookie->domain) {
    domain = apr_pstrcat(r->pool, "Domain=", cookie->domain, ";", NULL);
  }

  if (cookie->secure) {
    secure = "Secure;";
  }

  json_object_object_add(jcookie, "email",
                         json_object_new_string(cookie->verifiedEmail));
  json_object_object_add(jcookie, "issuer",
                         json_object_new_string(cookie->identityIssuer));

  char *jcookie_string =
    apr_pstrdup(r->pool,
                json_object_to_json_string_ext(jcookie,
                                               JSON_C_TO_STRING_PLAIN));
  const char *jcookie_base64u = ap_pbase64encode(r->pool, jcookie_string);
  const char *jcookie_base64 =
    cookie_base64urlescape(r->pool, jcookie_base64u);

  const char *digest64 = generateHMAC(r, secret, jcookie_base64);
  digest64 = cookie_base64urlescape(r->pool, digest64);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                ERRTAG "JSON cookie payload: %s", jcookie_string);

  char *cookie_buf = apr_psprintf(r->pool, "%s=%s|%s",
                                  cookie_name, digest64, jcookie_base64);
  char *cookie_flags = apr_psprintf(r->pool, ";HttpOnly;Version=1;%s%s%s%s",
                                    path, domain, max_age, secure);

  char *cookie_payload =
    apr_pstrcat(r->pool, cookie_buf, " ", cookie_flags, NULL);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                ERRTAG "Sending cookie payload: %s", cookie_payload);

  /* syntax of cookie is identity|signature */
  apr_table_set(r->err_headers_out, "Set-Cookie", cookie_payload);
  apr_table_set(r->headers_out, "Set-Cookie", cookie_payload);

  json_object_put(jcookie);
}
