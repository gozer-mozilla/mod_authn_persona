/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Based in part, on mod_auth_memcookie, made by Mathieu CARBONNEAUX.
 *
 * See http://authmemcookie.sourceforge.net/ for details;
 * licensed under Apache License, Version 2.0.
 *
 * SHA-1 implementation by Steve Reid, steve@edmweb.com, in
 * public domain.
 */

#include "defines.h"
#include "cookie.h"
#include "verify.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <apr_strings.h>
#include <apr_uuid.h>
#include <apr_tables.h>
#include <apr_random.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>       /* for ap_hook_(check_user_id | auth_checker) */
#include <apr_base64.h>

#include <curl/curl.h>
#include <curl/easy.h>
#include <assert.h>

#include "version.h"

/* apache module name */
module AP_MODULE_DECLARE_DATA authn_persona_module;

apr_table_t *parseArgs(request_rec *, char *);
const char *persona_server_secret_option(cmd_parms *, void *, const char *);
const char *persona_server_cookie_name(cmd_parms *, void *, const char *);
const char *persona_server_cookie_domain(cmd_parms *, void *, const char *);
const char *persona_server_cookie_duration(cmd_parms *, void *, const char *);
const char *persona_server_cookie_secure(cmd_parms *, void *, int);
const char *persona_server_verifier_url(cmd_parms *, void *, const char *);
const char *persona_server_login_url(cmd_parms *, void *, const char *);
static void persona_generate_secret(apr_pool_t *, server_rec *,
                                    persona_config_t *);

static int persona_authn_active(request_rec *r)
{
  return (strncmp("Persona", ap_auth_type(r), 9) == 0) ? 1 : 0;
}

/**************************************************
 * Authentication phase
 *
 * Pull the cookie from the header and verify it.
 **************************************************/
static int Auth_persona_check_cookie(request_rec *r)
{
  char *szCookieValue = NULL;
  const char *assertion = NULL;

  if (!persona_authn_active(r)) {
    return DECLINED;
  }

  persona_config_t *conf =
    ap_get_module_config(r->server->module_config, &authn_persona_module);
  persona_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &authn_persona_module);

  apr_table_set(r->err_headers_out, "X-Mod-Auth-Persona", VERSION);

  /* We take over all HTTP_UNAUTHORIZED pages */
  ap_custom_response(r, HTTP_UNAUTHORIZED, conf->login_url);

  // We'll trade you a valid assertion for a session cookie!
  // this is a programatic XHR request.

  // XXX: only test for post - issue #10
  assertion = apr_table_get(r->headers_in, conf->assertion_header);
  if (assertion) {
    VerifyResult res = processAssertion(r, conf->verifier_url, assertion);

    if (!res->errorResponse) {
      assert(res->verifiedEmail);
      assert(res->identityIssuer);

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, ERRTAG
                    "email '%s' verified, vouched for by issuer '%s'",
                    res->verifiedEmail, res->identityIssuer);
      Cookie cookie = apr_pcalloc(r->pool, sizeof(struct _Cookie));
      cookie->verifiedEmail = res->verifiedEmail;
      cookie->identityIssuer = res->identityIssuer;
      cookie->expires = conf->cookie_duration;
      cookie->domain = conf->cookie_domain;
      cookie->secure = conf->cookie_secure;
      cookie->path = dconf->location;
      // also check res->expires;
      sendSignedCookie(r, conf->secret, conf->cookie_name, cookie);
      return DONE;
    }
    else {
      r->status = HTTP_INTERNAL_SERVER_ERROR;
      ap_set_content_type(r, "application/json");
      ap_rwrite(res->errorResponse, strlen(res->errorResponse), r);

      // upon assertion verification failure we return JSON explaining why
      return DONE;
    }
  }

  // if there's a valid cookie, allow the user throught
  szCookieValue = extractCookie(r, conf->secret, conf->cookie_name);

  Cookie cookie = NULL;
  if (szCookieValue &&
      (cookie = validateCookie(r, conf->secret, szCookieValue))) {
    r->user = (char *) cookie->verifiedEmail;
    apr_table_setn(r->notes, PERSONA_ISSUER_NOTE, cookie->identityIssuer);
    apr_table_setn(r->subprocess_env, PERSONA_ENV_IDP,
                   cookie->identityIssuer);
    return OK;
  }

  return HTTP_UNAUTHORIZED;
}


/**************************************************
 * Authentication hook for Apache
 *
 * If the cookie is present, extract it and verify it.
 *
 * if it is valid, apply per-resource authorization rules.
 **************************************************/
static int Auth_persona_check_auth(request_rec *r)
{
  const apr_array_header_t *reqs_arr = NULL;
  require_line *reqs = NULL;
  register int x;
  const char *szRequireLine;
  char *szRequire_cmd;

  if (!persona_authn_active(r)) {
    return DECLINED;
  }

  persona_config_t *conf =
    ap_get_module_config(r->server->module_config, &authn_persona_module);

  apr_table_set(r->err_headers_out, "X-Mod-Auth-Persona", VERSION);

  /* We take over all HTTP_UNAUTHORIZED pages */
  ap_custom_response(r, HTTP_UNAUTHORIZED, conf->login_url);

  /* get require line */
  reqs_arr = ap_requires(r);
  reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

  /* decline if no require line found */
  if (!reqs_arr)
    return DECLINED;

  /* walk through the array to check each require command */
  for (x = 0; x < reqs_arr->nelts; x++) {

    if (!(reqs[x].method_mask & (AP_METHOD_BIT << r->method_number)))
      continue;

    /* get require line */
    szRequireLine = reqs[x].requirement;

    /* get the first word in require line */
    szRequire_cmd = ap_getword_white(r->pool, &szRequireLine);

    // persona-idp: check host part of user name
    if (!strcmp("persona-idp", szRequire_cmd)) {
      char *reqIdp = ap_getword_conf(r->pool, &szRequireLine);
      const char *issuer = apr_table_get(r->notes, PERSONA_ISSUER_NOTE);
      if (!issuer || strcmp(issuer, reqIdp)) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, r,
                      ERRTAG
                      "user '%s' is not authorized by idp:%s, but idp:%s instead",
                      r->user, reqIdp, (issuer ? issuer : "unknown"));

        char *error = apr_psprintf(r->pool,
                                   "user '%s' is not authenticated by IdP '%s' (but by '%s')",
                                   r->user, reqIdp,
                                   (issuer ? issuer : "unknown"));
        apr_table_setn(r->subprocess_env, "PERSONA_ERROR", error);

        return DECLINED;
      }

      ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, r,
                    ERRTAG "user '%s' is authorized by idp:%s", issuer,
                    r->user);
      return OK;
    }
  }

  /* give others a chance */
  return DECLINED;
}

/* Parse x-www-url-formencoded args */
apr_table_t *parseArgs(request_rec *r, char *argStr)
{
  char *pair;
  char *last = NULL;
  char *eq;

  apr_table_t *vars = apr_table_make(r->pool, 10);
  char *delim = "&";

  for (pair = apr_strtok(r->args, delim, &last);
       pair; pair = apr_strtok(NULL, delim, &last)) {
    for (eq = pair; *eq; ++eq)
      if (*eq == '+')
        *eq = ' ';

    ap_unescape_url(pair);
    eq = strchr(pair, '=');

    if (eq) {
      *eq++ = 0;
      apr_table_merge(vars, pair, eq);
    }
    else {
      apr_table_merge(vars, pair, "");
    }
  }
  return vars;
}

/* XXX: Not good, needs to verify one is logged in, otherwise, it's a free redirector */
static int processLogout(request_rec *r)
{
  persona_config_t *conf =
    ap_get_module_config(r->server->module_config, &authn_persona_module);
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool,
                             "%s=; Path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT",
                             conf->cookie_name));

  if (r->args) {
    if (strlen(r->args) > 16384) {
      return HTTP_REQUEST_URI_TOO_LARGE;
    }

    apr_table_t *vars = parseArgs(r, r->args);
    const char *returnto = apr_table_get(vars, "returnto");
    if (returnto) {
      apr_table_set(r->headers_out, "Location", returnto);
      return HTTP_TEMPORARY_REDIRECT;
    }
  }
  apr_table_set(r->headers_out, "Location", "/");
  return HTTP_TEMPORARY_REDIRECT;
}

static int Auth_persona_post_config(apr_pool_t * pconf, apr_pool_t * plog,
                                    apr_pool_t * ptemp, server_rec *s)
{
  server_rec *sp;
  persona_config_t *conf;

  for (sp = s; sp; sp = sp->next) {
    conf = ap_get_module_config(sp->module_config, &authn_persona_module);
    if (!conf->secret->len) {
      persona_generate_secret(pconf, sp, conf);
      ap_log_error(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, sp,
                   ERRTAG "created a secret since none was configured for %s",
                   sp->server_hostname);
    }
  }

  ap_add_version_component(pconf, "mod_authn_persona/" VERSION);

  return OK;
}

/**************************************************
 * register module hooks
 **************************************************/
static void register_hooks(apr_pool_t * p)
{
  // these hooks are are executed in order, first is first.
  ap_hook_check_user_id(Auth_persona_check_cookie, NULL, NULL,
                        APR_HOOK_FIRST);
  ap_hook_auth_checker(Auth_persona_check_auth, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_post_config(Auth_persona_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

#define RAND_BYTES_AT_A_TIME 256

static void persona_generate_secret(apr_pool_t * p, server_rec *s,
                                    persona_config_t * conf)
{
  apr_random_t *prng = apr_random_standard_new(p);
  char *secret = apr_palloc(p, conf->secret_size);
  apr_status_t status;

  while ((status =
          apr_random_secure_bytes(prng, secret,
                                  conf->secret_size)) ==
         APR_ENOTENOUGHENTROPY) {
    unsigned char randbuf[RAND_BYTES_AT_A_TIME];
    apr_generate_random_bytes(randbuf, RAND_BYTES_AT_A_TIME);
    apr_random_add_entropy(prng, randbuf, RAND_BYTES_AT_A_TIME);
  }

  /* XXX: if (status != OK) { */
  conf->secret->len = conf->secret_size;
  conf->secret->data = secret;
}

static void *persona_create_dir_config(apr_pool_t * p, char *path)
{
  persona_dir_config_t *conf = apr_palloc(p, sizeof(*conf));
  conf->location = path ? apr_pstrdup(p, path) : "/";
  return conf;
}

static void *persona_create_svr_config(apr_pool_t * p, server_rec *s)
{
  persona_config_t *conf = apr_palloc(p, sizeof(*conf));

  conf->secret = apr_pcalloc(p, sizeof(buffer_t));
  conf->assertion_header = PERSONA_ASSERTION_HEADER;
  conf->cookie_name = PERSONA_COOKIE_NAME;
  conf->cookie_domain = NULL;
  conf->cookie_secure = 0;
  conf->cookie_duration = PERSONA_COOKIE_DURATION;
  conf->verifier_url = PERSONA_DEFAULT_VERIFIER_URL;
  conf->secret_size = PERSONA_SECRET_SIZE;
  conf->login_url = PERSONA_LOGIN_URL;

  return conf;
}

const char *persona_server_secret_option(cmd_parms *cmd, void *cfg,
                                         const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->secret->len = strlen(arg);
  conf->secret->data = apr_palloc(cmd->pool, conf->secret->len);
  strncpy(conf->secret->data, arg, conf->secret->len);
  return NULL;
}

const char *persona_server_cookie_duration(cmd_parms *cmd, void *cfg,
                                           const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->cookie_duration = atoi(arg);
  return NULL;
}

const char *persona_server_cookie_name(cmd_parms *cmd, void *cfg,
                                       const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->cookie_name = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

const char *persona_server_cookie_secure(cmd_parms *cmd, void *cfg,
                                         int flag)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->cookie_secure = flag;
  return NULL;
}

const char *persona_server_cookie_domain(cmd_parms *cmd, void *cfg,
                                       const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->cookie_domain = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

const char *persona_server_verifier_url(cmd_parms *cmd, void *cfg,
                                        const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->verifier_url = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

const char *persona_server_login_url(cmd_parms *cmd, void *cfg,
                                     const char *arg)
{
  server_rec *s = cmd->server;
  persona_config_t *conf =
    ap_get_module_config(s->module_config, &authn_persona_module);
  conf->login_url = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const command_rec Auth_persona_options[] = {
  AP_INIT_TAKE1("AuthPersonaServerSecret", persona_server_secret_option,
                NULL, RSRC_CONF, "Server secret to use for cookie signing"),
  AP_INIT_TAKE1("AuthPersonaCookieName", persona_server_cookie_name,
                NULL, RSRC_CONF, "Name of the Persona Cookie"),
  AP_INIT_TAKE1("AuthPersonaCookieDomain", persona_server_cookie_domain,
                NULL, RSRC_CONF, "Domain for the Persona Cookie"),
  AP_INIT_TAKE1("AuthPersonaCookieDuration", persona_server_cookie_duration,
                NULL, RSRC_CONF, "Duration of the Persona Cookie"),
  AP_INIT_FLAG("AuthPersonaCookieSecure", persona_server_cookie_secure,
	        NULL, RSRC_CONF, "HTTPS only Persona Cookie"),
  AP_INIT_TAKE1("AuthPersonaVerifierURL", persona_server_verifier_url,
                NULL, RSRC_CONF, "URL to a Persona Verfier service"),
  AP_INIT_TAKE1("AuthPersonaLoginURL", persona_server_login_url,
                NULL, RSRC_CONF, "URL to a Persona login page"),
  {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA authn_persona_module = {
  STANDARD20_MODULE_STUFF,
  persona_create_dir_config,    /* dir config creator */
  NULL,                         /* dir merger --- default is to override */
  persona_create_svr_config,    /* server config creator */
  NULL,                         /* merge server config */
  Auth_persona_options,         /* command apr_table_t */
  register_hooks                /* register hooks */
};
