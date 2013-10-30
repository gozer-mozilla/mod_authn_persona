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

const char *persona_server_secret_option(cmd_parms *, void *, const char *);
const char *persona_server_cookie_name(cmd_parms *, void *, const char *);
const char *persona_server_cookie_domain(cmd_parms *, void *, const char *);
const char *persona_server_cookie_duration(cmd_parms *, void *, const char *);
const char *persona_server_cookie_secure(cmd_parms *, void *, int);
const char *persona_authoritative(cmd_parms *, void *, int);
const char *persona_local_verify(cmd_parms *, void *, int);
const char *persona_server_verifier_url(cmd_parms *, void *, const char *);
const char *persona_server_login_url(cmd_parms *, void *, const char *);
const char *persona_server_logout_url(cmd_parms *, void *, const char *);
const char *persona_server_logout_returnto_url(cmd_parms *, void *,
                                               const char *);
const char *persona_fake_basic_auth(cmd_parms *, void *, int);
static apr_status_t persona_generate_secret(apr_pool_t *, server_rec *,
                                            persona_config_t *);

static int persona_authn_active(request_rec *r)
{
  return (strcmp("Persona", ap_auth_type(r)) == 0) ? 1 : 0;
}

static void fake_basic_auth(request_rec *r)
{
  char *basic = apr_pstrcat(r->pool, r->user, ":", "password", NULL);
  apr_size_t size = (apr_size_t) strlen(basic);
  char *base64 = apr_palloc(r->pool,
                            apr_base64_encode_len(size + 1) * sizeof(char));
  apr_base64_encode(base64, basic, size);
  apr_table_setn(r->headers_in, "Authorization",
                 apr_pstrcat(r->pool, "Basic ", base64, NULL));
  return;
}

static void set_cookie_from_config(persona_dir_config_t * dconf,
                                   Cookie cookie)
{
  cookie->expires = dconf->cookie_duration;
  cookie->domain = dconf->cookie_domain;
  cookie->secure = dconf->cookie_secure;
  cookie->path = dconf->location;
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
  persona_dir_config_t *dconf =
    ap_get_module_config(r->per_dir_config, &authn_persona_module);

  apr_table_set(r->err_headers_out, "X-Mod-Auth-Persona", VERSION);

  /* We take over all HTTP_UNAUTHORIZED pages */
  ap_custom_response(r, HTTP_UNAUTHORIZED, dconf->login_url);

  /* Assertions should only appear on POST requests */
  if (r->method_number == M_POST) {
    assertion = apr_table_get(r->headers_in, dconf->assertion_header);
  }

  // We'll trade you a valid assertion for a session cookie!
  // this is a programatic XHR request
  if (assertion) {
    VerifyResult res = processAssertion(r, dconf->verifier_url, assertion);

    /* XXX: Needs to be configurable */
    if (dconf->local_verify) {
      verify_assertion_local(r, assertion);
    }
    
    if (!res->errorResponse) {
      assert(res->verifiedEmail);
      assert(res->identityIssuer);

      ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_NOERRNO, 0, r, ERRTAG
                    "email '%s' verified, vouched for by issuer '%s'",
                    res->verifiedEmail, res->identityIssuer);

      Cookie cookie = apr_pcalloc(r->pool, sizeof(struct _Cookie));
      cookie->verifiedEmail = res->verifiedEmail;
      cookie->identityIssuer = res->identityIssuer;
      set_cookie_from_config(dconf, cookie);

      sendSignedCookie(r, conf->secret, dconf->cookie_name, cookie);

      r->user = apr_pstrdup(r->pool, res->verifiedEmail);

      /* XXX: At this point, we have authenticated the user, but we bail out too soon
       * XXX: from the processing. For this request completion, there is no r->user
       * XXX: However, this is the XHR request, so bail out before sending content out
       */
      return DONE;
    }
    else {
      ap_set_content_type(r, "application/json");
      ap_rwrite(res->errorResponse, strlen(res->errorResponse), r);
      apr_table_set(r->err_headers_out, "X-Persona-Error",
                    res->errorResponse);

      // upon assertion verification failure we return JSON explaining why
      r->status = HTTP_INTERNAL_SERVER_ERROR;
      return DONE;
    }
  }

  // if there's a valid cookie, allow the user throught
  szCookieValue = extractCookie(r, conf->secret, dconf->cookie_name);

  Cookie cookie = NULL;
  if (szCookieValue) {
    if ((cookie = validateCookie(r, conf->secret, szCookieValue))) {
      r->user = (char *) cookie->verifiedEmail;
      apr_table_setn(r->notes, PERSONA_ISSUER_NOTE, cookie->identityIssuer);
      apr_table_setn(r->subprocess_env, PERSONA_ENV_IDP,
                     cookie->identityIssuer);

      /* If requested, fake a Authorization: header */
      if (dconf->fake_basic_auth) {
        fake_basic_auth(r);
      }

      /* Logged-in user is visiting the logout url */
      if (dconf->logout_url && strcmp(dconf->logout_url, r->uri) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, ERRTAG
                      "User '%s' logging out via '%s', sending to %s",
                      r->user, r->uri, dconf->logout_returnto_url);
        apr_table_setn(r->subprocess_env, PERSONA_ENV_LOGOUT_RETURNTO,
                       dconf->logout_returnto_url);
        set_cookie_from_config(dconf, cookie);
        clearCookie(r, conf->secret, dconf->cookie_name, cookie);
      }
      return OK;
    }
    else {                      /* cookie didn't validate */
      /* XXX: Absctraction not quite right, creating a cookie structure here feels wrong */
      cookie = apr_pcalloc(r->pool, sizeof(*cookie));
      cookie->path = dconf->location;
      clearCookie(r, conf->secret, dconf->cookie_name, cookie);
    }
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

  persona_dir_config_t *dconf =
    ap_get_module_config(r->per_dir_config, &authn_persona_module);

  apr_table_set(r->err_headers_out, "X-Mod-Auth-Persona", VERSION);

  /* We take over all HTTP_UNAUTHORIZED pages */
  ap_custom_response(r, HTTP_UNAUTHORIZED, dconf->login_url);

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
  if (dconf->authoritative) {
    return HTTP_UNAUTHORIZED;
  }
  else {
    return DECLINED;
  }
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
                   ERRTAG
                   "created a secret since none was configured for %s (AuthPersonaServerSecret %s)",
                   sp->server_hostname, conf->secret->data);
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

static apr_status_t persona_generate_secret(apr_pool_t * p, server_rec *s,
                                            persona_config_t * conf)
{
  unsigned char *secret = apr_pcalloc(p, conf->secret_size);
  apr_status_t status;

  status = apr_generate_random_bytes(secret, conf->secret_size);

  if (APR_SUCCESS == status) {
    /* Turn into printable */
    secret = (unsigned char *) ap_pbase64encode(p, (char *) secret);
    /* Truncate to right length */
    secret[conf->secret_size] = 0;
    conf->secret->data = (char *) secret;
    conf->secret->len = conf->secret_size;
  }

  return status;
}

static void *persona_create_dir_config(apr_pool_t * p, char *path)
{
  persona_dir_config_t *dconf = apr_palloc(p, sizeof(*dconf));
  dconf->location = path ? apr_pstrdup(p, path) : "/";
  dconf->verifier_url = PERSONA_DEFAULT_VERIFIER_URL;
  dconf->verifier_url_set = 0;
  dconf->login_url = PERSONA_LOGIN_URL;
  dconf->login_url_set = 0;
  dconf->logout_url = NULL;
  dconf->logout_url_set = 0;
  dconf->logout_returnto_url = "/";
  dconf->logout_returnto_url_set = 0;
  dconf->cookie_secure = 0;
  dconf->cookie_secure_set = 0;
  dconf->authoritative = 1;
  dconf->authoritative_set = 0;
  dconf->cookie_name = PERSONA_COOKIE_NAME;
  dconf->cookie_name_set = 0;
  dconf->cookie_domain = NULL;
  dconf->cookie_domain_set = 0;
  dconf->cookie_duration = PERSONA_COOKIE_DURATION;
  dconf->cookie_duration_set = 0;
  dconf->assertion_header = PERSONA_ASSERTION_HEADER;
  dconf->assertion_header_set = 0;
  dconf->local_verify = 0;
  dconf->local_verify_set = 0;
  return dconf;
}

static void *persona_create_svr_config(apr_pool_t * p, server_rec *s)
{
  persona_config_t *conf = apr_palloc(p, sizeof(*conf));

  conf->secret = apr_pcalloc(p, sizeof(buffer_t));
  conf->secret_size = PERSONA_SECRET_SIZE;


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
  persona_dir_config_t *dconf = cfg;
  dconf->cookie_duration = atoi(arg);
  dconf->cookie_duration_set = 1;
  return NULL;
}

const char *persona_server_cookie_name(cmd_parms *cmd, void *cfg,
                                       const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->cookie_name = apr_pstrdup(cmd->pool, arg);
  dconf->cookie_name_set = 1;
  return NULL;
}

const char *persona_server_cookie_secure(cmd_parms *cmd, void *cfg, int flag)
{
  persona_dir_config_t *dconf = cfg;
  dconf->cookie_secure = flag;
  dconf->cookie_secure_set = 1;
  return NULL;
}

const char *persona_local_verify(cmd_parms *cmd, void *cfg, int flag)
{
  persona_dir_config_t *dconf = cfg;
  dconf->local_verify = flag;
  dconf->local_verify_set = 1;
  return NULL;
}

const char *persona_authoritative(cmd_parms *cmd, void *cfg, int flag)
{
  persona_dir_config_t *dconf = cfg;
  dconf->authoritative = flag;
  dconf->authoritative_set = 1;
  return NULL;
}

const char *persona_fake_basic_auth(cmd_parms *cmd, void *cfg, int flag)
{
  persona_dir_config_t *dconf = cfg;
  dconf->fake_basic_auth = flag;
  dconf->fake_basic_auth_set = 1;
  return NULL;
}

const char *persona_server_cookie_domain(cmd_parms *cmd, void *cfg,
                                         const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->cookie_domain = apr_pstrdup(cmd->pool, arg);
  dconf->cookie_domain_set = 1;
  return NULL;
}

const char *persona_server_verifier_url(cmd_parms *cmd, void *cfg,
                                        const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->verifier_url = apr_pstrdup(cmd->pool, arg);
  dconf->verifier_url_set = 1;
  return NULL;
}

const char *persona_server_login_url(cmd_parms *cmd, void *cfg,
                                     const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->login_url = apr_pstrdup(cmd->pool, arg);
  dconf->login_url_set = 1;
  return NULL;
}

const char *persona_server_logout_url(cmd_parms *cmd, void *cfg,
                                      const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->logout_url = apr_pstrdup(cmd->pool, arg);
  dconf->logout_url_set = 1;
  return NULL;
}

const char *persona_server_logout_returnto_url(cmd_parms *cmd, void *cfg,
                                               const char *arg)
{
  persona_dir_config_t *dconf = cfg;
  dconf->logout_returnto_url = apr_pstrdup(cmd->pool, arg);
  dconf->logout_returnto_url_set = 1;
  return NULL;
}

/* If the current config is set, use it, otherwise, use the parent's */
#define persona_merge_parent(name, merged, parent, child) \
  merged->name = child->name ## _set ? child->name : parent->name; \
  merged->name ## _set = child->name ## _set ? child->name ## _set : parent->name ## _set

static void *persona_merge_dir_config(apr_pool_t * p, void *parent_conf,
                                      void *child_conf)
{
  persona_dir_config_t *parent = (persona_dir_config_t *) parent_conf;
  persona_dir_config_t *child = (persona_dir_config_t *) child_conf;
  persona_dir_config_t *merged = apr_pcalloc(p, sizeof(*merged));

  /* Just use the current location */
  merged->location = child->location;
// 
  persona_merge_parent(cookie_name, merged, parent, child);
  persona_merge_parent(cookie_domain, merged, parent, child);
  persona_merge_parent(cookie_duration, merged, parent, child);
  persona_merge_parent(cookie_secure, merged, parent, child);
  persona_merge_parent(authoritative, merged, parent, child);
  persona_merge_parent(login_url, merged, parent, child);
  persona_merge_parent(logout_url, merged, parent, child);
  persona_merge_parent(logout_returnto_url, merged, parent, child);
  persona_merge_parent(verifier_url, merged, parent, child);
  persona_merge_parent(assertion_header, merged, parent, child);
  persona_merge_parent(fake_basic_auth, merged, parent, child);
  persona_merge_parent(local_verify, merged, parent, child);

  return merged;
}

static void *persona_merge_svr_config(apr_pool_t * p, void *parent_conf,
                                      void *child_conf)
{
  persona_config_t *parent = (persona_config_t *) parent_conf;
  persona_config_t *child = (persona_config_t *) child_conf;
  persona_config_t *merged = apr_pcalloc(p, sizeof(*merged));

  if (child->secret->len) {
    merged->secret_size = child->secret_size;
    merged->secret = child->secret;
  }
  else {
    merged->secret_size = parent->secret_size;
    merged->secret = parent->secret;
  }

  return merged;
}

static const command_rec Auth_persona_options[] = {
  AP_INIT_TAKE1("AuthPersonaServerSecret", persona_server_secret_option,
                NULL, RSRC_CONF, "Server secret to use for cookie signing"),
  AP_INIT_TAKE1("AuthPersonaCookieName", persona_server_cookie_name,
                NULL, RSRC_CONF | OR_AUTHCFG, "Name of the Persona Cookie"),
  AP_INIT_TAKE1("AuthPersonaCookieDomain", persona_server_cookie_domain,
                NULL, RSRC_CONF | OR_AUTHCFG,
                "Domain for the Persona Cookie"),
  AP_INIT_TAKE1("AuthPersonaCookieDuration", persona_server_cookie_duration,
                NULL, RSRC_CONF | OR_AUTHCFG,
                "Duration of the Persona Cookie"),
  AP_INIT_FLAG("AuthPersonaCookieSecure", persona_server_cookie_secure,
               NULL, RSRC_CONF | OR_AUTHCFG, "HTTPS only Persona Cookie"),
  AP_INIT_FLAG("AuthPersonaAuthoritative", persona_authoritative,
               NULL, RSRC_CONF | OR_AUTHCFG, "HTTPS only Persona Cookie"),
  AP_INIT_FLAG("AuthPersonaLocalVerify", persona_local_verify,
               NULL, RSRC_CONF | OR_AUTHCFG, "Perform local assertion verification"),
  AP_INIT_TAKE1("AuthPersonaVerifierURL", persona_server_verifier_url,
                NULL, RSRC_CONF | OR_AUTHCFG,
                "URL to a Persona Verfier service"),
  AP_INIT_TAKE1("AuthPersonaLoginURL", persona_server_login_url,
                NULL, RSRC_CONF | OR_AUTHCFG, "URL to a Persona login page"),
  AP_INIT_TAKE1("AuthPersonaLogoutURL", persona_server_logout_url,
                NULL, RSRC_CONF | OR_AUTHCFG, "URL to a Persona logout page"),
  AP_INIT_TAKE1("AuthPersonaLogoutReturnTo",
                persona_server_logout_returnto_url,
                NULL, RSRC_CONF | OR_AUTHCFG,
                "URL to redirect to after logging out"),
  AP_INIT_FLAG("AuthPersonaFakeBasicAuth", persona_fake_basic_auth,
               NULL, RSRC_CONF | OR_AUTHCFG,
               "Should we fake basic authentication?"),
  {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA authn_persona_module = {
  STANDARD20_MODULE_STUFF,
  persona_create_dir_config,    /* dir config creator */
  persona_merge_dir_config,     /* dir merger --- default is to override */
  persona_create_svr_config,    /* server config creator */
  persona_merge_svr_config,     /* merge server config */
  Auth_persona_options,         /* command apr_table_t */
  register_hooks                /* register hooks */
};
