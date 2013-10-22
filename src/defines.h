#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stddef.h>
#include "hmac.h"

#define PERSONA_DEFAULT_VERIFIER_URL "https://verifier.login.persona.org/verify"
#define PERSONA_LOGIN_URL "/login.shtml"
#define PERSONA_COOKIE_NAME "Persona"
#define PERSONA_COOKIE_DURATION (60*60*12)
#define PERSONA_ENV_IDP "PERSONA_IDP"
#define PERSONA_ISSUER_NOTE "persona-identity-issuer"
#define PERSONA_SECRET_SIZE HMAC_DIGESTSIZE
#define PERSONA_ASSERTION_HEADER "X-Persona-Assertion"
#define PERSONA_END_PAGE "\n</script>\n</html>\n"

#define ERRTAG "authn_persona: "

typedef struct buffer
{
  size_t len;
  char *data;
} buffer_t;

typedef struct persona_dir_config
{
  char *location;
  char *verifier_url;
  int verifier_url_set;
  char *login_url;
  int login_url_set;
  char *cookie_name;
  int cookie_name_set;
  char *cookie_domain;
  int cookie_domain_set;
  unsigned int cookie_duration;
  int cookie_duration_set;
  int cookie_secure;
  int cookie_secure_set;
  char *assertion_header;
  int assertion_header_set;
  int authoritative;
  int authoritative_set;
} persona_dir_config_t;

typedef struct persona_config
{
  buffer_t *secret;
  unsigned int secret_size;
} persona_config_t;

#endif
