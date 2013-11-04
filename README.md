mod_authn_persona is a module for Apache 2.0 or later that
allows you quickly add Persona Authentication to a site hosted with
apache.

Installation
=======================

```
git clone https://github.com/lloyd/mod_authn_persona.git
cd mod_authn_persona
./buildconf
./configure --with-apxs=/usr/sbin/apxs
sudo make install
```

(this assumes apxs is behaving properly on your system; use --with-apxs
to point to your apxs or apxs2 binary of choice)

# Configuration

Configure the module:

    LoadModule authn_persona_module modules/mod_authn_persona.so
    
    #AuthPersonaServerSecret XXXSomeVerySecretUniqueString
    #AuthPersonaCookieName   Persona
    #AuthPersonaVerifierURL  https://verifier.login.anosrep.org/verify
    #AuthPersonaLoginURL     /login.shtml
    
    <Location />
       AuthType Persona
       Require valid-user
       # Or, require users with host/IdP example.com:
       # Require persona-idp example.com
       # Or, require specific users
       # Require user user@example.com
    </Location>

This will cause the module to require Persona authentication for all
requests to the server.

Dependencies
============

* apache 2.0.x or 2.2.x (mostly tested with 2.2 so far)
* libcurl 7.10.8 or later
* json-c
* OpenSSL

# Features

* **zero configuration** - The module is designed with reasonable
    defaults, so you can simply drop it in
* **automatic re-auth** - The module is designed to use session
    cookies and automatically re-authenticate.

# How it Works

The module works by intercepting requests bound for protected
resources, and checking for the presence of a session cookie.

If the cookie is not found, the user agent is served an HTML document
that presents a Persona login page.

Upon successful authentication with Persona, this page will send a
request to the server with a Persona assertion in an HTTP header.  The
module, upon detecting no cookie is present, will look for this
header, validate the assertion, and set a short session cookie.

The authentication page will then reload the desired resource.

Further configuration settings
==============================

* `AuthPersonaServerSecret`: (default: generated)
  A secret that will be used to sign cookies. Must be set in a server or
  VirtualHost context. If not provided, upon server start a secret will be
  generated automatically. Given re-authentication is automatic, it is only
  required to set a cookie secret if your application is hosted on multiple
  load-balanced Apache servers.

* `AuthPersonaCookieName`: (default: Persona)

  The name for the Persona Session cookie

* `AuthPersonaCookieDomain`: (default: None)

  The domain that the cookie is valid for, so for instance '.domain.com'
* `AuthPersonaCookieSecure`: (default: Off)

  If the cookie should be limited to SSL connections or not
  
  Sending this cookie via non-SSL connections is dangereous, as stealing this
  cookie steals your identity.

* `AuthPersonaCookieDuration`: (default: 1 day)

  The lifetime of the session itself, after that, the user will be re-authed

* `AuthPersonaAuthoritative`: (default: Off)

  Wherever the module will let other modules try their luck at authenticating users

* `AuthPersonaVerifierURL`: (default: https://verifier.login.persona.org/verify)

  This module uses a web service to verify recieved assertions, this is the URL
  of the service providing that service. It needs to be trusted

* `AuthPersonaLoginURL`: (default: /login.shtml)

  The location of the login page, it's never accessed directly. But it needs to be
  accessible by unauthenticated users.
* `AuthPersonaLogoutURL` (default: unset)

  The location where logout happens, accessing it triggers a session logout, but the
  location is responsible for the Persona JavaScript logout itself

* `AuthPersonaLogoutReturnTo` (default: /)

  When the logout page is accessed, where to redirect the now logged-out user to

* `AuthPersonaFakeBasicAuth`: (default: Off)

  When set, this will set a fake Authorization: header with the Persona userid and
  a fake password

* `Require persona-idp`:
  Only allow users with email addresses backed by the given Identity Provider.
  Note that this will often, but not necessarily, be the host part of the
  verified email address, in the case of email addresses backed by a secondary
  IdP (like the fallback IdP or a bridging IdP).
