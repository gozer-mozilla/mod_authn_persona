AUTOMAKE_OPTIONS=foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

module_LTLIBRARIES = mod_authn_persona.la

moduledir = $(shell $(APXS) -q LIBEXECDIR)

EXTRA_DIST=t/htdocs/logout.shtml \
 t/htdocs/testidp.shtml \
 t/htdocs/login.shtml \
 t/conf/extra.conf.in \
 README.md \
 ChangeLog \
 build/mod_authn_persona.spec \
 build/test.pl \
 .indent.pro

CLEANFILES=t/logs/access_log t/logs/error_log 
DISTCLEANFILES=t/htdocs/index.html t/TEST t/conf/extra.conf t/conf/httpd.conf t/conf/apache_test_config.pm

APR_CONFIG = $(shell $(APXS) -q APR_CONFIG)
APU_CONFIG = $(shell $(APXS) -q APU_CONFIG)
APR_CFLAGS = $(shell $(APR_CONFIG) --cflags --cppflags --includes)
APU_CFLAGS = $(shell $(APU_CONFIG) --includes)

HTTPD_CFLAGS = $(shell $(APXS) -q CFLAGS) -I $(shell $(APXS) -q INCLUDEDIR)

AM_CFLAGS = -Isrc $(HTTPD_CFLAGS) $(APR_CFLAGS) $(APU_CFLAGS) $(JSON_CFLAGS) $(LIBCURL_CPPFLAGS) $(OPENSSL_INCLUDES) $(WARN_CFLAGS)

mod_authn_persona_la_SOURCES = src/mod_authn_persona.c src/cookie.c src/verify.c src/hmac.c src/cookie.h src/defines.h src/verify.h src/hmac.h src/version.h
BUILT_SOURCES = src/version.h
mod_authn_persona_la_LDFLAGS = -module -avoid-version $(JSON_LIBS) $(LIBCURL) $(OPENSSL_LDFLAGS) $(OPENSSL_LIBS)

mod_authn_persona_ladir = $(datarootdir)/$(PACKAGE)
mod_authn_persona_la_DATA = t/htdocs/login.shtml t/htdocs/logout.shtml

TEST_VERBOSE := 0

check: test

test: all t/TEST
	$(PERL) t/TEST --verbose=$(TEST_VERBOSE)

t/TEST: build/test.pl
	$(PERL) build/test.pl -apxs $(APXS)

rpm: dist
	rpmbuild -ta $(DIST_ARCHIVES)

srpm: dist
	rpmbuild -ts $(DIST_ARCHIVES)

indent:
	indent -i2 -npsl -di0 -br -nce -d0 -cli0 -npcs -nfc1 -nut $(SOURCES)
