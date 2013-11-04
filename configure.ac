AC_PREREQ(2.60)
AC_INIT(mod_authn_persona, 0.4, gozer@mozilla.com)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([build])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_MACRO_DIR([m4])

AM_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([build/mod_authn_persona.spec src/version.h])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AX_WITH_APXS(no, [$PATH:/sbin:/usr/sbin:/usr/local/sbin])

if test "$apxs_found" = no ; then
    AC_MSG_ERROR([apxs is required])
fi

LIBCURL_CHECK_CONFIG([],[],[],[
    AC_MSG_ERROR([libcurl is required])
])

CHECK_SSL([],[AC_MSG_ERROR([openssl is required])])

PKG_CHECK_MODULES([JSON], [json])

AC_PROG_PERL_VERSION(5.8.0)
AC_PERL_MODULE_VERSION(Apache::Test 0, , AC_MSG_ERROR(Need some Perl modules))
AC_PERL_MODULE_VERSION(URI::Escape 0, , AC_MSG_ERROR(Need URI::Escape Perl modules))
AC_PERL_MODULE_VERSION(HTTP::Cookies 0, , AC_MSG_ERROR(Need HTTP::Cookies Perl modules))
AC_PERL_MODULE_VERSION(Test::More 0.94, , AC_MSG_ERROR(Need Test::More >= 0.94 Perl modules))
AC_C_CONST

AM_MAINTAINER_MODE

dnl Test compiler warning flags
AC_SUBST(WARN_CFLAGS)

AX_CHECK_COMPILE_FLAG(-Wall, [WARN_CFLAGS="$WARN_CFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG(-Werror, [WARN_CFLAGS="$WARN_CFLAGS -Werror"])

dnl We have some in progress, it's okay
AX_CHECK_COMPILE_FLAG(-Wno-unused-function, [WARN_CFLAGS="$WARN_CFLAGS -Wno-unused-function"])

dnl On OS X, this causes problems with unused -I flags
AX_CHECK_COMPILE_FLAG(-Qunused-arguments, [WARN_CFLAGS="$WARN_CFLAGS -Qunused-arguments"])


AC_OUTPUT(Makefile)
