AC_INIT([flopsar-ldap],[3.0.0])

AC_PROG_CC

CFLAGS="-Wall -std=c11 -fPIC -O3 -Werror=implicit-function-declaration -Werror=format -DLDAP_DEPRECATED=1"

AM_INIT_AUTOMAKE([foreign 1.13])

AC_SUBST([PLUGIN_NAME], [flopsar-ldap])

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug],
        [enable debugging support, default: no]))

AS_IF([test "x$enable_debug" != "xyes"], [
	CFLAGS+=" -DNDEBUG"
])

AC_CONFIG_FILES([Makefile])

AC_CONFIG_MACRO_DIRS([m4])

AC_SEARCH_LIBS([ldap_initialize], [ldap], [], [
 AC_MSG_ERROR([Cannot find ldap library])
])

LT_INIT

AC_OUTPUT
