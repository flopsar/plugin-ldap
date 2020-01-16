
#define _GNU_SOURCE
#include <string.h>
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#include "api/plugin.h"


#define AuthResult(t)	PLG_AUTH_##t

#if defined(NDEBUG)
#define debug(fmt,...)
#else
#define debug(fmt,...)		do { fprintf(stderr, "DEBUG [%d] "fmt"\n", __LINE__,##__VA_ARGS__);} while(0)
#endif
#define error(fmt,...)		do { fprintf(stderr, "ERROR [%d] "fmt"\n", __LINE__,##__VA_ARGS__);} while(0)

typedef struct {
	const char *key;
	char *value;
} Option;

enum {
	OPTION_URL = 0,
	OPTION_BASE_DN,
	OPTION_BIND_DN,
	OPTION_BIND_PASSWD,
	OPTION_USER_SEARCH,
	OPTION_USER_ATTR
};

static Option options[] = {
	{.key = "url", .value = NULL },
	{.key = "base.dn", .value = NULL },
	{.key = "bind.dn", .value = NULL },
	{.key = "bind.password", .value = NULL },
	{.key = "user.search", .value = NULL },
	{.key = "user.attr.username", .value = NULL },
	{0}
};

#define OPTION(t)	options[OPTION_##t].value

static int user_auth(const char*, const char*);
static int load_config(const char*);
static char* substitute(const char*, const char*, const char*);
static char* ldap_user_getdn(LDAP*, const char*, const char*, const char*, const char*);
static int bind_with_user(LDAP *, const char *, const char *);
static void parse_line(char *);






/*
* This is the function we are required to implement.
*/
int
plugin_init(Plugin *p, const char *cfg)
{
	/* Since the plugin has a configuration file, 
	 we need to parse and load the configuration first. */
	if (load_config(cfg))
		return -1;

	plugin_register_auth(p, user_auth);
	return 0;
}









static
int
user_auth(const char *username, const char *password)
{
	assert(username);
	assert(password);

	LDAP *ldap = NULL;
	int result = AuthResult(DENIED);

	debug("Initializing LDAP ...");
	int rc = ldap_initialize(&ldap, OPTION(URL));
	if (rc){
		error("LDAP error: %s.",ldap_err2string(rc));
		return result;
	}
	rc = bind_with_user(ldap, OPTION(BIND_DN), OPTION(BIND_PASSWD));
	if (rc){
		ldap_unbind_ext_s(ldap,NULL,NULL);
		goto exit_auth;
	}

	char *user_dn = ldap_user_getdn(ldap, username, OPTION(BASE_DN), OPTION(USER_SEARCH), OPTION(USER_ATTR));
	if (NULL != user_dn){
		rc = bind_with_user(ldap, user_dn, password);
		result = rc ? AuthResult(DENIED) : AuthResult(GRANTED);
		free(user_dn);
	}
exit_auth:;
	ldap_unbind_ext_s(ldap,NULL,NULL);
	return result;
}







static int
bind_with_user(LDAP *ldap, const char *user_dn, const char *password)
{
	assert(ldap);
	assert(user_dn);
	assert(password);

	int p = LDAP_VERSION3;
	int rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &p);
	if (LDAP_OPT_SUCCESS != rc){
		error("LDAP error: %s.", ldap_err2string(rc));
		return -1;
	}
	rc = ldap_simple_bind_s(ldap, user_dn, password);
	if (rc){
		error("LDAP error: %s.", ldap_err2string(rc));
		return -1;
	}
	debug("User %s bound to LDAP successfully.", user_dn);
	return 0;
}




static
char*
substitute(const char *string_s, const char *pattern_s,
	  const char *input_s)
{
	assert(string_s);

	size_t plen = strlen(pattern_s);
	size_t slen = strlen(string_s);
	size_t ilen = strlen(input_s);
	size_t olen = slen - plen + ilen + 1;

	char *begin = strstr(string_s, pattern_s);
	if (!begin)
		return NULL;

	char *out = malloc(olen);
	memcpy(out, string_s,begin - string_s);
	int offset = begin - string_s;
	memcpy(out + offset, input_s, ilen);
	offset += ilen;
	memcpy(out + offset,begin + plen,slen - (begin - string_s) - plen);
	*(out + olen - 1) = '\0';

	return out;
}







static char*
ldap_user_getdn(LDAP *ldap, const char *username_s, const char *base_dn_s,
	const char *user_search_s, const char *user_attr_name_s)
{
	LDAPMessage *result;
	char *user_dn = NULL;

	char *search_s = substitute(user_search_s,"$", username_s);
	char *attrs[] = { OPTION(USER_ATTR), NULL};

	debug("LDAP Searching LDAP with %s ...",search_s);
	int rc = ldap_search_ext_s(ldap, base_dn_s, LDAP_SCOPE_SUBTREE, search_s,
		attrs, 0, NULL, NULL, NULL, 0, &result);
	if (rc){
		error("LDAP search error: %s.", ldap_err2string(rc));
		free(search_s);
		return NULL;
	}

	char *dn;
	for (LDAPMessage *e = ldap_first_entry(ldap, result); e; e = ldap_next_entry(ldap, e)){
		if (NULL != user_dn)
			break;
		if (NULL == (dn = ldap_get_dn(ldap, e)))
			continue;

		BerElement *ber;
		struct berval **vals;
		for (char *a = ldap_first_attribute(ldap, e, &ber); a; a = ldap_next_attribute(ldap, e, ber)){
			if (strcmp(user_attr_name_s, a)){
				ldap_memfree(a);
				continue;
			}
			if ((vals = ldap_get_values_len(ldap, e, a))){
				for (size_t i = 0; vals[i]; i++ ) {
					if (strcmp(username_s, vals[i]->bv_val))
						continue;

					user_dn = strdup(dn);
					debug("LDAP Found %s user: %s", username_s, dn);
					break;
				}
				ldap_value_free_len(vals);
			}
			ldap_memfree(a);
		}
		ber_free(ber, 0);
		ldap_memfree(dn);
	}

	ldap_msgfree(result);
	if (!user_dn)
		debug("LDAP: No such user: %s",username_s);

	free(search_s);
	return user_dn;
}











static void
parse_line(char *line)
{
	while (isspace(*line))
		line++;
	if ('#' == *line)
		return;
	char *val = strchr(line, '=');
	if (NULL == val)
		return;
	*val = '\0';
	char *k = line;
	char *v = ++val;
	char *n = strchr(v, '\n');
	if (NULL != n){
		*n = '\0';
	}

	for (Option *o = options; o->key; o++){
		if (o->value || strcmp(o->key, k))
			continue;
		o->value = strdup(v);
	}
}




static
int
load_config(const char *cfg)
{
	char buff[512];

	if (NULL == cfg){
		error("No configuration file!");
		return -1;
	}
	FILE *c = fopen(cfg, "r");
	if (NULL == c){
		error("Cannot read configuration file! %s", strerror(errno));
		return -1;
	}
	while (fgets(buff, sizeof(buff), c)){
		char *line = buff;
		parse_line(line);
	}
	fclose(c);
	for (Option *o = options; o->key; o++){
		if (NULL == o->value){
			error("Missing %s option!", o->key);
			return -1;
		}
	}
   	return 0;
}















