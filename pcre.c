/*
 * Written by Alexey Tourbin <at@altlinux.org>.
 *
 * The author has dedicated the code to the public domain.  Anyone is free
 * to copy, modify, publish, use, compile, sell, or distribute the original
 * code, either in source code form or as a compiled binary, for any purpose,
 * commercial or non-commercial, and by any means.
 */

#if !defined(SQLITE_CORE) || defined(SQLITE_ENABLE_PCRE)

#ifdef WITH_HYPERSCAN
/* https://www.intel.com/content/www/us/en/developer/articles/training/why-and-how-to-replace-pcre-with-hyperscan.html */
/* TODO implement pcre fallback for com̂plex expressions. */
#else
#ifndef WITH_PCRE
#define WITH_PCRE
#endif
#endif
#if defined(WITH_PCRE) && !defined(WITH_PCRE2) && !defined(WITH_PCRE1)
#define WITH_PCRE1
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef WITH_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif
#ifdef WITH_PCRE1
#include <pcre.h>
#endif
#ifdef WITH_HYPERSCAN
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#endif
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

typedef struct {
    char *s;
#ifdef WITH_PCRE2
    pcre2_code *p;
    pcre2_match_data *matches;
#endif
#ifdef WITH_PCRE1
    pcre *p;
    pcre_extra *e;
#endif
#ifdef WITH_HYPERSCAN
    hs_database_t *hs;
    hs_scratch_t *scratch;
#endif
} cache_entry;

#ifndef CACHE_SIZE
#define CACHE_SIZE 16
#endif

#define POS_T int

/* PCRE1-to-2 compatibility layer */
#ifdef WITH_PCRE2
#undef POS_T
#define POS_T size_t
#endif

#ifdef WITH_HYPERSCAN
int sqlite3_hs_callback(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context)
{
    ++*((int *)context);
    return 1;
}
#endif

static
void regexp(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    const char *re, *str;
    cache_entry *cache;

    assert(argc == 2);

    re = (const char *) sqlite3_value_text(argv[0]);
    if (!re) {
	sqlite3_result_error(ctx, "no regexp", -1);
	return;
    }

    str = (const char *) sqlite3_value_text(argv[1]);
    if (!str) {
	sqlite3_result_null(ctx);
	return;
    }

    /* simple LRU cache */
    {
	int i;
	int found = 0;
	cache = sqlite3_user_data(ctx);

	assert(cache);

	for (i = 0; i < CACHE_SIZE && cache[i].s; i++)
	    if (strcmp(re, cache[i].s) == 0) {
		found = 1;
		break;
	    }
	if (found) {
	    if (i > 0) {
		cache_entry c = cache[i];
		memmove(cache + 1, cache, i * sizeof(cache_entry));
		cache[0] = c;
	    }
	}
	else {
	    cache_entry c;
	    bzero(&c, sizeof(c));
#ifdef WITH_PCRE2
#define ERR_MAX_LENGTH 1024
	    int errcode;
		char err[ERR_MAX_LENGTH];
#endif
#ifdef WITH_PCRE1
	    const char *err;
#endif
#ifdef WITH_HYPERSCAN
	    hs_error_t errcode;
	    hs_compile_error_t *err;
#endif
	    POS_T pos;
		const char *re2 = re;
		char *re2mod = NULL;
		int options = 0;
		/* interpret "/.../i" regex as ... with flags */
		if (re[0] == '/') {
			for (re2 = &re[strlen(re)]; --re2 > re;) {
				switch (*re2) {
					case 'i':
#ifdef WITH_PCRE2
						options |= PCRE2_CASELESS;
#endif
#ifdef WITH_PCRE1
						options |= PCRE_CASELESS;
#endif
#ifdef WITH_HYPERSCAN
						options |= HS_FLAG_CASELESS;
#endif
						break;
					case '/':
						pos = re2 - re;
						if (!(re2mod = strdup(re))) {
							sqlite3_result_error(ctx, "strdup: ENOMEM", -1);
							return;
						}
						re2mod[pos] = 0;
						re2 = re2mod + 1;
						goto breakfast;
					default:
						re2 = re;
				}
			}
			/* if going here we did not find an ending /: restore everything */
			options = 0;
		}
breakfast:
#ifdef WITH_PCRE2
	    c.p = pcre2_compile((const unsigned char *)re2, strlen(re2), options, &errcode, &pos, NULL);
	    pcre2_jit_compile(c.p, PCRE2_JIT_COMPLETE|PCRE2_JIT_PARTIAL_HARD|PCRE2_JIT_PARTIAL_SOFT);
#endif
#ifdef WITH_PCRE1
	    c.p = pcre_compile(re2, options, &err, &pos, NULL);
#endif
#ifdef WITH_HYPERSCAN
	    errcode = hs_compile(re2, options, HS_MODE_BLOCK, NULL, &c.hs, &err);
#endif
		if (re2mod) {
			free(re2mod);
		}
#ifdef WITH_PCRE
	    if (!c.p) {
#ifdef WITH_PCRE2
		pcre2_get_error_message(errcode, (unsigned char *)err, ERR_MAX_LENGTH);
#endif
		char *e2 = sqlite3_mprintf("%s: %s (offset %d)", re, err, pos);
#endif
#ifdef WITH_HYPERSCAN
	    if (errcode) {
		char *e2 = sqlite3_mprintf("%s: %s", re, err->message);
#endif
		sqlite3_result_error(ctx, e2, -1);
		sqlite3_free(e2);
		return;
	    }
#ifdef WITH_PCRE2
	    c.matches = pcre2_match_data_create_from_pattern(c.p, NULL);
	    if (!c.matches) {
		pcre2_code_free(c.p);
		sqlite3_result_error(ctx, "pcre2_match_data_create_from_pattern: ENOMEM", -1);
		return;
	    }
#endif
#ifdef WITH_PCRE1
	    c.e = pcre_study(c.p, 0, &err);
#endif
#ifdef WITH_HYPERSCAN
	    hs_alloc_scratch(c.hs, &c.scratch);
#endif
	    c.s = strdup(re);
	    if (!c.s) {
		sqlite3_result_error(ctx, "strdup: ENOMEM", -1);
#ifdef WITH_PCRE2
		pcre2_code_free(c.p);
		pcre2_match_data_free(c.matches);
#endif
#ifdef WITH_PCRE1
		pcre_free(c.p);
		pcre_free(c.e);
#endif
#ifdef WITH_HYPERSCAN
		hs_free_database(cache[i].hs);
#endif
		return;
	    }
	    i = CACHE_SIZE - 1;
	    if (cache[i].s) {
		free(cache[i].s);
#ifdef WITH_PCRE2
		pcre2_code_free(cache[i].p);
		pcre2_match_data_free(cache[i].matches);
#endif
#ifdef WITH_PCRE1
		assert(cache[i].p);
		pcre_free(cache[i].p);
		pcre_free(cache[i].e);
#endif
#ifdef WITH_HYPERSCAN
		hs_free_database(cache[i].hs);
#endif
	    }
	    memmove(cache + 1, cache, i * sizeof(cache_entry));
	    cache[0] = c;
	}
    }

    {
	int rc;
#ifdef WITH_PCRE2
	assert(cache);
	/* No need to use pcre2_jit_match, it seems that pcre2_match benefits from pcre2_jit_compile
	 * (even if call options are set to 0, as long as _jit_compile had the right options).
	 * Else we could use pcre2_jit_match conditionnally (like glib which tests which options are JIT-compatible else fallbacks to pcre2_match())
	 */
	rc = pcre2_match(cache->p, (const unsigned char *)str, strlen(str), 0, 0, cache->matches, NULL);
	sqlite3_result_int(ctx, rc >= 0);
#endif
#ifdef WITH_PCRE1
	assert(cache);
	rc = pcre_exec(cache->p, cache->e, str, strlen(str), 0, 0, NULL, 0);
	sqlite3_result_int(ctx, rc >= 0);
#endif
#ifdef WITH_HYPERSCAN
	int results = 0;
	rc = hs_scan(cache->hs, str, strlen(str), 0, cache->scratch, sqlite3_hs_callback, &results);
	sqlite3_result_int(ctx, rc == HS_SCAN_TERMINATED && results > 0);
#endif
	return;
    }
}

#if !defined(SQLITE_CORE)
int sqlite3_extension_init(sqlite3 *db, char **err, const sqlite3_api_routines *api)
{
	SQLITE_EXTENSION_INIT2(api)
#else
int sqlite3PcreInit(sqlite3 *db)
{
#endif
	cache_entry *cache = calloc(CACHE_SIZE, sizeof(cache_entry));
	if (!cache) {
#if !defined(SQLITE_CORE)
	    *err = "calloc: ENOMEM";
#else
        sqlite3ErrorWithMsg(db, SQLITE_ERROR, "calloc: ENOMEM");
#endif
	    return 1;
	}
	sqlite3_create_function(db, "REGEXP", 2, SQLITE_UTF8, cache, regexp, NULL, NULL);
	return 0;
}

#endif
