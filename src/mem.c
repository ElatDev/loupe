#include "mem.h"

#include <stdlib.h>

static long g_live;
static unsigned long long g_total;

void *lp_malloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (p) {
        g_live++;
        g_total++;
    }
    return p;
}

void *lp_calloc(size_t count, size_t size)
{
    void *p = calloc(count ? count : 1, size ? size : 1);
    if (p) {
        g_live++;
        g_total++;
    }
    return p;
}

void *lp_realloc(void *p, size_t n)
{
    if (!p)
        return lp_malloc(n);
    /* realloc leaves the old block alive on failure, so the count is
     * unchanged either way. */
    return realloc(p, n ? n : 1);
}

void lp_free(void *p)
{
    if (p) {
        g_live--;
        free(p);
    }
}

long lp_live_allocations(void) { return g_live; }

unsigned long long lp_total_allocations(void) { return g_total; }
