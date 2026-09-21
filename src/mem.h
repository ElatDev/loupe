/*
 * mem.h - counted heap allocation.
 *
 * Every allocation in Loupe goes through these wrappers so that the number of
 * live blocks can be checked. Batch mode, the tests and the fuzz driver all
 * assert that it returns to zero after each file: a leak shows up as a
 * number, even on toolchains without LeakSanitizer (MSVC).
 */
#ifndef LOUPE_MEM_H
#define LOUPE_MEM_H

#include <stddef.h>

void *lp_malloc(size_t n);
void *lp_calloc(size_t count, size_t size);
void *lp_realloc(void *p, size_t n);
void  lp_free(void *p);

long lp_live_allocations(void);
unsigned long long lp_total_allocations(void);

#endif
