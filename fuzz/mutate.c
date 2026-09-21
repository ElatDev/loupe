/*
 * mutate.c - a mutation fuzzer that needs no special toolchain.
 *
 * libFuzzer is better at finding new code paths, but it needs a compiler
 * that ships it. This driver runs anywhere: it takes real executables as
 * seeds, corrupts them in the ways that break parsers - sizes and counts
 * replaced with boundary values, offsets pointed off the end, files cut
 * short - and runs the parser in-process. Build it with a sanitizer and
 * every mutation is checked for out-of-bounds reads as well as crashes.
 *
 *   build.bat mutate
 *   build\fuzz\mutate.exe --runs 50000 build\loupe.exe C:\Windows\System32\*.dll
 *
 * The run is deterministic: the same --seed and the same seed files give
 * the same sequence of mutations, so a failure can be replayed.
 */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* fopen */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loupe.h"
#include "mem.h"

/* Values that tend to sit on the boundaries parsers get wrong. */
static const uint64_t interesting[] = {
    0, 1, 2, 3, 4, 7, 8, 0x10, 0x20, 0x3f, 0x40, 0x7e, 0x7f, 0x80, 0x81, 0xff,
    0x100, 0x1ff, 0x200, 0x1000, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7ffffffe,
    0x7fffffff, 0x80000000u, 0xfffffffeu, 0xffffffffu, 0x100000000ull,
    0x7fffffffffffffffull, 0x8000000000000000ull, 0xfffffffffffffffeull,
    0xffffffffffffffffull,
};

typedef struct rng {
    uint64_t s;
} rng;

static uint64_t next(rng *r)
{
    /* xorshift64*, so a run can be replayed from its seed */
    r->s ^= r->s >> 12;
    r->s ^= r->s << 25;
    r->s ^= r->s >> 27;
    return r->s * 0x2545f4914f6cdd1dull;
}

static uint64_t below(rng *r, uint64_t n) { return n ? next(r) % n : 0; }

typedef struct seed {
    uint8_t *data;
    size_t   size;
    const char *path;
} seed;

static bool load(const char *path, seed *s)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    for (;;) {
        if (len == cap) {
            cap *= 2;
            uint8_t *grown = realloc(buf, cap);
            if (!grown)
                break;
            buf = grown;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0)
            break;
    }
    fclose(f);
    if (!buf || !len) {
        free(buf);
        return false;
    }
    s->data = buf;
    s->size = len;
    s->path = path;
    return true;
}

/* Corrupt `buf`, favouring the header region where the interesting fields
 * live. Returns the (possibly shortened) size. */
static size_t mutate(rng *r, uint8_t *buf, size_t size, unsigned rounds)
{
    const size_t headers = size < 4096 ? size : 4096;
    for (unsigned i = 0; i < rounds && size; i++) {
        /* three times out of four, hit a header field */
        size_t region = (next(r) & 3) ? headers : size;
        size_t off = below(r, region ? region : 1);
        switch (next(r) % 5) {
        case 0:
            buf[off] = (uint8_t)next(r);
            break;
        case 1:
            buf[off] ^= (uint8_t)(1u << (next(r) & 7));
            break;
        case 2: { /* an interesting value, at a plausible field width */
            static const int widths[] = {1, 2, 4, 8};
            int w = widths[next(r) % 4];
            uint64_t v = interesting[next(r) % (sizeof interesting / sizeof *interesting)];
            if (next(r) & 1)
                v = size + (uint64_t)(int64_t)(below(r, 3) - 1); /* size, ±1 */
            if (off + (size_t)w <= size)
                for (int k = 0; k < w; k++)
                    buf[off + k] = (uint8_t)(v >> (8 * k));
            break;
        }
        case 3: { /* splice a chunk from somewhere else in the file */
            size_t from = below(r, size);
            size_t n = 1 + below(r, 64);
            if (n > size - off)
                n = size - off;
            if (n > size - from)
                n = size - from;
            memmove(buf + off, buf + from, n);
            break;
        }
        case 4: /* cut the file short */
            size = 1 + below(r, size);
            break;
        }
    }
    return size;
}

static double now(void)
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC)
        return 0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    unsigned long runs = 50000;
    uint64_t seed_value = 1;
    unsigned rounds = 6;
    int first = 1;

    for (; first < argc && argv[first][0] == '-'; first++) {
        const char *a = argv[first];
        if (!strcmp(a, "--runs") && first + 1 < argc)
            runs = strtoul(argv[++first], NULL, 0);
        else if (!strcmp(a, "--seed") && first + 1 < argc)
            seed_value = strtoull(argv[++first], NULL, 0);
        else if (!strcmp(a, "--mutations") && first + 1 < argc)
            rounds = (unsigned)strtoul(argv[++first], NULL, 0);
        else {
            fprintf(stderr,
                    "usage: mutate [--runs N] [--seed S] [--mutations M] FILE...\n"
                    "Mutates the given executables and parses the results.\n");
            return 64;
        }
    }
    if (first >= argc) {
        fprintf(stderr, "mutate: no seed files given\n");
        return 64;
    }

    seed *seeds = calloc((size_t)(argc - first), sizeof *seeds);
    size_t nseeds = 0, biggest = 0;
    for (int i = first; i < argc; i++) {
        if (load(argv[i], &seeds[nseeds])) {
            if (seeds[nseeds].size > biggest)
                biggest = seeds[nseeds].size;
            nseeds++;
        } else {
            fprintf(stderr, "mutate: cannot read %s\n", argv[i]);
        }
    }
    if (!nseeds) {
        fprintf(stderr, "mutate: no usable seeds\n");
        return 64;
    }

    uint8_t *work = malloc(biggest);
    rng r = {seed_value ? seed_value : 1};
    unsigned long status[4] = {0, 0, 0, 0};
    unsigned long long warnings = 0;
    double slowest = 0, started = now();
    unsigned long slowest_run = 0;
    long base = lp_live_allocations();

    printf("mutate: %lu runs over %zu seeds (largest %zu bytes), seed %llu\n", runs,
           nseeds, biggest, (unsigned long long)seed_value);

    for (unsigned long i = 0; i < runs; i++) {
        const seed *s = &seeds[below(&r, nseeds)];
        memcpy(work, s->data, s->size);
        size_t size = mutate(&r, work, s->size, 1 + (unsigned)below(&r, rounds));

        double t0 = now();
        lp_image *img = NULL;
        if (lp_image_wrap(work, size, &img) != LP_OK)
            continue;
        lp_out out;
        lp_out_null(&out);
        lp_opts opts = {LP_SHOW_ALL, false};
        lp_result res = lp_inspect(img, "mutant", &opts, &out);
        lp_image_free(img);
        double dt = now() - t0;

        status[res.status]++;
        warnings += res.warnings;
        if (dt > slowest) {
            slowest = dt;
            slowest_run = i;
        }
        if (lp_live_allocations() != base) {
            printf("LEAK after run %lu (seed %s, %zu bytes): %ld blocks\n", i, s->path,
                   size, lp_live_allocations() - base);
            return 1;
        }
    }

    double elapsed = now() - started;
    printf("\n%lu runs in %.1f s (%.0f/s)\n", runs, elapsed,
           elapsed > 0 ? (double)runs / elapsed : 0.0);
    printf("  parsed clean      %lu\n", status[LP_STATUS_OK]);
    printf("  parsed with warnings %lu (%llu warnings)\n", status[LP_STATUS_WARNINGS],
           warnings);
    printf("  rejected          %lu unsupported, %lu malformed\n",
           status[LP_STATUS_UNSUPPORTED], status[LP_STATUS_MALFORMED]);
    printf("  slowest run       %.3f s (run %lu)\n", slowest, slowest_run);
    printf("  heap              %ld live blocks, %llu allocations total\n",
           lp_live_allocations(), lp_total_allocations());

    for (size_t i = 0; i < nseeds; i++)
        free(seeds[i].data);
    free(seeds);
    free(work);
    return 0;
}
