/*
 * main.c - command line.
 *
 *   loupe [options] FILE...        inspect files
 *   loupe --batch < paths.txt      sweep many files, report anything unusual
 */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* getenv */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loupe.h"
#include "mem.h"
#include "term.h"

enum {
    EXIT_CLEAN = 0,
    EXIT_WARNINGS = 1,
    EXIT_REJECTED = 2,
    EXIT_IO = 3,
    EXIT_USAGE = 64
};

static const char usage[] =
    "usage: loupe [options] FILE...\n"
    "       loupe --batch [-v] < list-of-paths\n"
    "\n"
    "Prints the structure of PE (Windows) and ELF (Unix) executables: headers,\n"
    "sections, imports, exports and security mitigations. Loupe only reads;\n"
    "it never modifies, patches or runs anything.\n"
    "\n"
    "What to show (default -HmSlie):\n"
    "  -H, --headers       file header\n"
    "  -m, --mitigations   ASLR, DEP, CFG, CET (PE); PIE, NX, RELRO, canary (ELF)\n"
    "  -S, --sections      section table\n"
    "  -l, --segments      program headers (ELF)\n"
    "  -d, --directories   data directories (PE)\n"
    "  -i, --imports       imported modules and functions\n"
    "  -e, --exports       exported functions and symbols\n"
    "  -D, --dynamic       dynamic section (ELF)\n"
    "  -s, --symbols       symbol tables (ELF)\n"
    "  -g, --debug         debug directory and TLS callbacks (PE), notes (ELF)\n"
    "  -a, --all           everything above\n"
    "\n"
    "Output:\n"
    "      --flat          one tab-separated record per line, for grep and diff\n"
    "      --color=WHEN    auto (default), always or never\n"
    "  -q, --quiet         print nothing; report through the exit status\n"
    "\n"
    "Batch:\n"
    "      --batch         read paths from stdin, parse each one fully and\n"
    "                      silently, list the files that are not clean, then\n"
    "                      print a summary\n"
    "  -v, --verbose       with --batch, list every file\n"
    "\n"
    "  -h, --help          this text\n"
    "  -V, --version       version\n"
    "\n"
    "Exit status: 0 clean, 1 parsed with warnings, 2 not PE/ELF or malformed,\n"
    "3 unreadable, 64 usage error. With --batch the counts are in the summary\n"
    "and the status is 0 unless a leak was found.\n";

typedef struct cli {
    lp_opts opts;
    bool    any_what;
    int     color; /* -1 auto, 0 never, 1 always */
    bool    quiet, batch, verbose;
} cli;

static int status_exit(lp_status s)
{
    switch (s) {
    case LP_STATUS_OK:          return EXIT_CLEAN;
    case LP_STATUS_WARNINGS:    return EXIT_WARNINGS;
    case LP_STATUS_UNSUPPORTED:
    case LP_STATUS_MALFORMED:   return EXIT_REJECTED;
    }
    return EXIT_REJECTED;
}

static bool short_flag(cli *c, char f)
{
    unsigned bit = 0;
    switch (f) {
    case 'H': bit = LP_SHOW_HEADERS; break;
    case 'm': bit = LP_SHOW_MITIGATIONS; break;
    case 'S': bit = LP_SHOW_SECTIONS; break;
    case 'l': bit = LP_SHOW_SEGMENTS; break;
    case 'd': bit = LP_SHOW_DIRECTORIES; break;
    case 'i': bit = LP_SHOW_IMPORTS; break;
    case 'e': bit = LP_SHOW_EXPORTS; break;
    case 'D': bit = LP_SHOW_DYNAMIC; break;
    case 's': bit = LP_SHOW_SYMBOLS; break;
    case 'g': bit = LP_SHOW_DEBUG; break;
    case 'a': bit = LP_SHOW_ALL; break;
    case 'q': c->quiet = true; return true;
    case 'v': c->verbose = true; return true;
    default:  return false;
    }
    c->opts.what |= bit;
    c->any_what = true;
    return true;
}

static const struct {
    const char *name;
    char        flag;
} long_flags[] = {
    {"headers", 'H'},  {"mitigations", 'm'}, {"sections", 'S'}, {"segments", 'l'},
    {"directories", 'd'}, {"imports", 'i'},  {"exports", 'e'},  {"dynamic", 'D'},
    {"symbols", 's'},  {"debug", 'g'},       {"all", 'a'},      {"quiet", 'q'},
    {"verbose", 'v'},
};

/* Returns the index of the first operand, or -1 after printing an error. */
static int parse_args(cli *c, int argc, char **argv, bool *done, int *code)
{
    int i;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-' || a[1] == '\0')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (a[1] == '-') {
            const char *name = a + 2;
            bool matched = false;
            for (size_t k = 0; k < LP_COUNT(long_flags); k++) {
                if (!strcmp(name, long_flags[k].name)) {
                    short_flag(c, long_flags[k].flag);
                    matched = true;
                }
            }
            if (matched)
                continue;
            if (!strcmp(name, "flat")) {
                c->opts.flat = true;
            } else if (!strcmp(name, "batch")) {
                c->batch = true;
            } else if (!strcmp(name, "color") || !strcmp(name, "color=always")) {
                c->color = 1;
            } else if (!strcmp(name, "color=never")) {
                c->color = 0;
            } else if (!strcmp(name, "color=auto")) {
                c->color = -1;
            } else if (!strcmp(name, "help")) {
                fputs(usage, stdout);
                *done = true;
                *code = EXIT_CLEAN;
                return i;
            } else if (!strcmp(name, "version")) {
                printf("loupe %s\n", LOUPE_VERSION);
                *done = true;
                *code = EXIT_CLEAN;
                return i;
            } else {
                fprintf(stderr, "loupe: unknown option '%s' (try --help)\n", a);
                return -1;
            }
            continue;
        }
        for (const char *f = a + 1; *f; f++) {
            if (*f == 'h') {
                fputs(usage, stdout);
                *done = true;
                *code = EXIT_CLEAN;
                return i;
            }
            if (*f == 'V') {
                printf("loupe %s\n", LOUPE_VERSION);
                *done = true;
                *code = EXIT_CLEAN;
                return i;
            }
            if (!short_flag(c, *f)) {
                fprintf(stderr, "loupe: unknown option '-%c' (try --help)\n", *f);
                return -1;
            }
        }
    }
    return i;
}

static double now_seconds(void)
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC)
        return 0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void human_bytes(unsigned long long b, char *buf, size_t n)
{
    if (b >= 1ull << 30)
        snprintf(buf, n, "%.2f GiB", (double)b / (double)(1ull << 30));
    else if (b >= 1ull << 20)
        snprintf(buf, n, "%.1f MiB", (double)b / (double)(1ull << 20));
    else
        snprintf(buf, n, "%llu bytes", b);
}

/*
 * Batch mode: every file gets the full parse (all sections, output
 * discarded) in one process, and the live allocation count must return to
 * its starting value after each one.
 */
static int run_batch(const cli *c)
{
    unsigned long long files = 0, pe = 0, elf = 0, clean = 0, warned = 0,
                       unsupported = 0, malformed = 0, unreadable = 0,
                       leaks = 0, bytes = 0, warnings = 0;
    char line[8192], g[32];
    long base = lp_live_allocations();
    double t0 = now_seconds();
    lp_opts opts = {LP_SHOW_ALL, false};

    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        bool whole = n && line[n - 1] == '\n';
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (!whole && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != EOF && ch != '\n')
                ;
            printf("error    %s...  (path too long)\n", line);
            files++;
            unreadable++;
            continue;
        }
        if (!n)
            continue;
        files++;

        lp_image *img;
        lp_err err = lp_image_load(line, LP_MAX_FILE_SIZE, &img);
        if (err != LP_OK) {
            printf("error    %s  (%s)\n", line, lp_strerror(err));
            unreadable++;
            continue;
        }
        bytes += lp_image_size(img);

        lp_out out;
        lp_out_null(&out);
        lp_result r = lp_inspect(img, line, &opts, &out);
        lp_image_free(img);

        long live = lp_live_allocations();
        if (live != base) {
            printf("LEAK     %s  (%ld blocks)\n", line, live - base);
            leaks++;
            base = live;
        }

        if (r.format == LP_FORMAT_PE)
            pe++;
        else if (r.format == LP_FORMAT_ELF)
            elf++;
        warnings += r.warnings;
        switch (r.status) {
        case LP_STATUS_OK:
            clean++;
            if (c->verbose)
                printf("ok       %s\n", line);
            break;
        case LP_STATUS_WARNINGS:
            warned++;
            printf("warn     %s  (%lu: %s)\n", line, r.warnings, r.message);
            break;
        case LP_STATUS_UNSUPPORTED:
            unsupported++;
            if (c->verbose || r.format != LP_FORMAT_UNKNOWN)
                printf("skip     %s  (%s)\n", line, r.message);
            break;
        case LP_STATUS_MALFORMED:
            malformed++;
            printf("bad      %s  (%s)\n", line, r.message);
            break;
        }
        fflush(stdout);
    }

    double dt = now_seconds() - t0;
    char hb[32];
    human_bytes(bytes, hb, sizeof hb);
    printf("\n");
    printf("files          %s\n", lp_grp(files, g, sizeof g));
    printf("  PE           %s\n", lp_grp(pe, g, sizeof g));
    printf("  ELF          %s\n", lp_grp(elf, g, sizeof g));
    printf("clean          %s\n", lp_grp(clean, g, sizeof g));
    printf("warnings       %s files", lp_grp(warned, g, sizeof g));
    printf(" (%s warnings)\n", lp_grp(warnings, g, sizeof g));
    printf("malformed      %s\n", lp_grp(malformed, g, sizeof g));
    printf("not PE/ELF     %s\n", lp_grp(unsupported, g, sizeof g));
    printf("unreadable     %s\n", lp_grp(unreadable, g, sizeof g));
    printf("bytes parsed   %s\n", hb);
    printf("time           %.2f s (%.0f files/s)\n", dt, dt > 0 ? (double)files / dt : 0.0);
    printf("heap           %ld live blocks at exit, %s allocations total, ",
           lp_live_allocations(), lp_grp(lp_total_allocations(), g, sizeof g));
    if (leaks)
        printf("LEAKS: %llu files\n", leaks);
    else
        printf("no leaks\n");
    /* Unreadable files are the directory's problem, not the parser's, so
     * only a leak makes the sweep itself fail. */
    return leaks ? EXIT_IO : EXIT_CLEAN;
}

int main(int argc, char **argv)
{
    cli c;
    memset(&c, 0, sizeof c);
    c.color = -1;
    bool done = false;
    int code = EXIT_CLEAN;

    int first = parse_args(&c, argc, argv, &done, &code);
    if (done)
        return code;
    if (first < 0)
        return EXIT_USAGE;
    if (!c.any_what)
        c.opts.what = LP_SHOW_DEFAULT;

    if (c.batch) {
        if (first < argc) {
            fprintf(stderr, "loupe: --batch reads paths from stdin, not arguments\n");
            return EXIT_USAGE;
        }
        return run_batch(&c);
    }
    if (first >= argc) {
        fputs(usage, stderr);
        return EXIT_USAGE;
    }

    bool color = c.color == 1 || (c.color == -1 && !c.opts.flat && lp_term_color(stdout));
    int worst = EXIT_CLEAN;
    for (int i = first; i < argc; i++) {
        lp_image *img;
        lp_err err = lp_image_load(argv[i], LP_MAX_FILE_SIZE, &img);
        if (err != LP_OK) {
            fprintf(stderr, "loupe: %s: %s\n", argv[i], lp_strerror(err));
            if (worst < EXIT_IO)
                worst = EXIT_IO;
            continue;
        }
        lp_out out;
        if (c.quiet)
            lp_out_null(&out);
        else
            lp_out_file(&out, stdout, color);
        if (i > first && !c.quiet && !c.opts.flat)
            lp_printf(&out, "\n");
        lp_result r = lp_inspect(img, argv[i], &c.opts, &out);
        lp_image_free(img);
        int e = status_exit(r.status);
        if (e > worst && worst != EXIT_IO)
            worst = e;
    }
    fflush(stdout);
    return worst;
}
