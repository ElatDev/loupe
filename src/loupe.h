/*
 * loupe.h - the public entry point and the per-file context shared by the
 * PE and ELF parsers.
 */
#ifndef LOUPE_H
#define LOUPE_H

#include <stdbool.h>
#include <stdint.h>

#include "image.h"
#include "out.h"

#define LOUPE_VERSION "0.1.0"

/* What to print. */
enum {
    LP_SHOW_HEADERS     = 1u << 0,
    LP_SHOW_MITIGATIONS = 1u << 1,
    LP_SHOW_SECTIONS    = 1u << 2,
    LP_SHOW_SEGMENTS    = 1u << 3, /* ELF program headers */
    LP_SHOW_DIRECTORIES = 1u << 4, /* PE data directories */
    LP_SHOW_IMPORTS     = 1u << 5,
    LP_SHOW_EXPORTS     = 1u << 6,
    LP_SHOW_DYNAMIC     = 1u << 7, /* ELF dynamic section */
    LP_SHOW_SYMBOLS     = 1u << 8, /* ELF symbol tables */
    LP_SHOW_DEBUG       = 1u << 9  /* PE debug directory and TLS, ELF notes */
};
#define LP_SHOW_DEFAULT                                                     \
    (LP_SHOW_HEADERS | LP_SHOW_MITIGATIONS | LP_SHOW_SECTIONS |             \
     LP_SHOW_SEGMENTS | LP_SHOW_IMPORTS | LP_SHOW_EXPORTS)
#define LP_SHOW_ALL 0x3ffu

/*
 * Limits. Every count read from a file is clamped to one of these AND to
 * what the file could physically hold, so no field can make a loop run
 * longer than the input justifies.
 */
#define LP_MAX_FILE_SIZE          (4ull << 30)
#define LP_MAX_IMPORT_MODULES     4096u
#define LP_MAX_IMPORTS_PER_MODULE 65536u
#define LP_MAX_EXPORTS            (1u << 20)
#define LP_MAX_ELF_SECTIONS       (1u << 20)
#define LP_MAX_ELF_SEGMENTS       65536u
#define LP_MAX_SYMBOLS            (1u << 22)
#define LP_MAX_DYNAMIC            65536u
#define LP_MAX_WARNINGS_SHOWN     50u
/* Past this many anomalies the file has nothing left to tell us, and
 * formatting more of them is just work an attacker asked for. */
#define LP_MAX_WARNINGS           5000u

/*
 * Work budget per file, in loop iterations. The per-loop caps above bound
 * each loop; the budget bounds their product (nested lookups such as
 * RVA-to-offset over thousands of sections, or a version lookup per symbol).
 *
 * Measured, not guessed: cut this to a quarter and every one of the 8,825
 * real binaries in the System32, SysWOW64 and Android NDK sweeps still parses
 * completely; cut it to an eighth and one of them runs out. The ceiling is
 * for files built to be expensive, and a file that reaches it gets a warning
 * saying the output is incomplete rather than minutes of CPU time.
 */
#define LP_WORK_BUDGET (1ull << 23)

typedef struct lp_opts {
    unsigned what; /* LP_SHOW_* */
    bool flat;     /* one tab-separated record per line */
} lp_opts;

typedef enum lp_format {
    LP_FORMAT_UNKNOWN,
    LP_FORMAT_PE,
    LP_FORMAT_ELF
} lp_format;

typedef enum lp_status {
    LP_STATUS_OK,          /* parsed, nothing suspicious */
    LP_STATUS_WARNINGS,    /* parsed, but the file contradicts itself */
    LP_STATUS_UNSUPPORTED, /* not a PE or ELF image */
    LP_STATUS_MALFORMED    /* recognised, but the headers are unusable */
} lp_status;

#define LP_WARNING_TEXT 200

typedef struct lp_result {
    lp_format     format;
    lp_status     status;
    unsigned long warnings;
    char          message[LP_WARNING_TEXT]; /* why it was rejected, else the
                                               first warning */
} lp_result;

/* Inspect one image. `name` is only used for the title line. */
lp_result lp_inspect(const lp_image *img, const char *name,
                     const lp_opts *opts, lp_out *out);

/* ---- internal: shared by pe.c and elf.c --------------------------------- */

typedef struct lp_ctx {
    const lp_image *img;
    uint64_t        size;
    lp_out         *out;
    const lp_opts  *opts;
    unsigned long   warnings;
    uint64_t        budget;
    bool            exhausted;
    int             mute; /* >0 while a counting pre-pass re-walks a table */
    char            first_warning[LP_WARNING_TEXT];
    char            reject[LP_WARNING_TEXT];
} lp_ctx;

/* Record an anomaly. Printed inline (up to LP_MAX_WARNINGS_SHOWN), always
 * counted, except while muted: a table walked twice warns once. */
void lp_warn(lp_ctx *c, const char *fmt, ...) LP_PRINTF(2, 3);

/* Explain why a file cannot be parsed at all (not PE/ELF, or headers too
 * broken to continue). Printed as a line of output and kept for --batch. */
void lp_reject(lp_ctx *c, const char *fmt, ...) LP_PRINTF(2, 3);

/* Spend `cost` units of the work budget. Returns false once it is gone;
 * every loop checks it. */
bool lp_tick(lp_ctx *c, uint64_t cost);

/* Section heading, e.g. "IMPORTS  3 modules, 41 functions". */
void lp_heading(lp_ctx *c, const char *title, const char *fmt, ...)
    LP_PRINTF(3, 4);

/* "  label            value" */
void lp_field(lp_ctx *c, const char *label, const char *fmt, ...)
    LP_PRINTF(3, 4);

/* Print the names of the bits set in `v`, then any unknown bits in hex. */
typedef struct lp_flag {
    uint64_t    bit;
    const char *name;
} lp_flag;
void lp_flags(lp_ctx *c, uint64_t v, const lp_flag *table, size_t n,
              const char *sep);

#define LP_COUNT(a) (sizeof(a) / sizeof((a)[0]))

lp_status lp_pe_inspect(lp_ctx *c);
lp_status lp_elf_inspect(lp_ctx *c);

#endif
