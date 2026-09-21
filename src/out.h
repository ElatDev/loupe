/*
 * out.h - where output goes.
 *
 * An lp_out writes to a FILE, captures into memory (tests) or discards
 * (batch mode, fuzzing). Discarding still formats every line, so the
 * fuzzer exercises the printing code as well as the parsing code.
 */
#ifndef LOUPE_OUT_H
#define LOUPE_OUT_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "image.h"

#if defined(__GNUC__) || defined(__clang__)
#define LP_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
#define LP_PRINTF(fmt, args)
#endif

typedef enum lp_color {
    LP_C_RESET,
    LP_C_TITLE,   /* file name */
    LP_C_HEAD,    /* section headings */
    LP_C_LABEL,   /* field labels, table headers */
    LP_C_NAME,    /* module and symbol names */
    LP_C_MODULE,  /* DLL / library names */
    LP_C_NUM,     /* counts */
    LP_C_GOOD,
    LP_C_BAD,
    LP_C_WARN,
    LP_C_DIM,
    LP_C_COUNT_
} lp_color;

typedef struct lp_out {
    FILE  *fp;       /* NULL: discard */
    char  *buf;      /* capture buffer, NUL-terminated */
    size_t len, cap;
    bool   capture;
    bool   color;
    bool   oom;      /* capture buffer could not grow */
} lp_out;

void lp_out_file(lp_out *o, FILE *fp, bool color);
void lp_out_null(lp_out *o);
void lp_out_capture(lp_out *o);
void lp_out_free(lp_out *o);

void lp_printf(lp_out *o, const char *fmt, ...) LP_PRINTF(2, 3);
void lp_vprintf(lp_out *o, const char *fmt, va_list ap);

/* ANSI sequence for a color, or "" when color is off. */
const char *lp_c(const lp_out *o, lp_color c);

/* Printable copy of a string read from a file: bytes outside 0x20..0x7E
 * become \xNN, so a hostile name cannot smuggle terminal escape sequences.
 * Unterminated strings get a trailing marker. Returns dst. */
#define LP_ESC_MAX (LP_STR_MAX * 4 + 32)
const char *lp_esc(const lp_str *s, char *dst, size_t cap);

/* 1234567 -> "1,234,567". Returns dst. */
const char *lp_grp(uint64_t v, char *dst, size_t cap);

#endif
