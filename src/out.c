#include "out.h"

#include <string.h>

#include "mem.h"

void lp_out_file(lp_out *o, FILE *fp, bool color)
{
    memset(o, 0, sizeof *o);
    o->fp = fp;
    o->color = color;
}

void lp_out_null(lp_out *o) { memset(o, 0, sizeof *o); }

void lp_out_capture(lp_out *o)
{
    memset(o, 0, sizeof *o);
    o->capture = true;
}

void lp_out_free(lp_out *o)
{
    lp_free(o->buf);
    o->buf = NULL;
    o->len = o->cap = 0;
}

static void emit(lp_out *o, const char *s, size_t n)
{
    if (o->fp)
        fwrite(s, 1, n, o->fp);
    if (!o->capture || o->oom)
        return;
    if (o->len + n + 1 > o->cap) {
        size_t cap = o->cap ? o->cap : 4096;
        while (cap < o->len + n + 1)
            cap *= 2;
        char *grown = lp_realloc(o->buf, cap);
        if (!grown) {
            o->oom = true;
            return;
        }
        o->buf = grown;
        o->cap = cap;
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = '\0';
}

void lp_vprintf(lp_out *o, const char *fmt, va_list ap)
{
    /* Lines are short; anything longer than this is truncated, never
     * overrun. A --flat record can carry two escaped names (a module and a
     * symbol, or a section and a symbol that is itself name@version), so the
     * buffer holds three of them plus the formatting around them. */
    char line[LP_ESC_MAX * 3 + 1024];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    if (n < 0)
        return;
    size_t len = (size_t)n < sizeof line ? (size_t)n : sizeof line - 1;
    emit(o, line, len);
}

void lp_printf(lp_out *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    lp_vprintf(o, fmt, ap);
    va_end(ap);
}

const char *lp_c(const lp_out *o, lp_color c)
{
    static const char *const seq[LP_C_COUNT_] = {
        [LP_C_RESET]  = "\x1b[0m",
        [LP_C_TITLE]  = "\x1b[1;97m",
        [LP_C_HEAD]   = "\x1b[1;36m",
        [LP_C_LABEL]  = "\x1b[90m",
        [LP_C_NAME]   = "\x1b[97m",
        [LP_C_MODULE] = "\x1b[1;33m",
        [LP_C_NUM]    = "\x1b[36m",
        [LP_C_GOOD]   = "\x1b[32m",
        [LP_C_BAD]    = "\x1b[31m",
        [LP_C_WARN]   = "\x1b[1;35m",
        [LP_C_DIM]    = "\x1b[2m",
    };
    if (!o->color || (unsigned)c >= (unsigned)LP_C_COUNT_)
        return "";
    return seq[c];
}

const char *lp_esc(const lp_str *s, char *dst, size_t cap)
{
    static const char hex[] = "0123456789abcdef";
    size_t j = 0;
    if (cap == 0)
        return dst;
    for (size_t i = 0; i < s->len; i++) {
        unsigned char c = (unsigned char)s->s[i];
        if (c >= 0x20 && c < 0x7f) {
            if (j + 1 >= cap)
                break;
            dst[j++] = (char)c;
        } else {
            if (j + 4 >= cap)
                break;
            dst[j++] = '\\';
            dst[j++] = 'x';
            dst[j++] = hex[c >> 4];
            dst[j++] = hex[c & 15];
        }
    }
    const char *tail = s->truncated ? "..." : !s->terminated ? "<unterminated>" : "";
    size_t tl = strlen(tail);
    if (j + tl < cap) {
        memcpy(dst + j, tail, tl);
        j += tl;
    }
    dst[j] = '\0';
    return dst;
}

const char *lp_grp(uint64_t v, char *dst, size_t cap)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    size_t j = 0;
    for (int i = 0; i < n && j + 1 < cap; i++) {
        if (i > 0 && (n - i) % 3 == 0 && j + 2 < cap)
            dst[j++] = ',';
        dst[j++] = tmp[i];
    }
    if (cap)
        dst[j < cap ? j : cap - 1] = '\0';
    return dst;
}
