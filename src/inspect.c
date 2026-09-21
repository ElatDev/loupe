#include "loupe.h"

#include <stdio.h>
#include <string.h>

void lp_warn(lp_ctx *c, const char *fmt, ...)
{
    if (c->mute)
        return;
    c->warnings++;

    if (c->warnings > LP_MAX_WARNINGS_SHOWN) {
        /* Not even formatted: a file that contradicts itself thousands of
         * times must not be able to spend our time on messages. */
        if (c->warnings == LP_MAX_WARNINGS_SHOWN + 1 && !c->opts->flat)
            lp_printf(c->out, "  %s! further warnings suppressed%s\n",
                      lp_c(c->out, LP_C_WARN), lp_c(c->out, LP_C_RESET));
        if (c->warnings >= LP_MAX_WARNINGS) {
            c->exhausted = true; /* stop every loop */
            c->budget = 0;
        }
        return;
    }

    char msg[LP_WARNING_TEXT];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    if (c->warnings == 1)
        memcpy(c->first_warning, msg, sizeof msg);

    if (c->opts->flat)
        lp_printf(c->out, "warning\t%s\n", msg);
    else
        lp_printf(c->out, "  %s! %s%s\n", lp_c(c->out, LP_C_WARN), msg,
                  lp_c(c->out, LP_C_RESET));
}

void lp_reject(lp_ctx *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->reject, sizeof c->reject, fmt, ap);
    va_end(ap);
    if (!c->opts->flat)
        lp_printf(c->out, "%s\n", c->reject);
}

bool lp_tick(lp_ctx *c, uint64_t cost)
{
    if (c->exhausted)
        return false;
    if (cost > c->budget) {
        c->budget = 0;
        c->exhausted = true;
        int mute = c->mute; /* this one must be seen even mid pre-pass */
        c->mute = 0;
        lp_warn(c, "work limit reached; output is incomplete");
        c->mute = mute;
        return false;
    }
    c->budget -= cost;
    return true;
}

void lp_heading(lp_ctx *c, const char *title, const char *fmt, ...)
{
    if (c->opts->flat)
        return;
    lp_printf(c->out, "\n%s%s%s", lp_c(c->out, LP_C_HEAD), title,
              lp_c(c->out, LP_C_RESET));
    if (fmt && *fmt) {
        char detail[256];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof detail, fmt, ap);
        va_end(ap);
        lp_printf(c->out, "  %s%s%s", lp_c(c->out, LP_C_LABEL), detail,
                  lp_c(c->out, LP_C_RESET));
    }
    lp_printf(c->out, "\n");
}

void lp_field(lp_ctx *c, const char *label, const char *fmt, ...)
{
    if (c->opts->flat)
        return;
    char value[LP_ESC_MAX + 256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(value, sizeof value, fmt, ap);
    va_end(ap);
    lp_printf(c->out, "  %s%-19s%s %s\n", lp_c(c->out, LP_C_LABEL), label,
              lp_c(c->out, LP_C_RESET), value);
}

void lp_flags(lp_ctx *c, uint64_t v, const lp_flag *table, size_t n,
              const char *sep)
{
    uint64_t known = 0;
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        known |= table[i].bit;
        if (v & table[i].bit) {
            lp_printf(c->out, "%s%s", first ? "" : sep, table[i].name);
            first = false;
        }
    }
    if (v & ~known)
        lp_printf(c->out, "%s0x%llx", first ? "" : sep,
                  (unsigned long long)(v & ~known));
}

static lp_format detect(const lp_image *img)
{
    lp_slice s;
    uint8_t magic[4] = {0};
    if (lp_slice_at(img, 0, 4, false, &s) == LP_OK)
        lp_bytes(&s, magic, 4);
    else if (lp_slice_at(img, 0, 2, false, &s) == LP_OK)
        lp_bytes(&s, magic, 2);

    if (magic[0] == 'M' && magic[1] == 'Z')
        return LP_FORMAT_PE;
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return LP_FORMAT_ELF;
    return LP_FORMAT_UNKNOWN;
}

lp_result lp_inspect(const lp_image *img, const char *name,
                     const lp_opts *opts, lp_out *out)
{
    lp_result r;
    memset(&r, 0, sizeof r);

    lp_ctx c;
    memset(&c, 0, sizeof c);
    c.img = img;
    c.size = lp_image_size(img);
    c.out = out;
    c.opts = opts;
    c.budget = LP_WORK_BUDGET;

    r.format = detect(img);
    if (!opts->flat)
        lp_printf(out, "%s%s%s\n", lp_c(out, LP_C_TITLE), name ? name : "",
                  lp_c(out, LP_C_RESET));

    switch (r.format) {
    case LP_FORMAT_PE:
        r.status = lp_pe_inspect(&c);
        break;
    case LP_FORMAT_ELF:
        r.status = lp_elf_inspect(&c);
        break;
    default:
        lp_reject(&c, "not a PE or ELF file (%llu bytes)", (unsigned long long)c.size);
        r.status = LP_STATUS_UNSUPPORTED;
        break;
    }

    if (r.status == LP_STATUS_OK && c.warnings)
        r.status = LP_STATUS_WARNINGS;
    r.warnings = c.warnings;
    memcpy(r.message, c.reject[0] ? c.reject : c.first_warning, sizeof r.message);
    return r;
}
