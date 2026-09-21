#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* fopen */
#endif

#include "image.h"

#include <stdio.h>
#include <string.h>

#include "mem.h"

struct lp_image {
    const uint8_t *data;
    size_t size; /* bytes actually read: the only size anything is checked against */
    bool owned;
};

const char *lp_strerror(lp_err e)
{
    switch (e) {
    case LP_OK:           return "ok";
    case LP_ERR_RANGE:    return "out of range";
    case LP_ERR_OVERFLOW: return "offset overflow";
    case LP_ERR_NOMEM:    return "out of memory";
    case LP_ERR_IO:       return "cannot read file";
    case LP_ERR_TOOBIG:   return "file too large";
    }
    return "unknown error";
}

/* ---- loading ------------------------------------------------------------ */

lp_err lp_image_load(const char *path, uint64_t max_size, lp_image **out)
{
    *out = NULL;
    if (max_size > (uint64_t)SIZE_MAX - 1)
        max_size = (uint64_t)SIZE_MAX - 1;

    FILE *f = fopen(path, "rb");
    if (!f)
        return LP_ERR_IO;

    /* The seek/tell size is only a hint for the first allocation (ftell is
     * a long, which is 32 bits on Windows). The loop below reads until EOF
     * whatever the hint says, so a file that is lying, growing or huge still
     * ends up with its real size. */
    size_t cap = 64 * 1024;
    if (fseek(f, 0, SEEK_END) == 0) {
        long end = ftell(f);
        if (end > 0 && (uint64_t)end <= max_size)
            cap = (size_t)end + 1; /* +1 so EOF is seen without a regrow */
        if (fseek(f, 0, SEEK_SET) != 0) {
            fclose(f);
            return LP_ERR_IO;
        }
    }

    uint8_t *buf = lp_malloc(cap);
    if (!buf) {
        fclose(f);
        return LP_ERR_NOMEM;
    }

    size_t len = 0;
    lp_err err = LP_OK;
    for (;;) {
        if (len == cap) {
            if ((uint64_t)cap > max_size) {
                err = LP_ERR_TOOBIG;
                break;
            }
            uint64_t want = (uint64_t)cap * 2;
            if (want > max_size + 1)
                want = max_size + 1;
            uint8_t *grown = lp_realloc(buf, (size_t)want);
            if (!grown) {
                err = LP_ERR_NOMEM;
                break;
            }
            buf = grown;
            cap = (size_t)want;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            if (ferror(f))
                err = LP_ERR_IO;
            break;
        }
    }
    fclose(f);
    if (err == LP_OK && (uint64_t)len > max_size)
        err = LP_ERR_TOOBIG;
    if (err != LP_OK) {
        lp_free(buf);
        return err;
    }

    /* Trim to the exact size. */
    if (len != cap) {
        uint8_t *exact = lp_realloc(buf, len);
        if (exact)
            buf = exact;
    }

    lp_image *img = lp_malloc(sizeof *img);
    if (!img) {
        lp_free(buf);
        return LP_ERR_NOMEM;
    }
    img->data = buf;
    img->size = len;
    img->owned = true;
    *out = img;
    return LP_OK;
}

lp_err lp_image_wrap(const void *data, size_t size, lp_image **out)
{
    /* An empty image still needs a real pointer: forming data + 0 from NULL
     * is undefined behaviour, and slices are built by adding to this. */
    static const uint8_t nothing = 0;

    *out = NULL;
    if (!data && size)
        return LP_ERR_RANGE;
    lp_image *img = lp_malloc(sizeof *img);
    if (!img)
        return LP_ERR_NOMEM;
    img->data = data ? data : &nothing;
    img->size = size;
    img->owned = false;
    *out = img;
    return LP_OK;
}

void lp_image_free(lp_image *img)
{
    if (!img)
        return;
    if (img->owned)
        lp_free((void *)img->data);
    lp_free(img);
}

uint64_t lp_image_size(const lp_image *img) { return img ? img->size : 0; }

/* ---- the accessor ------------------------------------------------------- */

lp_err lp_slice_at(const lp_image *img, uint64_t off, uint64_t len,
                   bool big_endian, lp_slice *out)
{
    out->p_ = NULL;
    out->len_ = 0;
    out->pos_ = 0;
    out->be_ = big_endian;
    out->ok_ = false;

    if (!img)
        return LP_ERR_RANGE;
    if (len > UINT64_MAX - off)
        return LP_ERR_OVERFLOW;
    /* Written so that neither comparison can wrap: off <= size is checked
     * before size - off is formed. */
    if (off > img->size || len > img->size - off)
        return LP_ERR_RANGE;

    out->p_ = img->data + (size_t)off;
    out->len_ = (size_t)len;
    out->ok_ = true;
    return LP_OK;
}

bool   lp_ok(const lp_slice *s)  { return s->ok_; }
size_t lp_len(const lp_slice *s) { return s->len_; }
size_t lp_pos(const lp_slice *s) { return s->pos_; }

/* Invariant: pos_ <= len_, so len_ - pos_ never wraps. */
static const uint8_t *take(lp_slice *s, size_t n)
{
    if (!s->ok_ || n > s->len_ - s->pos_) {
        s->ok_ = false;
        return NULL;
    }
    const uint8_t *p = s->p_ + s->pos_;
    s->pos_ += n;
    return p;
}

uint8_t lp_u8(lp_slice *s)
{
    const uint8_t *p = take(s, 1);
    return p ? p[0] : 0;
}

uint16_t lp_u16(lp_slice *s)
{
    const uint8_t *p = take(s, 2);
    if (!p)
        return 0;
    return s->be_ ? (uint16_t)((unsigned)p[0] << 8 | p[1])
                  : (uint16_t)((unsigned)p[1] << 8 | p[0]);
}

uint32_t lp_u32(lp_slice *s)
{
    const uint8_t *p = take(s, 4);
    if (!p)
        return 0;
    if (s->be_)
        return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
               (uint32_t)p[2] << 8 | (uint32_t)p[3];
    return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
           (uint32_t)p[1] << 8 | (uint32_t)p[0];
}

uint64_t lp_u64(lp_slice *s)
{
    const uint8_t *p = take(s, 8);
    if (!p)
        return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (s->be_ ? 56 - 8 * i : 8 * i);
    return v;
}

uint64_t lp_uword(lp_slice *s, bool is64)
{
    return is64 ? lp_u64(s) : lp_u32(s);
}

void lp_bytes(lp_slice *s, void *dst, size_t n)
{
    const uint8_t *p = take(s, n);
    if (p)
        memcpy(dst, p, n);
    else
        memset(dst, 0, n);
}

void lp_skip(lp_slice *s, size_t n) { (void)take(s, n); }

void lp_seek(lp_slice *s, size_t pos)
{
    if (!s->ok_ || pos > s->len_)
        s->ok_ = false;
    else
        s->pos_ = pos;
}

/* ---- one-shot helpers --------------------------------------------------- */

lp_err lp_read_u16(const lp_image *img, uint64_t off, bool be, uint16_t *v)
{
    lp_slice s;
    lp_err e = lp_slice_at(img, off, 2, be, &s);
    *v = lp_u16(&s);
    return e;
}

lp_err lp_read_u32(const lp_image *img, uint64_t off, bool be, uint32_t *v)
{
    lp_slice s;
    lp_err e = lp_slice_at(img, off, 4, be, &s);
    *v = lp_u32(&s);
    return e;
}

lp_err lp_read_u64(const lp_image *img, uint64_t off, bool be, uint64_t *v)
{
    lp_slice s;
    lp_err e = lp_slice_at(img, off, 8, be, &s);
    *v = lp_u64(&s);
    return e;
}

/* ---- strings ------------------------------------------------------------ */

lp_err lp_read_str(const lp_image *img, uint64_t off, uint64_t limit,
                   lp_str *out)
{
    out->s[0] = '\0';
    out->len = 0;
    out->terminated = false;
    out->truncated = false;

    uint64_t size = lp_image_size(img);
    if (off >= size)
        return LP_ERR_RANGE;
    if (limit > size - off)
        limit = size - off;
    /* Scan one byte past LP_STR_MAX so an exactly-full string can still
     * find its terminator. */
    uint64_t scan = limit < LP_STR_MAX + 1 ? limit : LP_STR_MAX + 1;

    lp_slice s;
    lp_err e = lp_slice_at(img, off, scan, false, &s);
    if (e != LP_OK)
        return e;
    for (uint64_t i = 0; i < scan; i++) {
        uint8_t c = lp_u8(&s);
        if (c == 0) {
            out->terminated = true;
            break;
        }
        if (out->len == LP_STR_MAX) {
            out->truncated = true;
            break;
        }
        out->s[out->len++] = (char)c;
    }
    out->s[out->len] = '\0';
    return LP_OK;
}
