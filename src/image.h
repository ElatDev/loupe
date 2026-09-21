/*
 * image.h - the bounds-checked access layer.
 *
 * Every byte Loupe reads from an input file comes through lp_slice_at().
 *
 * lp_image is opaque: no code outside image.c can see the buffer pointer, so
 * the PE and ELF parsers cannot index the file directly even by accident.
 * They ask for a slice (an offset and a length, validated against the number
 * of bytes actually read from disk, never against anything the file claims)
 * and decode it with the lp_u8/u16/u32/u64 readers, which check each read
 * against the slice's own length.
 *
 * Failure is sticky and harmless. A slice that failed to open, or that a
 * reader tried to overrun, is poisoned: further reads return 0 and touch
 * nothing. A caller that forgets to check an error still cannot read out of
 * bounds, it just gets zeros and a false lp_ok().
 */
#ifndef LOUPE_IMAGE_H
#define LOUPE_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum lp_err {
    LP_OK = 0,
    LP_ERR_RANGE,    /* offset or length falls outside the file */
    LP_ERR_OVERFLOW, /* offset + length does not fit in 64 bits */
    LP_ERR_NOMEM,
    LP_ERR_IO,
    LP_ERR_TOOBIG    /* file is larger than the configured limit */
} lp_err;

const char *lp_strerror(lp_err e);

typedef struct lp_image lp_image;

/* Read a whole file into memory. The buffer is trimmed to the exact byte
 * count, so under AddressSanitizer an off-by-one read lands in a redzone
 * instead of in spare capacity. */
lp_err lp_image_load(const char *path, uint64_t max_size, lp_image **out);

/* Wrap memory the caller owns (tests, fuzzing). Nothing is copied; the data
 * must outlive the image. */
lp_err lp_image_wrap(const void *data, size_t size, lp_image **out);

void     lp_image_free(lp_image *img);
uint64_t lp_image_size(const lp_image *img);

/* A validated window onto the image. The fields are private to image.c. */
typedef struct lp_slice {
    const uint8_t *p_;
    size_t len_;
    size_t pos_;
    bool be_; /* big-endian reads */
    bool ok_;
} lp_slice;

/* The one accessor. Opens [off, off + len) or returns an error and a
 * poisoned slice. Overflow-safe for any 64-bit inputs. */
lp_err lp_slice_at(const lp_image *img, uint64_t off, uint64_t len,
                   bool big_endian, lp_slice *out);

bool   lp_ok(const lp_slice *s);
size_t lp_len(const lp_slice *s);
size_t lp_pos(const lp_slice *s);

/* Sequential readers. Each advances the cursor, or poisons the slice and
 * returns 0 if the value would run past the end of the slice. */
uint8_t  lp_u8(lp_slice *s);
uint16_t lp_u16(lp_slice *s);
uint32_t lp_u32(lp_slice *s);
uint64_t lp_u64(lp_slice *s);
uint64_t lp_uword(lp_slice *s, bool is64); /* 4 or 8 bytes, widened */
void     lp_bytes(lp_slice *s, void *dst, size_t n);
void     lp_skip(lp_slice *s, size_t n);
void     lp_seek(lp_slice *s, size_t pos);

/* One-shot reads of a single value at a file offset. */
lp_err lp_read_u16(const lp_image *img, uint64_t off, bool be, uint16_t *v);
lp_err lp_read_u32(const lp_image *img, uint64_t off, bool be, uint32_t *v);
lp_err lp_read_u64(const lp_image *img, uint64_t off, bool be, uint64_t *v);

/*
 * Strings. Nothing in a file is trusted to be NUL-terminated: lp_read_str
 * scans at most `limit` bytes (clamped to the end of the file) and copies
 * what it finds into a local buffer that is always terminated.
 */
#define LP_STR_MAX 1024

typedef struct lp_str {
    char   s[LP_STR_MAX + 1]; /* NUL-terminated copy, no embedded NULs */
    size_t len;
    bool   terminated; /* a NUL was found inside the limit */
    bool   truncated;  /* stopped at LP_STR_MAX before finding a NUL */
} lp_str;

/* LP_ERR_RANGE if off is at or past the end of the file. Otherwise LP_OK;
 * check out->terminated. !terminated && !truncated means the string ran
 * into the limit or EOF without a terminator. */
lp_err lp_read_str(const lp_image *img, uint64_t off, uint64_t limit,
                   lp_str *out);

#endif
