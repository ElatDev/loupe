/*
 * pe.c - Portable Executable (PE32 and PE32+) images.
 *
 *   0x00       DOS header, "MZ"; e_lfanew at 0x3C points to the NT headers
 *   e_lfanew   "PE\0\0", COFF file header (20 bytes), optional header,
 *              section table (40 bytes per section)
 *
 * Imports, exports, debug data and the rest are found through the data
 * directories, which hold RVAs (addresses relative to the loaded image), not
 * file offsets. pe_rva() maps them back through the section table, and
 * nearly everything below depends on it being right.
 */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* gmtime */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "loupe.h"
#include "mem.h"

#define PE_SIGNATURE 0x00004550u /* "PE\0\0" */
#define OPT_PE32     0x10b
#define OPT_PE32PLUS 0x20b
#define OPT_ROM      0x107

#define COFF_HEADER_SIZE    20
#define SECTION_HEADER_SIZE 40
#define OPT_STD_PE32        96  /* optional header up to the data directories */
#define OPT_STD_PE32PLUS    112

enum {
    DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY,
    DIR_BASERELOC, DIR_DEBUG, DIR_ARCHITECTURE, DIR_GLOBALPTR, DIR_TLS,
    DIR_LOADCONFIG, DIR_BOUNDIMPORT, DIR_IAT, DIR_DELAYIMPORT, DIR_CLR,
    DIR_RESERVED, DIR_COUNT
};

static const char *const dir_names[DIR_COUNT] = {
    "export", "import", "resource", "exception", "certificate",
    "base reloc", "debug", "architecture", "global ptr", "tls",
    "load config", "bound import", "iat", "delay import", "clr runtime",
    "reserved",
};

/* COFF characteristics */
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_DLL             0x2000

/* DllCharacteristics */
#define DLLC_HIGH_ENTROPY_VA 0x0020
#define DLLC_DYNAMIC_BASE    0x0040
#define DLLC_FORCE_INTEGRITY 0x0080
#define DLLC_NX_COMPAT       0x0100
#define DLLC_NO_SEH          0x0400
#define DLLC_APPCONTAINER    0x1000
#define DLLC_GUARD_CF        0x4000

/* Section characteristics */
#define SCN_CNT_CODE      0x00000020u
#define SCN_CNT_IDATA     0x00000040u
#define SCN_CNT_UDATA     0x00000080u
#define SCN_DISCARDABLE   0x02000000u
#define SCN_SHARED        0x10000000u
#define SCN_EXECUTE       0x20000000u
#define SCN_READ          0x40000000u
#define SCN_WRITE         0x80000000u

/* Debug directory types */
#define DEBUG_CODEVIEW  2
#define DEBUG_REPRO     16
#define DEBUG_EX_DLLCHARACTERISTICS 20
#define EX_DLLC_CET_COMPAT 0x01

#define MAX_DEBUG_ENTRIES 32
#define MAX_TLS_CALLBACKS 64

typedef struct pe_sec {
    uint8_t  name[8];
    uint32_t vsize, vaddr, raw_size, raw_ptr;
    uint32_t reloc_ptr, lineno_ptr;
    uint16_t nreloc, nlineno;
    uint32_t chars;
} pe_sec;

typedef struct pe_dir {
    uint32_t rva, size;
} pe_dir;

typedef struct pe_debug {
    uint32_t type, size, rva, ptr;
} pe_debug;

typedef struct pe {
    lp_ctx         *c;
    const lp_image *img;
    uint64_t        size;
    uint32_t        nt_off; /* offset of "PE\0\0" */

    /* COFF file header */
    uint16_t machine, nsec_hdr, opt_size, chars;
    uint32_t timestamp, symtab_ptr, nsyms;

    /* optional header */
    uint16_t magic;
    bool     is64;
    uint8_t  link_major, link_minor;
    uint32_t size_code, size_idata, size_udata, entry, base_code, base_data;
    uint64_t image_base;
    uint32_t sect_align, file_align;
    uint16_t os_major, os_minor, img_major, img_minor, sub_major, sub_minor;
    uint32_t win32_ver, size_image, size_headers, checksum;
    uint64_t checksum_off;
    uint16_t subsystem, dll_chars;
    uint64_t stack_res, stack_com, heap_res, heap_com;
    uint32_t loader_flags, nrva;
    uint32_t ndirs;
    pe_dir   dirs[DIR_COUNT];

    /* sections that are actually present in the file */
    pe_sec  *secs;
    uint32_t nsecs;
    uint32_t hit; /* last section pe_rva() matched */

    /* facts gathered for the header and mitigation summaries */
    pe_debug debug[MAX_DEBUG_ENTRIES];
    uint32_t ndebug;
    bool     repro, cet_compat, have_pdb;
    lp_str   pdb;
    uint8_t  pdb_guid[16];
    uint32_t pdb_age;
    uint32_t tls_callbacks[MAX_TLS_CALLBACKS]; /* stored as RVAs */
    uint32_t ntls;
    bool     tls_more;
    bool     have_loadcfg, safeseh;
    uint32_t seh_count;
    bool     have_clr;
    uint16_t clr_major, clr_minor;
    uint32_t clr_flags;
    bool     have_cert;
    uint32_t cert_size;
} pe;

/* ---- names for numbers -------------------------------------------------- */

static const char *machine_name(uint16_t m)
{
    switch (m) {
    case 0x0000: return "unknown";
    case 0x014c: return "i386";
    case 0x8664: return "x86-64";
    case 0xaa64: return "ARM64";
    case 0xa641: return "ARM64EC";
    case 0xa64e: return "ARM64X";
    case 0x01c0: return "ARM";
    case 0x01c2: return "ARM Thumb";
    case 0x01c4: return "ARMv7 Thumb-2";
    case 0x0200: return "IA-64";
    case 0x0166: return "MIPS R4000";
    case 0x0169: return "MIPS WCE v2";
    case 0x0266: return "MIPS16";
    case 0x0366: return "MIPS FPU";
    case 0x01f0: return "PowerPC";
    case 0x01f1: return "PowerPC FP";
    case 0x01a2: return "SH3";
    case 0x01a6: return "SH4";
    case 0x01a8: return "SH5";
    case 0x0184: return "Alpha";
    case 0x0284: return "Alpha 64";
    case 0x0ebc: return "EFI byte code";
    case 0x5032: return "RISC-V 32";
    case 0x5064: return "RISC-V 64";
    case 0x5128: return "RISC-V 128";
    case 0x6232: return "LoongArch 32";
    case 0x6264: return "LoongArch 64";
    case 0x9041: return "M32R";
    }
    return "unrecognised";
}

static const char *subsystem_name(uint16_t s)
{
    switch (s) {
    case 0:  return "unknown";
    case 1:  return "native";
    case 2:  return "Windows GUI";
    case 3:  return "Windows console";
    case 5:  return "OS/2 console";
    case 7:  return "POSIX console";
    case 8:  return "native Win9x driver";
    case 9:  return "Windows CE GUI";
    case 10: return "EFI application";
    case 11: return "EFI boot service driver";
    case 12: return "EFI runtime driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows boot application";
    }
    return "unrecognised";
}

static const char *debug_type_name(uint32_t t)
{
    static const char *const names[] = {
        "unknown", "coff", "codeview", "fpo", "misc", "exception", "fixup",
        "omap-to-src", "omap-from-src", "borland", "reserved10", "clsid",
        "vc-feature", "pogo", "iltcg", "mpx", "repro", "embedded-pdb",
        "spgo", "pdb-checksum", "ex-dllcharacteristics",
    };
    return t < LP_COUNT(names) ? names[t] : "unrecognised";
}

static const lp_flag coff_flags[] = {
    {0x0001, "relocs-stripped"},
    {0x0002, "executable"},
    {0x0004, "line-nums-stripped"},
    {0x0008, "local-syms-stripped"},
    {0x0010, "aggressive-ws-trim"},
    {0x0020, "large-address-aware"},
    {0x0080, "bytes-reversed-lo"},
    {0x0100, "32-bit"},
    {0x0200, "debug-stripped"},
    {0x0400, "removable-run-from-swap"},
    {0x0800, "net-run-from-swap"},
    {0x1000, "system"},
    {0x2000, "dll"},
    {0x4000, "up-system-only"},
    {0x8000, "bytes-reversed-hi"},
};

static const lp_flag dllc_flags[] = {
    {0x0020, "high-entropy-va"},
    {0x0040, "dynamic-base"},
    {0x0080, "force-integrity"},
    {0x0100, "nx-compat"},
    {0x0200, "no-isolation"},
    {0x0400, "no-seh"},
    {0x0800, "no-bind"},
    {0x1000, "appcontainer"},
    {0x2000, "wdm-driver"},
    {0x4000, "guard-cf"},
    {0x8000, "terminal-server-aware"},
};

static const lp_flag clr_flag_names[] = {
    {0x00001, "il-only"},
    {0x00002, "32-bit-required"},
    {0x00004, "il-library"},
    {0x00008, "strong-name-signed"},
    {0x00010, "native-entrypoint"},
    {0x10000, "track-debug-data"},
    {0x20000, "32-bit-preferred"},
};

/* ---- small helpers ------------------------------------------------------ */

static void str_from_bytes(lp_str *s, const uint8_t *b, size_t n)
{
    s->len = 0;
    s->terminated = true; /* a fixed-width field is complete by definition */
    s->truncated = false;
    for (size_t i = 0; i < n && b[i] && s->len < LP_STR_MAX; i++)
        s->s[s->len++] = (char)b[i];
    s->s[s->len] = '\0';
}

static void fmt_time(uint32_t t, char *buf, size_t n)
{
    time_t tt = (time_t)t;
    struct tm *tm = gmtime(&tt);
    if (!tm || !strftime(buf, n, "%Y-%m-%d %H:%M:%S UTC", tm))
        snprintf(buf, n, "?");
}

static bool is_pow2(uint32_t v) { return v && !(v & (v - 1)); }

static uint32_t dir_rva(const pe *p, int d)
{
    return (uint32_t)d < p->ndirs ? p->dirs[d].rva : 0;
}

static uint32_t dir_size(const pe *p, int d)
{
    return (uint32_t)d < p->ndirs ? p->dirs[d].size : 0;
}

/* ---- RVA to file offset ------------------------------------------------- */

typedef enum pe_map {
    MAP_OK,
    MAP_NONE,     /* no section contains the RVA */
    MAP_ZEROFILL, /* inside a section, but past its file-backed data */
    MAP_PARTIAL,  /* starts inside, runs past the end of the section's data */
    MAP_NOFILE    /* the section's data is beyond the end of the file */
} pe_map;

static const char *map_str(pe_map m)
{
    switch (m) {
    case MAP_OK:       return "ok";
    case MAP_NONE:     return "maps to no section";
    case MAP_ZEROFILL: return "falls in the zero-filled part of a section";
    case MAP_PARTIAL:  return "runs past the end of its section";
    case MAP_NOFILE:   return "maps past the end of the file";
    }
    return "?";
}

/* How much of the section's address range the loader fills from the file.
 * VirtualSize is the in-memory size; SizeOfRawData is rounded up to
 * FileAlignment, so it can be larger, and the difference is padding. When
 * VirtualSize is 0 the loader uses SizeOfRawData. */
static uint64_t sec_vsize(const pe_sec *s)
{
    return s->vsize ? s->vsize : s->raw_size;
}

static uint64_t sec_backed(const pe_sec *s)
{
    uint64_t v = sec_vsize(s);
    return s->raw_size < v ? s->raw_size : v;
}

/* The Windows loader rounds PointerToRawData down to a 512-byte boundary
 * whenever FileAlignment is at least 512. Legitimate files are already
 * aligned; hostile ones use the difference to confuse naive parsers. */
static uint64_t sec_raw_start(const pe *p, const pe_sec *s)
{
    uint64_t r = s->raw_ptr;
    if (p->file_align >= 0x200)
        r &= ~(uint64_t)0x1ff;
    return r;
}

static bool sec_contains(const pe_sec *s, uint32_t rva)
{
    return rva >= s->vaddr && (uint64_t)rva - s->vaddr < sec_vsize(s);
}

static bool sec_find(pe *p, uint32_t rva, uint32_t *idx)
{
    if (p->hit < p->nsecs && sec_contains(&p->secs[p->hit], rva)) {
        *idx = p->hit;
        return true;
    }
    if (!lp_tick(p->c, p->nsecs + 1u))
        return false;
    for (uint32_t i = 0; i < p->nsecs; i++) {
        if (sec_contains(&p->secs[i], rva)) {
            p->hit = i;
            *idx = i;
            return true;
        }
    }
    return false;
}

/*
 * Map [rva, rva + len) to a file offset. Succeeds only if every byte of the
 * range is backed by file data inside one section (or inside the headers,
 * which are mapped at RVA 0). *avail receives the number of file-backed
 * bytes from rva to the end of that region, which bounds string scans.
 *
 * The result is only a location. Reading it still goes through
 * lp_slice_at(), which checks it against the real file size again.
 */
static pe_map pe_rva(pe *p, uint32_t rva, uint64_t len, uint64_t *off,
                     uint64_t *avail)
{
    uint32_t i;
    uint64_t start, span;
    if (sec_find(p, rva, &i)) {
        const pe_sec *s = &p->secs[i];
        uint64_t delta = (uint64_t)rva - s->vaddr;
        uint64_t backed = sec_backed(s);
        if (delta >= backed)
            return MAP_ZEROFILL;
        if (len > backed - delta)
            return MAP_PARTIAL;
        start = sec_raw_start(p, s) + delta;
        span = backed - delta;
    } else {
        /* sec_find() also returns false when the work budget ran out. Do not
         * let that turn into "must be in the headers, then": fail closed. */
        if (p->c->exhausted)
            return MAP_NONE;
        uint64_t hdr = p->size_headers < p->size ? p->size_headers : p->size;
        if ((uint64_t)rva + len > hdr)
            return MAP_NONE;
        start = rva;
        span = hdr - rva;
    }
    if (start >= p->size || len > p->size - start)
        return MAP_NOFILE;
    if (span > p->size - start)
        span = p->size - start;
    *off = start;
    *avail = span;
    return MAP_OK;
}

static bool rva_slice(pe *p, uint32_t rva, uint64_t len, lp_slice *s,
                      pe_map *why)
{
    uint64_t off, avail;
    pe_map m = pe_rva(p, rva, len, &off, &avail);
    if (why)
        *why = m;
    if (m != MAP_OK) {
        lp_slice_at(NULL, 0, 0, false, s); /* poisoned */
        return false;
    }
    return lp_slice_at(p->img, off, len, false, s) == LP_OK;
}

static bool rva_u16(pe *p, uint32_t rva, uint16_t *v)
{
    lp_slice s;
    bool ok = rva_slice(p, rva, 2, &s, NULL);
    *v = lp_u16(&s);
    return ok;
}

static bool rva_u32(pe *p, uint32_t rva, uint32_t *v)
{
    lp_slice s;
    bool ok = rva_slice(p, rva, 4, &s, NULL);
    *v = lp_u32(&s);
    return ok;
}

static bool rva_uword(pe *p, uint32_t rva, uint64_t *v)
{
    lp_slice s;
    bool ok = rva_slice(p, rva, p->is64 ? 8 : 4, &s, NULL);
    *v = lp_uword(&s, p->is64);
    return ok;
}

/* Read a string at an RVA, bounded by its section's data and by `limit`. */
static pe_map rva_str(pe *p, uint32_t rva, uint64_t limit, lp_str *out)
{
    uint64_t off, avail;
    out->s[0] = '\0';
    out->len = 0;
    out->terminated = out->truncated = false;
    pe_map m = pe_rva(p, rva, 1, &off, &avail);
    if (m != MAP_OK)
        return m;
    lp_read_str(p->img, off, avail < limit ? avail : limit, out);
    /* Scanning a name is work too, so it is charged for: a table of long
     * names must not buy more byte-shuffling than the budget allows. */
    lp_tick(p->c, 1 + out->len / 32);
    return MAP_OK;
}

/* "0x00015a70 (.text+0x14a70)" style location for an RVA. */
static void where(pe *p, uint32_t rva, char *buf, size_t n)
{
    uint32_t i;
    if (rva && sec_find(p, rva, &i)) {
        lp_str name;
        char esc[64];
        str_from_bytes(&name, p->secs[i].name, 8);
        lp_esc(&name, esc, sizeof esc);
        snprintf(buf, n, "%s+0x%x", esc, rva - p->secs[i].vaddr);
    } else {
        snprintf(buf, n, "%s", rva ? "outside all sections" : "none");
    }
}

static uint32_t va_to_rva(const pe *p, uint64_t va, bool *ok)
{
    *ok = va >= p->image_base && va - p->image_base <= UINT32_MAX;
    return *ok ? (uint32_t)(va - p->image_base) : 0;
}

/* ---- headers ------------------------------------------------------------ */

static lp_status parse_headers(pe *p)
{
    lp_ctx *c = p->c;
    uint32_t lfanew;

    if (lp_read_u32(p->img, 0x3c, false, &lfanew) != LP_OK) {
        lp_reject(c, "MZ file too short for a DOS header (%llu bytes)",
                      (unsigned long long)p->size);
        return LP_STATUS_MALFORMED;
    }

    uint32_t sig;
    if (lp_read_u32(p->img, lfanew, false, &sig) != LP_OK) {
        lp_reject(c, "MZ executable; e_lfanew (0x%x) points past the end "
                         "of the file, so there is no PE header", lfanew);
        return LP_STATUS_UNSUPPORTED;
    }
    if (sig != PE_SIGNATURE) {
        const char *kind = "no PE header (DOS program)";
        switch (sig & 0xffff) {
        case 0x454e: kind = "an NE header (16-bit Windows or OS/2)"; break;
        case 0x454c: kind = "an LE header (VxD)"; break;
        case 0x584c: kind = "an LX header (OS/2)"; break;
        }
        lp_reject(c, "MZ executable with %s; not supported", kind);
        return LP_STATUS_UNSUPPORTED;
    }
    p->nt_off = lfanew;

    lp_slice s;
    if (lp_slice_at(p->img, (uint64_t)lfanew + 4, COFF_HEADER_SIZE, false, &s) != LP_OK) {
        lp_reject(c, "PE signature found, but the COFF header is cut off");
        return LP_STATUS_MALFORMED;
    }
    p->machine = lp_u16(&s);
    p->nsec_hdr = lp_u16(&s);
    p->timestamp = lp_u32(&s);
    p->symtab_ptr = lp_u32(&s);
    p->nsyms = lp_u32(&s);
    p->opt_size = lp_u16(&s);
    p->chars = lp_u16(&s);

    uint64_t opt_off = (uint64_t)lfanew + 4 + COFF_HEADER_SIZE;
    if (lp_read_u16(p->img, opt_off, false, &p->magic) != LP_OK) {
        lp_reject(c, "PE file with no optional header (an object file?)");
        return LP_STATUS_MALFORMED;
    }
    if (p->magic == OPT_ROM) {
        lp_reject(c, "ROM image (optional header magic 0x107); not supported");
        return LP_STATUS_UNSUPPORTED;
    }
    if (p->magic != OPT_PE32 && p->magic != OPT_PE32PLUS) {
        lp_reject(c, "unknown optional header magic 0x%04x", p->magic);
        return LP_STATUS_MALFORMED;
    }
    p->is64 = p->magic == OPT_PE32PLUS;
    uint32_t std = p->is64 ? OPT_STD_PE32PLUS : OPT_STD_PE32;

    /* The optional header is read from the file even if SizeOfOptionalHeader
     * says it is shorter: the loader does the same, and only uses that field
     * to find the section table. */
    if (lp_slice_at(p->img, opt_off, std, false, &s) != LP_OK) {
        lp_reject(c, "optional header is cut off by the end of the file");
        return LP_STATUS_MALFORMED;
    }
    lp_skip(&s, 2); /* magic */
    p->link_major = lp_u8(&s);
    p->link_minor = lp_u8(&s);
    p->size_code = lp_u32(&s);
    p->size_idata = lp_u32(&s);
    p->size_udata = lp_u32(&s);
    p->entry = lp_u32(&s);
    p->base_code = lp_u32(&s);
    if (!p->is64)
        p->base_data = lp_u32(&s);
    p->image_base = lp_uword(&s, p->is64);
    p->sect_align = lp_u32(&s);
    p->file_align = lp_u32(&s);
    p->os_major = lp_u16(&s);
    p->os_minor = lp_u16(&s);
    p->img_major = lp_u16(&s);
    p->img_minor = lp_u16(&s);
    p->sub_major = lp_u16(&s);
    p->sub_minor = lp_u16(&s);
    p->win32_ver = lp_u32(&s);
    p->size_image = lp_u32(&s);
    p->size_headers = lp_u32(&s);
    p->checksum_off = opt_off + lp_pos(&s);
    p->checksum = lp_u32(&s);
    p->subsystem = lp_u16(&s);
    p->dll_chars = lp_u16(&s);
    p->stack_res = lp_uword(&s, p->is64);
    p->stack_com = lp_uword(&s, p->is64);
    p->heap_res = lp_uword(&s, p->is64);
    p->heap_com = lp_uword(&s, p->is64);
    p->loader_flags = lp_u32(&s);
    p->nrva = lp_u32(&s);
    if (!lp_ok(&s))
        return LP_STATUS_MALFORMED; /* cannot happen: the slice was sized for it */

    if (p->opt_size < std)
        lp_warn(c, "SizeOfOptionalHeader is %u, smaller than the %u-byte %s header",
                p->opt_size, std, p->is64 ? "PE32+" : "PE32");

    /* Data directories. Only 16 are defined and the loader ignores the rest,
     * so NumberOfRvaAndSizes is never used as a loop bound directly. */
    p->ndirs = p->nrva < DIR_COUNT ? p->nrva : DIR_COUNT;
    if (p->nrva > DIR_COUNT)
        lp_warn(c, "NumberOfRvaAndSizes is %u; only %u data directories exist",
                p->nrva, DIR_COUNT);
    if (lp_slice_at(p->img, opt_off + std, (uint64_t)p->ndirs * 8, false, &s) != LP_OK) {
        uint64_t have = p->size > opt_off + std ? (p->size - opt_off - std) / 8 : 0;
        lp_warn(c, "data directories are cut off by the end of the file");
        p->ndirs = have < p->ndirs ? (uint32_t)have : p->ndirs;
        lp_slice_at(p->img, opt_off + std, (uint64_t)p->ndirs * 8, false, &s);
    }
    for (uint32_t i = 0; i < p->ndirs; i++) {
        p->dirs[i].rva = lp_u32(&s);
        p->dirs[i].size = lp_u32(&s);
    }
    if (std + (uint64_t)p->ndirs * 8 > p->opt_size && p->opt_size >= std)
        lp_warn(c, "data directories extend past SizeOfOptionalHeader (%u)",
                p->opt_size);

    /* Section table. Its count is clamped to what the file can hold. */
    uint64_t sec_off = opt_off + p->opt_size;
    uint64_t fit = sec_off < p->size ? (p->size - sec_off) / SECTION_HEADER_SIZE : 0;
    uint32_t n = p->nsec_hdr;
    if (n > fit) {
        lp_warn(c, "header claims %u sections but only %llu fit in the file",
                p->nsec_hdr, (unsigned long long)fit);
        n = (uint32_t)fit;
    }
    if (n) {
        p->secs = lp_calloc(n, sizeof *p->secs);
        if (!p->secs) {
            lp_warn(c, "out of memory for %u section headers", n);
            n = 0;
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        lp_slice_at(p->img, sec_off + (uint64_t)i * SECTION_HEADER_SIZE,
                    SECTION_HEADER_SIZE, false, &s);
        pe_sec *x = &p->secs[i];
        lp_bytes(&s, x->name, 8);
        x->vsize = lp_u32(&s);
        x->vaddr = lp_u32(&s);
        x->raw_size = lp_u32(&s);
        x->raw_ptr = lp_u32(&s);
        x->reloc_ptr = lp_u32(&s);
        x->lineno_ptr = lp_u32(&s);
        x->nreloc = lp_u16(&s);
        x->nlineno = lp_u16(&s);
        x->chars = lp_u32(&s);
    }
    p->nsecs = n;

    /* Consistency checks that a well-formed image always passes. */
    if (p->size_headers > p->size)
        lp_warn(c, "SizeOfHeaders (0x%x) is larger than the file", p->size_headers);
    if (!is_pow2(p->file_align))
        lp_warn(c, "FileAlignment 0x%x is not a power of two", p->file_align);
    if (!is_pow2(p->sect_align))
        lp_warn(c, "SectionAlignment 0x%x is not a power of two", p->sect_align);
    else if (p->sect_align < p->file_align)
        lp_warn(c, "SectionAlignment 0x%x is smaller than FileAlignment 0x%x",
                p->sect_align, p->file_align);
    for (uint32_t i = 0; i < p->nsecs; i++) {
        const pe_sec *x = &p->secs[i];
        if (x->raw_size && (uint64_t)x->raw_ptr + x->raw_size > p->size) {
            lp_str nm;
            char esc[64];
            str_from_bytes(&nm, x->name, 8);
            lp_warn(c, "section %u (%s): raw data 0x%x+0x%x runs past the end of the file",
                    i + 1, lp_esc(&nm, esc, sizeof esc), x->raw_ptr, x->raw_size);
        }
    }
    return LP_STATUS_OK;
}

/* Long section names ("/123") index the COFF string table, which follows
 * the (deprecated) COFF symbol table. MinGW images use them for .debug_*. */
static void section_name(pe *p, const pe_sec *s, lp_str *out)
{
    str_from_bytes(out, s->name, 8);
    if (out->len < 2 || out->s[0] != '/' || !p->symtab_ptr)
        return;
    uint64_t idx = 0;
    for (size_t i = 1; i < out->len; i++) {
        if (out->s[i] < '0' || out->s[i] > '9')
            return;
        idx = idx * 10 + (uint64_t)(out->s[i] - '0');
    }
    uint64_t table = (uint64_t)p->symtab_ptr + (uint64_t)p->nsyms * 18;
    uint32_t table_size;
    if (lp_read_u32(p->img, table, false, &table_size) != LP_OK || idx >= table_size)
        return;
    lp_str longname;
    if (lp_read_str(p->img, table + idx, table_size - idx, &longname) == LP_OK &&
        longname.len)
        *out = longname;
}

/* ---- facts gathered before printing -------------------------------------- */

static void gather_debug(pe *p)
{
    uint32_t rva = dir_rva(p, DIR_DEBUG), size = dir_size(p, DIR_DEBUG);
    if (!rva || !size)
        return;
    uint32_t n = size / 28;
    if (size % 28)
        lp_warn(p->c, "debug directory size %u is not a multiple of 28", size);
    if (n > MAX_DEBUG_ENTRIES) {
        lp_warn(p->c, "debug directory claims %u entries; reading %u", n, MAX_DEBUG_ENTRIES);
        n = MAX_DEBUG_ENTRIES;
    }
    lp_slice s;
    pe_map why;
    if (!rva_slice(p, rva, (uint64_t)n * 28, &s, &why)) {
        lp_warn(p->c, "debug directory at RVA 0x%08x %s", rva, map_str(why));
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        pe_debug *d = &p->debug[p->ndebug++];
        lp_skip(&s, 12); /* characteristics, timestamp, version */
        d->type = lp_u32(&s);
        d->size = lp_u32(&s);
        d->rva = lp_u32(&s);
        d->ptr = lp_u32(&s);

        if (d->type == DEBUG_REPRO)
            p->repro = true;
        if (d->type == DEBUG_EX_DLLCHARACTERISTICS && d->size >= 4) {
            uint32_t ex;
            if (lp_read_u32(p->img, d->ptr, false, &ex) == LP_OK)
                p->cet_compat = (ex & EX_DLLC_CET_COMPAT) != 0;
        }
        if (d->type == DEBUG_CODEVIEW && d->size >= 24 && !p->have_pdb) {
            /* RSDS: signature, GUID, age, then a NUL-terminated path, all
             * inside the SizeOfData bytes at PointerToRawData. */
            lp_slice cv;
            if (lp_slice_at(p->img, d->ptr, d->size, false, &cv) != LP_OK) {
                lp_warn(p->c, "CodeView record at 0x%x+0x%x is outside the file",
                        d->ptr, d->size);
                continue;
            }
            if (lp_u32(&cv) != 0x53445352u) /* "RSDS" */
                continue;
            lp_bytes(&cv, p->pdb_guid, 16);
            p->pdb_age = lp_u32(&cv);
            lp_read_str(p->img, (uint64_t)d->ptr + 24, d->size - 24, &p->pdb);
            p->have_pdb = true;
            if (!p->pdb.terminated && !p->pdb.truncated)
                lp_warn(p->c, "PDB path in the CodeView record is not terminated");
        }
    }
}

static void gather_tls(pe *p)
{
    uint32_t rva = dir_rva(p, DIR_TLS);
    if (!rva)
        return;
    lp_slice s;
    pe_map why;
    if (!rva_slice(p, rva, p->is64 ? 40 : 24, &s, &why)) {
        lp_warn(p->c, "TLS directory at RVA 0x%08x %s", rva, map_str(why));
        return;
    }
    lp_skip(&s, p->is64 ? 24 : 12); /* raw data start/end, index address */
    uint64_t cb_va = lp_uword(&s, p->is64);
    if (!cb_va)
        return;
    bool ok;
    uint32_t cb_rva = va_to_rva(p, cb_va, &ok);
    if (!ok) {
        lp_warn(p->c, "TLS callback table address 0x%llx is outside the image",
                (unsigned long long)cb_va);
        return;
    }
    uint32_t step = p->is64 ? 8 : 4;
    for (uint32_t i = 0;; i++) {
        uint64_t at = (uint64_t)cb_rva + (uint64_t)i * step;
        uint64_t fn;
        if (at > UINT32_MAX || !rva_uword(p, (uint32_t)at, &fn)) {
            lp_warn(p->c, "TLS callback table is not terminated inside the file");
            return;
        }
        if (!fn)
            return;
        if (i == MAX_TLS_CALLBACKS) {
            p->tls_more = true;
            return;
        }
        uint32_t fn_rva = va_to_rva(p, fn, &ok);
        p->tls_callbacks[p->ntls++] = ok ? fn_rva : 0;
    }
}

static void gather_misc(pe *p)
{
    uint32_t rva;

    /* Load config: only SafeSEH is read, and only for 32-bit x86. */
    if ((rva = dir_rva(p, DIR_LOADCONFIG)) != 0) {
        uint32_t size;
        if (rva_u32(p, rva, &size)) {
            p->have_loadcfg = true;
            if (!p->is64 && size >= 0x48) {
                lp_slice s;
                if (rva_slice(p, rva, 0x48, &s, NULL)) {
                    lp_seek(&s, 0x40);
                    uint32_t table = lp_u32(&s);
                    p->seh_count = lp_u32(&s);
                    p->safeseh = table != 0;
                }
            }
        } else {
            lp_warn(p->c, "load config directory at RVA 0x%08x is unreadable", rva);
        }
    }

    if ((rva = dir_rva(p, DIR_CLR)) != 0) {
        lp_slice s;
        pe_map why;
        if (rva_slice(p, rva, 20, &s, &why)) {
            p->have_clr = true;
            lp_skip(&s, 4); /* cb */
            p->clr_major = lp_u16(&s);
            p->clr_minor = lp_u16(&s);
            lp_skip(&s, 8); /* metadata directory */
            p->clr_flags = lp_u32(&s);
        } else {
            lp_warn(p->c, "CLR header at RVA 0x%08x %s", rva, map_str(why));
        }
    }

    /* The certificate table is the one directory that holds a file offset,
     * not an RVA: it is not mapped into memory. */
    if ((rva = dir_rva(p, DIR_SECURITY)) != 0) {
        uint32_t size = dir_size(p, DIR_SECURITY);
        lp_slice s;
        if (lp_slice_at(p->img, rva, size, false, &s) != LP_OK || size < 8) {
            lp_warn(p->c, "certificate table at file offset 0x%x+0x%x is outside the file",
                    rva, size);
        } else {
            p->have_cert = true;
            p->cert_size = size;
        }
    }
}

/* ---- checksum ----------------------------------------------------------- */

/*
 * The PE checksum: a ones'-complement-style sum of 16-bit words with the
 * CheckSum field itself treated as zero, plus the file length.
 *
 * This is the one loop whose length is the file's size rather than a count
 * out of a header, so it is capped instead: past PE_CHECKSUM_MAX the field
 * is reported unverified rather than spending seconds on a file that asked
 * for it. Bytes are pulled a page at a time, still through the accessor.
 */
#define PE_CHECKSUM_MAX (256ull << 20)

static bool pe_checksum(const pe *p, uint32_t *out)
{
    lp_slice s;
    if (p->size > PE_CHECKSUM_MAX || lp_slice_at(p->img, 0, p->size, false, &s) != LP_OK)
        return false;

    const uint64_t cs = p->checksum_off;
    uint8_t chunk[4096]; /* even, so no 16-bit word straddles two chunks */
    uint64_t sum = 0, pos = 0;
    while (pos < p->size) {
        uint64_t left = p->size - pos;
        size_t n = left < sizeof chunk ? (size_t)left : sizeof chunk;
        lp_bytes(&s, chunk, n);
        for (size_t i = 0; i < n; i += 2) {
            uint64_t at = pos + i;
            uint32_t lo = chunk[i];
            uint32_t hi = i + 1 < n ? chunk[i + 1] : 0;
            if (at >= cs && at < cs + 4)
                lo = 0;
            if (at + 1 >= cs && at + 1 < cs + 4)
                hi = 0;
            sum += lo | hi << 8;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        pos += n;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    *out = (uint32_t)(sum + p->size);
    return true;
}

/* ---- printing: headers and mitigations ---------------------------------- */

static void print_headers(pe *p)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    char buf[128], grp[32];

    lp_heading(c, "HEADERS", NULL);
    lp_field(c, "machine", "%s (0x%04x)", machine_name(p->machine), p->machine);
    lp_printf(o, "  %s%-19s%s 0x%04x  ", lp_c(o, LP_C_LABEL), "characteristics",
              lp_c(o, LP_C_RESET), p->chars);
    lp_flags(c, p->chars, coff_flags, LP_COUNT(coff_flags), ", ");
    lp_printf(o, "\n");
    if (p->repro) {
        lp_field(c, "timestamp", "0x%08x  %sreproducible build: a hash, not a date%s",
                 p->timestamp, lp_c(o, LP_C_LABEL), lp_c(o, LP_C_RESET));
    } else {
        fmt_time(p->timestamp, buf, sizeof buf);
        lp_field(c, "timestamp", "0x%08x  %s", p->timestamp, buf);
    }
    where(p, p->entry, buf, sizeof buf);
    lp_field(c, "entry point", "0x%08x  %s", p->entry, buf);
    lp_field(c, "image base", "0x%0*llx", p->is64 ? 16 : 8,
             (unsigned long long)p->image_base);
    lp_field(c, "size of image", "0x%08x  (%s bytes)", p->size_image,
             lp_grp(p->size_image, grp, sizeof grp));
    lp_field(c, "size of headers", "0x%x", p->size_headers);
    lp_field(c, "alignment", "section 0x%x, file 0x%x", p->sect_align, p->file_align);
    lp_field(c, "subsystem", "%s (%u), version %u.%u", subsystem_name(p->subsystem),
             p->subsystem, p->sub_major, p->sub_minor);
    lp_field(c, "versions", "os %u.%u  image %u.%u  linker %u.%u", p->os_major,
             p->os_minor, p->img_major, p->img_minor, p->link_major, p->link_minor);
    uint32_t real = 0;
    if (!p->checksum) {
        lp_field(c, "checksum", "0 (not set)");
    } else if (!pe_checksum(p, &real)) {
        lp_field(c, "checksum", "0x%08x  (not recomputed: file is %s bytes)",
                 p->checksum, lp_grp(p->size, grp, sizeof grp));
    } else {
        if (real == p->checksum)
            lp_field(c, "checksum", "0x%08x  %scorrect%s", p->checksum,
                     lp_c(o, LP_C_GOOD), lp_c(o, LP_C_RESET));
        else
            lp_field(c, "checksum", "0x%08x  %sfile sums to 0x%08x%s", p->checksum,
                     lp_c(o, LP_C_BAD), real, lp_c(o, LP_C_RESET));
    }
    lp_printf(o, "  %s%-19s%s 0x%04x  ", lp_c(o, LP_C_LABEL), "dll characteristics",
              lp_c(o, LP_C_RESET), p->dll_chars);
    lp_flags(c, p->dll_chars, dllc_flags, LP_COUNT(dllc_flags), ", ");
    lp_printf(o, "\n");
    lp_field(c, "stack", "reserve 0x%llx, commit 0x%llx",
             (unsigned long long)p->stack_res, (unsigned long long)p->stack_com);
    lp_field(c, "heap", "reserve 0x%llx, commit 0x%llx",
             (unsigned long long)p->heap_res, (unsigned long long)p->heap_com);
    if (p->have_pdb) {
        char esc[LP_ESC_MAX];
        const uint8_t *g = p->pdb_guid;
        lp_field(c, "pdb", "%s", lp_esc(&p->pdb, esc, sizeof esc));
        lp_field(c, "pdb guid",
                 "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
                 "  age %u",
                 g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10],
                 g[11], g[12], g[13], g[14], g[15], p->pdb_age);
    }
    if (p->have_clr) {
        lp_printf(o, "  %s%-19s%s runtime %u.%u  ", lp_c(o, LP_C_LABEL), ".net",
                  lp_c(o, LP_C_RESET), p->clr_major, p->clr_minor);
        lp_flags(c, p->clr_flags, clr_flag_names, LP_COUNT(clr_flag_names), ", ");
        lp_printf(o, "\n");
    }
    if (p->ntls) {
        lp_field(c, "tls callbacks", "%u%s  (these run before the entry point)",
                 p->ntls, p->tls_more ? "+" : "");
    }
}

static void mitigation(lp_ctx *c, const char *name, int state, const char *detail)
{
    /* state: 1 yes, 0 no, -1 not applicable */
    lp_out *o = c->out;
    const char *word = state > 0 ? "yes" : state == 0 ? "no" : "n/a";
    lp_color col = state > 0 ? LP_C_GOOD : state == 0 ? LP_C_BAD : LP_C_LABEL;
    lp_printf(o, "  %s%-19s%s %s%-3s%s", lp_c(o, LP_C_LABEL), name,
              lp_c(o, LP_C_RESET), lp_c(o, col), word, lp_c(o, LP_C_RESET));
    if (detail && *detail)
        lp_printf(o, "  %s%s%s", lp_c(o, LP_C_LABEL), detail, lp_c(o, LP_C_RESET));
    lp_printf(o, "\n");
}

static void print_mitigations(pe *p)
{
    lp_ctx *c = p->c;
    if (c->opts->flat)
        return;
    char buf[96], grp[32];
    bool aslr = (p->dll_chars & DLLC_DYNAMIC_BASE) != 0;
    bool stripped = (p->chars & IMAGE_FILE_RELOCS_STRIPPED) != 0;

    lp_heading(c, "MITIGATIONS", NULL);
    if (aslr && stripped)
        mitigation(c, "ASLR", 0, "dynamic-base is set but relocations are stripped");
    else if (aslr && p->is64)
        mitigation(c, "ASLR", 1, (p->dll_chars & DLLC_HIGH_ENTROPY_VA) ?
                                     "high-entropy 64-bit" : "without high-entropy VA");
    else
        mitigation(c, "ASLR", aslr, "");
    mitigation(c, "DEP / NX", (p->dll_chars & DLLC_NX_COMPAT) || p->is64,
               (p->dll_chars & DLLC_NX_COMPAT) ? "" : p->is64 ? "always on for 64-bit" : "");
    mitigation(c, "Control Flow Guard", (p->dll_chars & DLLC_GUARD_CF) != 0, "");
    mitigation(c, "CET shadow stack", p->cet_compat, "");
    if (p->machine != 0x014c) {
        mitigation(c, "SafeSEH", -1, "32-bit x86 only");
    } else if (p->dll_chars & DLLC_NO_SEH) {
        mitigation(c, "SafeSEH", -1, "image uses no SEH");
    } else {
        snprintf(buf, sizeof buf, "%u handlers registered", p->seh_count);
        mitigation(c, "SafeSEH", p->safeseh, p->safeseh ? buf : "");
    }
    if (p->have_cert) {
        snprintf(buf, sizeof buf, "signature present, %s bytes; not verified",
                 lp_grp(p->cert_size, grp, sizeof grp));
        mitigation(c, "Authenticode", 1, buf);
    } else {
        mitigation(c, "Authenticode", 0, "no embedded signature (may be catalog-signed)");
    }
    mitigation(c, "Force integrity", (p->dll_chars & DLLC_FORCE_INTEGRITY) != 0, "");
    if (p->dll_chars & DLLC_APPCONTAINER)
        mitigation(c, "AppContainer", 1, "");
}

/* ---- printing: sections and directories ---------------------------------- */

static void sec_flags(uint32_t ch, char *buf, size_t n)
{
    snprintf(buf, n, "%c%c%c %s%s%s", (ch & SCN_READ) ? 'r' : '-',
             (ch & SCN_WRITE) ? 'w' : '-', (ch & SCN_EXECUTE) ? 'x' : '-',
             (ch & SCN_CNT_CODE) ? "code" : (ch & SCN_CNT_UDATA) ? "bss"
                                           : (ch & SCN_CNT_IDATA) ? "data" : "",
             (ch & SCN_DISCARDABLE) ? " discard" : "",
             (ch & SCN_SHARED) ? " shared" : "");
}

static void print_sections(pe *p)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    char flags[48], esc[LP_ESC_MAX];

    lp_heading(c, "SECTIONS", "%u", p->nsecs);
    if (!c->opts->flat && p->nsecs)
        lp_printf(o, "  %s  #  %-10s %-10s %-10s %-10s %-10s %s%s\n", lp_c(o, LP_C_LABEL),
                  "name", "virt addr", "virt size", "raw off", "raw size", "flags",
                  lp_c(o, LP_C_RESET));
    for (uint32_t i = 0; i < p->nsecs; i++) {
        if (!lp_tick(c, 1))
            return;
        const pe_sec *s = &p->secs[i];
        lp_str name;
        section_name(p, s, &name);
        lp_esc(&name, esc, sizeof esc);
        sec_flags(s->chars, flags, sizeof flags);
        if (c->opts->flat)
            lp_printf(o, "section\t%u\t%s\t0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",
                      i + 1, esc, s->vaddr, s->vsize, s->raw_ptr, s->raw_size, s->chars);
        else
            lp_printf(o, "  %3u  %s%-10s%s 0x%08x 0x%08x 0x%08x 0x%08x %s\n", i + 1,
                      lp_c(o, LP_C_NAME), esc, lp_c(o, LP_C_RESET), s->vaddr, s->vsize,
                      s->raw_ptr, s->raw_size, flags);
    }
}

static void print_directories(pe *p)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    if (c->opts->flat)
        return;
    uint32_t used = 0;
    for (uint32_t i = 0; i < p->ndirs; i++)
        used += p->dirs[i].rva || p->dirs[i].size;
    lp_heading(c, "DATA DIRECTORIES", "%u of %u used", used, p->ndirs);
    for (uint32_t i = 0; i < p->ndirs; i++) {
        const pe_dir *d = &p->dirs[i];
        if (!d->rva && !d->size)
            continue;
        char loc[96];
        if (i == DIR_SECURITY)
            snprintf(loc, sizeof loc, "file offset, not an RVA");
        else
            where(p, d->rva, loc, sizeof loc);
        lp_printf(o, "  %s%-14s%s 0x%08x  0x%08x  %s%s%s\n", lp_c(o, LP_C_LABEL),
                  dir_names[i], lp_c(o, LP_C_RESET), d->rva, d->size,
                  lp_c(o, LP_C_LABEL), loc, lp_c(o, LP_C_RESET));
    }
}

static void print_debug(pe *p)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    if (c->opts->flat)
        return;
    if (p->ndebug) {
        lp_heading(c, "DEBUG DIRECTORY", "%u entries", p->ndebug);
        for (uint32_t i = 0; i < p->ndebug; i++) {
            const pe_debug *d = &p->debug[i];
            lp_printf(o, "  %s%-22s%s size 0x%-6x rva 0x%08x  file 0x%08x\n",
                      lp_c(o, LP_C_LABEL), debug_type_name(d->type),
                      lp_c(o, LP_C_RESET), d->size, d->rva, d->ptr);
        }
    }
    if (p->ntls) {
        lp_heading(c, "TLS CALLBACKS", "%u%s", p->ntls, p->tls_more ? "+" : "");
        for (uint32_t i = 0; i < p->ntls; i++) {
            char loc[96];
            where(p, p->tls_callbacks[i], loc, sizeof loc);
            lp_printf(o, "  0x%08x  %s%s%s\n", p->tls_callbacks[i],
                      lp_c(o, LP_C_LABEL), loc, lp_c(o, LP_C_RESET));
        }
    }
}

/* ---- imports ------------------------------------------------------------ */

typedef struct imp_totals {
    uint32_t modules, functions;
} imp_totals;

/* Walk one import lookup table (ILT/INT). Each entry is a 32- or 64-bit
 * thunk: top bit set means import by ordinal, otherwise the low 31 bits are
 * the RVA of a hint/name entry. Returns the number of entries. */
static uint32_t walk_thunks(pe *p, const char *mod, uint32_t table, bool print,
                            const char *kind)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    const uint32_t step = p->is64 ? 8 : 4;
    const uint64_t ord_flag = p->is64 ? 1ull << 63 : 1ull << 31;
    uint32_t n = 0;

    for (uint32_t j = 0;; j++) {
        if (j == LP_MAX_IMPORTS_PER_MODULE) {
            lp_warn(c, "%s: more than %u imports; stopping", mod, j);
            break;
        }
        if (!lp_tick(c, 1))
            break;
        uint64_t at = (uint64_t)table + (uint64_t)j * step;
        lp_slice s;
        pe_map why = MAP_NONE;
        if (at > UINT32_MAX || !rva_slice(p, (uint32_t)at, step, &s, &why)) {
            lp_warn(c, "%s: lookup table entry at RVA 0x%llx %s", mod,
                    (unsigned long long)at, map_str(why));
            break;
        }
        uint64_t v = lp_uword(&s, p->is64);
        if (!v)
            break;
        n++;
        if (!print)
            continue;

        if (v & ord_flag) {
            uint32_t ord = (uint32_t)(v & 0xffff);
            if (c->opts->flat)
                lp_printf(o, "%s\t%s\t#%u\t-\n", kind, mod, ord);
            else
                lp_printf(o, "      %sord%s  %s#%u%s\n", lp_c(o, LP_C_LABEL),
                          lp_c(o, LP_C_RESET), lp_c(o, LP_C_NAME), ord,
                          lp_c(o, LP_C_RESET));
            continue;
        }
        if (v >> 31) {
            lp_warn(c, "%s: import entry 0x%llx has reserved bits set", mod,
                    (unsigned long long)v);
            continue;
        }
        uint32_t hn = (uint32_t)v;
        uint16_t hint = 0;
        lp_str name;
        char esc[LP_ESC_MAX];
        pe_map m = MAP_OK;
        if (!rva_u16(p, hn, &hint) ||
            (m = rva_str(p, hn + 2, LP_STR_MAX + 1, &name)) != MAP_OK) {
            lp_warn(c, "%s: hint/name entry at RVA 0x%08x %s", mod, hn,
                    map_str(m == MAP_OK ? MAP_PARTIAL : m));
            continue;
        }
        if (!name.terminated && !name.truncated)
            lp_warn(c, "%s: import name at RVA 0x%08x is not terminated", mod, hn + 2);
        lp_esc(&name, esc, sizeof esc);
        if (c->opts->flat)
            lp_printf(o, "%s\t%s\t%s\t%u\n", kind, mod, esc, hint);
        else
            lp_printf(o, "      %s%04x%s  %s\n", lp_c(o, LP_C_LABEL), hint,
                      lp_c(o, LP_C_RESET), esc);
    }
    return n;
}

static void module_line(pe *p, const char *mod, uint32_t count)
{
    lp_out *o = p->c->out;
    if (!p->c->opts->flat)
        lp_printf(o, "  %s%s%s  %s%u%s\n", lp_c(o, LP_C_MODULE), mod,
                  lp_c(o, LP_C_RESET), lp_c(o, LP_C_LABEL), count,
                  lp_c(o, LP_C_RESET));
}

/* Import directory: an array of 20-byte descriptors ending in an all-zero
 * one. The directory's Size field is not trusted as a bound (the loader
 * ignores it too); the walk ends at the terminator or the first entry that
 * does not map. */
static void walk_imports(pe *p, bool print, imp_totals *t)
{
    lp_ctx *c = p->c;
    uint32_t base = dir_rva(p, DIR_IMPORT);
    if (!base)
        return;
    for (uint32_t i = 0;; i++) {
        if (i == LP_MAX_IMPORT_MODULES) {
            lp_warn(c, "import directory lists more than %u modules; stopping", i);
            break;
        }
        if (!lp_tick(c, 1))
            break;
        uint64_t at = (uint64_t)base + (uint64_t)i * 20;
        lp_slice s;
        pe_map why = MAP_NONE;
        if (at > UINT32_MAX || !rva_slice(p, (uint32_t)at, 20, &s, &why)) {
            lp_warn(c, "import descriptor %u at RVA 0x%llx %s", i,
                    (unsigned long long)at, map_str(why));
            break;
        }
        uint32_t ilt = lp_u32(&s), stamp = lp_u32(&s), chain = lp_u32(&s);
        uint32_t name_rva = lp_u32(&s), iat = lp_u32(&s);
        if (!ilt && !stamp && !chain && !name_rva && !iat)
            break;

        lp_str name;
        char mod[LP_ESC_MAX];
        pe_map m = rva_str(p, name_rva, 256, &name);
        if (m != MAP_OK || !name.terminated) {
            lp_warn(c, "import descriptor %u: module name at RVA 0x%08x %s", i, name_rva,
                    m != MAP_OK ? map_str(m) : "is not terminated");
            if (m != MAP_OK)
                snprintf(mod, sizeof mod, "<module %u>", i);
            else
                lp_esc(&name, mod, sizeof mod);
        } else {
            lp_esc(&name, mod, sizeof mod);
        }

        /* Old Borland linkers leave OriginalFirstThunk at 0 and keep names
         * only in the IAT. If the image is also bound, those are addresses
         * and the names are gone. */
        uint32_t table = ilt ? ilt : iat;
        if (!table) {
            lp_warn(c, "%s: descriptor has no lookup table", mod);
            continue;
        }
        if (!ilt && stamp)
            lp_warn(c, "%s: bound import without a lookup table; names are lost", mod);

        t->modules++;
        if (print && !c->opts->flat) {
            c->mute++;
            uint32_t n = walk_thunks(p, mod, table, false, "import");
            c->mute--;
            module_line(p, mod, n);
        }
        t->functions += walk_thunks(p, mod, table, print, "import");
    }
}

/* Delay-load descriptors are 32 bytes. Attribute bit 0 says the fields are
 * RVAs; without it (Visual C++ 6 era) they are virtual addresses. */
static void walk_delay_imports(pe *p, bool print, imp_totals *t)
{
    lp_ctx *c = p->c;
    uint32_t base = dir_rva(p, DIR_DELAYIMPORT);
    if (!base)
        return;
    for (uint32_t i = 0;; i++) {
        if (i == LP_MAX_IMPORT_MODULES) {
            lp_warn(c, "delay import directory lists more than %u modules; stopping", i);
            break;
        }
        if (!lp_tick(c, 1))
            break;
        uint64_t at = (uint64_t)base + (uint64_t)i * 32;
        lp_slice s;
        pe_map why = MAP_NONE;
        if (at > UINT32_MAX || !rva_slice(p, (uint32_t)at, 32, &s, &why)) {
            lp_warn(c, "delay import descriptor %u at RVA 0x%llx %s", i,
                    (unsigned long long)at, map_str(why));
            break;
        }
        uint32_t attrs = lp_u32(&s), name_rva = lp_u32(&s), hmod = lp_u32(&s);
        uint32_t iat = lp_u32(&s), intab = lp_u32(&s), biat = lp_u32(&s);
        uint32_t uiat = lp_u32(&s), stamp = lp_u32(&s);
        if (!attrs && !name_rva && !hmod && !iat && !intab && !biat && !uiat && !stamp)
            break;
        if (!name_rva)
            break;
        if (!(attrs & 1)) {
            bool ok1, ok2;
            name_rva = va_to_rva(p, name_rva, &ok1);
            intab = va_to_rva(p, intab, &ok2);
            if (!ok1 || !ok2) {
                lp_warn(c, "delay import descriptor %u: addresses are outside the image", i);
                continue;
            }
        }

        lp_str name;
        char mod[LP_ESC_MAX];
        pe_map m = rva_str(p, name_rva, 256, &name);
        if (m != MAP_OK || !name.terminated) {
            lp_warn(c, "delay import descriptor %u: module name at RVA 0x%08x %s", i,
                    name_rva, m != MAP_OK ? map_str(m) : "is not terminated");
            if (m != MAP_OK)
                snprintf(mod, sizeof mod, "<module %u>", i);
            else
                lp_esc(&name, mod, sizeof mod);
        } else {
            lp_esc(&name, mod, sizeof mod);
        }
        if (!intab) {
            lp_warn(c, "%s: delay descriptor has no name table", mod);
            continue;
        }
        t->modules++;
        if (print && !c->opts->flat) {
            c->mute++;
            uint32_t n = walk_thunks(p, mod, intab, false, "delayimport");
            c->mute--;
            module_line(p, mod, n);
        }
        t->functions += walk_thunks(p, mod, intab, print, "delayimport");
    }
}

static void print_imports(pe *p)
{
    lp_ctx *c = p->c;
    imp_totals t = {0, 0};
    if (dir_rva(p, DIR_IMPORT)) {
        if (!c->opts->flat) {
            c->mute++;
            walk_imports(p, false, &t);
            c->mute--;
            lp_heading(c, "IMPORTS", "%u modules, %u functions", t.modules, t.functions);
        }
        memset(&t, 0, sizeof t);
        walk_imports(p, true, &t);
    } else {
        lp_heading(c, "IMPORTS", "none");
    }
    if (dir_rva(p, DIR_DELAYIMPORT)) {
        if (!c->opts->flat) {
            memset(&t, 0, sizeof t);
            c->mute++;
            walk_delay_imports(p, false, &t);
            c->mute--;
            lp_heading(c, "DELAY-LOAD IMPORTS", "%u modules, %u functions", t.modules,
                       t.functions);
        }
        memset(&t, 0, sizeof t);
        walk_delay_imports(p, true, &t);
    }
}

/* ---- exports ------------------------------------------------------------ */

typedef struct exp_ctx {
    pe      *p;
    uint32_t dir_rva, dir_size;
} exp_ctx;

static void print_export(exp_ctx *x, uint64_t ordinal, long hint, uint32_t rva,
                         const char *name)
{
    pe *p = x->p;
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    char hintbuf[16];
    if (hint >= 0)
        snprintf(hintbuf, sizeof hintbuf, "%ld", hint);
    else
        hintbuf[0] = '\0';

    /* A forwarder is an RVA that points back inside the export directory,
     * at a "DLL.Function" or "DLL.#ordinal" string, instead of at code. */
    bool fwd = rva >= x->dir_rva && (uint64_t)rva - x->dir_rva < x->dir_size;
    if (fwd) {
        lp_str target;
        char esc[LP_ESC_MAX];
        uint64_t limit = (uint64_t)x->dir_rva + x->dir_size - rva;
        pe_map m = rva_str(p, rva, limit, &target);
        if (m != MAP_OK) {
            lp_warn(c, "export %s: forwarder string at RVA 0x%08x %s", name, rva, map_str(m));
            snprintf(esc, sizeof esc, "<unreadable>");
        } else {
            if (!target.terminated && !target.truncated)
                lp_warn(c, "export %s: forwarder string is not terminated inside the "
                           "export directory", name);
            lp_esc(&target, esc, sizeof esc);
        }
        if (c->opts->flat)
            lp_printf(o, "export\t%llu\t%s\t-> %s\n", (unsigned long long)ordinal, name, esc);
        else
            lp_printf(o, "  %7llu %5s  %sforward%s     %s  %s-> %s%s\n",
                      (unsigned long long)ordinal, hintbuf, lp_c(o, LP_C_LABEL),
                      lp_c(o, LP_C_RESET), name, lp_c(o, LP_C_LABEL), esc,
                      lp_c(o, LP_C_RESET));
        return;
    }
    if (c->opts->flat)
        lp_printf(o, "export\t%llu\t%s\t0x%08x\n", (unsigned long long)ordinal, name, rva);
    else
        lp_printf(o, "  %7llu %5s  0x%08x  %s%s%s\n", (unsigned long long)ordinal,
                  hintbuf, rva, lp_c(o, LP_C_NAME), name, lp_c(o, LP_C_RESET));
}

/* Clamp a table's entry count to the entries that are actually file-backed,
 * warning if the header claimed more. Returns the file offset of entry 0. */
static uint32_t clamp_table(pe *p, const char *what, uint32_t rva, uint32_t count,
                            uint32_t entsize, uint64_t *off)
{
    uint64_t avail;
    if (!count)
        return 0;
    pe_map m = pe_rva(p, rva, entsize, off, &avail);
    if (m != MAP_OK) {
        lp_warn(p->c, "export %s at RVA 0x%08x %s", what, rva, map_str(m));
        return 0;
    }
    uint64_t fit = avail / entsize;
    uint32_t n = count;
    if (n > fit) {
        lp_warn(p->c, "export %s claims %u entries; only %llu are in the file", what,
                count, (unsigned long long)fit);
        n = (uint32_t)fit;
    }
    if (n > LP_MAX_EXPORTS) {
        lp_warn(p->c, "export %s has %u entries; reading %u", what, n, LP_MAX_EXPORTS);
        n = LP_MAX_EXPORTS;
    }
    return n;
}

static void print_exports(pe *p)
{
    lp_ctx *c = p->c;
    lp_out *o = c->out;
    exp_ctx x = {p, dir_rva(p, DIR_EXPORT), dir_size(p, DIR_EXPORT)};
    if (!x.dir_rva) {
        lp_heading(c, "EXPORTS", "none");
        return;
    }

    lp_slice s;
    pe_map why;
    if (!rva_slice(p, x.dir_rva, 40, &s, &why)) {
        lp_heading(c, "EXPORTS", "unreadable");
        lp_warn(c, "export directory at RVA 0x%08x %s", x.dir_rva, map_str(why));
        return;
    }
    lp_skip(&s, 12); /* characteristics, timestamp, version */
    uint32_t name_rva = lp_u32(&s), base = lp_u32(&s);
    uint32_t nfuncs = lp_u32(&s), nnames = lp_u32(&s);
    uint32_t funcs_rva = lp_u32(&s), names_rva = lp_u32(&s), ords_rva = lp_u32(&s);

    lp_str dll;
    char dllesc[LP_ESC_MAX];
    if (rva_str(p, name_rva, 256, &dll) != MAP_OK)
        snprintf(dllesc, sizeof dllesc, "<unnamed>");
    else
        lp_esc(&dll, dllesc, sizeof dllesc);

    uint64_t funcs_off = 0, names_off = 0, ords_off = 0;
    uint32_t nf = clamp_table(p, "address table", funcs_rva, nfuncs, 4, &funcs_off);
    uint32_t nn = clamp_table(p, "name table", names_rva, nnames, 4, &names_off);
    uint32_t no = clamp_table(p, "ordinal table", ords_rva, nnames, 2, &ords_off);
    if (no < nn)
        nn = no;

    char g1[32], g2[32];
    lp_heading(c, "EXPORTS", "%s  %s functions, %s names, ordinal base %u", dllesc,
               lp_grp(nfuncs, g1, sizeof g1), lp_grp(nnames, g2, sizeof g2), base);
    if (!c->opts->flat && (nf || nn))
        lp_printf(o, "  %s%7s %5s  %-10s  %s%s\n", lp_c(o, LP_C_LABEL), "ordinal", "hint",
                  "rva", "name", lp_c(o, LP_C_RESET));

    /* One bit per function, to find the ones exported by ordinal only. */
    uint8_t *named = nf ? lp_calloc(((size_t)nf + 7) / 8, 1) : NULL;
    if (nf && !named)
        lp_warn(c, "out of memory tracking %u exports", nf);

    for (uint32_t i = 0; i < nn; i++) {
        if (!lp_tick(c, 1))
            break;
        uint32_t nrva;
        uint16_t idx;
        lp_read_u32(p->img, names_off + (uint64_t)i * 4, false, &nrva);
        lp_read_u16(p->img, ords_off + (uint64_t)i * 2, false, &idx);

        lp_str name;
        char esc[LP_ESC_MAX];
        pe_map m = rva_str(p, nrva, LP_STR_MAX + 1, &name);
        if (m != MAP_OK) {
            lp_warn(c, "export name %u at RVA 0x%08x %s", i, nrva, map_str(m));
            snprintf(esc, sizeof esc, "<name %u>", i);
        } else {
            if (!name.terminated && !name.truncated)
                lp_warn(c, "export name %u at RVA 0x%08x is not terminated", i, nrva);
            lp_esc(&name, esc, sizeof esc);
        }
        if (idx >= nf) {
            lp_warn(c, "export %s refers to function %u; the address table has %u", esc,
                    idx, nf);
            continue;
        }
        if (named)
            named[idx / 8] = (uint8_t)(named[idx / 8] | 1u << (idx % 8));
        uint32_t frva;
        lp_read_u32(p->img, funcs_off + (uint64_t)idx * 4, false, &frva);
        print_export(&x, (uint64_t)base + idx, (long)i, frva, esc);
    }
    for (uint32_t k = 0; named && k < nf; k++) {
        if (!lp_tick(c, 1))
            break;
        if (named[k / 8] & (1u << (k % 8)))
            continue;
        uint32_t frva;
        lp_read_u32(p->img, funcs_off + (uint64_t)k * 4, false, &frva);
        if (frva)
            print_export(&x, (uint64_t)base + k, -1, frva, "[NONAME]");
    }
    lp_free(named);
}

/* ---- entry point -------------------------------------------------------- */

lp_status lp_pe_inspect(lp_ctx *c)
{
    pe *p = lp_calloc(1, sizeof *p); /* ~4 KiB; kept off the stack */
    if (!p) {
        lp_warn(c, "out of memory");
        return LP_STATUS_MALFORMED;
    }
    p->c = c;
    p->img = c->img;
    p->size = c->size;

    lp_status st = parse_headers(p);
    if (st != LP_STATUS_OK) {
        lp_free(p->secs);
        lp_free(p);
        return st;
    }

    lp_out *o = c->out;
    unsigned what = c->opts->what;
    char grp[32];

    /* Before the banner: it reports whether this is a .NET image, which is
     * one of the things gather_misc() works out. */
    gather_debug(p);
    gather_tls(p);
    gather_misc(p);

    if (!c->opts->flat) {
        bool dll = (p->chars & IMAGE_FILE_DLL) != 0;
        lp_printf(o, "%s%s %s%s for %s, %s, %s bytes%s\n", lp_c(o, LP_C_LABEL),
                  p->is64 ? "PE32+" : "PE32", dll ? "DLL" : "executable",
                  p->have_clr ? " (.NET)" : "", machine_name(p->machine),
                  subsystem_name(p->subsystem), lp_grp(p->size, grp, sizeof grp),
                  lp_c(o, LP_C_RESET));
    } else {
        lp_printf(o, "format\t%s\t%s\n", p->is64 ? "PE32+" : "PE32",
                  machine_name(p->machine));
    }

    if (what & LP_SHOW_HEADERS && !c->opts->flat)
        print_headers(p);
    if (what & LP_SHOW_MITIGATIONS)
        print_mitigations(p);
    if (what & LP_SHOW_SECTIONS)
        print_sections(p);
    if (what & LP_SHOW_DIRECTORIES)
        print_directories(p);
    if (what & LP_SHOW_DEBUG)
        print_debug(p);
    if (what & LP_SHOW_IMPORTS)
        print_imports(p);
    if (what & LP_SHOW_EXPORTS)
        print_exports(p);

    lp_free(p->secs);
    lp_free(p);
    return LP_STATUS_OK;
}
