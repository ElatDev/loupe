/*
 * test_loupe.c - unit tests.
 *
 * Nothing here reads a file from disk. Every test builds a PE or ELF image
 * in memory, parses it, and checks what came out; the hostile cases take a
 * valid image and lie in one field at a time. Run under AddressSanitizer
 * (build.bat test), which turns any out-of-bounds read into a failure.
 *
 * The last two tests are the blunt ones: parse every prefix of every
 * fixture, and parse every fixture with every byte of its header region
 * replaced in turn. Between them they run the parsers tens of thousands of
 * times over input that is wrong in a different way each time.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loupe.h"
#include "mem.h"

static int checks, failures;
static const char *current_test = "";

#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                    \
    } while (0)

#define CHECK_HAS(text, needle)                                              \
    do {                                                                     \
        checks++;                                                            \
        if (!strstr((text), (needle))) {                                     \
            failures++;                                                      \
            printf("  FAIL %s:%d  output has no \"%s\"\n", __FILE__,         \
                   __LINE__, (needle));                                      \
        }                                                                    \
    } while (0)

static void start(const char *name)
{
    current_test = name;
    printf("%s\n", name);
}

/* ---- fixtures ----------------------------------------------------------- */

typedef struct fx {
    uint8_t *b;
    size_t   n;
} fx;

static fx fx_new(size_t n)
{
    fx f;
    f.b = calloc(n, 1);
    f.n = n;
    if (!f.b)
        exit(2);
    return f;
}

static void fx_free(fx *f)
{
    free(f->b);
    f->b = NULL;
}

/* Write `size` bytes of `v` at `off`. Tests are not hostile input, so a bad
 * offset here is a bug in the test: abort loudly. */
static void put(fx *f, size_t off, int size, uint64_t v, bool be)
{
    if (off + (size_t)size > f->n) {
        printf("  fixture overflow at %zu (+%d) in %s\n", off, size, current_test);
        exit(2);
    }
    for (int i = 0; i < size; i++)
        f->b[off + i] = (uint8_t)(v >> (be ? 8 * (size - 1 - i) : 8 * i));
}

static void put8(fx *f, size_t off, uint8_t v) { put(f, off, 1, v, false); }
static void put16(fx *f, size_t off, uint16_t v) { put(f, off, 2, v, false); }
static void put32(fx *f, size_t off, uint32_t v) { put(f, off, 4, v, false); }
static void put64(fx *f, size_t off, uint64_t v) { put(f, off, 8, v, false); }

static void puts_at(fx *f, size_t off, const char *s)
{
    size_t n = strlen(s) + 1;
    if (off + n > f->n)
        exit(2);
    memcpy(f->b + off, s, n);
}

/*
 * A PE image, valid and complete:
 *
 *   0x000  DOS header, e_lfanew -> 0x80
 *   0x080  PE signature, COFF header, optional header, 3 section headers
 *   0x200  .text    RVA 0x1000
 *   0x400  .rdata   RVA 0x2000: imports, exports, names
 *   (.bss RVA 0x3000 has no file data at all)
 *
 * Imports: KERNEL32.dll (ExitProcess by name, #17 by ordinal) and
 * USER32.dll (MessageBoxA). Exports: alpha, beta (forwarded to
 * KERNEL32.ExitProcess) and one with no name.
 */
#define PE_SIZE       0xc00
#define PE_NT         0x80
#define PE_RDATA_OFF  0x400
#define PE_RDATA_RVA  0x2000
#define PE_EXPORT_RVA 0x2500
#define PE_EXPORT_SIZE 0x200

static size_t pe_off(uint32_t rva) { return PE_RDATA_OFF + (rva - PE_RDATA_RVA); }

static fx build_pe(bool is64)
{
    fx f = fx_new(PE_SIZE);
    const uint32_t opt_std = is64 ? 112 : 96;
    const uint32_t opt_size = opt_std + 16 * 8;
    const size_t coff = PE_NT + 4;
    const size_t opt = coff + 20;
    const size_t sec = opt + opt_size;

    memcpy(f.b, "MZ", 2);
    put32(&f, 0x3c, PE_NT);
    memcpy(f.b + PE_NT, "PE\0\0", 4);

    put16(&f, coff + 0, is64 ? 0x8664 : 0x014c);
    put16(&f, coff + 2, 3);            /* sections */
    put32(&f, coff + 4, 0x5f000000);   /* timestamp */
    put16(&f, coff + 16, (uint16_t)opt_size);
    put16(&f, coff + 18, 0x2022);      /* executable, large-address-aware, dll */

    /* Field offsets are the same in both classes up to SizeOfStackReserve,
     * apart from ImageBase (and BaseOfData, which PE32+ drops). */
    put16(&f, opt + 0, is64 ? 0x20b : 0x10b);
    put8(&f, opt + 2, 14);             /* linker version */
    put32(&f, opt + 16, 0x1000);       /* AddressOfEntryPoint */
    put32(&f, opt + 20, 0x1000);       /* BaseOfCode */
    if (is64) {
        put64(&f, opt + 24, 0x140000000ull);
    } else {
        put32(&f, opt + 24, 0x2000);   /* BaseOfData */
        put32(&f, opt + 28, 0x400000); /* ImageBase */
    }
    put32(&f, opt + 32, 0x1000);       /* SectionAlignment */
    put32(&f, opt + 36, 0x200);        /* FileAlignment */
    put16(&f, opt + 40, 6);            /* MajorOperatingSystemVersion */
    put16(&f, opt + 48, 6);            /* MajorSubsystemVersion */
    put32(&f, opt + 56, 0x4000);       /* SizeOfImage */
    put32(&f, opt + 60, 0x200);        /* SizeOfHeaders */
    put16(&f, opt + 68, 3);            /* subsystem: console */
    put16(&f, opt + 70, 0x4160);       /* dll characteristics */
    size_t tail = opt + (is64 ? 104 : 88); /* LoaderFlags */
    put32(&f, tail + 4, 16);           /* NumberOfRvaAndSizes */
    size_t dirs = tail + 8;
    put32(&f, dirs + 0, PE_EXPORT_RVA);
    put32(&f, dirs + 4, PE_EXPORT_SIZE);
    put32(&f, dirs + 8, PE_RDATA_RVA); /* import directory */
    put32(&f, dirs + 12, 60);

    struct {
        const char *name;
        uint32_t vsize, vaddr, rawsize, rawptr, chars;
    } sections[3] = {
        {".text", 0x200, 0x1000, 0x200, 0x200, 0x60000020},
        {".rdata", 0x800, 0x2000, 0x800, 0x400, 0x40000040},
        {".bss", 0x1000, 0x3000, 0, 0, 0xc0000080},
    };
    for (int i = 0; i < 3; i++) {
        size_t s = sec + (size_t)i * 40;
        memcpy(f.b + s, sections[i].name, strlen(sections[i].name));
        put32(&f, s + 8, sections[i].vsize);
        put32(&f, s + 12, sections[i].vaddr);
        put32(&f, s + 16, sections[i].rawsize);
        put32(&f, s + 20, sections[i].rawptr);
        put32(&f, s + 36, sections[i].chars);
    }

    /* imports */
    size_t d = pe_off(0x2000);
    put32(&f, d + 0, 0x2100);  /* import lookup table */
    put32(&f, d + 12, 0x2200); /* module name */
    put32(&f, d + 16, 0x2300); /* IAT */
    put32(&f, d + 20, 0x2140);
    put32(&f, d + 32, 0x2210);
    put32(&f, d + 36, 0x2340);
    /* third descriptor is the all-zero terminator */

    const int tsz = is64 ? 8 : 4;
    const uint64_t ord_flag = is64 ? 1ull << 63 : 1ull << 31;
    size_t ilt = pe_off(0x2100);
    put(&f, ilt, tsz, 0x2400, false);
    put(&f, ilt + (size_t)tsz, tsz, ord_flag | 17, false);
    size_t ilt2 = pe_off(0x2140);
    put(&f, ilt2, tsz, 0x2420, false);

    puts_at(&f, pe_off(0x2200), "KERNEL32.dll");
    puts_at(&f, pe_off(0x2210), "USER32.dll");
    put16(&f, pe_off(0x2400), 0x123);
    puts_at(&f, pe_off(0x2400) + 2, "ExitProcess");
    put16(&f, pe_off(0x2420), 0x45);
    puts_at(&f, pe_off(0x2420) + 2, "MessageBoxA");

    /* exports */
    size_t e = pe_off(PE_EXPORT_RVA);
    put32(&f, e + 12, 0x2600); /* dll name */
    put32(&f, e + 16, 1);      /* ordinal base */
    put32(&f, e + 20, 3);      /* number of functions */
    put32(&f, e + 24, 2);      /* number of names */
    put32(&f, e + 28, 0x2540); /* address table */
    put32(&f, e + 32, 0x2550); /* name table */
    put32(&f, e + 36, 0x2560); /* ordinal table */
    put32(&f, pe_off(0x2540), 0x1010);
    put32(&f, pe_off(0x2544), 0x2650); /* inside the export directory: a forwarder */
    put32(&f, pe_off(0x2548), 0x1020);
    put32(&f, pe_off(0x2550), 0x2620);
    put32(&f, pe_off(0x2554), 0x2630);
    put16(&f, pe_off(0x2560), 0);
    put16(&f, pe_off(0x2562), 1);
    puts_at(&f, pe_off(0x2600), "loupe_test.dll");
    puts_at(&f, pe_off(0x2620), "alpha");
    puts_at(&f, pe_off(0x2630), "beta");
    puts_at(&f, pe_off(0x2650), "KERNEL32.ExitProcess");
    return f;
}

/*
 * An ELF shared object, in either class and byte order. Section and segment
 * data sit at fixed file offsets, and the single PT_LOAD maps the file 1:1,
 * so virtual addresses equal file offsets.
 */
#define ELF_PH_OFF     0x40
#define ELF_TEXT_OFF   0x100
#define ELF_DYNSTR_OFF 0x200
#define ELF_DYNSTR_SZ  0x100
#define ELF_DYNSYM_OFF 0x300
#define ELF_VERSYM_OFF 0x380
#define ELF_VERNEED_OFF 0x390
#define ELF_VERDEF_OFF 0x3c0
#define ELF_DYN_OFF    0x400
#define ELF_NOTE_OFF   0x500
#define ELF_SHSTR_OFF  0x560
#define ELF_SH_OFF     0x600
#define ELF_NSECTIONS  10
#define ELF_NSYMS      4

typedef struct elfx {
    bool   is64, be;
    size_t ehsize, phsize, shsize, symsize, dynsize, size;
    /* string table offsets, filled in by build_elf */
    uint32_t s_libc, s_soname, s_puts, s_export, s_chk, s_glibc, s_v1;
} elfx;

static void put_w(fx *f, const elfx *x, size_t off, uint64_t v)
{
    put(f, off, x->is64 ? 8 : 4, v, x->be);
}

static size_t add_str(fx *f, size_t *cursor, const char *s)
{
    size_t at = *cursor;
    puts_at(f, at, s);
    *cursor += strlen(s) + 1;
    return at - ELF_DYNSTR_OFF;
}

static fx build_elf(elfx *x)
{
    x->ehsize = x->is64 ? 64 : 52;
    x->phsize = x->is64 ? 56 : 32;
    x->shsize = x->is64 ? 64 : 40;
    x->symsize = x->is64 ? 24 : 16;
    x->dynsize = x->is64 ? 16 : 8;
    x->size = ELF_SH_OFF + ELF_NSECTIONS * x->shsize;

    fx f = fx_new(x->size);
    const bool be = x->be;

    memcpy(f.b, "\x7f" "ELF", 4);
    put8(&f, 4, x->is64 ? 2 : 1);
    put8(&f, 5, be ? 2 : 1);
    put8(&f, 6, 1);          /* version */
    put8(&f, 7, 3);          /* os/abi: Linux */
    put(&f, 16, 2, 3, be);   /* e_type: DYN */
    put(&f, 18, 2, x->is64 ? 62 : 3, be); /* e_machine: x86-64 / i386 */
    put(&f, 20, 4, 1, be);   /* e_version */
    size_t p = 24;
    put_w(&f, x, p, 0x1000); /* e_entry */
    p += x->is64 ? 8 : 4;
    put_w(&f, x, p, ELF_PH_OFF);
    p += x->is64 ? 8 : 4;
    put_w(&f, x, p, ELF_SH_OFF);
    p += x->is64 ? 8 : 4;
    put(&f, p, 4, 0, be); /* e_flags */
    put(&f, p + 4, 2, (uint64_t)x->ehsize, be);
    put(&f, p + 6, 2, (uint64_t)x->phsize, be);
    put(&f, p + 8, 2, 5, be); /* e_phnum */
    put(&f, p + 10, 2, (uint64_t)x->shsize, be);
    put(&f, p + 12, 2, ELF_NSECTIONS, be);
    put(&f, p + 14, 2, ELF_NSECTIONS - 1, be); /* e_shstrndx */

    /* strings */
    size_t cursor = ELF_DYNSTR_OFF + 1;
    x->s_libc = (uint32_t)add_str(&f, &cursor, "libc.so.6");
    x->s_soname = (uint32_t)add_str(&f, &cursor, "libtest.so");
    x->s_puts = (uint32_t)add_str(&f, &cursor, "puts");
    x->s_export = (uint32_t)add_str(&f, &cursor, "exported_fn");
    x->s_chk = (uint32_t)add_str(&f, &cursor, "__stack_chk_fail");
    x->s_glibc = (uint32_t)add_str(&f, &cursor, "GLIBC_2.2.5");
    x->s_v1 = (uint32_t)add_str(&f, &cursor, "V1");

    /* program headers */
    struct {
        uint32_t type, flags;
        uint64_t off, vaddr, filesz, memsz, align;
    } phs[5] = {
        {1, 5, 0, 0, x->size, x->size, 0x1000},                       /* LOAD r-x */
        {2, 6, ELF_DYN_OFF, ELF_DYN_OFF, 0, 0, 8},                    /* DYNAMIC */
        {4, 4, ELF_NOTE_OFF, ELF_NOTE_OFF, 24, 24, 4},                /* NOTE */
        {0x6474e551u, 6, 0, 0, 0, 0, 0x10},                           /* GNU_STACK rw- */
        {0x6474e552u, 4, ELF_DYN_OFF, ELF_DYN_OFF, 0x100, 0x100, 1},  /* GNU_RELRO */
    };
    const size_t ndyn = 14;
    phs[1].filesz = phs[1].memsz = ndyn * x->dynsize;
    for (int i = 0; i < 5; i++) {
        size_t s = ELF_PH_OFF + (size_t)i * x->phsize;
        put(&f, s, 4, phs[i].type, be);
        if (x->is64) {
            put(&f, s + 4, 4, phs[i].flags, be);
            put(&f, s + 8, 8, phs[i].off, be);
            put(&f, s + 16, 8, phs[i].vaddr, be);
            put(&f, s + 24, 8, phs[i].vaddr, be);
            put(&f, s + 32, 8, phs[i].filesz, be);
            put(&f, s + 40, 8, phs[i].memsz, be);
            put(&f, s + 48, 8, phs[i].align, be);
        } else {
            put(&f, s + 4, 4, phs[i].off, be);
            put(&f, s + 8, 4, phs[i].vaddr, be);
            put(&f, s + 12, 4, phs[i].vaddr, be);
            put(&f, s + 16, 4, phs[i].filesz, be);
            put(&f, s + 20, 4, phs[i].memsz, be);
            put(&f, s + 24, 4, phs[i].flags, be);
            put(&f, s + 28, 4, phs[i].align, be);
        }
    }

    /* dynamic symbols: undefined puts and __stack_chk_fail, defined
     * exported_fn */
    struct {
        uint32_t name;
        uint8_t  info;
        uint16_t shndx;
        uint64_t value, size;
    } syms[ELF_NSYMS] = {
        {0, 0, 0, 0, 0},
        {x->s_puts, 0x12, 0, 0, 0},           /* GLOBAL FUNC, UND */
        {x->s_export, 0x12, 1, 0x1130, 20},   /* GLOBAL FUNC, defined */
        {x->s_chk, 0x12, 0, 0, 0},
    };
    for (int i = 0; i < ELF_NSYMS; i++) {
        size_t s = ELF_DYNSYM_OFF + (size_t)i * x->symsize;
        put(&f, s, 4, syms[i].name, be);
        if (x->is64) {
            put8(&f, s + 4, syms[i].info);
            put(&f, s + 6, 2, syms[i].shndx, be);
            put(&f, s + 8, 8, syms[i].value, be);
            put(&f, s + 16, 8, syms[i].size, be);
        } else {
            put(&f, s + 4, 4, syms[i].value, be);
            put(&f, s + 8, 4, syms[i].size, be);
            put8(&f, s + 12, syms[i].info);
            put(&f, s + 14, 2, syms[i].shndx, be);
        }
    }

    /* .gnu.version: puts needs version 2, exported_fn defines version 3 */
    put(&f, ELF_VERSYM_OFF + 2, 2, 2, be);
    put(&f, ELF_VERSYM_OFF + 4, 2, 3, be);
    put(&f, ELF_VERSYM_OFF + 6, 2, 2, be);

    /* .gnu.version_r: libc.so.6 needs GLIBC_2.2.5 as version index 2 */
    put(&f, ELF_VERNEED_OFF + 0, 2, 1, be);           /* vn_version */
    put(&f, ELF_VERNEED_OFF + 2, 2, 1, be);           /* vn_cnt */
    put(&f, ELF_VERNEED_OFF + 4, 4, x->s_libc, be);   /* vn_file */
    put(&f, ELF_VERNEED_OFF + 8, 4, 16, be);          /* vn_aux */
    put(&f, ELF_VERNEED_OFF + 12, 4, 0, be);          /* vn_next */
    put(&f, ELF_VERNEED_OFF + 16 + 6, 2, 2, be);      /* vna_other */
    put(&f, ELF_VERNEED_OFF + 16 + 8, 4, x->s_glibc, be); /* vna_name */

    /* .gnu.version_d: this object defines V1 as version index 3 */
    put(&f, ELF_VERDEF_OFF + 0, 2, 1, be);            /* vd_version */
    put(&f, ELF_VERDEF_OFF + 4, 2, 3, be);            /* vd_ndx */
    put(&f, ELF_VERDEF_OFF + 6, 2, 1, be);            /* vd_cnt */
    put(&f, ELF_VERDEF_OFF + 12, 4, 20, be);          /* vd_aux */
    put(&f, ELF_VERDEF_OFF + 16, 4, 0, be);           /* vd_next */
    put(&f, ELF_VERDEF_OFF + 20, 4, x->s_v1, be);     /* vda_name */

    /* .dynamic */
    struct { uint64_t tag, val; } dyn[14] = {
        {1, 0},                       /* NEEDED, patched below */
        {14, 0},                      /* SONAME */
        {5, ELF_DYNSTR_OFF},          /* STRTAB */
        {10, ELF_DYNSTR_SZ},          /* STRSZ */
        {6, ELF_DYNSYM_OFF},          /* SYMTAB */
        {11, 0},                      /* SYMENT */
        {0x6ffffff0u, ELF_VERSYM_OFF},
        {0x6ffffffeu, ELF_VERNEED_OFF},
        {0x6fffffffu, 1},             /* VERNEEDNUM */
        {0x6ffffffcu, ELF_VERDEF_OFF},
        {0x6ffffffdu, 1},             /* VERDEFNUM */
        {30, 8},                      /* FLAGS: BIND_NOW */
        {0x6ffffffbu, 1},             /* FLAGS_1: NOW */
        {0, 0},                       /* NULL */
    };
    dyn[0].val = x->s_libc;
    dyn[1].val = x->s_soname;
    dyn[5].val = x->symsize;
    for (size_t i = 0; i < ndyn; i++) {
        size_t s = ELF_DYN_OFF + i * x->dynsize;
        put_w(&f, x, s, dyn[i].tag);
        put_w(&f, x, s + (x->is64 ? 8 : 4), dyn[i].val);
    }

    /* a GNU build-id note */
    put(&f, ELF_NOTE_OFF + 0, 4, 4, be);
    put(&f, ELF_NOTE_OFF + 4, 4, 8, be);
    put(&f, ELF_NOTE_OFF + 8, 4, 3, be); /* NT_GNU_BUILD_ID */
    memcpy(f.b + ELF_NOTE_OFF + 12, "GNU\0", 4);
    memcpy(f.b + ELF_NOTE_OFF + 16, "\x01\x23\x45\x67\x89\xab\xcd\xef", 8);

    /* section headers and their names */
    struct {
        const char *name;
        uint32_t type, link, info;
        uint64_t flags, addr, off, size, entsize;
    } shs[ELF_NSECTIONS] = {
        {"", 0, 0, 0, 0, 0, 0, 0, 0},
        {".text", 1, 0, 0, 6, ELF_TEXT_OFF, ELF_TEXT_OFF, 0x10, 0},
        {".dynstr", 3, 0, 0, 2, ELF_DYNSTR_OFF, ELF_DYNSTR_OFF, ELF_DYNSTR_SZ, 0},
        {".dynsym", 11, 2, 1, 2, ELF_DYNSYM_OFF, ELF_DYNSYM_OFF, 0, 0},
        {".gnu.version", 0x6fffffffu, 3, 0, 2, ELF_VERSYM_OFF, ELF_VERSYM_OFF, 8, 2},
        {".gnu.version_r", 0x6ffffffeu, 2, 1, 2, ELF_VERNEED_OFF, ELF_VERNEED_OFF, 32, 0},
        {".gnu.version_d", 0x6ffffffdu, 2, 1, 2, ELF_VERDEF_OFF, ELF_VERDEF_OFF, 28, 0},
        {".dynamic", 6, 2, 0, 3, ELF_DYN_OFF, ELF_DYN_OFF, 0, 0},
        {".note.gnu.build-id", 7, 0, 0, 2, ELF_NOTE_OFF, ELF_NOTE_OFF, 24, 0},
        {".shstrtab", 3, 0, 0, 0, 0, ELF_SHSTR_OFF, 0, 0},
    };
    shs[3].size = ELF_NSYMS * x->symsize;
    shs[3].entsize = x->symsize;
    shs[7].size = ndyn * x->dynsize;
    shs[7].entsize = x->dynsize;

    size_t names = ELF_SHSTR_OFF + 1;
    for (int i = 0; i < ELF_NSECTIONS; i++) {
        size_t s = ELF_SH_OFF + (size_t)i * x->shsize;
        uint32_t name_off = 0;
        if (shs[i].name[0]) {
            name_off = (uint32_t)(names - ELF_SHSTR_OFF);
            puts_at(&f, names, shs[i].name);
            names += strlen(shs[i].name) + 1;
        }
        put(&f, s, 4, name_off, be);
        put(&f, s + 4, 4, shs[i].type, be);
        if (x->is64) {
            put(&f, s + 8, 8, shs[i].flags, be);
            put(&f, s + 16, 8, shs[i].addr, be);
            put(&f, s + 24, 8, shs[i].off, be);
            put(&f, s + 32, 8, shs[i].size, be);
            put(&f, s + 40, 4, shs[i].link, be);
            put(&f, s + 44, 4, shs[i].info, be);
            put(&f, s + 48, 8, 1, be);
            put(&f, s + 56, 8, shs[i].entsize, be);
        } else {
            put(&f, s + 8, 4, shs[i].flags, be);
            put(&f, s + 12, 4, shs[i].addr, be);
            put(&f, s + 16, 4, shs[i].off, be);
            put(&f, s + 20, 4, shs[i].size, be);
            put(&f, s + 24, 4, shs[i].link, be);
            put(&f, s + 28, 4, shs[i].info, be);
            put(&f, s + 32, 4, 1, be);
            put(&f, s + 36, 4, shs[i].entsize, be);
        }
    }
    put(&f, ELF_SH_OFF + (ELF_NSECTIONS - 1) * x->shsize + (x->is64 ? 32 : 20),
        x->is64 ? 8 : 4, names - ELF_SHSTR_OFF, be); /* .shstrtab size */
    return f;
}

/* ---- running the parser -------------------------------------------------- */

static lp_result inspect(const uint8_t *data, size_t size, unsigned what, lp_out *out)
{
    lp_image *img = NULL;
    lp_opts opts = {what, false};
    lp_out_capture(out);
    if (lp_image_wrap(data, size, &img) != LP_OK) {
        lp_out_free(out);
        exit(2);
    }
    lp_result r = lp_inspect(img, "fixture", &opts, out);
    lp_image_free(img);
    return r;
}

static const char *text(const lp_out *o) { return o->buf ? o->buf : ""; }

/* Parse and throw the output away: for the cases where only "does not
 * crash, does not leak, does not hang" matters. */
static lp_result quiet(const uint8_t *data, size_t size)
{
    lp_out out;
    lp_result r = inspect(data, size, LP_SHOW_ALL, &out);
    lp_out_free(&out);
    return r;
}

/* ---- tests: the bounds-checked layer ------------------------------------- */

static void test_slices(void)
{
    start("bounds: slices");
    static const uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    lp_image *img;
    CHECK(lp_image_wrap(data, sizeof data, &img) == LP_OK);
    lp_slice s;

    CHECK(lp_slice_at(img, 0, 8, false, &s) == LP_OK);
    CHECK(lp_u32(&s) == 0x04030201);
    CHECK(lp_u32(&s) == 0x08070605);
    CHECK(lp_ok(&s));
    CHECK(lp_u8(&s) == 0); /* one byte too far */
    CHECK(!lp_ok(&s));

    CHECK(lp_slice_at(img, 0, 8, true, &s) == LP_OK);
    CHECK(lp_u16(&s) == 0x0102);
    CHECK(lp_u32(&s) == 0x03040506);
    CHECK(lp_slice_at(img, 0, 8, true, &s) == LP_OK);
    CHECK(lp_u64(&s) == 0x0102030405060708ull);

    /* past the end, and arithmetic that would wrap */
    CHECK(lp_slice_at(img, 0, 9, false, &s) == LP_ERR_RANGE);
    CHECK(!lp_ok(&s));
    CHECK(lp_u8(&s) == 0);
    CHECK(lp_slice_at(img, 9, 0, false, &s) == LP_ERR_RANGE);
    CHECK(lp_slice_at(img, 8, 0, false, &s) == LP_OK); /* empty at the end is fine */
    CHECK(lp_slice_at(img, UINT64_MAX, 8, false, &s) == LP_ERR_OVERFLOW);
    /* exactly 2^64, the sum that wraps to zero */
    CHECK(lp_slice_at(img, UINT64_MAX - 3, 4, false, &s) == LP_ERR_OVERFLOW);
    CHECK(lp_slice_at(img, UINT64_MAX - 3, 3, false, &s) == LP_ERR_RANGE);
    CHECK(lp_slice_at(img, 1ull << 40, 8, false, &s) == LP_ERR_RANGE);

    /* a header claiming an absurd size gets nothing */
    CHECK(lp_slice_at(img, 4, 0xffffffffull, false, &s) == LP_ERR_RANGE);
    CHECK(lp_u8(&s) == 0);

    CHECK(lp_slice_at(img, 0, 8, false, &s) == LP_OK);
    lp_seek(&s, 9);
    CHECK(!lp_ok(&s));

    uint32_t v;
    CHECK(lp_read_u32(img, 4, false, &v) == LP_OK && v == 0x08070605);
    CHECK(lp_read_u32(img, 5, false, &v) == LP_ERR_RANGE && v == 0);

    lp_image_free(img);
    CHECK(lp_live_allocations() == 0);
}

static void test_strings(void)
{
    start("bounds: strings");
    static const uint8_t data[] = "abc\0defghij"; /* no terminator after "defghij" */
    lp_image *img;
    CHECK(lp_image_wrap(data, sizeof data - 1, &img) == LP_OK);
    lp_str s;

    CHECK(lp_read_str(img, 0, 100, &s) == LP_OK);
    CHECK(s.terminated && !s.truncated && s.len == 3 && !strcmp(s.s, "abc"));

    /* runs to the end of the file without a NUL */
    CHECK(lp_read_str(img, 4, 100, &s) == LP_OK);
    CHECK(!s.terminated && !s.truncated && !strcmp(s.s, "defghij"));

    /* the caller's limit is honoured even when the file has more */
    CHECK(lp_read_str(img, 0, 2, &s) == LP_OK);
    CHECK(!s.terminated && s.len == 2 && !strcmp(s.s, "ab"));

    CHECK(lp_read_str(img, 11, 10, &s) == LP_ERR_RANGE);
    CHECK(s.len == 0 && s.s[0] == '\0');
    lp_image_free(img);

    /* longer than the largest name Loupe keeps */
    size_t big = LP_STR_MAX + 64;
    uint8_t *blob = malloc(big);
    memset(blob, 'x', big);
    CHECK(lp_image_wrap(blob, big, &img) == LP_OK);
    CHECK(lp_read_str(img, 0, big, &s) == LP_OK);
    CHECK(s.truncated && !s.terminated && s.len == LP_STR_MAX);
    CHECK(s.s[LP_STR_MAX] == '\0');
    lp_image_free(img);
    free(blob);

    /* escaping keeps control bytes out of the terminal */
    lp_str raw;
    memcpy(raw.s, "a\x1b[31mb", 8);
    raw.len = 7;
    raw.terminated = true;
    raw.truncated = false;
    char esc[LP_ESC_MAX];
    lp_esc(&raw, esc, sizeof esc);
    CHECK(!strcmp(esc, "a\\x1b[31mb"));
    CHECK(lp_live_allocations() == 0);
}

static void test_tiny_inputs(void)
{
    start("bounds: tiny and empty inputs");
    static const uint8_t empty[1] = {0};
    lp_result r = quiet(empty, 0);
    CHECK(r.status == LP_STATUS_UNSUPPORTED);

    /* No bytes and no pointer at all */
    lp_image *img;
    lp_slice s;
    CHECK(lp_image_wrap(NULL, 0, &img) == LP_OK);
    CHECK(lp_image_size(img) == 0);
    CHECK(lp_slice_at(img, 0, 0, false, &s) == LP_OK);
    CHECK(lp_slice_at(img, 0, 1, false, &s) == LP_ERR_RANGE);
    CHECK(lp_u8(&s) == 0);
    lp_image_free(img);
    CHECK(lp_image_wrap(NULL, 1, &img) == LP_ERR_RANGE);
    r = quiet((const uint8_t *)"M", 1);
    CHECK(r.status == LP_STATUS_UNSUPPORTED);
    r = quiet((const uint8_t *)"MZ", 2);
    CHECK(r.status == LP_STATUS_MALFORMED);
    r = quiet((const uint8_t *)"\x7f" "EL", 3);
    CHECK(r.status == LP_STATUS_UNSUPPORTED);
    r = quiet((const uint8_t *)"\x7f" "ELF", 4);
    CHECK(r.status == LP_STATUS_MALFORMED);
    CHECK(lp_live_allocations() == 0);
}

/* ---- tests: PE ----------------------------------------------------------- */

static void check_valid_pe(bool is64)
{
    fx f = build_pe(is64);
    lp_out out;
    lp_result r = inspect(f.b, f.n, LP_SHOW_ALL, &out);
    const char *t = text(&out);

    CHECK(r.format == LP_FORMAT_PE);
    if (r.status != LP_STATUS_OK) {
        failures++;
        printf("  FAIL %s fixture is not clean: %s\n", is64 ? "PE32+" : "PE32", r.message);
        printf("%s\n", t);
    }
    checks++;
    CHECK(r.warnings == 0);
    CHECK_HAS(t, is64 ? "PE32+" : "PE32");
    CHECK_HAS(t, ".rdata");
    CHECK_HAS(t, "KERNEL32.dll");
    CHECK_HAS(t, "ExitProcess");
    CHECK_HAS(t, "#17");
    CHECK_HAS(t, "USER32.dll");
    CHECK_HAS(t, "MessageBoxA");
    CHECK_HAS(t, "loupe_test.dll");
    CHECK_HAS(t, "alpha");
    CHECK_HAS(t, "beta");
    CHECK_HAS(t, "-> KERNEL32.ExitProcess");
    CHECK_HAS(t, "[NONAME]");
    CHECK_HAS(t, "IMPORTS  2 modules, 3 functions");
    lp_out_free(&out);
    fx_free(&f);
    CHECK(lp_live_allocations() == 0);
}

static void test_pe_valid(void)
{
    start("PE: a well-formed image");
    check_valid_pe(true);
    check_valid_pe(false);
}

/* Each case corrupts one field of a valid image. All of them must be
 * reported, and none of them may crash, hang or leak. */
static void test_pe_hostile(void)
{
    start("PE: hostile headers");
    const size_t coff = PE_NT + 4;
    const size_t opt = coff + 20;
    const size_t dirs = opt + 112;
    struct {
        const char *what;
        size_t      off;
        int         size;
        uint64_t    value;
        const char *expect;
    } cases[] = {
        {"e_lfanew past EOF", 0x3c, 4, 0xfffffff0, NULL},
        {"e_lfanew inside itself", 0x3c, 4, 0x3c, NULL},
        {"65535 sections", coff + 2, 2, 0xffff, "only"},
        {"absurd NumberOfRvaAndSizes", opt + 108, 4, 0xffffffff, "data director"},
        {"SizeOfOptionalHeader 0", coff + 16, 2, 0, NULL},
        {"SizeOfHeaders past EOF", opt + 60, 4, 0xffffff00, "SizeOfHeaders"},
        {"FileAlignment not a power of two", opt + 36, 4, 0x123, "power of two"},
        {"section raw size claims 4 GiB", opt + 112 + 128 + 40 + 16, 4, 0xffffffff,
         "past the end of the file"},
        {"import directory into .bss", dirs + 8, 4, 0x3000, "zero-filled"},
        {"import directory unmapped", dirs + 8, 4, 0x90000000, "maps to no section"},
        {"export table count overflow", 0, 0, 0, "only"},
        {"export names past the file", 0, 0, 0, NULL},
        {"forwarder with no terminator", 0, 0, 0, "not terminated"},
        {"import name unmapped", 0, 0, 0, "maps to no section"},
        {"import lookup table unterminated", 0, 0, 0, NULL},
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fx f = build_pe(true);
        switch (i) {
        case 10: /* NumberOfFunctions = 4 billion */
            put32(&f, pe_off(PE_EXPORT_RVA) + 20, 0xffffffff);
            break;
        case 11: /* AddressOfNames points outside any section */
            put32(&f, pe_off(PE_EXPORT_RVA) + 32, 0x90000000);
            break;
        case 12: /* forwarder string runs to the end of the export directory */
            put32(&f, pe_off(0x2544), PE_EXPORT_RVA + PE_EXPORT_SIZE - 1);
            memset(f.b + pe_off(PE_EXPORT_RVA + PE_EXPORT_SIZE - 1), 'A', 1);
            break;
        case 13: /* module name RVA maps nowhere */
            put32(&f, pe_off(0x2000) + 12, 0x90000000);
            break;
        case 14: /* fill the lookup table to the end of the section */
            for (size_t o = pe_off(0x2100); o < PE_RDATA_OFF + 0x800; o += 8)
                put64(&f, o, 0x2400);
            break;
        default:
            put(&f, cases[i].off, cases[i].size, cases[i].value, false);
            break;
        }

        lp_out out;
        lp_result r = inspect(f.b, f.n, LP_SHOW_ALL, &out);
        const char *t = text(&out);
        checks++;
        if (r.status == LP_STATUS_OK) {
            failures++;
            printf("  FAIL \"%s\" was accepted without complaint\n", cases[i].what);
        }
        if (cases[i].expect && r.status != LP_STATUS_MALFORMED &&
            r.status != LP_STATUS_UNSUPPORTED) {
            checks++;
            if (!strstr(t, cases[i].expect)) {
                failures++;
                printf("  FAIL \"%s\": no warning mentioning \"%s\"\n", cases[i].what,
                       cases[i].expect);
            }
        }
        lp_out_free(&out);
        fx_free(&f);
        CHECK(lp_live_allocations() == 0);
    }
}

/* ---- tests: ELF ---------------------------------------------------------- */

static void check_valid_elf(bool is64, bool be)
{
    elfx x = {is64, be, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fx f = build_elf(&x);
    lp_out out;
    lp_result r = inspect(f.b, f.n, LP_SHOW_ALL, &out);
    const char *t = text(&out);

    CHECK(r.format == LP_FORMAT_ELF);
    if (r.status != LP_STATUS_OK) {
        failures++;
        printf("  FAIL ELF%d %s fixture is not clean: %s\n", is64 ? 64 : 32,
               be ? "BE" : "LE", r.message);
        printf("%s\n", t);
    }
    checks++;
    CHECK_HAS(t, is64 ? "ELF64" : "ELF32");
    CHECK_HAS(t, be ? "big-endian" : "little-endian");
    CHECK_HAS(t, ".dynsym");
    CHECK_HAS(t, ".note.gnu.build-id");
    CHECK_HAS(t, "0123456789abcdef");   /* build id */
    CHECK_HAS(t, "libc.so.6");
    CHECK_HAS(t, "libtest.so");         /* SONAME */
    CHECK_HAS(t, "puts@GLIBC_2.2.5");   /* needed version */
    CHECK_HAS(t, "exported_fn@@V1");    /* defined version */
    CHECK_HAS(t, "__stack_chk_fail");
    CHECK_HAS(t, "Stack canary");
    CHECK_HAS(t, "BIND_NOW");
    CHECK_HAS(t, "full (GNU_RELRO + BIND_NOW)");
    lp_out_free(&out);
    fx_free(&f);
    CHECK(lp_live_allocations() == 0);
}

static void test_elf_valid(void)
{
    start("ELF: well-formed images, both classes and byte orders");
    check_valid_elf(true, false);
    check_valid_elf(true, true);
    check_valid_elf(false, false);
    check_valid_elf(false, true);
}

/*
 * A GNU property note whose descsz does not include the padding of its last
 * property. Walking it by padded steps runs the cursor past the end of the
 * descriptor, and an unsigned "bytes remaining" then wraps to something
 * enormous: the property walk has to notice and stop.
 */
static void test_elf_note_padding(void)
{
    start("ELF: a note whose last property is not padded");
    elfx x = {true, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fx f = build_elf(&x);

    /* Make the PT_NOTE segment 28 bytes: 12 header + 4 name + 12 descriptor. */
    size_t note_ph = ELF_PH_OFF + 2 * x.phsize;
    put64(&f, note_ph + 32, 28); /* p_filesz */
    put64(&f, note_ph + 40, 28); /* p_memsz */

    put32(&f, ELF_NOTE_OFF + 4, 12); /* descsz, one property, no tail padding */
    put32(&f, ELF_NOTE_OFF + 8, 5);  /* NT_GNU_PROPERTY_TYPE_0 */
    put32(&f, ELF_NOTE_OFF + 16, 0xc0000002); /* x86 feature bits */
    put32(&f, ELF_NOTE_OFF + 20, 4);          /* datasz */
    put32(&f, ELF_NOTE_OFF + 24, 3);          /* IBT and SHSTK */

    lp_out out;
    lp_result r = inspect(f.b, f.n, LP_SHOW_ALL, &out);
    CHECK(r.status == LP_STATUS_OK);
    CHECK_HAS(text(&out), "IBT on, SHSTK on");
    lp_out_free(&out);
    fx_free(&f);
    CHECK(lp_live_allocations() == 0);
}

static void test_elf_hostile(void)
{
    start("ELF: hostile headers");
    struct {
        const char *what;
        int         patch;
        const char *expect;
    } cases[] = {
        {"e_shnum beyond the file", 0, "fit in the file"},
        {"e_shentsize 0", 1, "smaller than a section header"},
        {"e_phentsize 0", 2, "smaller than a program header"},
        {"e_shoff near the 64-bit limit", 3, NULL},
        {"e_shstrndx out of range", 4, "not a valid section"},
        {"dynamic section with no DT_NULL", 5, "DT_NULL"},
        {"DT_STRTAB outside every segment", 6, "not inside any PT_LOAD"},
        {"symbol table linked to itself", 7, NULL},
        {"symbol name past the string table", 8, "outside its string table"},
        {"verneed count of 4 billion", 9, "version entries but only"},
        {"note with an absurd namesz", 10, "past the end"},
        {"section data past the end of the file", 11, "past the end of the file"},
        {"segment data past the end of the file", 12, "past the end of the file"},
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        elfx x = {true, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        fx f = build_elf(&x);
        const size_t eh_shnum = 60, eh_shent = 58, eh_phent = 54, eh_shoff = 40,
                     eh_shstrndx = 62;
        switch (cases[i].patch) {
        case 0:  put16(&f, eh_shnum, 0xfeff); break;
        case 1:  put16(&f, eh_shent, 0); break;
        case 2:  put16(&f, eh_phent, 0); break;
        case 3:  put64(&f, eh_shoff, 0xfffffffffffffff0ull); break;
        case 4:  put16(&f, eh_shstrndx, 0x7f00); break;
        case 5:  put64(&f, ELF_DYN_OFF + 13 * 16, 1); break; /* NULL -> NEEDED */
        case 6:  put64(&f, ELF_DYN_OFF + 2 * 16 + 8, 0x7fffffff0000ull); break;
        case 7:  put32(&f, ELF_SH_OFF + 3 * 64 + 40, 3); break;
        case 8:  put32(&f, ELF_DYNSYM_OFF + 24, 0xfff0); break;
        case 9:  put32(&f, ELF_SH_OFF + 5 * 64 + 44, 0xffffffff); break;
        case 10: put32(&f, ELF_NOTE_OFF, 0xfffffff0); break;
        case 11: put64(&f, ELF_SH_OFF + 2 * 64 + 32, 0xffffff00ull); break;
        case 12: put64(&f, ELF_PH_OFF + 32, 0xffffff00ull); break;
        default: break;
        }

        lp_out out;
        lp_result r = inspect(f.b, f.n, LP_SHOW_ALL, &out);
        const char *t = text(&out);
        checks++;
        if (r.status == LP_STATUS_OK) {
            failures++;
            printf("  FAIL \"%s\" was accepted without complaint\n", cases[i].what);
        }
        if (cases[i].expect) {
            checks++;
            if (!strstr(t, cases[i].expect)) {
                failures++;
                printf("  FAIL \"%s\": no warning mentioning \"%s\"\n", cases[i].what,
                       cases[i].expect);
            }
        }
        lp_out_free(&out);
        fx_free(&f);
        CHECK(lp_live_allocations() == 0);
    }
}

/* ---- tests: brute force -------------------------------------------------- */

/* Every prefix of every fixture: the file stops in a different place each
 * time, which is the commonest shape of malformed input there is. */
static void test_truncation(void)
{
    start("brute force: every truncation of every fixture");
    fx fixtures[6];
    size_t n = 0;
    fixtures[n++] = build_pe(true);
    fixtures[n++] = build_pe(false);
    for (int i = 0; i < 4; i++) {
        elfx x = {(i & 1) != 0, (i & 2) != 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        fixtures[n++] = build_elf(&x);
    }

    unsigned long parsed = 0;
    for (size_t i = 0; i < n; i++) {
        for (size_t len = 0; len <= fixtures[i].n; len++) {
            quiet(fixtures[i].b, len);
            parsed++;
            if (lp_live_allocations() != 0) {
                failures++;
                printf("  FAIL leak after parsing %zu bytes of fixture %zu\n", len, i);
                break;
            }
        }
        fx_free(&fixtures[i]);
    }
    checks++;
    printf("  %lu truncated images parsed\n", parsed);
    CHECK(lp_live_allocations() == 0);
}

/* Every byte of every header region, replaced with the values most likely
 * to break a parser. */
static void test_byte_mutations(void)
{
    start("brute force: single-byte mutations of the headers");
    static const uint8_t values[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
    fx fixtures[6];
    size_t n = 0;
    fixtures[n++] = build_pe(true);
    fixtures[n++] = build_pe(false);
    for (int i = 0; i < 4; i++) {
        elfx x = {(i & 1) != 0, (i & 2) != 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        fixtures[n++] = build_elf(&x);
    }

    unsigned long parsed = 0;
    for (size_t i = 0; i < n; i++) {
        fx *f = &fixtures[i];
        size_t region = f->n < 0x700 ? f->n : 0x700;
        for (size_t off = 0; off < region; off++) {
            uint8_t save = f->b[off];
            for (size_t v = 0; v < sizeof values; v++) {
                if (values[v] == save)
                    continue;
                f->b[off] = values[v];
                quiet(f->b, f->n);
                parsed++;
                if (lp_live_allocations() != 0) {
                    failures++;
                    printf("  FAIL leak after mutating byte %zu of fixture %zu\n", off, i);
                    goto next;
                }
            }
            f->b[off] = save;
        }
    next:
        fx_free(f);
    }
    checks++;
    printf("  %lu mutated images parsed\n", parsed);
    CHECK(lp_live_allocations() == 0);
}

int main(void)
{
    printf("loupe %s test suite\n\n", LOUPE_VERSION);
    test_slices();
    test_strings();
    test_tiny_inputs();
    test_pe_valid();
    test_pe_hostile();
    test_elf_valid();
    test_elf_note_padding();
    test_elf_hostile();
    test_truncation();
    test_byte_mutations();

    printf("\n%d checks, %d failures, %ld allocations still live\n", checks, failures,
           lp_live_allocations());
    if (lp_live_allocations() != 0)
        failures++;
    return failures ? 1 : 0;
}
