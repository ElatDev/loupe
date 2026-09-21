/*
 * elf.c - ELF32 and ELF64 images, in either byte order.
 *
 *   0x00  ELF header: e_ident (magic, class, byte order, OS ABI) and the
 *         offsets of two tables: program headers (segments, the loader's
 *         view) and section headers (sections, the linker's view).
 *
 * The dynamic section refers to its string and symbol tables by virtual
 * address, so those are mapped back to file offsets through the PT_LOAD
 * segments: the ELF counterpart of PE's RVA translation.
 */
#include <stdio.h>
#include <string.h>

#include "loupe.h"
#include "mem.h"

enum { ELFCLASS32 = 1, ELFCLASS64 = 2 };
enum { ELFDATA2LSB = 1, ELFDATA2MSB = 2 };
enum { ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE };

#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_GNU_STACK    0x6474e551u
#define PT_GNU_RELRO    0x6474e552u

#define PF_X 1u
#define PF_W 2u
#define PF_R 4u

#define SHT_NULL          0
#define SHT_SYMTAB        2
#define SHT_STRTAB        3
#define SHT_DYNAMIC       6
#define SHT_NOTE          7
#define SHT_NOBITS        8
#define SHT_DYNSYM        11
#define SHT_GNU_VERDEF    0x6ffffffdu
#define SHT_GNU_VERNEED   0x6ffffffeu
#define SHT_GNU_VERSYM    0x6fffffffu

#define SHN_UNDEF  0
#define SHN_ABS    0xfff1
#define SHN_COMMON 0xfff2
#define SHN_XINDEX 0xffff
#define PN_XNUM    0xffff

#define DT_NULL       0
#define DT_NEEDED     1
#define DT_STRTAB     5
#define DT_STRSZ      10
#define DT_SONAME     14
#define DT_RPATH      15
#define DT_TEXTREL    22
#define DT_BIND_NOW   24
#define DT_RUNPATH    29
#define DT_FLAGS      30
#define DT_FLAGS_1    0x6ffffffbu
#define DT_AUXILIARY  0x7ffffffdu
#define DT_FILTER     0x7fffffffu
#define DF_BIND_NOW   0x8
#define DF_TEXTREL    0x4
#define DF_1_NOW      0x1
#define DF_1_PIE      0x08000000u

#define STT_SECTION 3
#define STT_FILE    4
#define STB_LOCAL   0

#define NT_GNU_ABI_TAG      1
#define NT_GNU_BUILD_ID     3
#define NT_GNU_PROPERTY     5
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000u
#define GNU_PROPERTY_X86_FEATURE_1_AND     0xc0000002u

#define EM_386     3
#define EM_X86_64  62
#define EM_AARCH64 183

#define MAX_NOTES 64

typedef struct elf_ph {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
} elf_ph;

typedef struct elf_sh {
    uint32_t name, type;
    uint64_t flags, addr, offset, size;
    uint32_t link, info;
    uint64_t addralign, entsize;
} elf_sh;

typedef struct elf_sym {
    uint32_t name;
    uint8_t  info, other;
    uint16_t shndx;
    uint64_t value, size;
} elf_sym;

/* A string table, already validated to lie inside the file. */
typedef struct strtab {
    bool     ok;
    uint64_t off, size;
} strtab;

typedef struct elf {
    lp_ctx         *c;
    const lp_image *img;
    uint64_t        size;
    bool            is64, be;

    uint8_t  osabi, abiver;
    uint16_t type, machine, ehsize, phentsize, shentsize;
    uint32_t version, flags;
    uint64_t entry, phoff, shoff;
    uint64_t phnum, shnum, shstrndx; /* after extended numbering */

    elf_ph  *ph;
    uint32_t nph;
    elf_sh  *sh;
    uint32_t nsh;
    strtab   shstr;

    /* dynamic section */
    bool     have_dyn;
    uint64_t dyn_off;
    uint32_t ndyn;       /* entries, up to and including DT_NULL */
    strtab   dynstr;
    uint64_t dt_flags, dt_flags1;
    bool     bind_now, textrel, rpath, runpath;

    /* sections used for symbols and versions, or -1 */
    long dynsym, symtab, versym, verneed, verdef;

    /* facts for the summaries */
    bool     interp_found;
    lp_str   interp;
    uint8_t  build_id[64];
    uint32_t build_id_len;
    bool     gnu_stack, stack_exec, relro;
    bool     canary;
    uint32_t fortified;
    bool     have_feature;
    uint32_t feature_1; /* x86 IBT/SHSTK or AArch64 BTI/PAC bits */
} elf;

/* ---- names for numbers -------------------------------------------------- */

static const char *machine_name(uint16_t m)
{
    switch (m) {
    case 0:   return "none";
    case 2:   return "SPARC";
    case 3:   return "i386";
    case 4:   return "Motorola 68000";
    case 5:   return "Motorola 88000";
    case 7:   return "Intel 80860";
    case 8:   return "MIPS";
    case 10:  return "MIPS RS3000 LE";
    case 15:  return "PA-RISC";
    case 18:  return "SPARC32PLUS";
    case 20:  return "PowerPC";
    case 21:  return "PowerPC64";
    case 22:  return "IBM S/390";
    case 40:  return "ARM";
    case 41:  return "Alpha";
    case 42:  return "SuperH";
    case 43:  return "SPARC V9";
    case 50:  return "IA-64";
    case 62:  return "x86-64";
    case 83:  return "AVR";
    case 94:  return "Xtensa";
    case 105: return "MSP430";
    case 106: return "Blackfin";
    case 113: return "Altera Nios II";
    case 140: return "TI C6000";
    case 164: return "Qualcomm Hexagon";
    case 183: return "AArch64";
    case 188: return "MicroBlaze";
    case 190: return "NVIDIA CUDA";
    case 220: return "Z80";
    case 224: return "AMD GPU";
    case 243: return "RISC-V";
    case 247: return "BPF";
    case 252: return "C-SKY";
    case 258: return "LoongArch";
    case 0x9026: return "Alpha (unofficial)";
    }
    return "unrecognised";
}

static const char *osabi_name(uint8_t a)
{
    switch (a) {
    case 0:   return "System V";
    case 1:   return "HP-UX";
    case 2:   return "NetBSD";
    case 3:   return "Linux";
    case 4:   return "GNU Hurd";
    case 6:   return "Solaris";
    case 7:   return "AIX";
    case 8:   return "IRIX";
    case 9:   return "FreeBSD";
    case 10:  return "Tru64";
    case 11:  return "Novell Modesto";
    case 12:  return "OpenBSD";
    case 13:  return "OpenVMS";
    case 14:  return "NonStop Kernel";
    case 15:  return "AROS";
    case 16:  return "FenixOS";
    case 17:  return "CloudABI";
    case 18:  return "OpenVOS";
    case 64:  return "ARM EABI";
    case 97:  return "ARM";
    case 255: return "standalone";
    }
    return "unrecognised";
}

static const char *type_name(uint16_t t)
{
    switch (t) {
    case ET_NONE: return "NONE";
    case ET_REL:  return "REL (relocatable object)";
    case ET_EXEC: return "EXEC (executable)";
    case ET_DYN:  return "DYN (shared object or PIE)";
    case ET_CORE: return "CORE (core dump)";
    }
    return t >= 0xfe00 ? "OS/processor specific" : "unrecognised";
}

static bool has_interp(const elf *e)
{
    for (uint32_t i = 0; i < e->nph; i++)
        if (e->ph[i].type == PT_INTERP)
            return true;
    return false;
}

static const char *kind_name(const elf *e)
{
    switch (e->type) {
    case ET_REL:  return "relocatable object";
    case ET_EXEC: return "executable";
    case ET_DYN:  return has_interp(e) || (e->dt_flags1 & DF_1_PIE) ? "PIE executable"
                                                                    : "shared object";
    case ET_CORE: return "core dump";
    }
    return "file";
}

/* 0x70000000 and up mean different things on different architectures, so
 * they can only be named once the machine is known. */
static const char *proc_name(uint16_t machine, uint32_t t)
{
    switch (machine) {
    case 40: /* ARM */
        if (t == 0x70000001u) return "ARM_EXIDX";
        if (t == 0x70000002u) return "ARM_PREEMPTMAP";
        if (t == 0x70000003u) return "ARM_ATTRIBUTES";
        break;
    case EM_AARCH64:
        if (t == 0x70000003u) return "AARCH64_ATTRIBUTES";
        break;
    case EM_X86_64:
        if (t == 0x70000001u) return "X86_64_UNWIND";
        break;
    case 243: /* RISC-V */
        if (t == 0x70000003u) return "RISCV_ATTRIBUTES";
        break;
    case 8: /* MIPS */
        if (t == 0x70000000u) return "MIPS_LIBLIST";
        if (t == 0x70000006u) return "MIPS_REGINFO";
        if (t == 0x7000000du) return "MIPS_OPTIONS";
        if (t == 0x7000001eu) return "MIPS_ABIFLAGS";
        break;
    case 50: /* IA-64 */
        if (t == 0x70000000u) return "IA_64_EXT";
        if (t == 0x70000001u) return "IA_64_UNWIND";
        break;
    default:
        break;
    }
    return NULL;
}

static const char *ptype_name(uint16_t machine, uint32_t t, char *buf, size_t n)
{
    const char *proc = t >= 0x70000000u ? proc_name(machine, t) : NULL;
    if (proc)
        return proc;
    switch (t) {
    case 0: return "NULL";
    case 1: return "LOAD";
    case 2: return "DYNAMIC";
    case 3: return "INTERP";
    case 4: return "NOTE";
    case 5: return "SHLIB";
    case 6: return "PHDR";
    case 7: return "TLS";
    case 0x6474e550u: return "GNU_EH_FRAME";
    case 0x6474e551u: return "GNU_STACK";
    case 0x6474e552u: return "GNU_RELRO";
    case 0x6474e553u: return "GNU_PROPERTY";
    case 0x6474e554u: return "GNU_SFRAME";
    case 0x65a3dbe6u: return "OPENBSD_RANDOMIZE";
    case 0x65a3dbe7u: return "OPENBSD_WXNEEDED";
    case 0x65a41be6u: return "OPENBSD_BOOTDATA";
    }
    snprintf(buf, n, "0x%08x", t);
    return buf;
}

static const char *shtype_name(uint16_t machine, uint32_t t, char *buf, size_t n)
{
    const char *proc = t >= 0x70000000u ? proc_name(machine, t) : NULL;
    if (proc)
        return proc;
    switch (t) {
    case 0:  return "NULL";
    case 1:  return "PROGBITS";
    case 2:  return "SYMTAB";
    case 3:  return "STRTAB";
    case 4:  return "RELA";
    case 5:  return "HASH";
    case 6:  return "DYNAMIC";
    case 7:  return "NOTE";
    case 8:  return "NOBITS";
    case 9:  return "REL";
    case 10: return "SHLIB";
    case 11: return "DYNSYM";
    case 14: return "INIT_ARRAY";
    case 15: return "FINI_ARRAY";
    case 16: return "PREINIT_ARRAY";
    case 17: return "GROUP";
    case 18: return "SYMTAB_SHNDX";
    case 19: return "RELR";
    case 0x60000001u: return "ANDROID_REL";
    case 0x60000002u: return "ANDROID_RELA";
    case 0x6fff4c00u: return "LLVM_ODRTAB";
    case 0x6fff4c01u: return "LLVM_LINKER_OPTIONS";
    case 0x6fff4c02u: return "LLVM_CALL_GRAPH";
    case 0x6fff4c03u: return "LLVM_ADDRSIG";
    case 0x6fff4c04u: return "LLVM_DEPENDENT_LIBS";
    case 0x6fff4c05u: return "LLVM_SYMPART";
    case 0x6fff4c06u: return "LLVM_PART_EHDR";
    case 0x6fff4c07u: return "LLVM_PART_PHDR";
    case 0x6fff4c08u: return "LLVM_BB_ADDR_MAP";
    case 0x6fffff00u: return "ANDROID_RELR";
    case 0x6ffffff5u: return "GNU_ATTRIBUTES";
    case 0x6ffffff6u: return "GNU_HASH";
    case 0x6ffffff7u: return "GNU_LIBLIST";
    case 0x6ffffff8u: return "CHECKSUM";
    case 0x6ffffffdu: return "VERDEF";
    case 0x6ffffffeu: return "VERNEED";
    case 0x6fffffffu: return "VERSYM";
    }
    snprintf(buf, n, "0x%08x", t);
    return buf;
}

static const char *dtag_name(uint64_t t, char *buf, size_t n)
{
    static const char *const low[] = {
        "NULL", "NEEDED", "PLTRELSZ", "PLTGOT", "HASH", "STRTAB", "SYMTAB",
        "RELA", "RELASZ", "RELAENT", "STRSZ", "SYMENT", "INIT", "FINI",
        "SONAME", "RPATH", "SYMBOLIC", "REL", "RELSZ", "RELENT", "PLTREL",
        "DEBUG", "TEXTREL", "JMPREL", "BIND_NOW", "INIT_ARRAY", "FINI_ARRAY",
        "INIT_ARRAYSZ", "FINI_ARRAYSZ", "RUNPATH", "FLAGS", "ENCODING",
        "PREINIT_ARRAY", "PREINIT_ARRAYSZ", "SYMTAB_SHNDX", "RELRSZ", "RELR",
        "RELRENT",
    };
    if (t < LP_COUNT(low) && t != 31)
        return low[t];
    switch (t) {
    case 0x6000000fu: return "ANDROID_REL";
    case 0x60000010u: return "ANDROID_RELSZ";
    case 0x60000011u: return "ANDROID_RELA";
    case 0x60000012u: return "ANDROID_RELASZ";
    case 0x6fffe000u: return "ANDROID_RELR";
    case 0x6fffe001u: return "ANDROID_RELRSZ";
    case 0x6fffe003u: return "ANDROID_RELRENT";
    case 0x6ffffdf5u: return "GNU_PRELINKED";
    case 0x6ffffdf6u: return "GNU_CONFLICTSZ";
    case 0x6ffffdf7u: return "GNU_LIBLISTSZ";
    case 0x6ffffdf8u: return "CHECKSUM";
    case 0x6ffffdf9u: return "PLTPADSZ";
    case 0x6ffffdfau: return "MOVEENT";
    case 0x6ffffdfbu: return "MOVESZ";
    case 0x6ffffdfcu: return "FEATURE_1";
    case 0x6ffffdfdu: return "POSFLAG_1";
    case 0x6ffffdfeu: return "SYMINSZ";
    case 0x6ffffdffu: return "SYMINENT";
    case 0x6ffffef5u: return "GNU_HASH";
    case 0x6ffffef6u: return "TLSDESC_PLT";
    case 0x6ffffef7u: return "TLSDESC_GOT";
    case 0x6ffffef8u: return "GNU_CONFLICT";
    case 0x6ffffef9u: return "GNU_LIBLIST";
    case 0x6ffffefau: return "CONFIG";
    case 0x6ffffefbu: return "DEPAUDIT";
    case 0x6ffffefcu: return "AUDIT";
    case 0x6ffffefdu: return "PLTPAD";
    case 0x6ffffefeu: return "MOVETAB";
    case 0x6ffffeffu: return "SYMINFO";
    case 0x6ffffff0u: return "VERSYM";
    case 0x6ffffff9u: return "RELACOUNT";
    case 0x6ffffffau: return "RELCOUNT";
    case 0x6ffffffbu: return "FLAGS_1";
    case 0x6ffffffcu: return "VERDEF";
    case 0x6ffffffdu: return "VERDEFNUM";
    case 0x6ffffffeu: return "VERNEED";
    case 0x6fffffffu: return "VERNEEDNUM";
    case 0x7ffffffdu: return "AUXILIARY";
    case 0x7ffffffeu: return "USED";
    case 0x7fffffffu: return "FILTER";
    }
    snprintf(buf, n, "0x%llx", (unsigned long long)t);
    return buf;
}

static const lp_flag df_flags[] = {
    {0x01, "ORIGIN"}, {0x02, "SYMBOLIC"}, {0x04, "TEXTREL"},
    {0x08, "BIND_NOW"}, {0x10, "STATIC_TLS"},
};

static const lp_flag df1_flags[] = {
    {0x00000001, "NOW"},        {0x00000002, "GLOBAL"},
    {0x00000004, "GROUP"},      {0x00000008, "NODELETE"},
    {0x00000010, "LOADFLTR"},   {0x00000020, "INITFIRST"},
    {0x00000040, "NOOPEN"},     {0x00000080, "ORIGIN"},
    {0x00000100, "DIRECT"},     {0x00000200, "TRANS"},
    {0x00000400, "INTERPOSE"},  {0x00000800, "NODEFLIB"},
    {0x00001000, "NODUMP"},     {0x00002000, "CONFALT"},
    {0x00004000, "ENDFILTEE"},  {0x00008000, "DISPRELDNE"},
    {0x00010000, "DISPRELPND"}, {0x00020000, "NODIRECT"},
    {0x00040000, "IGNMULDEF"},  {0x00080000, "NOKSYMS"},
    {0x00100000, "NOHDR"},      {0x00200000, "EDITED"},
    {0x00400000, "NORELOC"},    {0x00800000, "SYMINTPOSE"},
    {0x01000000, "GLOBAUDIT"},  {0x02000000, "SINGLETON"},
    {0x04000000, "STUB"},       {0x08000000, "PIE"},
};

static const char *sym_type(uint8_t info, char *buf, size_t n)
{
    static const char *const t[] = {"NOTYPE", "OBJECT", "FUNC", "SECTION",
                                    "FILE", "COMMON", "TLS"};
    unsigned v = info & 0xf;
    if (v < LP_COUNT(t))
        return t[v];
    if (v == 10)
        return "IFUNC";
    snprintf(buf, n, "<%u>", v);
    return buf;
}

static const char *sym_bind(uint8_t info, char *buf, size_t n)
{
    static const char *const b[] = {"LOCAL", "GLOBAL", "WEAK"};
    unsigned v = info >> 4;
    if (v < LP_COUNT(b))
        return b[v];
    if (v == 10)
        return "UNIQUE";
    snprintf(buf, n, "<%u>", v);
    return buf;
}

static const char *sym_vis(uint8_t other)
{
    static const char *const v[] = {"DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED"};
    return v[other & 3];
}

static void perm_str(uint32_t f, char *buf)
{
    buf[0] = (f & PF_R) ? 'r' : '-';
    buf[1] = (f & PF_W) ? 'w' : '-';
    buf[2] = (f & PF_X) ? 'x' : '-';
    buf[3] = '\0';
}

static void shflag_str(uint64_t f, char *buf, size_t n)
{
    static const struct { uint64_t bit; char ch; } map[] = {
        {0x1, 'W'}, {0x2, 'A'}, {0x4, 'X'}, {0x10, 'M'}, {0x20, 'S'},
        {0x40, 'I'}, {0x80, 'L'}, {0x100, 'O'}, {0x200, 'G'}, {0x400, 'T'},
        {0x800, 'C'}, {0x80000000u, 'E'},
    };
    size_t j = 0;
    uint64_t known = 0;
    for (size_t i = 0; i < LP_COUNT(map) && j + 1 < n; i++) {
        known |= map[i].bit;
        if (f & map[i].bit)
            buf[j++] = map[i].ch;
    }
    if ((f & ~known) && j + 1 < n)
        buf[j++] = 'x'; /* OS or processor specific bits */
    buf[j] = '\0';
}

/* ---- readers ------------------------------------------------------------ */

static bool read_ph(elf *e, uint64_t off, elf_ph *p)
{
    lp_slice s;
    if (lp_slice_at(e->img, off, e->is64 ? 56 : 32, e->be, &s) != LP_OK)
        return false;
    p->type = lp_u32(&s);
    if (e->is64) {
        p->flags = lp_u32(&s);
        p->offset = lp_u64(&s);
        p->vaddr = lp_u64(&s);
        p->paddr = lp_u64(&s);
        p->filesz = lp_u64(&s);
        p->memsz = lp_u64(&s);
        p->align = lp_u64(&s);
    } else {
        p->offset = lp_u32(&s);
        p->vaddr = lp_u32(&s);
        p->paddr = lp_u32(&s);
        p->filesz = lp_u32(&s);
        p->memsz = lp_u32(&s);
        p->flags = lp_u32(&s);
        p->align = lp_u32(&s);
    }
    return lp_ok(&s);
}

static bool read_sh(elf *e, uint64_t off, elf_sh *h)
{
    lp_slice s;
    if (lp_slice_at(e->img, off, e->is64 ? 64 : 40, e->be, &s) != LP_OK)
        return false;
    h->name = lp_u32(&s);
    h->type = lp_u32(&s);
    h->flags = lp_uword(&s, e->is64);
    h->addr = lp_uword(&s, e->is64);
    h->offset = lp_uword(&s, e->is64);
    h->size = lp_uword(&s, e->is64);
    h->link = lp_u32(&s);
    h->info = lp_u32(&s);
    h->addralign = lp_uword(&s, e->is64);
    h->entsize = lp_uword(&s, e->is64);
    return lp_ok(&s);
}

static bool read_sym(elf *e, uint64_t off, elf_sym *y)
{
    lp_slice s;
    if (lp_slice_at(e->img, off, e->is64 ? 24 : 16, e->be, &s) != LP_OK)
        return false;
    y->name = lp_u32(&s);
    if (e->is64) {
        y->info = lp_u8(&s);
        y->other = lp_u8(&s);
        y->shndx = lp_u16(&s);
        y->value = lp_u64(&s);
        y->size = lp_u64(&s);
    } else {
        y->value = lp_u32(&s);
        y->size = lp_u32(&s);
        y->info = lp_u8(&s);
        y->other = lp_u8(&s);
        y->shndx = lp_u16(&s);
    }
    return lp_ok(&s);
}

/* A string table is usable only if all of it is inside the file. */
static strtab make_strtab(elf *e, uint64_t off, uint64_t size)
{
    strtab t = {false, 0, 0};
    lp_slice s;
    if (lp_slice_at(e->img, off, size, e->be, &s) == LP_OK && size) {
        t.ok = true;
        t.off = off;
        t.size = size;
    }
    return t;
}

/* Read string `idx` of a table; false if idx is outside it. The scan stops
 * at the end of the table, not the end of the file. */
static bool tab_str(elf *e, const strtab *t, uint64_t idx, lp_str *out)
{
    out->s[0] = '\0';
    out->len = 0;
    out->terminated = out->truncated = false;
    if (!t->ok || idx >= t->size)
        return false;
    bool ok = lp_read_str(e->img, t->off + idx, t->size - idx, out) == LP_OK;
    /* Scanning a name is work too, so it is charged for. */
    lp_tick(e->c, 1 + out->len / 32);
    return ok;
}

static strtab section_strtab(elf *e, uint64_t idx)
{
    strtab none = {false, 0, 0};
    if (idx >= e->nsh || e->sh[idx].type != SHT_STRTAB)
        return none;
    return make_strtab(e, e->sh[idx].offset, e->sh[idx].size);
}

static void sec_name(elf *e, uint32_t i, char *esc, size_t n)
{
    lp_str s;
    if (!e->shstr.ok) {
        snprintf(esc, n, "%s", "");
        return;
    }
    if (!tab_str(e, &e->shstr, e->sh[i].name, &s)) {
        snprintf(esc, n, "<bad name 0x%x>", e->sh[i].name);
        return;
    }
    lp_esc(&s, esc, n);
}

/* Map [addr, addr + len) to a file offset through the PT_LOAD segments. */
static bool vaddr_to_off(elf *e, uint64_t addr, uint64_t len, uint64_t *off,
                         uint64_t *avail)
{
    if (!lp_tick(e->c, e->nph + 1u))
        return false;
    for (uint32_t i = 0; i < e->nph; i++) {
        const elf_ph *p = &e->ph[i];
        if (p->type != PT_LOAD || addr < p->vaddr)
            continue;
        uint64_t delta = addr - p->vaddr;
        if (delta >= p->filesz || len > p->filesz - delta)
            continue;
        if (p->offset > UINT64_MAX - delta)
            continue;
        uint64_t o = p->offset + delta;
        if (o >= e->size)
            continue;
        *off = o;
        *avail = p->filesz - delta;
        if (*avail > e->size - o)
            *avail = e->size - o;
        return true;
    }
    return false;
}

/* ---- headers ------------------------------------------------------------ */

static uint32_t clamp_count(elf *e, const char *what, uint64_t off, uint64_t count,
                            uint64_t entsize, uint64_t max)
{
    uint64_t fit = off < e->size ? (e->size - off) / entsize : 0;
    uint64_t n = count;
    if (n > fit) {
        lp_warn(e->c, "%s: header claims %llu entries at 0x%llx but only %llu fit in the file",
                what, (unsigned long long)count, (unsigned long long)off,
                (unsigned long long)fit);
        n = fit;
    }
    if (n > max) {
        lp_warn(e->c, "%s: %llu entries; reading the first %llu", what,
                (unsigned long long)n, (unsigned long long)max);
        n = max;
    }
    return (uint32_t)n;
}

static lp_status parse_headers(elf *e)
{
    lp_ctx *c = e->c;
    lp_slice s;
    uint8_t ident[16];

    if (lp_slice_at(e->img, 0, 16, false, &s) != LP_OK) {
        lp_reject(c, "ELF magic, but the file is too short for e_ident");
        return LP_STATUS_MALFORMED;
    }
    lp_bytes(&s, ident, 16);
    if (ident[4] != ELFCLASS32 && ident[4] != ELFCLASS64) {
        lp_reject(c, "ELF file with unknown class %u", ident[4]);
        return LP_STATUS_MALFORMED;
    }
    if (ident[5] != ELFDATA2LSB && ident[5] != ELFDATA2MSB) {
        lp_reject(c, "ELF file with unknown data encoding %u", ident[5]);
        return LP_STATUS_MALFORMED;
    }
    e->is64 = ident[4] == ELFCLASS64;
    e->be = ident[5] == ELFDATA2MSB;
    e->osabi = ident[7];
    e->abiver = ident[8];
    if (ident[6] != 1)
        lp_warn(c, "e_ident version is %u, expected 1", ident[6]);

    if (lp_slice_at(e->img, 16, e->is64 ? 48 : 36, e->be, &s) != LP_OK) {
        lp_reject(c, "ELF header is cut off by the end of the file");
        return LP_STATUS_MALFORMED;
    }
    e->type = lp_u16(&s);
    e->machine = lp_u16(&s);
    e->version = lp_u32(&s);
    e->entry = lp_uword(&s, e->is64);
    e->phoff = lp_uword(&s, e->is64);
    e->shoff = lp_uword(&s, e->is64);
    e->flags = lp_u32(&s);
    e->ehsize = lp_u16(&s);
    e->phentsize = lp_u16(&s);
    e->phnum = lp_u16(&s);
    e->shentsize = lp_u16(&s);
    e->shnum = lp_u16(&s);
    e->shstrndx = lp_u16(&s);

    if (e->version != 1)
        lp_warn(c, "e_version is %u, expected 1", e->version);
    if (e->ehsize != (e->is64 ? 64 : 52))
        lp_warn(c, "e_ehsize is %u, expected %u", e->ehsize, e->is64 ? 64 : 52);

    const uint32_t phsz = e->is64 ? 56 : 32, shsz = e->is64 ? 64 : 40;

    /* Extended numbering: with more than 0xfeff sections, e_shnum is 0,
     * e_shstrndx is SHN_XINDEX and e_phnum PN_XNUM, and the real values
     * live in section header 0. */
    if (e->shoff && (e->shnum == 0 || e->shstrndx == SHN_XINDEX || e->phnum == PN_XNUM)) {
        elf_sh first;
        if (e->shentsize >= shsz && read_sh(e, e->shoff, &first)) {
            if (e->shnum == 0)
                e->shnum = first.size;
            if (e->shstrndx == SHN_XINDEX)
                e->shstrndx = first.link;
            if (e->phnum == PN_XNUM)
                e->phnum = first.info;
        } else {
            lp_warn(c, "extended section numbering, but section header 0 is unreadable");
        }
    }

    /* Program headers. The entry size comes from the file; it may be
     * larger than the struct (future fields), never smaller. */
    if (e->phnum) {
        if (e->phentsize < phsz) {
            lp_warn(c, "e_phentsize is %u, smaller than a program header (%u)",
                    e->phentsize, phsz);
        } else {
            uint32_t n = clamp_count(e, "program headers", e->phoff, e->phnum,
                                     e->phentsize, LP_MAX_ELF_SEGMENTS);
            e->ph = n ? lp_calloc(n, sizeof *e->ph) : NULL;
            if (n && !e->ph) {
                lp_warn(c, "out of memory for %u program headers", n);
                n = 0;
            }
            for (uint32_t i = 0; i < n; i++)
                read_ph(e, e->phoff + (uint64_t)i * e->phentsize, &e->ph[i]);
            e->nph = n;
        }
    }

    if (e->shnum) {
        if (e->shentsize < shsz) {
            lp_warn(c, "e_shentsize is %u, smaller than a section header (%u)",
                    e->shentsize, shsz);
        } else {
            uint32_t n = clamp_count(e, "section headers", e->shoff, e->shnum,
                                     e->shentsize, LP_MAX_ELF_SECTIONS);
            e->sh = n ? lp_calloc(n, sizeof *e->sh) : NULL;
            if (n && !e->sh) {
                lp_warn(c, "out of memory for %u section headers", n);
                n = 0;
            }
            for (uint32_t i = 0; i < n; i++)
                read_sh(e, e->shoff + (uint64_t)i * e->shentsize, &e->sh[i]);
            e->nsh = n;
        }
    }

    if (e->nsh && e->shstrndx != SHN_UNDEF) {
        if (e->shstrndx >= e->nsh) {
            lp_warn(c, "e_shstrndx %llu is not a valid section",
                    (unsigned long long)e->shstrndx);
        } else {
            const elf_sh *h = &e->sh[e->shstrndx];
            if (h->type != SHT_STRTAB)
                lp_warn(c, "section-name table (section %llu) is not a STRTAB",
                        (unsigned long long)e->shstrndx);
            e->shstr = make_strtab(e, h->offset, h->size);
            if (!e->shstr.ok && h->size)
                lp_warn(c, "section-name table 0x%llx+0x%llx is outside the file",
                        (unsigned long long)h->offset, (unsigned long long)h->size);
        }
    }

    /* Consistency checks a well-formed file passes. */
    for (uint32_t i = 0; i < e->nph; i++) {
        const elf_ph *p = &e->ph[i];
        if (p->filesz && (p->offset > e->size || p->filesz > e->size - p->offset))
            lp_warn(c, "segment %u: file data 0x%llx+0x%llx runs past the end of the file",
                    i, (unsigned long long)p->offset, (unsigned long long)p->filesz);
        if (p->type == PT_LOAD && p->memsz < p->filesz)
            lp_warn(c, "segment %u: p_memsz is smaller than p_filesz", i);
    }
    for (uint32_t i = 0; i < e->nsh; i++) {
        const elf_sh *h = &e->sh[i];
        if (h->type != SHT_NOBITS && h->type != SHT_NULL && h->size &&
            (h->offset > e->size || h->size > e->size - h->offset))
            lp_warn(c, "section %u: data 0x%llx+0x%llx runs past the end of the file",
                    i, (unsigned long long)h->offset, (unsigned long long)h->size);
        /* Version sections keep their entry count in sh_info. */
        uint64_t vent = h->type == SHT_GNU_VERDEF ? 20 : 16;
        if ((h->type == SHT_GNU_VERNEED || h->type == SHT_GNU_VERDEF) && h->info &&
            h->size / vent < h->info)
            lp_warn(c, "section %u: claims %u version entries but only %llu fit in it", i,
                    h->info, (unsigned long long)(h->size / vent));
    }
    return LP_STATUS_OK;
}

/* ---- facts gathered before printing ------------------------------------- */

static void parse_note_area(elf *e, uint64_t off, uint64_t size, uint64_t align)
{
    const uint64_t a = align == 8 ? 8 : 4;
    uint64_t pos = 0;
    for (uint32_t n = 0; n < MAX_NOTES && size - pos >= 12; n++) {
        if (!lp_tick(e->c, 1))
            return;
        lp_slice s;
        if (lp_slice_at(e->img, off + pos, 12, e->be, &s) != LP_OK)
            return;
        uint32_t namesz = lp_u32(&s), descsz = lp_u32(&s), type = lp_u32(&s);
        /* The descriptor starts at the next alignment boundary after the
         * name, measured from the start of the note (not from the name),
         * and the next note after the descriptor. With 8-byte notes that
         * is 12 + 4 -> 16, not 12 + 8. */
        uint64_t desc_rel = (12 + (uint64_t)namesz + a - 1) & ~(a - 1);
        uint64_t end_rel = (desc_rel + descsz + a - 1) & ~(a - 1);
        uint64_t room = size - pos;
        if (desc_rel + descsz > room) {
            lp_warn(e->c, "note at 0x%llx runs past the end of its segment",
                    (unsigned long long)(off + pos));
            return;
        }
        uint64_t name_off = off + pos + 12, desc_off = off + pos + desc_rel;
        char owner[8] = {0};
        if (namesz >= 4 && namesz <= sizeof owner) {
            lp_slice ns;
            lp_slice_at(e->img, name_off, namesz, e->be, &ns);
            lp_bytes(&ns, owner, namesz);
            owner[sizeof owner - 1] = '\0';
        }
        if (strcmp(owner, "GNU") == 0) {
            if (type == NT_GNU_BUILD_ID && descsz && descsz <= sizeof e->build_id &&
                !e->build_id_len) {
                lp_slice ds;
                lp_slice_at(e->img, desc_off, descsz, e->be, &ds);
                lp_bytes(&ds, e->build_id, descsz);
                if (lp_ok(&ds))
                    e->build_id_len = descsz;
            } else if (type == NT_GNU_PROPERTY) {
                /* An array of (type, datasz, data padded to 8 or 4). */
                const uint64_t pa = e->is64 ? 8 : 4;
                uint64_t q = 0;
                for (int k = 0; k < 64; k++) {
                    /* q is compared before it is subtracted from: the padded
                     * step below can otherwise walk it past descsz, and an
                     * unsigned descsz - q would wrap into a huge "remaining". */
                    if (q > descsz || descsz - q < 8)
                        break;
                    lp_slice ps;
                    if (lp_slice_at(e->img, desc_off + q, 8, e->be, &ps) != LP_OK)
                        break;
                    uint32_t ptype = lp_u32(&ps), datasz = lp_u32(&ps);
                    if (datasz > descsz - q - 8)
                        break;
                    if ((ptype == GNU_PROPERTY_X86_FEATURE_1_AND ||
                         ptype == GNU_PROPERTY_AARCH64_FEATURE_1_AND) && datasz >= 4) {
                        uint32_t bits;
                        if (lp_read_u32(e->img, desc_off + q + 8, e->be, &bits) == LP_OK) {
                            e->have_feature = true;
                            e->feature_1 = bits;
                        }
                    }
                    uint64_t step = 8 + (((uint64_t)datasz + pa - 1) & ~(pa - 1));
                    if (step > descsz - q)
                        break; /* the padded record leaves the descriptor */
                    q += step;
                }
            }
        }
        if (end_rel >= room)
            return;
        pos += end_rel;
    }
}

static void gather_segments(elf *e)
{
    bool notes_from_segments = false;
    for (uint32_t i = 0; i < e->nph; i++) {
        const elf_ph *p = &e->ph[i];
        switch (p->type) {
        case PT_INTERP:
            /* The path must be inside the segment. Reading it from p_offset
             * without honouring p_filesz, as some tools do, walks off the
             * end of an empty PT_INTERP into whatever follows. */
            if (!p->filesz) {
                lp_warn(e->c, "PT_INTERP segment is empty; no interpreter path");
            } else if (!e->interp_found &&
                       lp_read_str(e->img, p->offset, p->filesz, &e->interp) == LP_OK) {
                e->interp_found = true;
                if (!e->interp.terminated && !e->interp.truncated)
                    lp_warn(e->c, "PT_INTERP path is not terminated inside its segment");
            }
            break;
        case PT_GNU_STACK:
            e->gnu_stack = true;
            e->stack_exec = (p->flags & PF_X) != 0;
            break;
        case PT_GNU_RELRO:
            e->relro = true;
            break;
        case PT_NOTE:
            notes_from_segments = true;
            parse_note_area(e, p->offset, p->filesz, p->align);
            break;
        }
    }
    if (!notes_from_segments) {
        for (uint32_t i = 0; i < e->nsh; i++)
            if (e->sh[i].type == SHT_NOTE)
                parse_note_area(e, e->sh[i].offset, e->sh[i].size, e->sh[i].addralign);
    }
}

static void gather_dynamic(elf *e)
{
    uint64_t off = 0, size = 0;
    long dsec = -1;
    for (uint32_t i = 0; i < e->nsh; i++) {
        if (e->sh[i].type == SHT_DYNAMIC) {
            dsec = (long)i;
            break;
        }
    }
    bool found = false;
    for (uint32_t i = 0; i < e->nph && !found; i++) {
        if (e->ph[i].type == PT_DYNAMIC) {
            off = e->ph[i].offset;
            size = e->ph[i].filesz;
            found = true;
        }
    }
    if (!found && dsec >= 0) {
        off = e->sh[dsec].offset;
        size = e->sh[dsec].size;
        found = true;
    }
    if (!found)
        return;

    const uint64_t ent = e->is64 ? 16 : 8;
    uint32_t n = clamp_count(e, "dynamic section", off, size / ent, ent, LP_MAX_DYNAMIC);
    uint64_t strtab_addr = 0, strsz = 0;
    bool have_strtab = false, terminated = false;
    uint32_t i;
    for (i = 0; i < n; i++) {
        if (!lp_tick(e->c, 1))
            break;
        lp_slice s;
        lp_slice_at(e->img, off + (uint64_t)i * ent, ent, e->be, &s);
        uint64_t tag = lp_uword(&s, e->is64), val = lp_uword(&s, e->is64);
        if (tag == DT_NULL) {
            terminated = true;
            i++;
            break;
        }
        switch (tag) {
        case DT_STRTAB:   strtab_addr = val; have_strtab = true; break;
        case DT_STRSZ:    strsz = val; break;
        case DT_FLAGS:    e->dt_flags = val; break;
        case DT_FLAGS_1:  e->dt_flags1 = val; break;
        case DT_BIND_NOW: e->bind_now = true; break;
        case DT_TEXTREL:  e->textrel = true; break;
        case DT_RPATH:    e->rpath = true; break;
        case DT_RUNPATH:  e->runpath = true; break;
        }
    }
    e->have_dyn = true;
    e->dyn_off = off;
    e->ndyn = i;
    if (!terminated && n)
        lp_warn(e->c, "dynamic section has no DT_NULL terminator");
    if (e->dt_flags & DF_BIND_NOW || e->dt_flags1 & DF_1_NOW)
        e->bind_now = true;
    if (e->dt_flags & DF_TEXTREL)
        e->textrel = true;

    /* DT_STRTAB is an address; find its bytes through the segments. Fall
     * back to the section the dynamic section links to. */
    uint64_t soff, avail;
    if (have_strtab && vaddr_to_off(e, strtab_addr, 1, &soff, &avail)) {
        uint64_t len = strsz && strsz < avail ? strsz : avail;
        e->dynstr = make_strtab(e, soff, len);
    } else {
        if (have_strtab)
            lp_warn(e->c, "DT_STRTAB address 0x%llx is not inside any PT_LOAD segment",
                    (unsigned long long)strtab_addr);
        if (dsec >= 0)
            e->dynstr = section_strtab(e, e->sh[dsec].link);
    }
    if (!e->dynstr.ok && n)
        lp_warn(e->c, "dynamic string table not found");
}

static void find_symbol_sections(elf *e)
{
    e->dynsym = e->symtab = e->versym = e->verneed = e->verdef = -1;
    for (uint32_t i = 0; i < e->nsh; i++) {
        switch (e->sh[i].type) {
        case SHT_DYNSYM:      if (e->dynsym < 0) e->dynsym = (long)i; break;
        case SHT_SYMTAB:      if (e->symtab < 0) e->symtab = (long)i; break;
        case SHT_GNU_VERSYM:  if (e->versym < 0) e->versym = (long)i; break;
        case SHT_GNU_VERNEED: if (e->verneed < 0) e->verneed = (long)i; break;
        case SHT_GNU_VERDEF:  if (e->verdef < 0) e->verdef = (long)i; break;
        }
    }
}

/* ---- symbol tables ------------------------------------------------------ */

typedef struct symtab {
    long     sec;
    uint64_t off, entsize;
    uint32_t count;
    strtab   str;
} symtab;

static bool open_symtab(elf *e, long sec, symtab *t)
{
    memset(t, 0, sizeof *t);
    if (sec < 0)
        return false;
    const elf_sh *h = &e->sh[sec];
    const uint64_t min = e->is64 ? 24 : 16;
    t->sec = sec;
    t->off = h->offset;
    t->entsize = h->entsize;
    if (t->entsize < min) {
        if (t->entsize)
            lp_warn(e->c, "section %ld: sh_entsize %llu is smaller than a symbol (%llu)",
                    sec, (unsigned long long)t->entsize, (unsigned long long)min);
        t->entsize = min;
    }
    t->count = clamp_count(e, "symbol table", t->off, h->size / t->entsize, t->entsize,
                           LP_MAX_SYMBOLS);
    t->str = section_strtab(e, h->link);
    if (!t->str.ok && t->count > 1)
        lp_warn(e->c, "section %ld: linked string table (section %u) is missing or invalid",
                sec, h->link);
    return true;
}

static bool get_sym(elf *e, const symtab *t, uint32_t i, elf_sym *y, lp_str *name)
{
    if (!read_sym(e, t->off + (uint64_t)i * t->entsize, y))
        return false;
    if (!tab_str(e, &t->str, y->name, name) && y->name && t->str.ok)
        lp_warn(e->c, "symbol %u: name offset 0x%x is outside its string table", i, y->name);
    return true;
}

/*
 * Symbol versioning (GNU). .gnu.version holds one 16-bit index per dynamic
 * symbol. Index 0 is local, 1 is global/unversioned; anything higher names
 * an entry in .gnu.version_r (versions needed from other files) or
 * .gnu.version_d (versions this file defines). Both are chains linked by
 * unsigned relative offsets, so they only move forward and cannot loop; the
 * walks are still capped by section size and the work budget.
 */
typedef struct symver {
    lp_str name;
    lp_str file; /* for needed versions */
    bool   found, hidden, needed;
} symver;

static bool find_verneed(elf *e, uint16_t idx, symver *v)
{
    if (e->verneed < 0)
        return false;
    const elf_sh *h = &e->sh[e->verneed];
    strtab str = section_strtab(e, h->link);
    uint64_t base = h->offset, size = h->size, pos = 0;
    for (uint32_t n = 0; n < h->info && n < 4096; n++) {
        if (!lp_tick(e->c, 1) || pos > size || size - pos < 16)
            return false;
        lp_slice s;
        if (lp_slice_at(e->img, base + pos, 16, e->be, &s) != LP_OK)
            return false;
        lp_skip(&s, 2); /* vn_version */
        uint16_t cnt = lp_u16(&s);
        uint32_t file = lp_u32(&s), aux = lp_u32(&s), next = lp_u32(&s);
        uint64_t apos = pos + aux;
        for (uint16_t k = 0; k < cnt; k++) {
            if (!lp_tick(e->c, 1) || apos > size || size - apos < 16)
                break;
            lp_slice a;
            if (lp_slice_at(e->img, base + apos, 16, e->be, &a) != LP_OK)
                break;
            lp_skip(&a, 6); /* vna_hash, vna_flags */
            uint16_t other = lp_u16(&a);
            uint32_t vname = lp_u32(&a), anext = lp_u32(&a);
            if ((other & 0x7fff) == idx) {
                tab_str(e, &str, vname, &v->name);
                tab_str(e, &str, file, &v->file);
                v->found = v->needed = true;
                return true;
            }
            if (!anext)
                break;
            apos += anext;
        }
        if (!next)
            break;
        pos += next;
    }
    return false;
}

static bool find_verdef(elf *e, uint16_t idx, symver *v)
{
    if (e->verdef < 0)
        return false;
    const elf_sh *h = &e->sh[e->verdef];
    strtab str = section_strtab(e, h->link);
    uint64_t base = h->offset, size = h->size, pos = 0;
    for (uint32_t n = 0; n < h->info && n < 4096; n++) {
        if (!lp_tick(e->c, 1) || pos > size || size - pos < 20)
            return false;
        lp_slice s;
        if (lp_slice_at(e->img, base + pos, 20, e->be, &s) != LP_OK)
            return false;
        lp_skip(&s, 4); /* vd_version, vd_flags */
        uint16_t ndx = lp_u16(&s);
        uint16_t cnt = lp_u16(&s);
        lp_skip(&s, 4); /* vd_hash */
        uint32_t aux = lp_u32(&s), next = lp_u32(&s);
        if ((ndx & 0x7fff) == idx && cnt) {
            uint64_t apos = pos + aux;
            uint32_t vname;
            if (apos <= size && size - apos >= 8 &&
                lp_read_u32(e->img, base + apos, e->be, &vname) == LP_OK) {
                tab_str(e, &str, vname, &v->name);
                v->found = true;
                return true;
            }
            return false;
        }
        if (!next)
            break;
        pos += next;
    }
    return false;
}

static void sym_version(elf *e, uint32_t symidx, const elf_sym *y, symver *v)
{
    /* Every field, including the lp_str flags: the caller's symver is an
     * automatic, and lp_esc() reads .terminated and .truncated whatever
     * happened here. */
    v->found = v->hidden = v->needed = false;
    v->name.len = v->file.len = 0;
    v->name.s[0] = v->file.s[0] = '\0';
    v->name.terminated = v->file.terminated = true; /* empty and complete */
    v->name.truncated = v->file.truncated = false;
    if (e->versym < 0)
        return;
    const elf_sh *h = &e->sh[e->versym];
    if ((uint64_t)symidx * 2 + 2 > h->size)
        return;
    uint16_t raw;
    if (lp_read_u16(e->img, h->offset + (uint64_t)symidx * 2, e->be, &raw) != LP_OK)
        return;
    uint16_t idx = raw & 0x7fff;
    v->hidden = (raw & 0x8000) != 0;
    if (idx <= 1)
        return;
    if (y->shndx == SHN_UNDEF) {
        if (!find_verneed(e, idx, v))
            find_verdef(e, idx, v);
    } else if (!find_verdef(e, idx, v)) {
        find_verneed(e, idx, v);
    }
}

/* "name", "name@VER" (needed or hidden) or "name@@VER" (default). */
static void versioned_name(const lp_str *name, const symver *v, char *out, size_t n)
{
    char a[LP_ESC_MAX], b[LP_ESC_MAX];
    lp_esc(name, a, sizeof a);
    if (!v->found || !v->name.len) {
        snprintf(out, n, "%s", a);
        return;
    }
    lp_esc(&v->name, b, sizeof b);
    snprintf(out, n, "%s%s%s", a, (v->needed || v->hidden) ? "@" : "@@", b);
}

static void ndx_str(uint16_t ndx, char *buf, size_t n)
{
    switch (ndx) {
    case SHN_UNDEF:  snprintf(buf, n, "UND"); break;
    case SHN_ABS:    snprintf(buf, n, "ABS"); break;
    case SHN_COMMON: snprintf(buf, n, "COM"); break;
    case SHN_XINDEX: snprintf(buf, n, "XIDX"); break;
    default:         snprintf(buf, n, "%u", ndx); break;
    }
}

static void print_symtab(elf *e, long sec)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    symtab t;
    if (!open_symtab(e, sec, &t))
        return;
    char secname[LP_ESC_MAX], g[32];
    sec_name(e, (uint32_t)sec, secname, sizeof secname);
    char title[64];
    snprintf(title, sizeof title, "SYMBOLS %.40s", secname);
    lp_heading(c, title, "%s entries", lp_grp(t.count, g, sizeof g));
    if (!c->opts->flat && t.count)
        lp_printf(o, "  %s%7s  %-*s %7s %-7s %-7s %-9s %-5s %s%s\n", lp_c(o, LP_C_LABEL),
                  "num", e->is64 ? 16 : 8, "value", "size", "type", "bind", "vis", "ndx",
                  "name", lp_c(o, LP_C_RESET));
    bool dyn = sec == e->dynsym;
    for (uint32_t i = 0; i < t.count; i++) {
        if (!lp_tick(c, 1))
            return;
        elf_sym y;
        lp_str name;
        if (!get_sym(e, &t, i, &y, &name))
            break;
        symver v;
        v.found = false;
        if (dyn)
            sym_version(e, i, &y, &v);
        char full[LP_ESC_MAX * 2 + 4], tb[16], bb[16], ndx[16];
        versioned_name(&name, &v, full, sizeof full);
        ndx_str(y.shndx, ndx, sizeof ndx);
        if (c->opts->flat)
            lp_printf(o, "symbol\t%s\t%u\t0x%llx\t%llu\t%s\t%s\t%s\t%s\t%s\n", secname, i,
                      (unsigned long long)y.value, (unsigned long long)y.size,
                      sym_type(y.info, tb, sizeof tb), sym_bind(y.info, bb, sizeof bb),
                      sym_vis(y.other), ndx, full);
        else
            lp_printf(o, "  %7u  %0*llx %7llu %-7s %-7s %-9s %-5s %s\n", i, e->is64 ? 16 : 8,
                      (unsigned long long)y.value, (unsigned long long)y.size,
                      sym_type(y.info, tb, sizeof tb), sym_bind(y.info, bb, sizeof bb),
                      sym_vis(y.other), ndx, full);
    }
}

static bool ends_with(const lp_str *s, const char *suffix)
{
    size_t n = strlen(suffix);
    return s->len >= n && memcmp(s->s + s->len - n, suffix, n) == 0;
}

/* Scan symbol names for evidence of stack protection and FORTIFY_SOURCE. */
static void gather_symbol_facts(elf *e)
{
    long secs[2] = {e->dynsym, e->symtab};
    e->c->mute++; /* the tables are validated, with warnings, when printed */
    for (int k = 0; k < 2; k++) {
        symtab t;
        if (!open_symtab(e, secs[k], &t))
            continue;
        for (uint32_t i = 0; i < t.count; i++) {
            if (!lp_tick(e->c, 1))
                break;
            elf_sym y;
            lp_str name;
            if (!get_sym(e, &t, i, &y, &name))
                break;
            if (!strcmp(name.s, "__stack_chk_fail") || !strcmp(name.s, "__stack_chk_guard") ||
                !strcmp(name.s, "__intel_security_cookie"))
                e->canary = true;
            else if (name.len > 6 && name.s[0] == '_' && name.s[1] == '_' &&
                     ends_with(&name, "_chk") && y.shndx == SHN_UNDEF)
                e->fortified++;
        }
    }
    e->c->mute--;
}

/* ---- printing: header, mitigations, tables ------------------------------ */

static void print_header(elf *e)
{
    lp_ctx *c = e->c;
    char g[32];
    lp_heading(c, "HEADER", NULL);
    lp_field(c, "class", "%s", e->is64 ? "ELF64" : "ELF32");
    lp_field(c, "data", "%s", e->be ? "big-endian" : "little-endian");
    lp_field(c, "os/abi", "%s (%u), abi version %u", osabi_name(e->osabi), e->osabi,
             e->abiver);
    lp_field(c, "type", "%s", type_name(e->type));
    lp_field(c, "machine", "%s (%u)", machine_name(e->machine), e->machine);
    lp_field(c, "entry point", "0x%llx", (unsigned long long)e->entry);
    lp_field(c, "flags", "0x%x", e->flags);
    lp_field(c, "program headers", "%s at 0x%llx, %u bytes each",
             lp_grp(e->phnum, g, sizeof g), (unsigned long long)e->phoff, e->phentsize);
    lp_field(c, "section headers", "%s at 0x%llx, %u bytes each",
             lp_grp(e->shnum, g, sizeof g), (unsigned long long)e->shoff, e->shentsize);
    lp_field(c, "section names", "section %llu", (unsigned long long)e->shstrndx);
    if (e->interp_found) {
        char esc[LP_ESC_MAX];
        lp_field(c, "interpreter", "%s", lp_esc(&e->interp, esc, sizeof esc));
    }
    if (e->build_id_len) {
        char hex[sizeof e->build_id * 2 + 1];
        for (uint32_t i = 0; i < e->build_id_len; i++)
            snprintf(hex + i * 2, 3, "%02x", e->build_id[i]);
        lp_field(c, "build id", "%s", hex);
    }
}

static void mitigation(lp_ctx *c, const char *name, int state, const char *detail)
{
    lp_out *o = c->out;
    const char *word = state > 0 ? "yes" : state == 0 ? "no" : "n/a";
    lp_color col = state > 0 ? LP_C_GOOD : state == 0 ? LP_C_BAD : LP_C_LABEL;
    lp_printf(o, "  %s%-19s%s %s%-3s%s", lp_c(o, LP_C_LABEL), name,
              lp_c(o, LP_C_RESET), lp_c(o, col), word, lp_c(o, LP_C_RESET));
    if (detail && *detail)
        lp_printf(o, "  %s%s%s", lp_c(o, LP_C_LABEL), detail, lp_c(o, LP_C_RESET));
    lp_printf(o, "\n");
}

static void print_mitigations(elf *e)
{
    lp_ctx *c = e->c;
    if (c->opts->flat)
        return;
    lp_heading(c, "MITIGATIONS", NULL);
    if (e->type != ET_EXEC && e->type != ET_DYN) {
        lp_printf(c->out, "  %snot applicable to a %s%s\n", lp_c(c->out, LP_C_LABEL),
                  kind_name(e), lp_c(c->out, LP_C_RESET));
        return;
    }
    char buf[96];
    if (e->type == ET_EXEC)
        mitigation(c, "PIE", 0, "fixed load address");
    else if (e->interp_found || (e->dt_flags1 & DF_1_PIE))
        mitigation(c, "PIE", 1, "");
    else
        mitigation(c, "PIE", -1, "shared object; always relocatable");

    if (!e->gnu_stack)
        mitigation(c, "NX stack", 0, "no PT_GNU_STACK; many loaders default to executable");
    else
        mitigation(c, "NX stack", !e->stack_exec,
                   e->stack_exec ? "PT_GNU_STACK is executable" : "");

    if (e->relro && e->bind_now)
        mitigation(c, "RELRO", 1, "full (GNU_RELRO + BIND_NOW)");
    else if (e->relro)
        mitigation(c, "RELRO", 1, "partial (GNU_RELRO without BIND_NOW)");
    else
        mitigation(c, "RELRO", 0, "");

    mitigation(c, "Stack canary", e->canary, e->canary ? "__stack_chk_* referenced" : "");
    snprintf(buf, sizeof buf, "%u fortified calls", e->fortified);
    mitigation(c, "FORTIFY_SOURCE", e->fortified > 0, e->fortified ? buf : "");

    if (e->machine == EM_X86_64 || e->machine == EM_386) {
        bool ibt = e->have_feature && (e->feature_1 & 1);
        bool shstk = e->have_feature && (e->feature_1 & 2);
        snprintf(buf, sizeof buf, "IBT %s, SHSTK %s", ibt ? "on" : "off", shstk ? "on" : "off");
        mitigation(c, "CET", ibt || shstk, buf);
    } else if (e->machine == EM_AARCH64) {
        bool bti = e->have_feature && (e->feature_1 & 1);
        bool pac = e->have_feature && (e->feature_1 & 2);
        snprintf(buf, sizeof buf, "BTI %s, PAC %s", bti ? "on" : "off", pac ? "on" : "off");
        mitigation(c, "BTI / PAC", bti || pac, buf);
    }
    if (e->textrel)
        mitigation(c, "No text relocations", 0,
                   "TEXTREL present: code pages are patched at load");
    if (e->rpath || e->runpath)
        lp_printf(c->out, "  %s%-19s%s %s%s set%s\n", lp_c(c->out, LP_C_LABEL), "search path",
                  lp_c(c->out, LP_C_RESET), lp_c(c->out, LP_C_WARN),
                  e->rpath ? "DT_RPATH" : "DT_RUNPATH", lp_c(c->out, LP_C_RESET));
}

static void print_segments(elf *e)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    if (!e->nph && e->type == ET_REL)
        return;
    lp_heading(c, "SEGMENTS", "%u", e->nph);
    int w = e->is64 ? 16 : 8;
    if (!c->opts->flat && e->nph)
        lp_printf(o, "  %s %3s  %-14s %-10s %-*s %-10s %-10s %-5s %s%s\n", lp_c(o, LP_C_LABEL),
                  "#", "type", "offset", w + 2, "vaddr", "filesz", "memsz", "flags", "align",
                  lp_c(o, LP_C_RESET));
    for (uint32_t i = 0; i < e->nph; i++) {
        if (!lp_tick(c, 1))
            return;
        const elf_ph *p = &e->ph[i];
        char tb[16], perm[4];
        perm_str(p->flags, perm);
        const char *tn = ptype_name(e->machine, p->type, tb, sizeof tb);
        if (c->opts->flat)
            lp_printf(o, "segment\t%u\t%s\t0x%llx\t0x%llx\t0x%llx\t0x%llx\t%s\n", i, tn,
                      (unsigned long long)p->offset, (unsigned long long)p->vaddr,
                      (unsigned long long)p->filesz, (unsigned long long)p->memsz, perm);
        else
            lp_printf(o, "  %3u  %s%-14s%s 0x%08llx 0x%0*llx 0x%08llx 0x%08llx %-5s 0x%llx\n",
                      i, lp_c(o, LP_C_NAME), tn, lp_c(o, LP_C_RESET),
                      (unsigned long long)p->offset, w, (unsigned long long)p->vaddr,
                      (unsigned long long)p->filesz, (unsigned long long)p->memsz, perm,
                      (unsigned long long)p->align);
    }
}

static void print_sections(elf *e)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    lp_heading(c, "SECTIONS", "%u", e->nsh);
    int w = e->is64 ? 16 : 8;
    if (!c->opts->flat && e->nsh)
        lp_printf(o, "  %s %3s  %-20s %-14s %-*s %-10s %-10s %-5s %s%s\n", lp_c(o, LP_C_LABEL),
                  "#", "name", "type", w + 2, "address", "offset", "size", "flags",
                  "link/info/align", lp_c(o, LP_C_RESET));
    for (uint32_t i = 0; i < e->nsh; i++) {
        if (!lp_tick(c, 1))
            return;
        const elf_sh *h = &e->sh[i];
        char name[LP_ESC_MAX], tb[16], fl[16];
        sec_name(e, i, name, sizeof name);
        const char *tn = shtype_name(e->machine, h->type, tb, sizeof tb);
        shflag_str(h->flags, fl, sizeof fl);
        if (c->opts->flat)
            lp_printf(o, "section\t%u\t%s\t%s\t0x%llx\t0x%llx\t0x%llx\t%s\n", i, name, tn,
                      (unsigned long long)h->addr, (unsigned long long)h->offset,
                      (unsigned long long)h->size, fl);
        else
            lp_printf(o, "  %3u  %s%-20s%s %-14s 0x%0*llx 0x%08llx 0x%08llx %-5s %u/%u/%llu\n",
                      i, lp_c(o, LP_C_NAME), name, lp_c(o, LP_C_RESET), tn, w,
                      (unsigned long long)h->addr, (unsigned long long)h->offset,
                      (unsigned long long)h->size, fl, h->link, h->info,
                      (unsigned long long)h->addralign);
    }
}

static void dyn_value(elf *e, uint64_t tag, uint64_t val, char *buf, size_t n)
{
    lp_str s;
    char esc[LP_ESC_MAX];
    switch (tag) {
    case DT_NEEDED:
    case DT_SONAME:
    case DT_RPATH:
    case DT_RUNPATH:
    case DT_AUXILIARY:
    case DT_FILTER:
        if (tab_str(e, &e->dynstr, val, &s)) {
            if (!s.terminated && !s.truncated)
                lp_warn(e->c, "dynamic string at 0x%llx is not terminated",
                        (unsigned long long)val);
            snprintf(buf, n, "%s", lp_esc(&s, esc, sizeof esc));
        } else {
            if (e->dynstr.ok)
                lp_warn(e->c, "dynamic string offset 0x%llx is outside the string table",
                        (unsigned long long)val);
            snprintf(buf, n, "<string 0x%llx>", (unsigned long long)val);
        }
        return;
    case 2: case 8: case 9: case 10: case 11: case 18: case 19: case 27: case 28:
    case 33: case 35: case 37:
    case 0x6ffffff9u: case 0x6ffffffau: case 0x6ffffffdu: case 0x6fffffffu:
        snprintf(buf, n, "%llu", (unsigned long long)val);
        return;
    case 20: /* DT_PLTREL */
        snprintf(buf, n, "%s", val == 7 ? "RELA" : val == 17 ? "REL" : "?");
        return;
    }
    snprintf(buf, n, "0x%llx", (unsigned long long)val);
}

static void print_dynamic(elf *e)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    if (!e->have_dyn) {
        if (e->type == ET_EXEC || e->type == ET_DYN)
            lp_heading(c, "DYNAMIC", "none (statically linked)");
        return;
    }
    lp_heading(c, "DYNAMIC", "%u entries", e->ndyn);
    const uint64_t ent = e->is64 ? 16 : 8;
    for (uint32_t i = 0; i < e->ndyn; i++) {
        if (!lp_tick(c, 1))
            return;
        lp_slice s;
        lp_slice_at(e->img, e->dyn_off + (uint64_t)i * ent, ent, e->be, &s);
        uint64_t tag = lp_uword(&s, e->is64), val = lp_uword(&s, e->is64);
        char tb[24], vb[LP_ESC_MAX];
        const char *tn = dtag_name(tag, tb, sizeof tb);
        if (tag == DT_FLAGS || tag == DT_FLAGS_1) {
            if (c->opts->flat) {
                lp_printf(o, "dynamic\t%s\t0x%llx\n", tn, (unsigned long long)val);
            } else {
                lp_printf(o, "  %s%-18s%s ", lp_c(o, LP_C_LABEL), tn, lp_c(o, LP_C_RESET));
                if (tag == DT_FLAGS)
                    lp_flags(c, val, df_flags, LP_COUNT(df_flags), " ");
                else
                    lp_flags(c, val, df1_flags, LP_COUNT(df1_flags), " ");
                lp_printf(o, "\n");
            }
            continue;
        }
        dyn_value(e, tag, val, vb, sizeof vb);
        if (c->opts->flat)
            lp_printf(o, "dynamic\t%s\t%s\n", tn, vb);
        else
            lp_printf(o, "  %s%-18s%s %s\n", lp_c(o, LP_C_LABEL), tn, lp_c(o, LP_C_RESET), vb);
    }
}

/* ---- imports and exports ------------------------------------------------ */

/* Undefined dynamic symbols. `lib` NULL selects those with no needed
 * version (resolved from whichever library supplies them first); otherwise
 * those whose version requirement names that file. */
static uint32_t walk_undefined(elf *e, const symtab *t, const char *lib, bool print)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    uint32_t n = 0;
    for (uint32_t i = 1; i < t->count; i++) {
        if (!lp_tick(c, 1))
            break;
        elf_sym y;
        lp_str name;
        if (!get_sym(e, t, i, &y, &name))
            break;
        if (y.shndx != SHN_UNDEF || !name.len || (y.info >> 4) == STB_LOCAL)
            continue;
        symver v;
        sym_version(e, i, &y, &v);
        bool has_file = v.found && v.needed && v.file.len;
        if (!lib) {
            if (has_file)
                continue; /* this one belongs to a named library */
        } else {
            if (!has_file)
                continue;
            char file[LP_ESC_MAX];
            lp_esc(&v.file, file, sizeof file);
            if (strcmp(file, lib) != 0)
                continue;
        }
        n++;
        if (!print)
            continue;
        char full[LP_ESC_MAX * 2 + 4];
        versioned_name(&name, &v, full, sizeof full);
        if (c->opts->flat)
            lp_printf(o, "import\t%s\t%s\n", lib ? lib : "-", full);
        else
            lp_printf(o, "      %s\n", full);
    }
    return n;
}

static void print_imports(elf *e)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    symtab t;
    bool have_syms = open_symtab(e, e->dynsym, &t);

    /* Needed libraries, from the dynamic section. */
    uint32_t nlibs = 0;
    const uint64_t ent = e->is64 ? 16 : 8;
    for (uint32_t i = 0; e->have_dyn && i < e->ndyn; i++) {
        lp_slice s;
        lp_slice_at(e->img, e->dyn_off + (uint64_t)i * ent, ent, e->be, &s);
        if (lp_uword(&s, e->is64) == DT_NEEDED)
            nlibs++;
    }
    uint32_t total = 0;
    if (have_syms) {
        c->mute++;
        total = walk_undefined(e, &t, NULL, false);
        for (uint32_t i = 0; e->have_dyn && i < e->ndyn; i++) {
            lp_slice s;
            lp_slice_at(e->img, e->dyn_off + (uint64_t)i * ent, ent, e->be, &s);
            uint64_t tag = lp_uword(&s, e->is64), val = lp_uword(&s, e->is64);
            lp_str lib;
            char esc[LP_ESC_MAX];
            if (tag == DT_NEEDED && tab_str(e, &e->dynstr, val, &lib))
                total += walk_undefined(e, &t, lp_esc(&lib, esc, sizeof esc), false);
        }
        c->mute--;
    }
    if (!nlibs && !total) {
        lp_heading(c, "IMPORTS", "none");
        return;
    }
    lp_heading(c, "IMPORTS", "%u libraries, %u symbols", nlibs, total);

    for (uint32_t i = 0; e->have_dyn && i < e->ndyn; i++) {
        if (!lp_tick(c, 1))
            break;
        lp_slice s;
        lp_slice_at(e->img, e->dyn_off + (uint64_t)i * ent, ent, e->be, &s);
        uint64_t tag = lp_uword(&s, e->is64), val = lp_uword(&s, e->is64);
        if (tag != DT_NEEDED)
            continue;
        lp_str lib;
        char esc[LP_ESC_MAX];
        if (!tab_str(e, &e->dynstr, val, &lib))
            snprintf(esc, sizeof esc, "<string 0x%llx>", (unsigned long long)val);
        else
            lp_esc(&lib, esc, sizeof esc);
        uint32_t n = 0;
        if (have_syms) {
            c->mute++;
            n = walk_undefined(e, &t, esc, false);
            c->mute--;
        }
        if (c->opts->flat)
            lp_printf(o, "needed\t%s\n", esc);
        else
            lp_printf(o, "  %s%s%s  %s%u versioned%s\n", lp_c(o, LP_C_MODULE), esc,
                      lp_c(o, LP_C_RESET), lp_c(o, LP_C_LABEL), n, lp_c(o, LP_C_RESET));
        if (have_syms && n)
            walk_undefined(e, &t, esc, true);
    }
    if (have_syms) {
        c->mute++;
        uint32_t n = walk_undefined(e, &t, NULL, false);
        c->mute--;
        if (n) {
            if (!c->opts->flat)
                lp_printf(o, "  %sunversioned%s  %s%u, bound to whichever library provides "
                             "them first%s\n",
                          lp_c(o, LP_C_MODULE), lp_c(o, LP_C_RESET), lp_c(o, LP_C_LABEL), n,
                          lp_c(o, LP_C_RESET));
            walk_undefined(e, &t, NULL, true);
        }
    }
}

static bool is_export(const elf_sym *y, const lp_str *name)
{
    unsigned bind = y->info >> 4, type = y->info & 0xf, vis = y->other & 3;
    return y->shndx != SHN_UNDEF && name->len && bind != STB_LOCAL && type != STT_SECTION &&
           type != STT_FILE && (vis == 0 || vis == 3);
}

static void print_exports(elf *e)
{
    lp_ctx *c = e->c;
    lp_out *o = c->out;
    symtab t;
    if (!open_symtab(e, e->dynsym, &t)) {
        lp_heading(c, "EXPORTS", "none");
        return;
    }
    uint32_t total = 0;
    for (uint32_t i = 1; i < t.count; i++) {
        if (!lp_tick(c, 1))
            break;
        elf_sym y;
        lp_str name;
        c->mute++;
        bool ok = get_sym(e, &t, i, &y, &name);
        c->mute--;
        if (!ok)
            break;
        total += is_export(&y, &name);
    }
    char g[32];
    lp_heading(c, "EXPORTS", "%s symbols", lp_grp(total, g, sizeof g));
    if (!c->opts->flat && total)
        lp_printf(o, "  %s%-*s %7s %-7s %s%s\n", lp_c(o, LP_C_LABEL), e->is64 ? 16 : 8, "value",
                  "size", "type", "name", lp_c(o, LP_C_RESET));
    for (uint32_t i = 1; i < t.count; i++) {
        if (!lp_tick(c, 1))
            break;
        elf_sym y;
        lp_str name;
        if (!get_sym(e, &t, i, &y, &name))
            break;
        if (!is_export(&y, &name))
            continue;
        symver v;
        sym_version(e, i, &y, &v);
        char full[LP_ESC_MAX * 2 + 4], tb[16];
        versioned_name(&name, &v, full, sizeof full);
        if (c->opts->flat)
            lp_printf(o, "export\t0x%llx\t%s\n", (unsigned long long)y.value, full);
        else
            lp_printf(o, "  %0*llx %7llu %-7s %s%s%s\n", e->is64 ? 16 : 8,
                      (unsigned long long)y.value, (unsigned long long)y.size,
                      sym_type(y.info, tb, sizeof tb), lp_c(o, LP_C_NAME), full,
                      lp_c(o, LP_C_RESET));
    }
}

static void print_notes(elf *e)
{
    lp_ctx *c = e->c;
    if (c->opts->flat || !e->build_id_len)
        return;
    lp_heading(c, "NOTES", NULL);
    char hex[sizeof e->build_id * 2 + 1];
    for (uint32_t i = 0; i < e->build_id_len; i++)
        snprintf(hex + i * 2, 3, "%02x", e->build_id[i]);
    lp_field(c, "GNU build id", "%s", hex);
    if (e->have_feature)
        lp_field(c, "GNU feature_1", "0x%x", e->feature_1);
}

/* ---- entry point -------------------------------------------------------- */

lp_status lp_elf_inspect(lp_ctx *c)
{
    elf *e = lp_calloc(1, sizeof *e);
    if (!e) {
        lp_warn(c, "out of memory");
        return LP_STATUS_MALFORMED;
    }
    e->c = c;
    e->img = c->img;
    e->size = c->size;

    lp_status st = parse_headers(e);
    if (st == LP_STATUS_OK) {
        lp_out *o = c->out;
        char g[32];

        /* Before the banner: naming a static PIE correctly needs DT_FLAGS_1,
         * which gather_dynamic() reads. */
        find_symbol_sections(e);
        gather_segments(e);
        gather_dynamic(e);
        gather_symbol_facts(e);

        if (c->opts->flat)
            lp_printf(o, "format\t%s\t%s\n", e->is64 ? "ELF64" : "ELF32",
                      machine_name(e->machine));
        else
            lp_printf(o, "%s%s %s for %s, %s, %s bytes%s\n", lp_c(o, LP_C_LABEL),
                      e->is64 ? "ELF64" : "ELF32", kind_name(e), machine_name(e->machine),
                      e->be ? "big-endian" : "little-endian", lp_grp(e->size, g, sizeof g),
                      lp_c(o, LP_C_RESET));

        unsigned what = c->opts->what;
        if (what & LP_SHOW_HEADERS && !c->opts->flat)
            print_header(e);
        if (what & LP_SHOW_MITIGATIONS)
            print_mitigations(e);
        if (what & LP_SHOW_SEGMENTS)
            print_segments(e);
        if (what & LP_SHOW_SECTIONS)
            print_sections(e);
        if (what & LP_SHOW_DYNAMIC)
            print_dynamic(e);
        if (what & LP_SHOW_DEBUG)
            print_notes(e);
        if (what & LP_SHOW_IMPORTS)
            print_imports(e);
        if (what & LP_SHOW_EXPORTS)
            print_exports(e);
        if (what & LP_SHOW_SYMBOLS) {
            if (e->dynsym >= 0)
                print_symtab(e, e->dynsym);
            if (e->symtab >= 0)
                print_symtab(e, e->symtab);
        }
    }
    lp_free(e->ph);
    lp_free(e->sh);
    lp_free(e);
    return st;
}
