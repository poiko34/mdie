#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "compiler.h"
#include "pe_utils.h"

#define SCAN_LIMIT (16u * 1024u * 1024u)
#define CHUNK 65536u
#define OVERLAP 256u

static uint32_t u32(const unsigned char *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 |
           (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static int read_at(FILE *f, uint64_t file_size, uint64_t off, void *out, size_t n)
{
    return off <= LONG_MAX && file_range_valid(file_size, off, n) &&
           fseek(f, (long)off, SEEK_SET) == 0 && fread(out, 1, n, f) == n;
}
static int rva_read(FILE *f, uint64_t file_size, const PE_OPTIONAL_INFO *o,
                    const PE_SECTION_INFO *s, size_t count,
                    uint64_t rva, unsigned char *out, size_t n)
{
    if (rva > UINT32_MAX || n > UINT64_C(0x100000000) - rva) return 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t off;
        if (!rva_to_file_offset(s, count, o->size_of_headers, file_size,
                               (uint32_t)(rva + i), &off) ||
            !read_at(f, file_size, off, out + i, 1)) return 0;
    }
    return 1;
}
static uint32_t rotate(uint32_t value, unsigned n)
{
    n &= 31;
    return n ? (value << n) | (value >> (32 - n)) : value;
}

/* Rich is not authenticated and does not identify the source-language compiler.
 * Check decoded DanS, padding, record shape and the conventional checksum. */
static void detect_rich(FILE *f, uint64_t file_size, const PE_DOS_INFO *dos,
                        PE_BUILD_INFO *r)
{
    if (dos->e_lfanew < 88) return;
    if (dos->e_lfanew > 65536) { r->incomplete = 1; return; }
    size_t n = (size_t)dos->e_lfanew;
    unsigned char *b = malloc(n);
    if (!b || !read_at(f, file_size, 0, b, n)) {
        free(b); r->incomplete = 1; return;
    }
    size_t candidates = 0;
    for (size_t end = 80; end + 8 <= n; end += 4) {
        if (memcmp(b + end, "Rich", 4)) continue;
        if (++candidates > 32) { r->incomplete = 1; break; }
        r->rich_invalid = 1;
        uint32_t key = u32(b + end + 4);
        for (size_t start = 64; start + 16 <= end; start += 4) {
            if ((u32(b + start) ^ key) != 0x536e6144 || (end - start - 16) % 8)
                continue;
            if ((u32(b + start + 4) ^ key) || (u32(b + start + 8) ^ key) ||
                (u32(b + start + 12) ^ key)) continue;
            uint32_t sum = (uint32_t)start;
            for (size_t j = 0; j < start; ++j)
                if (j < 0x3c || j >= 0x40) sum += rotate(b[j], (unsigned)j);
            for (size_t j = start + 16; j < end; j += 8)
                sum += rotate(u32(b + j) ^ key, u32(b + j + 4) ^ key);
            if (sum == key && end > start + 16) {
                r->rich = 1; r->rich_invalid = 0; free(b); return;
            }
        }
    }
    free(b);
}

static void detect_clr(FILE *f, uint64_t size, const PE_OPTIONAL_INFO *o,
                        const PE_SECTION_INFO *s, size_t count,
                        const PE_DATA_DIRECTORY *d, PE_BUILD_INFO *r)
{
    if (!d->virtual_address && !d->size) return;
    unsigned char h[72], m[20];
    if (!d->virtual_address || d->size < sizeof(h) ||
        !rva_read(f, size, o, s, count, d->virtual_address, h, sizeof(h)) ||
        u32(h) < sizeof(h) || u32(h) > d->size || !u32(h + 8) ||
        u32(h + 12) < sizeof(m) ||
        !rva_read(f, size, o, s, count, u32(h + 8), m, sizeof(m)) ||
        memcmp(m, "BSJB", 4) || !u32(m + 12) || u32(m + 12) > 256 ||
        (uint64_t)u32(m + 12) + 20 > u32(h + 12)) {
        r->incomplete = 1;
        return;
    }
    unsigned char version[256];
    if (!rva_read(f, size, o, s, count, (uint64_t)u32(h + 8) + 16,
                  version, u32(m + 12)) || !memchr(version, 0, u32(m + 12))) {
        r->incomplete = 1; return;
    }
    r->clr = 1; /* CLR/metadata headers, not validation of all metadata streams. */
}

/* Modern Go inline build-info version. Older pointer-based layouts remain
 * a weak marker instead of being misinterpreted as inline strings. */
static void detect_go(const unsigned char *b, size_t n, uint64_t rva, PE_BUILD_INFO *r)
{
    if (n < 32 || rva % 16 || memcmp(b, "\xff Go buildinf:", 14)) return;
    if ((b[14] != 4 && b[14] != 8) || (b[15] & ~3)) return;
    r->go_marker = 1;
    if (!(b[15] & 2) || n < 34) return;
    size_t len = b[32];
    if (len & 128 || len < 4 || len >= sizeof(r->go_version) || 33 + len > n) return;
    if (memcmp(b + 33, "go1.", 4)) return;
    for (size_t i = 0; i < len; ++i)
        if (b[33 + i] < 32 || b[33 + i] > 126) return;
    memcpy(r->go_version, b + 33, len);
    r->go_version[len] = 0;
    r->go = 1;
}

typedef struct { const char *text; int kind; } MARKER;
/* These are embedded artifacts, potentially from a linked dependency. Do not
 * treat plain library names, PE linker version or section names as proof. */
static const MARKER markers[] = {
    {"GCC: (", 0}, {"GNU C17 ", 0}, {"GNU C11 ", 0}, {"GNU C99 ", 0},
    {"GNU C++14 ", 0}, {"GNU C++17 ", 0}, {"GNU C++20 ", 0},
    {"clang version ", 1},
    {"Microsoft (R) Optimizing Compiler", 2},
    {"Mingw-w64 runtime failure:", 3}, {"__mingw_vfprintf", 3},
    {"__mingw_get_crt_info", 3}, {"llvm-mingw", 4},
    {"LLD Linker", 5}, {"Linker: LLD ", 5}, {"GNU ld (", 6}
};
static void marker(PE_BUILD_INFO *r, int kind, uint32_t off)
{
    int *flags[] = {&r->gcc, &r->clang, &r->msvc, &r->mingw,
                   &r->llvm_mingw, &r->lld, &r->gnu_ld};
    uint32_t *offsets[] = {&r->gcc_offset, &r->clang_offset, &r->msvc_offset,
                         &r->mingw_offset, &r->llvm_mingw_offset,
                         &r->lld_offset, &r->gnu_ld_offset};
    if (!*flags[kind]) { *flags[kind] = 1; *offsets[kind] = off; }
}

int detect_build_tools(FILE *file, const PE_DOS_INFO *dos,
                       const PE_OPTIONAL_INFO *optional,
                       const PE_SECTION_INFO *sections, size_t count,
                       uint64_t file_size, const PE_DATA_DIRECTORY *directories,
                       PE_BUILD_INFO *r)
{
    memset(r, 0, sizeof(*r));
    detect_rich(file, file_size, dos, r);
    detect_clr(file, file_size, optional, sections, count, &directories[14], r);
    unsigned char *buffer = malloc(CHUNK + OVERLAP);
    if (!buffer) { r->incomplete = 1; return 0; }
    uint64_t budget = SCAN_LIMIT;
    for (size_t i = 0; i < count; ++i) {
        const PE_SECTION_INFO *s = &sections[i];
        uint64_t length = s->size_of_raw_data;
        if (!length) continue;
        if (!file_range_valid(file_size, s->pointer_to_raw_data, length)) {
            r->incomplete = 1; continue;
        }
        if (length > budget) { length = budget; r->incomplete = 1; }
        budget -= length;
        for (uint64_t pos = 0; pos < length; pos += CHUNK) {
            size_t n = length - pos > CHUNK + OVERLAP ? CHUNK + OVERLAP : (size_t)(length - pos);
            if (!read_at(file, file_size, (uint64_t)s->pointer_to_raw_data + pos, buffer, n)) {
                r->incomplete = 1; break;
            }
            size_t starts = n > CHUNK ? CHUNK : n;
            for (size_t j = 0; j < starts; ++j) {
                detect_go(buffer + j, n - j, (uint64_t)s->virtual_address + pos + j, r);
                for (size_t k = 0; k < sizeof(markers)/sizeof(markers[0]); ++k) {
                    if (buffer[j] != (unsigned char)markers[k].text[0]) continue;
                    size_t size = strlen(markers[k].text);
                    if (size <= n - j && !memcmp(buffer + j, markers[k].text, size)) {
                        uint64_t off = (uint64_t)s->pointer_to_raw_data + pos + j;
                        if (off <= UINT32_MAX) marker(r, markers[k].kind, (uint32_t)off);
                    }
                }
            }
        }
    }
    free(buffer);
    return !r->incomplete;
}

static void artifact(const char *what, uint32_t offset)
{
    printf("  - %s at file offset 0x%08" PRIX32 " (embedded marker).\n", what, offset);
}
void print_build_tools(const PE_BUILD_INFO *r, const PE_OPTIONAL_INFO *o)
{
    printf("\nBuild tool detection (heuristic)\n\n");
    int compilers = r->gcc + r->clang + r->msvc + r->go;
    if (compilers > 1) printf("Compiler: mixed evidence; primary compiler unknown\n");
    else if (r->clang) printf("Compiler: LLVM/Clang candidate [medium]\n");
    else if (r->gcc) printf("Compiler: GCC candidate [medium]\n");
    else if (r->msvc) printf("Compiler: MSVC candidate [medium]\n");
    else if (r->go) printf("Compiler: Go toolchain candidate [medium]\n");
    else printf("Compiler: unknown\n");

    if (r->mingw && r->clang && !r->gcc)
        printf("Toolchain: Clang + MinGW-compatible [medium]; LLVM-MinGW distribution unconfirmed\n");
    else if (r->mingw && r->gcc && !r->clang)
        printf("Toolchain: MinGW GCC-compatible [medium]\n");
    else if (r->mingw) printf("Toolchain: MinGW-compatible [low]; compiler not established by runtime\n");
    else if (r->rich) printf("Toolchain: Microsoft-compatible build artifacts [medium]\n");
    else printf("Toolchain: unknown\n");
    if (r->llvm_mingw) printf("Distribution hint: LLVM-MinGW [low; embedded text only]\n");

    if ((r->lld + r->gnu_ld + r->rich) > 1)
        printf("Linker: mixed evidence; final linker unknown\n");
    else if (r->lld) printf("Linker: LLVM LLD candidate [low]\n");
    else if (r->gnu_ld) printf("Linker: GNU ld candidate [low]\n");
    else if (r->rich) printf("Linker: Microsoft LINK-compatible candidate [medium]\n");
    else printf("Linker: unknown\n");
    printf("PE linker version field: %u.%u (not an identity)\n",
           o->major_linker_version, o->minor_linker_version);

    if (r->clr) printf("Runtime: .NET/CLR metadata [high]; source language unknown\n");
    if (r->go) printf("Runtime: Go build-info %s [high]\n", r->go_version);
    else if (r->go_marker) printf("Runtime: possible Go [low; build-info version not decoded]\n");
    if (!r->clr && !r->go_marker) printf("Runtime: unknown\n");
    printf("\nEvidence:\n");
    if (r->gcc) artifact("GCC producer text", r->gcc_offset);
    if (r->clang) artifact("Clang producer text", r->clang_offset);
    if (r->msvc) artifact("MSVC compiler banner", r->msvc_offset);
    if (r->mingw) artifact("MinGW runtime/symbol text", r->mingw_offset);
    if (r->llvm_mingw) artifact("llvm-mingw text", r->llvm_mingw_offset);
    if (r->lld) artifact("LLD identifier", r->lld_offset);
    if (r->gnu_ld) artifact("GNU ld identifier", r->gnu_ld_offset);
    if (r->rich) printf("  - Rich/DanS records with matching checksum; product IDs not classified.\n");
    if (r->rich_invalid) printf("  - Rich marker failed structural/checksum checks; ignored.\n");
    if (r->clr) printf("  - CLR header and BSJB metadata root/version string.\n");
    if (r->go_marker) printf("  - Aligned Go build-info header in section raw data.\n");
    if (!compilers && !r->mingw && !r->llvm_mingw && !r->lld && !r->gnu_ld &&
        !r->rich && !r->rich_invalid && !r->clr && !r->go_marker)
        printf("  - No supported identifying artifacts found.\n");
    printf("\nConfidence labels are heuristic, not probabilities.\n");
    printf("Artifacts may belong to dependencies or be forged; absence proves nothing.\n");
    if (r->incomplete) printf("Scan: incomplete (limit, invalid metadata or unreadable data).\n");
}

void print_build_summary(const PE_BUILD_INFO *r)
{
    const char *compiler = "unknown";
    int count = r->gcc + r->clang + r->msvc + r->go;
    if (count > 1) compiler = "unknown (mixed evidence)";
    else if (r->clang) compiler = r->mingw ? "Clang / MinGW (likely)" : "LLVM/Clang (likely)";
    else if (r->gcc) compiler = r->mingw ? "GCC / MinGW (likely)" : "GCC (likely)";
    else if (r->msvc) compiler = "MSVC (likely)";
    else if (r->go) compiler = "Go toolchain (likely)";
    else if (r->mingw) compiler = "unknown / MinGW-compatible";
    const char *linker = "unknown";
    if (r->lld + r->gnu_ld + r->rich > 1) linker = "unknown (mixed evidence)";
    else if (r->lld) linker = "LLVM LLD (possible)";
    else if (r->gnu_ld) linker = "GNU ld (possible)";
    else if (r->rich) linker = "Microsoft LINK-compatible (likely)";
    printf("Compiler:        %s\n", compiler);
    printf("Linker:          %s\n", linker);
    printf("Runtime:         ");
    if (r->clr) printf(".NET/CLR%s", r->go_marker ? "; " : "");
    if (r->go) printf("Go %s", r->go_version);
    else if (r->go_marker) printf("Go (possible)");
    else if (!r->clr) printf("unknown");
    putchar('\n');
}
