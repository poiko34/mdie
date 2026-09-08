#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include "imports.h"
#include "pe_defs.h"
#include "pe_utils.h"

#define MAX_IMPORT_DLLS 4096
#define MAX_IMPORT_ENTRIES 65536

typedef struct {
    FILE *file;
    const PE_OPTIONAL_INFO *optional;
    const PE_SECTION_INFO *sections;
    size_t count;
    uint64_t file_size;
} IMPORT_READER;

static int warning(const char *message)
{
    fprintf(stderr, "Warning: imports: %s\n", message);
    return 0;
}

/* Map every byte, including reads crossing section boundaries. No assumption
 * that adjacent RVAs correspond to adjacent physical file bytes. */
static int read_rva(const IMPORT_READER *r, uint64_t rva, unsigned char *out, size_t n)
{
    if (rva > UINT32_MAX || n > (uint64_t)UINT32_MAX + 1 - rva) return 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t offset;
        if (!rva_to_file_offset(r->sections, r->count, r->optional->size_of_headers,
                               r->file_size, (uint32_t)(rva + i), &offset)) return 0;
#if LONG_MAX < UINT32_MAX
        if (offset > LONG_MAX) return 0;
#endif
        if (fseek(r->file, (long)offset, SEEK_SET) != 0 ||
            fread(out + i, 1, 1, r->file) != 1) return 0;
    }
    return 1;
}

static uint64_t decode(const unsigned char *bytes, size_t n)
{
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static int read_value(const IMPORT_READER *r, uint64_t rva, size_t width, uint64_t *v)
{
    unsigned char bytes[8];
    if (!read_rva(r, rva, bytes, width)) return 0;
    *v = decode(bytes, width);
    return 1;
}

static int read_name(const IMPORT_READER *r, uint64_t rva, char *name, size_t capacity)
{
    for (size_t i = 0; i < capacity; ++i) {
        unsigned char ch;
        if (!read_rva(r, rva + i, &ch, 1)) return 0;
        if (!ch) { name[i] = '\0'; return i != 0; }
        if (i + 1 == capacity) return 0;
        name[i] = ch >= 32 && ch <= 126 ? (char)ch : '?';
    }
    return 0;
}

static int visit_thunks(const IMPORT_READER *r, uint32_t lookup, uint32_t iat,
                         int bound_without_names, size_t *total,
                         const PE_IMPORT_VISITOR *visitor)
{
    size_t width = r->optional->magic == PE32P ? 8 : 4;
    uint64_t flag = width == 8 ? UINT64_C(0x8000000000000000) : UINT64_C(0x80000000);
    for (uint64_t index = 0; ; ++index) {
        uint64_t thunk, stored;
        uint64_t lookup_rva = (uint64_t)lookup + index * width;
        uint64_t iat_rva = (uint64_t)iat + index * width;
        if (!read_value(r, lookup_rva, width, &thunk) ||
            !read_value(r, iat_rva, width, &stored))
            return warning("thunk/IAT range is unreadable or lacks a terminator.");
        if (!thunk) {
            if (stored) return warning("IAT and lookup table terminators disagree.");
            return 1;
        }
        if (!stored) return warning("IAT ends before the lookup table.");
        if (*total >= MAX_IMPORT_ENTRIES)
            return warning("analysis limit reached (65536 imports); output is incomplete.");
        PE_IMPORT_ENTRY entry = {0};
        entry.iat_rva = (uint32_t)iat_rva;
        if (!rva_to_file_offset(r->sections, r->count, r->optional->size_of_headers,
                               r->file_size, entry.iat_rva, &entry.file_offset))
            return warning("IAT slot has no file offset.");
        entry.value = stored;
        entry.bound_without_names = bound_without_names;
        if (!bound_without_names) {
            if (thunk & flag) {
                if (thunk & ~(flag | UINT64_C(0xffff)))
                    return warning("ordinal thunk contains reserved bits.");
                entry.by_ordinal = 1;
                entry.hint_or_ordinal = (uint16_t)thunk;
            } else {
                uint64_t hint;
                if (thunk > 0x7fffffff || !read_value(r, thunk, 2, &hint) ||
                    !read_name(r, thunk + 2, entry.name, sizeof(entry.name)))
                    return warning("invalid, unterminated or oversized import name (max 1024 bytes).");
                entry.hint_or_ordinal = (uint16_t)hint;
            }
        }
        visitor->entry(&entry);
        ++*total;
    }
}

int visit_imports(FILE *file, const PE_OPTIONAL_INFO *optional,
                  const PE_SECTION_INFO *sections, size_t count,
                  uint64_t file_size, const PE_DATA_DIRECTORY *directory,
                  const PE_IMPORT_VISITOR *visitor)
{
    if (!directory->virtual_address && !directory->size) return 1;
    if (!directory->virtual_address || directory->size < 20 ||
        (uint64_t)directory->virtual_address + directory->size > UINT64_C(0x100000000))
        return warning("invalid Import Directory range.");
    IMPORT_READER r = {file, optional, sections, count, file_size};
    size_t total = 0;
    int valid = 1;
    for (uint64_t index = 0; (index + 1) * 20 <= directory->size; ++index) {
        unsigned char bytes[20];
        if (!read_rva(&r, (uint64_t)directory->virtual_address + index * 20, bytes, 20))
            return warning("unreadable import descriptor.");
        uint32_t fields[5];
        int empty = 1;
        for (size_t j = 0; j < 5; ++j) {
            fields[j] = (uint32_t)decode(bytes + j * 4, 4);
            if (fields[j]) empty = 0;
        }
        if (empty) return valid;
        if (index >= MAX_IMPORT_DLLS)
            return warning("analysis limit reached (4096 DLLs); output is incomplete.");
        char dll[257];
        if (!fields[3] || !fields[4] ||
            !read_name(&r, fields[3], dll, sizeof(dll))) {
            warning("invalid DLL name or missing FirstThunk.");
            valid = 0;
            continue;
        }
        int fallback = fields[0] == 0;
        int bound = fields[1] != 0;
        visitor->dll(dll, fallback, bound);
        if (!visit_thunks(&r, fallback ? fields[4] : fields[0], fields[4],
                          fallback && bound, &total, visitor)) valid = 0;
        if (total >= MAX_IMPORT_ENTRIES)
            return warning("analysis limit reached (65536 imports); remaining descriptors were not checked.");
    }
    return warning("Import Directory has no terminating null descriptor within its declared size.");
}
