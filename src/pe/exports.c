#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "pe/exports.h"
#include "pe/utils.h"

#define MAX_EXPORTS 65536u
#define NONE UINT32_MAX

typedef struct {
    FILE *file;
    const PE_OPTIONAL_INFO *optional;
    const PE_SECTION_INFO *sections;
    size_t count;
    uint64_t file_size;
} EXPORT_READER;
typedef struct { uint32_t target, head, tail; } SLOT;
typedef struct { uint32_t rva, next; } NAME;

static int warning(const char *message)
{
    fprintf(stderr, "Warning: exports: %s\n", message);
    return 0;
}
static int read_rva(const EXPORT_READER *r, uint64_t rva, unsigned char *out, size_t n)
{
    if (rva > UINT32_MAX || n > UINT64_C(0x100000000) - rva) return 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t off;
        if (!rva_to_file_offset(r->sections, r->count, r->optional->size_of_headers,
                               r->file_size, (uint32_t)(rva + i), &off)) return 0;
#if LONG_MAX < UINT32_MAX
        if (off > LONG_MAX) return 0;
#endif
        if (fseek(r->file, (long)off, SEEK_SET) || fread(out + i, 1, 1, r->file) != 1)
            return 0;
    }
    return 1;
}
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static int value(const EXPORT_READER *r, uint64_t rva, size_t n, uint32_t *out)
{
    unsigned char b[4] = {0};
    if (!read_rva(r, rva, b, n)) return 0;
    *out = u32(b);
    return 1;
}
static int name(const EXPORT_READER *r, uint64_t rva, uint64_t end, char out[1025])
{
    for (size_t i = 0; i < 1025 && rva + i < end; ++i) {
        unsigned char ch;
        if (!read_rva(r, rva + i, &ch, 1)) return 0;
        if (!ch) { out[i] = 0; return i != 0; }
        if (i == 1024) return 0;
        out[i] = ch >= 32 && ch <= 126 ? (char)ch : '?';
    }
    return 0;
}

int visit_exports(FILE *file, const PE_OPTIONAL_INFO *optional,
                  const PE_SECTION_INFO *sections, size_t count,
                  uint64_t file_size, const PE_DATA_DIRECTORY *d,
                  const PE_EXPORT_VISITOR *visitor)
{
    if (!d->virtual_address && !d->size) return 1;
    uint64_t end = (uint64_t)d->virtual_address + d->size;
    if (!d->virtual_address || d->size < 40 || end > UINT64_C(0x100000000))
        return warning("invalid Export Directory range.");
    EXPORT_READER r = {file, optional, sections, count, file_size};
    unsigned char h[40];
    if (!read_rva(&r, d->virtual_address, h, sizeof(h)))
        return warning("unreadable Export Directory header.");
    uint32_t base = u32(h + 16), slots_count = u32(h + 20), names_count = u32(h + 24);
    uint32_t eat = u32(h + 28), names = u32(h + 32), ordinals = u32(h + 36);
    if (slots_count > MAX_EXPORTS || names_count > MAX_EXPORTS)
        return warning("analysis limit exceeded (65536 EAT slots or names).");
    if ((slots_count && (!eat || (uint64_t)base + slots_count - 1 > UINT32_MAX ||
                        (uint64_t)eat + (uint64_t)slots_count * 4 > UINT64_C(0x100000000))) ||
        (names_count && (!names || !ordinals || !slots_count)))
        return warning("invalid table pointers, counts or ordinal range.");
    char module[1025];
    if (!u32(h + 12) || !name(&r, u32(h + 12), UINT64_C(0x100000000), module))
        return warning("invalid or oversized module name.");
    SLOT *slots = calloc(slots_count ? slots_count : 1, sizeof(*slots));
    NAME *entries = calloc(names_count ? names_count : 1, sizeof(*entries));
    if (!slots || !entries) {
        free(slots); free(entries);
        return warning("cannot allocate export tables.");
    }
    const char *error = NULL;
    for (uint32_t i = 0; i < slots_count; ++i) {
        slots[i].head = slots[i].tail = NONE;
        if (!value(&r, (uint64_t)eat + (uint64_t)i * 4, 4, &slots[i].target)) {
            error = "unreadable EAT slot."; goto done;
        }
    }
    /* Each name ordinal is an unbiased EAT index, not the public ordinal. */
    for (uint32_t i = 0; i < names_count; ++i) {
        uint32_t index;
        if (!value(&r, (uint64_t)ordinals + (uint64_t)i * 2, 2, &index) ||
            !value(&r, (uint64_t)names + (uint64_t)i * 4, 4, &entries[i].rva) ||
            index >= slots_count || !entries[i].rva || !slots[index].target) {
            error = "invalid name table or ordinal index."; goto done;
        }
        entries[i].next = NONE;
        if (slots[index].tail != NONE) entries[slots[index].tail].next = i;
        else slots[index].head = i;
        slots[index].tail = i;
    }
    visitor->module(module, slots_count, names_count);
    for (uint32_t i = 0; i < slots_count; ++i) {
        if (!slots[i].target) continue; /* Holes in the EAT are not exports. */
        PE_EXPORT_ENTRY e = {0};
        e.ordinal = base + i;
        e.eat_rva = eat + i * 4;
        e.target_rva = slots[i].target;
        e.is_forwarder = e.target_rva >= d->virtual_address && e.target_rva < end;
        if (e.is_forwarder) {
            if (!name(&r, e.target_rva, end, e.forwarder)) {
                error = "invalid forwarder or terminator outside Export Directory."; goto done;
            }
            const char *dot = strchr(e.forwarder, '.');
            if (!dot || dot == e.forwarder || !dot[1]) {
                error = "invalid forwarder syntax."; goto done;
            }
        } else if (e.target_rva >= optional->size_of_image) {
            error = "export target RVA is outside SizeOfImage."; goto done;
        }
        e.has_file_offset = rva_to_file_offset(sections, count, optional->size_of_headers,
                                               file_size, e.target_rva, &e.file_offset);
        if (!e.is_forwarder && !e.has_file_offset) {
            int zero_filled = 0;
            for (size_t j = 0; j < count; ++j) {
                const PE_SECTION_INFO *section = &sections[j];
                if (e.target_rva >= section->virtual_address) {
                    uint64_t delta = (uint64_t)e.target_rva - section->virtual_address;
                    if (delta < section->virtual_size && delta >= section->size_of_raw_data)
                        zero_filled = 1;
                }
            }
            if (!zero_filled) {
                error = "export target has neither a file byte nor zero-filled section storage.";
                goto done;
            }
        }
        /* An exported variable can live in zero-filled memory without a file byte. */
        uint32_t index = slots[i].head;
        if (index == NONE) visitor->entry(&e);
        else for (; index != NONE; index = entries[index].next) {
            if (!name(&r, entries[index].rva, UINT64_C(0x100000000), e.name)) {
                error = "invalid, unterminated or oversized export name."; goto done;
            }
            visitor->entry(&e);
        }
    }
done:
    free(slots); free(entries);
    return error ? warning(error) : 1;
}
