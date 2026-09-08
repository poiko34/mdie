#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "pe/utils.h"
#include "resources_internal.h"

typedef struct {
    FILE *file;
    const PE_OPTIONAL_INFO *optional;
    const PE_SECTION_INFO *sections;
    size_t count;
    uint64_t file_size;
    const PE_DATA_DIRECTORY *directory;
    const PE_RESOURCE_VISITOR *visitor;
    uint32_t ancestors[3];
    unsigned entries;
    size_t text_budget;
    int valid, stopped;
} RESOURCE_READER;

static uint16_t u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void warning(RESOURCE_READER *r, const char *message)
{
    r->valid = 0;
    r->visitor->warning(message, r->visitor->context);
}

/* Check/read whole RVA ranges in mapped spans, without scanning large opaque
 * payloads byte by byte. Stop spans at mapping boundaries, including overlap
 * starts, to preserve the shared RVA resolver's first-section semantics. */
static int read_rva(const RESOURCE_READER *r, uint64_t rva, uint64_t size,
                    unsigned char *out)
{
    if (rva > UINT32_MAX || size > UINT64_C(0x100000000) - rva) return 0;
    while (size) {
        uint32_t off;
        if (!rva_to_file_offset(r->sections, r->count, r->optional->size_of_headers,
                                r->file_size, (uint32_t)rva, &off)) return 0;
        uint64_t end = rva;
        if (rva < r->optional->size_of_headers) end = r->optional->size_of_headers;
        else for (size_t i = 0; i < r->count; ++i) {
            const PE_SECTION_INFO *s = r->sections + i;
            if (rva >= s->virtual_address &&
                rva - s->virtual_address < s->virtual_size) {
                uint32_t span = s->virtual_size < s->size_of_raw_data ?
                                s->virtual_size : s->size_of_raw_data;
                end = (uint64_t)s->virtual_address + span;
                break;
            }
        }
        for (size_t i = 0; i < r->count; ++i)
            if (r->sections[i].virtual_address > rva && r->sections[i].virtual_address < end)
                end = r->sections[i].virtual_address;
        if (end <= rva) return 0;
        uint64_t n = end - rva;
        if (n > size) n = size;
        if (n > UINT64_C(0x100000000) - off || !file_range_valid(r->file_size, off, n)) return 0;
        if (out) {
#if LONG_MAX < UINT32_MAX
            if (off > LONG_MAX) return 0;
#endif
            if (n > SIZE_MAX ||
                fseek(r->file, (long)off, SEEK_SET) ||
                fread(out, 1, (size_t)n, r->file) != (size_t)n) return 0;
            out += (size_t)n;
        }
        rva += n;
        size -= n;
    }
    return 1;
}

static int read_relative(const RESOURCE_READER *r, uint64_t off, size_t size, unsigned char *out)
{
    return file_range_valid(r->directory->size, off, size) &&
           read_rva(r, (uint64_t)r->directory->virtual_address + off, size, out);
}

static int read_name(RESOURCE_READER *r, uint32_t value, PE_RESOURCE_NAME *name)
{
    name->named = (value >> 31) != 0;
    if (!name->named) {
        name->id = value;
        return value <= UINT16_MAX;
    }
    uint32_t off = value & 0x7fffffff;
    unsigned char data[PE_RESOURCE_MAX_NAME * 2], h[2];
    if (!read_relative(r, off, 2, h)) return 0;
    size_t units = u16(h), length;
    if (units > PE_RESOURCE_MAX_NAME ||
        !read_relative(r, (uint64_t)off + 2, units * 2, data) ||
        !resource_text(data, units * 2, 1, 0, name->name, sizeof(name->name), &length)) return 0;
    return !memchr(name->name, 0, length);
}

static void payload(RESOURCE_READER *r, uint32_t off, uint32_t type)
{
    unsigned char h[16];
    if (!read_relative(r, off, sizeof(h), h)) {
        warning(r, "unreadable resource data entry.");
        return;
    }
    PE_RESOURCE_DATA data = {0};
    data.rva = u32(h);
    data.size = u32(h + 4);
    data.codepage = u32(h + 8);
    data.has_file_offset = rva_to_file_offset(r->sections, r->count,
        r->optional->size_of_headers, r->file_size, data.rva, &data.file_offset);
    data.valid = (!data.size || data.rva) && read_rva(r, data.rva, data.size, NULL);
    r->visitor->data(&data, r->visitor->context);
    if (!data.valid) { warning(r, "invalid resource payload RVA/file range."); return; }
    if (u32(h + 12)) warning(r, "nonzero reserved field in resource data entry.");
    if (type != 16 && type != 24) return;
    if (type == 16 && data.size > PE_RESOURCE_MAX_VERSION) {
        warning(r, "version resource size limit exceeded (65536 bytes)."); return;
    }
    size_t size = data.size;
    int truncated = type == 24 && size > PE_RESOURCE_MAX_MANIFEST;
    if (truncated) size = PE_RESOURCE_MAX_MANIFEST;
    if (size > r->text_budget) {
        warning(r, "resource text budget exceeded (262144 bytes); content omitted."); return;
    }
    r->text_budget -= size;
    unsigned char *bytes = malloc(size ? size : 1);
    if (!bytes) { warning(r, "cannot allocate resource payload."); return; }
    if (!read_rva(r, data.rva, size, bytes)) warning(r, "unreadable resource payload.");
    else if (type == 16) {
        if (!resource_version(bytes, size, r->visitor)) r->valid = 0;
    } else {
        size_t skip = 0, length = 0;
        int encoding = 0;
        if (size >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe) { encoding = 1; skip = 2; }
        else if (size >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) { encoding = 2; skip = 2; }
        else if (size >= 3 && !memcmp(bytes, "\xef\xbb\xbf", 3)) skip = 3;
        else if (size >= 4 && bytes[0] == '<' && bytes[1] == 0) encoding = 1;
        else if (size >= 4 && bytes[0] == 0 && bytes[1] == '<') encoding = 2;
        char *text = malloc(size * 3 + 1);
        if (!text) warning(r, "cannot allocate manifest text.");
        else {
            if (!resource_text(bytes + skip, size - skip, encoding, truncated,
                                text, size * 3 + 1, &length))
                warning(r, "invalid manifest UTF-8/UTF-16 encoding.");
            else r->visitor->manifest(text, length, truncated, r->visitor->context);
            free(text);
        }
        if (truncated) warning(r, "manifest preview truncated at 16384 input bytes.");
    }
    free(bytes);
}

static void directory(RESOURCE_READER *r, uint32_t off, unsigned depth, uint32_t type)
{
    for (unsigned i = 0; i < depth; ++i)
        if (r->ancestors[i] == off) { warning(r, "cycle in resource directory tree."); return; }
    if (depth >= 3) { warning(r, "resource tree depth exceeds type/name/language levels."); return; }
    r->ancestors[depth] = off;
    unsigned char h[16];
    if (!read_relative(r, off, sizeof(h), h)) { warning(r, "unreadable resource directory header."); return; }
    uint32_t named = u16(h + 12), count = named + u16(h + 14);
    if (count > PE_RESOURCE_MAX_ENTRIES - r->entries) {
        warning(r, "resource entry limit exceeded (1024 entries)."); r->stopped = 1; return;
    }
    if (!file_range_valid(r->directory->size, (uint64_t)off + 16, (uint64_t)count * 8)) {
        warning(r, "resource entry table exceeds Resource Directory size."); return;
    }
    for (uint32_t i = 0; i < count && !r->stopped; ++i) {
        if (r->entries == PE_RESOURCE_MAX_ENTRIES) {
            warning(r, "resource entry limit exceeded (1024 entries)."); r->stopped = 1; return;
        }
        ++r->entries;
        unsigned char e[8];
        if (!read_relative(r, (uint64_t)off + 16 + (uint64_t)i * 8, sizeof(e), e)) {
            warning(r, "unreadable resource directory entry."); return;
        }
        PE_RESOURCE_NAME name = {0};
        if (!read_name(r, u32(e), &name)) {
            warning(r, "invalid resource ID/name, UTF-16 or name limit (256 units)."); continue;
        }
        if (name.named != (i < named)) warning(r, "resource named/ID entry counts disagree with entries.");
        r->visitor->node(depth, &name, r->visitor->context);
        uint32_t target = u32(e + 4);
        uint32_t next_type = depth == 0 ? (name.named ? UINT32_MAX : name.id) : type;
        if (target >> 31) directory(r, target & 0x7fffffff, depth + 1, next_type);
        else if (depth != 2) warning(r, "resource data leaf is not at language level.");
        else payload(r, target, next_type);
    }
}

int visit_resources(FILE *file, const PE_OPTIONAL_INFO *optional,
                    const PE_SECTION_INFO *sections, size_t count,
                    uint64_t file_size, const PE_DATA_DIRECTORY *d,
                    const PE_RESOURCE_VISITOR *visitor)
{
    RESOURCE_READER r = {file, optional, sections, count, file_size, d, visitor,
                         {0}, 0, PE_RESOURCE_TEXT_BUDGET, 1, 0};
    if (!d->virtual_address && !d->size) return 1;
    if (!d->virtual_address || d->size < 16 ||
        (uint64_t)d->virtual_address + d->size > UINT64_C(0x100000000)) {
        warning(&r, "invalid Resource Directory range."); return 0;
    }
    if (!read_rva(&r, d->virtual_address, d->size, NULL))
        warning(&r, "declared Resource Directory range is not fully file-backed.");
    directory(&r, 0, 0, UINT32_MAX);
    return r.valid;
}
