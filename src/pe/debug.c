#include <limits.h>
#include <string.h>

#include "pe/debug.h"
#include "pe/utils.h"

static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int read_at(FILE *file, uint64_t file_size, uint64_t offset,
                   void *out, size_t size)
{
    if (!file_range_valid(file_size, offset, size) || offset > LONG_MAX)
        return 0;
    return fseek(file, (long)offset, SEEK_SET) == 0 &&
           fread(out, 1, size, file) == size;
}

static int read_record(FILE *file, const PE_OPTIONAL_INFO *optional,
                       const PE_SECTION_INFO *sections, size_t count,
                       uint64_t file_size, uint64_t rva, unsigned char out[28])
{
    /* Resolve every byte: neither EOF nor a virtual-only section tail may
     * supply bytes merely because the start of a record was mapped. */
    if (rva > UINT32_MAX || 28 > UINT64_C(0x100000000) - rva) return 0;
    for (size_t i = 0; i < 28; ++i) {
        uint32_t offset;
        if (!rva_to_file_offset(sections, count, optional->size_of_headers,
                                file_size, (uint32_t)(rva + i), &offset) ||
            !read_at(file, file_size, offset, out + i, 1)) return 0;
    }
    return 1;
}

static const char *read_codeview(FILE *file, uint64_t file_size, PE_DEBUG_ENTRY *e)
{
    unsigned char header[24];
    if (e->size < 4 || !read_at(file, file_size, e->file_offset, header, 4))
        return "truncated CodeView signature.";
    memcpy(e->signature, header, 4);
    e->codeview = PE_CODEVIEW_UNKNOWN;
    size_t header_size;
    if (!memcmp(header, "RSDS", 4)) header_size = 24;
    else if (!memcmp(header, "NB10", 4)) header_size = 16;
    else return NULL;

    if (e->size <= header_size ||
        !read_at(file, file_size, e->file_offset, header, header_size))
        return "truncated CodeView header or missing PDB path terminator.";

    size_t path_size = e->size - header_size;
    if (path_size > sizeof(e->pdb_path)) path_size = sizeof(e->pdb_path);
    if (!read_at(file, file_size, (uint64_t)e->file_offset + header_size,
                 e->pdb_path, path_size)) return "unreadable PDB path.";
    if (!memchr(e->pdb_path, 0, path_size)) {
        e->pdb_path[0] = 0;
        return "unterminated PDB path or path limit exceeded (4096 bytes).";
    }

    if (header_size == 24) {
        e->codeview = PE_CODEVIEW_RSDS;
        memcpy(e->guid, header + 4, sizeof(e->guid));
        e->age = u32(header + 20);
    } else {
        e->codeview = PE_CODEVIEW_NB10;
        e->timestamp = u32(header + 8);
        e->age = u32(header + 12);
    }
    return NULL;
}

int visit_debug(FILE *file, const PE_OPTIONAL_INFO *optional,
                const PE_SECTION_INFO *sections, size_t count,
                uint64_t file_size, const PE_DATA_DIRECTORY *d,
                const PE_DEBUG_VISITOR *visitor)
{
    if (!d->virtual_address && !d->size) return 1;
    if (!d->virtual_address || !d->size ||
        (uint64_t)d->virtual_address + d->size > UINT64_C(0x100000000)) {
        visitor->warning("invalid Debug Directory range.");
        return 0;
    }
    int valid = 1;
    if (d->size % 28) {
        visitor->warning("Debug Directory size is not a multiple of 28 bytes.");
        valid = 0;
    }
    uint32_t entries = d->size / 28;
    if (entries > PE_DEBUG_MAX_ENTRIES) {
        visitor->warning("Debug Directory entry limit exceeded (4096 entries).");
        return 0;
    }
    for (uint32_t i = 0; i < entries; ++i) {
        unsigned char h[28];
        if (!read_record(file, optional, sections, count, file_size,
                          (uint64_t)d->virtual_address + (uint64_t)i * 28, h)) {
            visitor->warning("unreadable or truncated Debug Directory record.");
            return 0;
        }
        PE_DEBUG_ENTRY e = {0};
        e.index = i + 1;
        e.type = u32(h + 12);
        e.size = u32(h + 16);
        e.data_rva = u32(h + 20);
        e.file_offset = u32(h + 24);
        if (e.size && (!e.file_offset ||
            !file_range_valid(file_size, e.file_offset, e.size)))
            e.error = "invalid debug payload file range.";
        else if (e.type == 2) e.error = read_codeview(file, file_size, &e);
        if (e.error) valid = 0;
        visitor->entry(&e);
    }
    return valid;
}
