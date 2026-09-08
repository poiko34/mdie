#include <math.h>
#include <stdint.h>
#include <limits.h>

#include "pe_utils.h"
#include "pe_defs.h"

static int read_le(FILE *file, size_t width, uint64_t *value)
{
    unsigned char bytes[8];
    if (fread(bytes, 1, width, file) != width) {
        fprintf(stderr, "Error: truncated data or read failure (%zu-byte field).\n", width);
        return 0;
    }
    *value = 0;
    for (size_t i = 0; i < width; ++i)
        *value |= (uint64_t)bytes[i] << (8 * i);
    return 1;
}

int read_u16_le(FILE *file, uint16_t *value)
{
    uint64_t v;
    if (!read_le(file, 2, &v)) return 0;
    *value = (uint16_t)v;
    return 1;
}

int read_u32_le(FILE *file, uint32_t *value)
{
    uint64_t v;
    if (!read_le(file, 4, &v)) return 0;
    *value = (uint32_t)v;
    return 1;
}

int read_u64_le(FILE *file, uint64_t *value)
{
    return read_le(file, 8, value);
}

int get_file_size(FILE *file, uint64_t *size)
{
    long position = ftell(file);
    if (position < 0 || fseek(file, 0, SEEK_END) != 0) return 0;
    long end = ftell(file);
    int restored = fseek(file, position, SEEK_SET) == 0;
    if (end < 0 || !restored) return 0;
    *size = (uint64_t)end;
    return 1;
}

int file_range_valid(uint64_t file_size, uint64_t offset, uint64_t size)
{
    return offset <= file_size && size <= file_size - offset;
}

void format_section_name(const char name[8], char output[9])
{
    size_t i = 0;
    for (; i < 8 && name[i]; ++i) {
        unsigned char c = (unsigned char)name[i];
        output[i] = c >= 32 && c <= 126 ? (char)c : '?';
    }
    output[i] = '\0';
}

int skip_bytes(FILE *file, size_t n)
{
    uint64_t size;
    long position = ftell(file);
    if (position < 0 || n > LONG_MAX || !get_file_size(file, &size) ||
        !file_range_valid(size, (uint64_t)position, n)) return 0;
    return fseek(file, (long)n, SEEK_CUR) == 0;
}

void get_section_perms(uint32_t ch, char *perm_str)
{
    perm_str[0] = (ch & IMAGE_SCN_MEM_READ) ? 'R' : '-';
    perm_str[1] = (ch & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
    perm_str[2] = (ch & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
    perm_str[3] = (ch & IMAGE_SCN_CNT_CODE) ? 'C' : '-';
    perm_str[4] = (ch & IMAGE_SCN_CNT_INITIALIZED_DATA) ? 'I' : '-';
    perm_str[5] = (ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA) ? 'U' : '-';
    perm_str[6] = '\0';
}

int calculate_entropy(
    FILE *file,
    uint32_t offset,
    uint32_t size,
    double *entropy
)
{
    *entropy = 0.0;

    if (size == 0) {
        return 1;
    }

    uint64_t file_size;
    if (!get_file_size(file, &file_size) ||
        !file_range_valid(file_size, offset, size)) return 0;

    long original_position = ftell(file);

    if (original_position < 0) {
        return 0;
    }

    if (fseek(file, offset, SEEK_SET) != 0) {
        return 0;
    }

    unsigned long frequencies[256] = {0};

    unsigned char buffer[4096];
    uint32_t remaining = size;

    while (remaining > 0) {
        size_t to_read = remaining < sizeof(buffer)
                       ? remaining
                       : sizeof(buffer);

        size_t bytes_read = fread(buffer, 1, to_read, file);

        if (bytes_read == 0) {
            fseek(file, original_position, SEEK_SET);
            return 0;
        }

        for (size_t i = 0; i < bytes_read; i++) {
            frequencies[buffer[i]]++;
        }

        remaining -= (uint32_t)bytes_read;
    }

    if (fseek(file, original_position, SEEK_SET) != 0) {
        return 0;
    }

    double result = 0.0;

    for (size_t i = 0; i < 256; i++) {
        if (frequencies[i] == 0) {
            continue;
        }

        double probability =
            (double)frequencies[i] / (double)size;

        result -= probability * log2(probability);
    }

    *entropy = result;

    return 1;
}

int rva_to_offset(
    const PE_SECTION_INFO *sections,
    size_t count,
    uint32_t rva,
    uint32_t *offset
)
{
    for (size_t i = 0; i < count; i++) {
        const PE_SECTION_INFO *section = &sections[i];

        uint64_t virtual_start = section->virtual_address;
        uint64_t virtual_end = virtual_start + section->virtual_size;

        if (rva < virtual_start || rva >= virtual_end) {
            continue;
        }

        /* RVA belongs to this section's virtual range, but that does not
         * imply a corresponding byte exists in the file: raw data may be
         * absent (e.g. .bss) or shorter than the virtual range. */
        if (section->size_of_raw_data == 0) {
            return 0;
        }

        uint32_t delta = rva - section->virtual_address;

        if (delta >= section->size_of_raw_data) {
            return 0;
        }

        uint64_t file_offset = (uint64_t)section->pointer_to_raw_data + delta;

        if (file_offset > UINT32_MAX) {
            return 0;
        }

        *offset = (uint32_t)file_offset;
        return 1;
    }

    return 0;
}

/* Resolve actual file bytes, including RVAs in the PE headers. */
int rva_to_file_offset(const PE_SECTION_INFO *sections, size_t count,
                       uint32_t size_of_headers, uint64_t file_size,
                       uint32_t rva, uint32_t *offset)
{
    uint32_t candidate;
    if (rva < size_of_headers) candidate = rva;
    else if (!rva_to_offset(sections, count, rva, &candidate)) return 0;
    if (!file_range_valid(file_size, candidate, 1)) return 0;
    *offset = candidate;
    return 1;
}
