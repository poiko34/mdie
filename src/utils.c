#include <math.h>
#include <stdint.h>

#include "pe_utils.h"
#include "pe_defs.h"

int skip_bytes(FILE *file, size_t n)
{
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
