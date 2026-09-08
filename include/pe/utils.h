#ifndef MDIE_PE_UTILS_H
#define MDIE_PE_UTILS_H

#include <stdint.h>
#include <stdio.h>

#include "pe/image.h"

int read_u16_le(FILE *file, uint16_t *value);
int read_u32_le(FILE *file, uint32_t *value);
int read_u64_le(FILE *file, uint64_t *value);
int get_file_size(FILE *file, uint64_t *size);
int file_range_valid(uint64_t file_size, uint64_t offset, uint64_t size);
/* Checked conversion to an existing file byte; also handles header RVAs. */
int rva_to_file_offset(const PE_SECTION_INFO *sections, size_t count,
                       uint32_t size_of_headers, uint64_t file_size,
                       uint32_t rva, uint32_t *offset);

int skip_bytes(FILE *file, size_t n);

/* Section-only arithmetic conversion; does not validate against EOF.
 * Use rva_to_file_offset for untrusted file-backed addresses. */
int rva_to_offset(
    const PE_SECTION_INFO *sections,
    size_t count,
    uint32_t rva,
    uint32_t *offset
);

#endif
