#ifndef MDIE_PE_UTILS_H
#define MDIE_PE_UTILS_H

#include <stdint.h>
#include <stdio.h>

#include "pe.h"

int skip_bytes(FILE *file, size_t n);

void get_section_perms(
    uint32_t characteristics,
    char *perm_str
);

int calculate_entropy(
    FILE *file,
    uint32_t offset,
    uint32_t size,
    double *entropy
);

int rva_to_offset(
    const PE_SECTION_INFO *sections,
    size_t count,
    uint32_t rva,
    uint32_t *offset
);

#endif
