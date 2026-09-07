#ifndef MDIE_PE_UTILS_H
#define MDIE_PE_UTILS_H

#include <stdint.h>
#include <stdio.h>

int skip_bytes(FILE *file, size_t n);

void get_section_perms(
    uint32_t characteristics,
    char *perm_str
);

double calculate_entropy(
    FILE *file, 
    uint32_t offset,
    uint32_t size
);

#endif
