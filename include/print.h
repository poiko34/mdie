#ifndef MDIE_PRINT_H
#define MDIE_PRINT_H

#include <stddef.h>

#include "pe.h"

void print_sections(
    FILE *file,
    const PE_SECTION_INFO *sections,
    size_t count
);

void print_pe_info(
    const PE_DOS_INFO *dos,
    const PE_FILE_HEADER *file_header,
    const PE_OPTIONAL_INFO *optional,
    const PE_SECTION_INFO *sections,
    size_t count
);

void print_data_directories(
    const PE_DATA_DIRECTORY *directories,
    size_t count
);

#endif
