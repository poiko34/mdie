#ifndef MDIE_RESOURCES_OUTPUT_H
#define MDIE_RESOURCES_OUTPUT_H

#include "pe/image.h"

int print_resources(FILE *file, const PE_OPTIONAL_INFO *optional,
                    const PE_SECTION_INFO *sections, size_t count,
                    uint64_t file_size, const PE_DATA_DIRECTORY *directory);

#endif
