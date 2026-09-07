#include <stdio.h>
#include <stdlib.h>

#include "pe.h"
#include "pe_utils.h"

PE_SECTION_INFO *read_sections(
    FILE *file,
    const PE_FILE_HEADER *file_header,
    long optional_header_offset,
    size_t *count
) {
    if (fseek(
            file,
            optional_header_offset + file_header->size_of_optional_header,
            SEEK_SET
        ) != 0) {
        return NULL;
    }

    size_t section_count = file_header->number_of_sections;

    PE_SECTION_INFO *sections =
        calloc(section_count, sizeof(PE_SECTION_INFO));

    if (sections == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < section_count; i++) {
        PE_SECTION_INFO *section = &sections[i];

        if (fread(section->name, 1, 8, file) != 8 ||
            fread(&section->virtual_size, sizeof(uint32_t), 1, file) != 1 ||
            fread(&section->virtual_address, sizeof(uint32_t), 1, file) != 1 ||
            fread(&section->size_of_raw_data, sizeof(uint32_t), 1, file) != 1 ||
            fread(&section->pointer_to_raw_data, sizeof(uint32_t), 1, file) != 1) {
            free(sections);
            return NULL;
        }

        /*
         * PointerToRelocations
         * PointerToLinenumbers
         * NumberOfRelocations
         * NumberOfLinenumbers
         */
        if (!skip_bytes(file, 12)) {
            free(sections);
            return NULL;
        }

        if (fread(
                &section->characteristics,
                sizeof(uint32_t),
                1,
                file
            ) != 1) {
            free(sections);
            return NULL;
        }
    }

    *count = section_count;
    return sections;
}
