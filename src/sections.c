#include <stdio.h>
#include <stdlib.h>

#include "pe.h"
#include "pe_utils.h"

PE_SECTION_INFO *read_sections(
    FILE *file,
    const PE_FILE_HEADER *file_header,
    long optional_header_offset,
    size_t *count
)
{
    long section_table_offset =
        optional_header_offset + file_header->size_of_optional_header;

    if (fseek(file, section_table_offset, SEEK_SET) != 0) {
        return NULL;
    }

    size_t section_count = file_header->number_of_sections;

    PE_SECTION_INFO *sections = calloc(
        section_count,
        sizeof(*sections)
    );

    if (sections == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < section_count; i++) {
        PE_SECTION_INFO *section = &sections[i];

        if (fread(section->name, 1, sizeof(section->name), file) !=
            sizeof(section->name)) {
            free(sections);
            return NULL;
        }

        if (fread(&section->virtual_size,
                  sizeof(section->virtual_size), 1, file) != 1) {
            free(sections);
            return NULL;
        }

        if (fread(&section->virtual_address,
                  sizeof(section->virtual_address), 1, file) != 1) {
            free(sections);
            return NULL;
        }

        if (fread(&section->size_of_raw_data,
                  sizeof(section->size_of_raw_data), 1, file) != 1) {
            free(sections);
            return NULL;
        }

        if (fread(&section->pointer_to_raw_data,
                  sizeof(section->pointer_to_raw_data), 1, file) != 1) {
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

        if (fread(&section->characteristics,
                  sizeof(section->characteristics), 1, file) != 1) {
            free(sections);
            return NULL;
        }
    }

    *count = section_count;

    return sections;
}
