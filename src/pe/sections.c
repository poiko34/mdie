#include <stdio.h>
#include <stdlib.h>

#include "pe/image.h"
#include "pe/utils.h"

PE_SECTION_INFO *read_sections(
    FILE *file,
    const PE_FILE_HEADER *file_header,
    long optional_header_offset,
    size_t *count
)
{
    *count = 0;
    uint64_t file_size;
    uint64_t table_offset = (uint64_t)optional_header_offset +
                            file_header->size_of_optional_header;
    if (optional_header_offset < 0 || !get_file_size(file, &file_size) ||
        !file_range_valid(file_size, table_offset,
                          (uint64_t)file_header->number_of_sections * 40)) {
        fprintf(stderr, "Error: section table extends beyond the file.\n");
        return NULL;
    }
    long section_table_offset = (long)table_offset;

    if (fseek(file, section_table_offset, SEEK_SET) != 0) {
        return NULL;
    }

    size_t section_count = file_header->number_of_sections;

    PE_SECTION_INFO *sections = calloc(
        section_count ? section_count : 1,
        sizeof(*sections)
    );

    if (sections == NULL) {
        fprintf(stderr, "Error: cannot allocate section table.\n");
        return NULL;
    }

    for (size_t i = 0; i < section_count; i++) {
        PE_SECTION_INFO *section = &sections[i];

        if (fread(section->name, 1, sizeof(section->name), file) !=
            sizeof(section->name)) {
            free(sections);
            return NULL;
        }

        if (!read_u32_le(file, &section->virtual_size)) {
            free(sections);
            return NULL;
        }

        if (!read_u32_le(file, &section->virtual_address)) {
            free(sections);
            return NULL;
        }

        if (!read_u32_le(file, &section->size_of_raw_data)) {
            free(sections);
            return NULL;
        }

        if (!read_u32_le(file, &section->pointer_to_raw_data)) {
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

        if (!read_u32_le(file, &section->characteristics)) {
            free(sections);
            return NULL;
        }
    }

    *count = section_count;

    return sections;
}
