#include <inttypes.h>
#include <stdio.h>

#include "print.h"
#include "pe_defs.h"
#include "pe_utils.h"

void print_sections(
    FILE *file,
    const PE_SECTION_INFO *sections,
    size_t count
)
{
    printf("\nSections: %zu\n\n", count);

    printf(
        "%-8s %-8s %-8s %-8s %-8s %-8s %-6s\n",
        "Name",
        "RVA",
        "VSize",
        "RawSize",
        "RawPtr",
        "Entropy",
        "Flags"
    );

    printf(
        "-------- -------- -------- -------- -------- -------- ------\n"
    );

    for (size_t i = 0; i < count; i++) {
        char perms[7];

        get_section_perms(
            sections[i].characteristics,
            perms
        );

        char entropy_str[16];
        double entropy;

        if (calculate_entropy(
                file,
                sections[i].pointer_to_raw_data,
                sections[i].size_of_raw_data,
                &entropy)) {
            snprintf(entropy_str, sizeof(entropy_str), "%.2f", entropy);
        } else {
            snprintf(entropy_str, sizeof(entropy_str), "N/A");
        }

        printf(
            "%-8.8s "
            "%08" PRIX32 " "
            "%08" PRIX32 " "
            "%08" PRIX32 " "
            "%08" PRIX32 " "
            "%-8s "
            "%-6s\n",
            sections[i].name,
            sections[i].virtual_address,
            sections[i].virtual_size,
            sections[i].size_of_raw_data,
            sections[i].pointer_to_raw_data,
            entropy_str,
            perms
        );
    }
}

void print_pe_info(
    const PE_DOS_INFO *dos,
    const PE_FILE_HEADER *file_header,
    const PE_OPTIONAL_INFO *optional
)
{
    printf("e_magic:         0x%04X\n", dos->e_magic);
    printf("e_lfanew:        0x%08X\n", (uint32_t)dos->e_lfanew);

    printf("Machine:         0x%04X\n", file_header->machine);
    printf("Sections:        %u\n", file_header->number_of_sections);
    printf(
        "Timestamp:       0x%08" PRIX32 "\n",
        file_header->timestamp
    );
    printf(
        "Characteristics: 0x%04X\n",
        file_header->characteristics
    );

    printf(
        "Optional Header: %s\n",
        optional->magic == PE32 ? "PE32" : "PE32+"
    );

    printf(
        "Linker version:  %u.%02u\n",
        optional->major_linker_version,
        optional->minor_linker_version
    );

    printf(
        "Entry Point:     0x%08" PRIX32 "\n",
        optional->address_of_entry_point
    );

    printf(
        "Image Base:      0x%016" PRIX64 "\n",
        optional->image_base
    );

    printf(
        "Section Align:   0x%08" PRIX32 "\n",
        optional->section_alignment
    );

    printf(
        "File Align:      0x%08" PRIX32 "\n",
        optional->file_alignment
    );

    printf(
        "Image Size:      0x%08" PRIX32 "\n",
        optional->size_of_image
    );

    printf(
        "Header Size:     0x%08" PRIX32 "\n",
        optional->size_of_headers
    );
}
