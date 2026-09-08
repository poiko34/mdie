#include <inttypes.h>
#include <stdio.h>

#include "print.h"
#include "imports.h"
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
        char name[9];
        format_section_name(sections[i].name, name);
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
            name,
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
    const PE_OPTIONAL_INFO *optional,
    const PE_SECTION_INFO *sections,
    size_t count,
    uint64_t file_size
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

    uint32_t ep_offset;

    if (optional->address_of_entry_point && rva_to_file_offset(
            sections,
            count,
            optional->size_of_headers,
            file_size,
            optional->address_of_entry_point,
            &ep_offset)) {
        printf("EP File Offset:  0x%08" PRIX32 "\n", ep_offset);
    } else {
        printf("EP File Offset:  N/A\n");
    }

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

void print_data_directories(
    const PE_DATA_DIRECTORY *directories,
    size_t count
)
{
    static const char *const names[PE_MAX_DATA_DIRECTORIES] = {
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "CLR Runtime Header",
        "Reserved"
    };

    printf("\nData Directories:\n\n");

    printf("%-24s %-11s %s\n", "Name", "RVA/Offset", "Size");
    printf(
        "------------------------ ----------- ----------\n"
    );

    for (size_t i = 0; i < PE_MAX_DATA_DIRECTORIES; i++) {
        int present =
            i < count &&
            (directories[i].virtual_address != 0 ||
             directories[i].size != 0);

        if (present) {
            char value_str[16];

            snprintf(
                value_str,
                sizeof(value_str),
                "0x%08" PRIX32,
                directories[i].virtual_address
            );

            if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                printf(
                    "%-24s %-11s 0x%08" PRIX32 " (file offset)\n",
                    names[i],
                    value_str,
                    directories[i].size
                );
            } else {
                printf(
                    "%-24s %-11s 0x%08" PRIX32 "\n",
                    names[i],
                    value_str,
                    directories[i].size
                );
            }
        } else {
            printf("%-24s N/A\n", names[i]);
        }
    }
}

static void print_import_dll(const char *name, int fallback, int bound)
{
    printf("\n%s%s%s\n", name, fallback ? " [FirstThunk fallback]" : "",
           bound ? " [bound]" : "");
    printf("  IAT RVA     File offset  Stored IAT value    Hint/Ord  Function\n");
}

static void print_import_entry(const PE_IMPORT_ENTRY *entry)
{
    printf("  0x%08" PRIX32 "  0x%08" PRIX32 "   0x%016" PRIX64 "  ",
           entry->iat_rva, entry->file_offset, entry->value);
    if (entry->bound_without_names) printf("       -  <bound address; name unavailable>\n");
    else if (entry->by_ordinal)
        printf("#%-7u  <ordinal import>\n", (unsigned)entry->hint_or_ordinal);
    else printf("%-8u  %s\n", (unsigned)entry->hint_or_ordinal, entry->name);
}

int print_imports(FILE *file, const PE_OPTIONAL_INFO *optional,
                  const PE_SECTION_INFO *sections, size_t count,
                  uint64_t file_size, const PE_DATA_DIRECTORY *directory)
{
    printf("\nImports / IAT (file contents)\n");
    if (!directory->virtual_address && !directory->size) {
        printf("  No ordinary imports.\n");
        return 1;
    }
    printf("Names: lookup table; stored values: IAT on disk.\n");
    PE_IMPORT_VISITOR visitor = {print_import_dll, print_import_entry};
    return visit_imports(file, optional, sections, count, file_size, directory, &visitor);
}
