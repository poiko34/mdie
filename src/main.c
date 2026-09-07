#include <stdio.h>
#include <stdlib.h>

#include "pe.h"
#include "print.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror(argv[1]);
        return 1;
    }

    PE_DOS_INFO dos;
    PE_FILE_HEADER file_header;
    PE_OPTIONAL_INFO optional;
    PE_SECTION_INFO *sections;

    long optional_header_offset;
    size_t sections_count;

    if (!read_nt_header(
            file,
            &file_header,
            &dos,
            &optional_header_offset)) {
        fclose(file);
        return 1;
    }

    if (!read_optional_header(file, &optional)) {
        fclose(file);
        return 1;
    }

    sections = read_sections(
        file,
        &file_header,
        optional_header_offset,
        &sections_count
    );

    if (!sections) {
        fclose(file);
        return 1;
    }

    print_pe_info(&dos, &file_header, &optional);
    print_sections(sections, sections_count);

    free(sections);
    fclose(file);

    return 0;
}