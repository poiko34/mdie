#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>

#include "pe.h"
#include "pe_defs.h"
#include "print.h"
#include "graph.h"
#include "defs.h"

static void print_help(const char *prog_name)
{
    printf("Usage: %s [OPTIONS] <file.exe>\n\n", prog_name);
    printf("Options:\n");
    printf("  -f, --file <path>   Path to PE file to analyze\n");
    printf("  -d, --directories   Show PE data directories\n");
    printf("  -g, --graph         Show entropy graph map\n");
    printf("  -v, --version       Print version\n");
    printf("  -h, --help          Print this help message\n");
}

int main(int argc, char **argv)
{
    char *filepath = NULL;
    int directories_mode = 0;
    int graph_mode = 0;

    static struct option const long_options[] = {
        {"file",        required_argument, NULL, 'f'},
        {"directories", no_argument,       NULL, 'd'},
        {"graph",       no_argument,       NULL, 'g'},
        {"version",     no_argument,       NULL, 'v'},
        {"help",        no_argument,       NULL, 'h'},
        {NULL,          0,                 NULL,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:dgvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f':
                filepath = optarg;
                break;
            case 'd':
                directories_mode = 1;
                break;
            case 'g':
                graph_mode = 1;
                break;
            case 'v':
                printf("mdie version " VERSION "\n");
                return 0;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    /* Fallback to positional argument if -f was not specified */
    if (!filepath && optind < argc) {
        filepath = argv[optind];
    }

    if (!filepath) {
        fprintf(stderr, "Error: No input file specified.\n\n");
        print_help(argv[0]);
        return 1;
    }

    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror(filepath);
        return 1;
    }

    PE_DOS_INFO dos;
    PE_FILE_HEADER file_header;
    PE_OPTIONAL_INFO optional;
    PE_SECTION_INFO *sections;
    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES];

    long optional_header_offset;
    size_t sections_count;
    size_t directories_count;

    if (!read_nt_header(
            file,
            &file_header,
            &dos,
            &optional_header_offset)) {
        fclose(file);
        return 1;
    }

    if (!read_optional_header(
            file,
            file_header.size_of_optional_header,
            &optional)) {
        fclose(file);
        return 1;
    }

    if (directories_mode) {
        size_t available_entries = get_available_data_directories(
            &optional,
            file_header.size_of_optional_header
        );

        if (optional.number_of_rva_and_sizes > available_entries) {
            fprintf(
                stderr,
                "Warning: Data Directory table is truncated "
                "(declared: %" PRIu32 ", available: %zu)\n",
                optional.number_of_rva_and_sizes,
                available_entries
            );
        }

        directories_count = read_data_directories(
            file,
            &optional,
            optional_header_offset,
            file_header.size_of_optional_header,
            directories
        );
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

    print_pe_info(
        &dos,
        &file_header,
        &optional,
        sections,
        sections_count
    );

    if (directories_mode) {
        print_data_directories(directories, directories_count);
    }

    print_sections(file, sections, sections_count);

    /* Print entropy graph only if -g / --graph flag is explicitly requested */
    if (graph_mode) {
        print_entropy_graph(file, sections, sections_count);
    }

    free(sections);
    fclose(file);

    return 0;
}