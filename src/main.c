#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>

#include "pe.h"
#include "pe_utils.h"
#include "pe_defs.h"
#include "print.h"
#include "graph.h"
#include "defs.h"
#include "compiler.h"
#include "ui.h"

static void print_help(const char *prog_name)
{
    printf("Usage: %s [OPTIONS] <file.exe>\n\n", prog_name);
    printf("Default: overview, build tools and section table.\n\n");
    printf("Add detail:\n");
    printf("  -H, --headers       Show raw DOS, COFF and Optional Header fields\n");
    printf("  -f, --file <path>   Path to PE file to analyze\n");
    printf("  -d, --directories   Show PE data directories\n");
    printf("  -i, --import        Show imports and IAT slots\n");
    printf("  -c, --compiler      Show detailed build-tool evidence\n");
    printf("  -g, --graph         Show entropy graph map\n");
    printf("  -v, --version       Print version\n");
    printf("  -h, --help          Print this help message\n");
}

int main(int argc, char **argv)
{
    char *filepath = NULL;
    int directories_mode = 0;
    int graph_mode = 0;
    int imports_mode = 0;
    int compiler_mode = 0;
    int headers_mode = 0;

    static struct option const long_options[] = {
        {"headers",     no_argument,       NULL, 'H'},
        {"file",        required_argument, NULL, 'f'},
        {"directories", no_argument,       NULL, 'd'},
        {"import",      no_argument,       NULL, 'i'},
        {"compiler",    no_argument,       NULL, 'c'},
        {"graph",       no_argument,       NULL, 'g'},
        {"version",     no_argument,       NULL, 'v'},
        {"help",        no_argument,       NULL, 'h'},
        {NULL,          0,                 NULL,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:Hdicgvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'H':
                headers_mode = 1;
                break;
            case 'f':
                filepath = optarg;
                break;
            case 'd':
                directories_mode = 1;
                break;
            case 'i':
                imports_mode = 1;
                break;
            case 'c':
                compiler_mode = 1;
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
        filepath = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Error: unexpected extra input argument.\n");
        return 1;
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

    uint64_t file_size;
    if (!get_file_size(file, &file_size)) {
        fprintf(stderr, "Error: cannot determine input file size.\n");
        fclose(file);
        return 1;
    }
    int malformed = 0;
    PE_DOS_INFO dos;
    PE_FILE_HEADER file_header;
    PE_OPTIONAL_INFO optional;
    PE_SECTION_INFO *sections;
    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES] = {0};

    long optional_header_offset;
    size_t sections_count;
    size_t directories_count = 0;

    if (!read_nt_header(
            file,
            &file_header,
            &dos,
            &optional_header_offset)) {
        fprintf(stderr, "Error: cannot read DOS/PE/COFF headers.\n");
        fclose(file);
        return 1;
    }

    if (!read_optional_header(
            file,
            file_header.size_of_optional_header,
            &optional)) {
        fprintf(stderr, "Error: cannot read Optional Header.\n");
        fclose(file);
        return 1;
    }

    size_t available_entries = get_available_data_directories(
        &optional,
        file_header.size_of_optional_header
    );

    if (optional.number_of_rva_and_sizes > available_entries) {
        malformed = 1;
        fprintf(
            stderr,
            "Warning: Data Directory table is truncated "
            "(declared: %" PRIu32 ", available: %zu)\n",
            optional.number_of_rva_and_sizes,
            available_entries
        );
    }

    /* Directories also feed the default build-tool summary. */
    {
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
        fprintf(stderr, "Error: cannot read section table.\n");
        fclose(file);
        return 1;
    }

    for (size_t i = 0; i < sections_count; ++i) {
        if (sections[i].size_of_raw_data &&
            !file_range_valid(file_size, sections[i].pointer_to_raw_data,
                              sections[i].size_of_raw_data)) {
            fprintf(stderr, "Warning: section #%zu raw data extends beyond the file.\n", i + 1);
            malformed = 1;
        }
    }
    if (optional.size_of_headers > file_size) {
        fprintf(stderr, "Warning: SizeOfHeaders exceeds file size.\n");
        malformed = 1;
    }
    if (optional.address_of_entry_point) {
        uint32_t ep;
        if (!rva_to_file_offset(sections, sections_count, optional.size_of_headers,
                               file_size, optional.address_of_entry_point, &ep)) {
            fprintf(stderr, "Warning: entry point has no corresponding file byte.\n");
            malformed = 1;
        }
    }

    ui_file(filepath, file_size);
    print_pe_info(
        &dos,
        &file_header,
        &optional,
        sections,
        sections_count,
        file_size
    );

    {
        PE_BUILD_INFO build;
        if (!detect_build_tools(file, &dos, &optional, sections, sections_count,
                                file_size, directories, &build)) {
            fprintf(stderr, "Warning: build-tool analysis is incomplete.\n");
            malformed = 1;
        }
        size_t expected = optional.number_of_rva_and_sizes;
        if (expected > available_entries) expected = available_entries;
        if (expected > PE_MAX_DATA_DIRECTORIES) expected = PE_MAX_DATA_DIRECTORIES;
        if (directories_count < expected) {
            fprintf(stderr, "Warning: build-tool data directories are incomplete.\n");
            build.incomplete = 1;
            malformed = 1;
        }
        if (compiler_mode) print_build_tools(&build, &optional);
        else print_build_summary(&build);
    }

    print_sections(file, sections, sections_count);

    if (headers_mode)
        print_raw_headers(&dos, &file_header, &optional, sections, sections_count, file_size);

    if (directories_mode) {
        print_data_directories(directories, directories_count);
    }

    if (imports_mode) {
        size_t expected = optional.number_of_rva_and_sizes;
        if (expected > available_entries) expected = available_entries;
        if (expected > PE_MAX_DATA_DIRECTORIES) expected = PE_MAX_DATA_DIRECTORIES;
        if (directories_count < expected) {
            fprintf(stderr, "Warning: imports: cannot read declared data directories.\n");
            malformed = 1;
        } else if (!print_imports(file, &optional, sections, sections_count,
                                  file_size, &directories[1])) malformed = 1;
    }


    /* Print entropy graph only if -g / --graph flag is explicitly requested */
    if (graph_mode) {
        print_entropy_graph(file, sections, sections_count);
    }

    free(sections);
    fclose(file);

    return malformed ? 2 : 0;
}
