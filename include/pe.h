#ifndef MDIE_PE_H
#define MDIE_PE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* DOS Header */
typedef struct {
    uint16_t e_magic;
    int32_t  e_lfanew;
} PE_DOS_INFO;

/* COFF/File Header */
typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} PE_FILE_HEADER;

/* Optional Header */
typedef struct {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;

    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;

    uint32_t address_of_entry_point;
    uint32_t base_of_code;

    uint64_t image_base;

    uint32_t section_alignment;
    uint32_t file_alignment;

    uint32_t size_of_image;
    uint32_t size_of_headers;

    uint16_t subsystem;
    uint16_t dll_characteristics;

    uint32_t number_of_rva_and_sizes;
} PE_OPTIONAL_INFO;

/* Section Header */
typedef struct {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t characteristics;
} PE_SECTION_INFO;

/* Data Directory entry (Optional Header) */
typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} PE_DATA_DIRECTORY;

/* PE parsing */
int read_nt_header(
    FILE *file,
    PE_FILE_HEADER *file_header,
    PE_DOS_INFO *dos,
    long *optional_header_offset
);

int read_optional_header(
    FILE *file,
    uint16_t size_of_optional_header,
    PE_OPTIONAL_INFO *info
);

PE_SECTION_INFO *read_sections(
    FILE *file,
    const PE_FILE_HEADER *file_header,
    long optional_header_offset,
    size_t *count
);

size_t get_available_data_directories(
    const PE_OPTIONAL_INFO *optional,
    uint16_t size_of_optional_header
);

/* Reads up to PE_MAX_DATA_DIRECTORIES entries into `directories`, bounded by
 * both NumberOfRvaAndSizes and the space actually available in the
 * declared SizeOfOptionalHeader. Returns the number of entries filled. */
size_t read_data_directories(
    FILE *file,
    const PE_OPTIONAL_INFO *optional,
    long optional_header_offset,
    uint16_t size_of_optional_header,
    PE_DATA_DIRECTORY *directories
);

#endif
