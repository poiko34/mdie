#include <inttypes.h>
#include "pe.h"
#include "pe_defs.h"
#include "pe_utils.h"

int read_nt_header(
    FILE *file,
    PE_FILE_HEADER *file_header,
    PE_DOS_INFO* dos,
    long *optional_header_offset
) {

    /* DOS signature */
    if (fread(&dos->e_magic, sizeof(dos->e_magic), 1, file) != 1) { return 0; }

    if (dos->e_magic != E_MAGIC) { fprintf(stderr, "Not a PE file: invalid MZ signature\n"); return 0; }

    /* e_lfanew */
    if (fseek(file, E_LFANEW_OFFSET, SEEK_SET) != 0)              { return 0; }
    if (fread(&dos->e_lfanew, sizeof(dos->e_lfanew), 1, file) != 1) { return 0; }

    /* PE signature */
    if (fseek(file, dos->e_lfanew, SEEK_SET) != 0) { return 0; }

    uint32_t signature;
    if (fread(&signature, sizeof(signature), 1, file) != 1) { return 0; }

    if (signature != IMAGE_NT_SIGNATURE) { fprintf(stderr, "Invalid PE signature\n"); return 0; }

    /* COFF/File Header */
    if (fread(file_header, sizeof(*file_header), 1, file) != 1) { return 0; }

    *optional_header_offset = ftell(file);

    return 1;
}

int read_optional_header(FILE *file, PE_OPTIONAL_INFO *info) {
    uint16_t optional_magic;

    if (fread(&optional_magic, sizeof(optional_magic), 1, file) != 1) return 0;
    info->magic = optional_magic;

    /* Common fields */
    if (fread(&info->major_linker_version, sizeof(info->major_linker_version), 1, file) != 1) return 0;
    if (fread(&info->minor_linker_version, sizeof(info->minor_linker_version), 1, file) != 1) return 0;
    if (fread(&info->size_of_code, sizeof(info->size_of_code), 1, file) != 1) return 0;
    if (fread(&info->size_of_initialized_data, sizeof(info->size_of_initialized_data), 1, file) != 1) return 0;
    if (fread(&info->size_of_uninitialized_data, sizeof(info->size_of_uninitialized_data), 1, file) != 1) return 0;
    if (fread(&info->address_of_entry_point, sizeof(info->address_of_entry_point), 1, file) != 1) return 0;
    if (fread(&info->base_of_code, sizeof(info->base_of_code), 1, file) != 1) return 0;

    /* ImageBase differs between PE32 and PE32+ */
    if (optional_magic == PE32) {
        uint32_t base_of_data;
        uint32_t image_base_32;

        if (fread(&base_of_data, sizeof(base_of_data), 1, file) != 1) return 0;
        if (fread(&image_base_32, sizeof(image_base_32), 1, file) != 1) return 0;
        info->image_base = image_base_32;
    } else if (optional_magic == PE32P) {
        if (fread(&info->image_base, sizeof(info->image_base), 1, file) != 1) return 0;
    } else {
        fprintf(stderr, "Unknown Optional Header magic: 0x%04X\n", optional_magic);
        return 0;
    }

    /* SectionAlignment & FileAlignment */
    if (fread(&info->section_alignment, sizeof(info->section_alignment), 1, file) != 1) return 0;
    if (fread(&info->file_alignment, sizeof(info->file_alignment), 1, file) != 1) return 0;

    /* OS/Image/Subsystem versions + Win32VersionValue */
    if (!skip_bytes(file, 16)) return 0;

    /* SizeOfImage & SizeOfHeaders */
    if (fread(&info->size_of_image, sizeof(info->size_of_image), 1, file) != 1) return 0;
    if (fread(&info->size_of_headers, sizeof(info->size_of_headers), 1, file) != 1) return 0;

    /* CheckSum */
    if (!skip_bytes(file, 4)) return 0;

    /* Subsystem & DllCharacteristics */
    if (fread(&info->subsystem, sizeof(info->subsystem), 1, file) != 1) return 0;
    if (fread(&info->dll_characteristics, sizeof(info->dll_characteristics), 1, file) != 1) return 0;

    /* Stack/Heap sizes + LoaderFlags */
    if (optional_magic == PE32P) {
        if (!skip_bytes(file, 32 + 4)) return 0;
    } else {
        if (!skip_bytes(file, 16 + 4)) return 0;
    }

    /* NumberOfRvaAndSizes */
    if (fread(&info->number_of_rva_and_sizes, sizeof(info->number_of_rva_and_sizes), 1, file) != 1) return 0;

    return 1;
}