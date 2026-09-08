#include <inttypes.h>

#include "pe.h"
#include "pe_defs.h"
#include "pe_utils.h"

int read_nt_header(
    FILE *file,
    PE_FILE_HEADER *file_header,
    PE_DOS_INFO *dos,
    long *optional_header_offset
)
{
    if (fseek(file, 0, SEEK_END) != 0) {
        return 0;
    }

    long file_size = ftell(file);

    if (file_size < 0) {
        return 0;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        return 0;
    }

    /* DOS signature */
    if (!read_u16_le(file, &dos->e_magic)) {
        return 0;
    }

    if (dos->e_magic != E_MAGIC) {
        fprintf(
            stderr,
            "Not a PE file: invalid MZ signature\n"
        );
        return 0;
    }

    /* e_lfanew */
    if (fseek(file, E_LFANEW_OFFSET, SEEK_SET) != 0) {
        return 0;
    }

    uint32_t lfanew;
    if (!read_u32_le(file, &lfanew)) {
        return 0;
    }

    if (lfanew > INT32_MAX) {
        fprintf(stderr, "Invalid negative e_lfanew.\n");
        return 0;
    }
    dos->e_lfanew = (int32_t)lfanew;

    if (dos->e_lfanew < 0 ||
        dos->e_lfanew > file_size - (long)sizeof(uint32_t)) {
        fprintf(
            stderr,
            "Invalid e_lfanew: PE signature offset out of file bounds\n"
        );
        return 0;
    }

    /* PE signature */
    if (fseek(file, dos->e_lfanew, SEEK_SET) != 0) {
        return 0;
    }

    uint32_t signature;

    if (!read_u32_le(file, &signature)) {
        return 0;
    }

    if (signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE signature\n");
        return 0;
    }

    /* COFF/File Header */
    if (!read_u16_le(file, &file_header->machine) ||
        !read_u16_le(file, &file_header->number_of_sections) ||
        !read_u32_le(file, &file_header->timestamp) ||
        !read_u32_le(file, &file_header->pointer_to_symbol_table) ||
        !read_u32_le(file, &file_header->number_of_symbols) ||
        !read_u16_le(file, &file_header->size_of_optional_header) ||
        !read_u16_le(file, &file_header->characteristics)) {
        return 0;
    }

    *optional_header_offset = ftell(file);

    return *optional_header_offset >= 0;
}

int read_optional_header(
    FILE *file,
    uint16_t size_of_optional_header,
    PE_OPTIONAL_INFO *info
)
{
    uint64_t file_size;
    long start = ftell(file);
    if (size_of_optional_header < 2 || start < 0 ||
        !get_file_size(file, &file_size) ||
        !file_range_valid(file_size, (uint64_t)start, size_of_optional_header)) {
        fprintf(stderr, "Error: Optional Header extends beyond the file or is too small.\n");
        return 0;
    }
    uint16_t optional_magic;

    if (!read_u16_le(file, &optional_magic)) {
        return 0;
    }

    info->magic = optional_magic;

    /* Minimum standard-fields size for each known Optional Header variant
     * (i.e. without data directories). Used to reject a declared
     * SizeOfOptionalHeader that is too small to hold the fields this
     * function is about to read. */
    size_t min_optional_header_size;

    if (optional_magic == PE32) {
        min_optional_header_size = PE32_OPTIONAL_HEADER_MIN_SIZE;
    } else if (optional_magic == PE32P) {
        min_optional_header_size = PE32P_OPTIONAL_HEADER_MIN_SIZE;
    } else {
        fprintf(
            stderr,
            "Unknown Optional Header magic: 0x%04X\n",
            optional_magic
        );
        return 0;
    }

    if (size_of_optional_header < min_optional_header_size) {
        fprintf(
            stderr,
            "Optional header too small: %u bytes (need at least %zu)\n",
            size_of_optional_header,
            min_optional_header_size
        );
        return 0;
    }

    /* Common fields */
    if (fread(&info->major_linker_version,
              sizeof(info->major_linker_version), 1, file) != 1) {
        return 0;
    }

    if (fread(&info->minor_linker_version,
              sizeof(info->minor_linker_version), 1, file) != 1) {
        return 0;
    }

    if (!read_u32_le(file, &info->size_of_code)) {
        return 0;
    }

    if (!read_u32_le(file, &info->size_of_initialized_data)) {
        return 0;
    }

    if (!read_u32_le(file, &info->size_of_uninitialized_data)) {
        return 0;
    }

    if (!read_u32_le(file, &info->address_of_entry_point)) {
        return 0;
    }

    if (!read_u32_le(file, &info->base_of_code)) {
        return 0;
    }

    /* ImageBase differs between PE32 and PE32+ */
    if (optional_magic == PE32) {
        uint32_t base_of_data;
        uint32_t image_base_32;

        if (!read_u32_le(file, &base_of_data)) {
            return 0;
        }

        if (!read_u32_le(file, &image_base_32)) {
            return 0;
        }

        info->image_base = image_base_32;
    } else {
        /* PE32P: already validated above */
        if (!read_u64_le(file, &info->image_base)) {
            return 0;
        }
    }

    /* SectionAlignment & FileAlignment */
    if (!read_u32_le(file, &info->section_alignment)) {
        return 0;
    }

    if (!read_u32_le(file, &info->file_alignment)) {
        return 0;
    }

    /* OS/Image/Subsystem versions + Win32VersionValue */
    if (!skip_bytes(file, 16)) {
        return 0;
    }

    /* SizeOfImage & SizeOfHeaders */
    if (!read_u32_le(file, &info->size_of_image)) {
        return 0;
    }

    if (!read_u32_le(file, &info->size_of_headers)) {
        return 0;
    }

    /* CheckSum */
    if (!skip_bytes(file, 4)) {
        return 0;
    }

    /* Subsystem & DllCharacteristics */
    if (!read_u16_le(file, &info->subsystem)) {
        return 0;
    }

    if (!read_u16_le(file, &info->dll_characteristics)) {
        return 0;
    }

    /* Stack/Heap sizes + LoaderFlags */
    if (optional_magic == PE32P) {
        if (!skip_bytes(file, 32 + 4)) {
            return 0;
        }
    } else {
        if (!skip_bytes(file, 16 + 4)) {
            return 0;
        }
    }

    /* NumberOfRvaAndSizes */
    if (!read_u32_le(file, &info->number_of_rva_and_sizes)) {
        return 0;
    }

    return 1;
}

size_t get_available_data_directories(
    const PE_OPTIONAL_INFO *optional,
    uint16_t size_of_optional_header
)
{
    size_t standard_fields_size =
        (optional->magic == PE32P)
            ? PE32P_OPTIONAL_HEADER_MIN_SIZE
            : PE32_OPTIONAL_HEADER_MIN_SIZE;

    if (size_of_optional_header <= standard_fields_size) {
        return 0;
    }

    size_t available_bytes =
        (size_t)size_of_optional_header - standard_fields_size;

    return available_bytes / 8;
}

size_t read_data_directories(
    FILE *file,
    const PE_OPTIONAL_INFO *optional,
    long optional_header_offset,
    uint16_t size_of_optional_header,
    PE_DATA_DIRECTORY *directories
)
{
    size_t standard_fields_size = (optional->magic == PE32P)
        ? PE32P_OPTIONAL_HEADER_MIN_SIZE
        : PE32_OPTIONAL_HEADER_MIN_SIZE;

    if (size_of_optional_header <= standard_fields_size) {
        return 0;
    }

    /* Do not assume NumberOfRvaAndSizes is 16: clamp it against both the
     * space actually declared in SizeOfOptionalHeader and the number of
     * directory kinds mdie knows how to label. */
    size_t available_bytes =
        (size_t)size_of_optional_header - standard_fields_size;
    size_t available_entries = available_bytes / 8;

    size_t count = optional->number_of_rva_and_sizes;

    if (count > available_entries) {
        count = available_entries;
    }

    if (count > PE_MAX_DATA_DIRECTORIES) {
        count = PE_MAX_DATA_DIRECTORIES;
    }

    if (count == 0) {
        return 0;
    }

    if (fseek(file,
              optional_header_offset + (long)standard_fields_size,
              SEEK_SET) != 0) {
        return 0;
    }

    size_t read_count = 0;

    for (size_t i = 0; i < count; i++) {
        uint32_t virtual_address;
        uint32_t size;

        if (!read_u32_le(file, &virtual_address)) {
            break;
        }

        if (!read_u32_le(file, &size)) {
            break;
        }

        directories[read_count].virtual_address = virtual_address;
        directories[read_count].size = size;
        read_count++;
    }

    return read_count;
}
