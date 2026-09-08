#ifndef MDIE_DEBUG_H
#define MDIE_DEBUG_H

#include "pe/image.h"

#define PE_DEBUG_MAX_ENTRIES 4096u
#define PE_DEBUG_MAX_PATH 4096u

typedef enum {
    PE_CODEVIEW_NONE, PE_CODEVIEW_UNKNOWN, PE_CODEVIEW_RSDS, PE_CODEVIEW_NB10
} PE_CODEVIEW_KIND;

typedef struct {
    uint32_t index, type, size, data_rva, file_offset;
    PE_CODEVIEW_KIND codeview;
    unsigned char signature[4], guid[16];
    uint32_t timestamp, age;
    char pdb_path[PE_DEBUG_MAX_PATH + 1];
    const char *error;
} PE_DEBUG_ENTRY;

typedef struct {
    void (*entry)(const PE_DEBUG_ENTRY *entry);
    void (*warning)(const char *message);
} PE_DEBUG_VISITOR;

/* Arguments passed to callbacks are temporary. Paths contain raw bytes;
 * the presentation layer must sanitize them. Nonempty payloads are read
 * using PointerToRawData, including overlays; AddressOfRawData is metadata.
 * Returns 0 for malformed data or analysis limits, 1 otherwise.
 * Unsupported types/signatures are reported without decoding their payload. */
int visit_debug(FILE *file, const PE_OPTIONAL_INFO *optional,
                const PE_SECTION_INFO *sections, size_t count,
                uint64_t file_size, const PE_DATA_DIRECTORY *directory,
                const PE_DEBUG_VISITOR *visitor);

#endif
