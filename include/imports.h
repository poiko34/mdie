#ifndef MDIE_IMPORTS_H
#define MDIE_IMPORTS_H
#include "pe.h"

typedef struct {
    uint32_t iat_rva;
    uint32_t file_offset;
    uint64_t value; /* Stored IAT value, not a resolved runtime address. */
    uint16_t hint_or_ordinal;
    int by_ordinal;
    int bound_without_names;
    char name[1025];
} PE_IMPORT_ENTRY;

typedef struct {
    void (*dll)(const char *name, int fallback, int bound);
    void (*entry)(const PE_IMPORT_ENTRY *entry);
} PE_IMPORT_VISITOR;

/* Visits ordinary imports. Returns 0 on malformed data or analysis limits.
 * Callback arguments are temporary and must be copied if retained. */
int visit_imports(FILE *file, const PE_OPTIONAL_INFO *optional,
                  const PE_SECTION_INFO *sections, size_t count,
                  uint64_t file_size, const PE_DATA_DIRECTORY *directory,
                  const PE_IMPORT_VISITOR *visitor);
#endif
