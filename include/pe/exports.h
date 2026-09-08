#ifndef MDIE_EXPORTS_H
#define MDIE_EXPORTS_H
#include "pe/image.h"

typedef struct {
    uint32_t ordinal, eat_rva, target_rva, file_offset;
    int has_file_offset, is_forwarder;
    char name[1025];
    char forwarder[1025];
} PE_EXPORT_ENTRY;
typedef struct {
    void (*module)(const char *name, uint32_t slots, uint32_t names);
    void (*entry)(const PE_EXPORT_ENTRY *entry);
} PE_EXPORT_VISITOR;
/* Visits occupied EAT slots, including ordinal-only exports and name aliases.
 * Callback arguments are temporary. Returns 0 on malformed data/limits. */
int visit_exports(FILE *file, const PE_OPTIONAL_INFO *optional,
                  const PE_SECTION_INFO *sections, size_t count,
                  uint64_t file_size, const PE_DATA_DIRECTORY *directory,
                  const PE_EXPORT_VISITOR *visitor);
#endif
