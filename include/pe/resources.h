#ifndef MDIE_RESOURCES_H
#define MDIE_RESOURCES_H

#include "pe/image.h"

#define PE_RESOURCE_MAX_ENTRIES 1024u
#define PE_RESOURCE_MAX_NAME 256u
#define PE_RESOURCE_MAX_VERSION 65536u
#define PE_RESOURCE_MAX_MANIFEST 16384u
#define PE_RESOURCE_TEXT_BUDGET 262144u

typedef struct {
    int named;
    uint32_t id;
    char name[PE_RESOURCE_MAX_NAME * 3 + 1];
} PE_RESOURCE_NAME;

typedef struct {
    uint32_t rva, size, file_offset, codepage;
    int has_file_offset, valid;
} PE_RESOURCE_DATA;

typedef struct {
    void (*node)(unsigned depth, const PE_RESOURCE_NAME *name, void *context);
    void (*data)(const PE_RESOURCE_DATA *data, void *context);
    void (*version)(const char *table, const char *key, const char *value, void *context);
    void (*manifest)(const char *text, size_t length, int truncated, void *context);
    void (*warning)(const char *message, void *context);
    void *context;
} PE_RESOURCE_VISITOR;

/* Walks type -> name/ID -> language. Callback arguments are temporary;
 * text is validated UTF-8, but must be escaped by the presentation layer.
 * Returns 0 on malformed data or limits (partial output is retained).
 * Only numeric RT_VERSION (16) and RT_MANIFEST (24) payloads are decoded. */
int visit_resources(FILE *file, const PE_OPTIONAL_INFO *optional,
                    const PE_SECTION_INFO *sections, size_t count,
                    uint64_t file_size, const PE_DATA_DIRECTORY *directory,
                    const PE_RESOURCE_VISITOR *visitor);

#endif
