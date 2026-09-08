#ifndef MDIE_RESOURCES_INTERNAL_H
#define MDIE_RESOURCES_INTERNAL_H

#include "pe/resources.h"

/* Encoding: 0 = UTF-8, 1 = UTF-16LE, 2 = UTF-16BE. A partial preview may
 * end within a character; such a trailing fragment is omitted. */
int resource_text(const unsigned char *data, size_t size, int encoding,
                  int partial, char *out, size_t capacity, size_t *length);
int resource_version(const unsigned char *data, size_t size,
                     const PE_RESOURCE_VISITOR *visitor);

#endif
