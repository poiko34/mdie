#include <stdio.h>
#include <string.h>

#include "resources_internal.h"

typedef struct {
    size_t end, children, value, value_size;
    unsigned type;
    char key[193];
} VERSION_BLOCK;

typedef struct {
    const unsigned char *bytes;
    const PE_RESOURCE_VISITOR *visitor;
    unsigned blocks;
    int valid;
} VERSION_READER;

static uint16_t u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static size_t aligned(size_t n) { return (n + 3) & ~(size_t)3; }
static int invalid(VERSION_READER *r, const char *message)
{
    r->valid = 0;
    r->visitor->warning(message, r->visitor->context);
    return 0;
}

static int block(VERSION_READER *r, size_t start, size_t end, VERSION_BLOCK *b)
{
    if (++r->blocks > 256) return invalid(r, "version block limit exceeded (256 blocks).");
    if (start > end || end - start < 6) return invalid(r, "truncated version block header.");
    size_t size = u16(r->bytes + start);
    size_t value_units = u16(r->bytes + start + 2);
    b->type = u16(r->bytes + start + 4);
    if (size < 8 || size > end - start || size % 2 || b->type > 1)
        return invalid(r, "invalid version block length/type.");
    b->end = start + size;
    size_t key = start + 6, cursor = key;
    while (cursor + 2 <= b->end && u16(r->bytes + cursor)) cursor += 2;
    size_t length;
    if (cursor + 2 > b->end || cursor - key > 128 ||
        !resource_text(r->bytes + key, cursor - key, 1, 0, b->key, sizeof(b->key), &length))
        return invalid(r, "invalid version key UTF-16, terminator or limit (64 units).");
    b->value = aligned(cursor + 2);
    b->value_size = value_units * (b->type ? 2u : 1u);
    if (b->value_size && (b->value > b->end || b->value_size > b->end - b->value))
        return invalid(r, "version value extends beyond its block.");
    b->children = aligned(b->value + b->value_size);
    if (b->children > b->end) b->children = b->end;
    return 1;
}

static int selected(const char *key)
{
    return !strcmp(key, "FileVersion") || !strcmp(key, "ProductVersion") ||
           !strcmp(key, "CompanyName") || !strcmp(key, "FileDescription") ||
           !strcmp(key, "OriginalFilename");
}

static int string_value(VERSION_READER *r, const VERSION_BLOCK *b, char out[3073])
{
    if (b->type != 1 || b->value_size > 2048)
        return invalid(r, "invalid version string type or limit (1024 UTF-16 units).");
    if (!b->value_size) { out[0] = 0; return 1; }
    size_t length;
    if (u16(r->bytes + b->value + b->value_size - 2) ||
        !resource_text(r->bytes + b->value, b->value_size - 2, 1, 0, out, 3073, &length) ||
        memchr(out, 0, length))
        return invalid(r, "invalid version string UTF-16 or terminator.");
    return 1;
}

enum { ROOT, STRING_INFO, STRING_TABLE, STRING_VALUE, VAR_INFO, VAR_VALUE };

static void children(VERSION_READER *r, const VERSION_BLOCK *parent, unsigned kind,
                     unsigned depth, const char *table)
{
    if (parent->children == parent->end) return;
    if (depth >= 4) { invalid(r, "version block depth limit exceeded."); return; }
    for (size_t pos = parent->children; pos < parent->end;) {
        VERSION_BLOCK b;
        if (!block(r, pos, parent->end, &b)) return;
        unsigned next;
        if (kind == ROOT) {
            if (!strcmp(b.key, "StringFileInfo")) next = STRING_INFO;
            else if (!strcmp(b.key, "VarFileInfo")) next = VAR_INFO;
            else { invalid(r, "unknown version root child."); goto advance; }
            if (b.type != 1 || b.value_size) { invalid(r, "invalid version info container."); goto advance; }
        } else if (kind == STRING_INFO) {
            next = STRING_TABLE;
            if (strlen(b.key) != 8 || strspn(b.key, "0123456789abcdefABCDEF") != 8 ||
                b.type != 1 || b.value_size) {
                invalid(r, "invalid version language/codepage table."); goto advance;
            }
        } else if (kind == STRING_TABLE) {
            next = STRING_VALUE;
            char value[3073];
            if (string_value(r, &b, value) && selected(b.key))
                r->visitor->version(table, b.key, value, r->visitor->context);
        } else if (kind == VAR_INFO) {
            next = VAR_VALUE;
            if (strcmp(b.key, "Translation") || b.type || b.value_size % 4)
                invalid(r, "invalid version Translation block.");
        } else { invalid(r, "unexpected children in version value."); goto advance; }
        children(r, &b, next, depth + 1, next == STRING_TABLE ? b.key : table);
advance:
        pos = aligned(b.end);
    }
}

static void fixed_version(VERSION_READER *r, const unsigned char *p, const char *key)
{
    uint32_t ms = u32(p), ls = u32(p + 4);
    char value[32];
    snprintf(value, sizeof(value), "%u.%u.%u.%u", (unsigned)(ms >> 16),
             (unsigned)(ms & 65535), (unsigned)(ls >> 16), (unsigned)(ls & 65535));
    r->visitor->version("fixed", key, value, r->visitor->context);
}

int resource_version(const unsigned char *data, size_t size, const PE_RESOURCE_VISITOR *visitor)
{
    VERSION_READER r = {data, visitor, 0, 1};
    VERSION_BLOCK root;
    if (!block(&r, 0, size, &root)) return 0;
    if (strcmp(root.key, "VS_VERSION_INFO") || root.type)
        return invalid(&r, "invalid VS_VERSION_INFO root.");
    if (root.value_size) {
        if (root.value_size != 52 || u32(data + root.value) != 0xfeef04bd)
            invalid(&r, "invalid VS_FIXEDFILEINFO size/signature.");
        else {
            fixed_version(&r, data + root.value + 8, "FileVersion");
            fixed_version(&r, data + root.value + 16, "ProductVersion");
        }
    }
    children(&r, &root, ROOT, 1, "");
    return r.valid;
}
