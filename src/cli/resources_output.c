#include <inttypes.h>
#include <string.h>

#include "cli/resources_output.h"
#include "cli/ui.h"
#include "pe/resources.h"

static const char *type_name(uint32_t type)
{
    switch (type) {
        case 1: return "RT_CURSOR";
        case 2: return "RT_BITMAP";
        case 3: return "RT_ICON";
        case 4: return "RT_MENU";
        case 5: return "RT_DIALOG";
        case 6: return "RT_STRING";
        case 7: return "RT_FONTDIR";
        case 8: return "RT_FONT";
        case 9: return "RT_ACCELERATOR";
        case 10: return "RT_RCDATA";
        case 11: return "RT_MESSAGETABLE";
        case 12: return "RT_GROUP_CURSOR";
        case 14: return "RT_GROUP_ICON";
        case 16: return "RT_VERSION";
        case 17: return "RT_DLGINCLUDE";
        case 19: return "RT_PLUGPLAY";
        case 20: return "RT_VXD";
        case 21: return "RT_ANICURSOR";
        case 22: return "RT_ANIICON";
        case 23: return "RT_HTML";
        case 24: return "RT_MANIFEST";
        default: return "CUSTOM";
    }
}

/* The parser supplies validated UTF-8. Escape C0/C1 controls and Unicode
 * format/bidi controls; only manifest newlines may affect terminal layout. */
static void safe_text(const char *text, size_t size, int multiline)
{
    size_t column = 0, width = ui_width();
    if (width < 40) width = 40;
    if (width > 100) width = 100;
    for (size_t i = 0; i < size;) {
        size_t start = i;
        unsigned char first = (unsigned char)text[i++];
        uint32_t ch = first;
        unsigned extra = first < 0x80 ? 0 : first < 0xe0 ? 1 : first < 0xf0 ? 2 : 3;
        if (extra) {
            ch = first & (extra == 1 ? 31 : extra == 2 ? 15 : 7);
            for (unsigned j = 0; j < extra && i < size; ++j)
                ch = (ch << 6) | ((unsigned char)text[i++] & 63);
        }
        if (multiline && ch == '\r' && i < size && text[i] == '\n') continue;
        if (multiline && ch == '\n') { printf("\n          "); column = 0; continue; }
        char escaped[16];
        size_t length = i - start;
        const char *piece = text + start;
        if (ch < 32 || (ch >= 0x7f && ch <= 0x9f) || ch == 0xad || ch == 0x61c ||
            (ch >= 0x200b && ch <= 0x200f) || (ch >= 0x2028 && ch <= 0x202e) ||
            (ch >= 0x2060 && ch <= 0x206f) || ch == 0xfeff ||
            (ch >= 0xfff9 && ch <= 0xfffb) || (ch >= 0xe0000 && ch <= 0xe007f)) {
            length = (size_t)snprintf(escaped, sizeof(escaped), "\\u%04" PRIX32, ch);
            piece = escaped;
        } else if (ch == '\\' || (!multiline && ch == '"')) {
            escaped[0] = '\\'; escaped[1] = (char)ch; piece = escaped; length = 2;
        }
        size_t columns = piece == escaped ? length : 1;
        if (multiline && column + columns > width - 10) { printf("\n          "); column = 0; }
        fwrite(piece, 1, length, stdout);
        column += columns;
    }
}

static void node(unsigned depth, const PE_RESOURCE_NAME *name, void *context)
{
    unsigned *nodes = context;
    ++*nodes;
    static const char *labels[] = {"Type", "Name", "Language"};
    printf("%*s%s: ", (int)(2 + depth * 2), "", labels[depth]);
    if (name->named) {
        putchar('"'); safe_text(name->name, strlen(name->name), 0); putchar('"');
    } else if (!depth) printf("%s (#%" PRIu32 ")", type_name(name->id), name->id);
    else if (depth == 2) printf("0x%04" PRIX32, name->id);
    else printf("#%" PRIu32, name->id);
    putchar('\n');
}
static void data(const PE_RESOURCE_DATA *entry, void *context)
{
    (void)context;
    printf("        Size: %" PRIu32 " bytes\n        RVA: 0x%08" PRIX32 "\n        File offset: ",
           entry->size, entry->rva);
    if (entry->has_file_offset) printf("0x%08" PRIX32, entry->file_offset);
    else printf("N/A");
    printf("\n        Code page: %" PRIu32 "%s\n", entry->codepage,
           entry->valid ? "" : " (invalid payload range)");
}
static void version(const char *table, const char *key, const char *value, void *context)
{
    (void)context;
    printf("        %s [%s]: ", key, table);
    safe_text(value, strlen(value), 0);
    putchar('\n');
}
static void manifest(const char *text, size_t length, int truncated, void *context)
{
    (void)context;
    printf("        Manifest%s:\n          ", truncated ? " (truncated preview)" : "");
    safe_text(text, length, 1);
    putchar('\n');
}
static void warning(const char *message, void *context)
{
    (void)context;
    fprintf(stderr, "Warning: resources: %s\n", message);
}

int print_resources(FILE *file, const PE_OPTIONAL_INFO *optional,
                    const PE_SECTION_INFO *sections, size_t count,
                    uint64_t file_size, const PE_DATA_DIRECTORY *directory)
{
    ui_heading("Resources");
    unsigned nodes = 0;
    PE_RESOURCE_VISITOR visitor = {node, data, version, manifest, warning, &nodes};
    int valid = visit_resources(file, optional, sections, count, file_size, directory, &visitor);
    if (valid && !nodes) printf("  No resources.\n");
    return valid;
}
