#include <inttypes.h>

#include "cli/debug_output.h"
#include "cli/ui.h"
#include "pe/debug.h"

static const char *type_name(uint32_t type)
{
    switch (type) {
        case 0: return "UNKNOWN";
        case 1: return "COFF";
        case 2: return "CODEVIEW";
        case 3: return "FPO";
        case 4: return "MISC";
        case 5: return "EXCEPTION";
        case 6: return "FIXUP";
        case 7: return "OMAP_TO_SRC";
        case 8: return "OMAP_FROM_SRC";
        case 9: return "BORLAND";
        case 10: return "RESERVED10";
        case 11: return "CLSID";
        case 12: return "VC_FEATURE";
        case 13: return "POGO";
        case 14: return "ILTCG";
        case 15: return "MPX";
        case 16: return "REPRO";
        case 17: return "EMBEDDED_PORTABLE_PDB";
        case 19: return "PDB_CHECKSUM";
        case 20: return "EX_DLLCHARACTERISTICS";
        default: return "UNKNOWN";
    }
}

static void print_guid(const unsigned char g[16])
{
    /* GUID Data1/Data2/Data3 are little endian; Data4 keeps its byte order. */
    const unsigned order[] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) putchar('-');
        printf("%02X", (unsigned)g[order[i]]);
    }
}

static void print_entry(const PE_DEBUG_ENTRY *e)
{
    printf("  # %" PRIu32 "  %s (%" PRIu32 ")\n", e->index, type_name(e->type), e->type);
    printf("    Size: %" PRIu32 " | RVA: 0x%08" PRIX32 " | File: 0x%08" PRIX32 "\n",
           e->size, e->data_rva, e->file_offset);
    if (e->error) {
        printf("    Invalid debug data.\n");
        fprintf(stderr, "Warning: debug: record #%" PRIu32 ": %s\n", e->index, e->error);
        return;
    }
    if (e->codeview == PE_CODEVIEW_NONE) return;
    if (e->codeview == PE_CODEVIEW_UNKNOWN) {
        printf("    Unsupported CodeView signature: %02X %02X %02X %02X\n",
               (unsigned)e->signature[0], (unsigned)e->signature[1],
               (unsigned)e->signature[2], (unsigned)e->signature[3]);
        return;
    }
    if (e->codeview == PE_CODEVIEW_RSDS) {
        printf("    CodeView: RSDS\n    GUID: ");
        print_guid(e->guid);
        putchar('\n');
    } else {
        printf("    CodeView: NB10\n    Timestamp: 0x%08" PRIX32 "\n", e->timestamp);
    }
    printf("    Age: %" PRIu32 "\n    PDB: ", e->age);
    if (!e->pdb_path[0]) printf("<empty>");
    else for (const unsigned char *p = (const unsigned char *)e->pdb_path; *p; ++p)
        putchar(*p >= 32 && *p <= 126 ? *p : '?');
    putchar('\n');
}

static void print_warning(const char *message)
{
    fprintf(stderr, "Warning: debug: %s\n", message);
}

int print_debug(FILE *file, const PE_OPTIONAL_INFO *optional,
                const PE_SECTION_INFO *sections, size_t count,
                uint64_t file_size, const PE_DATA_DIRECTORY *directory)
{
    ui_heading("Debug Directory");
    if (!directory->virtual_address && !directory->size) {
        printf("  No debug entries.\n");
        return 1;
    }
    PE_DEBUG_VISITOR visitor = {print_entry, print_warning};
    return visit_debug(file, optional, sections, count, file_size, directory, &visitor);
}
