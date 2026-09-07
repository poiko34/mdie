#include "pe.h"
#include "pe_defs.h"
#include "pe_utils.h"
#include <inttypes.h>

void print_sections(const PE_SECTION_INFO *sections, size_t count);
void print_pe_info(const PE_DOS_INFO *dos, const PE_FILE_HEADER *file_header, const PE_OPTIONAL_INFO *optional);
