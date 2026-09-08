#ifndef MDIE_COMPILER_H
#define MDIE_COMPILER_H
#include "pe/image.h"

typedef struct {
    int gcc, clang, msvc, mingw, llvm_mingw, lld, gnu_ld;
    int rich, rich_invalid, clr, go, go_marker;
    int incomplete;
    char go_version[128];
    uint32_t gcc_offset, clang_offset, msvc_offset, mingw_offset;
    uint32_t lld_offset, gnu_ld_offset, llvm_mingw_offset;
} PE_BUILD_INFO;

int detect_build_tools(FILE *file, const PE_DOS_INFO *dos,
                       const PE_OPTIONAL_INFO *optional,
                       const PE_SECTION_INFO *sections, size_t count,
                       uint64_t file_size, const PE_DATA_DIRECTORY *directories,
                       PE_BUILD_INFO *result);
#endif
