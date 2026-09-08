#include <inttypes.h>
#include <stdio.h>
#include "analysis/compiler.h"
#include "cli/ui.h"

static void artifact(const char *what, uint32_t offset)
{
    printf("  - %s at file offset 0x%08" PRIX32 " (embedded marker).\n", what, offset);
}
void print_build_tools(const PE_BUILD_INFO *r, const PE_OPTIONAL_INFO *o)
{
    ui_heading("Build tool detection (heuristic)");
    int compilers = r->gcc + r->clang + r->msvc + r->go;
    if (compilers > 1) printf("Compiler: mixed evidence; primary compiler unknown\n");
    else if (r->clang) printf("Compiler: LLVM/Clang candidate [medium]\n");
    else if (r->gcc) printf("Compiler: GCC candidate [medium]\n");
    else if (r->msvc) printf("Compiler: MSVC candidate [medium]\n");
    else if (r->go) printf("Compiler: Go toolchain candidate [medium]\n");
    else printf("Compiler: unknown\n");

    if (r->mingw && r->clang && !r->gcc)
        printf("Toolchain: Clang + MinGW-compatible [medium]; LLVM-MinGW distribution unconfirmed\n");
    else if (r->mingw && r->gcc && !r->clang)
        printf("Toolchain: MinGW GCC-compatible [medium]\n");
    else if (r->mingw) printf("Toolchain: MinGW-compatible [low]; compiler not established by runtime\n");
    else if (r->rich) printf("Toolchain: Microsoft-compatible build artifacts [medium]\n");
    else printf("Toolchain: unknown\n");
    if (r->llvm_mingw) printf("Distribution hint: LLVM-MinGW [low; embedded text only]\n");

    if ((r->lld + r->gnu_ld + r->rich) > 1)
        printf("Linker: mixed evidence; final linker unknown\n");
    else if (r->lld) printf("Linker: LLVM LLD candidate [low]\n");
    else if (r->gnu_ld) printf("Linker: GNU ld candidate [low]\n");
    else if (r->rich) printf("Linker: Microsoft LINK-compatible candidate [medium]\n");
    else printf("Linker: unknown\n");
    printf("PE linker version field: %u.%u (not an identity)\n",
           o->major_linker_version, o->minor_linker_version);

    if (r->clr) printf("Runtime: .NET/CLR metadata [high]; source language unknown\n");
    if (r->go) printf("Runtime: Go build-info %s [high]\n", r->go_version);
    else if (r->go_marker) printf("Runtime: possible Go [low; build-info version not decoded]\n");
    if (!r->clr && !r->go_marker) printf("Runtime: unknown\n");
    printf("\nEvidence:\n");
    if (r->gcc) artifact("GCC producer text", r->gcc_offset);
    if (r->clang) artifact("Clang producer text", r->clang_offset);
    if (r->msvc) artifact("MSVC compiler banner", r->msvc_offset);
    if (r->mingw) artifact("MinGW runtime/symbol text", r->mingw_offset);
    if (r->llvm_mingw) artifact("llvm-mingw text", r->llvm_mingw_offset);
    if (r->lld) artifact("LLD identifier", r->lld_offset);
    if (r->gnu_ld) artifact("GNU ld identifier", r->gnu_ld_offset);
    if (r->rich) printf("  - Rich/DanS records with matching checksum; product IDs not classified.\n");
    if (r->rich_invalid) printf("  - Rich marker failed structural/checksum checks; ignored.\n");
    if (r->clr) printf("  - CLR header and BSJB metadata root/version string.\n");
    if (r->go_marker) printf("  - Aligned Go build-info header in section raw data.\n");
    if (!compilers && !r->mingw && !r->llvm_mingw && !r->lld && !r->gnu_ld &&
        !r->rich && !r->rich_invalid && !r->clr && !r->go_marker)
        printf("  - No supported identifying artifacts found.\n");
    printf("\nConfidence labels are heuristic, not probabilities.\n");
    printf("Artifacts may belong to dependencies or be forged; absence proves nothing.\n");
    if (r->incomplete) printf("Scan: incomplete (limit, invalid metadata or unreadable data).\n");
}

void print_build_summary(const PE_BUILD_INFO *r)
{
    ui_heading("Build tools");
    const char *compiler = "unknown";
    int count = r->gcc + r->clang + r->msvc + r->go;
    if (count > 1) compiler = "unknown (mixed evidence)";
    else if (r->clang) compiler = r->mingw ? "Clang / MinGW (likely)" : "LLVM/Clang (likely)";
    else if (r->gcc) compiler = r->mingw ? "GCC / MinGW (likely)" : "GCC (likely)";
    else if (r->msvc) compiler = "MSVC (likely)";
    else if (r->go) compiler = "Go toolchain (likely)";
    else if (r->mingw) compiler = "unknown / MinGW-compatible";
    const char *linker = "unknown";
    if (r->lld + r->gnu_ld + r->rich > 1) linker = "unknown (mixed evidence)";
    else if (r->lld) linker = "LLVM LLD (possible)";
    else if (r->gnu_ld) linker = "GNU ld (possible)";
    else if (r->rich) linker = "Microsoft LINK-compatible (likely)";
    printf("Compiler:        %s\n", compiler);
    printf("Linker:          %s\n", linker);
    printf("Runtime:         ");
    if (r->clr) printf(".NET/CLR%s", r->go_marker ? "; " : "");
    if (r->go) printf("Go %s", r->go_version);
    else if (r->go_marker) printf("Go (possible)");
    else if (!r->clr) printf("unknown");
    putchar('\n');
}
