#ifndef MDIE_BUILD_OUTPUT_H
#define MDIE_BUILD_OUTPUT_H
#include "analysis/compiler.h"
void print_build_summary(const PE_BUILD_INFO *info);
void print_build_tools(const PE_BUILD_INFO *info, const PE_OPTIONAL_INFO *optional);
#endif
