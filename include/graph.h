#ifndef MDIE_GRAPH_H
#define MDIE_GRAPH_H

#include <stddef.h>
#include <stdio.h>

#include "pe.h"

void print_entropy_graph(
    FILE *file,
    const PE_SECTION_INFO *sections,
    size_t count
);

#endif