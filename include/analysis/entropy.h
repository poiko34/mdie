#ifndef MDIE_ENTROPY_H
#define MDIE_ENTROPY_H
#include <stdint.h>
#include <stdio.h>
int calculate_entropy(FILE *file, uint32_t offset, uint32_t size, double *entropy);
#endif
