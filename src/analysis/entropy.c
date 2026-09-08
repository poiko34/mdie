#include <math.h>
#include "pe/utils.h"
#include "analysis/entropy.h"

int calculate_entropy(
    FILE *file,
    uint32_t offset,
    uint32_t size,
    double *entropy
)
{
    *entropy = 0.0;

    if (size == 0) {
        return 1;
    }

    uint64_t file_size;
    if (!get_file_size(file, &file_size) ||
        !file_range_valid(file_size, offset, size)) return 0;

    long original_position = ftell(file);

    if (original_position < 0) {
        return 0;
    }

    if (fseek(file, offset, SEEK_SET) != 0) {
        return 0;
    }

    unsigned long frequencies[256] = {0};

    unsigned char buffer[4096];
    uint32_t remaining = size;

    while (remaining > 0) {
        size_t to_read = remaining < sizeof(buffer)
                       ? remaining
                       : sizeof(buffer);

        size_t bytes_read = fread(buffer, 1, to_read, file);

        if (bytes_read == 0) {
            fseek(file, original_position, SEEK_SET);
            return 0;
        }

        for (size_t i = 0; i < bytes_read; i++) {
            frequencies[buffer[i]]++;
        }

        remaining -= (uint32_t)bytes_read;
    }

    if (fseek(file, original_position, SEEK_SET) != 0) {
        return 0;
    }

    double result = 0.0;

    for (size_t i = 0; i < 256; i++) {
        if (frequencies[i] == 0) {
            continue;
        }

        double probability =
            (double)frequencies[i] / (double)size;

        result -= probability * log2(probability);
    }

    *entropy = result;

    return 1;
}
