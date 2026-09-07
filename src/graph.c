#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "graph.h"
#include "pe_utils.h"

#define GRAPH_MARGIN 2
#define SECTION_LABEL_WIDTH 8
#define MIN_ENTROPY_BLOCK_SIZE 16

static size_t get_terminal_width(void)
{
    struct winsize window;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == 0 &&
        window.ws_col > 0) {
        return window.ws_col;
    }

    return 80;
}

/* RGB color structure */
typedef struct {
    int r, g, b;
} RGB;

/* Smooth color interpolation function based on entropy (from 0.0 to 8.0) */
static RGB interpolate_entropy_color(double entropy)
{
    if (entropy < 0.0) entropy = 0.0;
    if (entropy > 8.0) entropy = 8.0;

    /* Color stops (from dark blue to bright red) */
    RGB stops[] = {
        {0, 0, 139},     /* 0.0 */
        {0, 191, 255},   /* 2.0 */
        {50, 205, 50},   /* 4.0 */
        {255, 215, 0},   /* 6.0 */
        {255, 140, 0},   /* 7.0 */
        {255, 0, 0}      /* 8.0 */
    };
    int num_stops = 6;

    double normalized = (entropy / 8.0) * (num_stops - 1);
    int idx = (int)normalized;
    if (idx >= num_stops - 1) idx = num_stops - 2;
    double t = normalized - idx;

    RGB c1 = stops[idx];
    RGB c2 = stops[idx + 1];

    RGB result;
    result.r = (int)(c1.r + t * (c2.r - c1.r));
    result.g = (int)(c1.g + t * (c2.g - c1.g));
    result.b = (int)(c1.b + t * (c2.b - c1.b));
    return result;
}

/* Print a single colored block using TrueColor ANSI */
static void print_entropy_block(double entropy)
{
    RGB col = interpolate_entropy_color(entropy);
    printf("\033[38;2;%d;%d;%dm█\033[0m", col.r, col.g, col.b);
}

/* Print a marker for a byte range whose entropy could not be read,
 * distinct from any valid entropy color so it isn't mistaken for
 * low-entropy data. */
static void print_entropy_error_block(void)
{
    printf("\033[38;2;128;128;128m?\033[0m");
}

void print_entropy_graph(
    FILE *file,
    const PE_SECTION_INFO *sections,
    size_t count
)
{
    size_t terminal_width = get_terminal_width();

    if (terminal_width <=
        GRAPH_MARGIN * 2 + SECTION_LABEL_WIDTH) {
        return;
    }

    size_t graph_width =
        terminal_width
        - GRAPH_MARGIN * 2
        - SECTION_LABEL_WIDTH;

    printf("\nEntropy map\n\n");

    /* Print scale numbers aligned with the graph width */
    printf("%*s", SECTION_LABEL_WIDTH, "");
    printf("0.0");
    if (graph_width > 3) {
        for (size_t s = 0; s < graph_width - 3; s++) {
            putchar(' ');
        }
    }
    printf("8.0\n");

    /* Print gradient scale bar made of blocks */
    printf("%*s", SECTION_LABEL_WIDTH, "");
    for (size_t s = 0; s < graph_width; s++) {
        double entropy = (graph_width > 1) 
            ? ((double)s / (graph_width - 1)) * 8.0 
            : 0.0;
        print_entropy_block(entropy);
    }
    printf("\n\n");

    for (size_t i = 0; i < count; i++) {
        const PE_SECTION_INFO *section = &sections[i];

        if (section->size_of_raw_data == 0) {
            continue;
        }

        size_t block_size =
            (section->size_of_raw_data + graph_width - 1)
            / graph_width;

        if (block_size < MIN_ENTROPY_BLOCK_SIZE) {
            block_size = MIN_ENTROPY_BLOCK_SIZE;
        }

        printf("%-*.*s", SECTION_LABEL_WIDTH, 8, section->name);

        uint32_t offset = section->pointer_to_raw_data;
        uint32_t remaining = section->size_of_raw_data;

        while (remaining > 0) {
            uint32_t current_size =
                remaining < block_size
                ? remaining
                : (uint32_t)block_size;

            double entropy;

            if (calculate_entropy(file, offset, current_size, &entropy)) {
                print_entropy_block(entropy);
            } else {
                print_entropy_error_block();
            }

            offset += current_size;
            remaining -= current_size;
        }

        putchar('\n');
    }

    printf("\n");
}