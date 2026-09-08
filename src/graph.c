#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "graph.h"
#include "ui.h"
#include "pe_utils.h"

#define ENTROPY_WINDOW_SIZE 1024
#define ROW_PREFIX_WIDTH 27

static size_t get_terminal_width(void)
{
    struct winsize window;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == 0 && window.ws_col)
        return window.ws_col;
    return 80;
}

static void print_cell(double entropy, int color)
{
    static const double levels[] = {0, 2, 4, 6, 7, 8};
    static const int rgb[][3] = {
        {65, 105, 225}, {0, 185, 220}, {70, 200, 140},
        {240, 205, 70}, {250, 145, 65}, {240, 75, 85}
    };
    if (entropy < 0) { putchar('?'); return; }
    if (entropy > 8) entropy = 8;
    if (!color) {
        static const char shades[] = ".:-=+*#%@";
        putchar(shades[(int)(entropy + 0.5)]);
        return;
    }
    size_t i = 0;
    while (i < 4 && entropy > levels[i + 1]) ++i;
    double t = (entropy - levels[i]) / (levels[i + 1] - levels[i]);
    int r = (int)(rgb[i][0] + t * (rgb[i + 1][0] - rgb[i][0]));
    int g = (int)(rgb[i][1] + t * (rgb[i + 1][1] - rgb[i][1]));
    int b = (int)(rgb[i][2] + t * (rgb[i + 1][2] - rgb[i][2]));
    printf("\033[38;2;%d;%d;%dm█\033[0m", r, g, b);
}

static void format_size(uint32_t bytes, char output[16])
{
    if (bytes < 1024) snprintf(output, 16, "%u B", (unsigned)bytes);
    else if (bytes < 1024 * 1024)
        snprintf(output, 16, "%.1f KiB", bytes / 1024.0);
    else snprintf(output, 16, "%.1f MiB", bytes / (1024.0 * 1024.0));
}

/* Analyze fixed byte windows, independently of the terminal width. Cells
 * display overlap-weighted window entropy. Repeated cells reuse the cached
 * window value; stretching a small section does not create smaller samples. */
static void print_section_bar(FILE *file, const PE_SECTION_INFO *section,
                              size_t width, int color)
{
    uint64_t cached_window = UINT64_MAX;
    double cached_entropy = -1;
    uint64_t size = section->size_of_raw_data;
    for (size_t col = 0; col < width; ++col) {
        uint64_t begin = col * size / width;
        uint64_t end = (col + 1) * size / width;
        if (end == begin) end = begin + 1;
        double weighted = 0;
        int readable = 1;
        for (uint64_t pos = begin; pos < end;) {
            uint64_t window = pos / ENTROPY_WINDOW_SIZE;
            uint64_t start = window * ENTROPY_WINDOW_SIZE;
            uint64_t stop = start + ENTROPY_WINDOW_SIZE;
            if (stop > size) stop = size;
            if (window != cached_window) {
                uint64_t offset = (uint64_t)section->pointer_to_raw_data + start;
                cached_window = window;
                if (offset > UINT32_MAX ||
                    !calculate_entropy(file, (uint32_t)offset,
                                       (uint32_t)(stop - start), &cached_entropy))
                    cached_entropy = -1;
            }
            uint64_t next = stop < end ? stop : end;
            if (cached_entropy < 0) readable = 0;
            else weighted += cached_entropy * (double)(next - pos);
            pos = next;
        }
        print_cell(readable ? weighted / (double)(end - begin) : -1, color);
    }
}

void print_entropy_graph(FILE *file, const PE_SECTION_INFO *sections, size_t count)
{
    size_t terminal_width = get_terminal_width();
    if (terminal_width < 32) {
        printf("\nEntropy map: widen terminal to at least 32 columns.\n");
        return;
    }
    const char *term = getenv("TERM");
    int color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR") &&
                (!term || strcmp(term, "dumb") != 0);
    int compact = terminal_width < 64;
    size_t prefix = compact ? 2 : ROW_PREFIX_WIDTH;
    size_t width = terminal_width - prefix - 1;

    ui_heading("Entropy map");
    printf("Each bar spans one section.\n");
    printf("Left = start; right = end.\n");
    printf("Color/density = entropy (H).\n\n");
    printf("  Low ");
    size_t legend_width = terminal_width < 64 ? 12 : 24;
    for (size_t j = 0; j < legend_width; ++j)
        print_cell(8.0 * j / (legend_width - 1), color);
    printf(" High\n");
    printf("  0 = uniform; 8 = diverse bytes\n\n");

    if (!compact) printf("%-8s %9s %5s   ", "Section", "Raw size", "H/8");
    else printf("  ");
    printf("0%%%*s100%%\n", (int)width - 6, "");

    for (size_t i = 0; i < count; ++i) {
        const PE_SECTION_INFO *section = &sections[i];
        char name[9], size[16], value[16];
        format_section_name(section->name, name);
        format_size(section->size_of_raw_data, size);
        double entropy;
        int valid = calculate_entropy(file, section->pointer_to_raw_data,
                                      section->size_of_raw_data, &entropy);
        if (!section->size_of_raw_data || !valid) snprintf(value, sizeof(value), "N/A");
        else snprintf(value, sizeof(value), "%.2f", entropy);
        char marker = section->size_of_raw_data &&
                      section->size_of_raw_data < ENTROPY_WINDOW_SIZE ? '*' : ' ';
        printf("%-8s %9s %5s%c  ", name, size, value, marker);
        if (compact) printf("\n  ");
        if (!section->size_of_raw_data) printf("(no raw data)");
        else print_section_bar(file, section, width, color);
        putchar('\n');
    }
    printf("\nH/8: whole-section entropy.\n");
    printf("Windows: up to 1 KiB.\n");
    printf("* Short section; less evidence.\n");
    printf("? Unreadable data.\n\n");
}
