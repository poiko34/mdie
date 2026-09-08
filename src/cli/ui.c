#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "cli/ui.h"
#include "cli/version.h"

int ui_color(void)
{
    const char *term = getenv("TERM");
    return isatty(STDOUT_FILENO) && !getenv("NO_COLOR") &&
           (!term || strcmp(term, "dumb") != 0);
}
size_t ui_width(void)
{
    struct winsize window;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == 0 && window.ws_col)
        return window.ws_col;
    return 80;
}
void ui_text(const char *text, size_t limit)
{
    size_t i = 0;
    for (; text[i] && i < limit; ++i) {
        unsigned char ch = (unsigned char)text[i];
        putchar(ch >= 32 && ch <= 126 ? ch : '?');
    }
    if (text[i]) printf("...");
}
void ui_heading(const char *title)
{
    putchar('\n');
    if (ui_color()) printf("\033[1;36m");
    printf("%s", title);
    if (ui_color()) printf("\033[0m");
    putchar('\n');
    if (ui_color()) printf("\033[2m");
    size_t width = ui_width();
    if (width > 80) width = 80;
    for (size_t i = 0; i + 1 < width; ++i) putchar('-');
    if (ui_color()) printf("\033[0m");
    putchar('\n');
}
void ui_file(const char *path, uint64_t size)
{
    if (ui_color()) printf("\033[1;36m");
    printf("mdie " VERSION);
    if (ui_color()) printf("\033[0m");
    printf("  /  PE inspection\n\n");
    printf("File:            ");
    const char *base = strrchr(path, '/');
    size_t width = ui_width();
    ui_text(base ? base + 1 : path, width > 20 ? width - 20 : 12);
    putchar('\n');
    printf("File size:       ");
    if (size >= 1024 * 1024) printf("%.2f MiB", size / (1024.0 * 1024.0));
    else if (size >= 1024) printf("%.2f KiB", size / 1024.0);
    else printf("%" PRIu64 " B", size);
    if (width >= 64 && size >= 1024) printf(" (%" PRIu64 " bytes)", size);
    putchar('\n');
}
