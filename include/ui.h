#ifndef MDIE_UI_H
#define MDIE_UI_H
#include <stddef.h>
#include <stdint.h>
int ui_color(void);
size_t ui_width(void);
void ui_heading(const char *title);
void ui_text(const char *text, size_t limit);
void ui_file(const char *path, uint64_t size);
#endif
