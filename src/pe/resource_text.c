#include "resources_internal.h"

static uint32_t word(const unsigned char *p, int big)
{
    return big ? (uint32_t)p[0] << 8 | p[1] : (uint32_t)p[1] << 8 | p[0];
}

int resource_text(const unsigned char *data, size_t size, int encoding,
                  int partial, char *out, size_t capacity, size_t *length)
{
    size_t used = 0;
    for (size_t i = 0; i < size;) {
        uint32_t ch;
        if (encoding) {
            if (size - i < 2) { if (partial) break; return 0; }
            ch = word(data + i, encoding == 2);
            i += 2;
            if (ch >= 0xd800 && ch <= 0xdbff) {
                if (size - i < 2) { if (partial) break; return 0; }
                uint32_t low = word(data + i, encoding == 2);
                if (low < 0xdc00 || low > 0xdfff) return 0;
                ch = 0x10000 + ((ch - 0xd800) << 10) + low - 0xdc00;
                i += 2;
            } else if (ch >= 0xdc00 && ch <= 0xdfff) return 0;
        } else {
            unsigned char first = data[i++];
            unsigned extra;
            uint32_t minimum;
            if (first < 0x80) { ch = first; extra = 0; minimum = 0; }
            else if (first >= 0xc2 && first <= 0xdf) { ch = first & 31; extra = 1; minimum = 0x80; }
            else if (first >= 0xe0 && first <= 0xef) { ch = first & 15; extra = 2; minimum = 0x800; }
            else if (first >= 0xf0 && first <= 0xf4) { ch = first & 7; extra = 3; minimum = 0x10000; }
            else return 0;
            if (size - i < extra) { if (partial) break; return 0; }
            for (unsigned j = 0; j < extra; ++j) {
                if ((data[i] & 0xc0) != 0x80) return 0;
                ch = (ch << 6) | (data[i++] & 63);
            }
            if (ch < minimum || ch > 0x10ffff || (ch >= 0xd800 && ch <= 0xdfff)) return 0;
        }
        size_t n = ch < 0x80 ? 1 : ch < 0x800 ? 2 : ch < 0x10000 ? 3 : 4;
        if (used >= capacity || n >= capacity - used) return 0;
        if (n == 1) out[used++] = (char)ch;
        else {
            out[used++] = (char)((n == 2 ? 0xc0 : n == 3 ? 0xe0 : 0xf0) |
                                  (ch >> (6 * (n - 1))));
            for (size_t j = n - 1; j; --j)
                out[used++] = (char)(0x80 | ((ch >> (6 * (j - 1))) & 63));
        }
    }
    if (used >= capacity) return 0;
    out[used] = 0;
    *length = used;
    return 1;
}
