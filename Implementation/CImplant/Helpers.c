#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

byte hex_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0; // Error case, not a valid hex digit
}

byte *from_hex(const char *hex, size_t *out_len) {
    if (strlen(hex) % 2 != 0) return NULL;

    *out_len = strlen(hex) / 2;
    byte *result = malloc(*out_len);
    if (!result) return NULL;

    for (size_t i = 0; i < *out_len; ++i) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        result[i] = (hex_to_byte(c1) << 4) + hex_to_byte(c2);
    }

    return result;
}