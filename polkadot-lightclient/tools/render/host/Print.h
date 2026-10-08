#pragma once
#include <stddef.h>
#include <stdint.h>
class Print {
public:
    virtual ~Print() = default;
    virtual size_t write(uint8_t) = 0;
    size_t print(const char *text) {
        size_t n = 0;
        while (*text) n += write(static_cast<uint8_t>(*text++));
        return n;
    }
};
