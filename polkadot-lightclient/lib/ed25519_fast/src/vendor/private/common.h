#ifndef lc_shim_common_H
#define lc_shim_common_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])
#endif
