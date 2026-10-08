#ifndef lc_shim_utils_H
#define lc_shim_utils_H
#include <stddef.h>
void  sodium_memzero(void *pnt, size_t len);
int   sodium_is_zero(const unsigned char *n, size_t nlen);
int   sodium_memcmp(const void *b1_, const void *b2_, size_t len);
#endif
