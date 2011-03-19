#include "Cniapi.h"

extern void* kernel_alloc(size_t size) NOREGPARM;

extern void kernel_free(void *p, size_t size) NOREGPARM;

extern void* kernel_memset(void *s, int c, size_t n) NOREGPARM;

extern void* kernel_memcpy(void *dest, const void *src, size_t n) NOREGPARM;

extern void* kernel_memmove(void *dest, const void *src, size_t n) NOREGPARM;

extern int kernel_memcmp(const void *s1, const void *s2, size_t n)  NOREGPARM;

extern size_t kernel_strlen(const char *s) NOREGPARM;

extern char* kernel_strcpy(char *dest, const char *src) NOREGPARM;

extern char *kernel_strchr(const char *s, int c) NOREGPARM;

#ifdef CLEAR
#undef CLEAR
#endif
#define CLEAR(a) kernel_memset(&a,0,sizeof(a)) 

