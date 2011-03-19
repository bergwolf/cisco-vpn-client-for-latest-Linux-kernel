#include "linux/string.h"
#include "linux/slab.h"

#define NOREGPARM __attribute__((regparm(0)))

NOREGPARM void *
kernel_alloc(size_t size)
{
    void*rc = kmalloc(size, GFP_ATOMIC);
    if(NULL == rc)
    {
        printk("<1> os_malloc size %d failed\n",size);
    }

    return rc;
}

NOREGPARM void
kernel_free(void *p, size_t size)
{
    kfree(p);
}

NOREGPARM void *
kernel_memset(void *s, int c, size_t n)
{
    return memset(s,c,n);
}

NOREGPARM void *
kernel_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest,src,n);
}

NOREGPARM void *
kernel_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest,src,n);
}

NOREGPARM int 
kernel_memcmp(const void *s1, const void *s2, size_t n) 
{
    return memcmp(s1,s2,n);
}

NOREGPARM size_t 
kernel_strlen(const char *s)
{
    return strlen(s);
}

NOREGPARM char *
kernel_strcpy(char *dest, const char *src)
{
    return strcpy(dest, src); 
}

NOREGPARM char *
kernel_strchr(const char *s, int c)
{
    return strchr(s,c);
}
