/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    linux_os.h
*  Date:    04/25/2001
*
***************************************************************************
*
* Macros for handling differences in the linux kernel api.
*
***************************************************************************/
#ifndef LINUX_OS_H
#define LINUX_OS_H

#define IPPP_MAX_HEADER 10

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define net_device device
#define net_device_stats enet_statistics
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,48)
#define MOD_INC_AND_DEC
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,70)
#define PACKET_TYPE_NEXT(pt) (list_entry((pt)->list.next,struct packet_type,list))
#else
#define PACKET_TYPE_NEXT(pt) ((pt)->next)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,5)
#include <asm/uaccess.h>
#else
extern inline int
copy_from_user(void *dest, void *src, unsigned long size)
{
    int error;
    error = verify_area(VERIFY_READ, (void *) src, size);
    if (error == 0)
    {
        memcpy_fromfs(dest, src, size);
    }
    return error;
}
extern inline int
copy_to_user(void *dest, void *src, unsigned long size)
{
    int error;
    error = verify_area(VERIFY_WRITE, (void *) dest, size);
    if (error == 0)
    {
        memcpy_tofs(dest, src, size);
    }
    return error;
}
#endif

#ifndef module_init
#define module_init(func) int init_module(void) { return func(); }
#endif
#ifndef module_exit
#define module_exit(func) void cleanup_module(void) { func(); }
#endif
#ifndef __init
#define __init
#endif
#ifndef __exit
#define __exit
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(str)
#endif

#endif //LINUX_OS_H
