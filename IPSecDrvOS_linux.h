/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    IPSecDrvOSFunctions.h
*  Date:    05/09/2001
*
***************************************************************************
*
*
*   This contains the OS-specific definitions, headers and function
*   prototypes that are used within the IPSEC Driver.  Note that the 
*   CNIAPI.H contains the generic OS calls that are defined as part of the
*   CNI API.
*
***************************************************************************/
#ifndef IPSECDRVOS_LINUX_H
#define IPSECDRVOS_LINUX_H

#ifdef CNI_LINUX_INTERFACE
#include <linux/version.h>
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#include <asm/byteorder.h>

#ifdef _DEBUG
#define DBG_PRINT(args) printk args
#define DBG_PRINT_LVL(lvl,args) if (lvl&gnDbgLevel) { DBG_PRINT(args); }
#else
#define DBG_PRINT(args) 
#define DBG_PRINT_LVL(lvl,args)
#endif

#define CRITICAL_SECTION		void *

#define INIT_CRITICAL(lock)
#define ENTER_CRITICAL(lock)
#define LEAVE_CRITICAL(lock)
#define DESTROY_CRITICAL(lock)

#endif /*IPSECDRVOS_LINUX_H*/
