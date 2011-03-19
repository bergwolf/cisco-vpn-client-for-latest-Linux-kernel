/**************************************************************************
*           Copyright (c) 2000, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    IPSecDrvOSFunctions.h
*  Date:    10/30/00
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

#ifndef _IPSECDRVOSFUNCTIONS_H_
#define _IPSECDRVOSFUNCTIONS_H_

#if defined(WINNT) || defined(WIN95)
#include "IPSecDrvOS_windows.h"
#elif defined(CNI_LINUX_INTERFACE)
#include "IPSecDrvOS_linux.h"
#elif defined(CNI_SOLARIS_INTERFACE)
#include "IPSecDrvOS_solaris.h"
#elif defined(CNI_DARWIN_INTERFACE)
#include "IPSecDrvOS_darwin.h"
#else
#error Add code for your os here.
#endif

/*this macro can be used to align a pointer to a 32 bit word boundary
 * by rounding up
 */
#define ALIGN_32(x) \
    (((uintptr_t)(x) + \
       (uintptr_t)sizeof(uint32) - 1L) & ~((uintptr_t)sizeof(uint32) - 1L))

/* jjg 08-13-2001 - on platforms with alignment restrictions, we need to
 * make sure that buffers that contain packets (mac hdr + ip hdr ...)
 * are set up so that the ip header starts on a word boundary. This macro
 * is used to find the address where the mac header should begin so that
 * the ip header is properly aligned.
 */
#ifdef STRICT_ALIGNMENT
#define ALIGN_MAC_HDR_START(addr,macsize) \
   ((char*)((ALIGN_32((addr) + (macsize))) - (macsize)))
#define ALIGN_PADDING sizeof(uint32)
#else
#define ALIGN_MAC_HDR_START(addr,macsize) (addr)
#define ALIGN_PADDING 0
#endif


/* OS Specific Debug print code */
#define DBG_LVL_CRYPTO 0x00000001L
#define DBG_LVL_ALL    0xFFFFFFFFL
#define DBG_LVL_NONE   0x00000000L

extern int gnDbgLevel;

/* Time code */
int32 GetCurrentTime (void) NOREGPARM;
void UpdateTimeZoneOffset(void) NOREGPARM;

/* Key expiration code */
bool32 IsKeyExpirationTimerExpired(void) NOREGPARM;
int32  GetKeyExpirationTimerPeriod(void) NOREGPARM;
uint32 InitKeyExpirationTimer(int32 keyExpirationPeriod) NOREGPARM;
uint32 CancelKeyExpirationTimer(void) NOREGPARM;

#endif /* _IPSECDRVOSFUNCTIONS_H_ */
