/**************************************************************************
*           Copyright (c) 2000, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    GenDefs.h
*  Date:    8/23/00
*
***************************************************************************
*  defines base types to be used by all UNITY client components
***************************************************************************/
#ifndef __GENDEFS_H
#define __GENDEFS_H


#ifndef _WIN32
#define PRELIM_UNIX_PORT
#include <linux/version.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#ifndef CNI_LINUX_INTERFACE
#include <stdint.h>
#endif
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif 

#ifdef HAVE_SYS_TYPES_H 
#ifndef CNI_LINUX_INTERFACE
#include <sys/types.h>
#else
#include <linux/types.h>
#undef _UINTPTR_T_DEFINED
#undef _INTPTR_T_DEFINED
#endif
#endif

#else //_WIN32
#undef HAVE_CONFIG_H
#undef HAVE_STDINT_H
#undef HAVE_SYS_TYPES_H
#define WORDS_BIGENDIAN 0
#endif //_WIN32

#undef TRUE
#define TRUE            1

#undef FALSE
#define FALSE           0

// it'd be nice if we could switch to the C99 standard types at some point...
#if defined(HAVE_STDINT_H) || defined(HAVE_INTTYPES_H)
typedef uint8_t		bool8;
typedef uint16_t	bool16;
typedef uint32_t	bool32;

typedef int8_t		int8;
typedef int16_t		int16;
#if !defined(CNI_LINUX_INTERFACE) || !defined(CONFIG_ISDN_PPP) || !defined(CONFIG_ISDN_PPP_VJ) || !defined(_SLHC_H)
typedef int32_t 	int32;
typedef int64_t         int64;
#endif

typedef uint8_t		uint8;
typedef uint16_t	uint16;
typedef uint32_t	uint32;

typedef uint64_t	uint64;
#else
//original windows definitions (32 bit)
typedef unsigned char   bool8;
typedef unsigned short  bool16;
typedef unsigned long   bool32;

typedef signed char     int8;
typedef signed short    int16;
typedef signed long     int32;

typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned long   uint32;
#ifdef _WIN32
typedef __int64                    int64;
typedef unsigned __int64           uint64;
#else
typedef long long                  int64;
typedef unsigned long long__int64 uint64;
#endif
#endif

// integer types for doing pointer arithmetic, they should be the
// same size as a pointer. Part of the C99 standard, but they aren't
// available everywhere yet.
// These defs should work with IA32 (x86), ILP32 (sparcv8) and LP64 (sparcv9).
// These types are protected with the WIN32 macros (_INTPTR_T_DEFINED), since
// some, but not all of the WIN32 SDK's define these types.
#ifndef _INTPTR_T_DEFINED
#if defined(_LP64)
typedef int64 intptr_t;
#else
typedef int32 intptr_t;
#endif
#define _INTPTR_T_DEFINED
#endif

#ifndef _UINTPTR_T_DEFINED
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#if defined(_LP64)
#warning 64 bit
typedef uint64 uintptr_t;
#else
typedef uint32 uintptr_t;
#endif
#endif
#define _UINTPTR_T_DEFINED
#endif


typedef int 	BOOL;
#ifndef _WIN32
typedef int 	BOOLEAN;
#endif

#ifdef _WIN32
typedef int mode_t;
#endif

typedef	unsigned char   uchar;
#ifndef HAVE_SYS_TYPES_H
typedef unsigned int    uint;
typedef unsigned short  ushort;
typedef unsigned long   ulong;
#endif

typedef ulong   ULONG;
typedef ulong*  PULONG;
typedef uint32  DWORD;
typedef uint32* PDWORD;
typedef long    LONG;
typedef long*   PLONG;
typedef int     INT;
typedef int*    PINT;
typedef uint    UINT;
typedef uint*   PUINT;
typedef uint16  USHORT;
typedef uint16* PUSHORT;
typedef int16   SHORT;
typedef int16*  PSHORT;
typedef uint16  WORD;
typedef uint16* PWORD;
typedef char    CHAR;
typedef uchar   UCHAR;
typedef char*   PCHAR;
typedef uint8   BYTE;
typedef uint8*  PBYTE;
#define         VOID  void
typedef void*   PVOID;
#ifdef _WIN32
typedef void*   HANDLE;
#else
typedef int     HANDLE;
#endif //!_WIN32
typedef HANDLE* PHANDLE;
typedef uint8   KIRQL;

/* function parameter context */
#undef IN
#define IN

#undef OUT
#define OUT

#undef BOTH
#define BOTH

#undef packed
#define packed

#ifndef CLEAR
#define CLEAR(a)			memset(&a,0,sizeof(a))
#endif

#ifndef POINT_BEYOND
#define POINT_BEYOND(a,t)	(t) &((&a)[1])
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef _WIN32
#define _ftime ftime
#define _timeb timeb
#define __cdecl
#ifndef WINAPI
#define WINAPI
#endif
#define ALTIGA_NETWORKS /* XXX */
#endif

#ifndef _WIN32
#undef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef MAX_INTERFACES
#define MAX_INTERFACES 20
#endif
/* END OF MACRO HELL */
#endif /*__GENDEFS_H*/
