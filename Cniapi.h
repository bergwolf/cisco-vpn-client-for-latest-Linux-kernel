/**************************************************************************
*           Copyright (c) 2000, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    CNIAPI.h
*  Date:    6/19/00
*
***************************************************************************
*  This is the header file for the Cisco Network Interceptor API.  It
*  should be included in any module that will be making calls to CNI.
***************************************************************************/
#ifndef _CNIAPI_H_
#define _CNIAPI_H_
/******************************* Includes *********************************/
#include "GenDefs.h"

/*************************** Generic constants ****************************/

/* IN/OUT/OPTIONAL defines are for readability only*/

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

/* the 2.6 kernel has a config option, CONFIG_REGPARM, which
   causes gcc to pass function arguments in registers. Since
   our binary-only code is compiled without this optimization,
   any functions used by the linux driver need to be declared
   with the following gcc attribute.
*/
#if defined(CNI_LINUX_INTERFACE)
#define NOREGPARM __attribute__((regparm(0)))
#else
#define NOREGPARM
#endif

/**************************** Flags Definitions ****************************/
#define CNI_USE_BUFFER      0x00000001
#define CNI_COPY_BUFFER     0x00000002
#define CNI_KEEP_BUFFERS    0x00000004
#define CNI_RELEASE_BUFFERS 0x00000008
#define CNI_TRUNCATE_PACKET 0x00000010

/**************************** Status Definition ****************************
 *
 *  Status values are 32 bits, and follow a format similar to Microsoft, and DN.
 *
 *   f e d c b a 9 8 7 6 5 4 3 2 1 0 f e d c b a 9 8 7 6 5 4 3 2 1 0
 *  +---+-+-+-----------------------+-------------------------------+
 *  |Sev|C|R|     Facility          |               Code            |
 *  +---+-+-+-----------------------+-------------------------------+
 *
 *
 *      Sev - Severity code
 *
 *          00 - Success
 *          01 - Informational
 *          10 - Warning
 *          11 - Error
 *
 *      C - is the Customer code flag, indicates that this is a non-MS code,
 *          this is 1 for ALL CNI codes.
 *      R - is a reserved bit, always 0
 *      Facility - is the facility code 
 *                 constant 0x451, I don't know if MS is supposed to assign these
 *                 but we should have something to differentiate us from MS, this one
 *                 is nothing special, just a number.
 *      Code - is the facility's status code
 *
 **************************************************************************/
/*
 Typedef CNISTATUS
*/
typedef ULONG CNISTATUS;

/*
* Define the Severity Levles
*/
#define CNI_STATUS_SEVERITY_MASK         ((CNISTATUS) 0xC0000000L)
#define CNI_STATUS_SEVERITY_SUCCESS      ((CNISTATUS) 0x00000000L)
#define CNI_STATUS_SEVERITY_INFORMATION  ((CNISTATUS) 0x40000000L)
#define CNI_STATUS_SEVERITY_WARNING      ((CNISTATUS) 0x80000000L)
#define CNI_STATUS_SEVERITY_ERROR        ((CNISTATUS) 0xC0000000L)

/*
* Define the Customer Flag
*/
#define CNI_STATUS_CUSTOMER_FLAG ((CNISTATUS) 0x20000000L)

/*
* Define the Facility
*/
#define CNI_STATUS_FACILITY_MASK ((CNISTATUS) 0x0FFF0000L)
#define CNI_STATUS_FACILITY_CNI  ((CNISTATUS) 0x04510000L)

/*
* Define the Codes
*/
#define CNI_STATUS_CODE_MASK     ((CNISTATUS) 0x0000ffffL)
#define CNI_SUCCESS              (CNI_STATUS_SEVERITY_SUCCESS | CNI_STATUS_FACILITY_CNI | CNI_STATUS_CUSTOMER_FLAG)
#define CNI_PENDING              (CNI_SUCCESS | (CNISTATUS)0x1L)
#define CNI_CHAIN                (CNI_SUCCESS | (CNISTATUS)0x2L)
#define CNI_DISCARD              (CNI_SUCCESS | (CNISTATUS)0x3L)
#define CNI_CONSUME              (CNI_SUCCESS | (CNISTATUS)0x4L)

#if 0
#define CNI_REPLACE              (CNI_SUCCESS | (CNISTATUS)0x3L)
#define CNI_CONSUME_EX           (CNI_SUCCESS | (CNISTATUS)0x5L)
#define CNI_BUFFER_REPLACED      (CNI_SUCCESS | (CNISTATUS)0x6L)
#define CNI_BUFFER_USED          (CNI_SUCCESS | (CNISTATUS)0x7L)
#define CNI_UPGRADE              (CNI_SUCCESS | (CNISTATUS)0x9L)
#define CNI_REBOOT               (CNI_SUCCESS | (CNISTATUS)0x10L)
#endif

#define CNI_WARNING              (CNI_STATUS_SEVERITY_WARNING | CNI_STATUS_FACILITY_CNI | CNI_STATUS_CUSTOMER_FLAG)
#define CNI_W_BAD_FORMAT         (CNI_WARNING | (CNISTATUS)0x1L)
#define CNI_W_COULD_NOT_SHORTEN  (CNI_WARNING | (CNISTATUS)0x2L)
#define CNI_W_FRAG_DESC_FAILURE  (CNI_WARNING | (CNISTATUS)0x3L)
#define CNI_W_NEED_BUFFER        (CNI_WARNING | (CNISTATUS)0x4L)
#define CNI_W_OUT_OF_DESCRIPTORS (CNI_WARNING | (CNISTATUS)0x5L)
#define CNI_W_OUT_OF_RANGE       (CNI_WARNING | (CNISTATUS)0x6L)
#define CNI_W_OUT_OF_RESOURCES   (CNI_WARNING | (CNISTATUS)0x7L)
#define CNI_W_PACKET_TOO_SMALL   (CNI_WARNING | (CNISTATUS)0x8L)
#define CNI_W_NOT_ACCEPTED       (CNI_WARNING | (CNISTATUS)0x9L)
#define CNI_W_BUFFER_TOO_SMALL	 (CNI_WARNING | (CNISTATUS)0xAL)
 
#define CNI_ERROR                (CNI_STATUS_SEVERITY_ERROR | CNI_STATUS_FACILITY_CNI | CNI_STATUS_CUSTOMER_FLAG)
#define CNI_E_OUT_OF_MEMORY      (CNI_ERROR | (CNISTATUS)0x1L)
#define CNI_E_BAD_BINDING        (CNI_ERROR | (CNISTATUS)0x2L)
#define CNI_E_BAD_FRAGMENT       (CNI_ERROR | (CNISTATUS)0x3L)
#define CNI_E_BAD_MEMORY         (CNI_ERROR | (CNISTATUS)0x4L)
#define CNI_E_BAD_PACKET         (CNI_ERROR | (CNISTATUS)0x5L)
#define CNI_E_BAD_PARAMETER      (CNI_ERROR | (CNISTATUS)0x6L)
#define CNI_E_FRAGMENT_TOO_SHORT (CNI_ERROR | (CNISTATUS)0x7L)
#define CNI_E_NO_ENTRY_POINT     (CNI_ERROR | (CNISTATUS)0x8L)
#define CNI_E_GENERIC            (CNI_ERROR | (CNISTATUS)0x9L)
#define CNI_E_DUPLICATE_FILTER   (CNI_ERROR | (CNISTATUS)0xAL)
#define CNI_E_SETCONFIG_FAIL     (CNI_ERROR | (CNISTATUS)0xBL)

#define CNI_E_FRAGMENT_NOT_FOUND     (CNI_ERROR | (CNISTATUS)0xCL)
#define CNI_E_UNKNOWN_FLAGS          (CNI_ERROR | (CNISTATUS)0xDL)
#define CNI_E_ITEM_NOT_FOUND         (CNI_ERROR | (CNISTATUS)0xEL)
#define CNI_E_UNSUCCESSFUL           (CNI_ERROR | (CNISTATUS)0xFL)
#define CNI_E_BAD_CONTEXT            (CNI_ERROR | (CNISTATUS)0x10L)
#define CNI_E_LAST_FRAGMENT          (CNI_ERROR | (CNISTATUS)0x11L)
#define CNI_E_UNAVAILABLE            (CNI_ERROR | (CNISTATUS)0x12L)
#define CNI_E_CANNOT_INSTALL         (CNI_ERROR | (CNISTATUS)0x13L)
#define CNI_E_CANNOT_LOAD            (CNI_ERROR | (CNISTATUS)0x14L)
#define CNI_E_COLLECTION_FULL        (CNI_ERROR | (CNISTATUS)0x15L)
#define CNI_E_FILTER_REG_FAILURE     (CNI_ERROR | (CNISTATUS)0x16L)
#define CNI_E_CANNOT_CREATE_KEY      (CNI_ERROR | (CNISTATUS)0x17L)
#define CNI_E_OLDER_VERSION          (CNI_ERROR | (CNISTATUS)0x18L)
#define CNI_E_INSTALL_FAILED         (CNI_ERROR | (CNISTATUS)0x19L)
#define CNI_E_UNINSTALL_FAILED       (CNI_ERROR | (CNISTATUS)0x1AL)
#define CNI_E_SERVICE_PACK_REQUIRED  (CNI_ERROR | (CNISTATUS)0x1BL)
#define CNI_E_FILTER_LIMIT_EXCEEDED  (CNI_ERROR | (CNISTATUS)0x1CL)
#define CNI_E_NOT_SUPPORTED          (CNI_ERROR | (CNISTATUS)0x1DL)
#define CNI_E_NOT_BOUND              (CNI_ERROR | (CNISTATUS)0x1EL)
#define CNI_E_PKT_DESC_FAILURE       (CNI_ERROR | (CNISTATUS)0x1FL)
#define CNI_E_FRAG_DESC_FAILURE      (CNI_ERROR | (CNISTATUS)0x20L)
#define CNI_E_OUT_OF_RANGE           (CNI_ERROR | (CNISTATUS)0x21L)
#define CNI_E_BAD_FORMAT             (CNI_ERROR | (CNISTATUS)0x22L)
#define CNI_E_NOT_ACCEPTED           (CNI_ERROR | (CNISTATUS)0x23L)

#define CNI_E_KEY_NOT_FOUND          (CNI_ERROR | (CNISTATUS)0x29L)
#define CNI_E_KEY_ALREADY_OPEN       (CNI_ERROR | (CNISTATUS)0x2AL)
#define CNI_E_VALUE_NOT_FOUND        (CNI_ERROR | (CNISTATUS)0x2BL)
#define CNI_E_KEY_ALREADY_EXISTS     (CNI_ERROR | (CNISTATUS)0x2CL)

#define CNI_E_ALREADY_INITIALIZED    (CNI_ERROR | (CNISTATUS)0x2DL)
#define CNI_E_NOT_INITIALIZED        (CNI_ERROR | (CNISTATUS)0x2EL)
#define CNI_E_IN_USE                 (CNI_ERROR | (CNISTATUS)0x2FL)
#define CNI_E_NO_WRITE_LOCK          (CNI_ERROR | (CNISTATUS)0x30L)
#define CNI_E_NEED_REBOOT            (CNI_ERROR | (CNISTATUS)0x31L)
#define CNI_E_ACTIVE_RAS_CONNECTIONS (CNI_ERROR | (CNISTATUS)0x32L)
#define CNI_E_ADAPTER_NOT_FOUND      (CNI_ERROR | (CNISTATUS)0x33L)
#define CNI_E_COMPONENT_REMOVED_PENDING_REBOOT (CNI_ERROR | (CNISTATUS)0x34L)


/*
* Define some useful macros for determining success, etc.
*/
#define CNI_IS_SUCCESS(x)     (!(x&CNI_STATUS_SEVERITY_ERROR))
#define CNI_IS_WARNING(x)     ((x&CNI_STATUS_SEVERITY_MASK)==CNI_STATUS_SEVERITY_WARNING)
#define CNI_IS_INFORMATION(x) ((x&CNI_STATUS_SEVERITY_MASK)==CNI_STATUS_SEVERITY_INFORMATION)
#define CNI_IS_ERROR(x)       ((x&CNI_STATUS_SEVERITY_MASK)==CNI_STATUS_SEVERITY_ERROR)
#define CNI_IS_PENDING(x)     (CNI_IS_SUCCESS(x) && ((CNI_STATUS_CODE_MASK & CNI_PENDING) == (CNI_STATUS_CODE_MASK&CNI_PENDING)))
	
/**************************** Opaque Data Types ***************************/
/*#ifndef CNI_API_SOURCE*/
typedef PVOID          OPAQUE_HANDLE;
typedef OPAQUE_HANDLE  CNIPACKET;
typedef OPAQUE_HANDLE  CNIFRAGMENT;
typedef OPAQUE_HANDLE  CNIBINDING;

typedef CNIPACKET      *PCNIPACKET;
typedef CNIFRAGMENT    *PCNIFRAGMENT;
typedef CNIBINDING     *PCNIBINDING;
/*#endif*/

/**************************** CNI_CHARACTERISTICS *************************/
typedef struct {
	ULONG ulAPIVersion; 
	ULONG ulMaxPacketDescriptors;
	ULONG ulMaxFragmentDescriptors;

	/*** Callback function pointers ***/
	CNISTATUS 
	(*Send)(IN OUT PCNIBINDING pBinding,
			IN OUT PVOID *pSendContext,
			IN OUT PCNIFRAGMENT pMacHeader,
			IN OUT PCNIPACKET pPacket) NOREGPARM;

	CNISTATUS
	(*SendComplete)(IN CNIBINDING Binding,
					IN PVOID SendContext,
					IN OUT CNIPACKET Packet) NOREGPARM ;

    CNISTATUS
	(*Receive)(IN OUT PCNIBINDING pBinding,
			   IN OUT PVOID *pReceiveContext,
			   IN OUT PCNIFRAGMENT pMacHeader,
			   IN OUT PCNIFRAGMENT pLookAhead,
			   OUT PCNIPACKET pReplacementPacket,
			   IN ULONG  *pulPacketSize) NOREGPARM;

    CNISTATUS 
	(*ReceiveComplete)(IN  CNIBINDING Binding,
					   IN  PVOID ReceiveContext,
					   IN OUT CNIPACKET Packet) NOREGPARM;

    CNISTATUS 
	(*TransferData)(IN CNIBINDING Binding,
					IN PVOID ReceiveContext,
					IN OUT CNIPACKET Packet,
					IN ULONG ulBytesOffset,
					IN ULONG ulBytesToTransfer) NOREGPARM;

    VOID
	(*PluginError)(IN CNISTATUS Status,
				   IN CHAR *pcErrorDescription) NOREGPARM;

} CNI_CHARACTERISTICS, *PCNI_CHARACTERISTICS;


/**************************** NICMEDIUM ***********************************/
typedef enum
{
	CniMediumUNKNOWN = 0,
	CniMedium802_3,
	CniMedium802_5,
	CniMediumFddi,
	CniMediumWan,
	CniMediumLocalTalk,
	CniMediumDix,
	CniMediumArcnetRaw,
	CniMediumArcnet878_2,
	CniMediumAtm,
	CniMediumWirelessWan,
	CniMediumIrda
} NICMEDIUM, *PNICMEDIUM;

/********************************* IRQL ***********************************/
#if !defined(RAISE_IRQL) && defined(WINNT)
#include <ndis.h>
#include "spinlock.h"
/* This is taken from the DNE code and will only be used with the DNE API on NT*/
extern DN_SPIN_LOCK _Dn_Global_Plugin_Lock;
#define DN_IRQL               KIRQL
#define _LOWER_IRQL(i)         KeLowerIrql((i))
#define _RAISE_IRQL(i)         KeRaiseIrql(DISPATCH_LEVEL,(i))
#define _RAISE_IRQL_SYNC_TIMER KeRaiseIrql(DISPATCH_LEVEL,(i))

#define RAISE_IRQL(i) \
    _RAISE_IRQL(i);\
    ACQUIRE_SPINLOCK( &_Dn_Global_Plugin_Lock )

#define LOWER_IRQL(i) \
    RELEASE_SPINLOCK( &_Dn_Global_Plugin_Lock );\
    _LOWER_IRQL(i)

#endif


#if !defined( RAISE_IRQL ) && defined( WIN95 )
/*
* This method of raising IRQL for 9x is a hack.  It will only
* disable interrupts for the current VM.  Therefore you should be VERY
* careful about where you use them and how long the IRQL is raised
* since this could impact everything in the system, from mouse input
* to disk access.  But... this method has worked in the DNE implementation
* on 9x for some time and may as well remain the same until a 
* problem is found.
*/

#define RAISE_IRQL( x ) { \
    *x=1; \
    __asm{ pushfd } \
    __asm{ cli } \
}

#define LOWER_IRQL( x ) {\
    __asm{ popfd } \
}

#endif // !RAISE_IRQL


#if defined(CNI_LINUX_INTERFACE )
/* avoid warnings from unused variables...*/
#define RAISE_IRQL(x) (void)(x)
#define LOWER_IRQL(x)
#elif defined(CNI_SOLARIS_INTERFACE)
#define RAISE_IRQL(x) (void)(x)
#define LOWER_IRQL(x)
#elif defined( CNI_DARWIN_INTERFACE )
#define RAISE_IRQL(x) (void)(x)
#define LOWER_IRQL(x)
#endif /* !RAISE_IRQL */


/*************************** Memory Management ****************************/

PVOID 
CniMemRealloc(IN UINT uiSize,
			OUT  PVOID pMem) NOREGPARM;

CNISTATUS 
CniMemAlloc(IN UINT uiSize,
			OUT  PVOID *ppMem) NOREGPARM;

CNISTATUS 
CniMemFree(IN PVOID pMem) NOREGPARM;

/****************************Packet Management*****************************/

CNISTATUS 
CniNewPacket(IN UINT uiSize,
			 IN OUT PCNIPACKET pPacket) NOREGPARM;

CNISTATUS 
CniReleasePacket(IN CNIPACKET Packet,
			  IN ULONG ulFlags) NOREGPARM;

CNISTATUS 
CniGetPacketData(IN CNIPACKET Packet,
				 IN ULONG ulOffset,
				 IN ULONG ulSize,
				 OUT PCHAR pBuffer) NOREGPARM;

CNISTATUS 
CniSetPacketData(IN CNIPACKET Packet,
				 IN ULONG ulOffset,
				 IN ULONG ulSize,
				 IN PCHAR pBuffer,
				 IN ULONG ulFlags) NOREGPARM;

CNISTATUS 
CniQueryPacket(IN CNIPACKET Packet,
			   OUT PULONG pulSize OPTIONAL,
			   OUT PULONG pulNumFragments OPTIONAL,
			   OUT PCNIFRAGMENT pFirstFragment OPTIONAL,
			   OUT PCNIFRAGMENT pLastFragment OPTIONAL) NOREGPARM;

CNISTATUS 
CniAddFragToFront(IN CNIPACKET Packet,
				  IN CNIFRAGMENT Fragment) NOREGPARM;

CNISTATUS 
CniCopyFragment(IN CNIFRAGMENT SourceFragment,
				IN OUT PCNIFRAGMENT pDestFragment,
				IN ULONG ulFlags) NOREGPARM;

CNISTATUS 
CniNewFragment(IN ULONG ulSize,
			   IN CHAR *pBuffer,
			   OUT CNIFRAGMENT *pFragment,
			   IN ULONG ulFlags) NOREGPARM;

CNISTATUS 
CniReleaseFragment(IN CNIFRAGMENT Fragment,
				   IN ULONG ulFlags) NOREGPARM;

CNISTATUS 
CniSetFragmentLength(IN OUT CNIFRAGMENT Fragment,
					 IN ULONG ulLength,
					 IN OUT CNIPACKET Packet) NOREGPARM;

CNISTATUS 
CniGetFragmentInfo(IN CNIFRAGMENT Fragment,
				   OUT PCHAR *ppData,
				   OUT ULONG *pulLength) NOREGPARM;

CNISTATUS 
CniGetFrameType(IN CNIBINDING Binding,
				OUT PNICMEDIUM pMedium) NOREGPARM;

CNISTATUS
CniGetMacName(IN  CNIBINDING   Binding,
              OUT PCHAR       *pszMacName) NOREGPARM;

CNISTATUS
CniGetMacAddress(IN CNIBINDING Binding,
				 OUT PCHAR *ppMacAddress,
				 OUT ULONG *pulMacAddressSize) NOREGPARM;

CNISTATUS
CniGetMTUSize(IN CNIBINDING Binding,
			  OUT PULONG pulMtuSize) NOREGPARM;

CNIBINDING 
CniGetTrueBinding(IN CNIBINDING BINDING) NOREGPARM;

CNIBINDING 
CniGetBindingforIpcUdp(IN CNIBINDING BINDING) NOREGPARM;


#ifdef PLATFORM_LINUX
CNISTATUS
CNI_DNEListBindings(OUT CNIBINDING* bindingArray,
                    IN OUT ULONG*   bindingArraySize) NOREGPARM;

CNIBINDING
CniGetBindingByIndex(IN INT iIndex) NOREGPARM;
#endif

#if !defined(_WIN32) && defined(VIRTUAL_ADAPTER)
CNIBINDING
CniGetVABinding(void) NOREGPARM;
#endif
/*************************** Traffic Management ***************************/

CNISTATUS  
CniInjectReceive(IN CNIBINDING Binding,
				 IN PVOID ReceiveContext,
				 IN CNIFRAGMENT MacHeader,
				 IN CNIPACKET Packet,
				 IN ULONG ulSize) NOREGPARM;

CNISTATUS
CniInjectSend(IN CNIBINDING Binding,
			  IN PVOID SendContext,
			  IN CNIFRAGMENT MacHeader,
			  IN CNIPACKET Packet) NOREGPARM;


/********************* Initialization Entry Points ************************/
#ifndef CNI_API_SOURCE
CNISTATUS 
CniPluginLoad(OUT PCHAR *szName,
			  OUT PCNI_CHARACTERISTICS *pCniChars) NOREGPARM;

CNISTATUS
CniPluginDeviceCreated(void) NOREGPARM;

CNISTATUS
CniPluginUnload(void) NOREGPARM;

uint32 
CniPluginIOCTL(IN uint32 ulCode,
               IN PVOID pIoBuffer,
               IN uint32 ulInputBufferSize,
               IN uint32 ulOutputBufferSize,
               OUT uint32* pulReturnSize) NOREGPARM;

#endif

#endif /*#ifndef _CNIAPI_H_*/
