/**************************************************************************
*           Copyright (c) 2000, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    IPSecDrvOS_linux.c
*  Date:    05/09/2001
*
***************************************************************************
*
* A collection of OS-specific functions in the IPSEC Driver..
*   
*
***************************************************************************/
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "GenDefs.h"
#include "Cniapi.h"
#include "IPSecDrvOSFunctions.h"

/**************************************************************************** 
 *
 * OS specific time functions
 *
 ****************************************************************************/

/************************ UpdateTimeZoneOffset **********************
*
*    Purpose: Get our local timezone offset so we can use UTC 
*            time for calculating expiration periods.
*
*    Result is stored in the static variable s_tzOffset.
********************************************************************/
NOREGPARM void
UpdateTimeZoneOffset(void)
{
}

/************************ Get Current Time Procedure ************************
*
* Purpose:    To get the current local time.  It is represented as seconds since 
*           Jan 1 1970
*            
*
* parms:
*    none
*
* return:
*    cur_time, of type uint32
*
*****************************************************************************/
NOREGPARM int32
GetCurrentTime(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    time_t cur_time;
    ulong flags;
    
    save_flags(flags);
    cli();

    cur_time = CURRENT_TIME;

    restore_flags(flags);

    return (int32)cur_time;
#else
    struct timespec cur_time;
    cur_time = CURRENT_TIME;
    return (int32)cur_time.tv_sec;
#endif
}


/**************************************************************************** 
 *
 * Key expiration timer code
 *
 ****************************************************************************/

/* local variables */
static struct timer_list expiration_timerLinux;
static bool32 TimerExpire = TRUE;
static ULONG expiration_period;


/*************************************************************************
*
* expirationFunc
*
* Description:
*
*   callback when the timer expire
*
* Argument:
*
*   (NONE) unsigned long - (NOT USE)
*
* Returns:
*
*   NONE
*
*************************************************************************/
static void
expirationFunc(unsigned long ptr)
{
    TimerExpire = TRUE;
}

/*************************************************************************
* 
* IsKeyExpirationTimerExpired
* 
* Description:
* 
*   Checks if the Key expiration timer has completed
* 
* Argument:
* 
*   (NONE) No Argument
* 
* Returns:
* 
*   bool32 -  TRUE timer has completed
*             FALSE timer has not completed
* 
*************************************************************************/
NOREGPARM bool32
IsKeyExpirationTimerExpired(void)
{
    if(TimerExpire)
    {
        /* ResetTimer */
        
        InitKeyExpirationTimer(expiration_period);
        
        return TRUE;
    }
            
    return FALSE;
}


/*************************************************************************
* 
* GetKeyExpirationTimerPeriod
* 
* Description:
* 
*   Gets the number of milliseconds between timer expiration
* 
* Argument:
* 
*   (NONE) No Argument
* 
* Returns:
* 
*   int32 - number of milliseconds between the timer signalling
* 
*************************************************************************/
NOREGPARM int32 
GetKeyExpirationTimerPeriod(void)
{
   return expiration_period;
}


/*************************************************************************
* 
* InitKeyExpirationTimer
* 
* Description:
* 
*   
* 
* Argument:
* 
*   (IN/OUT) int32 keyExpirationPeriod - The period to wait before timeing out.
* 
* Returns:
* 
*   uint32 - zero success
*            non-zero failure
* 
*************************************************************************/
NOREGPARM uint32
InitKeyExpirationTimer(int32 keyExpirationPeriod)
{
    uint32 rc = 0;

    TimerExpire = FALSE;

    expiration_period = keyExpirationPeriod;
    
    init_timer(&expiration_timerLinux);
    
    expiration_timerLinux.function = expirationFunc;
    /* convert milliseconds into clock ticks*/
    expiration_timerLinux.expires = jiffies + ((HZ * keyExpirationPeriod)/1000);
    expiration_timerLinux.data = 0;
    
    add_timer(&expiration_timerLinux);

    return rc;
}


/*************************************************************************
* 
* CancelKeyExpirationTimer
* 
* Description:
* 
*   Cancels the expiration timer
* 
* Argument:
* 
*   (NONE) No Argument
* 
* Returns:
* 
*   uint32 - zero success
*            non-zero failure.
* 
*************************************************************************/
NOREGPARM uint32
CancelKeyExpirationTimer(void)
{
    uint32 rc = 0;
    del_timer(&expiration_timerLinux);
    return rc;
}
