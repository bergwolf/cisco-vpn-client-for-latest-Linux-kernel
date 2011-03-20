/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    linuxcniapi.h
*  Date:    4/3/01
*
***************************************************************************
* This module contains the prototypes for the translation layer between the
* CNI API and the Linux Interceptor driver.
***************************************************************************/
#ifndef _LINUXCNIAPI_H_
#define _LINUXCNIAPI_H_

/*************************** internal binding structure ********************/
typedef struct
{
    BOOL called;
    int rc;
} inject_status;
typedef struct {
    /*desription of the device */
    struct net_device *pDevice;
    struct packet_type *pPT;
    int (*InjectReceive) (struct sk_buff *, 
                          struct net_device *,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
                          struct packet_type *,
                          struct net_device *);
#else
                          struct packet_type *);
#endif
    int (*InjectSend) (struct sk_buff * skb, struct net_device * dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
    struct net_device_ops stack_netops;
    const struct net_device_ops *saved_netops;
#endif

    int recv_real_hh_len;
    int send_real_hh_len;
    int original_mtu;

    inject_status send_stat;
    inject_status recv_stat;
} BINDING, *PBINDING;

/********************************************************************************/
#endif                          /* _LINUXCNIAPI_H_ */
