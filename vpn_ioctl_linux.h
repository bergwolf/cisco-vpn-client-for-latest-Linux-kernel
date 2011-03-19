/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    vpn_ioctl_linux.h
*  Date:    04/13/2001
*
***************************************************************************
*
* Definitons for the ioctls supported by the linux driver.
*
***************************************************************************/
#ifndef VPN_IOCTL_LINUX_H
#define VPN_IOCTL_LINUX_H

#define SIOCGVPNCMD     (SIOCDEVPRIVATE + 0)
#define SIOCGVPNIFUP    (SIOCDEVPRIVATE + 1)
#define SIOCGVPNIFDOWN  (SIOCDEVPRIVATE + 2)

#define VPNIFUP_SUCCESS     0
#define VPNIFDOWN_SUCCESS   0
#define VPNIFUP_FAILURE     1
#define VPNIFDOWN_FAILURE   2

#define LINUX_VPN_IFNAME "cipsec0"

#define CTRL_DATA_SIZE 4096
struct ifvpncmd {
    unsigned int cmd;
    unsigned int datalen;
    unsigned char data[CTRL_DATA_SIZE];
};

#endif  /* VPN_IOCTL_LINUX_H */
