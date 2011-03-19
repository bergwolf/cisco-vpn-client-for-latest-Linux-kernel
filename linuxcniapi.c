/**************************************************************************
 *           Copyright (c) 2001, Cisco Systems, All Rights Reserved
 ***************************************************************************
 *
 *  File:    linuxcniapi.c
 *  Date:    22/03/01
 *
 ***************************************************************************
 * This module implements a translation layer between the CNI API and the
 * Linux Interceptor driver.
 ***************************************************************************/
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "linux_os.h"
#include "vpn_ioctl_linux.h"

#include "Cniapi.h"
#include "unixcniapi.h"
#include "linuxcniapi.h"
#include "unixkernelapi.h"

/******************************** Globals *********************************/
extern BINDING Bindings[MAX_INTERFACES];
extern unsigned long rx_bytes;

CNI_CHARACTERISTICS CNICallbackTable; /* This stores the Plugin's function pointers */
PCHAR pcDeviceName;             /* Ignore. Only our pluggin so we don't care about it */

/*************************************************************************
 *
 * CniGetFrameType
 *
 * Description:
 * This function retrieves the media type for the packets sent and received
 * via this medium.
 *
 *	
 * Argument:
 *
 *   IN CNIBINDING Binding - A binding handle.
 *   OUT PNICMEDIUM pMedium - The media type for this binding.
 *                CniMedium802_3	Ethernet
 *                CniMedium802_5	Token Ring
 *                CniMediumFddi	Fiber Distributed Data Interface
 *                CniMediumWan	Various point to point and WAN interfaces
 *                CniMediumLocalTalk	LoacalTalk network (MAC)
 *                CniMediumDix	Ethernet - drivers use the DIX header format.
 *                CniMediumArcnetRaw	ARCNET network
 *                CniMediumArcnet878_2	ARCNET 878.2 network
 *                CniMediumAtm	ATM network
 *                CniMediumWirelessWan	Various wireless WAN networks
 *                CniMediumIrda	IRDA, infrared network
 *
 *  NOTE - Only CniMediumUNKNOWN, CniMedium802_3 and CniMediumWan will be
 *         returned at present as only the second 2 are accepted. Other
 *         is for errors (shouldn't happen).
 *
 * Returns:
 *
 *   CNISTATUS  - CNI_SUCCESS - The Frame type was returned.
 *                CNI_E_BAD_BINDING - The Binding is not a CNIBINDING.
 *                CNI_E_BAD_PARAMETER - pMedium was NULL.
 *
 *************************************************************************/
NOREGPARM CNISTATUS
CniGetFrameType(IN CNIBINDING Binding, OUT PNICMEDIUM pMedium)
{

    // We will support 802_3 for now.
    *pMedium = CniMedium802_3;


    return CNI_SUCCESS;
}

/*************************************************************************
 *
 * CniGetMacAddress
 *
 * Description:
 * This function retrieves the MAC address for the binding specified.
 * The character array represented by *ppMacAddress must not be modified,
 * or released.
 *
 *
 * Argument:	
 *
 *   IN CNIBINDING Binding - A binding handle
 *   OUT PCHAR *ppMacAddress - A pointer to a character array that
 *                contains the MAC address.
 *   OUT ULONG pulMacAddressSize - The Fragment length was changed.
 *
 * Returns:
 *
 *   CNISTATUS  - CNI_SUCCESS - Returned the MAC address.
 *                CNI_E_BAD_BINDING - The Binding is not a CNIBINDING.
 *                CNI_E_BAD_PARAMETER - pMedium was NULL.
 *
 *************************************************************************/
NOREGPARM CNISTATUS
CniGetMacAddress(IN CNIBINDING Binding,
                 OUT PCHAR * ppMacAddress,
                 OUT ULONG * pulMacAddressSize) 
{
    //  this code will be different in 2.4.x kernel
    PBINDING pBinding;

    pBinding = (PBINDING) Binding;

    if (!pBinding || !pBinding->pDevice)
    {
        return CNI_E_BAD_BINDING;
    }

    if (!ppMacAddress || !pulMacAddressSize)
    {
        return CNI_E_BAD_PARAMETER;
    }

    *ppMacAddress = pBinding->pDevice->dev_addr;

    *pulMacAddressSize = ETH_ALEN;

    return CNI_SUCCESS;
}

/*************************************************************************
 *
 * CniGetMacName
 *
 * Description:
 * This function retrieves the name of the network device associated with a
 * given binding.  It works differently depending on the operating system.
 *
 * On NT systems, the MAC name will be the full device name of the NIC card,
 * as seen by the IPCONFIG.EXE application.  The name string on NT includes
 * the full device driver name for the NIC driver, which has the form:
 * "DosDevices\<driver name>".  The registry settings for the device can be
 *  found in the registry at:
 * "HKEY_LOCAL_MACNIE\System\CurrentControlSet\Services\<driver name>"
 *
 * On Windows 95/98 systems, the name string is an enumerated string
 * corresponding to the NIC driver.  Settings for the NIC driver are found in
 * the registry at:
 * "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Class\Net\<enumerated string>"
 *
 *
 *
 * Argument:
 *	
 *   IN CNIBINDING Binding - A binding handle that will be used to determine
 *                           the associated network adapter
 *   OUT PCHAR *macName - a pointer to the character string giving the name
 *                        of the name associated with Binding
 *
 * Returns:
 *
 *   CNISTATUS  - CNI_SUCCESS - The packet was sent by the NIC.
 *                CNI_E_BAD_PARAMETER - One of the parameters was invalid
 *
 *************************************************************************/
NOREGPARM CNISTATUS
CniGetMacName(IN CNIBINDING Binding, OUT PCHAR * pszMacName) 
{
    PBINDING pBinding;

    pBinding = (PBINDING) Binding;

    if (!pBinding || !pszMacName || !pBinding->pDevice)
    {
        return CNI_E_BAD_PARAMETER;
    }


    *pszMacName = pBinding->pDevice->name;

    return CNI_SUCCESS;
}

/*************************************************************************
 *
 * CniGetMTUSize
 *
 * Description:
 * This function retrieves the MTU for the specified binding.
 *
 *	
 * Argument:
 *
 *   IN CNIBINDING Binding - A binding handle
 *   OUT PULONG pulMtuSize - The size, in bytes, of the MTU for
 *                this binding.
 *
 * Returns:
 *
 *   CNISTATUS  - CNI_SUCCESS - The MTU was retrieved.
 *                CNI_E_BAD_BINDING - The Binding is not a CNIBINDING.
 *                CNI_E_BAD_PARAMETER - pulMtuSize was NULL.
 *
 *************************************************************************/
NOREGPARM CNISTATUS
CniGetMTUSize(IN CNIBINDING Binding, OUT PULONG pulMtuSize) 
{
    PBINDING pBinding;

    if (!Binding || !pulMtuSize)
        return CNI_E_BAD_PARAMETER;

    pBinding = (PBINDING) Binding;

    /* return the original MTU */
    *pulMtuSize = (ULONG) pBinding->original_mtu;

    return CNI_SUCCESS;
}


/*************************************************************************
 * 
 * CniInjectReceive
 * 
 * Description:
 * This function will inject a Packet into the receive data stream as though
 * they were received by and send to a NIC/protocol pair defined by Binding.
 * The ReceiveContext should be set to provide packet-specific information 
 * to CniTransferData() and CniReceiveComplete().  This plugin will not see
 * the injected packet at its CniReceive() interface, it will be sent 
 * directly to the protocol.
 * If the size of Packet is less than ulSize, and the receiving protocol is
 * interested in receiving the rest of the packet the plugin's
 * CniTransferData() entry point will be called to copy the remaining packet
 * data into a Packet belonging to the protocol.
 * 
 * Argument:
 * 
 *   IN CNIBINDING Binding - A binding handle that will be used to
 *                receive this packet.
 *   IN PVOID ReceiveContext -	Data to be passed to the 
 *                TransferData entry point.
 *   IN CNIFRAGMENT MacHeader - This is the header that will be 
 *                copied to the packet before it is received by the protocol.
 *                It should correspond to the Binding.
 *   IN CNIPACKET Packet - The packet that will be received, minus 
 *                the MAC Header.
 *   IN ULONG ulSize - The size of the complete packet.
 * 
 * Returns:
 * 
 *   CNISTATUS  - CNI_SUCCESS - The packet was sent
 *                CNI_PENDING - The packet was not sent yet, but will be.
 *                CNI_W_BAD_FORMAT - The packet data was formatted incorrectly.
 *                CNI_E_NO_ENTRY_POINT - The plugin did not have a 
 *                CniTransferData() entry point.
 * 
 *************************************************************************/
NOREGPARM CNISTATUS
CniInjectReceive(IN CNIBINDING Binding,
                 IN PVOID ReceiveContext,
                 IN CNIFRAGMENT MacHeader, IN CNIPACKET Packet,
                 IN ULONG ulSize) 
{
    CNISTATUS rc = CNI_SUCCESS;
    LPPACKETDESCRIPTOR lpPacketDescriptor;
    PBINDING pBinding;
    LPFRAGMENTBUFFER lpMacFragment;
    struct sk_buff *skb = NULL;
    unsigned char *pIP = NULL, *pMac = NULL;

    /* we need to build the actual sk_buff from the packet structure */
    pBinding = (PBINDING) Binding;
    lpPacketDescriptor = (LPPACKETDESCRIPTOR) Packet;
    lpMacFragment = (LPFRAGMENTBUFFER) MacHeader;

    skb = dev_alloc_skb(lpPacketDescriptor->uiPacketSize
                        + lpMacFragment->uiFragmentDataSize);
    if (!skb)
    {
        rc = CNI_W_OUT_OF_DESCRIPTORS;
        goto exit_gracefully;
    }
    /* move the data into the packet */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    {
        struct timeval timestamp;

        do_gettimeofday(&timestamp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb->tstamp = timeval_to_ktime(timestamp);
#else
        skb_set_timestamp(skb,&timestamp);
#endif
    }
#else
    do_gettimeofday(&skb->stamp);
#endif

    pIP = skb_put(skb, lpPacketDescriptor->uiPacketSize);

    CniGetPacketData(Packet, 0, lpPacketDescriptor->uiPacketSize, pIP);

    skb->dev = pBinding->pDevice;

    /* put back the mac header */
    switch (pBinding->recv_real_hh_len)
    {
    case ETH_HLEN:
        pMac = skb_push(skb, lpMacFragment->uiFragmentDataSize);
        kernel_memcpy(pMac, lpMacFragment->lpFragmentData,
               lpMacFragment->uiFragmentDataSize);

        skb->protocol = eth_type_trans(skb, skb->dev);
        break;
    case IPPP_MAX_HEADER:
    case 0:
        pMac = pIP;
        skb->protocol = htons(ETH_P_IP);
        break;
    default:
        break;
    }
//    skb->dev = pBinding->pDevice;

    skb->ip_summed = CHECKSUM_UNNECESSARY;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    skb->network_header = (sk_buff_data_t) skb->data;
    skb->mac_header = (sk_buff_data_t)pMac;
#else
    skb->nh.iph = (struct iphdr *) skb->data;
    skb->mac.raw = pMac;
#endif

    pBinding->recv_stat.called = TRUE;

#ifdef VIRTUAL_ADAPTER
    if(!strncmp(skb->dev->name,LINUX_VPN_IFNAME,IFNAMSIZ))
    {
        rx_bytes+=skb->len;
    }
#else
    rx_bytes+=skb->len;
#endif

    pBinding->recv_stat.rc = pBinding->InjectReceive(skb, 
                                                     skb->dev, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
                                                     pBinding->pPT,
                                                     skb->dev);
#else
                                                     pBinding->pPT);
#endif

  exit_gracefully:
    CNICallbackTable.ReceiveComplete(Binding, ReceiveContext, Packet);
    return rc;
}


/*************************************************************************
 * 
 * CniInjectSend
 * 
 * Description:
 * This call will inject a packet into the send data stream, the packet will
 * appear to be originating from and sent via a protocol/NIC pair defined by
 * Binding.  This plugin will not see the packet in it CniSend() entry point,
 * but will receive notification that the packet has been sent via it's 
 * CniSendComplete() entry point.  The SendContext will be used to send 
 * packet-specific data to CniSendComplete so that this packet may be 
 * identified as belonging to this plugin.
 *
 * 
 * 
 * Argument:
 *	
 *   IN DNBINDING Binding - A binding handle that will be used
 *                 to receive this packet.
 *   IN PVOID SendContext - Data to be passed to the SendComplete
 *                 entry point.
 *   IN DNFRAGMENT MacHeader - This is the header that will be 
 *                copied to the packet before it is sent over the NIC.  It 
 *                should correspond to the Binding.
 *   IN DNPACKET Packet - The packet that will be sent, minus the
 *                 MAC header.
 * 
 * Returns:
 * 
 *   CNISTATUS  - CNI_SUCCESS - The packet was sent by the NIC.
 *                CNI_PENDING - The packet will be sent by theNIC.
 *                CNI_W_BAD_FORMAT - The packet data was not formatted 
 *                correctly for the NIC.
 * 
 *************************************************************************/
NOREGPARM CNISTATUS
CniInjectSend(IN CNIBINDING Binding,
              IN PVOID SendContext,
              IN CNIFRAGMENT MacHeader, IN CNIPACKET Packet) 
{
    CNISTATUS rc = CNI_SUCCESS;
    LPPACKETDESCRIPTOR lpPacketDescriptor;
    PBINDING pBinding,pVABinding;
    LPFRAGMENTBUFFER lpMacFragment;
    struct sk_buff *skb;
    unsigned char *pIP = NULL, *pMac = NULL;
    int tmp_rc = 0;

    int (*tmp_InjectSend) (struct sk_buff * skb, struct net_device * dev);
    tmp_InjectSend = NULL;

    /* we need to build the actual sk_buff from the packet structure */
    pBinding = (PBINDING) Binding;
    lpPacketDescriptor = (LPPACKETDESCRIPTOR) Packet;
    lpMacFragment = (LPFRAGMENTBUFFER) MacHeader;

    /*XXX somebody write a comment about the + 2 on this call... */
    skb = dev_alloc_skb(lpPacketDescriptor->uiPacketSize
                        + lpMacFragment->uiFragmentDataSize + 2);

    if (!skb)
    {
        rc = CNI_W_OUT_OF_DESCRIPTORS;
        goto exit_gracefully;
    }
    /* transfer the packet data into sk_buff */

    switch (pBinding->send_real_hh_len)
    {
    case ETH_HLEN:
        pMac = skb_put(skb, lpMacFragment->uiFragmentDataSize);
        kernel_memcpy(pMac, lpMacFragment->lpFragmentData,
               lpMacFragment->uiFragmentDataSize);
        break;
    case 0:
        pMac = skb->data;
        break;
    case IPPP_MAX_HEADER:
        pMac = skb_put(skb,IPPP_MAX_HEADER);
        break;
    default:
        break;
    };

    pIP = skb_put(skb, lpPacketDescriptor->uiPacketSize);
    CniGetPacketData(Packet, 0, lpPacketDescriptor->uiPacketSize, pIP);

    /* put the mac header on */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    {
      struct timeval timestamp;
      
      do_gettimeofday(&timestamp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
      skb->tstamp = timeval_to_ktime(timestamp);
#else
      skb_set_timestamp(skb,&timestamp);
#endif
    }
#else
    do_gettimeofday(&skb->stamp);
#endif

    skb->dev = pBinding->pDevice;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    skb->mac_header = (sk_buff_data_t)pMac;
    skb->network_header = (sk_buff_data_t)pIP;
#else
    skb->mac.raw = pMac;
    skb->nh.raw = pIP;
#endif

    /*ip header length is in 32bit words */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    skb->transport_header = (sk_buff_data_t)
      (pIP + (((struct iphdr*)(skb->network_header))->ihl * 4));
#else
    skb->h.raw = pIP + (skb->nh.iph->ihl * 4);
#endif
    skb->protocol = htons(ETH_P_IP);

    /* send this packet up the NIC driver */
    // May need to call dev_queue_xmit(skb) instead
    tmp_rc = pBinding->InjectSend(skb, skb->dev);

#ifdef VIRTUAL_ADAPTER
    pVABinding = CniGetVABinding();
    if(pVABinding != NULL)
    {
        pVABinding->send_stat.rc = tmp_rc;
        if (pVABinding->send_stat.rc != 0)
        {
            dev_kfree_skb(skb);
        }
        pVABinding->send_stat.called = TRUE;
    }
#else
    pBinding->send_stat.rc = tmp_rc;
    /* if the nic's hard_start_xmit function failed,
       the kernel will queue original packet
       and send to us again.  So, we free the packet that was just built,
       and when the kernel calls dev->hard_start_xmit, we'll start all
       over again... see sch_generic.c:qdisc_restart() for details.
    */
    if (pBinding->send_stat.rc != 0)
    {
        dev_kfree_skb(skb);
    }
    pBinding->send_stat.called = TRUE;
#endif
  exit_gracefully:
    /* we have to call Sendcomplete here or else the sendcontext will
     * not be free */
    // pBinding is not used by SendComplete 
    CNICallbackTable.SendComplete(pBinding, SendContext, Packet);
    return rc;
}


NOREGPARM CNISTATUS
CNI_DNEListBindings(OUT CNIBINDING* bindingArray,
                    IN OUT ULONG*   bindingArraySize)
{
    ULONG tmp_size = 0;
    int i;

    if ((bindingArraySize == NULL)
        || (*bindingArraySize > 0 && bindingArray == NULL))
    {
        return CNI_E_BAD_PARAMETER;
    }

    for (i = 0; i < MAX_INTERFACES; i++)
    {
        if (Bindings[i].pDevice != NULL)
        {
            tmp_size++;
        }
    }
    
    if (tmp_size > *bindingArraySize)
    {
        *bindingArraySize = tmp_size;
        return CNI_W_BUFFER_TOO_SMALL;
    }

    tmp_size = 0;
    for (i = 0; i < MAX_INTERFACES; i++)
    {
        if (Bindings[i].pDevice != NULL)
        {
            bindingArray[tmp_size] = &Bindings[i]; 
            tmp_size++;
        }
    }
    *bindingArraySize = tmp_size;
    return CNI_SUCCESS;
}

NOREGPARM CNIBINDING
CniGetBindingByIndex(IN INT iIndex)
{
    int i;
    
    for (i=0; i <= MAX_INTERFACES; i++)
    {
        BINDING *b = &Bindings[i];
        if (b->pDevice && (iIndex == b->pDevice->ifindex))
        {
            return b;
        }
    }
    return NULL;
}
