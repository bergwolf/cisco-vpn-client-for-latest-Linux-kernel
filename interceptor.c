/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    interceptor.c
*  Date:    04/10/2001
*
***************************************************************************
* This module implements the linux driver.
***************************************************************************/
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/ppp_defs.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/protocol.h>

#include "linux_os.h"

#include "vpn_ioctl_linux.h"
#include "Cniapi.h"
#include "linuxcniapi.h"
#include "frag.h"
#include "mtu.h"
#include "unixkernelapi.h"

static uint8_t interceptor_eth_addr[] = { 0x00, 0x0b, 0xfc, 0xf8, 0x01, 0x8f };

// packet statistics 
static unsigned long tx_packets;
static unsigned long tx_dropped;
static unsigned long tx_bytes;
static unsigned long rx_packets;
static unsigned long rx_dropped;
unsigned long rx_bytes;

/*methods of the cipsec network device*/
static int interceptor_init(struct net_device *);
static struct net_device_stats *interceptor_stats(struct net_device *dev);
static int interceptor_ioctl(struct net_device *dev, struct ifreq *ifr,
                             int cmd);
static int interceptor_tx(struct sk_buff *skb, struct net_device *dev);

/*helper functions*/
static BINDING *getbindingbydev(struct net_device *dev);
static void do_cleanup(void);
static int handle_vpnup(void);
static int handle_vpndown(void);
static CNIFRAGMENT build_ppp_fake_mac_frag(struct ethhdr *dummy);
static int supported_device(struct net_device *dev);

/*packet handler functions*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int recv_ip_packet_handler(struct sk_buff *skb,
                                  struct net_device *dev,
                                  struct packet_type *type,
                                  struct net_device *orig_dev);
#else
static int recv_ip_packet_handler(struct sk_buff *skb,
                                  struct net_device *dev,
                                  struct packet_type *type);
#endif
static int replacement_dev_xmit(struct sk_buff *skb, struct net_device *dev);

static int handle_netdev_event(struct notifier_block *self, unsigned long,
                               void *);

struct packet_type_funcs
{
    struct packet_type *pt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    int (*orig_handler_func) (struct sk_buff *, 
                              struct net_device *,
                              struct packet_type *,
                              struct net_device *);
#else
    int (*orig_handler_func) (struct sk_buff *, 
                              struct net_device *,
                              struct packet_type *);
#endif
};
static struct packet_type_funcs original_ip_handler;

extern CNI_CHARACTERISTICS CNICallbackTable; /* This stores the Plugin's function pointers */
extern PCHAR pcDeviceName;      /* Ignore. Only our pluggin so we don't care about it */

static int vpn_is_up = FALSE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
#define interceptor_name LINUX_VPN_IFNAME
#else
static char interceptor_name[] = LINUX_VPN_IFNAME;
#endif

BINDING Bindings[MAX_INTERFACES];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static struct net_device *interceptor_dev;
#else
static struct net_device interceptor_dev = {
    .name = interceptor_name,
    .init = interceptor_init
};
#endif

static struct notifier_block interceptor_notifier = {
    .notifier_call = handle_netdev_event,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
static int
#else
static int __init
#endif
interceptor_init(struct net_device *dev)
{
    ether_setup(dev);

    dev->hard_start_xmit = interceptor_tx;
    dev->get_stats = interceptor_stats;
    dev->do_ioctl = interceptor_ioctl;

    dev->mtu = ETH_DATA_LEN-MTU_REDUCTION;
    kernel_memcpy(dev->dev_addr, interceptor_eth_addr,ETH_ALEN);
    dev->flags |= IFF_NOARP;
    dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
    kernel_memset(dev->broadcast, 0xFF, ETH_ALEN);

    return 0;
}

static struct net_device_stats *
interceptor_stats(struct net_device *dev)
{
    static struct net_device_stats es;

    es.rx_packets = rx_packets;
    es.rx_bytes = rx_bytes;
    es.rx_errors = 0;
    es.rx_dropped = rx_dropped;
    es.rx_fifo_errors = 0;
    es.rx_length_errors = 0;
    es.rx_over_errors = 0;
    es.rx_crc_errors = 0;
    es.rx_frame_errors = 0;
    es.tx_packets = tx_packets;
    es.tx_bytes = tx_bytes;
    es.tx_errors = 0;
    es.tx_dropped = tx_dropped;
    es.tx_fifo_errors = 0;
    es.collisions = 0;
    es.tx_carrier_errors = 0;
    es.tx_aborted_errors = 0;
    es.tx_window_errors = 0;
    es.tx_heartbeat_errors = 0;

    return (&es);
}

static int
interceptor_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    int error = 0;
    static struct ifvpncmd command;

#ifdef MOD_INC_AND_DEC
    MOD_INC_USE_COUNT;
#endif
    switch (cmd)
    {
    case SIOCGVPNCMD:
        {
            uint32 ret_size;

            char *from = (char *) ifr->ifr_ifru.ifru_data;

            error = copy_from_user(&command, from, sizeof(struct ifvpncmd));
            if (error)
            {
                break;
            }

            error = CniPluginIOCTL(command.cmd, (void *) command.data,
                                   command.datalen, sizeof(command.data),
                                   &ret_size);

            if (!error)
            {
                command.datalen = ret_size;
            }
            else
            {
                command.datalen = 0;
            }

            error = copy_to_user(from, &command, sizeof(struct ifvpncmd));
        }
        break;

    case SIOCGVPNIFUP:
        error = handle_vpnup();
        break;

    case SIOCGVPNIFDOWN:
        error = handle_vpndown();
        break;

    default:
        error = -EOPNOTSUPP;
        break;
    }

#ifdef MOD_INC_AND_DEC
    MOD_DEC_USE_COUNT;
#endif

    return error;
}

static int
interceptor_tx(struct sk_buff *skb, struct net_device *dev)
{
    tx_dropped++;
    dev_kfree_skb(skb);
    return 0;
}
static int
add_netdev(struct net_device *dev)
{
    int rc = -1;
    int i = 0;

    if (!supported_device(dev))
    {
        goto exit_gracefully;
    }

    for (i = 0; i < MAX_INTERFACES; i++)
    {
        if (Bindings[i].pDevice == NULL)
        {
            break;
        }
    }
    if (i >= MAX_INTERFACES)
    {
        printk(KERN_DEBUG "%s:exceeded max network devices (%d) at dev %s (%d)",
               __FUNCTION__, MAX_INTERFACES, dev->name, dev->ifindex);
        rc = -1;
        goto exit_gracefully;
    }

    Bindings[i].pDevice = dev;
    /* store the original mtu for this device. */
    Bindings[i].original_mtu = dev->mtu;

    /*replace the original send function with our send function */
    Bindings[i].InjectSend = dev->hard_start_xmit;
    dev->hard_start_xmit = replacement_dev_xmit;

    /*copy in the ip packet handler function and packet type struct */
    Bindings[i].InjectReceive = original_ip_handler.orig_handler_func;
    Bindings[i].pPT = original_ip_handler.pt;

    rc = 0; 

exit_gracefully:
    return rc;
}
static int
remove_netdev(struct net_device *dev)
{
    int rc = -1;
    BINDING *b;

    b = getbindingbydev(dev);

    if (b)
    {   
        rc = 0;
        dev->hard_start_xmit = b->InjectSend;
        kernel_memset(b, 0, sizeof(BINDING));
    }
    else
    {
        printk(KERN_DEBUG "%s: missing dev %s (%d)", __FUNCTION__,
               dev->name, dev->ifindex);
    }
    return rc;
}
static int
handle_vpnup(void)
{
    /*temporary structure used to retrieve the registered ip packet handler.
     *it is static because it gets inserted temporarily into a kernel hash
     *table and if things went incredibly wrong it could end up staying there
     */
    static struct packet_type dummy_pt;

    struct net_device *dp = NULL;
    struct packet_type *default_pt = NULL;
    int error = VPNIFUP_SUCCESS, num_target_devices;

    cleanup_frag_queue();

#ifdef MOD_INC_AND_DEC
    MOD_INC_USE_COUNT;
#else
    if (!try_module_get(THIS_MODULE))
    {
        return -EBUSY;
    }
#endif
    if (vpn_is_up)
    {
        error = VPNIFUP_FAILURE;
        return error;
    }
    /* find the handler for inbound IP packets by adding a dummy handler
     * for that packet type into the kernel. Because the packet handlers
     * are stored in a hash table, we'll be able to pull the original 
     * ip packet handler out of the list that dummy_pt was inserted into.*/
    kernel_memset(&dummy_pt, 0, sizeof(dummy_pt));
    dummy_pt.type = htons(ETH_P_IP);
    dummy_pt.func = recv_ip_packet_handler;

    dev_add_pack(&dummy_pt);
    /* this should be the original IP packet handler */
    default_pt = PACKET_TYPE_NEXT(&dummy_pt);
    /* there may be more than one other packet handler in our bucket,
     * so look through all the buckets */
    while (default_pt != NULL && default_pt->type != htons(ETH_P_IP))
    {
        default_pt = PACKET_TYPE_NEXT(default_pt);
    }
    if (!default_pt)
    {
        printk(KERN_DEBUG "No default handler found for %x protocol!!\n",
               dummy_pt.type);
        dev_remove_pack(&dummy_pt);
        error = VPNIFUP_FAILURE;
        goto error_exit;
    }
    /*remove the dummy handler handler */
    original_ip_handler.pt = default_pt;
    dev_remove_pack(&dummy_pt);

    /*and replace the original handler function with our function */
    original_ip_handler.orig_handler_func = original_ip_handler.pt->func;
    original_ip_handler.pt->func = recv_ip_packet_handler;

    /* identify the active network devices */
    kernel_memset(&Bindings, 0, sizeof(Bindings));

    dp = NULL;
    num_target_devices = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    for_each_netdev(&init_net, dp)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    for_each_netdev(dp)
#else
    for (dp = dev_base; dp != NULL; dp = dp->next)
#endif
    {
        if (add_netdev(dp) == 0)
        {
            num_target_devices++;
        }
    }

    if (num_target_devices == 0)
    {
        printk(KERN_DEBUG "No network devices detected.\n");
        error = VPNIFUP_FAILURE;
        goto error_exit;
    }
    vpn_is_up = TRUE;
    return error;

  error_exit:
    do_cleanup();
    vpn_is_up = FALSE;
#ifdef MOD_INC_AND_DEC
    MOD_DEC_USE_COUNT;
#else
    module_put(THIS_MODULE);
#endif
    return error;
}
static void
do_cleanup(void)
{
    int i;

    cleanup_frag_queue();
    /*restore IP packet handler */
    if (original_ip_handler.pt != NULL)
    {
        original_ip_handler.pt->func = original_ip_handler.orig_handler_func;
    }
    kernel_memset(&original_ip_handler, 0, sizeof(original_ip_handler));

    /*restore network devices */
    for (i = 0; i < MAX_INTERFACES; i++)
    {
        struct net_device *dev = Bindings[i].pDevice;
        if (dev)
        {
            remove_netdev(dev);
        }
    }
    kernel_memset(&Bindings, 0, sizeof(Bindings));
}
static int
handle_vpndown(void)
{
    int error = VPNIFDOWN_SUCCESS;

    if (!vpn_is_up)
    {
        error = VPNIFDOWN_FAILURE;
        goto exit_gracefully;
    }
    do_cleanup();

    vpn_is_up = FALSE;

#ifdef MOD_INC_AND_DEC
    MOD_DEC_USE_COUNT;
#else
    module_put(THIS_MODULE);
#endif
  exit_gracefully:
    return error;
}
static int
handle_netdev_event(struct notifier_block *self, unsigned long event, void *val)
{
    struct net_device *dev = NULL;

    dev = (struct net_device *) val;

    if (!vpn_is_up)
    {
        return 0;
    }
    switch (event)
    {
    case NETDEV_REGISTER:
        add_netdev(dev);
        break;
    case NETDEV_UNREGISTER:
        remove_netdev(dev);
        break;
    default:
        break;
    }

    return 0;
}

static void
reset_inject_status(inject_status * s)
{
    s->called = FALSE;
    s->rc = 0;
}

static int
supported_device(struct net_device* dev)
{
    int rc=0;

    if(dev->type == ARPHRD_ETHER)
    {
        rc=1;
    }
    else if(dev->type == ARPHRD_PPP)
    {
        rc=1;
    }

    return rc;
}


static BINDING *
getbindingbydev(struct net_device *dev)
{
    int i;
    
    for (i=0; i < MAX_INTERFACES; i++)
    {
        BINDING *b = &Bindings[i];
        if (b->pDevice && (dev->ifindex == b->pDevice->ifindex))
        {
            return b;
        }
    }
    return NULL;
}

static CNIFRAGMENT
build_ppp_fake_mac_frag(struct ethhdr *dummy)
{
    CNIFRAGMENT MacHdr = NULL;

    kernel_memset(dummy->h_dest, 45, ETH_ALEN);
    kernel_memset(dummy->h_source, 45, ETH_ALEN);
    dummy->h_proto = htons(ETH_P_IP);

    CniNewFragment(ETH_HLEN, (char *) dummy, &MacHdr, CNI_USE_BUFFER);
    return MacHdr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int
recv_ip_packet_handler(struct sk_buff *skb,
                       struct net_device *dev, 
                       struct packet_type *type,
                       struct net_device *orig_dev)
#else
static int
recv_ip_packet_handler(struct sk_buff *skb,
                       struct net_device *dev, 
                       struct packet_type *type)
#endif
{
    int rc2 = 0;
    int tmp_rc = 0;
    CNISTATUS rc = 0;
    CNIPACKET NewPacket = NULL;
    CNIFRAGMENT Fragment = NULL;
    CNIFRAGMENT MacHdr = NULL;
    PVOID lpReceiveContext = NULL;
    ULONG ulFinalPacketSize;
    BINDING *pBinding = NULL;
    struct ethhdr ppp_dummy_buf;
    int hard_header_len;

#ifdef MOD_INC_AND_DEC
    MOD_INC_USE_COUNT;
#endif
    if (dev->type == ARPHRD_LOOPBACK)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type, dev);
#else
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type);
#endif
        goto exit_gracefully;
    }

    /* Don't handle non-eth non-ppp packets */
    if (!supported_device(dev))
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type, dev);
#else
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type);
#endif
        goto exit_gracefully;
    }

    pBinding = getbindingbydev(dev);

    /* if we don't have a binding, this is a new device that
     *  has been brought up while the tunnel is up. For now,
     *  just pass the packet
     */
    if (!pBinding)
    {
        static int firsttime = 1;
        if (firsttime)
        {
            printk(KERN_DEBUG "RECV: new dev %s detected\n", dev->name);
            firsttime = 0;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type, dev);
#else
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type);
#endif
        goto exit_gracefully;
    }

    //only need to handle IP packets.
    if (skb->protocol != htons(ETH_P_IP))
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type, dev);
#else
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type);
#endif
        goto exit_gracefully;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
    if (skb->ip_summed == CHECKSUM_PARTIAL)
#else
    if (skb->ip_summed == CHECKSUM_HW)
#endif
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
       if (skb_checksum_help(skb))
#else
       if (skb_checksum_help(skb,1))
#endif
#else
       if (skb_checksum_help(&skb,1))
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
       {
           dev_kfree_skb(skb);
           skb = NULL;
           goto exit_gracefully;
       }
#else
       skb->ip_summed = CHECKSUM_NONE;
#endif
    }

    reset_inject_status(&pBinding->recv_stat);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    if (skb->mac_header)
#else
    if (skb->mac.raw)
#endif
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
        hard_header_len = skb->data - skb->mac_header;
#else
        hard_header_len = skb->data - skb->mac.raw;
#endif
        if ((hard_header_len < 0) || (hard_header_len > skb_headroom(skb)))
        {
            printk(KERN_DEBUG "bad hh len %d\n", hard_header_len);
            hard_header_len = 0;
        }
    }
    else
    {
        hard_header_len = 0;
    }

    pBinding->recv_real_hh_len = hard_header_len;

    switch (hard_header_len)
    {
    case ETH_HLEN:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
        CniNewFragment(ETH_HLEN, skb->mac_header, &MacHdr, CNI_USE_BUFFER);
#else
        CniNewFragment(ETH_HLEN, skb->mac.raw, &MacHdr, CNI_USE_BUFFER);
#endif
        break;
    case IPPP_MAX_HEADER:
    case 0:
        MacHdr = build_ppp_fake_mac_frag(&ppp_dummy_buf);
        break;
    default:
        printk(KERN_DEBUG "unknown mac header length (%d)\n", hard_header_len);
        dev_kfree_skb(skb);
        skb = NULL;
        goto exit_gracefully;
    }

    CniNewFragment(skb->len, skb->data, &Fragment, CNI_USE_BUFFER);
    ulFinalPacketSize = skb->len;

    rc = CNICallbackTable.Receive((void *) &pBinding,
                                  &lpReceiveContext,
                                  &MacHdr,
                                  &Fragment, &NewPacket, &ulFinalPacketSize);

    switch (rc)
    {
    case CNI_CONSUME:
        tmp_rc = CNICallbackTable.ReceiveComplete(pBinding,
                                                  lpReceiveContext, NewPacket);

        dev_kfree_skb(skb);
        rx_packets++;
        if (pBinding->recv_stat.called)
        {
            rc2 = pBinding->recv_stat.rc;
        }
        break;
    case CNI_CHAIN:
        tmp_rc = CNICallbackTable.ReceiveComplete(pBinding,
                                                  lpReceiveContext, NewPacket);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type, dev);
#else
        rc2 = original_ip_handler.orig_handler_func(skb, dev, type);
#endif

        if (pBinding->recv_stat.called)
        {
            rc2 = pBinding->recv_stat.rc;
        }

        break;
    case CNI_DISCARD:
        dev_kfree_skb(skb);
        rx_dropped++;
        break;
    default:
        printk(KERN_DEBUG "RECV: Unhandled case in %s rc was %x\n",
               __FUNCTION__, (uint) rc);

        dev_kfree_skb(skb);
        rx_dropped++;
    }
  exit_gracefully:
    if (MacHdr)
    {
        CniReleaseFragment(MacHdr, CNI_KEEP_BUFFERS);
    }
    if (Fragment)
    {
        CniReleaseFragment(Fragment, CNI_KEEP_BUFFERS);
    }
#ifdef MOD_INC_AND_DEC
    MOD_DEC_USE_COUNT;
#endif

    return rc2;
}

int
do_cni_send(BINDING * pBinding, struct sk_buff *skb, struct net_device *dev)
{
    int rc2 = 0;
    CNISTATUS rc = 0;
    CNIPACKET Packet = NULL;
    CNIFRAGMENT Fragment = NULL;
    CNIFRAGMENT MacHdr = NULL;
    PVOID lpSendContext = NULL;
    struct ethhdr ppp_dummy_buf;
    int hard_header_len = 0;

    int (*tmp_InjectSend) (struct sk_buff * skb, struct net_device * dev);
    tmp_InjectSend = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
    if (skb->ip_summed == CHECKSUM_PARTIAL)
#else
    if (skb->ip_summed == CHECKSUM_HW)
#endif
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
       if (skb_checksum_help(skb))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
       if (skb_checksum_help(skb,0))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
       if (skb_checksum_help(&skb,0))
#else
       if ((skb = skb_checksum_help(skb)) == NULL)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
       {
           goto exit_gracefully;
       }
    }
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
    reset_inject_status(&pBinding->send_stat);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    hard_header_len = skb->network_header - skb->data;
#else
    hard_header_len = skb->nh.raw - skb->data;
#endif
    pBinding->send_real_hh_len = hard_header_len;
    switch (hard_header_len)
    {
    case ETH_HLEN:
        CniNewFragment(ETH_HLEN, skb->data, &MacHdr, CNI_USE_BUFFER);
        break;
    case IPPP_MAX_HEADER:
    case 0:
        MacHdr = build_ppp_fake_mac_frag(&ppp_dummy_buf);
        /* note: the PPP device says it's hard_header_len is 4,
         * but skb->data points at the IP header*/
        break;
    default:
        printk(KERN_DEBUG "unknown mac header length (%d)\n",
               skb->dev->hard_header_len);
        dev_kfree_skb(skb);
        skb = NULL;
        goto exit_gracefully;
    }
    CniNewPacket(0, &Packet);
    /*skb->data points to the mac header, the fragment should start
     *with the ip header */
    CniNewFragment(skb->len - hard_header_len,
                   skb->data + hard_header_len, &Fragment, CNI_USE_BUFFER);

    CniAddFragToFront(Packet, Fragment);

    rc = CNICallbackTable.Send((void *) &pBinding,
                               &lpSendContext, &MacHdr, &Packet);

    switch (rc)
    {
    case CNI_DISCARD:
        /* packet was tunneled */
        if (pBinding->send_stat.called)
        {
            rc2 = pBinding->send_stat.rc;

            /*if the packet was tunneled, rc2 should
               now contain the return code from the
               call to the nic's hard_start_xmit function.
               if that function failed, the kernel is going
               to queue this skb and send it to us again later,
               so don't free it. */
            if (rc2 == 0)
            {
                tx_bytes+=skb->len;
                dev_kfree_skb(skb);
                tx_packets++;
            }
        }
        /* packet dropped */
        else
        {
            dev_kfree_skb(skb);
            tx_dropped++;
        }
        break;
    case CNI_CHAIN:
        rc2 = pBinding->InjectSend(skb, dev);
        break;
    default:
        printk(KERN_DEBUG "Unhandled case in %s rc was %x\n", __FUNCTION__,
               (uint) rc);

        dev_kfree_skb(skb);
        tx_dropped++;
        rc2 = 0;
    }
  exit_gracefully:
    if (MacHdr)
    {
        CniReleaseFragment(MacHdr, CNI_KEEP_BUFFERS);
    }
    if (Packet)
    {
        CniReleasePacket(Packet, CNI_KEEP_BUFFERS);
    }

    return rc2;
}
static int
replacement_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int rc2 = 0;
    BINDING *pBinding = 0;

#ifdef MOD_INC_AND_DEC
    MOD_INC_USE_COUNT;
#endif
    pBinding = getbindingbydev(dev);
    /* if we don't have a binding, this is a new device that
     *  has been brought up while the tunnel is up. For now,
     *  just drop the packet.
     */
    if (!pBinding)
    {
        static int firsttime = 1;
        if (firsttime)
        {
            printk(KERN_DEBUG "XMIT: new dev %s detected\n", dev->name);
            firsttime = 0;
        }
        dev_kfree_skb(skb);
        goto exit_gracefully;
    }

    //only need to handle IP packets.
    if (skb->protocol != htons(ETH_P_IP))
    {
        rc2 = pBinding->InjectSend(skb, dev);
        goto exit_gracefully;
    }

    if (need_reorder_frag(skb))
    {
        rc2 = handle_fragment(pBinding, skb, dev);
    }
    else
    {
        rc2 = do_cni_send(pBinding, skb, dev);
    }
  exit_gracefully:
#ifdef MOD_INC_AND_DEC
    MOD_DEC_USE_COUNT;
#endif

    return rc2;
}


static int __init
interceptor_mod_init(void)
{
    int status = 0;
    PCNI_CHARACTERISTICS PCNICallbackTable;
    CNISTATUS rc = CNI_SUCCESS;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    interceptor_dev= alloc_netdev( 0, interceptor_name, (void *)interceptor_init);
#endif
    rc = CniPluginLoad(&pcDeviceName, &PCNICallbackTable);

    if (CNI_IS_SUCCESS(rc))
    {

        CNICallbackTable = *PCNICallbackTable;
        CniPluginDeviceCreated();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
        if ((status = register_netdev(interceptor_dev)) != 0)
#else
        if ((status = register_netdev(&interceptor_dev)) != 0)
#endif
        {
            printk(KERN_INFO "%s: error %d registering device \"%s\".\n",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
                   LINUX_VPN_IFNAME, status, interceptor_dev->name);
#else
                   LINUX_VPN_IFNAME, status, interceptor_dev.name);
#endif
            CniPluginUnload();
            return status;
        }
        register_netdevice_notifier(&interceptor_notifier);
    }
    if (status == 0)
    {
        printk(KERN_INFO "Cisco Systems VPN Client Version "
                BUILDVER_STRING " kernel module loaded\n");
    }
    return (status);
}

static void __exit
interceptor_mod_cleanup(void)
{
    cleanup_frag_queue();
    CniPluginUnload();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    unregister_netdev(interceptor_dev);
#else
    unregister_netdev(&interceptor_dev);
#endif
    unregister_netdevice_notifier(&interceptor_notifier);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    free_netdev(interceptor_dev);
#endif
    return;
}

module_init(interceptor_mod_init);
module_exit(interceptor_mod_cleanup);
MODULE_LICENSE("Proprietary");
