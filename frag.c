#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ppp_defs.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/protocol.h>
#include <net/dst.h>

#include "linux_os.h"
#include "vpn_ioctl_linux.h"
#include "Cniapi.h"
#include "linuxcniapi.h"
#include "frag.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define SKB_IPHDR(skb) ((struct iphdr*)skb->network_header)
#else
#define SKB_IPHDR(skb) skb->nh.iph
#endif

/*number of queues available at one time*/
#define NUMQUEUES 10
struct frag_queue_entry
{
    struct frag_queue_entry *next;
    struct sk_buff *skb;
};
static struct frag_queue_entry *frag_queue_head;


extern int do_cni_send(BINDING *,struct sk_buff*, struct net_device*);
extern char* GetPeerMac(uint32);

static int queue_fragment(struct sk_buff* skb)
{
    u_int16_t id=0;
    u_int16_t skb_offset=0,cur_offset=0,prev_offset=0;
    int ret=FALSE;
    struct frag_queue_entry *cur=NULL,*n=NULL,*prev=NULL;

    id = ntohs(SKB_IPHDR(skb)->id);
    /* look for an entry with the same id as this packet*/
    if (frag_queue_head && id != ntohs(SKB_IPHDR(frag_queue_head->skb)->id))
    {
        printk(KERN_INFO "%s: incomplete fragment set destroyed",__FUNCTION__);
        cleanup_frag_queue();
    }  
    /*allocate a new entry*/
    n = kmalloc(sizeof(struct frag_queue_entry),GFP_ATOMIC);
    if (!n)
    {
        printk(KERN_DEBUG "%s: kmalloc failed.",__FUNCTION__);
        goto exit_gracefully;
    }
    memset(n,0,sizeof(struct frag_queue_entry));
    n->skb = skb;

    cur = frag_queue_head;

    prev = NULL;
    skb_offset = ntohs(SKB_IPHDR(skb)->frag_off) & IP_OFFSET;
    while (cur)
    {
      cur_offset = ntohs(SKB_IPHDR(cur->skb)->frag_off) & IP_OFFSET;
        /*sanity check*/
        if (cur_offset < prev_offset)
        {
            printk(KERN_DEBUG "%s: cur_offset(%d) < prev_offset(%d)",
                   __FUNCTION__,cur_offset,prev_offset);
 
        } 
        if (cur_offset > skb_offset)
        {
            break; 
        }
        prev = cur;
        prev_offset = cur_offset;
        cur = cur->next;
    }
    /*at the front*/
    if (!prev)
    {
        n->next = frag_queue_head;
        frag_queue_head = n;
        n = NULL;
    }
    /*somewhere in the middle*/
    else
    {
        n->next = prev->next;
        prev->next = n;
        n = NULL;
    }

    ret = TRUE;

exit_gracefully:
    if (n)
    {
        kfree(n);
    }
    return ret;
}
static int have_all_fragments(void)
{
    int retval = FALSE;
    struct frag_queue_entry *cur=NULL,*prev = NULL;
    u_int16_t cur_offset=0,prev_offset=0,prev_end_offset=0;

    if (!frag_queue_head)
    {
        printk(KERN_DEBUG "%s: got a NULL frag_queue_head.",__FUNCTION__);
        goto done_with_tests;
    }
    cur = frag_queue_head;
    /*first in queue must be first frag.*/
    if ((ntohs(SKB_IPHDR(cur->skb)->frag_off) & IP_OFFSET) != 0)
    {
        goto done_with_tests;
    }
    /* go through all the packets and make sure there are packets missing,
       by comparing adjacent offset values and packet lengths*/
    while (cur)
    {
      cur_offset = (ntohs(SKB_IPHDR(cur->skb)->frag_off) & IP_OFFSET)*8;
        if (cur_offset != prev_end_offset)
        { 
            goto done_with_tests;
        }
        prev = cur;
        prev_offset = cur_offset;
        prev_end_offset = prev_offset + ntohs(SKB_IPHDR(prev->skb)->tot_len)
	  - (SKB_IPHDR(prev->skb)->ihl*4);
        cur = cur->next;
    } 
    /*last in queue must not have more frags set*/
    if (ntohs(SKB_IPHDR(prev->skb)->frag_off) & IP_MF)
    {
        goto done_with_tests;
    }
    retval = TRUE;
done_with_tests:
    return retval;
}
static struct sk_buff *get_next_frag(void)
{
    struct frag_queue_entry *cur=NULL;
    struct sk_buff *skb=NULL;

    cur = frag_queue_head;
    if (!cur)
    {
        return NULL;
    }
    frag_queue_head = cur->next;
    skb = cur->skb;
    cur->skb = NULL;
    kfree(cur);
    return skb;
}
void cleanup_frag_queue(void)
{
    struct frag_queue_entry *cur,*tmp=NULL;
    if (!frag_queue_head)
    {
        return;
    }
    cur = frag_queue_head;
    while (cur)
    {
        dev_kfree_skb(cur->skb);
        cur->skb = NULL;
        tmp = cur;
        cur = cur->next;
        kfree(tmp);
    }
    frag_queue_head  = NULL;
}
int need_reorder_frag(struct sk_buff *skb)
{
    struct iphdr *iph = NULL;
    int retval = FALSE;
    u_int16_t offset=0;
    if (skb->protocol != htons(ETH_P_IP))
    {
        /*not an IP packet*/
        goto done_with_tests;
    }
    iph = SKB_IPHDR(skb);
    if (!iph)
    {
        printk(KERN_DEBUG "%s: skb->nh is NULL.", __FUNCTION__);
        goto done_with_tests;
    }
    offset = ntohs(iph->frag_off);
    if (((offset & IP_MF) == 0) && ((offset & IP_OFFSET) == 0))
    {
        /*packet isn't a fragment*/
        goto done_with_tests;
    }
    if (GetPeerMac(iph->daddr) == NULL)
    {
        /*packet isn't going to concentrator*/
        goto done_with_tests;
    }
    if (iph->protocol == IPPROTO_UDP)
    {
        /*packet is udp*/
        retval = TRUE;
    }
done_with_tests:
    return retval;
}
int handle_fragment(BINDING* pBinding,struct sk_buff *skb,
                            struct net_device *dev)
{
    struct sk_buff *tmp_skb=NULL;

    if (!queue_fragment(skb))
    {

        goto exit_gracefully;
    }
    skb = NULL; /*skb is managed by the queue now. don't eat.*/
    if (!have_all_fragments())
    {
        goto exit_gracefully;

    }
    while ( (tmp_skb = get_next_frag()) )
    {
        int rc;

        rc = do_cni_send(pBinding,tmp_skb,dev); 
        /* this fails, we're toast, because the NIC driver
           is asking the IP stack to queue the packet we just
           tried to send (probably because the hardware is too busy).
           However, because we're sending other packets too, we
           can't just return -1 and let the kernel start over.
           All of the fragments that haven't been sent will have
           to be dropped.
        */
        if (rc)
        {
            dev_kfree_skb(tmp_skb);
            printk(KERN_DEBUG 
                   "%s: dev %s hardware busy. Packet dropped.", __FUNCTION__,
                    dev->name);
            break;
        }
    }
    cleanup_frag_queue();

exit_gracefully:
    return 0;
}
