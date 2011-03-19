#ifndef FRAG_H
#define FRAG_H
int need_reorder_frag(struct sk_buff *skb);
int handle_fragment(BINDING* pBinding,struct sk_buff *skb,
                    struct net_device *dev);
void cleanup_frag_queue(void);
#endif /*FRAG_H*/
