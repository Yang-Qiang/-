#ifndef _CHECK_H
#define _CHECK_H
#include <linux/skbuff.h>
/* check ip*/
int check_ip_packet(struct sk_buff* skb);
/* check port*/
int check_port_packet(struct sk_buff* skb);
#endif
