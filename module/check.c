
#include "check.h"
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include "linux_in.h"
#include "linux_ip.h"
#include "linux_tcp.h"
#include "linux_udp.h"
#include "linux_netfilter.h"
#include "linux_netfilter_ipv4.h"

extern unsigned int* deny_ip;      // defined in module.c
extern unsigned short* deny_port;  // define in module.c

#define MAX_NR 100  //能过滤的IP地址数量，port数量
/*Check ip*/
int check_ip_packet(struct sk_buff* skb) {
    int i;
    struct iphdr* iph;
    iph = ip_hdr(skb);

    if (!skb) return NF_ACCEPT;

    if (!ip_hdr(skb)) return NF_ACCEPT;

    for (i = 0; i < MAX_NR; i++) {
        if (iph->saddr == *(deny_ip + i) && *(deny_ip + i) != 0) {
            printk(KERN_DEBUG "------------->%x ip is drop<-------\n", htonl(*(deny_ip + i)));
            printk(KERN_DEBUG "------------->%x iph->saddr is drop<-------\n", htonl(iph->saddr));
            printk(KERN_DEBUG "------------->%x iph->daddr is drop<-------\n", htonl(iph->daddr));
            printk(KERN_DEBUG "------------->%x iph->protocol is drop<-------\n", htonl(iph->protocol));
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

/* check port*/
int check_port_packet(struct sk_buff* skb) {
    int i;
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;

    iph = ip_hdr(skb);

    if (!skb) return NF_ACCEPT;

    if (!ip_hdr(skb)) return NF_ACCEPT;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr*) (skb->data + (iph->ihl * 4));
            for (i = 0; i < MAX_NR; i++) {
                if ((ntohs(tcph->dest) == *(deny_port + i)) && *(deny_port + i) != 0) {
                    printk(KERN_DEBUG "----------->%d tcp port is drop<--------\n", *(deny_port + i));
                    printk(KERN_DEBUG "----------->%d tcph->source port is drop<--------\n",
                           ntohs(tcph->source));
                    printk(KERN_DEBUG "----------->%d tcph->dest port is drop<--------\n", ntohs(tcph->dest));
                    return NF_DROP;
                }
            }
            break;

        case IPPROTO_UDP:
            udph = (struct udphdr*) (skb->data + (iph->ihl * 4));
            for (i = 0; i < MAX_NR; i++) {
                if ((ntohs(udph->dest) == *(deny_port + i)) && *(deny_port + i) != 0) {
                    printk(KERN_DEBUG "----------->%d udp port is drop<--------\n", *(deny_port + i));
                    printk(KERN_DEBUG "----------->%d udph->source port is drop<--------\n",
                           ntohs(udph->source));
                    printk(KERN_DEBUG "----------->%d udph->dest port is drop<--------\n",
                           ntohs(udph->source));
                    return NF_DROP;
                }
            }
            break;
        default:
            return -ENOTTY;
    }

    return NF_ACCEPT;
}
